//! Archived messages: decrypting a page of `EBMessageRangeQueryForThreadsQuery`, message by
//! message, and what mautrix makes of a decrypted message. Ported from mautrix's
//! `archive.go`, `history.go` (from `archiveEncryptionVersion` down, plus the request and
//! response of `FetchMessages`) and `convertArchiveMessage` in `connector/backfill_e2ee.go`.
//!
//! A message is one of three formats: protobuf stanzas sealed under an epoch key (this
//! file), an Echo document ([`super::echo`]) or a Minos stanza ([`super::minos`]). Each
//! decrypts to a `BackupMessage`, with its supplementals (reactions, edits) keyed beside it.

use std::collections::BTreeMap;

use prost::Message;

use super::aead::{SealError, decrypt_data};
use super::minos::{MinosError, MinosReader, hkdf_key};
use super::proto::{
    ARMADILLO_APPLICATION_VERSION, ApplicationPayload, Armadillo, BackupMessage, BackupPayload,
    CONSUMER_APPLICATION_VERSION, ConsumerApplication, MULTI_DEVICE_APPLICATION_VERSION,
    MessageApplication, SubProtocol,
};
use super::{ArchiveAttachment, ArchiveMessage, ArchiveProtobuf, Device, MessageRange};
use crate::armadillo::{self, Content};

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("missing or invalid archive epoch or thread")]
    EpochOrThread,
    #[error("unsupported archive encryption version {0}")]
    Version(i64),
    #[error("unsupported Messenger archive encryption version {0:?}")]
    VersionName(String),
    #[error("failed to decrypt archive message: {0}")]
    Decrypt(SealError),
    #[error("failed to decode archive message: {0}")]
    Decode(prost::DecodeError),
    #[error("missing Messenger archive message epoch")]
    MissingEpoch,
    #[error("failed to decrypt Messenger archive supplemental key: {0}")]
    SupplementalKey(SealError),
    #[error("missing or unsupported Messenger archive message")]
    Unsupported,
    #[error("invalid unencrypted Messenger archive message: {0}")]
    Unencrypted(prost::DecodeError),
    #[error("missing Messenger archive message payload")]
    MissingPayload,
    #[error("missing Messenger archive supplemental key")]
    MissingSupplementalKey,
    #[error("missing Messenger Minos supplemental metadata")]
    MinosSupplemental,
    #[error("missing Messenger archive Echo epoch")]
    EchoEpoch,
    #[error("invalid Messenger archive Echo document: {0}")]
    Echo(#[from] super::echo::EchoError),
    #[error(transparent)]
    Minos(#[from] MinosError),
    #[error("archive device is not enrolled")]
    NotEnrolled,
    #[error("invalid Messenger archive range")]
    InvalidRange,
    #[error("invalid archive range response: {0}")]
    Response(serde_json::Error),
    #[error("missing Messenger archive range response")]
    MissingRange,
    #[error("archive is no longer available")]
    MailboxDeleted,
    #[error("archive thread was not found")]
    ThreadMissing,
    #[error("archive server rejected the range request")]
    Rejected,
    #[error("archive response belongs to a different backup")]
    OtherBackup,
    #[error("missing Messenger archive pagination")]
    MissingPagination,
}

/// The archive cipher's version number from the name a stanza gives it.
pub fn archive_encryption_version(version: &str) -> Result<i64, ArchiveError> {
    match version {
        "" | "UNKNOWN" => Ok(0),
        "ENCRYPTION_KDF_WITH_VERSION" => Ok(2),
        "ENCRYPTION_KDF_WITH_NULL_SALT" => Ok(3),
        "ENCRYPTION_KDF_WITH_NULL_SALT_DF_CANARY" => Ok(4),
        other => Err(ArchiveError::VersionName(other.to_string())),
    }
}

/// Opens an archive envelope (a stanza or an Echo document) under the key its epoch and
/// thread derive: versions 0 and 2 salt with the thread id, 3 and 4 with ten zero bytes.
pub(crate) fn decrypt_archive_payload(
    epoch_root_key: &[u8],
    epoch_anon_id: &str,
    thread_id: &str,
    version: i64,
    envelope: &[u8],
) -> Result<Vec<u8>, ArchiveError> {
    if epoch_root_key.len() != 32 || epoch_anon_id.is_empty() || thread_id.is_empty() {
        return Err(ArchiveError::EpochOrThread);
    }
    let mut info = format!("message_key_in_epoch_{epoch_anon_id}");
    let salt: &[u8] = match version {
        0 => thread_id.as_bytes(),
        2 => {
            info.push_str("_cipher_version_2");
            thread_id.as_bytes()
        }
        3 | 4 => {
            info.push_str(&format!("_cipher_version_{version}_thread_{thread_id}"));
            &[0; 10]
        }
        other => return Err(ArchiveError::Version(other)),
    };
    let key = hkdf_key(epoch_root_key, Some(salt), info.as_bytes(), 32);
    decrypt_data(
        &key,
        envelope,
        format!("message_thread_{thread_id}").as_bytes(),
    )
    .map_err(ArchiveError::Decrypt)
}

/// mautrix's exported `DecryptArchiveMessage`: an envelope opened and decoded.
pub fn decrypt_archive_message(
    epoch_root_key: &[u8],
    epoch_anon_id: &str,
    thread_id: &str,
    version: i64,
    envelope: &[u8],
) -> Result<BackupMessage, ArchiveError> {
    let plaintext =
        decrypt_archive_payload(epoch_root_key, epoch_anon_id, thread_id, version, envelope)?;
    BackupMessage::decode(plaintext.as_slice()).map_err(ArchiveError::Decode)
}

/// A decrypted stanza and the timestamp the page gave it.
#[derive(Debug, Clone, PartialEq)]
pub struct DecryptedProtobuf {
    pub message: BackupMessage,
    pub timestamp_ms: i64,
}

/// An archived message, decrypted: `id` is its otid, and `supplementals` (reactions and
/// edits) are keyed as the archive keys them, e.g. `reaction:<user id>`.
#[derive(Debug, Clone)]
pub struct DecryptedMessage {
    pub id: String,
    pub message: DecryptedProtobuf,
    pub supplementals: BTreeMap<String, DecryptedProtobuf>,
    pub attachments: Vec<ArchiveAttachment>,
    pub tags: Vec<String>,
}

impl ArchiveProtobuf {
    /// The stanza, and its supplemental key when it carries one (else `""`).
    fn decrypt(
        &self,
        device: &Device,
        thread_id: &str,
    ) -> Result<(DecryptedProtobuf, String), ArchiveError> {
        let epoch = device
            .epochs
            .get(&self.epoch_id)
            .filter(|e| e.anon_id == self.epoch_anon_id.as_bytes())
            .ok_or(ArchiveError::MissingEpoch)?;
        let version = archive_encryption_version(&self.encryption_version)?;
        let message = decrypt_archive_message(
            &epoch.root_key,
            &self.epoch_anon_id,
            thread_id,
            version,
            &self.encrypted,
        )?;
        let mut key = String::new();
        if !self.key_ciphertext.is_empty() {
            let sealing = hkdf_key(
                &epoch.root_key,
                Some(&[0; 10]),
                b"kdf_info:mailbox_root_key_v2>supplemental_enc_key",
                32,
            );
            let plain = decrypt_data(&sealing, &self.key_ciphertext, b"supplemental_enc_aad")
                .map_err(ArchiveError::SupplementalKey)?;
            // shortcut: a key that is not UTF-8 is read lossily, where Go keeps the bytes;
            // no key seen so far is anything but ASCII.
            key = String::from_utf8_lossy(&plain).into_owned();
        }
        Ok((
            DecryptedProtobuf {
                message,
                timestamp_ms: self.timestamp_ms,
            },
            key,
        ))
    }
}

impl ArchiveMessage {
    fn decrypt(
        &self,
        device: &Device,
        thread_id: &str,
        minos: &mut MinosReader,
    ) -> Result<DecryptedMessage, ArchiveError> {
        if self.id.is_empty() || (self.protobufs.is_none() && self.echo.is_none()) {
            return Err(ArchiveError::Unsupported);
        }
        let protobufs = match (&self.echo, &self.protobufs) {
            (Some(echo), p)
                if p.as_ref().is_none_or(|p| {
                    p.message.is_none() && p.unencrypted.is_none() && p.minos_message.is_none()
                }) =>
            {
                return self.decrypt_echo(echo, device, thread_id);
            }
            (_, Some(p)) => p,
            (_, None) => unreachable!("without stanzas the message has an Echo document"),
        };
        let message = if let Some(stanza) = &protobufs.minos_message {
            minos.decrypt(stanza, &self.id)?
        } else if let Some(unencrypted) = &protobufs.unencrypted {
            DecryptedProtobuf {
                message: BackupMessage::decode(unencrypted.message.as_slice())
                    .map_err(ArchiveError::Unencrypted)?,
                timestamp_ms: unencrypted.timestamp_ms,
            }
        } else if let Some(stanza) = &protobufs.message {
            stanza.decrypt(device, thread_id)?.0
        } else {
            return Err(ArchiveError::MissingPayload);
        };
        let mut supplementals = BTreeMap::new();
        for supplemental in &protobufs.supplementals {
            let (message, key) = supplemental.decrypt(device, thread_id)?;
            if key.is_empty() {
                return Err(ArchiveError::MissingSupplementalKey);
            }
            supplementals.insert(key, message);
        }
        for supplemental in &protobufs.minos_supplementals {
            if supplemental.supplemental_key.is_empty() || supplemental.supplemental_id.is_empty() {
                return Err(ArchiveError::MinosSupplemental);
            }
            let message = minos.decrypt(supplemental, &supplemental.supplemental_id)?;
            supplementals.insert(supplemental.supplemental_key.clone(), message);
        }
        Ok(DecryptedMessage {
            id: self.id.clone(),
            message,
            supplementals,
            attachments: self.attachments.clone(),
            tags: protobufs.tags.clone(),
        })
    }
}

impl MessageRange {
    /// Decrypts every message of the page that can be, skipping (and logging) the rest as
    /// mautrix does: one bad message does not cost the page. `self_user_id` and `is_group`
    /// build the thread id Minos authenticates.
    pub fn decrypt(
        &self,
        device: &Device,
        thread_id: &str,
        self_user_id: i64,
        is_group: bool,
    ) -> Vec<DecryptedMessage> {
        self.decrypt_each(device, thread_id, self_user_id, is_group)
            .into_iter()
            .filter_map(|(id, result)| {
                result
                    .inspect_err(|error| {
                        tracing::warn!(message_id = %id, %error, "Failed to decrypt Messenger archive message");
                    })
                    .ok()
            })
            .collect()
    }

    /// [`MessageRange::decrypt`] with each message's outcome, by otid. Visibility records
    /// (`EB_VISIBILITY_METADATA`) are left out, as they are not messages.
    pub fn decrypt_each(
        &self,
        device: &Device,
        thread_id: &str,
        self_user_id: i64,
        is_group: bool,
    ) -> Vec<(String, Result<DecryptedMessage, ArchiveError>)> {
        let mut minos =
            MinosReader::new(device, &self.minos_keys, thread_id, self_user_id, is_group);
        self.messages
            .iter()
            .filter(|m| {
                !m.protobufs
                    .as_ref()
                    .is_some_and(|p| p.tags.iter().any(|t| t == "EB_VISIBILITY_METADATA"))
            })
            .map(|m| (m.id.clone(), m.decrypt(device, thread_id, &mut minos)))
            .collect()
    }
}

/// The variables of `EBMessageRangeQueryForThreadsQuery` for `count` messages of a thread
/// before (or after) `timestamp_ms`, as `FetchMessages` builds them.
pub fn message_range_variables(
    device: &Device,
    app_id: &str,
    thread_id: &str,
    before: bool,
    timestamp_ms: i64,
    count: i64,
) -> Result<serde_json::Value, ArchiveError> {
    if device.id.is_empty()
        || device.backup_id.is_empty()
        || device.mailbox_root_key.is_empty()
        || device.ocmf_client_state.is_empty()
        || app_id.is_empty()
    {
        return Err(ArchiveError::NotEnrolled);
    }
    let thread_key: i64 = thread_id.parse().map_err(|_| ArchiveError::InvalidRange)?;
    if thread_key <= 0 || !(0..=(1 << 48) - 1).contains(&timestamp_ms) || count <= 0 {
        return Err(ArchiveError::InvalidRange);
    }
    let b64 = |bytes: &[u8]| {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    };
    // `Device.epochs` is ordered by id, so its keys are already sorted as Go sorts them.
    let epochs: Vec<&String> = device.epochs.keys().collect();
    // serde_json's map is ordered by key, so this serializes as Go's map does.
    let payload = serde_json::json!({
        "restore_context": {
            "act_thread_id": thread_id,
            "site": "www",
            "source": -1,
            "tam_thread_subtype": 0,
        },
        "success": {
            "device_context": {
                "device_id": device.id,
                "locally_available_epochs": epochs,
                "raw_tokens": {
                    "mailbox_root_key": b64(&device.mailbox_root_key),
                    "ocmf_client_state_blob": b64(&device.ocmf_client_state),
                },
            },
            "direction": if before { 1 } else { 2 },
            "query_num_messages": count,
            "reference_timestamp": timestamp_ms.to_string(),
            "server_thread_key": thread_key,
            "source": -1,
        },
    });
    Ok(serde_json::json!({
        "app_id": app_id,
        "includeAttachmentData": true,
        "restore_payload_strings": [payload.to_string()],
        "restore_type": "RANGE_QUERY_RESTORE",
    }))
}

/// Reads the query's `viewer` result into its one page, refusing what `FetchMessages`
/// refuses: a deleted mailbox, a server exception, another backup's page, no pagination.
pub fn parse_message_range(viewer: &[u8], device: &Device) -> Result<MessageRange, ArchiveError> {
    #[derive(serde::Deserialize)]
    struct Response {
        encrypted_backup: Option<Backup>,
    }
    #[derive(serde::Deserialize)]
    struct Backup {
        mailbox: Option<Mailbox>,
    }
    #[derive(serde::Deserialize)]
    struct Mailbox {
        #[serde(default)]
        messages_from_selected_threads: Option<Vec<Option<MessageRange>>>,
    }
    let response: Option<Response> =
        serde_json::from_slice(viewer).map_err(ArchiveError::Response)?;
    let ranges = response
        .and_then(|r| r.encrypted_backup)
        .and_then(|b| b.mailbox)
        .ok_or(ArchiveError::MissingRange)?
        .messages_from_selected_threads
        .unwrap_or_default();
    let [Some(range)] = <[_; 1]>::try_from(ranges).map_err(|_| ArchiveError::MissingRange)? else {
        return Err(ArchiveError::MissingRange);
    };
    if range.delete_mailbox {
        return Err(ArchiveError::MailboxDeleted);
    } else if range.exception.is_some() {
        return Err(if range.thread_missing {
            ArchiveError::ThreadMissing
        } else {
            ArchiveError::Rejected
        });
    } else if !range.backup_id.is_empty() && range.backup_id != device.backup_id {
        return Err(ArchiveError::OtherBackup);
    } else if range
        .range
        .as_ref()
        .is_none_or(|r| r.has_more_before.is_none() || r.has_more_after.is_none())
    {
        return Err(ArchiveError::MissingPagination);
    }
    Ok(range)
}

/// Why a decrypted message does not convert (`convertArchiveMessage`'s errors).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConvertError {
    #[error("missing Messenger archive message payload")]
    MissingPayload,
    #[error("invalid archived Messenger application")]
    Application,
    #[error("unsupported archived Messenger application: {0}")]
    UnsupportedApplication(&'static str),
    #[error("{0}")]
    Armadillo(#[from] armadillo::ArmadilloError),
    #[error("missing Messenger archive message metadata")]
    Metadata,
    #[error("invalid Messenger archive sender")]
    Sender,
    #[error("missing Messenger archive supplemental metadata")]
    SupplementalMetadata,
    #[error("archive reaction references a different message")]
    ReactionTarget,
    #[error("archive edit references a different message")]
    EditTarget,
    #[error("invalid Messenger archive edit")]
    Edit,
    #[error("unsupported Messenger archive supplemental")]
    Supplemental,
}

/// An archived message as the archive keeps it: who sent it when, what it says (with its
/// latest edit folded in), and the reactions standing on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackfillMessage {
    pub id: String,
    pub sender: String,
    pub timestamp_ms: i64,
    pub content: Content,
    /// When the content is an edit's: the edit's own timestamp, else its stanza's.
    pub edit_timestamp_ms: Option<i64>,
    /// Ordered by sender.
    pub reactions: Vec<BackfillReaction>,
    /// Where each attachment is on the CDN, by object id (`ContextKeyWAMediaPaths`).
    pub media_paths: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackfillReaction {
    pub sender: String,
    pub timestamp_ms: i64,
    pub emoji: String,
}

/// A `BackupMessage` decoded as `decodeArchiveMessage` decodes it.
struct Decoded {
    sender: String,
    /// The `MessageApplication` bytes, for [`armadillo::decode`].
    application: Option<Vec<u8>>,
    consumer: Option<ConsumerApplication>,
    armadillo: Option<Armadillo>,
}

/// `whatsmeow.DecodeFBApplication`: the sub-protocol inside, refusing the payload kinds it
/// refuses. Business, payment and VoIP payloads decode to nothing, as there.
fn decode_application(
    bytes: &[u8],
) -> Result<(Option<ConsumerApplication>, Option<Armadillo>), ConvertError> {
    let application = MessageApplication::decode(bytes).map_err(|_| ConvertError::Application)?;
    let Some(payload) = application.payload else {
        return Ok((None, None));
    };
    let unsupported = ConvertError::UnsupportedApplication;
    let sub = match payload {
        ApplicationPayload {
            sub_protocol: Some(sub),
            ..
        } => sub,
        ApplicationPayload {
            core_content: Some(_),
            ..
        } => return Err(unsupported("core content")),
        ApplicationPayload {
            signal: Some(_), ..
        } => return Err(unsupported("signal")),
        ApplicationPayload {
            application_data: Some(_),
            ..
        } => return Err(unsupported("application data")),
        _ => return Err(unsupported("no content")),
    };
    fn open<M: Message + Default>(
        sub: &SubProtocol,
        version: i32,
        what: &'static str,
    ) -> Result<M, ConvertError> {
        match sub.decode(version) {
            Some(Ok(message)) => Ok(message),
            Some(Err(_)) => Err(ConvertError::Application),
            None => Err(armadillo::ArmadilloError::Version(what, sub.version.unwrap_or(0)).into()),
        }
    }
    if let Some(consumer) = &sub.consumer_message {
        Ok((
            Some(open(
                consumer,
                CONSUMER_APPLICATION_VERSION,
                "ConsumerApplication",
            )?),
            None,
        ))
    } else if let Some(armadillo) = &sub.armadillo {
        Ok((
            None,
            Some(open(armadillo, ARMADILLO_APPLICATION_VERSION, "Armadillo")?),
        ))
    } else if let Some(multi_device) = &sub.multi_device {
        open::<super::proto::Empty>(
            multi_device,
            MULTI_DEVICE_APPLICATION_VERSION,
            "MultiDevice",
        )?;
        Ok((None, None))
    } else if sub.business_message.is_some() || sub.payment_message.is_some() || sub.voip.is_some()
    {
        Ok((None, None))
    } else {
        Err(unsupported("no sub-protocol"))
    }
}

/// `decodeArchiveMessage`: `None` for a transport event, which converts to nothing.
fn decode_archive_message(
    message: &BackupMessage,
    timestamp_ms: i64,
) -> Result<Option<Decoded>, ConvertError> {
    let (application, (consumer, armadillo)) = match &message.payload {
        Some(BackupPayload::EncryptedTransportMessage(bytes)) => {
            (Some(bytes.clone()), decode_application(bytes)?)
        }
        Some(
            BackupPayload::EncryptedTransportEvent(_)
            | BackupPayload::EncryptedTransportLocallyTransformedMessage(_),
        ) => return Ok(None),
        Some(BackupPayload::MiTransportAdminMessage(_)) => (None, (None, None)),
        None => return Err(ConvertError::MissingPayload),
    };
    if message.message_id().is_empty() || message.sender_id().is_empty() || timestamp_ms < 0 {
        return Err(ConvertError::Metadata);
    }
    message
        .sender_id()
        .parse::<i64>()
        .map_err(|_| ConvertError::Sender)?;
    Ok(Some(Decoded {
        sender: message.sender_id().to_string(),
        application,
        consumer,
        armadillo,
    }))
}

impl DecryptedMessage {
    /// `convertArchiveMessage` without the bridge: the message's content, its latest edit and
    /// its reactions. `None` for a message that converts to nothing (a transport event).
    pub fn convert(&self) -> Result<Option<BackfillMessage>, ConvertError> {
        let Some(parent) =
            decode_archive_message(&self.message.message, self.message.timestamp_ms)?
        else {
            return Ok(None);
        };
        let parent_id = self.message.message.message_id();
        let mut reactions: BTreeMap<String, BackfillReaction> = BTreeMap::new();
        let mut latest_edit: Option<(String, Option<i64>, i64)> = None;
        for supplemental in self.supplementals.values() {
            if !matches!(
                supplemental.message.payload,
                Some(BackupPayload::EncryptedTransportMessage(_)) | None
            ) {
                continue;
            }
            let timestamp_ms = supplemental
                .message
                .timestamp_ms()
                .ok_or(ConvertError::SupplementalMetadata)?;
            let Some(decoded) = decode_archive_message(&supplemental.message, timestamp_ms)? else {
                continue;
            };
            let content = decoded
                .consumer
                .as_ref()
                .and_then(|c| c.payload.as_ref())
                .and_then(|p| p.content.as_ref());
            let target = |key: &Option<super::proto::MessageKey>| {
                key.as_ref()
                    .and_then(|k| k.id.clone())
                    .filter(|id| !id.is_empty() && id != parent_id)
            };
            if let Some(reaction) = content.and_then(|c| c.reaction_message.as_ref()) {
                if target(&reaction.key).is_some() {
                    return Err(ConvertError::ReactionTarget);
                }
                let emoji = reaction.text.clone().unwrap_or_default();
                let keep = reactions.get(&decoded.sender).is_none_or(|previous| {
                    timestamp_ms > previous.timestamp_ms
                        || (timestamp_ms == previous.timestamp_ms && emoji.is_empty())
                });
                if keep {
                    reactions.insert(
                        decoded.sender.clone(),
                        BackfillReaction {
                            sender: decoded.sender,
                            timestamp_ms,
                            emoji,
                        },
                    );
                }
            } else if let Some(edit) = content.and_then(|c| c.edit_message.as_ref()) {
                if target(&edit.key).is_some() {
                    return Err(ConvertError::EditTarget);
                }
                let Some(text) = edit
                    .message
                    .as_ref()
                    .filter(|_| decoded.sender == parent.sender)
                else {
                    return Err(ConvertError::Edit);
                };
                if latest_edit
                    .as_ref()
                    .is_none_or(|(_, _, at)| timestamp_ms > *at)
                {
                    latest_edit = Some((
                        text.text.clone().unwrap_or_default(),
                        edit.timestamp_ms,
                        timestamp_ms,
                    ));
                }
            } else {
                // A poll's votes, and armadillo notices without content, are passed over.
                let poll_vote = content.is_some_and(|c| c.poll_update_message.is_some())
                    && parent
                        .consumer
                        .as_ref()
                        .and_then(|c| c.payload.as_ref())
                        .and_then(|p| p.content.as_ref())
                        .is_some_and(|c| c.poll_creation_message.is_some());
                let notice = decoded.armadillo.as_ref().is_some_and(|a| {
                    a.payload
                        .as_ref()
                        .and_then(|p| p.content.as_ref())
                        .is_none_or(|c| c.raven_action_notif_message.is_some())
                });
                if !poll_vote && !notice {
                    return Err(ConvertError::Supplemental);
                }
            }
        }
        let content = match &parent.application {
            // The archive keeps the bare `MessageApplication`; the decoder reads it inside the
            // `MessageTransport` (at the application's version, 2) that a live message has.
            Some(application) => armadillo::decode(&wrap_application(application))?,
            None => Content::Other("admin message".into()),
        };
        let (content, edit_timestamp_ms) = match latest_edit {
            Some((text, edited_at, stanza_at)) => {
                // The edit replaces the content, not the application's reply metadata.
                let reply_to = parent
                    .application
                    .as_deref()
                    .and_then(|a| MessageApplication::decode(a).ok())
                    .and_then(|a| a.metadata?.quoted_message?.stanza_id);
                (
                    Content::Text { text, reply_to },
                    Some(edited_at.filter(|&t| t != 0).unwrap_or(stanza_at)),
                )
            }
            None => (content, None),
        };
        Ok(Some(BackfillMessage {
            id: parent_id.to_string(),
            sender: parent.sender,
            timestamp_ms: self.message.timestamp_ms,
            content,
            edit_timestamp_ms,
            reactions: reactions
                .into_values()
                .filter(|r| !r.emoji.is_empty())
                .collect(),
            media_paths: self
                .attachments
                .iter()
                .filter(|a| !a.object_id.is_empty() && !a.url.is_empty())
                .map(|a| (a.object_id.clone(), a.url.clone()))
                .collect(),
        }))
    }
}

/// `MessageTransport{payload: {applicationPayload: {payload, version: 2}}}` around bytes.
fn wrap_application(application: &[u8]) -> Vec<u8> {
    #[derive(Clone, PartialEq, Message)]
    struct Transport {
        #[prost(message, optional, tag = "1")]
        payload: Option<TransportPayload>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct TransportPayload {
        #[prost(message, optional, tag = "1")]
        application_payload: Option<SubProtocol>,
    }
    Transport {
        payload: Some(TransportPayload {
            application_payload: Some(SubProtocol {
                payload: Some(application.to_vec()),
                version: Some(2),
            }),
        }),
    }
    .encode_to_vec()
}
