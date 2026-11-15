//! Messenger's encrypted history backup ("secure storage"), read side: recover the backup
//! with the account's PIN, join it as a history device, and decrypt the archived messages of
//! end-to-end encrypted chats. Ported from mautrix-meta's `pkg/messagix/securehistory`
//! (AGPL-3.0, like this crate); only restoring is ported, not uploading sent messages.
//!
//! The flow, as mautrix's `login_history.go` runs it: the backup's ids
//! (`useMWEncryptedBackupsFetchBackupIdsV2Query`), PIN recovery against Meta's HSM over
//! OPAQUE ([`vesta`], [`opaque`]), the virtual device that recovery unlocks ([`device`]),
//! its epoch keys ([`epochs`]), enrolment of a history device ([`enrollment`]), then pages of
//! archived messages, decrypted by [`archive`], [`echo`] or [`minos`] by their format.
//!
//! Byte fields arrive as standard base64 in JSON (Go's `[]byte`), and `,string` integers as
//! strings: [`b64`] and [`int_string`] read them as Go writes them.

pub mod aead;
pub mod archive;
pub mod device;
pub mod echo;
pub mod enrollment;
pub mod epochs;
pub mod minos;
pub mod opaque;
pub mod vesta;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `[]byte` as Go's `encoding/json` writes it: standard base64 with padding, `null` as empty.
pub mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        match Option::<String>::deserialize(d)? {
            None => Ok(Vec::new()),
            Some(text) => STANDARD.decode(text).map_err(serde::de::Error::custom),
        }
    }
}

/// A list or map Go may write as `null`: read as empty, as Go's own decoding leaves it.
pub mod nullable {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de> + Default,
    {
        Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
    }
}

/// An `int64` tagged `,string`: a JSON string holding the number.
pub mod int_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &i64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
        match Option::<String>::deserialize(d)? {
            None => Ok(0),
            Some(text) => text.parse().map_err(serde::de::Error::custom),
        }
    }
}

/// The account's backup, from `useMWEncryptedBackupsFetchBackupIdsV2Query`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Backup {
    #[serde(default)]
    pub id: String,
    #[serde(default, rename = "encryption_management_delegator_id")]
    pub delegator_id: String,
    #[serde(default, rename = "virtual_devices", deserialize_with = "nullable::deserialize")]
    pub devices: Vec<BackupDevice>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackupDevice {
    #[serde(default, rename = "device_type")]
    pub kind: String,
    #[serde(default, rename = "client_generated_id")]
    pub client_id: String,
}

impl Backup {
    /// The HSM device's client id: the `fbid` PIN recovery asks for (the last one, as Go).
    pub fn vesta_id(&self) -> Option<&str> {
        self.devices
            .iter()
            .rev()
            .find(|d| d.kind == "HSM")
            .map(|d| d.client_id.as_str())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EncryptedSecrets {
    #[serde(default, with = "b64", rename = "encrypted_epoch_anon_id")]
    pub epoch_anon_id: Vec<u8>,
    #[serde(default, with = "b64", rename = "encrypted_epoch_root_key")]
    pub epoch_root_key: Vec<u8>,
    #[serde(default, with = "b64", rename = "encrypted_epoch_storage_private_key")]
    pub epoch_storage_private_key: Vec<u8>,
    #[serde(default, with = "b64", rename = "encrypted_mailbox_root_key_blob")]
    pub mailbox_root_key: Vec<u8>,
    #[serde(default, with = "b64", rename = "encrypted_oblivious_validation_token_blob")]
    pub oblivious_validation_token: Vec<u8>,
    #[serde(default, with = "b64", rename = "encrypted_ocmf_client_state")]
    pub ocmf_client_state: Vec<u8>,
    #[serde(default, with = "b64", rename = "encrypted_orf_client_state_v2")]
    pub orf_client_state: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MinosEpoch {
    #[serde(default, with = "b64", rename = "epoch_head")]
    pub head: Vec<u8>,
    #[serde(default, with = "b64", rename = "self_epoch_signature")]
    pub self_signature: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochData {
    #[serde(default, with = "b64", rename = "epoch_anon_id")]
    pub anon_id: Vec<u8>,
    #[serde(default, with = "b64", rename = "epoch_root_key")]
    pub root_key: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncEpoch {
    #[serde(default, rename = "epoch_id")]
    pub id: String,
    #[serde(default)]
    pub backup_id: String,
    #[serde(default, rename = "epoch_anon_id")]
    pub anon_id: String,
    #[serde(default, with = "b64", rename = "epoch_auth_public_key")]
    pub auth_public_key: Vec<u8>,
    #[serde(default, with = "b64", rename = "encrypted_epoch_key")]
    pub encrypted_key: Vec<u8>,
    #[serde(default, rename = "is_active_epoch")]
    pub active: bool,
    #[serde(default, rename = "next_epoch_id")]
    pub next_id: String,
    #[serde(default, rename = "prev_epoch_id")]
    pub previous_id: String,
    #[serde(default, rename = "epoch_data_v2")]
    pub encrypted_data: Option<EpochData>,
    #[serde(default, rename = "minos_epoch")]
    pub minos: Option<MinosEpoch>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochRefId {
    #[serde(default, rename = "epoch_id")]
    pub id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackwardEdge {
    #[serde(default, rename = "from_epoch")]
    pub from: EpochRefId,
    #[serde(default, with = "b64", rename = "backward_edge")]
    pub backward_edge: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VirtualDeviceInfo {
    #[serde(default, rename = "encrypted_secret_values")]
    pub secrets: Option<EncryptedSecrets>,
    #[serde(default)]
    pub epoch_id: String,
    #[serde(default, with = "b64")]
    pub epoch_storage_public_key: Vec<u8>,
    #[serde(default)]
    pub last_epoch_id: String,
    #[serde(default, rename = "sync_epochs", deserialize_with = "nullable::deserialize")]
    pub epochs: Vec<SyncEpoch>,
    #[serde(default, rename = "minos_epoch")]
    pub minos: Option<MinosEpoch>,
    #[serde(default, rename = "epoch_edges", deserialize_with = "nullable::deserialize")]
    pub edges: Vec<BackwardEdge>,
}

/// What PIN recovery unlocks: the backup's virtual device, its id and the key its secrets
/// are sealed with (both from the recovery code), and what the server holds for it.
#[derive(Debug, Clone, Default)]
pub struct VirtualDevice {
    pub id: Vec<u8>,
    pub blob_key: Vec<u8>,
    pub info: VirtualDeviceInfo,
}

/// One epoch's keys, with the field names mautrix stores them under.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Epoch {
    pub id: String,
    #[serde(with = "b64")]
    pub anon_id: Vec<u8>,
    #[serde(with = "b64")]
    pub root_key: Vec<u8>,
}

/// The enrolled history device, kept between runs: what reading the archive needs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub backup_id: String,
    #[serde(with = "b64")]
    pub storage_public_key: Vec<u8>,
    #[serde(with = "b64")]
    pub storage_private_key: Vec<u8>,
    #[serde(with = "b64")]
    pub mailbox_root_key: Vec<u8>,
    #[serde(with = "b64")]
    pub ocmf_client_state: Vec<u8>,
    #[serde(default, deserialize_with = "nullable::deserialize")]
    pub epochs: BTreeMap<String, Epoch>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochRef {
    #[serde(default, rename = "epoch_id")]
    pub id: String,
    #[serde(default, rename = "epoch_anon_id")]
    pub anon_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochForwardEdge {
    #[serde(default, with = "b64")]
    pub auth_public_key: Vec<u8>,
    #[serde(default, with = "b64")]
    pub encrypted_entropy: Vec<u8>,
    #[serde(default)]
    pub entropy_fingerprint: String,
    #[serde(default, with = "b64", rename = "epoch_storage_public_key")]
    pub storage_public_key: Vec<u8>,
    #[serde(default)]
    pub psk_fingerprint: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochEdge {
    #[serde(default, rename = "from_epoch")]
    pub from: EpochRef,
    #[serde(default, rename = "to_epoch")]
    pub to: EpochRef,
    #[serde(default, with = "b64", rename = "backward_edge")]
    pub backward: Vec<u8>,
    #[serde(default, rename = "forward_edge")]
    pub forward: Option<EpochForwardEdge>,
    #[serde(default, rename = "from_epoch_fingerprint")]
    pub from_fingerprint: String,
    #[serde(default, rename = "to_epoch_fingerprint")]
    pub to_fingerprint: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpochDerivationSet {
    #[serde(default, rename = "epoch_edges", deserialize_with = "nullable::deserialize")]
    pub edges: Vec<EpochEdge>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageRangeInfo {
    #[serde(default)]
    pub has_more_before: Option<bool>,
    #[serde(default)]
    pub has_more_after: Option<bool>,
    #[serde(default, with = "int_string", rename = "next_message_timestamp_ms_before")]
    pub before: i64,
    #[serde(default, with = "int_string", rename = "next_message_timestamp_ms_after")]
    pub after: i64,
}

/// One page of a thread's archive, from `EBMessageRangeQueryForThreadsQuery`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageRange {
    #[serde(default)]
    pub backup_id: String,
    #[serde(default, rename = "encrypted_messages", deserialize_with = "nullable::deserialize")]
    pub messages: Vec<ArchiveMessage>,
    #[serde(default, rename = "message_range_info")]
    pub range: Option<MessageRangeInfo>,
    #[serde(default, rename = "epoch_derivation_set")]
    pub epochs: Option<EpochDerivationSet>,
    #[serde(default, rename = "minos_decryption_keys", deserialize_with = "nullable::deserialize")]
    pub minos_keys: Vec<MinosKeyEntry>,
    #[serde(default, rename = "exception_string")]
    pub exception: Option<String>,
    #[serde(default, rename = "thread_not_found")]
    pub thread_missing: bool,
    #[serde(default, rename = "should_delete_mailbox")]
    pub delete_mailbox: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchiveAttachment {
    #[serde(default, rename = "attachment_cdn_url")]
    pub url: String,
    #[serde(default, rename = "attachment_object_id")]
    pub object_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchiveProtobuf {
    #[serde(default, with = "b64", rename = "encrypted_protobuf_stanza")]
    pub encrypted: Vec<u8>,
    #[serde(default)]
    pub encryption_version: String,
    #[serde(default)]
    pub epoch_id: String,
    #[serde(default)]
    pub epoch_anon_id: String,
    #[serde(default, with = "int_string", rename = "protobuf_timestamp_ms")]
    pub timestamp_ms: i64,
    #[serde(default)]
    pub supplemental_key: String,
    #[serde(default, rename = "supplemental_otid")]
    pub supplemental_id: String,
    #[serde(default, with = "b64", rename = "sk_ciphertext")]
    pub key_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MinosProtobuf {
    #[serde(default)]
    pub actor_token: String,
    #[serde(default, with = "b64", rename = "encrypted_protobuf")]
    pub encrypted: Vec<u8>,
    #[serde(default)]
    pub mek_fbid: String,
    #[serde(default, with = "b64")]
    pub mek_id: Vec<u8>,
    #[serde(default, with = "int_string", rename = "protobuf_timestamp")]
    pub timestamp: i64,
    #[serde(default, with = "b64", rename = "transport_sender_signing_pk")]
    pub transport_signing_pk: Vec<u8>,
    #[serde(default, with = "b64", rename = "transport_sender_message_signature")]
    pub signature: Vec<u8>,
    #[serde(default, rename = "message_encryption_version")]
    pub encryption_version: i64,
    #[serde(default, rename = "message_metadata_version")]
    pub metadata_version: i64,
    #[serde(default)]
    pub server_origin_content_type: serde_json::Value,
    #[serde(default)]
    pub supplemental_key: String,
    #[serde(default, rename = "supplemental_otid")]
    pub supplemental_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MinosKeyEntry {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub keys: Option<MinosKeyData>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MinosKeyData {
    #[serde(default)]
    pub mek_info: Option<MinosMekInfo>,
    #[serde(default)]
    pub recipient_info: Option<MinosRecipientInfo>,
    #[serde(default, rename = "mek_creator_info")]
    pub creator_info: Option<MinosCreatorInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MinosMekInfo {
    #[serde(default, with = "b64", rename = "mek_id")]
    pub id: Vec<u8>,
    #[serde(default, with = "b64")]
    pub roster_hash: Vec<u8>,
    #[serde(default, with = "b64", rename = "encrypted_mek")]
    pub encrypted: Vec<u8>,
    #[serde(default, with = "int_string", rename = "mek_creation_timestamp")]
    pub creation_timestamp: i64,
    #[serde(default, rename = "mek_encryption_version")]
    pub encryption_version: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MinosRecipientInfo {
    #[serde(default, rename = "epoch_fbid")]
    pub epoch_id: String,
    #[serde(default, with = "b64", rename = "epoch_anon_id")]
    pub epoch_anon: Vec<u8>,
    #[serde(default, with = "b64")]
    pub epoch_head: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MinosCreatorKeys {
    #[serde(default, with = "b64", rename = "sender_auth_pk")]
    pub auth_public_key: Vec<u8>,
    #[serde(default, with = "b64", rename = "sender_epoch_head")]
    pub epoch_head: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MinosTransportKeys {
    #[serde(default, with = "b64", rename = "ephm_hpke_pk")]
    pub ephemeral_public_key: Vec<u8>,
    #[serde(default, with = "b64", rename = "ephm_signature")]
    pub signature: Vec<u8>,
    #[serde(default, with = "b64", rename = "mek_creator_transport_signing_pk")]
    pub signing_public_key: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MinosCreatorInfo {
    #[serde(default, rename = "minos_keys")]
    pub minos: Option<MinosCreatorKeys>,
    #[serde(default, rename = "transport_keys")]
    pub transport: Option<MinosTransportKeys>,
    #[serde(default, rename = "mandrake_keys")]
    pub mandrake: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EchoDocument {
    #[serde(default, with = "b64", rename = "echo_document_string")]
    pub document: Vec<u8>,
    #[serde(default)]
    pub encryption_version: String,
    #[serde(default)]
    pub epoch_anon_id: String,
    #[serde(default)]
    pub epoch_id: Option<String>,
    #[serde(default)]
    pub epoch_fingerprint: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnencryptedProtobuf {
    #[serde(default, with = "b64", rename = "unencrypted_protobuf")]
    pub message: Vec<u8>,
    #[serde(default, with = "int_string", rename = "protobuf_timestamp_ms")]
    pub timestamp_ms: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchiveProtobufs {
    #[serde(default, rename = "top_level_protobuf")]
    pub message: Option<ArchiveProtobuf>,
    #[serde(default, rename = "supplemental_protobufs", deserialize_with = "nullable::deserialize")]
    pub supplementals: Vec<ArchiveProtobuf>,
    #[serde(default, rename = "top_level_protobuf_unencrypted")]
    pub unencrypted: Option<UnencryptedProtobuf>,
    #[serde(default, rename = "top_level_protobuf_v2")]
    pub minos_message: Option<MinosProtobuf>,
    #[serde(default, rename = "supplemental_protobufs_v2", deserialize_with = "nullable::deserialize")]
    pub minos_supplementals: Vec<MinosProtobuf>,
    #[serde(default, rename = "message_tags", deserialize_with = "nullable::deserialize")]
    pub tags: Vec<String>,
}

/// One archived message as the page lists it: `otid` is its id.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchiveMessage {
    #[serde(default, rename = "otid")]
    pub id: String,
    #[serde(default, rename = "attachment_data", deserialize_with = "nullable::deserialize")]
    pub attachments: Vec<ArchiveAttachment>,
    #[serde(default, rename = "echo_document")]
    pub echo: Option<EchoDocument>,
    #[serde(default, rename = "protobuf_stanzas")]
    pub protobufs: Option<ArchiveProtobufs>,
}
