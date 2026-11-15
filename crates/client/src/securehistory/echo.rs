//! Echo documents: the archive's older format, a message kept as mail-style header fields
//! (`Key: value` lines ending in CRLF) sealed like a stanza. Ported from mautrix's `echo.go`,
//! which rebuilds each document into the `BackupMessage` a stanza would have decrypted to,
//! so everything after decryption reads one format; this does the same, byte for byte.

use std::collections::BTreeMap;

use base64::Engine;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use prost::Message;

use super::archive::{
    ArchiveError, DecryptedMessage, DecryptedProtobuf, archive_encryption_version,
    decrypt_archive_payload,
};
use super::minos::parse_uint;
use super::proto::{
    ARMADILLO_APPLICATION_VERSION, ApplicationMetadata, ApplicationPayload, Armadillo,
    ArmadilloContent, ArmadilloPayload, AudioAncillary, AudioMessage, AudioTransport,
    BackupMessage, BackupPayload, CONSUMER_APPLICATION_VERSION, CTA_OPEN_NATIVE, CaptionedMedia,
    ConsumerApplication, ConsumerContent, ConsumerPayload, Cta, DocumentMessage, DocumentTransport,
    EXTENDED_CONTENT_TYPES, EditMessage, Empty, ExtendedContentMessage, ImageAncillary,
    ImageTransport, MEDIA_TRANSPORT_VERSION, MessageApplication, MessageKey, MessageText, Metadata,
    OVERLAY_ICON_GLYPHS, QuotedMessage, ReactionMessage, StickerAncillary, StickerMessage,
    StickerTransport, SubProtocol, SubProtocolPayload, TransportIntegral, VideoAncillary,
    VideoTransport, WaMediaAncillary, WaMediaIntegral, WaMediaTransport, XMA_LAYOUT_TYPES,
    enum_value,
};
use super::{ArchiveMessage, Device, EchoDocument};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EchoError {
    #[error("invalid Echo field encoding")]
    Encoding,
    #[error("invalid Echo field")]
    Field,
    #[error("missing or mismatched Echo message metadata")]
    Metadata,
    #[error("invalid Echo sender address")]
    SenderAddress,
    #[error("invalid Echo sender ID")]
    SenderId,
    #[error("unsupported Echo content type {0:?}")]
    ContentType(String),
    #[error("invalid Echo edit timestamp")]
    EditTimestamp,
    #[error("invalid Echo reactions")]
    Reactions,
    #[error("invalid Echo reaction IDs")]
    ReactionIds,
    #[error("mismatched Echo reaction metadata")]
    ReactionCount,
    #[error("invalid Echo reaction metadata")]
    Reaction,
    #[error("invalid Echo media {0}")]
    MediaField(&'static str),
    #[error("missing Echo attachment metadata")]
    Attachment,
    #[error("invalid Echo media dimensions")]
    Dimensions,
    #[error("unsupported Echo attachment type {0:?}")]
    AttachmentType(String),
    #[error("unsupported Echo XMA target type")]
    XmaTarget,
}

impl ArchiveMessage {
    /// Opens the message's Echo document under its epoch (named, or found by anonymous id)
    /// and rebuilds it into protobufs.
    pub(crate) fn decrypt_echo(
        &self,
        echo: &EchoDocument,
        device: &Device,
        thread_id: &str,
    ) -> Result<DecryptedMessage, ArchiveError> {
        let anon = echo.epoch_anon_id.as_bytes();
        let epoch = match &echo.epoch_id {
            Some(id) => device.epochs.get(id),
            // Go takes the first match of a map; a BTreeMap's first is the lowest epoch id.
            None => device.epochs.values().find(|e| e.anon_id == anon),
        };
        let epoch = epoch
            .filter(|e| !anon.is_empty() && e.anon_id == anon && e.root_key.len() == 32)
            .ok_or(ArchiveError::EchoEpoch)?;
        let version = archive_encryption_version(&echo.encryption_version)?;
        let plaintext = decrypt_archive_payload(
            &epoch.root_key,
            &echo.epoch_anon_id,
            thread_id,
            version,
            &echo.document,
        )?;
        let mut result = decode_echo(&plaintext, &self.id)?;
        result.attachments = self.attachments.clone();
        Ok(result)
    }
}

/// A document's fields; a later line wins, and an empty value removes the field.
struct EchoFields(BTreeMap<String, String>);

fn parse_echo(data: &[u8]) -> Result<EchoFields, EchoError> {
    let text = std::str::from_utf8(data).map_err(|_| EchoError::Encoding)?;
    if !text.contains("\r\n") {
        return Err(EchoError::Encoding);
    }
    let mut fields = BTreeMap::new();
    for line in text.split("\r\n").filter(|l| !l.is_empty()) {
        let (key, value) = line.split_once(':').ok_or(EchoError::Field)?;
        let (key, value) = (key.trim(), value.trim());
        if key.is_empty() {
            return Err(EchoError::Field);
        } else if value.is_empty() {
            fields.remove(key);
        } else {
            fields.insert(key.to_string(), value.to_string());
        }
    }
    Ok(EchoFields(fields))
}

impl EchoFields {
    fn raw(&self, key: &str) -> &str {
        self.0.get(key).map_or("", String::as_str)
    }

    /// The value, unquoted if it is quoted (`\r` and `\n` escaped, anything else after a
    /// backslash taken as is); an unterminated quote reads as empty.
    fn text(&self, key: &str) -> String {
        let value = self.raw(key).as_bytes();
        if value.first() != Some(&b'"') {
            return self.raw(key).to_string();
        }
        let mut out = Vec::new();
        let mut i = 1;
        while i < value.len() {
            match value[i] {
                b'"' => {
                    return String::from_utf8(out)
                        .expect("only ASCII bytes of valid UTF-8 are dropped or replaced");
                }
                b'\\' => {
                    i += 1;
                    match value.get(i) {
                        None => return String::new(),
                        Some(b'r') => out.push(b'\r'),
                        Some(b'n') => out.push(b'\n'),
                        Some(&c) => out.push(c),
                    }
                }
                c => out.push(c),
            }
            i += 1;
        }
        String::new()
    }

    /// Go's `strconv.ParseInt(value, 10, 64)` of the raw value, when it parses.
    fn integer(&self, key: &str) -> Option<i64> {
        self.raw(key).parse().ok()
    }

    /// What `strconv.ParseInt` returns beside its error, for the reads that ignore it: an
    /// out-of-range number as the nearest bound, anything else unparsable as 0.
    fn integer_or_bound(&self, key: &str) -> i64 {
        use std::num::IntErrorKind;
        self.raw(key)
            .parse()
            .unwrap_or_else(|e: std::num::ParseIntError| match e.kind() {
                IntErrorKind::PosOverflow => i64::MAX,
                IntErrorKind::NegOverflow => i64::MIN,
                _ => 0,
            })
    }
}

/// The user id in a sender's address: the local part, a non-zero number.
fn echo_sender(value: &str) -> Result<String, EchoError> {
    let address = mail::parse_address(value).map_err(|_| EchoError::SenderAddress)?;
    let id = address
        .address
        .split_once('@')
        .map_or(address.address.as_str(), |(id, _)| id);
    match parse_uint(id) {
        Some(n) if n != 0 => Ok(id.to_string()),
        _ => Err(EchoError::SenderId),
    }
}

fn echo_protobuf(
    content: ConsumerContent,
    metadata: Option<ApplicationMetadata>,
    id: &str,
    sender: &str,
    timestamp: i64,
) -> DecryptedProtobuf {
    let consumer = ConsumerApplication {
        payload: Some(ConsumerPayload {
            content: Some(content),
        }),
    };
    echo_application(
        sub_protocol_application(
            SubProtocolPayload {
                consumer_message: Some(SubProtocol::of(&consumer, CONSUMER_APPLICATION_VERSION)),
                ..Default::default()
            },
            metadata,
        ),
        id,
        sender,
        timestamp,
    )
}

fn sub_protocol_application(
    sub: SubProtocolPayload,
    metadata: Option<ApplicationMetadata>,
) -> MessageApplication {
    MessageApplication {
        payload: Some(ApplicationPayload {
            sub_protocol: Some(sub),
            ..Default::default()
        }),
        metadata,
    }
}

fn echo_metadata(id: &str, sender: &str, timestamp: i64) -> Metadata {
    Metadata {
        sender_id: Some(sender.to_string()),
        message_id: Some(id.to_string()),
        timestamp_ms: Some(timestamp),
        ..Default::default()
    }
}

fn echo_application(
    application: MessageApplication,
    id: &str,
    sender: &str,
    timestamp: i64,
) -> DecryptedProtobuf {
    DecryptedProtobuf {
        timestamp_ms: timestamp,
        message: BackupMessage {
            metadata: Some(echo_metadata(id, sender, timestamp)),
            payload: Some(BackupPayload::EncryptedTransportMessage(
                application.encode_to_vec(),
            )),
        },
    }
}

fn message_text(text: String) -> Option<MessageText> {
    Some(MessageText { text: Some(text) })
}

fn key(id: &str) -> Option<MessageKey> {
    Some(MessageKey {
        id: Some(id.to_string()),
    })
}

fn decode_echo(data: &[u8], id: &str) -> Result<DecryptedMessage, EchoError> {
    let fields = parse_echo(data)?;
    let timestamp = fields
        .integer("Sort-Order")
        .filter(|&t| t >= 0)
        .filter(|_| {
            !fields.text("Message-ID").is_empty()
                && !fields.text("Thread-ID").is_empty()
                && fields.text("X-Offline-Threading-ID") == id
        })
        .ok_or(EchoError::Metadata)?;
    let sender = echo_sender(fields.raw("From"))?;
    let content_type = fields.text("Message-Content-Type");
    if fields.raw("Is-Tombstoned") == "1"
        || content_type == "decryption_failure"
        || (content_type == "placeholder" && fields.text("Message-Content-Subtype") == "unsend")
    {
        return Ok(DecryptedMessage {
            id: id.to_string(),
            message: DecryptedProtobuf {
                timestamp_ms: timestamp,
                message: BackupMessage {
                    metadata: Some(echo_metadata(id, &sender, timestamp)),
                    payload: Some(BackupPayload::EncryptedTransportEvent(
                        SubProtocol::default(),
                    )),
                },
            },
            supplementals: BTreeMap::new(),
            attachments: Vec::new(),
            tags: Vec::new(),
        });
    }
    let mut metadata = ApplicationMetadata {
        is_forwarded: Some(fields.raw("Is-Forwarded") == "1"),
        quoted_message: None,
    };
    let quote = fields.text("Reply-Message-Id");
    if !quote.is_empty() {
        let participant = echo_sender(fields.raw("Reply-Message-Sender"))?;
        metadata.quoted_message = Some(QuotedMessage {
            stanza_id: Some(quote),
            participant: Some(format!("{participant}@msgr")),
        });
    }
    let message = match content_type.as_str() {
        "text"
        | "admin_message"
        | "unsupported_needs_update"
        | "null_state"
        | "placeholder"
        | "" => {
            let content = ConsumerContent {
                message_text: message_text(fields.text("Text")),
                ..Default::default()
            };
            echo_protobuf(content, Some(metadata), id, &sender, timestamp)
        }
        "xma" => fields.xma_protobuf(metadata, id, &sender, timestamp)?,
        "media" => echo_protobuf(
            fields.media_content()?,
            Some(metadata),
            id,
            &sender,
            timestamp,
        ),
        other => return Err(EchoError::ContentType(other.to_string())),
    };
    let mut supplementals = BTreeMap::new();
    for field in fields.0.keys() {
        let Some(edit_id) = field.strip_prefix("Edit-Contents-") else {
            continue;
        };
        if edit_id == id {
            continue;
        }
        let edited_at = fields
            .integer(&format!("Edit-Timestamps-{edit_id}"))
            .filter(|&t| t >= 0)
            .ok_or(EchoError::EditTimestamp)?;
        let edit = ConsumerContent {
            edit_message: Some(EditMessage {
                key: key(id),
                message: message_text(fields.text(field)),
                timestamp_ms: Some(edited_at),
            }),
            ..Default::default()
        };
        supplementals.insert(
            format!("edit:{edit_id}"),
            echo_protobuf(edit, None, edit_id, &sender, edited_at),
        );
    }
    if !fields.raw("Reactions").is_empty() {
        let reactions =
            mail::parse_address_list(fields.raw("Reactions")).map_err(|_| EchoError::Reactions)?;
        let ids = mail::parse_address_list(fields.raw("X-Reaction-Offline-Threading-IDs"))
            .map_err(|_| EchoError::ReactionIds)?;
        let timestamps = mail::parse_address_list(fields.raw("Reaction-Authoritative-Timestamps"))
            .ok()
            .filter(|t| ids.len() == reactions.len() && t.len() == reactions.len())
            .ok_or(EchoError::ReactionCount)?;
        for ((reaction, reaction_id), reacted_at) in reactions.iter().zip(&ids).zip(&timestamps) {
            let actor = echo_sender(&reaction.address)?;
            let reacted_at = reacted_at
                .name
                .parse::<i64>()
                .ok()
                .filter(|&t| t >= 0 && !reaction_id.name.is_empty())
                .ok_or(EchoError::Reaction)?;
            let content = ConsumerContent {
                reaction_message: Some(ReactionMessage {
                    key: key(id),
                    text: Some(reaction.name.clone()),
                    sender_timestamp_ms: Some(reacted_at),
                }),
                ..Default::default()
            };
            supplementals.insert(
                format!("reaction:{actor}"),
                echo_protobuf(content, None, &reaction_id.name, &actor, reacted_at),
            );
        }
    }
    Ok(DecryptedMessage {
        id: id.to_string(),
        message,
        supplementals,
        attachments: Vec::new(),
        tags: Vec::new(),
    })
}

/// Go's `base64.RawURLEncoding`: no padding, and lenient about the unused trailing bits.
const RAW_URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone),
);

/// Go's `base64.StdEncoding`: padded, and lenient about the unused trailing bits.
const STD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// Go's base64 decoders skip line breaks anywhere in the input.
fn go_base64(engine: &GeneralPurpose, text: &str) -> Option<Vec<u8>> {
    let text: String = text.chars().filter(|c| !matches!(c, '\r' | '\n')).collect();
    engine.decode(text).ok()
}

impl EchoFields {
    /// The attachment as consumer content: the kept attachment's keys (prefixed by its
    /// object id when there are several), the message's sizes, and its caption.
    fn media_content(&self) -> Result<ConsumerContent, EchoError> {
        let mut object_id = self.text("X-Object-Id");
        let mut prefix = String::new();
        let objects = self.text("X-Attachment-Object-Ids");
        if !objects.is_empty() {
            let ids: Vec<&str> = objects.split(',').map(str::trim).collect();
            object_id = ids[0].to_string();
            if let Some(kept) = ids.iter().find(|id| {
                !self.text(&format!("{id}-X-Backup-Status")).is_empty()
                    || self.text(&format!("{id}-X-Content-Type")) == "full"
            }) {
                object_id = kept.to_string();
            }
            prefix = format!("{object_id}-");
        }
        let decode = |field: &'static str| {
            let value = self.text(&format!("{prefix}{field}"));
            go_base64(&RAW_URL, value.trim_end_matches('='))
                .filter(|d| d.len() == 32)
                .ok_or(EchoError::MediaField(field))
        };
        let media_key = decode("X-Media-Key")?;
        let hash = decode("X-Plaintext-Hash")?;
        let enc_hash = decode("X-Encrypted-Hash")?;
        let path = self.text(&format!("{prefix}X-Direct-Path"));
        if object_id.is_empty() || path.is_empty() {
            return Err(EchoError::Attachment);
        }
        let size = self.integer_or_bound("Size");
        let width = self.integer_or_bound("Width");
        let height = self.integer_or_bound("Height");
        let mut duration = self.integer_or_bound("Playable-Duration");
        let key_timestamp = self.integer_or_bound(&format!("{prefix}X-Media-Key-Timestamp"));
        let u32_range = 0..=i64::from(u32::MAX);
        if size < 0
            || !u32_range.contains(&width)
            || !u32_range.contains(&height)
            || !u32_range.contains(&duration)
        {
            return Err(EchoError::Dimensions);
        }
        let transport = WaMediaTransport {
            integral: Some(WaMediaIntegral {
                file_sha256: Some(hash),
                media_key: Some(media_key),
                file_enc_sha256: Some(enc_hash),
                direct_path: Some(path),
                media_key_timestamp: Some(key_timestamp),
            }),
            ancillary: Some(WaMediaAncillary {
                file_length: Some(size as u64),
                mimetype: Some(self.text("Content-Type")),
                object_id: Some(object_id),
            }),
        };
        let integral = Some(TransportIntegral {
            transport: Some(transport),
        });
        let (width, height) = (Some(width as u32), Some(height as u32));
        let caption = message_text(self.text("Text"));
        let wrap = |payload: Vec<u8>| {
            Some(SubProtocol {
                payload: Some(payload),
                version: Some(MEDIA_TRANSPORT_VERSION),
            })
        };
        let mut content = ConsumerContent::default();
        match self.text("Attachment-Type").as_str() {
            "image" | "animated_image" => {
                let image = ImageTransport {
                    integral,
                    ancillary: Some(ImageAncillary { height, width }),
                };
                content.image_message = Some(CaptionedMedia {
                    media: wrap(image.encode_to_vec()),
                    caption,
                });
            }
            "sticker" => {
                let sticker = StickerTransport {
                    integral,
                    ancillary: Some(StickerAncillary { height, width }),
                };
                content.sticker_message = Some(StickerMessage {
                    sticker: wrap(sticker.encode_to_vec()),
                });
            }
            "video" => {
                let video = VideoTransport {
                    integral,
                    ancillary: Some(VideoAncillary {
                        seconds: Some(duration as u32),
                        height,
                        width,
                    }),
                };
                content.video_message = Some(CaptionedMedia {
                    media: wrap(video.encode_to_vec()),
                    caption,
                });
            }
            "audio" => {
                let ptt = self.text(&format!("{prefix}X-Attachment-Type")) == "1";
                // A duration in milliseconds; short clips are already in seconds.
                if duration >= 1000 {
                    duration /= 1000;
                }
                let audio = AudioTransport {
                    integral,
                    ancillary: Some(AudioAncillary {
                        seconds: Some(duration as u32),
                    }),
                };
                content.audio_message = Some(AudioMessage {
                    audio: wrap(audio.encode_to_vec()),
                    ptt: Some(ptt),
                });
            }
            "document" | "file" => {
                let document = DocumentTransport {
                    integral,
                    ancillary: Some(Empty {}),
                };
                content.document_message = Some(DocumentMessage {
                    document: wrap(document.encode_to_vec()),
                    file_name: Some(self.text("File-Name")),
                });
            }
            other => return Err(EchoError::AttachmentType(other.to_string())),
        }
        Ok(content)
    }

    /// A link or share card: an `ExtendedContentMessage` in the armadillo sub-protocol, with
    /// the document's image as its preview when it has one.
    fn xma_protobuf(
        &self,
        metadata: ApplicationMetadata,
        id: &str,
        sender: &str,
        timestamp: i64,
    ) -> Result<DecryptedProtobuf, EchoError> {
        let target = enum_value(EXTENDED_CONTENT_TYPES, &self.text("XMA-Target-Type"))
            .ok_or(EchoError::XmaTarget)?;
        let mut xma = ExtendedContentMessage {
            target_type: Some(target),
            target_id: Some(self.text("XMA-Target-ID")),
            target_username: Some(self.text("XMA-Target-Username")),
            title_text: Some(self.text("XMA-Title-Text")),
            subtitle_text: Some(self.text("XMA-Subtitle-Text")),
            header_title: Some(self.text("XMA-Header-Title")),
            header_subtitle: Some(self.text("XMA-Header-Subtitle")),
            message_text: Some(self.text("Text")),
            content_ref: Some(self.text("XMA-Content-Ref")),
            xma_dataclass: Some(self.text("XMA-Dataclass")),
            target_expiring_at_sec: self.integer("XMA-Target-Expiry"),
            xma_layout_type: enum_value(XMA_LAYOUT_TYPES, &self.text("XMA-Layout-Type")),
            overlay_icon_glyph: enum_value(OVERLAY_ICON_GLYPHS, &self.text("XMA-Gating-Type")),
            ctas: Vec::new(),
            previews: Vec::new(),
        };
        let cta = self.text("XMA-Default-CTA");
        if !cta.is_empty() {
            xma.ctas.push(Cta {
                action_url: Some(cta.clone()),
                native_url: Some(cta),
                button_type: Some(CTA_OPEN_NATIVE),
            });
        }
        if !self.text("Attachment-Type").is_empty() && !self.text("X-Media-Key").is_empty() {
            let mut fields = EchoFields(self.0.clone());
            fields.0.insert("Attachment-Type".into(), "image".into());
            let media = fields.media_content()?;
            let mut preview = media
                .image_message
                .and_then(|i| i.media)
                .expect("an image attachment is an image message");
            preview.version = Some(2);
            xma.previews.push(preview);
        }
        let armadillo = Armadillo {
            payload: Some(ArmadilloPayload {
                content: Some(ArmadilloContent {
                    extended_content_message: Some(xma),
                    raven_action_notif_message: None,
                }),
            }),
        };
        Ok(echo_application(
            sub_protocol_application(
                SubProtocolPayload {
                    armadillo: Some(SubProtocol::of(&armadillo, ARMADILLO_APPLICATION_VERSION)),
                    ..Default::default()
                },
                Some(metadata),
            ),
            id,
            sender,
            timestamp,
        ))
    }
}

/// The part of Go's `net/mail` that Echo documents use: RFC 5322 addresses and address
/// lists (`ParseAddress`, `ParseAddressList`), display names decoded from RFC 2047
/// encoded-words. Ported step for step, so it accepts and refuses what Go does.
mod mail {
    use super::{STD, go_base64};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Address {
        pub name: String,
        pub address: String,
    }

    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    #[error("mail: {0}")]
    pub struct MailError(&'static str);

    pub fn parse_address(address: &str) -> Result<Address, MailError> {
        let mut parser = Parser { s: address };
        let mut addresses = parser.parse_address(true)?;
        if !parser.skip_cfws() {
            return Err(MailError("misformatted parenthetical comment"));
        } else if !parser.s.is_empty() {
            return Err(MailError("expected single address"));
        }
        match addresses.len() {
            0 => Err(MailError("empty group")),
            1 => Ok(addresses.remove(0)),
            _ => Err(MailError("group with multiple addresses")),
        }
    }

    pub fn parse_address_list(list: &str) -> Result<Vec<Address>, MailError> {
        let mut parser = Parser { s: list };
        let mut out = Vec::new();
        loop {
            parser.skip_space();
            // Empty entries are allowed (RFC 5322 obs-addr-list).
            if parser.consume(b',') {
                continue;
            }
            out.extend(parser.parse_address(true)?);
            if !parser.skip_cfws() {
                return Err(MailError("misformatted parenthetical comment"));
            } else if parser.s.is_empty() {
                break;
            } else if parser.peek() != b',' {
                return Err(MailError("expected comma"));
            }
            while parser.consume(b',') {
                parser.skip_space();
            }
            if parser.s.is_empty() {
                break;
            }
        }
        Ok(out)
    }

    struct Parser<'a> {
        s: &'a str,
    }

    impl Parser<'_> {
        fn parse_address(&mut self, handle_group: bool) -> Result<Vec<Address>, MailError> {
            self.skip_space();
            if self.s.is_empty() {
                return Err(MailError("no address"));
            }
            // An addr-spec is tried first, then a name-addr.
            if let Ok(spec) = self.consume_addr_spec() {
                self.skip_space();
                let name = if self.s.starts_with('(') {
                    self.consume_display_name_comment()?
                } else {
                    String::new()
                };
                return Ok(vec![Address {
                    name,
                    address: spec,
                }]);
            }
            let name = if self.peek() != b'<' {
                self.consume_phrase()?
            } else {
                String::new()
            };
            self.skip_space();
            if handle_group && self.consume(b':') {
                return self.consume_group_list();
            }
            if !self.consume(b'<') {
                return Err(MailError("no angle-addr"));
            }
            let spec = self.consume_addr_spec()?;
            if !self.consume(b'>') {
                return Err(MailError("unclosed angle-addr"));
            }
            Ok(vec![Address {
                name,
                address: spec,
            }])
        }

        fn consume_group_list(&mut self) -> Result<Vec<Address>, MailError> {
            let mut group = Vec::new();
            self.skip_space();
            if self.consume(b';') {
                return if self.skip_cfws() {
                    Ok(group)
                } else {
                    Err(MailError("misformatted parenthetical comment"))
                };
            }
            loop {
                self.skip_space();
                group.extend(self.parse_address(false)?);
                if !self.skip_cfws() {
                    return Err(MailError("misformatted parenthetical comment"));
                }
                if self.consume(b';') {
                    if !self.skip_cfws() {
                        return Err(MailError("misformatted parenthetical comment"));
                    }
                    return Ok(group);
                }
                if !self.consume(b',') {
                    return Err(MailError("expected comma"));
                }
            }
        }

        /// An addr-spec, leaving the input as it was when there is none.
        fn consume_addr_spec(&mut self) -> Result<String, MailError> {
            let original = self.s;
            let result = self.addr_spec();
            if result.is_err() {
                self.s = original;
            }
            result
        }

        fn addr_spec(&mut self) -> Result<String, MailError> {
            self.skip_space();
            if self.s.is_empty() {
                return Err(MailError("no addr-spec"));
            }
            let local = if self.peek() == b'"' {
                let quoted = self.consume_quoted_string()?;
                if quoted.is_empty() {
                    return Err(MailError("empty quoted string in addr-spec"));
                }
                quoted
            } else {
                self.consume_atom(true, false)?.to_string()
            };
            if !self.consume(b'@') {
                return Err(MailError("missing @ in addr-spec"));
            }
            self.skip_space();
            if self.s.is_empty() {
                return Err(MailError("no domain in addr-spec"));
            }
            let domain = if self.peek() == b'[' {
                self.consume_domain_literal()?
            } else {
                self.consume_atom(true, false)?.to_string()
            };
            Ok(format!("{local}@{domain}"))
        }

        /// Words (atoms or quoted strings); adjacent encoded-words join without a space.
        fn consume_phrase(&mut self) -> Result<String, MailError> {
            let mut words: Vec<String> = Vec::new();
            let mut encoded = String::new();
            let mut failed = false;
            loop {
                // obs-phrase allows CFWS after one word.
                if !words.is_empty() && !self.skip_cfws() {
                    return Err(MailError("misformatted parenthetical comment"));
                }
                self.skip_space();
                if self.s.is_empty() {
                    break;
                }
                let word = if self.peek() == b'"' {
                    self.consume_quoted_string().map(|w| (w, false))
                } else {
                    // A dot-atom, more permissive than RFC 5322's atom.
                    self.consume_atom(true, true).and_then(|atom| {
                        Ok(match decode_rfc2047_word(atom)? {
                            Some(decoded) => (decoded, true),
                            None => (atom.to_string(), false),
                        })
                    })
                };
                match word {
                    Err(_) => {
                        failed = true;
                        break;
                    }
                    Ok((word, true)) => encoded.push_str(&word),
                    Ok((word, false)) => {
                        if !encoded.is_empty() {
                            words.push(std::mem::take(&mut encoded));
                        }
                        words.push(word);
                    }
                }
            }
            if !encoded.is_empty() {
                words.push(encoded);
            }
            // An error after at least one word is ignored.
            if failed && words.is_empty() {
                return Err(MailError("missing word in phrase"));
            }
            Ok(words.join(" "))
        }

        /// A quoted string, the opening quote being the next byte.
        fn consume_quoted_string(&mut self) -> Result<String, MailError> {
            let mut out = String::new();
            let mut escaped = false;
            for (i, r) in self.s.char_indices().skip(1) {
                if escaped {
                    if !is_vchar(r) && !is_wsp(r) {
                        return Err(MailError("bad character in quoted-string"));
                    }
                    out.push(r);
                    escaped = false;
                } else if is_qtext(r) || is_wsp(r) {
                    out.push(r);
                } else if r == '"' {
                    self.s = &self.s[i + 1..];
                    return Ok(out);
                } else if r == '\\' {
                    escaped = true;
                } else {
                    return Err(MailError("bad character in quoted-string"));
                }
            }
            Err(MailError("unclosed quoted-string"))
        }

        /// An atom (a dot-atom with `dot`); `permissive` allows stray dots in it. Like Go,
        /// a refused atom is still consumed.
        fn consume_atom(&mut self, dot: bool, permissive: bool) -> Result<&str, MailError> {
            let end = self
                .s
                .char_indices()
                .find(|&(_, r)| !is_atext(r, dot))
                .map_or(self.s.len(), |(i, _)| i);
            if end == 0 {
                return Err(MailError("invalid string"));
            }
            let (atom, rest) = self.s.split_at(end);
            self.s = rest;
            if !permissive && (atom.starts_with('.') || atom.contains("..") || atom.ends_with('.'))
            {
                return Err(MailError("stray dot in atom"));
            }
            Ok(atom)
        }

        fn consume_domain_literal(&mut self) -> Result<String, MailError> {
            if !self.consume(b'[') {
                return Err(MailError("missing [ in domain-literal"));
            }
            let end = self
                .s
                .char_indices()
                .find(|&(_, r)| r == ']' || !is_dtext(r));
            let dtext = match end {
                None => return Err(MailError("unclosed domain-literal")),
                Some((_, r)) if r != ']' => {
                    return Err(MailError("bad character in domain-literal"));
                }
                Some((i, _)) => &self.s[..i],
            };
            self.s = &self.s[dtext.len() + 1..];
            let valid = match dtext.strip_prefix("IPv6:") {
                Some(address) => go_parse_ip(address).is_some(),
                None => go_parse_ip(dtext).is_some_and(|ip| ip.to_canonical().is_ipv4()),
            };
            if !valid {
                return Err(MailError("invalid IP address in domain-literal"));
            }
            Ok(format!("[{dtext}]"))
        }

        fn consume_display_name_comment(&mut self) -> Result<String, MailError> {
            if !self.consume(b'(') {
                return Err(MailError("comment does not start with ("));
            }
            let comment = self
                .consume_comment()
                .ok_or(MailError("misformatted parenthetical comment"))?;
            let words = comment
                .split([' ', '\t'])
                .filter(|w| !w.is_empty())
                .map(|w| Ok(decode_rfc2047_word(w)?.unwrap_or_else(|| w.to_string())))
                .collect::<Result<Vec<_>, MailError>>()?;
            Ok(words.join(" "))
        }

        fn consume(&mut self, c: u8) -> bool {
            match self.s.strip_prefix(char::from(c)) {
                Some(rest) => {
                    self.s = rest;
                    true
                }
                None => false,
            }
        }

        fn skip_space(&mut self) {
            self.s = self.s.trim_start_matches([' ', '\t']);
        }

        fn peek(&self) -> u8 {
            self.s.as_bytes()[0]
        }

        /// Comments and folding white space; false for an unclosed comment.
        fn skip_cfws(&mut self) -> bool {
            self.skip_space();
            while self.consume(b'(') {
                if self.consume_comment().is_none() {
                    return false;
                }
                self.skip_space();
            }
            true
        }

        /// The rest of a comment whose `(` is consumed, nested comments and escapes kept
        /// as Go keeps them; `None` when it is not closed.
        fn consume_comment(&mut self) -> Option<String> {
            let bytes = self.s.as_bytes();
            let mut depth = 1;
            let mut comment = Vec::new();
            let mut i = 0;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'\\' && bytes.len() - i > 1 {
                    i += 1;
                } else if bytes[i] == b'(' {
                    depth += 1;
                } else if bytes[i] == b')' {
                    depth -= 1;
                }
                if depth > 0 {
                    comment.push(bytes[i]);
                }
                i += 1;
            }
            // `i` stops after a `)` or at the end, both character boundaries; only ASCII
            // backslashes were dropped, so the comment is still UTF-8.
            self.s = &self.s[i..];
            let comment = String::from_utf8(comment).expect("UTF-8 less some ASCII bytes");
            (depth == 0).then_some(comment)
        }
    }

    /// An RFC 2047 encoded-word decoded (`Some`), or `None` when the word is not one. An
    /// encoded-word in a charset Go does not know is an error.
    fn decode_rfc2047_word(word: &str) -> Result<Option<String>, MailError> {
        if word.len() < 8
            || !word.starts_with("=?")
            || !word.ends_with("?=")
            || word.matches('?').count() != 4
        {
            return Ok(None);
        }
        let inner = &word[2..word.len() - 2];
        let (charset, rest) = inner.split_once('?').unwrap_or((inner, ""));
        let (encoding, text) = rest.split_once('?').unwrap_or((rest, ""));
        if charset.is_empty() || encoding.len() != 1 {
            return Ok(None);
        }
        let content = match encoding.as_bytes()[0] {
            b'B' | b'b' => go_base64(&STD, text),
            b'Q' | b'q' => q_decode(text),
            _ => None,
        };
        let Some(content) = content else {
            return Ok(None);
        };
        if equal_fold(charset, "utf-8") {
            // shortcut: invalid UTF-8 is replaced, where Go keeps the bytes in its string;
            // only a malformed document has any.
            Ok(Some(String::from_utf8_lossy(&content).into_owned()))
        } else if equal_fold(charset, "iso-8859-1") {
            Ok(Some(content.iter().map(|&b| char::from(b)).collect()))
        } else if equal_fold(charset, "us-ascii") {
            Ok(Some(
                content
                    .iter()
                    .map(|&b| {
                        if b.is_ascii() {
                            char::from(b)
                        } else {
                            '\u{FFFD}'
                        }
                    })
                    .collect(),
            ))
        } else {
            Err(MailError("charset not supported"))
        }
    }

    /// Go's `strings.EqualFold` against an ASCII name: Unicode folds `ſ` to `s` and the
    /// Kelvin sign to `k` as well.
    fn equal_fold(text: &str, ascii: &str) -> bool {
        let folded = text.chars().map(|c| match c {
            'ſ' => 's',
            '\u{212A}' => 'k',
            c => c.to_ascii_lowercase(),
        });
        folded.eq(ascii.chars())
    }

    /// The Q encoding: `_` is a space, `=XX` a byte, printable ASCII as is.
    fn q_decode(text: &str) -> Option<Vec<u8>> {
        let bytes = text.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'_' => out.push(b' '),
                b'=' => {
                    if i + 2 >= bytes.len() {
                        return None;
                    }
                    let hex = |b: u8| match b {
                        b'0'..=b'9' => Some(b - b'0'),
                        b'A'..=b'F' => Some(b - b'A' + 10),
                        b'a'..=b'f' => Some(b - b'a' + 10),
                        _ => None,
                    };
                    out.push(hex(bytes[i + 1])? << 4 | hex(bytes[i + 2])?);
                    i += 2;
                }
                c @ (b' '..=b'~' | b'\n' | b'\r' | b'\t') => out.push(c),
                _ => return None,
            }
            i += 1;
        }
        Some(out)
    }

    /// Go's `net.ParseIP`: dotted IPv4 or IPv6 (with an embedded IPv4), no zone.
    fn go_parse_ip(text: &str) -> Option<std::net::IpAddr> {
        text.parse().ok()
    }

    fn is_atext(r: char, dot: bool) -> bool {
        match r {
            '.' => dot,
            '(' | ')' | '<' | '>' | '[' | ']' | ':' | ';' | '@' | '\\' | ',' | '"' => false,
            r => is_vchar(r),
        }
    }

    fn is_qtext(r: char) -> bool {
        r != '\\' && r != '"' && is_vchar(r)
    }

    /// A visible character: printable ASCII, or any non-ASCII one (RFC 6532).
    fn is_vchar(r: char) -> bool {
        ('!'..='~').contains(&r) || !r.is_ascii()
    }

    fn is_wsp(r: char) -> bool {
        r == ' ' || r == '\t'
    }

    fn is_dtext(r: char) -> bool {
        r != '[' && r != ']' && r != '\\' && is_vchar(r)
    }
}
