//! Messenger's encrypted message payload ("armadillo"): from what a Signal session decrypts to
//! what the archive keeps.
//!
//! Three protobufs, each wrapping the next as versioned bytes: `MessageTransport` (with the
//! sender-key and device-list extras beside the payload), `MessageApplication` (reply and
//! group metadata), `ConsumerApplication` (the content). Ported from whatsmeow's
//! `armadillomessage.go` and its `waMsgTransport`, `waMsgApplication`, `waConsumerApplication`
//! and `waCommon` protobufs, with only the fields read here. A oneof is declared as its
//! separate optional fields, which reads the same bytes.

use prost::Message;

/// What a message says, as far as the archive cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    Text {
        text: String,
        /// The stanza id of the message this one replies to.
        reply_to: Option<String>,
    },
    /// A kind of attachment, with its caption when it has one.
    Media {
        kind: &'static str,
        caption: Option<String>,
        reply_to: Option<String>,
        /// Where the encrypted file is and how to open it, when the kind carries a file.
        media: Option<MediaRef>,
    },
    Edit {
        target: String,
        text: String,
    },
    /// Unsent for everyone.
    Revoke {
        target: String,
    },
    /// An empty emoji takes a reaction back.
    Reaction {
        target: String,
        emoji: String,
    },
    /// Nothing for the archive: a transport-only message, or content not ported. The text says
    /// which, by field number, for the log.
    Other(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArmadilloError {
    #[error("{0} does not decode")]
    Decode(&'static str),
    #[error("{0} version {1} is not the one ported")]
    Version(&'static str, i32),
}

/// `MessageApplication`'s version for Messenger (Instagram's is 3).
const FB_MESSAGE_APPLICATION: i32 = 2;
const CONSUMER_APPLICATION: i32 = 1;

#[derive(Clone, PartialEq, Message)]
struct SubProtocol {
    #[prost(bytes = "vec", optional, tag = "1")]
    payload: Option<Vec<u8>>,
    #[prost(int32, optional, tag = "2")]
    version: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
struct MessageTransport {
    #[prost(message, optional, tag = "1")]
    payload: Option<TransportPayload>,
}

#[derive(Clone, PartialEq, Message)]
struct TransportPayload {
    #[prost(message, optional, tag = "1")]
    application_payload: Option<SubProtocol>,
}

#[derive(Clone, PartialEq, Message)]
struct MessageApplication {
    #[prost(message, optional, tag = "1")]
    payload: Option<ApplicationPayload>,
    #[prost(message, optional, tag = "2")]
    metadata: Option<ApplicationMetadata>,
}

#[derive(Clone, PartialEq, Message)]
struct ApplicationPayload {
    #[prost(message, optional, tag = "4")]
    sub_protocol: Option<SubProtocolPayload>,
}

#[derive(Clone, PartialEq, Message)]
struct SubProtocolPayload {
    #[prost(message, optional, tag = "2")]
    consumer_message: Option<SubProtocol>,
    #[prost(message, optional, tag = "7")]
    armadillo: Option<SubProtocol>,
}

#[derive(Clone, PartialEq, Message)]
struct ApplicationMetadata {
    #[prost(message, optional, tag = "10")]
    quoted_message: Option<QuotedMessage>,
}

#[derive(Clone, PartialEq, Message)]
struct QuotedMessage {
    #[prost(string, optional, tag = "1")]
    stanza_id: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct ConsumerApplication {
    #[prost(message, optional, tag = "1")]
    payload: Option<ConsumerPayload>,
}

#[derive(Clone, PartialEq, Message)]
struct ConsumerPayload {
    #[prost(message, optional, tag = "1")]
    content: Option<ConsumerContent>,
    #[prost(message, optional, tag = "2")]
    application_data: Option<ApplicationData>,
}

#[derive(Clone, PartialEq, Message)]
struct ApplicationData {
    #[prost(message, optional, tag = "1")]
    revoke: Option<Keyed>,
}

/// Any message whose field 1 is a `MessageKey` and field 2 a `MessageText`, or none.
#[derive(Clone, PartialEq, Message)]
struct Keyed {
    #[prost(message, optional, tag = "1")]
    key: Option<MessageKey>,
}

#[derive(Clone, PartialEq, Message)]
struct MessageKey {
    #[prost(string, optional, tag = "3")]
    id: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct MessageText {
    #[prost(string, optional, tag = "1")]
    text: Option<String>,
}

/// A message holding a `MessageText` as field `N`: a caption, or a link preview's text.
#[derive(Clone, PartialEq, Message)]
struct Captioned1 {
    #[prost(message, optional, tag = "1")]
    text: Option<MessageText>,
}

#[derive(Clone, PartialEq, Message)]
struct Captioned5 {
    #[prost(message, optional, tag = "5")]
    caption: Option<MessageText>,
}

#[derive(Clone, PartialEq, Message)]
struct Reaction {
    #[prost(message, optional, tag = "1")]
    key: Option<MessageKey>,
    #[prost(string, optional, tag = "2")]
    text: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct Edit {
    #[prost(message, optional, tag = "1")]
    key: Option<MessageKey>,
    #[prost(message, optional, tag = "2")]
    message: Option<MessageText>,
}

/// An encrypted file on Meta's CDN: what `waMediaTransport.WAMediaTransport` carries. The
/// file is fetched and opened the way WhatsApp's media are (whatsapp-client's `media`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaRef {
    pub direct_path: Option<String>,
    pub media_key: Vec<u8>,
    pub file_sha256: Option<Vec<u8>>,
    pub file_enc_sha256: Option<Vec<u8>>,
    pub mime_type: Option<String>,
    pub file_length: Option<u64>,
    /// An audio or video file's length.
    pub seconds: Option<u32>,
    /// A recorded voice note rather than an audio file.
    pub voice_note: bool,
}

/// `ImageMessage` and `VideoMessage`: the transport, then a caption.
#[derive(Clone, PartialEq, Message)]
struct CaptionedMedia {
    #[prost(message, optional, tag = "1")]
    media: Option<SubProtocol>,
    #[prost(message, optional, tag = "2")]
    caption: Option<MessageText>,
}

#[derive(Clone, PartialEq, Message)]
struct AudioMessage {
    #[prost(message, optional, tag = "1")]
    media: Option<SubProtocol>,
    #[prost(bool, optional, tag = "2")]
    ptt: Option<bool>,
}

/// `DocumentMessage` and `StickerMessage`: the transport first.
#[derive(Clone, PartialEq, Message)]
struct FileMedia {
    #[prost(message, optional, tag = "1")]
    media: Option<SubProtocol>,
}

/// Every `waMediaTransport.*Transport`: `integral.transport`, and an ancillary part whose
/// field 1 is the duration for audio and video.
#[derive(Clone, PartialEq, Message)]
struct KindTransport {
    #[prost(message, optional, tag = "1")]
    integral: Option<KindIntegral>,
    #[prost(message, optional, tag = "2")]
    ancillary: Option<KindAncillary>,
}

#[derive(Clone, PartialEq, Message)]
struct KindIntegral {
    #[prost(message, optional, tag = "1")]
    transport: Option<WaMediaTransport>,
}

#[derive(Clone, PartialEq, Message)]
struct KindAncillary {
    #[prost(uint32, optional, tag = "1")]
    seconds: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
struct WaMediaTransport {
    #[prost(message, optional, tag = "1")]
    integral: Option<WaIntegral>,
    #[prost(message, optional, tag = "2")]
    ancillary: Option<WaAncillary>,
}

#[derive(Clone, PartialEq, Message)]
struct WaIntegral {
    #[prost(bytes = "vec", optional, tag = "1")]
    file_sha256: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    media_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    file_enc_sha256: Option<Vec<u8>>,
    #[prost(string, optional, tag = "4")]
    direct_path: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct WaAncillary {
    #[prost(uint64, optional, tag = "1")]
    file_length: Option<u64>,
    #[prost(string, optional, tag = "2")]
    mimetype: Option<String>,
}

/// Every media transport is at version 1 (`waConsumerApplication`'s `*TransportVersion`).
const MEDIA_TRANSPORT: i32 = 1;

/// The file reference inside an attachment, or `None` when it is absent or does not read:
/// the message itself is still worth keeping without it.
fn media_ref(sub: Option<&SubProtocol>, timed: bool, voice_note: bool) -> Option<MediaRef> {
    let bytes = sub_protocol(sub?, "media transport", MEDIA_TRANSPORT).ok()?;
    let kind = KindTransport::decode(bytes).ok()?;
    let transport = kind.integral?.transport?;
    let integral = transport.integral?;
    let ancillary = transport.ancillary.unwrap_or_default();
    Some(MediaRef {
        direct_path: integral.direct_path,
        media_key: integral.media_key.filter(|k| !k.is_empty())?,
        file_sha256: integral.file_sha256,
        file_enc_sha256: integral.file_enc_sha256,
        mime_type: ancillary.mimetype,
        file_length: ancillary.file_length,
        seconds: if timed {
            kind.ancillary.and_then(|a| a.seconds)
        } else {
            None
        },
        voice_note,
    })
}

/// An empty message: only whether the field was there matters.
#[derive(Clone, PartialEq, Message)]
struct Present {}

#[derive(Clone, PartialEq, Message)]
struct ConsumerContent {
    #[prost(message, optional, tag = "1")]
    message_text: Option<MessageText>,
    #[prost(message, optional, tag = "2")]
    image: Option<CaptionedMedia>,
    #[prost(message, optional, tag = "3")]
    contact: Option<Present>,
    #[prost(message, optional, tag = "4")]
    location: Option<Present>,
    #[prost(message, optional, tag = "5")]
    extended_text: Option<Captioned1>,
    #[prost(message, optional, tag = "7")]
    document: Option<FileMedia>,
    #[prost(message, optional, tag = "8")]
    audio: Option<AudioMessage>,
    #[prost(message, optional, tag = "9")]
    video: Option<CaptionedMedia>,
    #[prost(message, optional, tag = "10")]
    contacts: Option<Present>,
    #[prost(message, optional, tag = "11")]
    live_location: Option<Captioned5>,
    #[prost(message, optional, tag = "12")]
    sticker: Option<FileMedia>,
    #[prost(message, optional, tag = "14")]
    view_once: Option<Present>,
    #[prost(message, optional, tag = "16")]
    reaction: Option<Reaction>,
    #[prost(message, optional, tag = "17")]
    poll: Option<Present>,
    #[prost(message, optional, tag = "19")]
    edit: Option<Edit>,
}

fn sub_protocol<'a>(
    sub: &'a SubProtocol,
    what: &'static str,
    version: i32,
) -> Result<&'a [u8], ArmadilloError> {
    match sub.version {
        Some(v) if v == version => Ok(sub.payload.as_deref().unwrap_or_default()),
        other => Err(ArmadilloError::Version(what, other.unwrap_or(0))),
    }
}

fn text(message: Option<MessageText>) -> Option<String> {
    message.and_then(|m| m.text).filter(|t| !t.is_empty())
}

fn target(key: Option<MessageKey>) -> String {
    key.and_then(|k| k.id).unwrap_or_default()
}

/// Decodes a version-3 plaintext (a `<enc v="3">`, which carries no padding).
pub fn decode(plaintext: &[u8]) -> Result<Content, ArmadilloError> {
    let transport = MessageTransport::decode(plaintext)
        .map_err(|_| ArmadilloError::Decode("MessageTransport"))?;
    let Some(application) = transport.payload.and_then(|p| p.application_payload) else {
        return Ok(Content::Other("transport only".into()));
    };
    let application = MessageApplication::decode(sub_protocol(
        &application,
        "MessageApplication",
        FB_MESSAGE_APPLICATION,
    )?)
    .map_err(|_| ArmadilloError::Decode("MessageApplication"))?;
    let reply_to = application
        .metadata
        .and_then(|m| m.quoted_message)
        .and_then(|q| q.stanza_id);
    let Some(sub) = application.payload.and_then(|p| p.sub_protocol) else {
        return Ok(Content::Other("application without a sub-protocol".into()));
    };
    let Some(consumer) = sub.consumer_message else {
        let which = if sub.armadillo.is_some() {
            "armadillo"
        } else {
            "another"
        };
        return Ok(Content::Other(format!("{which} sub-protocol")));
    };
    let consumer = ConsumerApplication::decode(sub_protocol(
        &consumer,
        "ConsumerApplication",
        CONSUMER_APPLICATION,
    )?)
    .map_err(|_| ArmadilloError::Decode("ConsumerApplication"))?;
    let Some(payload) = consumer.payload else {
        return Ok(Content::Other("consumer without a payload".into()));
    };
    if let Some(revoke) = payload.application_data.and_then(|d| d.revoke) {
        return Ok(Content::Revoke {
            target: target(revoke.key),
        });
    }
    let Some(c) = payload.content else {
        return Ok(Content::Other("consumer payload without content".into()));
    };
    let media = |kind, caption, media| Content::Media {
        kind,
        caption,
        reply_to: reply_to.clone(),
        media,
    };
    Ok(if let Some(t) = text(c.message_text) {
        Content::Text { text: t, reply_to }
    } else if let Some(t) = c.extended_text.and_then(|e| text(e.text)) {
        Content::Text { text: t, reply_to }
    } else if let Some(r) = c.reaction {
        Content::Reaction {
            target: target(r.key),
            emoji: r.text.unwrap_or_default(),
        }
    } else if let Some(e) = c.edit {
        Content::Edit {
            target: target(e.key),
            text: text(e.message).unwrap_or_default(),
        }
    } else if let Some(i) = c.image {
        let file = media_ref(i.media.as_ref(), false, false);
        media("image", text(i.caption), file)
    } else if let Some(v) = c.video {
        let file = media_ref(v.media.as_ref(), true, false);
        media("video", text(v.caption), file)
    } else if let Some(a) = c.audio {
        let file = media_ref(a.media.as_ref(), true, a.ptt.unwrap_or(false));
        media("audio", None, file)
    } else if let Some(d) = c.document {
        media("document", None, media_ref(d.media.as_ref(), false, false))
    } else if let Some(s) = c.sticker {
        media("sticker", None, media_ref(s.media.as_ref(), false, false))
    } else if c.contact.is_some() || c.contacts.is_some() {
        media("contact", None, None)
    } else if c.location.is_some() {
        media("location", None, None)
    } else if let Some(l) = c.live_location {
        media("live location", text(l.caption), None)
    } else if c.view_once.is_some() {
        media("view once", None, None)
    } else if c.poll.is_some() {
        media("poll", None, None)
    } else {
        Content::Other("consumer content not ported".into())
    })
}
