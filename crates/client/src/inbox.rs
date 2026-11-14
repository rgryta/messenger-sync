//! A received encrypted message: who sent it, in which chat, and what it says.
//!
//! The stanza is WhatsApp's `<message>` with Messenger's addresses (`user:device@msgr`), one
//! `<enc>` child per payload. Each is opened by the device's Signal sessions and, at version
//! 3, read by [`armadillo`]. Ported from whatsmeow's `message.go` (`parseMessageSource`,
//! `decryptMessages`, `decryptDM`) for the one-to-one case. The store changes only when a
//! payload decrypts, and only in memory: saving it is the caller's job.

use chrono::{DateTime, Utc};
use messenger_core::models::{E2eeEvent, E2eeWhat};
use whatsapp_client::binary::{Content as NodeContent, Node, Value};
use whatsapp_client::signal::{Address, SignalError, Store};

use crate::armadillo::{self, ArmadilloError, Content};

pub const MESSENGER_SERVER: &str = "msgr";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub id: String,
    /// The device that encrypted it, as Signal addresses it.
    pub sender: Address,
    /// The other person in a one-to-one chat: the sender, or the recipient when one of our own
    /// devices sent it.
    pub chat: String,
    pub from_me: bool,
    /// Seconds since the epoch, as the server stamped it.
    pub timestamp: Option<i64>,
    pub parts: Vec<Part>,
}

/// One `<enc>` child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    Content(Content),
    /// It did not open; the text says why, without content.
    Failed(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InboxError {
    #[error("the stanza has no {0}")]
    Missing(&'static str),
    #[error("a {0} address is not ported")]
    UnsupportedServer(String),
    #[error("a recipient on a message not from us")]
    RecipientNotFromMe,
}

/// `(user, device, server)` of an address attribute, however it travelled.
fn address(value: &Value) -> Option<(String, u32, String)> {
    match value {
        Value::Jid(jid) => Some((
            jid.user.clone(),
            jid.device_number().into(),
            jid.server.clone(),
        )),
        Value::Str(text) => {
            let (local, server) = text.split_once('@')?;
            let (user, device) = local.split_once(':').unwrap_or((local, "0"));
            Some((user.to_owned(), device.parse().ok()?, server.to_owned()))
        }
    }
}

fn open(store: &mut Store, sender: &Address, enc: &Node) -> Part {
    let kind = enc.get("type").map(ToString::to_string).unwrap_or_default();
    let version = enc.get("v").map(ToString::to_string).unwrap_or_default();
    let NodeContent::Bytes(ciphertext) = &enc.content else {
        return Part::Failed(format!("{kind} without a payload"));
    };
    let plaintext = match kind.as_str() {
        "pkmsg" => store.decrypt_prekey(sender, ciphertext),
        "msg" => store.decrypt(sender, ciphertext),
        other => return Part::Failed(format!("{other} payloads are not ported")),
    };
    match (plaintext, version.as_str()) {
        (Ok(plaintext), "3") => match armadillo::decode(&plaintext) {
            Ok(content) => Part::Content(content),
            Err(ArmadilloError::Decode(what)) => Part::Failed(format!("{what} does not decode")),
            Err(e) => Part::Failed(e.to_string()),
        },
        (Ok(_), other) => Part::Failed(format!("a version {other} payload is not ported")),
        (Err(SignalError::Duplicate { .. }), _) => Part::Failed("already decrypted".into()),
        (Err(e), _) => Part::Failed(format!("{kind}: {e}")),
    }
}

/// Reads and opens a `<message>`. `me` is our own Messenger user id.
pub fn receive(store: &mut Store, node: &Node, me: &str) -> Result<Received, InboxError> {
    let id = node
        .get("id")
        .map(ToString::to_string)
        .ok_or(InboxError::Missing("id"))?;
    let (user, device, server) = node
        .get("from")
        .and_then(address)
        .ok_or(InboxError::Missing("from"))?;
    if server != MESSENGER_SERVER {
        return Err(InboxError::UnsupportedServer(server));
    }
    let from_me = user == me;
    let chat = match node.get("recipient").and_then(address) {
        Some(_) if !from_me => return Err(InboxError::RecipientNotFromMe),
        Some((recipient, _, _)) => recipient,
        None => user.clone(),
    };
    let sender = Address { name: user, device };
    let parts = node
        .children()
        .iter()
        .filter(|child| child.tag == "enc")
        .map(|enc| open(store, &sender, enc))
        .collect();
    Ok(Received {
        id,
        sender,
        chat,
        from_me,
        timestamp: node.get("t").and_then(|t| t.to_string().parse().ok()),
        parts,
    })
}

/// What the archive keeps of a received message: its first payload that opened to something
/// the archive holds. `now` stands in for a missing server timestamp.
pub fn event(received: &Received, now: DateTime<Utc>) -> Option<E2eeEvent> {
    let what = received.parts.iter().find_map(|part| match part {
        Part::Content(Content::Text { text, reply_to }) => Some(E2eeWhat::Message {
            text: Some(text.clone()),
            reply_to: reply_to.clone(),
            media: None,
        }),
        Part::Content(Content::Media {
            kind,
            caption,
            reply_to,
        }) => Some(E2eeWhat::Message {
            text: caption.clone(),
            reply_to: reply_to.clone(),
            media: Some((*kind).into()),
        }),
        Part::Content(Content::Edit { target, text }) => Some(E2eeWhat::Edit {
            target: target.clone(),
            text: text.clone(),
        }),
        Part::Content(Content::Revoke { target }) => Some(E2eeWhat::Unsend {
            target: target.clone(),
        }),
        Part::Content(Content::Reaction { target, emoji }) => Some(E2eeWhat::Reaction {
            target: target.clone(),
            emoji: emoji.clone(),
        }),
        Part::Content(Content::Other(_)) | Part::Failed(_) => None,
    })?;
    Some(E2eeEvent {
        otid: received.id.clone(),
        ts: received
            .timestamp
            .and_then(|t| DateTime::from_timestamp(t, 0))
            .unwrap_or(now),
        sender_id: received.sender.name.clone(),
        what,
    })
}
