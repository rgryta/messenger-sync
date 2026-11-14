//! The row types the read surface hands to the renderer, and what the client writes.
//!
//! One struct per query shape, mirroring the columns `store` selects. The write inputs
//! (`Account` .. `Member`) were ported field for field, defaults included, from the
//! retired Python `models.py`. The DOM capture's inputs never were: nothing writes those
//! tables any more.
//!
//! `raw` is not selected anywhere here. It holds the LightSpeed op that produced the
//! row, kept so a later decode can re-read it — the read surface never shows it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ------------------------------------------------------------------ the write inputs

fn yes() -> bool {
    true
}

fn object() -> Value {
    Value::Object(Default::default())
}

#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    pub id: String,
    pub fb_user_id: String,
    pub username: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Participant {
    pub account_id: String,
    pub fb_user_id: String,
    pub name: Option<String>,
    pub username: Option<String>,
    pub profile_pic_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Thread {
    pub account_id: String,
    pub thread_key: String,
    pub sync_group: i32,
    pub title: Option<String>,
    #[serde(default)]
    pub is_group: bool,
    pub last_activity_at: Option<DateTime<Utc>>,
    #[serde(default = "object")]
    pub raw: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Message {
    pub account_id: String,
    pub thread_key: String,
    pub message_id: String,
    pub ts: DateTime<Utc>,
    pub sender_id: Option<String>,
    pub text: Option<String>,
    #[serde(default = "Message::text_item")]
    pub item_type: String,
    pub reply_to_id: Option<String>,
    #[serde(default = "Message::no_attachments")]
    pub attachments: Value,
    #[serde(default = "Message::inbox")]
    pub sync_group: i32,
    #[serde(default = "object")]
    pub raw: Value,
}

impl Message {
    fn text_item() -> String {
        "text".into()
    }

    fn no_attachments() -> Value {
        Value::Array(Vec::new())
    }

    /// `SYNC_GROUP_INBOX`.
    fn inbox() -> i32 {
        1
    }
}

/// One person's reaction to one message.
#[derive(Debug, Clone, Deserialize)]
pub struct Reaction {
    pub account_id: String,
    pub thread_key: String,
    pub message_id: String,
    pub actor_id: String,
    pub emoji: String,
    pub reacted_at: DateTime<Utc>,
}

/// One decrypted encrypted-chat message, as the client's own device read it. `otid` is the
/// stanza id, which is the envelope's offline threading id; targets are OTIDs too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eeEvent {
    pub otid: String,
    pub ts: DateTime<Utc>,
    pub sender_id: String,
    pub what: E2eeWhat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum E2eeWhat {
    /// Text, or an attachment of `media` kind with its caption as the text.
    Message {
        text: Option<String>,
        reply_to: Option<String>,
        media: Option<String>,
        /// The encrypted file's reference, in the shape whatsapp-client's `MediaRef` reads.
        #[serde(default)]
        media_ref: Option<serde_json::Value>,
    },
    Edit {
        target: String,
        text: String,
    },
    Unsend {
        target: String,
    },
    /// An empty emoji takes the sender's reaction back.
    Reaction {
        target: String,
        emoji: String,
    },
}

/// Media or a shared link hanging off a message. `kind` is which instruction carried
/// it: `blob` for uploaded media, `xma` for a link or share preview.
#[derive(Debug, Clone, Deserialize)]
pub struct Attachment {
    pub account_id: String,
    pub thread_key: String,
    pub message_id: String,
    pub attachment_id: Option<String>,
    #[serde(default = "Attachment::blob")]
    pub kind: String,
    pub mime_type: Option<String>,
    pub url: Option<String>,
    pub preview_url: Option<String>,
    #[serde(default = "object")]
    pub raw: Value,
}

impl Attachment {
    fn blob() -> String {
        "blob".into()
    }
}

/// Thread membership as Meta's roster states it. A dict in the Python, not a model.
#[derive(Debug, Clone, Deserialize)]
pub struct Member {
    pub account_id: String,
    pub thread_key: String,
    pub fb_user_id: String,
    pub joined_at: Option<DateTime<Utc>>,
    pub is_admin: bool,
}

/// A thread the forward loop should walk: the listing has moved past what we hold.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ForwardTarget {
    pub thread_key: String,
    pub sync_group: i32,
    pub newest_seen_at: Option<DateTime<Utc>>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub title: Option<String>,
}

/// A thread the backward crawl has not finished.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HistoryTarget {
    pub thread_key: String,
    pub sync_group: i32,
    pub oldest_seen_at: Option<DateTime<Utc>>,
    pub title: Option<String>,
}

// ---------------------------------------------------------------------- the read rows

/// A person as the MCP layer names them: ids plus whatever we can call them.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Identity {
    pub account_id: String,
    pub fb_user_id: String,
    pub name: Option<String>,
    pub username: Option<String>,
}

/// One conversation as `threads` lists it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ThreadRow {
    pub account_id: String,
    pub thread_key: String,
    /// A one-to-one thread has no title; the renderer names it by who is in it.
    pub title: Option<String>,
    pub is_group: bool,
    pub sync_group: i32,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub history_done: bool,
    /// Holds messages and not one of them carries text, *and* nothing has been read
    /// off the client's screen either. Not the same as "filed under the encrypted
    /// store" — see `_THREAD_HAS_NO_TEXT` in the store.
    pub has_no_text: Option<bool>,
    /// `GREATEST` of the envelope watermark and the newest rendered line. Rendered
    /// lines count as captured: the envelope watermark alone said "May" for a thread
    /// whose screen had been read to this morning.
    pub newest_seen_at: Option<DateTime<Utc>>,
    /// Distinct `(ts, text, sender_label)` triples held for this thread. Reported
    /// beside `message_count`, never added to it: a rendered line and an envelope can
    /// be the same message, so a sum would count it twice.
    pub rendered_lines: i64,
    pub message_count: i64,
    /// Everyone who has spoken here except the account holder, most recent speaker
    /// first. `NULL` when nobody has.
    pub counterparts: Option<Vec<String>>,
    pub total_matches: i64,
}

/// One line of a conversation: an envelope from `message`, or a line read off the
/// client's screen from `dom_message`.
///
/// The two arrive through one `UNION ALL` and are deliberately never joined to each
/// other. A rendered line carries no message id anywhere in the client's own markup,
/// and its clock is precise to the minute, so two messages from one person inside a
/// minute are indistinguishable — a key invented here would be the join this design
/// refuses to make.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HistoryRow {
    pub account_id: String,
    pub thread_key: String,
    /// `None` on a rendered line, and only there.
    pub message_id: Option<String>,
    pub ts: DateTime<Utc>,
    pub sender_id: Option<String>,
    pub text: Option<String>,
    /// `rendered` marks a line read off the screen; everything else is the stored
    /// `item_type`, which defaults to `text`.
    pub item_type: String,
    pub sync_group: Option<i32>,
    pub reply_to_id: Option<String>,
    pub deleted_at: Option<DateTime<Utc>>,
    /// Derived, never stored: "was this edited" is exactly "is there a history of it",
    /// so a column saying so could drift from the rows it describes.
    pub edited: bool,
    /// The participant's name, or — on a rendered line — the client's own sender
    /// label, which names a sender without identifying one.
    pub sender_name: Option<String>,
    pub sender_username: Option<String>,
    /// `👍×3, ❤️`, newest first.
    pub reactions: Option<String>,
    /// What is attached, by mime type. The URLs are Meta CDN links that expire, so the
    /// useful thing to show is that media exists and what it is.
    pub attachments: Option<String>,
}

/// One search hit. Rendered lines are searched alongside the envelopes, so this too
/// can have no `message_id`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SearchHit {
    pub account_id: String,
    pub thread_key: String,
    pub message_id: Option<String>,
    pub ts: DateTime<Utc>,
    pub sender_id: Option<String>,
    pub text: Option<String>,
    pub item_type: String,
    pub thread_title: Option<String>,
    pub sender_name: Option<String>,
    pub sender_username: Option<String>,
    pub headline: Option<String>,
    pub total_matches: i64,
}

/// One person as `people` shows them, with every name form held for each.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PersonRow {
    pub account_id: String,
    pub fb_user_id: String,
    pub name: Option<String>,
    pub username: Option<String>,
    pub aliases: Option<String>,
    pub message_count: i64,
    /// Up to five conversations this person has spoken in, most recent first. The
    /// person → conversation hop: without it a caller had to full-text search for
    /// something they said and read the thread key off the hit.
    pub thread_keys: Option<Vec<String>>,
}

/// One alias and the people it names.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AliasRow {
    pub alias: String,
    pub note: Option<String>,
    pub members: Option<String>,
}

/// Per account: how much is stored, how much history is still owed, session health.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AccountStatus {
    pub account_id: String,
    pub username: Option<String>,
    pub enabled: bool,
    pub last_auth_error: Option<String>,
    pub last_auth_error_at: Option<DateTime<Utc>>,
    pub threads: i64,
    pub textless_threads: i64,
    pub textless_messages: i64,
    pub threads_pending_history: i64,
    pub messages: i64,
    pub system_events: i64,
    pub participants: i64,
    pub oldest_message_at: Option<DateTime<Utc>>,
    pub newest_message_at: Option<DateTime<Utc>>,
}

/// One harvest loop's last run.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LoopRow {
    pub account_id: String,
    /// `loop` is a Rust keyword; the column is not.
    #[sqlx(rename = "loop")]
    pub loop_name: String,
    pub current_thread_key: Option<String>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub last_error_at: Option<DateTime<Utc>>,
}

/// One revision of one message: what it said, and for how long.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Revision {
    pub seq: i32,
    /// Nullable because a message can be edited from having text to having none.
    pub text: Option<String>,
    /// `NULL` on seq 1 and only there, and it means "unknown", not "missing": nothing
    /// records when a message was first stored.
    pub first_seen_at: Option<DateTime<Utc>>,
    /// `NULL` marks the revision that is current.
    pub superseded_at: Option<DateTime<Utc>>,
}
