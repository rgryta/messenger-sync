//! Decoded rows from a stream of LightSpeed steps, and the write that stores them, ported
//! from the retired Python harvester's `_Collector` and `_persist`.
//!
//! Every map is keyed exactly as the Python keyed its dict, so a row delivered twice in one
//! page is written once, and the last delivery wins.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use messenger_core::models::{Attachment, Member, Message, Participant, Reaction, Thread};
use messenger_core::store::writes;
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection};

use crate::{ls, ops};

pub const SYNC_GROUP_INBOX: u8 = 1;
pub const SYNC_GROUP_E2EE: u8 = 95;

fn at(ms: i64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp_millis(ms)
}

#[derive(Debug, Default)]
pub struct Collector {
    pub account_id: String,
    /// The thread (and its sync group) of the message-page task in flight: the fallback for a
    /// message that names no thread of its own.
    pub expect: Option<(String, u8)>,
    pub threads: BTreeMap<String, Thread>,
    pub participants: BTreeMap<String, Participant>,
    pub e2ee_keys: BTreeSet<String>,
    pub messages: BTreeMap<(String, String), Message>,
    /// By (message id, actor).
    pub reactions: BTreeMap<(String, String), Reaction>,
    /// By (thread, user).
    pub members: BTreeMap<(String, String), Member>,
    /// By (message id, attachment id or url or "").
    pub attachments: BTreeMap<(String, String), Attachment>,
    /// New texts, by message id: an edit names no thread.
    pub edits: BTreeMap<String, String>,
    /// Earlier texts of edited messages, by (thread, message id), then edit time.
    pub history: BTreeMap<(String, String), BTreeMap<i64, String>>,
    /// By (thread, message id): when it was unsent, if LightSpeed said.
    pub unsends: BTreeMap<(String, String), Option<DateTime<Utc>>>,
    pub per_thread_oldest: HashMap<String, DateTime<Utc>>,
    pub per_thread_newest: HashMap<String, DateTime<Utc>>,
    /// Messages decoded during the current page: what the walks key off, because rows
    /// written cannot tell "nothing came back" from "we already had it".
    pub decoded_messages: usize,
}

impl Collector {
    pub fn new(account_id: &str) -> Self {
        Collector {
            account_id: account_id.to_owned(),
            ..Default::default()
        }
    }

    /// Resets the per-page evidence before a message-page task.
    pub fn begin_page(&mut self) {
        self.messages.clear();
        self.reactions.clear();
        self.attachments.clear();
        self.members.clear();
        self.edits.clear();
        self.history.clear();
        self.unsends.clear();
        self.decoded_messages = 0;
    }

    /// Forgets the threads and people already written, so a page does not re-upsert the
    /// whole inbox.
    pub fn clear_directory(&mut self) {
        self.threads.clear();
        self.participants.clear();
        self.e2ee_keys.clear();
        self.members.clear();
    }

    /// Every stored-procedure call in `steps`, pushed on the stream of `event_group`.
    pub fn feed(&mut self, event_group: Option<u8>, steps: &Value) {
        let account = self.account_id.clone();
        for op in ls::calls(steps) {
            if let Some(key) = ops::e2ee_thread_key(op) {
                self.e2ee_keys.insert(key);
            } else if let Some(t) = ops::thread(op, event_group.unwrap_or(SYNC_GROUP_INBOX)) {
                self.threads.insert(
                    t.thread_key.clone(),
                    Thread {
                        account_id: account.clone(),
                        thread_key: t.thread_key,
                        sync_group: t.sync_group.into(),
                        title: t.title,
                        is_group: t.is_group,
                        last_activity_at: t.last_activity_ms.and_then(at),
                        raw: json!({"op": op}),
                    },
                );
            } else if let Some(p) = ops::participant(op) {
                self.participants.insert(
                    p.fb_user_id.clone(),
                    Participant {
                        account_id: account.clone(),
                        fb_user_id: p.fb_user_id,
                        name: p.name,
                        username: p.username,
                        profile_pic_url: p.profile_pic_url,
                    },
                );
            } else if let Some(m) = ops::member(op) {
                self.members.insert(
                    (m.thread_key.clone(), m.fb_user_id.clone()),
                    Member {
                        account_id: account.clone(),
                        thread_key: m.thread_key,
                        fb_user_id: m.fb_user_id,
                        joined_at: m.joined_ms.and_then(at),
                        is_admin: m.is_admin,
                    },
                );
            } else if let Some(r) = ops::reaction(op) {
                let Some(reacted_at) = at(r.reacted_ms) else {
                    continue;
                };
                self.reactions.insert(
                    (r.message_id.clone(), r.actor_id.clone()),
                    Reaction {
                        account_id: account.clone(),
                        thread_key: r.thread_key,
                        message_id: r.message_id,
                        actor_id: r.actor_id,
                        emoji: r.emoji,
                        reacted_at,
                    },
                );
            } else if let Some(e) = ops::edit(op) {
                self.edits.insert(e.message_id, e.text);
            } else if let Some(h) = ops::edit_history(op) {
                self.history
                    .entry((h.thread_key, h.message_id))
                    .or_default()
                    .insert(h.edited_ms, h.text);
            } else if let Some(a) = ops::attachment(op) {
                let key = a
                    .attachment_id
                    .clone()
                    .or(a.url.clone())
                    .unwrap_or_default();
                self.attachments.insert(
                    (a.message_id.clone(), key),
                    Attachment {
                        account_id: account.clone(),
                        thread_key: a.thread_key,
                        message_id: a.message_id,
                        attachment_id: a.attachment_id,
                        kind: a.kind.to_owned(),
                        mime_type: a.mime_type,
                        url: a.url,
                        preview_url: a.preview_url,
                        raw: json!({"op": op}),
                    },
                );
            } else {
                // The message names its own thread; the task in flight is only a fallback,
                // so two overlapping pages cannot file each other's messages.
                let (fallback, group) = match &self.expect {
                    Some((thread, group)) => (Some(thread.as_str()), *group),
                    None => (None, event_group.unwrap_or(SYNC_GROUP_INBOX)),
                };
                if let Some(u) = ops::unsend(op, fallback) {
                    self.unsends
                        .insert((u.thread_key, u.message_id), u.unsent_ms.and_then(at));
                }
                let Some(m) = ops::message(op, fallback, group) else {
                    continue;
                };
                let Some(ts) = at(m.ts_ms) else {
                    continue;
                };
                self.decoded_messages += 1;
                let oldest = self
                    .per_thread_oldest
                    .entry(m.thread_key.clone())
                    .or_insert(ts);
                *oldest = (*oldest).min(ts);
                let newest = self
                    .per_thread_newest
                    .entry(m.thread_key.clone())
                    .or_insert(ts);
                *newest = (*newest).max(ts);
                self.messages.insert(
                    (m.thread_key.clone(), m.message_id.clone()),
                    Message {
                        account_id: account.clone(),
                        thread_key: m.thread_key,
                        message_id: m.message_id,
                        ts,
                        sender_id: m.sender_id,
                        text: m.text,
                        item_type: "text".into(),
                        reply_to_id: m.reply_to_id,
                        attachments: json!([]),
                        sync_group: m.sync_group.into(),
                        raw: json!({"op": op}),
                    },
                );
            }
        }
    }
}

/// Writes what was collected in one transaction, parents before children, and returns how
/// many messages were new.
pub async fn persist(conn: &mut PgConnection, batch: &Collector) -> sqlx::Result<u64> {
    let mut tx = conn.begin().await?;
    for thread in batch.threads.values() {
        writes::upsert_thread(&mut tx, thread).await?;
    }
    // Encrypted threads are announced by key alone and never appear in a listing, so their
    // rows have to exist before their messages can reference them.
    for key in &batch.e2ee_keys {
        writes::note_thread_seen(&mut tx, &batch.account_id, key, SYNC_GROUP_E2EE.into()).await?;
    }
    for m in batch.messages.values() {
        writes::note_thread_seen(&mut tx, &batch.account_id, &m.thread_key, m.sync_group).await?;
    }
    let participants: Vec<Participant> = batch.participants.values().cloned().collect();
    writes::upsert_participants(&mut tx, &participants).await?;
    let messages: Vec<Message> = batch.messages.values().cloned().collect();
    let written = writes::insert_messages(&mut tx, &messages).await?;
    // The roster first, then what speech implies: the second never clears `from_roster`.
    let members: Vec<Member> = batch.members.values().cloned().collect();
    writes::record_thread_members(&mut tx, &members).await?;
    writes::record_thread_participants(&mut tx, &messages).await?;
    // Not keyed to a stored message: an attachment often arrives in a different page from
    // its message, and dropping it for arriving early would lose it for good.
    let reactions: Vec<Reaction> = batch.reactions.values().cloned().collect();
    writes::insert_reactions(&mut tx, &reactions).await?;
    let attachments: Vec<Attachment> = batch.attachments.values().cloned().collect();
    writes::insert_attachments(&mut tx, &attachments).await?;
    // A message already held, delivered again with other words: edited while no stream was
    // open, which is most of the time between passes. The live `editMessage` is only seen
    // during a pass; this is what the retired Python's re-read caught. Identical text, and
    // NULL against '', change nothing.
    for m in &messages {
        if let Some(text) = m.text.as_deref() {
            writes::record_revision(
                &mut tx,
                &m.account_id,
                &m.thread_key,
                &m.message_id,
                Some(text),
            )
            .await?;
        }
    }
    // A message first seen already edited: its page carries the texts it had before.
    for ((thread_key, message_id), versions) in &batch.history {
        let earlier: Vec<(DateTime<Utc>, &str)> = versions
            .iter()
            .filter_map(|(ms, text)| Some((at(*ms)?, text.as_str())))
            .collect();
        writes::record_history(&mut tx, &batch.account_id, thread_key, message_id, &earlier)
            .await?;
    }
    // After the messages, so an edit or unsend of a message in this same page finds it.
    for (message_id, text) in &batch.edits {
        writes::apply_edit(&mut tx, &batch.account_id, message_id, text).await?;
    }
    for ((thread_key, message_id), at) in &batch.unsends {
        writes::mark_unsent(&mut tx, &batch.account_id, thread_key, message_id, *at).await?;
    }
    tx.commit().await?;
    Ok(written)
}
