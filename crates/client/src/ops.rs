//! LightSpeed instructions to archive rows, ported from the retired Python harvester's `ops.py`.
//!
//! Every instruction is `[5, "<procedure>", args…]` and an i64 argument is boxed as
//! `[19, "<digits>"]`, so every id here is text. Positions were read off live captures by the
//! Python, and each decoder reads them only behind the guard the Python used — a `mid.` id,
//! the constant `"80"` at a fixed position, an exact width — so a layout Meta moves is refused,
//! not read into the wrong columns. `tests/fixtures/ops.json` holds the Python's own output
//! (made by the since-deleted `scripts/ops-fixture.py`) for a corpus that exercises every guard.

use serde_json::Value;

/// Milliseconds a Messenger message could plausibly carry: 2013 through 2035. Snowflake and
/// threading ids are long digit strings too, and must not parse as far-future dates.
const TS_MIN_MS: i64 = 1_356_998_400_000;
const TS_MAX_MS: i64 = 2_051_222_400_000;
const MARK: &str = "80";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub thread_key: String,
    pub message_id: String,
    pub ts_ms: i64,
    pub sender_id: Option<String>,
    pub text: Option<String>,
    pub reply_to_id: Option<String>,
    pub sync_group: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thread {
    pub thread_key: String,
    pub sync_group: u8,
    pub title: Option<String>,
    pub is_group: bool,
    pub last_activity_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    pub fb_user_id: String,
    pub name: Option<String>,
    pub username: Option<String>,
    pub profile_pic_url: Option<String>,
}

/// `editMessage`: a message's new text. It names no thread (mautrix-meta's
/// `LSEditMessage`), so the message is found by id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    pub message_id: String,
    pub text: String,
}

/// `deleteThenInsertMessage` with `IsUnsent`: the sender unsent it for everyone, and
/// LightSpeed swapped it for a placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsend {
    pub thread_key: String,
    pub message_id: String,
    pub unsent_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaction {
    pub thread_key: String,
    pub message_id: String,
    pub actor_id: String,
    pub emoji: String,
    pub reacted_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub thread_key: String,
    pub message_id: String,
    pub attachment_id: Option<String>,
    pub kind: &'static str,
    pub mime_type: Option<String>,
    pub url: Option<String>,
    pub preview_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub thread_key: String,
    pub fb_user_id: String,
    pub joined_ms: Option<i64>,
    pub is_admin: bool,
}

pub fn name(op: &[Value]) -> Option<&str> {
    op.get(1)?.as_str()
}

/// The boxed i64 at `index`, as text.
fn boxed(op: &[Value], index: usize) -> Option<&str> {
    match op.get(index)?.as_array()?.as_slice() {
        [tag, Value::String(digits)] if tag.as_u64() == Some(19) => Some(digits),
        _ => None,
    }
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// A boxed timestamp inside the plausible range.
fn stamp(op: &[Value], index: usize) -> Option<i64> {
    let s = boxed(op, index).filter(|s| digits(s))?;
    let ms: i64 = s.parse().ok()?;
    (TS_MIN_MS..=TS_MAX_MS).contains(&ms).then_some(ms)
}

fn string(op: &[Value], index: usize) -> Option<&str> {
    op.get(index)?.as_str()
}

fn mid(op: &[Value], index: usize) -> Option<&str> {
    string(op, index).filter(|s| s.starts_with("mid."))
}

/// `upsertMessage` / `deleteThenInsertMessage`. `thread_key` is only a fallback for an
/// instruction that names no thread of its own.
pub fn message(op: &[Value], thread_key: Option<&str>, sync_group: u8) -> Option<Message> {
    if !matches!(name(op)?, "upsertMessage" | "deleteThenInsertMessage") {
        return None;
    }
    let message_id = mid(op, 10)?;
    let ts_ms = stamp(op, 7)?;
    let thread = boxed(op, 5).filter(|t| *t != "0").or(thread_key)?;
    // Structured payloads (`{"contextual_menu_actions":…}`) share the text slot.
    let text = string(op, 2).filter(|t| !t.starts_with('{'));
    Some(Message {
        thread_key: thread.to_owned(),
        message_id: message_id.to_owned(),
        ts_ms,
        sender_id: boxed(op, 12)
            .filter(|s| !s.is_empty() && *s != "0")
            .map(str::to_owned),
        text: text.map(str::to_owned),
        reply_to_id: mid(op, 25).map(str::to_owned),
        sync_group,
    })
}

/// `editMessage`: argument 0 the message id, 2 the new text (`LSEditMessage`).
pub fn edit(op: &[Value]) -> Option<Edit> {
    if name(op)? != "editMessage" {
        return None;
    }
    Some(Edit {
        message_id: mid(op, 2)?.to_owned(),
        text: string(op, 4)?.to_owned(),
    })
}

/// `deleteThenInsertMessage` whose argument 17, `IsUnsent`, is true; argument 18 is when
/// (`LSDeleteThenInsertMessage`). Any other `deleteThenInsertMessage` is a plain message.
pub fn unsend(op: &[Value], thread_key: Option<&str>) -> Option<Unsend> {
    if name(op)? != "deleteThenInsertMessage" || op.get(19)?.as_bool() != Some(true) {
        return None;
    }
    let thread = boxed(op, 5).filter(|t| *t != "0").or(thread_key)?;
    Some(Unsend {
        thread_key: thread.to_owned(),
        message_id: mid(op, 10)?.to_owned(),
        unsent_ms: stamp(op, 20),
    })
}

/// `deleteThenInsertThread` / `updateOrInsertThread`. An untitled thread is a DM.
pub fn thread(op: &[Value], sync_group: u8) -> Option<Thread> {
    if !matches!(name(op)?, "deleteThenInsertThread" | "updateOrInsertThread") {
        return None;
    }
    if op.len() <= 9 || boxed(op, 8) != Some(MARK) {
        return None;
    }
    let key = boxed(op, 9).filter(|k| digits(k))?;
    let title = string(op, 5).filter(|t| !t.is_empty()).map(str::to_owned);
    Some(Thread {
        thread_key: key.to_owned(),
        sync_group,
        is_group: title.is_some(),
        title,
        last_activity_ms: stamp(op, 2),
    })
}

/// Every boxed value in an instruction, in order, at any depth.
fn all_boxed<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    if let Value::Array(items) = v {
        if let [tag, Value::String(s)] = items.as_slice()
            && tag.as_u64() == Some(19)
        {
            out.push(s);
            return;
        }
        for item in items {
            all_boxed(item, out);
        }
    }
}

/// The key of an encrypted thread: the only boxed value wide enough to be one.
pub fn e2ee_thread_key(op: &[Value]) -> Option<String> {
    if !matches!(
        name(op)?,
        "verifyE2EEMetadataThreadExistsV2" | "verifyHybridThreadExists"
    ) {
        return None;
    }
    let mut values = Vec::new();
    for v in op {
        all_boxed(v, &mut values);
    }
    values
        .into_iter()
        .find(|v| digits(v) && (15..=19).contains(&v.len()))
        .map(str::to_owned)
}

/// A rendered human name, not a URL, a path, a JSON blob or an id.
fn looks_like_a_name(v: Option<&str>) -> Option<&str> {
    v.filter(|s| {
        !s.is_empty()
            && !s.starts_with("http")
            && !s.starts_with('/')
            && !s.starts_with('{')
            && !digits(s)
    })
}

/// `verifyContactRowExists` (25 wide) / `deleteThenInsertContact` (61 wide).
pub fn participant(op: &[Value]) -> Option<Participant> {
    let (width, picture, display, handle) = match name(op)? {
        "verifyContactRowExists" => (25, 4, 5, None),
        "deleteThenInsertContact" => (61, 4, 11, Some(12)),
        _ => return None,
    };
    if op.len() != width {
        return None;
    }
    let id = boxed(op, 2).filter(|i| digits(i))?;
    Some(Participant {
        fb_user_id: id.to_owned(),
        name: looks_like_a_name(string(op, display)).map(str::to_owned),
        username: handle
            .and_then(|h| looks_like_a_name(string(op, h)))
            .map(str::to_owned),
        profile_pic_url: string(op, picture)
            .filter(|p| p.starts_with("http"))
            .map(str::to_owned),
    })
}

/// `upsertReaction`, nine wide.
pub fn reaction(op: &[Value]) -> Option<Reaction> {
    if name(op)? != "upsertReaction" || op.len() <= 8 || boxed(op, 7) != Some(MARK) {
        return None;
    }
    let message_id = mid(op, 4)?;
    let thread = boxed(op, 2).filter(|t| !t.is_empty())?;
    let actor = boxed(op, 5).filter(|a| !a.is_empty())?;
    let emoji = string(op, 6).filter(|e| !e.is_empty())?;
    Some(Reaction {
        thread_key: thread.to_owned(),
        message_id: message_id.to_owned(),
        actor_id: actor.to_owned(),
        emoji: emoji.to_owned(),
        reacted_ms: stamp(op, 8)?,
    })
}

/// `insertBlobAttachment` (51 wide) / `insertXmaAttachment` (135 wide).
pub fn attachment(op: &[Value]) -> Option<Attachment> {
    // (width, thread, message, url, mime, preview, id, kind)
    let (width, thread, message, url, mime, preview, id, kind) = match name(op)? {
        "insertBlobAttachment" => (51, 29, 34, 5, 8, Some(10), Some(2), "blob"),
        "insertXmaAttachment" => (135, 27, 32, 10, 13, None, None, "xma"),
        _ => return None,
    };
    if op.len() != width {
        return None;
    }
    let message_id = mid(op, message)?;
    let thread = boxed(op, thread).filter(|t| !t.is_empty())?;
    let text = |i: Option<usize>| {
        i.and_then(|i| string(op, i))
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    Some(Attachment {
        thread_key: thread.to_owned(),
        message_id: message_id.to_owned(),
        attachment_id: text(id),
        kind,
        mime_type: text(Some(mime)),
        url: text(Some(url)),
        preview_url: text(preview),
    })
}

/// `addParticipantIdToGroupThread`, seventeen wide: one person's membership of a thread.
pub fn member(op: &[Value]) -> Option<Member> {
    if name(op)? != "addParticipantIdToGroupThread" || op.len() != 17 || boxed(op, 11) != Some(MARK)
    {
        return None;
    }
    let thread = boxed(op, 2).filter(|t| digits(t))?;
    let user = boxed(op, 3).filter(|u| digits(u))?;
    Some(Member {
        thread_key: thread.to_owned(),
        fb_user_id: user.to_owned(),
        joined_ms: stamp(op, 4),
        is_admin: op.get(15) == Some(&Value::Bool(true)),
    })
}
