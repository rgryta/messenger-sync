//! Rows to text.
//!
//! Everything a tool returns is read by a model, so the format optimises for that: one
//! fact per line, ids kept inline so a follow-up call needs no lookup, and an explicit
//! note when a result was truncated. A silently short list reads as "that is all there
//! is", which is the one lie worth going out of the way to avoid.
//!
//! Ported byte for byte from the retired Python server's `render.py`, so clients saw no
//! change at cutover.

use chrono::{DateTime, TimeDelta, Utc};
use messenger_core::models::{
    AccountStatus, AliasRow, HistoryRow, LoopRow, PersonRow, Revision, SearchHit, ThreadRow,
};

pub const CAPTION_LIMIT: usize = 200;

/// How far the listing's clock may run ahead of the newest captured message before it is
/// worth mentioning.
///
/// Not a round number for tidiness: `0009_forward_attempt.sql` measured the encrypted
/// store sitting *permanently* ahead by "0.26s, 7s, 50s, two minutes" on threads that
/// already held every message the walk had ever been given. Reporting every such gap
/// would put a staleness note on all sixteen encrypted threads forever, which is the
/// same false signal this note exists to remove. An hour clears that measured range by a
/// wide margin and still surfaces the case that matters — a thread days behind.
const STALE_AFTER_SECONDS: i64 = 3600;

/// How many members to name before a group is summarised by a count instead.
const NAMED_MEMBERS: usize = 3;

pub fn when(value: Option<DateTime<Utc>>) -> String {
    match value {
        Some(value) => value.format("%Y-%m-%dT%H:%M%z").to_string(),
        None => "never".to_owned(),
    }
}

/// Python's `repr` of a string, which is what several messages quote a caller's value
/// with.
///
/// shortcut: control characters other than tab, newline and carriage return are passed
/// through rather than escaped as `\xNN`, so a value containing one renders differently
/// from the Python. Upgrade this if a message ever has to be byte-identical for such a
/// value; no caller sends one today.
pub fn py_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(value.len() + 2);
    out.push(quote);
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Whitespace collapsed, then clipped on a word boundary with the overflow counted.
fn clip(text: &str) -> String {
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let length = flat.chars().count();
    if length <= CAPTION_LIMIT {
        return flat;
    }
    let window: String = flat.chars().take(CAPTION_LIMIT).collect();
    // `rsplit(" ", 1)[0]`: everything before the last space, or the whole window when
    // there is none.
    let head = match window.rsplit_once(' ') {
        Some((head, _)) => head.to_owned(),
        None => window,
    };
    let dropped = length - head.chars().count();
    format!("{head}\u{2026} (+{dropped} chars)")
}

fn truncation(total: i64, shown: usize) -> Option<String> {
    if shown == 0 {
        return None;
    }
    if total > shown as i64 {
        return Some(format!(
            "note: showing {shown} of {total} match(es) — raise `limit` or narrow the filters"
        ));
    }
    None
}

fn speaker(name: Option<&str>, username: Option<&str>, id: Option<&str>) -> String {
    name.filter(|value| !value.is_empty())
        .or(username.filter(|value| !value.is_empty()))
        .or(id.filter(|value| !value.is_empty()))
        .unwrap_or("unknown")
        .to_owned()
}

/// What to call a conversation.
///
/// A one-to-one thread has no title — the real client renders the other person's name —
/// so every DM used to print as "(untitled)" and the archive could not tell one from
/// another. The people who have spoken in it are the next best thing, and for a DM there
/// is exactly one of them.
fn thread_name(row: &ThreadRow) -> String {
    if let Some(title) = row.title.as_deref().filter(|title| !title.is_empty()) {
        return title.to_owned();
    }
    let people: Vec<&str> = row
        .counterparts
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(String::as_str)
        .filter(|person| !person.is_empty())
        .collect();
    if people.is_empty() {
        // A thread we hold but have never seen anybody speak in: real, and better said
        // plainly than dressed up with a name we do not have.
        return "(nobody identified yet)".to_owned();
    }
    if people.len() <= NAMED_MEMBERS {
        return people.join(", ");
    }
    let shown = people[..NAMED_MEMBERS].join(", ");
    format!("{shown} +{} more", people.len() - NAMED_MEMBERS)
}

pub fn render_threads(rows: &[ThreadRow]) -> String {
    if rows.is_empty() {
        return "no conversations match".to_owned();
    }
    let mut lines = vec![format!(
        "{} conversation(s), most recently active first",
        rows.len()
    )];
    for row in rows {
        let kind = if row.is_group { "group" } else { "DM" };
        // Said out loud because it changes what the archive can promise: the message
        // count is real and the text behind it is absent, which is the one combination a
        // reader will otherwise assume cannot happen.
        let crypto = if row.has_no_text.unwrap_or(false) {
            ", metadata only, no text"
        } else {
            ""
        };
        let owed = if row.history_done {
            ""
        } else {
            ", history still being fetched"
        };
        // `last_activity_at` is the listing's timestamp and moves for things that are
        // not messages — a reaction will do it — so this reports the discrepancy and
        // does not claim messages are missing.
        let stale = match (row.newest_seen_at, row.last_activity_at) {
            (Some(seen), Some(activity))
                if (activity - seen) > TimeDelta::seconds(STALE_AFTER_SECONDS) =>
            {
                format!(
                    ", listing moved since the newest captured message ({})",
                    when(Some(seen))
                )
            }
            _ => String::new(),
        };
        // Said beside the envelope count, not instead of it: the two overlap, and the
        // envelope count is the only one that says how many messages the protocol held.
        let screen = if row.rendered_lines != 0 {
            format!(
                ", {} line(s) read from the client's screen",
                row.rendered_lines
            )
        } else {
            String::new()
        };
        lines.push(format!(
            "{} ({kind}{crypto}, {} message(s){screen}, last {}{owed}{stale})  [thread {}]",
            thread_name(row),
            row.message_count,
            when(row.last_activity_at),
            row.thread_key,
        ));
    }
    if let Some(note) = truncation(rows.first().map_or(0, |row| row.total_matches), rows.len()) {
        lines.push(note);
    }
    lines.join("\n")
}

/// What to print for a message, which for most of this archive is what to print for a
/// message that carries no text.
///
/// `item_type` defaults to 'text' for everything the decoder stores, so a photo, a
/// sticker, a voice note and a genuinely empty message all rendered as the same `[text]`
/// — a reader could not tell which. Until the payload shapes for media are captured and
/// decoded, this says what is actually known.
fn body(
    deleted_at: Option<DateTime<Utc>>,
    text: Option<&str>,
    edited: bool,
    item_type: &str,
    attachments: Option<&str>,
) -> String {
    if let Some(at) = deleted_at {
        // Ahead of every other branch. The text is still in the archive and still in the
        // revision log; this layer withholds it, because printing what someone deleted
        // beside the note that they deleted it makes the marker pointless.
        return format!("[deleted {}]", when(Some(at)));
    }
    if let Some(text) = text.filter(|text| !text.is_empty()) {
        let clipped = clip(text);
        return if edited {
            format!("{clipped} (edited)")
        } else {
            clipped
        };
    }
    if !item_type.is_empty() && item_type != "text" && item_type != "rendered" {
        return format!("[{item_type}]");
    }
    if let Some(attached) = attachments.filter(|attached| !attached.is_empty()) {
        // Media travels in its own instruction, so a photo or GIF decodes with no text
        // at all. Saying which kind beats printing an empty message.
        return format!("[{attached}]");
    }
    // One line, because there is only one case. Reaching here means `text IS NULL`,
    // which across the whole archive means no text was delivered; the empty string is
    // never stored. So the honest line is the one that says nothing about what was sent.
    "[text not captured]".to_owned()
}

/// Reactions and reply context, appended to a rendered message.
fn annotations(reply_to: Option<&str>, reactions: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(reply_to) = reply_to.filter(|value| !value.is_empty()) {
        parts.push(format!("replying to {reply_to}"));
    }
    if let Some(reactions) = reactions.filter(|value| !value.is_empty()) {
        parts.push(reactions.to_owned());
    }
    if parts.is_empty() {
        return String::new();
    }
    format!("  ({})", parts.join("; "))
}

pub fn render_history(
    rows: &[HistoryRow],
    thread_key: &str,
    windowed: bool,
    note: Option<&str>,
) -> String {
    if rows.is_empty() {
        // Saying "nothing stored" about a thread holding 9,243 messages, because two
        // requested days happened to be quiet, is how a reader concludes the archive is
        // empty and stops asking.
        if windowed {
            return format!(
                "no messages for thread {thread_key} in that date window - \
                 the thread may still hold messages outside it; `threads` prints its total"
            );
        }
        return format!("no messages stored for thread {thread_key}");
    }
    let rendered = rows
        .iter()
        .filter(|row| row.item_type == "rendered")
        .count();
    let mut header = format!(
        "thread {thread_key} — {} message(s), oldest first",
        rows.len()
    );
    if rendered != 0 {
        // Said up front, because the two kinds of line mean different things and a
        // reader who does not know that will read a minute-precise screen reading as the
        // archive's own record of when something was sent.
        header.push_str(&format!(
            "; {rendered} of them read from the client's screen (marked `screen`, \
             clock precise to the minute, no message id)"
        ));
    }
    let mut lines = vec![header];
    for row in rows {
        let body = body(
            row.deleted_at,
            row.text.as_deref(),
            row.edited,
            &row.item_type,
            row.attachments.as_deref(),
        );
        let speaker = speaker(
            row.sender_name.as_deref(),
            row.sender_username.as_deref(),
            row.sender_id.as_deref(),
        );
        if row.item_type == "rendered" {
            // No message id to print: the rendering carries none, which is why these are
            // their own rows and are never joined to the envelopes.
            lines.push(format!(
                "{} {speaker}: {body}  [screen]",
                when(Some(row.ts))
            ));
            continue;
        }
        lines.push(format!(
            "{} {speaker}: {body}{}  [message {}]",
            when(Some(row.ts)),
            annotations(row.reply_to_id.as_deref(), row.reactions.as_deref()),
            option_str(row.message_id.as_deref()),
        ));
    }
    if let Some(note) = note {
        lines.push(note.to_owned());
    }
    lines.join("\n")
}

/// `f"{value}"` on a Python `None`, which is what an absent id prints as.
///
/// Only reachable on a search hit for a rendered line, which carries no message id. The
/// Python printed `message None` there and the port kept it; it is called out as a wart in
/// the port's notes and pinned by `tests/archive/tools.rs`.
fn option_str(value: Option<&str>) -> String {
    value.unwrap_or("None").to_owned()
}

pub fn render_search(rows: &[SearchHit], query: &str) -> String {
    if rows.is_empty() {
        return format!("no messages match {}", py_repr(query));
    }
    let mut lines = vec![format!(
        "{} result(s) for {}, best match first",
        rows.len(),
        py_repr(query)
    )];
    for row in rows {
        let title = row
            .thread_title
            .as_deref()
            .filter(|title| !title.is_empty())
            .unwrap_or(&row.thread_key);
        lines.push(format!(
            "[{title}] {} {}: {}  [thread {} message {}]",
            when(Some(row.ts)),
            speaker(
                row.sender_name.as_deref(),
                row.sender_username.as_deref(),
                row.sender_id.as_deref(),
            ),
            body(None, row.text.as_deref(), false, &row.item_type, None),
            row.thread_key,
            option_str(row.message_id.as_deref()),
        ));
        if let Some(headline) = row.headline.as_deref().filter(|value| !value.is_empty()) {
            lines.push(format!("    \u{2026}{headline}\u{2026}"));
        }
    }
    if let Some(note) = truncation(rows.first().map_or(0, |row| row.total_matches), rows.len()) {
        lines.push(note);
    }
    lines.join("\n")
}

pub fn render_people(rows: &[PersonRow], aliases: &[AliasRow]) -> String {
    if rows.is_empty() {
        return "nobody matches".to_owned();
    }
    let mut lines = vec![format!("{} person/people", rows.len())];
    for row in rows {
        let names = row
            .name
            .as_deref()
            .filter(|value| !value.is_empty())
            .or(row.username.as_deref().filter(|value| !value.is_empty()))
            .unwrap_or(&row.fb_user_id);
        let handle = match row.username.as_deref().filter(|value| !value.is_empty()) {
            Some(username) => format!("@{username}"),
            None => "no handle".to_owned(),
        };
        let alias = match row.aliases.as_deref().filter(|value| !value.is_empty()) {
            Some(aliases) => format!("alias {aliases}; "),
            None => String::new(),
        };
        // The hop that did not exist: a caller who wants this person's DM no longer has
        // to search for something they said and read the key off the hit.
        let threads = row.thread_keys.as_deref().unwrap_or(&[]);
        let where_ = if threads.is_empty() {
            String::new()
        } else {
            format!("  [threads {}]", threads.join(", "))
        };
        lines.push(format!(
            "{names} ({alias}{handle}) — {} message(s)  [member {}:{}]{where_}",
            row.message_count, row.account_id, row.fb_user_id,
        ));
    }
    lines.push(String::new());
    if aliases.is_empty() {
        lines.push("no aliases set".to_owned());
    } else {
        lines.push(format!("{} alias(es)", aliases.len()));
        for alias in aliases {
            let note = match alias.note.as_deref().filter(|value| !value.is_empty()) {
                Some(note) => format!("{note}: "),
                None => String::new(),
            };
            let members = alias
                .members
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("(nobody)");
            lines.push(format!("{} — {note}{members}", alias.alias));
        }
    }
    lines.join("\n")
}

pub fn render_status(accounts: &[AccountStatus], loops: &[LoopRow]) -> String {
    if accounts.is_empty() {
        return "no account registered yet — the client has never run".to_owned();
    }
    let mut lines = vec!["harvest status".to_owned()];
    for row in accounts {
        let state = if row.enabled { "enabled" } else { "disabled" };
        let username = row
            .username
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("?");
        lines.push(format!(
            "{} (@{username}, {state}): {} thread(s) of which {} hold no text, \
             {} message(s), {} participant(s)",
            row.account_id, row.threads, row.textless_threads, row.messages, row.participants,
        ));
        lines.push(format!(
            "  history {} to {}, {} thread(s) still being paged backwards",
            when(row.oldest_message_at),
            when(row.newest_message_at),
            row.threads_pending_history,
        ));
        if row.textless_threads != 0 {
            // Searchability is the consequence people trip over: full-text search
            // matches on stored text, so these threads cannot ever appear in a result,
            // and a search that misses them looks like one that found everything. New
            // encrypted text is decrypted by the client's own device as it arrives; these
            // envelopes predate that and nothing can fill them in.
            lines.push(format!(
                "  {} thread(s) hold envelopes only, {} message(s) in total with no text — \
                 stored before the client decrypted one-to-one chats itself (2026-11-14), \
                 so it will stay without text and cannot appear in search results.",
                row.textless_threads, row.textless_messages,
            ));
        }
        if row.system_events != 0 {
            lines.push(format!(
                "  plus {} system event(s) — stored and shown when reading a thread, \
                 but nobody sent them, so they are not counted as messages",
                row.system_events
            ));
        }
        if let Some(error) = row.last_auth_error.as_deref().filter(|e| !e.is_empty()) {
            // Not a transient fault: nothing new is archived until a human signs in
            // again and hands the client the new session.
            lines.push(format!(
                "  SESSION FAILING since {}: {error} — nothing new is being archived \
                 until a human signs in again and gives the client the new session",
                when(row.last_auth_error_at)
            ));
        }
    }
    if loops.is_empty() {
        lines.push("no loop has reported a run yet".to_owned());
    }
    for entry in loops {
        let detail = match entry
            .current_thread_key
            .as_deref()
            .filter(|key| !key.is_empty())
        {
            Some(key) => format!(" (thread {key})"),
            None => String::new(),
        };
        lines.push(format!(
            "{} loop: last run {}{detail}",
            entry.loop_name,
            when(entry.last_run_at)
        ));
        if let Some(error) = entry.last_error.as_deref().filter(|e| !e.is_empty()) {
            lines.push(format!(
                "  last error {}: {error}",
                when(entry.last_error_at)
            ));
        }
    }
    lines.join("\n")
}

/// One message's text over time, oldest first.
///
/// The only place a deleted message's text is shown. Every other view withholds it on
/// purpose; asking for the history is asking for exactly this.
pub fn render_revisions(
    rows: &[Revision],
    header: &str,
    deleted_at: Option<DateTime<Utc>>,
) -> String {
    if rows.is_empty() && deleted_at.is_none() {
        return format!("{header}\nno recorded changes");
    }
    let mut lines = vec![header.to_owned()];
    for row in rows {
        // A NULL start is unknown, not missing: nothing records when a message was first
        // stored, so the earliest text held has no honest start time.
        let start = match row.first_seen_at {
            Some(at) => when(Some(at)),
            None => "unknown".to_owned(),
        };
        let end = match row.superseded_at {
            Some(at) => when(Some(at)),
            None => "current".to_owned(),
        };
        let text = row
            .text
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("(no text)");
        lines.push(format!("  {}  {start} -> {end}   \"{text}\"", row.seq));
    }
    if let Some(at) = deleted_at {
        lines.push(format!("deleted {}", when(Some(at))));
    }
    if !rows.is_empty() {
        lines.push(
            "note: revision 1 is the earliest text this archive saw, which is not \
             necessarily what was first sent."
                .to_owned(),
        );
    }
    lines.join("\n")
}

/// Say how much of the requested period was not shown, and the call that fetches it.
///
/// Without this a capped page is indistinguishable from the whole period, and a caller
/// who asked for July reads the last day of it as all of July. The cursor overlaps the
/// page by a second so that a message sharing the boundary's timestamp is never skipped.
pub fn window_note(
    more: i64,
    first: DateTime<Utc>,
    last: DateTime<Utc>,
    oldest_first: bool,
) -> Option<String> {
    if more <= 0 {
        return None;
    }
    if oldest_first {
        let cursor = (last - TimeDelta::seconds(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        return Some(format!(
            "note: {more} more row(s) in this period after the last one shown - \
             next page: after={cursor} (a second of overlap, so none is skipped)"
        ));
    }
    let cursor = (first + TimeDelta::seconds(1))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    Some(format!(
        "note: {more} older row(s) match this request - \
         next page: before={cursor} (a second of overlap, so none is skipped)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn moment() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
    }

    #[test]
    fn a_timestamp_prints_with_an_offset_and_no_seconds() {
        // `strftime("%Y-%m-%dT%H:%M%z")`, which is what every line of every tool uses.
        assert_eq!(when(Some(moment())), "2026-08-01T12:00+0000");
        assert_eq!(when(None), "never");
    }

    #[test]
    fn whitespace_is_collapsed_and_long_text_is_clipped_on_a_word() {
        assert_eq!(clip("two   words\nhere"), "two words here");
        let long = "ab ".repeat(100); // 300 characters
        let clipped = clip(&long);
        assert!(clipped.starts_with("ab ab"), "{clipped}");
        assert!(clipped.ends_with(" chars)"), "{clipped}");
        assert!(!clipped.contains("  "), "{clipped}");
    }

    #[test]
    fn clipping_counts_characters_not_bytes() {
        // The corpus is mostly Polish. Clipping on bytes would cut mid-character and
        // report a character count that is nothing like the one Python prints.
        let text = "\u{17c}".repeat(250);
        let clipped = clip(&text);
        assert!(clipped.contains("(+50 chars)"), "{clipped}");
    }

    #[test]
    fn a_message_with_no_text_never_claims_it_was_sent_empty() {
        assert_eq!(body(None, None, false, "text", None), "[text not captured]");
    }

    #[test]
    fn an_item_type_and_an_attachment_both_beat_the_empty_line() {
        assert_eq!(body(None, None, false, "sticker", None), "[sticker]");
        assert_eq!(
            body(None, None, false, "text", Some("image/jpeg")),
            "[image/jpeg]"
        );
    }

    #[test]
    fn a_deleted_message_withholds_its_text_in_favour_of_the_marker() {
        assert_eq!(
            body(Some(moment()), Some("secret"), false, "text", None),
            "[deleted 2026-08-01T12:00+0000]"
        );
    }

    #[test]
    fn an_edit_is_marked_after_the_text() {
        assert_eq!(body(None, Some("hi"), true, "text", None), "hi (edited)");
    }

    #[test]
    fn a_query_is_quoted_the_way_python_does() {
        assert_eq!(py_repr("pierogi"), "'pierogi'");
        assert_eq!(py_repr("don't"), "\"don't\"");
        assert_eq!(py_repr("it's \"fine\""), "'it\\'s \"fine\"'");
        assert_eq!(py_repr("back\\slash"), "'back\\\\slash'");
    }

    #[test]
    fn a_page_that_is_the_whole_period_gets_no_note() {
        assert!(window_note(0, moment(), moment(), true).is_none());
        assert!(window_note(-3, moment(), moment(), false).is_none());
    }

    #[test]
    fn the_next_page_cursor_overlaps_by_a_second_in_both_directions() {
        let forward = window_note(5, moment(), moment(), true).unwrap();
        assert!(forward.contains("after=2026-08-01T11:59:59Z"), "{forward}");
        let backward = window_note(5, moment(), moment(), false).unwrap();
        assert!(
            backward.contains("before=2026-08-01T12:00:01Z"),
            "{backward}"
        );
    }

    #[test]
    fn an_unknown_speaker_is_named_rather_than_left_blank() {
        assert_eq!(speaker(None, None, None), "unknown");
        assert_eq!(speaker(None, None, Some("61550")), "61550");
        assert_eq!(speaker(Some("Zofia"), Some("k"), Some("1")), "Zofia");
    }
}
