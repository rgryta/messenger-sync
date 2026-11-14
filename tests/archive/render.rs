//! What a thread with no text is allowed to claim.
//!
//! Ported case for case from the retired Python `tests/test_render_encrypted.py`. The
//! archive holds 85,185 messages with no text across 55 threads, and only 16 of those
//! threads sit in the end-to-end-encrypted store. The risk is not that those rows are
//! missing — it is that they render identically to a message somebody genuinely sent empty,
//! and a count beside them reads as a count of readable messages.
//!
//! What these cases are keyed on changed: whether the archive holds any text, which it
//! can observe, rather than which store a row was filed under, which it cannot trust.
//!
//! No database here. These are the only tests in the suite that run without Docker.

use chrono::{DateTime, TimeDelta, TimeZone, Utc};
use messenger_core::models::{AccountStatus, HistoryRow, ThreadRow};
use messenger_mcp::render::{render_history, render_status, render_threads, window_note};

const SYNC_GROUP_INBOX: i32 = 1;
const SYNC_GROUP_E2EE: i32 = 95;
/// The tolerance `render.rs` allows before it calls a listing stale.
const STALE_AFTER: TimeDelta = TimeDelta::hours(1);

fn when() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 21, 20, 28, 0).unwrap()
}

/// An envelope: a time, a sender and an id, and no words.
fn envelope() -> HistoryRow {
    HistoryRow {
        account_id: "me".to_owned(),
        thread_key: "7000000000000042".to_owned(),
        message_id: Some("mid.$abc".to_owned()),
        ts: when(),
        sender_id: Some("100000000000623".to_owned()),
        text: None,
        item_type: "text".to_owned(),
        sync_group: Some(SYNC_GROUP_E2EE),
        reply_to_id: None,
        deleted_at: None,
        edited: false,
        sender_name: Some("Tester Testowy".to_owned()),
        sender_username: None,
        reactions: None,
        attachments: None,
    }
}

/// A line read from the client's screen, as `get_history` returns it.
fn screen() -> HistoryRow {
    HistoryRow {
        message_id: None,
        sender_id: None,
        sender_name: Some("\u{141}ukasz".to_owned()),
        text: Some("nie wiadomo".to_owned()),
        item_type: "rendered".to_owned(),
        sync_group: None,
        ..envelope()
    }
}

fn listed() -> ThreadRow {
    ThreadRow {
        account_id: "me".to_owned(),
        thread_key: "7000000000000042".to_owned(),
        title: None,
        is_group: false,
        sync_group: SYNC_GROUP_E2EE,
        last_activity_at: Some(when()),
        history_done: true,
        has_no_text: Some(true),
        newest_seen_at: Some(when()),
        rendered_lines: 0,
        message_count: 22185,
        counterparts: Some(vec!["Kontakt Przykładowy".to_owned()]),
        total_matches: 1,
    }
}

fn account() -> AccountStatus {
    AccountStatus {
        account_id: "me".to_owned(),
        username: None,
        enabled: true,
        last_auth_error: None,
        last_auth_error_at: None,
        threads: 91,
        textless_threads: 55,
        textless_messages: 85185,
        threads_pending_history: 0,
        messages: 206230,
        system_events: 0,
        participants: 261,
        oldest_message_at: Some(when()),
        newest_message_at: Some(when()),
    }
}

#[test]
fn a_message_with_no_text_never_claims_it_was_sent_empty() {
    let out = render_history(&[envelope()], "7000000000000042", false, None);
    assert!(out.contains("[text not captured]"), "{out}");
    assert!(!out.contains("no text and nothing attached"), "{out}");
}

#[test]
fn a_plain_store_message_with_no_text_says_the_same_thing() {
    // The case that was wrong, and the reason it looked right. This used to say
    // "[no text and nothing attached]" for anything outside the encrypted store —
    // "where empty means empty". It is not: 39 one-to-one DMs in the plain store hold
    // 9,992 rows whose text never arrived either, and every one was being described as a
    // message the sender had left blank.
    let row = HistoryRow {
        sync_group: Some(SYNC_GROUP_INBOX),
        ..envelope()
    };
    let out = render_history(&[row], "T1", false, None);
    assert!(out.contains("[text not captured]"), "{out}");
    assert!(!out.contains("no text and nothing attached"), "{out}");
}

#[test]
fn text_still_wins_in_an_encrypted_thread() {
    // Ordering guard: were a frame ever to arrive with text, print the text. The marker
    // is a statement about what reached the archive, not about the store a row came from.
    let row = HistoryRow {
        text: Some("hello".to_owned()),
        ..envelope()
    };
    let out = render_history(&[row], "T1", false, None);
    assert!(out.contains("hello"), "{out}");
    assert!(!out.contains("text not captured"), "{out}");
}

#[test]
fn a_thread_listing_says_the_count_has_no_text_behind_it() {
    let out = render_threads(&[listed()]);
    assert!(out.contains("22185 message(s)"), "{out}");
    assert!(out.contains("metadata only"), "{out}");
}

#[test]
fn a_thread_that_holds_text_is_not_labelled() {
    let out = render_threads(&[ThreadRow {
        has_no_text: Some(false),
        ..listed()
    }]);
    assert!(!out.contains("metadata only"), "{out}");
}

#[test]
fn a_plain_store_thread_with_no_text_is_still_labelled() {
    // Keyed on the store, these 39 threads were reported as ordinary conversations
    // carrying 9,992 readable messages.
    let out = render_threads(&[ThreadRow {
        sync_group: SYNC_GROUP_INBOX,
        has_no_text: Some(true),
        ..listed()
    }]);
    assert!(out.contains("metadata only, no text"), "{out}");
}

#[test]
fn status_counts_every_thread_that_holds_no_text() {
    // It reported 16 while 55 threads held no text, because it counted the encrypted
    // store rather than the threads with nothing in them.
    let out = render_status(&[account()], &[]);
    assert!(out.contains("of which 55 hold no text"), "{out}");
    assert!(out.contains("55 thread(s) hold envelopes only"), "{out}");
    assert!(out.contains("85185 message(s)"), "{out}");
    assert!(out.contains("search"), "{out}");
}

#[test]
fn status_says_the_missing_text_is_not_coming_back() {
    // Nothing recovers it any more, so the status must not point at a tool that would.
    let out = render_status(&[account()], &[]);
    assert!(out.contains("will stay without text"), "{out}");
    assert!(!out.contains("capture"), "{out}");
}

#[test]
fn status_stays_quiet_when_every_thread_holds_text() {
    let out = render_status(
        &[AccountStatus {
            textless_threads: 0,
            ..account()
        }],
        &[],
    );
    assert!(!out.contains("envelopes only"), "{out}");
}

#[test]
fn an_archive_with_no_account_says_so_rather_than_printing_nothing() {
    assert_eq!(
        render_status(&[], &[]),
        "no account registered yet — the client has never run"
    );
    assert!(render_status(&[account()], &[]).contains("no loop has reported a run yet"));
}

#[test]
fn a_thread_whose_listing_moved_since_capture_says_so() {
    // The case that started this: activity today, newest captured message days old.
    let out = render_threads(&[ThreadRow {
        newest_seen_at: Some(Utc.with_ymd_and_hms(2026, 10, 18, 15, 28, 0).unwrap()),
        ..listed()
    }]);
    assert!(
        out.contains("listing moved since the newest captured message"),
        "{out}"
    );
    assert!(out.contains("2026-10-18T15:28"), "{out}");
    // `last_activity_at` moves for reactions too, so the wording stays factual.
    assert!(!out.to_lowercase().contains("missing"), "{out}");
}

#[test]
fn a_current_thread_says_nothing_about_staleness() {
    assert!(!render_threads(&[listed()]).contains("listing moved"));
}

#[test]
fn the_listings_permanent_head_start_is_not_reported() {
    // `0009_forward_attempt.sql` measured encrypted threads permanently ahead by
    // seconds. Those threads held every message the walk had ever been given, so a note
    // on them would be noise on all sixteen, forever.
    for ahead in [
        TimeDelta::milliseconds(260),
        TimeDelta::seconds(7),
        TimeDelta::seconds(50),
        TimeDelta::minutes(2),
    ] {
        let out = render_threads(&[ThreadRow {
            newest_seen_at: Some(when() - ahead),
            ..listed()
        }]);
        assert!(!out.contains("listing moved"), "{ahead} -- {out}");
    }
}

#[test]
fn a_gap_past_the_tolerance_is_reported() {
    let out = render_threads(&[ThreadRow {
        newest_seen_at: Some(when() - STALE_AFTER - TimeDelta::minutes(1)),
        ..listed()
    }]);
    assert!(
        out.contains("listing moved since the newest captured message"),
        "{out}"
    );
}

#[test]
fn a_screen_line_is_marked_and_prints_its_words() {
    // The point of folding these in: "show me this conversation" now answers with the
    // words for an encrypted DM, instead of sending the reader to a second tool.
    let out = render_history(&[screen()], "T1", false, None);
    assert!(out.contains("nie wiadomo"), "{out}");
    assert!(out.contains("[screen]"), "{out}");
}

#[test]
fn a_screen_line_carries_no_message_id() {
    // The rendering has none, which is why these are their own rows. Printing
    // `[message None]` would invite exactly the cross-reference that does not exist.
    let out = render_history(&[screen()], "T1", false, None);
    assert!(!out.contains("[message"), "{out}");
    assert!(!out.contains("None"), "{out}");
}

#[test]
fn the_header_says_how_many_lines_came_from_the_screen() {
    // Said up front, because the two kinds of line mean different things: one knows the
    // second a message was sent and not its words, the other the reverse.
    let typed = HistoryRow {
        text: Some("hello".to_owned()),
        ..envelope()
    };
    let out = render_history(&[screen(), typed], "T1", false, None);
    assert!(
        out.contains("1 of them read from the client's screen"),
        "{out}"
    );
    assert!(out.contains("precise to the minute"), "{out}");
}

#[test]
fn a_thread_with_no_screen_lines_says_nothing_about_them() {
    let typed = HistoryRow {
        text: Some("hello".to_owned()),
        ..envelope()
    };
    assert!(!render_history(&[typed], "T1", false, None).contains("screen"));
}

#[test]
fn a_listing_says_how_many_lines_were_read_from_the_screen() {
    let out = render_threads(&[ThreadRow {
        has_no_text: Some(false),
        rendered_lines: 3306,
        ..listed()
    }]);
    assert!(
        out.contains("22185 message(s), 3306 line(s) read from the client's screen"),
        "{out}"
    );
    assert!(!out.contains("metadata only"), "{out}");
}

#[test]
fn a_thread_never_read_from_the_screen_says_nothing_about_it() {
    assert!(!render_threads(&[listed()]).contains("read from the client's screen"));
}

#[test]
fn an_empty_window_is_not_reported_as_an_empty_thread() {
    // Saying "nothing stored" about a thread holding 9,243 messages, because two
    // requested days happened to be quiet, is how a reader concludes the archive is
    // empty and stops asking.
    let windowed = render_history(&[], "T1", true, None);
    assert!(windowed.contains("in that date window"), "{windowed}");
    assert!(
        windowed.contains("`threads` prints its total"),
        "{windowed}"
    );
    assert_eq!(
        render_history(&[], "T1", false, None),
        "no messages stored for thread T1"
    );
}

#[test]
fn a_capped_page_says_how_many_more_the_period_holds() {
    let first = Utc.with_ymd_and_hms(2026, 7, 22, 11, 55, 2).unwrap();
    let last = Utc.with_ymd_and_hms(2026, 7, 26, 9, 0, 0).unwrap();

    let forward = window_note(405, first, last, true).expect("a note");
    let backward = window_note(405, first, last, false).expect("a note");

    assert!(forward.contains("405 more row(s)"), "{forward}");
    assert!(forward.contains("after=2026-07-26T08:59:59Z"), "{forward}");
    assert!(backward.contains("405 older row(s)"), "{backward}");
    assert!(
        backward.contains("before=2026-07-22T11:55:03Z"),
        "{backward}"
    );
    assert!(window_note(0, first, last, true).is_none());
}

#[test]
fn a_dm_with_nobody_in_it_is_named_plainly_rather_than_untitled() {
    let out = render_threads(&[ThreadRow {
        counterparts: None,
        ..listed()
    }]);
    assert!(out.starts_with("1 conversation(s)"), "{out}");
    assert!(out.contains("(nobody identified yet)"), "{out}");
}

#[test]
fn a_crowded_group_names_three_and_counts_the_rest() {
    let out = render_threads(&[ThreadRow {
        is_group: true,
        counterparts: Some(
            ["a", "b", "c", "d", "e"]
                .iter()
                .map(|n| (*n).to_owned())
                .collect(),
        ),
        ..listed()
    }]);
    assert!(out.contains("a, b, c +2 more (group"), "{out}");
}

#[test]
fn an_empty_listing_says_so_rather_than_printing_a_header() {
    assert_eq!(render_threads(&[]), "no conversations match");
}
