//! The read queries, against a real Postgres.
//!
//! Ported from the read half of the retired Python `tests/test_store.py` and the reader
//! half of `tests/test_revisions.py`. The writers are checked by `writes.rs` instead,
//! against the Python's recorded output.

use messenger_core::store::{self, Deletion};

use crate::support::{
    ACCOUNT, DM, GROUP, ME, Said, Thread, at, base, captured, db_test, deleted, me, participant,
    said, spoke_in, thread,
};

db_test!(history_is_returned_oldest_first_from_the_newest_page, |f| {
    me(&f.pool).await;
    thread(&f.pool, Thread::dm(DM)).await;
    for (id, second) in [("m1", 0), ("m2", 60), ("m3", 120)] {
        said(&f.pool, Said::new(DM, id, second)).await;
    }
    // Two of three, so the page is genuinely the newest one and not the whole thread.
    let rows = store::get_history(&f.pool, DM, None, None, None, 2)
        .await
        .expect("history");
    let ids: Vec<&str> = rows
        .iter()
        .map(|row| row.message_id.as_deref().unwrap())
        .collect();
    assert_eq!(ids, ["m2", "m3"]);
});

db_test!(
    history_with_an_after_reads_forward_and_counts_every_row_in_the_window,
    |f| {
        // The bug this guards: an `after` that handed back the END of the period read as
        // though everything between the start and it were missing.
        me(&f.pool).await;
        thread(&f.pool, Thread::dm(DM)).await;
        for second in 0..5 {
            said(&f.pool, Said::new(DM, &format!("m{second}"), second * 60)).await;
        }
        let rows = store::get_history(&f.pool, DM, None, None, Some(at(-1)), 2)
            .await
            .expect("history");
        let ids: Vec<&str> = rows
            .iter()
            .map(|row| row.message_id.as_deref().unwrap())
            .collect();
        assert_eq!(ids, ["m0", "m1"], "the oldest two after the cursor");
        let total = store::count_history(&f.pool, DM, None, None, Some(at(-1)))
            .await
            .expect("count");
        assert_eq!(total, 5, "the window holds five, not the two shown");
    }
);

db_test!(history_returns_rendered_lines_beside_the_envelopes, |f| {
    // The words of an encrypted conversation exist nowhere else. Keeping them behind a
    // second tool meant "show me this conversation" had the wrong answer for every DM.
    me(&f.pool).await;
    thread(&f.pool, Thread::encrypted(DM)).await;
    said(&f.pool, Said::new(DM, "m1", 0).envelope()).await;
    captured(
        &f.pool,
        DM,
        "run-1",
        base(),
        &[(0, Some(at(30)), "herbata", "Zofia")],
    )
    .await;
    let rows = store::get_history(&f.pool, DM, None, None, None, 50)
        .await
        .expect("history");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].item_type, "text");
    assert!(rows[0].text.is_none(), "the envelope carries no words");
    assert_eq!(rows[1].item_type, "rendered");
    assert_eq!(rows[1].text.as_deref(), Some("herbata"));
    assert!(
        rows[1].message_id.is_none(),
        "a rendering carries no message id anywhere, which is why it is its own row"
    );
    assert_eq!(rows[1].sender_name.as_deref(), Some("Zofia"));
});

db_test!(a_line_held_by_two_captures_is_returned_once, |f| {
    // A capture is a cumulative walk, so each pass re-stores everything the one before
    // it did. Measured 700 rows for 445 distinct lines on one live thread; reading an
    // encrypted thread repeated more than half of it.
    me(&f.pool).await;
    thread(&f.pool, Thread::encrypted(DM)).await;
    let line = (0, Some(at(30)), "herbata", "Zofia");
    captured(&f.pool, DM, "run-1", base(), &[line]).await;
    captured(
        &f.pool,
        DM,
        "run-2",
        at(600),
        &[line, (1, Some(at(60)), "pierogi", "Zofia")],
    )
    .await;
    let rows = store::get_history(&f.pool, DM, None, None, None, 50)
        .await
        .expect("history");
    let texts: Vec<&str> = rows
        .iter()
        .map(|row| row.text.as_deref().unwrap())
        .collect();
    assert_eq!(texts, ["herbata", "pierogi"]);
    let total = store::count_history(&f.pool, DM, None, None, None)
        .await
        .expect("count");
    assert_eq!(total, 2, "the count must dedupe the same way the page does");
});

db_test!(history_leaves_out_a_rendered_line_with_no_timestamp, |f| {
    // An undated line cannot be placed in a time window at all, and ordering by capture
    // position instead would mix threads of time.
    me(&f.pool).await;
    thread(&f.pool, Thread::encrypted(DM)).await;
    captured(
        &f.pool,
        DM,
        "run-1",
        base(),
        &[
            (0, None, "undateable", "Zofia"),
            (1, Some(at(30)), "herbata", "Zofia"),
        ],
    )
    .await;
    let rows = store::get_history(&f.pool, DM, None, None, None, 50)
        .await
        .expect("history");
    let texts: Vec<&str> = rows
        .iter()
        .map(|row| row.text.as_deref().unwrap())
        .collect();
    assert_eq!(texts, ["herbata"]);
});

db_test!(history_windows_rendered_lines_like_everything_else, |f| {
    me(&f.pool).await;
    thread(&f.pool, Thread::encrypted(DM)).await;
    captured(
        &f.pool,
        DM,
        "run-1",
        base(),
        &[
            (0, Some(at(-600)), "old", "Zofia"),
            (1, Some(at(600)), "new", "Zofia"),
        ],
    )
    .await;
    let rows = store::get_history(&f.pool, DM, None, None, Some(base()), 50)
        .await
        .expect("history");
    let texts: Vec<&str> = rows
        .iter()
        .map(|row| row.text.as_deref().unwrap())
        .collect();
    assert_eq!(texts, ["new"]);
});

db_test!(search_finds_rendered_text, |f| {
    // Without this, `search` silently missed every encrypted conversation: it matched
    // only `message.search`, so the words the archive worked hardest to get were the
    // ones it could not find.
    me(&f.pool).await;
    thread(&f.pool, Thread::encrypted(DM)).await;
    captured(
        &f.pool,
        DM,
        "run-1",
        base(),
        &[(0, Some(at(30)), "herbata z cytryna", "Zofia")],
    )
    .await;
    let hits = store::search_messages(&f.pool, "herbata", None, None, None, None, None, 25)
        .await
        .expect("search");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].item_type, "rendered");
    assert!(hits[0].message_id.is_none());
});

db_test!(search_by_person_leaves_rendered_text_out, |f| {
    // A rendered row has a sender *label*, not an id, so a person filter would have to
    // match a display string — and a filter that quietly matches differently per store is
    // worse than one that declines.
    me(&f.pool).await;
    thread(&f.pool, Thread::encrypted(DM)).await;
    participant(&f.pool, "200", Some("Zofia"), Some("zofia")).await;
    said(&f.pool, Said::new(DM, "m1", 0).from("200").text("herbata")).await;
    captured(
        &f.pool,
        DM,
        "run-1",
        base(),
        &[(0, Some(at(30)), "herbata z cytryna", "Zofia")],
    )
    .await;
    let senders = vec!["200".to_owned()];
    let hits = store::search_messages(
        &f.pool,
        "herbata",
        None,
        None,
        Some(&senders),
        None,
        None,
        25,
    )
    .await
    .expect("search");
    assert_eq!(hits.len(), 1, "the envelope only");
    assert_eq!(hits[0].message_id.as_deref(), Some("m1"));
});

db_test!(a_deleted_message_is_not_searchable, |f| {
    // Ported from `test_deleted_messages_are_not_searchable`. A hit is a headline of the
    // matching text, so returning one would print exactly what every other view holds
    // back; the text stays reachable through `revisions`.
    me(&f.pool).await;
    thread(&f.pool, Thread::dm(DM)).await;
    said(&f.pool, Said::new(DM, "m1", 0).text("herbata")).await;
    deleted(&f.pool, DM, "m1", at(60)).await;
    let hits = store::search_messages(&f.pool, "herbata", None, None, None, None, None, 25)
        .await
        .expect("search");
    assert!(hits.is_empty());
});

db_test!(a_dm_is_named_by_who_is_in_it, |f| {
    // A one-to-one thread has no title, so every DM used to list as "(untitled)" and the
    // archive could not tell one from another.
    me(&f.pool).await;
    thread(&f.pool, Thread::dm(DM)).await;
    participant(&f.pool, "200", Some("Zofia"), None).await;
    participant(&f.pool, ME, Some("Tester"), None).await;
    spoke_in(&f.pool, DM, "200", at(60)).await;
    spoke_in(&f.pool, DM, ME, at(120)).await;
    said(&f.pool, Said::new(DM, "m1", 0)).await;
    let rows = store::list_threads(&f.pool, None, None, None, 30)
        .await
        .expect("threads");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].counterparts.as_deref(),
        Some(["Zofia".to_owned()].as_slice()),
        "the account holder is not one of the counterparts"
    );
});

db_test!(
    a_thread_read_off_the_screen_is_no_longer_listed_as_metadata_only,
    |f| {
        // The bug this exists for: a walked thread listed as "metadata only, no text"
        // beside the lines the capture had already read off its screen. The
        // `CROSS JOIN LATERAL` in `list_threads` is what fixes it, and it must stay.
        me(&f.pool).await;
        thread(&f.pool, Thread::encrypted(DM)).await;
        said(&f.pool, Said::new(DM, "m1", 0).envelope()).await;
        let before = store::list_threads(&f.pool, None, None, None, 30)
            .await
            .expect("threads");
        assert_eq!(before[0].has_no_text, Some(true));
        assert_eq!(before[0].rendered_lines, 0);

        captured(
            &f.pool,
            DM,
            "run-1",
            base(),
            &[(0, Some(at(30)), "herbata", "Zofia")],
        )
        .await;
        let after = store::list_threads(&f.pool, None, None, None, 30)
            .await
            .expect("threads");
        assert_eq!(after[0].has_no_text, Some(false));
        assert_eq!(after[0].rendered_lines, 1);
        assert_eq!(
            after[0].message_count, 1,
            "the rendered line is reported beside the envelope count, never added to it"
        );
    }
);

db_test!(a_listings_rendered_line_count_is_distinct, |f| {
    // Two captures holding the same line must not double the number a reader sees.
    me(&f.pool).await;
    thread(&f.pool, Thread::encrypted(DM)).await;
    let line = (0, Some(at(30)), "herbata", "Zofia");
    captured(&f.pool, DM, "run-1", base(), &[line]).await;
    captured(&f.pool, DM, "run-2", at(600), &[line]).await;
    let rows = store::list_threads(&f.pool, None, None, None, 30)
        .await
        .expect("threads");
    assert_eq!(rows[0].rendered_lines, 1);
});

db_test!(since_narrows_the_listing_and_the_count_it_reports, |f| {
    // What makes "what did I miss" one call rather than one per thread.
    me(&f.pool).await;
    thread(&f.pool, Thread::dm(DM)).await;
    said(&f.pool, Said::new(DM, "old", -600)).await;
    said(&f.pool, Said::new(DM, "new", -60)).await;
    let rows = store::list_threads(&f.pool, None, Some(at(-300)), None, 30)
        .await
        .expect("threads");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].message_count, 1, "only what arrived after `since`");
});

db_test!(a_group_filter_selects_one_kind_of_conversation, |f| {
    me(&f.pool).await;
    thread(&f.pool, Thread::dm(DM)).await;
    thread(&f.pool, Thread::group(GROUP, "Sailing")).await;
    for (group, expected) in [(Some(true), GROUP), (Some(false), DM)] {
        let rows = store::list_threads(&f.pool, None, None, group, 30)
            .await
            .expect("threads");
        assert_eq!(rows.len(), 1, "{group:?}");
        assert_eq!(rows[0].thread_key, expected);
    }
    let both = store::list_threads(&f.pool, None, None, None, 30)
        .await
        .expect("threads");
    assert_eq!(both.len(), 2, "no filter is no filter");
});

db_test!(a_truncated_listing_knows_how_many_it_did_not_show, |f| {
    me(&f.pool).await;
    for key in ["a", "b", "c"] {
        thread(&f.pool, Thread::dm(key)).await;
    }
    let rows = store::list_threads(&f.pool, None, None, None, 2)
        .await
        .expect("threads");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].total_matches, 3);
});

db_test!(status_counts_threads_by_whether_they_hold_text, |f| {
    // `text IS NULL`, never `sync_group = 95`: 55 live threads hold nothing but
    // text-less messages and only 16 sit in the encrypted store.
    me(&f.pool).await;
    thread(&f.pool, Thread::dm("plain-but-empty")).await;
    thread(&f.pool, Thread::dm("has-text")).await;
    thread(&f.pool, Thread::dm("no-messages-at-all")).await;
    said(&f.pool, Said::new("plain-but-empty", "m1", 0).envelope()).await;
    said(&f.pool, Said::new("plain-but-empty", "m2", 60).envelope()).await;
    said(&f.pool, Said::new("has-text", "m3", 0).text("hello")).await;
    let rows = store::account_status(&f.pool).await.expect("status");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].threads, 3);
    assert_eq!(
        rows[0].textless_threads, 1,
        "a thread with no messages at all holds no envelopes either"
    );
    assert_eq!(rows[0].textless_messages, 2);
    assert_eq!(rows[0].messages, 3);
});

db_test!(
    status_stops_counting_a_thread_once_its_screen_is_read,
    |f| {
        me(&f.pool).await;
        thread(&f.pool, Thread::encrypted(DM)).await;
        said(&f.pool, Said::new(DM, "m1", 0).envelope()).await;
        captured(
            &f.pool,
            DM,
            "run-1",
            base(),
            &[(0, Some(at(30)), "herbata", "Zofia")],
        )
        .await;
        let rows = store::account_status(&f.pool).await.expect("status");
        assert_eq!(rows[0].textless_threads, 0);
        assert_eq!(rows[0].textless_messages, 0);
    }
);

db_test!(system_events_are_stored_but_not_counted_as_messages, |f| {
    me(&f.pool).await;
    thread(&f.pool, Thread::dm(DM)).await;
    said(&f.pool, Said::new(DM, "m1", 0).text("hello")).await;
    said(
        &f.pool,
        Said::new(DM, "e1", 60).kind("call_event").envelope(),
    )
    .await;
    let rows = store::account_status(&f.pool).await.expect("status");
    assert_eq!(rows[0].messages, 1);
    assert_eq!(rows[0].system_events, 1);
    let listed = store::list_threads(&f.pool, None, None, None, 30)
        .await
        .expect("threads");
    assert_eq!(listed[0].message_count, 1, "a listing counts the same way");
    let read = store::get_history(&f.pool, DM, None, None, None, 50)
        .await
        .expect("history");
    assert_eq!(
        read.len(),
        2,
        "stored and shown when reading a thread, just not counted"
    );
});

db_test!(people_hand_back_the_threads_they_speak_in, |f| {
    // The hop that did not exist: a caller who wants this person's DM no longer has to
    // search for something they said and read the key off the hit.
    me(&f.pool).await;
    thread(&f.pool, Thread::dm(DM)).await;
    participant(&f.pool, "200", Some("Zofia"), Some("zofia")).await;
    spoke_in(&f.pool, DM, "200", at(60)).await;
    said(&f.pool, Said::new(DM, "m1", 0).from("200")).await;
    let rows = store::find_people(&f.pool, Some("zofi"), 50)
        .await
        .expect("people");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].message_count, 1);
    assert_eq!(
        rows[0].thread_keys.as_deref(),
        Some([DM.to_owned()].as_slice())
    );
});

db_test!(an_alias_round_trips_and_can_be_deleted, |f| {
    me(&f.pool).await;
    participant(&f.pool, "200", Some("Zofia"), None).await;
    let members = [(ACCOUNT.to_owned(), "200".to_owned())];
    store::set_alias(&f.pool, "zona", &members, Some("the one"))
        .await
        .expect("set");
    let found = store::resolve_people(&f.pool, "zona")
        .await
        .expect("resolve");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].fb_user_id, "200");

    // A second set with no note keeps the note it had — `COALESCE(EXCLUDED.note, ...)`.
    store::set_alias(&f.pool, "zona", &members, None)
        .await
        .expect("re-set");
    let aliases = store::list_aliases(&f.pool).await.expect("aliases");
    assert_eq!(aliases.len(), 1);
    assert_eq!(aliases[0].note.as_deref(), Some("the one"));
    assert_eq!(aliases[0].members.as_deref(), Some("Zofia"));

    assert!(store::delete_alias(&f.pool, "zona").await.expect("delete"));
    assert!(
        !store::delete_alias(&f.pool, "zona").await.expect("again"),
        "a second delete reports that there was nothing to remove"
    );
    assert!(
        store::list_aliases(&f.pool)
            .await
            .expect("aliases")
            .is_empty()
    );
});

db_test!(an_alias_resolves_a_person_a_handle_and_a_raw_id, |f| {
    me(&f.pool).await;
    participant(&f.pool, "200", Some("Zofia Nowak"), Some("zofia.nowak")).await;
    for name in ["Zofia Nowak", "zofia.nowak", "200", "ZOFIA NOWAK"] {
        let found = store::resolve_people(&f.pool, name).await.expect("resolve");
        assert_eq!(found.len(), 1, "{name}");
    }
    assert!(
        store::resolve_people(&f.pool, "Zofia")
            .await
            .expect("resolve")
            .is_empty(),
        "a whole name, not a fragment: a loose match would silently widen the question"
    );
});

db_test!(people_match_with_or_without_diacritics, |f| {
    // Polish names are typed without their accents as often as with them.
    me(&f.pool).await;
    participant(&f.pool, "301", Some("Michał Wiśniak"), None).await;
    participant(&f.pool, "302", Some("Michal Grabek"), None).await;
    participant(&f.pool, "303", Some("Łukasz Pąk"), Some("lpak")).await;
    let ids = |rows: Vec<messenger_core::models::PersonRow>| {
        let mut ids: Vec<_> = rows.into_iter().map(|row| row.fb_user_id).collect();
        ids.sort();
        ids
    };
    for (query, want) in [
        ("Michal", vec!["301", "302"]),
        ("michał", vec!["301", "302"]),
        ("Michał Wiśniak", vec!["301"]),
        ("wisniak", vec!["301"]),
        ("ŁUKASZ", vec!["303"]),
        ("lukasz", vec!["303"]),
        ("Łukasz", vec!["303"]),
    ] {
        let rows = store::find_people(&f.pool, Some(query), 50)
            .await
            .expect("people");
        assert_eq!(ids(rows), want, "{query}");
    }
    for (query, want) in [
        ("michal wisniak", "301"),
        ("Michał Grabek", "302"),
        ("LUKASZ PAK", "303"),
        ("Łukasz Pąk", "303"),
    ] {
        let found = store::resolve_people(&f.pool, query)
            .await
            .expect("resolve");
        assert_eq!(found.len(), 1, "{query}");
        assert_eq!(found[0].fb_user_id, want, "{query}");
    }
});

db_test!(an_alias_resolves_without_its_diacritics, |f| {
    me(&f.pool).await;
    participant(&f.pool, "304", Some("Paweł Żurek"), None).await;
    let members = [(ACCOUNT.to_owned(), "304".to_owned())];
    store::set_alias(&f.pool, "Paweł", &members, None)
        .await
        .expect("set");
    let found = store::resolve_people(&f.pool, "pawel")
        .await
        .expect("resolve");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].fb_user_id, "304");
    let rows = store::find_people(&f.pool, Some("zurek"), 50)
        .await
        .expect("people");
    assert_eq!(rows.len(), 1);
});

db_test!(resolve_message_separates_unknown_from_not_deleted, |f| {
    // NULL alone cannot carry both answers and the tool words them differently.
    me(&f.pool).await;
    thread(&f.pool, Thread::dm(DM)).await;
    said(&f.pool, Said::new(DM, "m1", 0)).await;
    said(&f.pool, Said::new(DM, "m2", 60)).await;
    deleted(&f.pool, DM, "m2", at(120)).await;
    assert_eq!(
        store::resolve_message(&f.pool, ACCOUNT, DM, "nope")
            .await
            .expect("resolve"),
        Deletion::Unknown
    );
    assert_eq!(
        store::resolve_message(&f.pool, ACCOUNT, DM, "m1")
            .await
            .expect("resolve"),
        Deletion::NotDeleted
    );
    assert_eq!(
        store::resolve_message(&f.pool, ACCOUNT, DM, "m2")
            .await
            .expect("resolve"),
        Deletion::Deleted(at(120))
    );
});

db_test!(the_reader_sees_the_edit_and_deletion_markers, |f| {
    me(&f.pool).await;
    thread(&f.pool, Thread::dm(DM)).await;
    said(&f.pool, Said::new(DM, "m1", 0).text("second")).await;
    crate::support::revision(&f.pool, DM, "m1", 1, Some("first"), Some(at(30))).await;
    crate::support::revision(&f.pool, DM, "m1", 2, Some("second"), None).await;
    let rows = store::get_history(&f.pool, DM, None, None, None, 50)
        .await
        .expect("history");
    assert!(rows[0].edited, "derived, never stored");
    let revisions = store::list_revisions(&f.pool, ACCOUNT, DM, "m1")
        .await
        .expect("revisions");
    assert_eq!(revisions.len(), 2);
    assert_eq!(revisions[0].seq, 1);
    assert_eq!(revisions[0].text.as_deref(), Some("first"));
    assert!(revisions[1].superseded_at.is_none(), "seq 2 is current");
});

db_test!(a_reaction_and_an_attachment_reach_the_reader, |f| {
    // An archive that stored them and never showed them would be no better than one that
    // dropped them.
    me(&f.pool).await;
    thread(&f.pool, Thread::dm(DM)).await;
    said(&f.pool, Said::new(DM, "m1", 0)).await;
    crate::support::reacted(&f.pool, DM, "m1", "200", "\u{1f44d}").await;
    crate::support::reacted(&f.pool, DM, "m1", "300", "\u{1f44d}").await;
    crate::support::reacted(&f.pool, DM, "m1", "400", "\u{2764}").await;
    crate::support::attached(&f.pool, DM, "m1", Some("image/jpeg")).await;
    let rows = store::get_history(&f.pool, DM, None, None, None, 50)
        .await
        .expect("history");
    assert_eq!(
        rows[0].reactions.as_deref(),
        Some("\u{1f44d}\u{d7}2, \u{2764}"),
        "counted per emoji, most-reacted first"
    );
    assert_eq!(rows[0].attachments.as_deref(), Some("image/jpeg"));
});

db_test!(an_attachment_with_no_mime_type_is_still_reported, |f| {
    me(&f.pool).await;
    thread(&f.pool, Thread::dm(DM)).await;
    said(&f.pool, Said::new(DM, "m1", 0).envelope()).await;
    crate::support::attached(&f.pool, DM, "m1", None).await;
    let rows = store::get_history(&f.pool, DM, None, None, None, 50)
        .await
        .expect("history");
    assert_eq!(
        rows[0].attachments.as_deref(),
        Some("blob"),
        "COALESCE falls back to the kind"
    );
});

db_test!(the_loop_state_is_reported_per_account_and_loop, |f| {
    me(&f.pool).await;
    crate::support::loop_run(&f.pool, "forward", Some(DM), None).await;
    crate::support::loop_run(&f.pool, "history", None, Some("timed out")).await;
    let loops = store::sync_loops(&f.pool).await.expect("loops");
    let names: Vec<&str> = loops.iter().map(|row| row.loop_name.as_str()).collect();
    assert_eq!(names, ["forward", "history"]);
    assert_eq!(loops[0].current_thread_key.as_deref(), Some(DM));
    assert_eq!(loops[1].last_error.as_deref(), Some("timed out"));
});

db_test!(an_account_filter_narrows_every_read_that_takes_one, |f| {
    // Two accounts could share this database, and a read that ignored the filter would
    // merge two people's corpora.
    me(&f.pool).await;
    crate::support::account(&f.pool, "other", "999", Some("other")).await;
    thread(&f.pool, Thread::dm(DM)).await;
    sqlx::query(
        "INSERT INTO thread (account_id, thread_key, sync_group, last_activity_at, history_done) \
         VALUES ('other', 'theirs', 1, now(), true)",
    )
    .execute(&f.pool)
    .await
    .expect("their thread");
    let mine = store::list_threads(&f.pool, Some(ACCOUNT), None, None, 30)
        .await
        .expect("threads");
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].thread_key, DM);
});
