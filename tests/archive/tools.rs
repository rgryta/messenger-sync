//! What each tool actually prints, against a real archive.
//!
//! Ported from the reader half of the retired Python `tests/test_store.py`,
//! `tests/test_revisions.py` and `tests/test_end_to_end.py`. The seeding is raw SQL rather
//! than a harvest pass, so the end-to-end file's "a pass writes every kind of row" has no
//! equivalent here: that is a test of the client's pass (`crates/client/tests/daemon.rs`).

use messenger_mcp::tools::{self, ToolError};

use crate::support::{
    ACCOUNT, DM, GROUP, ME, Said, Thread, at, base, captured, db_test, deleted, me, participant,
    said, spoke_in, thread,
};

/// The seed most cases below share: one DM with a counterpart and three messages.
async fn seed(pool: &sqlx::PgPool) {
    me(pool).await;
    thread(pool, Thread::dm(DM)).await;
    participant(pool, "200", Some("Zofia Nowak"), Some("zofia.nowak")).await;
    participant(pool, ME, Some("Tester Testowy"), Some("tester")).await;
    spoke_in(pool, DM, "200", at(120)).await;
    said(pool, Said::new(DM, "m1", 0).from("200").text("czesc")).await;
    said(pool, Said::new(DM, "m2", 60).text("hej")).await;
    said(pool, Said::new(DM, "m3", 120).from("200").text("herbata")).await;
}

db_test!(
    threads_lists_a_dm_by_its_counterpart_with_the_ids_inline,
    |f| {
        seed(&f.pool).await;
        let out = tools::threads(&f.pool, None, None, None, None)
            .await
            .expect("threads");
        assert_eq!(
            out,
            format!(
                "1 conversation(s), most recently active first\n\
             Zofia Nowak (DM, 3 message(s), last 2026-08-01T12:00+0000)  [thread {DM}]"
            )
        );
    }
);

db_test!(threads_marks_a_conversation_that_holds_no_text, |f| {
    me(&f.pool).await;
    thread(&f.pool, Thread::encrypted(DM)).await;
    said(&f.pool, Said::new(DM, "m1", 0).envelope()).await;
    let out = tools::threads(&f.pool, None, None, None, None)
        .await
        .expect("threads");
    assert!(out.contains("metadata only, no text"), "{out}");
});

db_test!(threads_says_when_a_listing_is_empty, |f| {
    me(&f.pool).await;
    assert_eq!(
        tools::threads(&f.pool, None, None, None, None)
            .await
            .expect("threads"),
        "no conversations match"
    );
});

db_test!(messages_reads_a_conversation_oldest_first, |f| {
    seed(&f.pool).await;
    let out = tools::messages(&f.pool, DM, None, None, None, None)
        .await
        .expect("messages");
    assert_eq!(
        out,
        format!(
            "thread {DM} — 3 message(s), oldest first\n\
             2026-08-01T12:00+0000 Zofia Nowak: czesc  [message m1]\n\
             2026-08-01T12:01+0000 Tester Testowy: hej  [message m2]\n\
             2026-08-01T12:02+0000 Zofia Nowak: herbata  [message m3]"
        )
    );
});

db_test!(
    messages_notes_the_next_page_when_the_period_holds_more,
    |f| {
        seed(&f.pool).await;
        let out = tools::messages(&f.pool, DM, None, None, None, Some(2))
            .await
            .expect("messages");
        assert!(out.contains("1 older row(s) match this request"), "{out}");
        assert!(out.contains("before=2026-08-01T12:01:01Z"), "{out}");
    }
);

db_test!(messages_reads_forward_from_an_after_cursor, |f| {
    seed(&f.pool).await;
    let out = tools::messages(&f.pool, DM, None, Some("2026-08-01T11:59"), None, Some(2))
        .await
        .expect("messages");
    assert!(out.contains("czesc"), "{out}");
    assert!(out.contains("hej"), "{out}");
    assert!(!out.contains("herbata"), "{out}");
    assert!(out.contains("1 more row(s) in this period"), "{out}");
    assert!(out.contains("after=2026-08-01T12:00:59Z"), "{out}");
});

db_test!(
    messages_distinguishes_an_empty_window_from_an_empty_thread,
    |f| {
        seed(&f.pool).await;
        let windowed = tools::messages(&f.pool, DM, None, Some("2027-01-01"), None, None)
            .await
            .expect("messages");
        assert!(windowed.contains("in that date window"), "{windowed}");
        let unknown = tools::messages(&f.pool, "nope", None, None, None, None)
            .await
            .expect("messages");
        assert_eq!(unknown, "no messages stored for thread nope");
    }
);

db_test!(
    messages_folds_the_screen_lines_in_and_says_which_they_are,
    |f| {
        // The whole reason the DOM path exists: for an encrypted DM this is the only place
        // the words are, and they come back from `messages` like anything else.
        me(&f.pool).await;
        thread(&f.pool, Thread::encrypted(DM)).await;
        participant(&f.pool, "200", Some("Zofia Nowak"), None).await;
        said(&f.pool, Said::new(DM, "m1", 0).from("200").envelope()).await;
        captured(
            &f.pool,
            DM,
            "run-1",
            base(),
            &[(0, Some(at(60)), "nie wiadomo", "Zofia")],
        )
        .await;
        let out = tools::messages(&f.pool, DM, None, None, None, None)
            .await
            .expect("messages");
        assert_eq!(
            out,
            format!(
                "thread {DM} — 2 message(s), oldest first; 1 of them read from the client's \
             screen (marked `screen`, clock precise to the minute, no message id)\n\
             2026-08-01T12:00+0000 Zofia Nowak: [text not captured]  [message m1]\n\
             2026-08-01T12:01+0000 Zofia: nie wiadomo  [screen]"
            )
        );
    }
);

db_test!(messages_shows_reactions_a_reply_and_an_attachment, |f| {
    seed(&f.pool).await;
    crate::support::reacted(&f.pool, DM, "m2", "200", "\u{1f44d}").await;
    crate::support::attached(&f.pool, DM, "m1", Some("image/jpeg")).await;
    sqlx::query("UPDATE message SET reply_to_id = 'm1' WHERE message_id = 'm2'")
        .execute(&f.pool)
        .await
        .expect("reply");
    let out = tools::messages(&f.pool, DM, None, None, None, None)
        .await
        .expect("messages");
    assert!(
        out.contains("Tester Testowy: hej  (replying to m1; \u{1f44d})  [message m2]"),
        "{out}"
    );
    // Text wins over the attachment note; the attachment stands in only when there is
    // nothing to print.
    assert!(out.contains("Zofia Nowak: czesc  [message m1]"), "{out}");
});

db_test!(
    messages_withholds_a_deleted_message_in_favour_of_the_marker,
    |f| {
        seed(&f.pool).await;
        deleted(&f.pool, DM, "m2", at(600)).await;
        let out = tools::messages(&f.pool, DM, None, None, None, None)
            .await
            .expect("messages");
        assert!(out.contains("[deleted 2026-08-01T12:10+0000]"), "{out}");
        assert!(!out.contains("hej"), "{out}");
    }
);

db_test!(search_ranks_matches_and_prints_a_headline, |f| {
    seed(&f.pool).await;
    let out = tools::search(&f.pool, "herbata", None, None, None, None, None, None)
        .await
        .expect("search");
    assert!(
        out.starts_with("1 result(s) for 'herbata', best match first"),
        "{out}"
    );
    assert!(out.contains(&format!("[thread {DM} message m3]")), "{out}");
    assert!(out.contains("<b>herbata</b>"), "{out}");
});

db_test!(a_search_hit_on_a_screen_line_prints_message_none, |f| {
    // A wart, pinned rather than fixed: `render_search` prints `[thread K message M]` for
    // every hit, and a rendered line has no message id, so the Python printed the literal
    // `message None`. `messages` handles the same row by printing `[screen]` instead. The
    // pair is not a cursor — `revisions` would answer "no message None in thread K" — so
    // the line invites exactly the cross-reference that does not exist. Kept identical to
    // the Python on purpose; the PR says why.
    me(&f.pool).await;
    thread(&f.pool, Thread::encrypted(DM)).await;
    captured(
        &f.pool,
        DM,
        "run-1",
        base(),
        &[(0, Some(at(30)), "herbata", "Zofia")],
    )
    .await;
    let out = tools::search(&f.pool, "herbata", None, None, None, None, None, None)
        .await
        .expect("search");
    assert!(
        out.contains(&format!("[thread {DM} message None]")),
        "{out}"
    );
});

db_test!(
    since_narrows_the_message_count_but_not_the_screen_lines,
    |f| {
        // A second wart, pinned rather than fixed: `since` filters `message_count` and which
        // threads are listed, but the `CROSS JOIN LATERAL` that counts rendered lines takes
        // no `since` at all. So a thread that moved recently reads "0 message(s), 1 line(s)
        // read from the client's screen" — an all-time number standing beside a narrowed one.
        // Identical in both servers.
        me(&f.pool).await;
        thread(&f.pool, Thread::encrypted(DM)).await;
        said(&f.pool, Said::new(DM, "m1", -600).envelope()).await;
        captured(
            &f.pool,
            DM,
            "run-1",
            base(),
            &[(0, Some(at(-600)), "herbata", "Zofia")],
        )
        .await;
        let out = tools::threads(&f.pool, None, Some("2026-08-01T11:58"), None, None)
            .await
            .expect("threads");
        assert!(
            out.contains("0 message(s), 1 line(s) read from the client's screen"),
            "{out}"
        );
    }
);

db_test!(
    search_says_nothing_matched_rather_than_printing_an_empty_list,
    |f| {
        seed(&f.pool).await;
        assert_eq!(
            tools::search(&f.pool, "pierogi", None, None, None, None, None, None)
                .await
                .expect("search"),
            "no messages match 'pierogi'"
        );
    }
);

db_test!(
    search_by_an_unknown_person_is_an_error_not_a_silent_pass,
    |f| {
        // A filter that silently does nothing turns "what did Zofia say" into the whole
        // corpus, and the caller has no way to notice.
        seed(&f.pool).await;
        let error = tools::search(
            &f.pool,
            "herbata",
            Some("Nobody At All"),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect_err("a usage error");
        assert!(
            matches!(&error, ToolError::Usage(message)
                 if message == "nobody is called 'Nobody At All' — try the people tool \
                                to find the name"),
            "{error}"
        );
    }
);

db_test!(search_by_a_known_person_narrows_to_what_they_said, |f| {
    seed(&f.pool).await;
    // The same word from the account holder, so the filter has something to exclude.
    said(&f.pool, Said::new(DM, "m4", 180).text("czesc znowu")).await;
    let out = tools::search(
        &f.pool,
        "czesc",
        Some("Zofia Nowak"),
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("search");
    assert!(out.contains("message m1"), "{out}");
    assert!(!out.contains("message m4"), "{out}");
    // And without the filter, both.
    let all = tools::search(&f.pool, "czesc", None, None, None, None, None, None)
        .await
        .expect("search");
    assert!(all.contains("message m4"), "{all}");
});

db_test!(an_unreadable_date_is_a_usage_error_naming_the_value, |f| {
    seed(&f.pool).await;
    let error = tools::messages(&f.pool, DM, None, Some("last tuesday"), None, None)
        .await
        .expect_err("a usage error");
    assert!(
        matches!(&error, ToolError::Usage(message) if message.starts_with("'last tuesday' is not")),
        "{error}"
    );
});

db_test!(people_print_every_name_form_and_where_to_find_them, |f| {
    seed(&f.pool).await;
    let out = tools::people(&f.pool, Some("zofi"), None)
        .await
        .expect("people");
    assert_eq!(
        out,
        format!(
            "1 person/people\n\
             Zofia Nowak (@zofia.nowak) — 2 message(s)  [member me:200]  [threads {DM}]\n\
             \n\
             no aliases set"
        )
    );
});

db_test!(people_list_the_aliases_in_force_underneath, |f| {
    seed(&f.pool).await;
    tools::set_alias(&f.pool, "zona", &["me:200".to_owned()], Some("the one"))
        .await
        .expect("set");
    let out = tools::people(&f.pool, Some("zofi"), None)
        .await
        .expect("people");
    assert!(out.contains("alias zona; @zofia.nowak"), "{out}");
    assert!(
        out.ends_with("1 alias(es)\nzona — the one: Zofia Nowak"),
        "{out}"
    );
});

db_test!(people_say_nobody_matches_rather_than_an_empty_header, |f| {
    seed(&f.pool).await;
    assert_eq!(
        tools::people(&f.pool, Some("zzz"), None)
            .await
            .expect("people"),
        "nobody matches"
    );
});

db_test!(
    set_alias_echoes_who_it_now_names_and_can_delete_itself,
    |f| {
        seed(&f.pool).await;
        assert_eq!(
            tools::set_alias(&f.pool, "zona", &["me:200".to_owned()], None)
                .await
                .expect("set"),
            "alias 'zona' now names Zofia Nowak [member me:200]"
        );
        assert_eq!(
            tools::set_alias(&f.pool, "zona", &[], None)
                .await
                .expect("delete"),
            "alias 'zona' deleted"
        );
        assert_eq!(
            tools::set_alias(&f.pool, "zona", &[], None)
                .await
                .expect("delete again"),
            "alias 'zona' did not exist"
        );
    }
);

db_test!(
    set_alias_refuses_a_member_that_is_not_account_colon_id,
    |f| {
        seed(&f.pool).await;
        let error = tools::set_alias(&f.pool, "zona", &["200".to_owned()], None)
            .await
            .expect_err("a usage error");
        assert!(
            matches!(&error, ToolError::Usage(message)
                 if message == "member '200' must be written as account:fb_user_id — the \
                                people tool prints each person's in that form"),
            "{error}"
        );
    }
);

db_test!(set_alias_says_so_when_the_ids_name_nobody, |f| {
    // The alias is still written — the tool takes ids, not people — but the answer does
    // not pretend it found anyone.
    seed(&f.pool).await;
    assert_eq!(
        tools::set_alias(&f.pool, "ghosts", &["me:999".to_owned()], None)
            .await
            .expect("set"),
        "alias 'ghosts' now names (nobody found — check the ids)"
    );
});

db_test!(an_alias_is_a_person_filter_in_its_own_right, |f| {
    seed(&f.pool).await;
    tools::set_alias(&f.pool, "zona", &["me:200".to_owned()], None)
        .await
        .expect("set");
    let out = tools::search(
        &f.pool,
        "herbata",
        Some("zona"),
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("search");
    assert!(out.contains("herbata"), "{out}");
});

db_test!(revisions_reads_one_messages_text_over_time, |f| {
    seed(&f.pool).await;
    crate::support::revision(&f.pool, DM, "m2", 1, Some("hejka"), Some(at(300))).await;
    crate::support::revision(&f.pool, DM, "m2", 2, Some("hej"), None).await;
    let out = tools::revisions(&f.pool, DM, "m2", None)
        .await
        .expect("revisions");
    assert_eq!(
        out,
        "2 revision(s) of m2, oldest first\n  \
         1  2026-08-01T12:00+0000 -> 2026-08-01T12:05+0000   \"hejka\"\n  \
         2  2026-08-01T12:00+0000 -> current   \"hej\"\n\
         note: revision 1 is the earliest text this archive saw, which is not necessarily \
         what was first sent."
    );
});

db_test!(revisions_is_the_one_place_a_deleted_text_is_shown, |f| {
    seed(&f.pool).await;
    deleted(&f.pool, DM, "m2", at(600)).await;
    let out = tools::revisions(&f.pool, DM, "m2", None)
        .await
        .expect("revisions");
    assert!(out.contains("deleted 2026-08-01T12:10+0000"), "{out}");
});

db_test!(revisions_of_an_unedited_message_is_not_an_error, |f| {
    seed(&f.pool).await;
    assert_eq!(
        tools::revisions(&f.pool, DM, "m2", None)
            .await
            .expect("revisions"),
        "0 revision(s) of m2, oldest first\nno recorded changes"
    );
});

db_test!(
    revisions_of_an_unknown_message_names_what_it_looked_for,
    |f| {
        seed(&f.pool).await;
        assert_eq!(
            tools::revisions(&f.pool, DM, "nope", None)
                .await
                .expect("revisions"),
            format!("no message nope in thread {DM}")
        );
    }
);

db_test!(status_reports_the_corpus_and_the_loops, |f| {
    me(&f.pool).await;
    thread(&f.pool, Thread::dm(DM)).await;
    thread(&f.pool, Thread::group(GROUP, "Sailing")).await;
    said(&f.pool, Said::new(DM, "m1", 0).envelope()).await;
    said(&f.pool, Said::new(GROUP, "g1", 60).text("hello")).await;
    crate::support::loop_run(&f.pool, "forward", Some(DM), None).await;
    let out = tools::status(&f.pool).await.expect("status");
    assert_eq!(
        out,
        format!(
            "harvest status\n\
             me (@tester, enabled): 2 thread(s) of which 1 hold no text, 2 message(s), \
             0 participant(s)\n  \
             history 2026-08-01T12:00+0000 to 2026-08-01T12:01+0000, 0 thread(s) still being \
             paged backwards\n  \
             1 thread(s) hold envelopes only, 1 message(s) in total with no text — stored \
             before the client decrypted one-to-one chats itself (2026-11-14), so it will stay \
             without text and cannot appear in search results.\n\
             forward loop: last run 2026-08-01T12:00+0000 (thread {DM})"
        )
    );
});

db_test!(status_says_out_loud_when_the_session_is_dead, |f| {
    // Not a transient fault: nothing new is archived until a human signs in again, and
    // the archive going quietly stale is the failure this prevents.
    me(&f.pool).await;
    sqlx::query("UPDATE account SET last_auth_error = $2, last_auth_error_at = $3 WHERE id = $1")
        .bind(ACCOUNT)
        .bind("logged out")
        .bind(base())
        .execute(&f.pool)
        .await
        .expect("auth error");
    let out = tools::status(&f.pool).await.expect("status");
    assert!(
        out.contains(
            "SESSION FAILING since 2026-08-01T12:00+0000: logged out — nothing new is being \
             archived until a human signs in again and gives the client the new session"
        ),
        "{out}"
    );
});

db_test!(a_limit_is_clamped_rather_than_refused, |f| {
    // The caller is a language model, and a model that asks for 100000 messages gets an
    // answer that does not fit in its own context.
    me(&f.pool).await;
    for key in 0..3 {
        thread(&f.pool, Thread::dm(&format!("t{key}"))).await;
    }
    let out = tools::threads(&f.pool, None, None, None, Some(100_000))
        .await
        .expect("threads");
    assert!(out.starts_with("3 conversation(s)"), "{out}");
    let one = tools::threads(&f.pool, None, None, None, Some(1))
        .await
        .expect("threads");
    assert!(one.contains("showing 1 of 3 match(es)"), "{one}");
});
