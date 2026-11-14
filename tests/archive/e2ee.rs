//! Decrypted encrypted-chat messages into the archive (`store::e2ee`), joined to their
//! LightSpeed envelopes by OTID in either order. New with the Rust client: no Python
//! counterpart.

use messenger_core::models::{E2eeEvent, E2eeWhat, Message};
use messenger_core::store::e2ee::{self, Stored};
use messenger_core::store::writes;
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::support::{self, ACCOUNT, ME, SYNC_GROUP_E2EE, Thread, at, db_test};

const THREAD: &str = "7000000000000001";
const PEER: &str = "100000000000002";

fn event(otid: &str, second: i64, sender: &str, what: E2eeWhat) -> E2eeEvent {
    E2eeEvent {
        otid: otid.into(),
        ts: at(second),
        sender_id: sender.into(),
        what,
    }
}

fn text(t: &str) -> E2eeWhat {
    E2eeWhat::Message {
        text: Some(t.into()),
        reply_to: None,
        media: None,
        media_ref: None,
    }
}

/// The envelope LightSpeed delivers: `upsertMessage` with the OTID as argument 9.
fn envelope(mid: &str, otid: &str, second: i64) -> Message {
    let mut op = vec![json!(5), json!("upsertMessage")];
    op.extend((0..9).map(|_| Value::Null));
    op.push(json!(otid));
    Message {
        account_id: ACCOUNT.into(),
        thread_key: THREAD.into(),
        message_id: mid.into(),
        ts: at(second),
        sender_id: Some(PEER.into()),
        text: None,
        item_type: "text".into(),
        reply_to_id: None,
        attachments: json!([]),
        sync_group: SYNC_GROUP_E2EE,
        raw: json!({ "op": op }),
    }
}

async fn setup(pool: &PgPool) {
    support::me(pool).await;
    support::thread(pool, Thread::encrypted(THREAD)).await;
    support::spoke_in(pool, THREAD, ME, at(0)).await;
    support::spoke_in(pool, THREAD, PEER, at(0)).await;
}

async fn rows(pool: &PgPool) -> Vec<(String, Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT message_id, text, reply_to_id FROM message WHERE thread_key = $1 ORDER BY ts, message_id",
    )
    .bind(THREAD)
    .fetch_all(pool)
    .await
    .unwrap()
}

db_test!(decrypted_first_then_its_envelope_is_one_row, |fx| {
    setup(&fx.pool).await;
    let mut conn = fx.pool.acquire().await.unwrap();
    let stored = e2ee::store(
        &mut conn,
        ACCOUNT,
        THREAD,
        &event("111", 10, PEER, text("hi")),
    )
    .await;
    assert_eq!(stored.unwrap(), Stored::Applied);
    // The same message again changes nothing.
    let again = e2ee::store(
        &mut conn,
        ACCOUNT,
        THREAD,
        &event("111", 10, PEER, text("hi")),
    )
    .await;
    assert_eq!(again.unwrap(), Stored::Unchanged);
    let inserted = writes::insert_messages(&mut conn, &[envelope("mid.$a", "111", 10)]).await;
    assert_eq!(inserted.unwrap(), 0);
    assert_eq!(
        rows(&fx.pool).await,
        [("111".into(), Some("hi".into()), None)]
    );
});

db_test!(an_envelope_stored_first_takes_the_text, |fx| {
    setup(&fx.pool).await;
    let mut conn = fx.pool.acquire().await.unwrap();
    writes::insert_messages(&mut conn, &[envelope("mid.$a", "111", 10)])
        .await
        .unwrap();
    let reply = E2eeWhat::Message {
        text: Some("yes".into()),
        reply_to: Some("111".into()),
        media: None,
        media_ref: None,
    };
    e2ee::store(
        &mut conn,
        ACCOUNT,
        THREAD,
        &event("111", 10, PEER, text("hi")),
    )
    .await
    .unwrap();
    e2ee::store(&mut conn, ACCOUNT, THREAD, &event("222", 20, ME, reply))
        .await
        .unwrap();
    // The reply points at the envelope's id, the one the archive knows the message by.
    assert_eq!(
        rows(&fx.pool).await,
        [
            ("mid.$a".into(), Some("hi".into()), None),
            ("222".into(), Some("yes".into()), Some("mid.$a".into())),
        ]
    );
    // Envelopes of other OTIDs still go in.
    let inserted = writes::insert_messages(&mut conn, &[envelope("mid.$b", "333", 30)]).await;
    assert_eq!(inserted.unwrap(), 1);
});

db_test!(
    edits_unsends_and_reactions_find_their_message_by_otid,
    |fx| {
        setup(&fx.pool).await;
        let mut conn = fx.pool.acquire().await.unwrap();
        let store = async |conn: &mut sqlx::PgConnection, e: E2eeEvent| {
            e2ee::store(conn, ACCOUNT, THREAD, &e).await.unwrap()
        };
        store(&mut conn, event("111", 10, PEER, text("helo"))).await;
        let edit = E2eeWhat::Edit {
            target: "111".into(),
            text: "hello".into(),
        };
        assert_eq!(
            store(&mut conn, event("112", 11, PEER, edit)).await,
            Stored::Applied
        );
        let revisions: Vec<(i32, Option<String>)> = sqlx::query_as(
            "SELECT seq, text FROM message_revision WHERE message_id = '111' ORDER BY seq",
        )
        .fetch_all(&fx.pool)
        .await
        .unwrap();
        assert_eq!(
            revisions,
            [(1, Some("helo".into())), (2, Some("hello".into()))]
        );

        let react = |emoji: &str| E2eeWhat::Reaction {
            target: "111".into(),
            emoji: emoji.into(),
        };
        store(&mut conn, event("113", 12, ME, react("❤"))).await;
        let reactions = || async {
            sqlx::query_scalar::<_, String>(
                "SELECT emoji FROM message_reaction WHERE message_id = '111'",
            )
            .fetch_all(&fx.pool)
            .await
            .unwrap()
        };
        assert_eq!(reactions().await, ["❤"]);
        store(&mut conn, event("114", 13, ME, react(""))).await;
        assert!(reactions().await.is_empty());

        let unsend = E2eeWhat::Unsend {
            target: "111".into(),
        };
        assert_eq!(
            store(&mut conn, event("115", 14, PEER, unsend)).await,
            Stored::Applied
        );
        let deleted: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT deleted_at FROM message WHERE message_id = '111'")
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        assert_eq!(deleted, Some(at(14)));

        let lost = E2eeWhat::Unsend {
            target: "999".into(),
        };
        assert_eq!(
            store(&mut conn, event("116", 15, PEER, lost)).await,
            Stored::NoTarget
        );
    }
);

db_test!(
    a_message_waits_for_its_thread_and_is_placed_once_it_is_known,
    |fx| {
        support::me(&fx.pool).await;
        let mut conn = fx.pool.acquire().await.unwrap();
        assert_eq!(
            e2ee::thread_with(&mut conn, ACCOUNT, PEER).await.unwrap(),
            None
        );
        e2ee::hold(
            &mut conn,
            ACCOUNT,
            PEER,
            &event("111", 10, PEER, text("hi")),
        )
        .await
        .unwrap();
        assert_eq!(e2ee::place_held(&mut conn, ACCOUNT).await.unwrap(), 0);

        support::thread(&fx.pool, Thread::encrypted(THREAD)).await;
        support::spoke_in(&fx.pool, THREAD, PEER, at(0)).await;
        assert_eq!(
            e2ee::thread_with(&mut conn, ACCOUNT, PEER)
                .await
                .unwrap()
                .as_deref(),
            Some(THREAD)
        );
        assert_eq!(e2ee::place_held(&mut conn, ACCOUNT).await.unwrap(), 1);
        assert_eq!(
            rows(&fx.pool).await,
            [("111".into(), Some("hi".into()), None)]
        );
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM e2ee_unplaced")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
    }
);

db_test!(a_note_to_self_finds_the_self_chat_not_the_latest_dm, |fx| {
    setup(&fx.pool).await;
    let mut conn = fx.pool.acquire().await.unwrap();
    // The account takes part in every one-to-one thread: with no self-chat known, a note to
    // self waits rather than landing in the chat with someone else.
    assert_eq!(
        e2ee::thread_with(&mut conn, ACCOUNT, ME).await.unwrap(),
        None
    );

    const SELF_CHAT: &str = "7000000000000009";
    support::thread(&fx.pool, Thread::encrypted(SELF_CHAT)).await;
    support::spoke_in(&fx.pool, SELF_CHAT, ME, at(0)).await;
    assert_eq!(
        e2ee::thread_with(&mut conn, ACCOUNT, ME)
            .await
            .unwrap()
            .as_deref(),
        Some(SELF_CHAT)
    );
    assert_eq!(
        e2ee::thread_with(&mut conn, ACCOUNT, PEER)
            .await
            .unwrap()
            .as_deref(),
        Some(THREAD)
    );
});

db_test!(
    an_unsent_message_comes_back_under_the_unsends_otid_and_is_skipped,
    |fx| {
        setup(&fx.pool).await;
        let mut conn = fx.pool.acquire().await.unwrap();
        e2ee::store(
            &mut conn,
            ACCOUNT,
            THREAD,
            &event("111", 10, ME, text("oops")),
        )
        .await
        .unwrap();
        let unsend = E2eeWhat::Unsend {
            target: "111".into(),
        };
        e2ee::store(&mut conn, ACCOUNT, THREAD, &event("222", 28, ME, unsend))
            .await
            .unwrap();
        // LightSpeed's envelope for the unsent message: the original time, the unsend's OTID.
        let inserted = writes::insert_messages(&mut conn, &[envelope("mid.$u", "222", 10)]).await;
        assert_eq!(inserted.unwrap(), 0);
        assert_eq!(
            rows(&fx.pool).await,
            [("111".into(), Some("oops".into()), None)]
        );
    }
);
