//! The collector and its write: synthetic steps in, archive rows out.

mod support;

use messenger_client::collect::{Collector, persist};
use messenger_core::models::Account;
use messenger_core::store::writes;
use serde_json::json;
use sqlx::Row;
use support::{
    MINUTE, T0, blob, contact, e2ee, edit, edit_history, member, message, reaction, thread, unsent,
};

const GROUP: &str = "1000000000000001";
const SECRET: &str = "7000000000000000009";
const ORPHAN: &str = "1000000000000077";

#[tokio::test]
async fn a_batch_is_keyed_like_the_python_and_written_parents_first() {
    let Some((pool, _, _turn)) = support::database("client_collect").await else {
        return;
    };
    messenger_core::db::ensure_schema(&pool).await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    writes::upsert_account(
        &mut conn,
        &Account {
            id: "me".into(),
            fb_user_id: "100".into(),
            username: None,
            enabled: true,
        },
    )
    .await
    .unwrap();

    let mut batch = Collector::new("me");
    batch.feed(
        Some(1),
        &json!([
            thread(GROUP, Some("a group"), T0 + 5 * MINUTE),
            contact("200", "Someone"),
            member(GROUP, "200", true),
            message(GROUP, "mid.$one", T0, "200", "first"),
            // Delivered twice in one page: one row, the later delivery.
            message(GROUP, "mid.$one", T0, "200", "first, again"),
            message(GROUP, "mid.$two", T0 + MINUTE, "200", "second"),
            reaction(GROUP, "mid.$one", "200", "👍"),
            reaction(GROUP, "mid.$one", "200", "❤"),
            blob(GROUP, "mid.$one", "att-1"),
        ]),
    );
    // An encrypted thread is announced by key alone, and its message names it.
    batch.feed(
        Some(95),
        &json!([
            e2ee(SECRET),
            message(SECRET, "mid.$secret", T0, "200", "hidden")
        ]),
    );
    // A message naming no thread is filed under the task in flight, in that task's group.
    batch.expect = Some((ORPHAN.into(), 95));
    batch.feed(
        Some(1),
        &json!([message("0", "mid.$orphan", T0 + 2 * MINUTE, "200", "lost")]),
    );
    batch.expect = None;

    assert_eq!(batch.decoded_messages, 5);
    assert_eq!(batch.messages.len(), 4);
    assert_eq!(
        batch.messages[&(GROUP.to_owned(), "mid.$one".to_owned())]
            .text
            .as_deref(),
        Some("first, again")
    );
    assert_eq!(batch.reactions.len(), 1);
    assert_eq!(batch.attachments.len(), 1);
    assert!(
        batch
            .attachments
            .contains_key(&("mid.$one".to_owned(), "att-1".to_owned()))
    );
    assert_eq!(batch.members.len(), 1);
    assert_eq!(batch.e2ee_keys.len(), 1);
    assert_eq!(batch.per_thread_oldest[GROUP].timestamp_millis(), T0);
    assert_eq!(
        batch.per_thread_newest[GROUP].timestamp_millis(),
        T0 + MINUTE
    );
    assert_eq!(
        batch.messages[&(ORPHAN.to_owned(), "mid.$orphan".to_owned())].sync_group,
        95
    );

    assert_eq!(persist(&mut conn, &batch).await.unwrap(), 4);
    // A re-read page stores nothing new.
    assert_eq!(persist(&mut conn, &batch).await.unwrap(), 0);

    let threads: Vec<(String, i32, Option<String>)> =
        sqlx::query_as("SELECT thread_key, sync_group, title FROM thread ORDER BY thread_key")
            .fetch_all(&mut *conn)
            .await
            .unwrap();
    assert_eq!(
        threads,
        [
            (GROUP.to_owned(), 1, Some("a group".to_owned())),
            (ORPHAN.to_owned(), 95, None),
            (SECRET.to_owned(), 95, None),
        ]
    );
    let messages: Vec<(String, String, i32, Option<String>)> = sqlx::query_as(
        "SELECT thread_key, message_id, sync_group, text FROM message ORDER BY message_id",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap();
    assert_eq!(messages.len(), 4);
    assert!(messages.contains(&(
        SECRET.to_owned(),
        "mid.$secret".to_owned(),
        95,
        Some("hidden".to_owned())
    )));
    let row = sqlx::query(
        "SELECT (SELECT emoji FROM message_reaction) AS emoji, \
                (SELECT attachment_key FROM message_attachment) AS attachment, \
                (SELECT name FROM participant WHERE fb_user_id = '200') AS name, \
                (SELECT from_roster AND is_admin FROM thread_participant \
                  WHERE thread_key = $1 AND fb_user_id = '200') AS roster, \
                (SELECT raw->'op'->>1 FROM message WHERE message_id = 'mid.$two') AS raw",
    )
    .bind(GROUP)
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("emoji"), "❤");
    assert_eq!(row.get::<String, _>("attachment"), "att-1");
    assert_eq!(row.get::<String, _>("name"), "Someone");
    assert!(row.get::<bool, _>("roster"));
    assert_eq!(row.get::<String, _>("raw"), "upsertMessage");
}

#[tokio::test]
async fn an_edit_keeps_the_old_text_and_an_unsend_marks_the_message() {
    let Some((pool, _, _turn)) = support::database("client_collect").await else {
        return;
    };
    messenger_core::db::ensure_schema(&pool).await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    writes::upsert_account(
        &mut conn,
        &Account {
            id: "me".into(),
            fb_user_id: "100".into(),
            username: None,
            enabled: true,
        },
    )
    .await
    .unwrap();
    let mut batch = Collector::new("me");
    batch.feed(
        Some(1),
        &json!([
            thread(GROUP, Some("a group"), T0),
            message(GROUP, "mid.$one", T0, "200", "helo"),
            message(GROUP, "mid.$two", T0 + MINUTE, "200", "oops"),
        ]),
    );
    persist(&mut conn, &batch).await.unwrap();

    // Later, on the sync stream: one message edited, the other unsent.
    batch.begin_page();
    batch.feed(
        Some(1),
        &json!([
            edit("mid.$one", "hello"),
            unsent(GROUP, "mid.$two", T0 + MINUTE, T0 + 2 * MINUTE),
        ]),
    );
    assert_eq!(batch.edits.len(), 1);
    assert_eq!(batch.unsends.len(), 1);
    persist(&mut conn, &batch).await.unwrap();

    let texts: Vec<(i32, Option<String>)> = sqlx::query_as(
        "SELECT seq, text FROM message_revision WHERE message_id = 'mid.$one' ORDER BY seq",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap();
    assert_eq!(texts, [(1, Some("helo".into())), (2, Some("hello".into()))]);
    let row = sqlx::query(
        "SELECT (SELECT text FROM message WHERE message_id = 'mid.$one') AS one, \
                (SELECT text FROM message WHERE message_id = 'mid.$two') AS two, \
                (SELECT deleted_at IS NOT NULL FROM message WHERE message_id = 'mid.$two') AS gone",
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("one"), "hello");
    // The text is kept; the unsend only marks it.
    assert_eq!(row.get::<String, _>("two"), "oops");
    assert!(row.get::<bool, _>("gone"));
}

#[tokio::test]
async fn a_message_edited_or_unsent_between_passes_is_caught_on_the_next() {
    let Some((pool, _, _turn)) = support::database("client_collect").await else {
        return;
    };
    messenger_core::db::ensure_schema(&pool).await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    writes::upsert_account(
        &mut conn,
        &Account {
            id: "me".into(),
            fb_user_id: "100".into(),
            username: None,
            enabled: true,
        },
    )
    .await
    .unwrap();
    let mut batch = Collector::new("me");
    batch.feed(
        Some(1),
        &json!([
            thread(GROUP, Some("a group"), T0),
            message(GROUP, "mid.$one", T0, "200", "helo"),
            message(GROUP, "mid.$two", T0 + MINUTE, "200", "same"),
        ]),
    );
    persist(&mut conn, &batch).await.unwrap();

    // The next pass's snapshot: no editMessage, just the message with its current words;
    // the other one unchanged.
    batch.begin_page();
    batch.feed(
        Some(1),
        &json!([
            message(GROUP, "mid.$one", T0, "200", "hello"),
            message(GROUP, "mid.$two", T0 + MINUTE, "200", "same"),
        ]),
    );
    persist(&mut conn, &batch).await.unwrap();
    let revisions: Vec<(String, i32)> =
        sqlx::query_as("SELECT message_id, seq FROM message_revision ORDER BY message_id, seq")
            .fetch_all(&mut *conn)
            .await
            .unwrap();
    assert_eq!(revisions, [("mid.$one".into(), 1), ("mid.$one".into(), 2)]);

    // An unsend seen only in a later snapshot: an upsertMessage carrying IsUnsent.
    let mut flagged = message(GROUP, "mid.$two", T0 + MINUTE, "200", "");
    flagged[19] = json!(true);
    batch.begin_page();
    batch.feed(Some(1), &json!([flagged]));
    assert_eq!(batch.unsends.len(), 1);
    persist(&mut conn, &batch).await.unwrap();
    let gone: bool = sqlx::query_scalar(
        "SELECT deleted_at IS NOT NULL FROM message WHERE message_id = 'mid.$two'",
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    assert!(gone);
}

#[tokio::test]
async fn a_message_first_seen_edited_gets_its_earlier_texts_from_the_page() {
    let Some((pool, _, _turn)) = support::database("client_collect").await else {
        return;
    };
    messenger_core::db::ensure_schema(&pool).await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    writes::upsert_account(
        &mut conn,
        &Account {
            id: "me".into(),
            fb_user_id: "100".into(),
            username: None,
            enabled: true,
        },
    )
    .await
    .unwrap();
    let mut batch = Collector::new("me");
    batch.feed(
        Some(1),
        &json!([
            thread(GROUP, Some("a group"), T0),
            message(GROUP, "mid.$one", T0, "200", "third"),
            edit_history(GROUP, "mid.$one", T0 + 2 * MINUTE, "second"),
            edit_history(GROUP, "mid.$one", T0 + MINUTE, "first"),
            // The held text is not an earlier version.
            edit_history(GROUP, "mid.$one", T0 + 3 * MINUTE, "third"),
        ]),
    );
    persist(&mut conn, &batch).await.unwrap();
    let rows: Vec<(i32, Option<String>, bool, bool)> = sqlx::query_as(
        "SELECT seq, text, first_seen_at IS NOT NULL, superseded_at IS NULL
           FROM message_revision WHERE message_id = 'mid.$one' ORDER BY seq",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap();
    assert_eq!(
        rows,
        [
            (1, Some("first".into()), false, false),
            (2, Some("second".into()), false, false),
            (3, Some("third".into()), true, true),
        ]
    );

    // Seen again: a message already tracked keeps its record.
    persist(&mut conn, &batch).await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM message_revision WHERE message_id = 'mid.$one'")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
    assert_eq!(count, 3);
}
