//! The client's writers against the retired Python's recorded output:
//! `tests/fixtures/store_writes.json` (made by the since-deleted
//! `scripts/store-writes-fixture.py`) is a script of writes that, replayed through
//! `store::writes` on an empty schema, must return what the Python `store.py` returned and
//! leave every table exactly as it left them. The fixture also carries the dump query, so
//! both sides were measured with one instrument.

use chrono::{DateTime, Utc};
use messenger_core::models::{Account, Attachment, Member, Message, Participant, Reaction, Thread};
use messenger_core::store::writes;
use serde_json::{Value, from_value, json};
use sqlx::PgConnection;

use crate::support::db_test;

const FIXTURE: &str = include_str!("../fixtures/store_writes.json");

fn text<'a>(args: &'a Value, key: &str) -> &'a str {
    args[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} in {args}"))
}

fn maybe<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn ts(args: &Value, key: &str) -> Option<DateTime<Utc>> {
    from_value(args.get(key).cloned().unwrap_or_default()).expect("a timestamp")
}

fn ms(at: Option<DateTime<Utc>>) -> Value {
    json!(at.map(|at| at.timestamp_millis()))
}

/// One script entry through the Rust writer of the same name, its return as the Python
/// fixture spells it.
async fn call(conn: &mut PgConnection, name: &str, args: &Value) -> Value {
    let returned = match name {
        "upsert_account" => {
            let account: Account = from_value(args.clone()).unwrap();
            writes::upsert_account(conn, &account)
                .await
                .map(|()| json!(null))
        }
        "record_auth_error" => {
            writes::record_auth_error(conn, text(args, "account_id"), text(args, "error"))
                .await
                .map(|()| json!(null))
        }
        "clear_auth_error" => writes::clear_auth_error(conn, text(args, "account_id"))
            .await
            .map(|()| json!(null)),
        "upsert_participants" => {
            let participants: Vec<Participant> = from_value(args.clone()).unwrap();
            writes::upsert_participants(conn, &participants)
                .await
                .map(|()| json!(null))
        }
        "upsert_thread" => {
            let thread: Thread = from_value(args.clone()).unwrap();
            writes::upsert_thread(conn, &thread)
                .await
                .map(|()| json!(null))
        }
        "note_thread_seen" => {
            let sync_group = args["sync_group"].as_i64().unwrap() as i32;
            writes::note_thread_seen(
                conn,
                text(args, "account_id"),
                text(args, "thread_key"),
                sync_group,
            )
            .await
            .map(|()| json!(null))
        }
        "record_thread_members" => {
            let members: Vec<Member> = from_value(args.clone()).unwrap();
            writes::record_thread_members(conn, &members)
                .await
                .map(|n| json!(n))
        }
        "insert_reactions" => {
            let reactions: Vec<Reaction> = from_value(args.clone()).unwrap();
            writes::insert_reactions(conn, &reactions)
                .await
                .map(|n| json!(n))
        }
        "insert_attachments" => {
            let attachments: Vec<Attachment> = from_value(args.clone()).unwrap();
            writes::insert_attachments(conn, &attachments)
                .await
                .map(|n| json!(n))
        }
        "record_thread_participants" => {
            let messages: Vec<Message> = from_value(args.clone()).unwrap();
            writes::record_thread_participants(conn, &messages)
                .await
                .map(|()| json!(null))
        }
        "insert_messages" => {
            let messages: Vec<Message> = from_value(args.clone()).unwrap();
            writes::insert_messages(conn, &messages)
                .await
                .map(|n| json!(n))
        }
        "set_history_progress" => writes::set_history_progress(
            conn,
            text(args, "account_id"),
            text(args, "thread_key"),
            ts(args, "oldest_seen_at"),
            args["done"].as_bool().unwrap(),
        )
        .await
        .map(|()| json!(null)),
        "set_forward_progress" => writes::set_forward_progress(
            conn,
            text(args, "account_id"),
            text(args, "thread_key"),
            ts(args, "newest_seen_at"),
            ts(args, "answered_activity_at"),
        )
        .await
        .map(|()| json!(null)),
        "threads_with_new_activity" => writes::threads_with_new_activity(
            conn,
            text(args, "account_id"),
            args["limit"].as_i64().unwrap(),
        )
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|t| {
                    json!({"thread_key": t.thread_key, "sync_group": t.sync_group,
                           "newest_seen_at": ms(t.newest_seen_at),
                           "last_activity_at": ms(t.last_activity_at), "title": t.title})
                })
                .collect()
        }),
        "threads_needing_history" => writes::threads_needing_history(
            conn,
            text(args, "account_id"),
            args["limit"].as_i64().unwrap(),
        )
        .await
        .map(|rows| {
            rows.into_iter()
                .map(|t| {
                    json!({"thread_key": t.thread_key, "sync_group": t.sync_group,
                           "oldest_seen_at": ms(t.oldest_seen_at), "title": t.title})
                })
                .collect()
        }),
        "reopen_history" => {
            writes::reopen_history(conn, text(args, "account_id"), maybe(args, "thread_key"))
                .await
                .map(|n| json!(n))
        }
        "mark_loop_run" => writes::mark_loop_run(
            conn,
            text(args, "account_id"),
            text(args, "loop"),
            maybe(args, "thread_key"),
            maybe(args, "error"),
        )
        .await
        .map(|()| json!(null)),
        other => panic!("the script names a writer this test does not know: {other}"),
    };
    returned.unwrap_or_else(|e| panic!("{name}({args}): {e}"))
}

db_test!(the_writers_leave_the_archive_as_the_python_does, |f| {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("the fixture is JSON");
    let mut conn = f.pool.acquire().await.expect("a connection");

    let script = fixture["script"].as_array().expect("a script");
    let returns = fixture["returns"].as_array().expect("returns");
    assert_eq!(script.len(), returns.len());
    for (i, (step, expected)) in script.iter().zip(returns).enumerate() {
        let name = step[0].as_str().expect("a writer's name");
        let got = call(&mut conn, name, &step[1]).await;
        assert_eq!(&got, expected, "call {i}, {name}, returned differently");
    }

    let dump: String = sqlx::query_scalar(sqlx::AssertSqlSafe(
        fixture["dump"].as_str().expect("the dump query"),
    ))
    .fetch_one(&mut *conn)
    .await
    .expect("dump");
    let mut tables: Value = serde_json::from_str(&dump).expect("the dump is JSON");
    // `message.otid` (migration 0014) postdates the recorded fixture. It is generated from
    // `raw`, which is compared, so dropping it hides nothing the writers did.
    for row in tables["message"].as_array_mut().into_iter().flatten() {
        if let Some(row) = row.as_object_mut() {
            for column in ["otid", "transcript", "transcript_status"] {
                row.remove(column);
            }
        }
    }
    let expected = fixture["tables"].as_object().expect("tables");
    assert_eq!(
        tables
            .as_object()
            .expect("tables")
            .keys()
            .collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>(),
    );
    for (table, rows) in expected {
        let (got, rows) = (tables[table].as_array().unwrap(), rows.as_array().unwrap());
        for (i, (got, want)) in got.iter().zip(rows).enumerate() {
            assert_eq!(got, want, "{table} row {i} differs");
        }
        assert_eq!(
            got.len(),
            rows.len(),
            "{table} holds a different number of rows"
        );
    }
});
