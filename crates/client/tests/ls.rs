//! LightSpeed requests and responses, in the shapes mautrix-meta sends and reads.

use messenger_client::ls::{
    FETCH_THREADS, Response, epoch_id, fetch_threads, procedure_calls, task_request,
};
use serde_json::{Value, json};

#[test]
fn a_thread_fetch_is_three_layers_of_json_like_the_web_client_sends() {
    let (label, queue) = FETCH_THREADS;
    let request = task_request(
        "2220391788200892",
        "12345678901234567890",
        1,
        epoch_id(1_700_000_000_000, 0),
        &[
            (label, queue, fetch_threads(1)),
            (label, queue, fetch_threads(95)),
        ],
    );
    let outer: Value = serde_json::from_slice(&request).unwrap();
    assert_eq!(outer["app_id"], "2220391788200892");
    assert_eq!(outer["request_id"], 1);
    assert_eq!(outer["type"], 3);
    // The payload is a JSON string, not an object, and its version stays exact text.
    let batch: Value = serde_json::from_str(outer["payload"].as_str().unwrap()).unwrap();
    assert_eq!(batch["version_id"], "12345678901234567890");
    assert_eq!(batch["epoch_id"], json!((1_700_000_000_000_i64 << 22) | 42));
    let tasks = batch["tasks"].as_array().unwrap();
    assert_eq!(tasks.len(), 2);
    for (i, (task, group)) in tasks.iter().zip([1, 95]).enumerate() {
        assert_eq!(task["label"], "145");
        assert_eq!(task["queue_name"], "trq");
        assert_eq!(task["task_id"], i);
        assert!(task["failure_count"].is_null());
        let payload: Value = serde_json::from_str(task["payload"].as_str().unwrap()).unwrap();
        assert_eq!(payload["sync_group"], group);
        assert_eq!(payload["parent_thread_key"], -1);
        assert_eq!(
            payload["reference_activity_timestamp"],
            9_999_999_999_999_i64
        );
    }
}

#[test]
fn epoch_ids_count_within_a_millisecond() {
    assert_eq!(epoch_id(1, 0), (1 << 22) | 42);
    assert_eq!(epoch_id(1, 3), (1 << 22) | (3 << 12) | 42);
}

#[test]
fn stored_procedure_calls_are_found_at_any_depth_in_order() {
    // A cut of a reply: a block of calls, one nested in a conditional, other step types around.
    let steps = json!([
        1,
        [5, "executeFirstBlockForSyncTransaction", [19, "1"], "c1"],
        [23, [2, 0], [1, [5, "upsertThread", [19, "123"], "t"]]],
        [5, "upsertMessage", "text", 9],
        [2, 5],
        "a string, not a call"
    ]);
    let response = Response {
        request_id: Some(1),
        payload: json!({"name": null, "step": steps}).to_string(),
        sp: vec!["upsertThread".into()],
    };
    assert_eq!(
        procedure_calls(&response.steps().unwrap()),
        [
            "executeFirstBlockForSyncTransaction",
            "upsertThread",
            "upsertMessage"
        ]
    );
}

#[test]
fn a_reply_reads_with_or_without_its_optional_fields() {
    let r: Response = serde_json::from_str(
        r#"{"request_id":7,"payload":"{\"step\":[5,\"x\"]}","sp":["x"],"target":2}"#,
    )
    .unwrap();
    assert_eq!(r.request_id, Some(7));
    assert_eq!(procedure_calls(&r.steps().unwrap()), ["x"]);
    let push: Response = serde_json::from_str(r#"{"payload":"{\"step\":[]}"}"#).unwrap();
    assert_eq!(push.request_id, None);
    assert!(procedure_calls(&push.steps().unwrap()).is_empty());
}

#[test]
fn listed_threads_are_read_at_the_harvesters_positions_behind_its_guard() {
    use messenger_client::ls::threads;
    // `[5, name, arg2, …]`: last activity at 2, the layout mark at 8, the thread key at 9.
    let thread = |name: &str, mark: &str, key: &str| {
        json!([
            5,
            name,
            [19, "1700000000000"],
            null,
            "preview",
            "title",
            null,
            null,
            [19, mark],
            [19, key],
            0
        ])
    };
    let steps = json!([
        1,
        thread("deleteThenInsertThread", "80", "1000000000000001"),
        thread("updateOrInsertThread", "80", "1000000000000002"),
        // A moved layout is refused rather than read into the wrong column.
        thread("deleteThenInsertThread", "81", "1000000000000003"),
        // Another procedure with the same shape is not a thread listing.
        thread("upsertMessage", "80", "1000000000000004"),
        [5, "deleteThenInsertThread", [19, "1"]]
    ]);
    assert_eq!(
        threads(&steps),
        [
            ("1000000000000001".to_owned(), Some(1_700_000_000_000)),
            ("1000000000000002".to_owned(), Some(1_700_000_000_000)),
        ]
    );
}

#[test]
fn a_message_page_is_asked_for_like_the_harvesters_mrq() {
    use messenger_client::ls::{FETCH_MESSAGES, fetch_messages};
    assert_eq!(FETCH_MESSAGES, "228");
    let p = fetch_messages(1_000_000_000_000_001, 1_700_000_000_000, 1);
    assert_eq!(
        p,
        json!({"thread_key": 1_000_000_000_000_001_i64, "direction": 0,
               "reference_timestamp_ms": 1_700_000_000_000_i64, "reference_message_id": "",
               "sync_group": 1, "cursor": null})
    );
}

#[test]
fn the_sync_cursor_is_read_from_the_first_block_either_version() {
    use messenger_client::ls::{SyncCursor, sync_cursor};
    let v4 = json!([
        1,
        [
            5,
            "executeFirstBlockForSyncTransactionV4",
            [19, "1"],
            [19, "77"],
            "cur",
            "next",
            [19, "3"],
            0,
            true
        ]
    ]);
    assert_eq!(
        sync_cursor(&v4),
        Some(SyncCursor {
            database: 1,
            current: Some("cur".into()),
            next: "next".into()
        })
    );
    // A first sync: the current cursor is LightSpeed's undefined.
    let first = json!([[
        5,
        "executeFirstBlockForSyncTransactionV4",
        [19, "1"],
        [19, "7"],
        [9],
        "next"
    ]]);
    assert_eq!(
        sync_cursor(&first).unwrap(),
        SyncCursor {
            database: 1,
            current: None,
            next: "next".into()
        }
    );
    assert_eq!(messenger_client::ls::sync_block_shapes(&first), ["b,b,u,s"]);
    let v1 = json!([[5, "executeFirstBlockForSyncTransaction", 95, 77, "c", "n"]]);
    assert_eq!(sync_cursor(&v1).unwrap().database, 95);
    assert_eq!(sync_cursor(&json!([[5, "upsertMessage", "x"]])), None);
}

#[test]
fn a_database_query_keeps_the_version_a_bare_exact_number() {
    use messenger_client::ls::{database_query, sync_request};
    let q = database_query(1, "cur\"sor", "12345678901234567890", 42);
    assert!(q.contains(r#""version":12345678901234567890"#), "{q}");
    let parsed: Value = serde_json::from_str(&q).unwrap();
    assert_eq!(parsed["database"], 1);
    assert_eq!(parsed["last_applied_cursor"], "cur\"sor");
    assert!(parsed["sync_params"].is_null());
    assert_eq!(parsed["epoch_id"], 42);
    let request: Value = serde_json::from_slice(&sync_request("772", &q, 3)).unwrap();
    assert_eq!(request["type"], 2);
    assert_eq!(request["request_id"], 3);
    assert_eq!(request["payload"], q.as_str());
}
