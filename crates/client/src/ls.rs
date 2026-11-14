//! LightSpeed over the gateway: task requests in, stored-procedure steps out.
//!
//! A request is JSON — `{app_id, payload, request_id, type}` — whose `payload` is itself a JSON
//! string: for `type` 3, a batch of tasks (`{epoch_id, tasks, version_id}`), each task's own
//! payload one more JSON string. The answer's `payload` is a step tree in which
//! `[5, "procedure", args…]` is a call to one of the client database's stored procedures:
//! that is what the archive is built from. Shapes from mautrix-meta's `socket.go`,
//! `taskManager.go`, `socket/database.go` and `lightspeed/`.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// `FetchThreadsTask`'s label and queue.
pub const FETCH_THREADS: (&str, &str) = ("145", "trq");
/// `FetchMessagesTask`'s label; its queue is `mrq.<thread key>`.
pub const FETCH_MESSAGES: &str = "228";
/// The stored procedures that list a thread, and where the Python `ops.py` read them.
const THREAD_OPS: [&str; 2] = ["deleteThenInsertThread", "updateOrInsertThread"];
const THREAD_UPDATED: usize = 2;
const THREAD_MARK: usize = 8;
const THREAD_KEY: usize = 9;
/// What `THREAD_MARK` holds when the layout is the one these positions were read from.
const THREAD_MARK_VALUE: &str = "80";
const TASKS: u8 = 3;
const CALL_STORED_PROCEDURE: u64 = 5;

/// mautrix's `GenerateEpochID`: milliseconds shifted past a 10-bit counter and the constant 42.
pub fn epoch_id(now_ms: i64, counter: i64) -> i64 {
    (now_ms << 22) | (counter << 12) | 42
}

/// `FetchThreadsTask` for the newest threads of a sync group (1 the inbox, 95 encrypted).
pub fn fetch_threads(sync_group: u8) -> Value {
    json!({
        "is_after": 0,
        "parent_thread_key": -1,
        "reference_thread_key": 0,
        "reference_activity_timestamp": 9_999_999_999_999_i64,
        "additional_pages_to_fetch": 0,
        "cursor": null,
        "messaging_tag": null,
        "sync_group": sync_group,
    })
}

/// `FetchMessagesTask`: the page of messages before `reference_ms` in a thread, as the
/// retired harvester's `mrq` asked for it.
pub fn fetch_messages(thread_key: i64, reference_ms: i64, sync_group: u8) -> Value {
    json!({
        "thread_key": thread_key,
        "direction": 0,
        "reference_timestamp_ms": reference_ms,
        "reference_message_id": "",
        "sync_group": sync_group,
        "cursor": null,
    })
}

/// Where a database's sync stands, from `executeFirstBlockForSyncTransaction[V4]`: arguments
/// 0, 2 and 3 of mautrix's `LSExecuteFirstBlockForSyncTransactionV4`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCursor {
    pub database: u32,
    /// Absent on a first sync, where the step holds LightSpeed's undefined, `[9]`.
    pub current: Option<String>,
    pub next: String,
}

/// The first sync block in a reply, if it names a database and a next cursor.
pub fn sync_cursor(steps: &Value) -> Option<SyncCursor> {
    calls(steps).into_iter().find_map(|c| {
        let name = c.get(1)?.as_str()?;
        if name != "executeFirstBlockForSyncTransactionV4"
            && name != "executeFirstBlockForSyncTransaction"
        {
            return None;
        }
        let database = boxed(c.get(2))
            .map(str::to_owned)
            .or_else(|| c.get(2)?.as_u64().map(|n| n.to_string()))?
            .parse()
            .ok()?;
        Some(SyncCursor {
            database,
            current: c.get(4).and_then(Value::as_str).map(str::to_owned),
            next: c.get(5)?.as_str()?.to_owned(),
        })
    })
}

/// The argument types of every sync block in a reply — never their values — for saying why
/// `sync_cursor` found none: `n` number, `s` string, `b` boxed i64, `u` undefined, `a` other.
pub fn sync_block_shapes(steps: &Value) -> Vec<String> {
    calls(steps)
        .into_iter()
        .filter(|c| {
            c.get(1)
                .and_then(Value::as_str)
                .is_some_and(|n| n.starts_with("executeFirstBlockForSyncTransaction"))
        })
        .map(|c| {
            c.iter()
                .skip(2)
                .map(|a| match a {
                    Value::Number(_) => "n",
                    Value::String(_) => "s",
                    Value::Bool(_) => "t",
                    Value::Null => "z",
                    _ if boxed(Some(a)).is_some() => "b",
                    Value::Array(v) if v.first().and_then(Value::as_u64) == Some(9) => "u",
                    _ => "a",
                })
                .collect::<Vec<_>>()
                .join(",")
        })
        .collect()
}

/// mautrix's `DatabaseQuery`: continue `database` from `cursor` (request type 2). The version
/// is written as the bare number the page gave, never through a float.
pub fn database_query(database: u32, cursor: &str, version: &str, epoch_id: i64) -> String {
    format!(
        r#"{{"database":{database},"last_applied_cursor":{},"sync_params":null,"epoch_id":{epoch_id},"version":{version},"failure_count":null}}"#,
        Value::String(cursor.to_owned())
    )
}

/// A database sync request: `{app_id, payload, request_id, type: 2}`.
pub fn sync_request(app_id: &str, query: &str, request_id: u16) -> Vec<u8> {
    json!({"app_id": app_id, "payload": query, "request_id": request_id, "type": 2})
        .to_string()
        .into_bytes()
}

/// One LS request carrying `tasks`, each `(label, queue, payload)`.
pub fn task_request(
    app_id: &str,
    version: &str,
    request_id: u16,
    epoch_id: i64,
    tasks: &[(&str, &str, Value)],
) -> Vec<u8> {
    let tasks: Vec<Value> = tasks
        .iter()
        .enumerate()
        .map(|(id, (label, queue, payload))| {
            json!({
                "failure_count": null,
                "label": label,
                "payload": payload.to_string(),
                "queue_name": queue,
                "task_id": id,
            })
        })
        .collect();
    let batch = json!({"epoch_id": epoch_id, "tasks": tasks, "version_id": version});
    json!({
        "app_id": app_id,
        "payload": batch.to_string(),
        "request_id": request_id,
        "type": TASKS,
    })
    .to_string()
    .into_bytes()
}

/// The answer to a request, or a push the server sends on its own.
#[derive(Debug, Deserialize, Serialize)]
pub struct Response {
    #[serde(default)]
    pub request_id: Option<i64>,
    #[serde(default)]
    pub payload: String,
    /// The stored procedures the steps depend on.
    #[serde(default)]
    pub sp: Vec<String>,
}

impl Response {
    pub fn steps(&self) -> serde_json::Result<Value> {
        let data: Value = serde_json::from_str(&self.payload)?;
        Ok(data.get("step").cloned().unwrap_or(Value::Null))
    }
}

/// Every stored-procedure call in a step tree, in order: `[5, name, args…]`.
pub fn calls(steps: &Value) -> Vec<&[Value]> {
    let mut out = Vec::new();
    collect(steps, &mut out);
    out
}

/// The names of `calls`.
pub fn procedure_calls(steps: &Value) -> Vec<String> {
    calls(steps)
        .iter()
        .filter_map(|c| c.get(1)?.as_str().map(str::to_owned))
        .collect()
}

fn collect<'a>(v: &'a Value, out: &mut Vec<&'a [Value]>) {
    if let Value::Array(items) = v {
        if items.first().and_then(Value::as_u64) == Some(CALL_STORED_PROCEDURE)
            && items.get(1).is_some_and(Value::is_string)
        {
            out.push(items);
        }
        for item in items {
            collect(item, out);
        }
    }
}

/// A boxed i64, `[19, "digits"]`, as text.
fn boxed(v: Option<&Value>) -> Option<&str> {
    match v?.as_array()?.as_slice() {
        [tag, Value::String(digits)] if tag.as_u64() == Some(19) => Some(digits),
        _ => None,
    }
}

/// Every thread a reply lists, as `(thread key, last activity ms)`, read at `ops.py`'s
/// positions and only when its layout guard holds.
pub fn threads(steps: &Value) -> Vec<(String, Option<i64>)> {
    calls(steps)
        .into_iter()
        .filter(|c| {
            c.get(1)
                .and_then(Value::as_str)
                .is_some_and(|n| THREAD_OPS.contains(&n))
        })
        .filter(|c| boxed(c.get(THREAD_MARK)) == Some(THREAD_MARK_VALUE))
        .filter_map(|c| {
            let key = boxed(c.get(THREAD_KEY)).filter(|k| k.chars().all(|d| d.is_ascii_digit()))?;
            let updated = boxed(c.get(THREAD_UPDATED)).and_then(|t| t.parse().ok());
            Some((key.to_owned(), updated))
        })
        .collect()
}
