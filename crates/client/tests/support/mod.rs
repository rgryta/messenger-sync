//! What the client's Postgres tests share: a throwaway database, synthetic LightSpeed steps,
//! and a fake gateway.
//!
//! The same named test container the archive tests use (`tests/archive/support.rs`), but a
//! database per test binary, so no suite's truncation reaches another. Never a real database:
//! the DSN is built from the container, nothing is read from the environment. The steps are
//! the shapes of `tests/fixtures/ops.json` with made-up content.

#![allow(dead_code)] // each test binary uses its own part of this

use std::collections::{HashMap, VecDeque};

use messenger_client::gateway::{Event, Gateway, GatewayError};
use serde_json::{Value, json};
use sqlx::postgres::{PgPool, PgPoolOptions};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt, ReuseDirective};
use tokio::sync::{Mutex, MutexGuard, OnceCell};
use tokio::time::Instant;

static CONTAINER: OnceCell<Option<(ContainerAsync<Postgres>, String)>> = OnceCell::const_new();
static TURN: Mutex<()> = Mutex::const_new(());

/// A pool on an emptied database `name` (nothing applied), the server's DSN without a
/// database, and this test's turn; `None` when Docker is unreachable (the test then returns).
pub async fn database(name: &str) -> Option<(PgPool, String, MutexGuard<'static, ()>)> {
    let turn = TURN.lock().await;
    let server = CONTAINER
        .get_or_init(|| async {
            let request = Postgres::default()
                .with_tag("18-alpine")
                .with_container_name("messenger-sync-test-pg")
                .with_reuse(ReuseDirective::Always);
            match request.start().await {
                Ok(c) => {
                    let (host, port) = (
                        c.get_host().await.ok()?,
                        c.get_host_port_ipv4(5432).await.ok()?,
                    );
                    Some((c, format!("postgresql://postgres:postgres@{host}:{port}")))
                }
                Err(e) => {
                    eprintln!("SKIPPING the client's postgres tests: docker is not reachable: {e}");
                    None
                }
            }
        })
        .await
        .as_ref()
        .map(|(_, s)| s.clone())?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{server}/postgres"))
        .await
        .unwrap();
    // `name` is one of this crate's own constants, never input.
    for sql in [
        format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"),
        format!("CREATE DATABASE {name}"),
    ] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
            .execute(&admin)
            .await
            .unwrap();
    }
    admin.close().await;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&format!("{server}/{name}"))
        .await
        .unwrap();
    Some((pool, server, turn))
}

// --------------------------------------------------------------------------- the steps

/// Messages in 2025, so "now" is always after them.
pub const T0: i64 = 1_760_000_000_000;
pub const MINUTE: i64 = 60_000;

fn boxed(s: &str) -> Value {
    json!([19, s])
}

/// `[5, name, …]`, `width` arguments wide, LightSpeed's undefined everywhere but `set`.
fn op(name: &str, width: usize, set: Vec<(usize, Value)>) -> Value {
    let mut args = vec![json!([9]); width];
    args[0] = json!(5);
    args[1] = json!(name);
    for (i, v) in set {
        args[i] = v;
    }
    Value::Array(args)
}

/// `thread` "0" makes a message that names no thread of its own.
pub fn message(thread: &str, mid: &str, ts_ms: i64, sender: &str, text: &str) -> Value {
    op(
        "upsertMessage",
        84,
        vec![
            (2, json!(text)),
            (5, boxed(thread)),
            (7, boxed(&ts_ms.to_string())),
            (10, json!(mid)),
            (12, boxed(sender)),
        ],
    )
}

/// `editMessage`: the message id and its new text.
pub fn edit(mid: &str, text: &str) -> Value {
    op("editMessage", 6, vec![(2, json!(mid)), (4, json!(text))])
}

/// `deleteThenInsertMessage` with `IsUnsent`: the placeholder LightSpeed puts where an
/// unsent message was.
pub fn unsent(thread: &str, mid: &str, ts_ms: i64, unsent_ms: i64) -> Value {
    op(
        "deleteThenInsertMessage",
        84,
        vec![
            (5, boxed(thread)),
            (7, boxed(&ts_ms.to_string())),
            (10, json!(mid)),
            (19, json!(true)),
            (20, boxed(&unsent_ms.to_string())),
        ],
    )
}

pub fn thread(key: &str, title: Option<&str>, activity_ms: i64) -> Value {
    op(
        "deleteThenInsertThread",
        92,
        vec![
            (2, boxed(&activity_ms.to_string())),
            (5, title.map_or(json!([9]), |t| json!(t))),
            (8, boxed("80")),
            (9, boxed(key)),
        ],
    )
}

pub fn e2ee(key: &str) -> Value {
    json!([
        5,
        "verifyE2EEMetadataThreadExistsV2",
        boxed(key),
        boxed("1")
    ])
}

pub fn contact(id: &str, name: &str) -> Value {
    op(
        "verifyContactRowExists",
        25,
        vec![
            (2, boxed(id)),
            (4, json!("https://example.invalid/p.jpg")),
            (5, json!(name)),
        ],
    )
}

pub fn member(thread: &str, user: &str, admin: bool) -> Value {
    op(
        "addParticipantIdToGroupThread",
        17,
        vec![
            (2, boxed(thread)),
            (3, boxed(user)),
            (4, boxed(&T0.to_string())),
            (11, boxed("80")),
            (15, json!(admin)),
        ],
    )
}

pub fn reaction(thread: &str, mid: &str, actor: &str, emoji: &str) -> Value {
    op(
        "upsertReaction",
        9,
        vec![
            (2, boxed(thread)),
            (4, json!(mid)),
            (5, boxed(actor)),
            (6, json!(emoji)),
            (7, boxed("80")),
            (8, boxed(&T0.to_string())),
        ],
    )
}

pub fn blob(thread: &str, mid: &str, id: &str) -> Value {
    op(
        "insertBlobAttachment",
        51,
        vec![
            (2, json!(id)),
            (5, json!("https://example.invalid/a.jpg")),
            (8, json!("image/jpeg")),
            (29, boxed(thread)),
            (34, json!(mid)),
        ],
    )
}

// ------------------------------------------------------------------------- the gateway

/// A message-page task as the fake read it back off its payload.
#[derive(Debug, Clone)]
pub struct Task {
    pub queue: String,
    pub thread: String,
    pub reference_ms: i64,
    pub sync_group: u8,
}

type Respond = Box<dyn FnMut(&Task) -> Vec<Value>>;

/// The server side of the socket: every task is answered with `respond`'s steps, pushed on
/// the sync stream of the task's group, as Meta pushes them; every sync stream answers on
/// open with `on_open`'s steps for its database, unless `silent`. Deadlines are ignored: an
/// empty queue is a window that closed.
pub struct Fake {
    pub opened: Vec<(u32, String)>,
    pub tasks: Vec<Task>,
    pub on_open: HashMap<u32, Value>,
    pub silent: bool,
    pub respond: Respond,
    queue: VecDeque<Event>,
}

impl Fake {
    pub fn new(respond: impl FnMut(&Task) -> Vec<Value> + 'static) -> Self {
        Fake {
            opened: Vec::new(),
            tasks: Vec::new(),
            on_open: HashMap::new(),
            silent: false,
            respond: Box::new(respond),
            queue: VecDeque::new(),
        }
    }
}

impl Gateway for Fake {
    async fn open_sync(&mut self, database: u32, cursor: &str) -> Result<(), GatewayError> {
        self.opened.push((database, cursor.to_owned()));
        if !self.silent {
            let steps = self.on_open.remove(&database).unwrap_or(json!([]));
            self.queue.push_back(Event::Sync { database, steps });
        }
        Ok(())
    }

    async fn send_task(
        &mut self,
        label: &str,
        queue: &str,
        payload: Value,
    ) -> Result<(), GatewayError> {
        assert_eq!(label, "228", "only message pages are sent");
        let task = Task {
            queue: queue.to_owned(),
            thread: payload["thread_key"].as_i64().unwrap().to_string(),
            reference_ms: payload["reference_timestamp_ms"].as_i64().unwrap(),
            sync_group: payload["sync_group"].as_u64().unwrap() as u8,
        };
        let steps = (self.respond)(&task);
        self.queue.push_back(Event::Sync {
            database: task.sync_group.into(),
            steps: Value::Array(steps),
        });
        self.queue.push_back(Event::TaskDone);
        self.tasks.push(task);
        Ok(())
    }

    async fn next_event(&mut self, _deadline: Instant) -> Result<Option<Event>, GatewayError> {
        Ok(self.queue.pop_front())
    }
}

/// A thread's history as Meta pages it: the 20 newest messages before the reference.
pub fn history(thread: &str, timestamps: Vec<i64>) -> impl FnMut(&Task) -> Vec<Value> + 'static {
    let thread = thread.to_owned();
    move |task: &Task| {
        if task.thread != thread {
            return Vec::new();
        }
        let mut older: Vec<i64> = timestamps
            .iter()
            .copied()
            .filter(|ts| *ts < task.reference_ms)
            .collect();
        older.sort_unstable_by(|a, b| b.cmp(a));
        older
            .into_iter()
            .take(20)
            .map(|ts| message(&thread, &format!("mid.$fake{ts}"), ts, "200", "word"))
            .collect()
    }
}
