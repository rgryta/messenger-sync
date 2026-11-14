//! Test fixtures.
//!
//! Postgres tests run against a throwaway testcontainer and report a loud skip when
//! Docker is unreachable. They must never reach the homelab database: **nothing here
//! reads a DSN from the environment**, the container builds its own. That is the
//! structural half of "never point tests at a real database", and it is why
//! `#[sqlx::test]` is not used anywhere — that macro wants `DATABASE_URL` from the
//! environment and creates databases itself, which re-opens the door this file keeps
//! shut.
//!
//! The seeders here write raw SQL rather than calling `store::writes`: they predate the
//! port of the writers.
//!
//! **No real capture ever enters this repository.** Every rendered line below is a
//! made-up word in the shape a capture produces; `AGENTS.md` says why.

use chrono::{DateTime, TimeDelta, TimeZone, Utc};
use messenger_core::db::{create_pool, ensure_schema};
use sqlx::postgres::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt, ReuseDirective};
use tokio::sync::{Mutex, OnceCell};

/// The retired Python fixture's `_TABLES`, plus the eight tables added after it was written.
/// `schema_migration` is deliberately absent: truncating it would make the shared schema
/// look unapplied to the next test.
const TRUNCATE_ALL: &str = "TRUNCATE message_revision, message_reaction, message_attachment, \
                            e2ee_unplaced, dom_message, dom_capture, thread_participant, \
                            message, thread, \
                            participant, person_alias_member, person_alias, sync_state, account \
                            RESTART IDENTITY CASCADE";

/// One named container serves every run. It is parked in a `static`, which Rust never
/// drops, so it is marked for reuse rather than reaping: the next run attaches to the
/// same container instead of leaving a second one behind. Remove it with
/// `docker rm -f messenger-sync-test-pg` when you want the disk back.
const CONTAINER_NAME: &str = "messenger-sync-test-pg";

static CONTAINER: OnceCell<Option<(ContainerAsync<Postgres>, String)>> = OnceCell::const_new();
/// One database, many tests, and each one truncates: they have to take turns.
static TURN: Mutex<()> = Mutex::const_new(());

pub struct Fixture {
    pub pool: PgPool,
    _turn: tokio::sync::MutexGuard<'static, ()>,
}

/// A pool over an empty database, or `None` when Docker is unreachable.
///
/// Returning `None` rather than failing is deliberate: Postgres tests skip when Docker
/// is not there. Rust has no "skipped" outcome, so each caller prints the reason and
/// returns — loudly enough to notice in a log.
pub async fn fixture() -> Option<Fixture> {
    let turn = TURN.lock().await;
    let dsn = CONTAINER
        .get_or_init(|| async {
            let request = Postgres::default()
                .with_tag("18-alpine")
                .with_container_name(CONTAINER_NAME)
                .with_reuse(ReuseDirective::Always);
            match request.start().await {
                Ok(container) => {
                    let host = container.get_host().await.ok()?;
                    let port = container.get_host_port_ipv4(5432).await.ok()?;
                    let dsn = format!("postgresql://postgres:postgres@{host}:{port}/postgres");
                    let pool = create_pool(&dsn).await.ok()?;
                    ensure_schema(&pool).await.ok()?;
                    pool.close().await;
                    Some((container, dsn))
                }
                Err(error) => {
                    eprintln!("SKIPPING the postgres tests: docker is not reachable: {error}");
                    None
                }
            }
        })
        .await
        .as_ref()
        .map(|(_, dsn)| dsn.clone())?;

    let pool = create_pool(&dsn).await.expect("the container is up");
    sqlx::query(TRUNCATE_ALL)
        .execute(&pool)
        .await
        .expect("truncate");
    Some(Fixture { pool, _turn: turn })
}

/// Skip the body with a printed reason when Docker is unreachable.
macro_rules! db_test {
    ($name:ident, |$fixture:ident| $body:block) => {
        #[tokio::test]
        async fn $name() {
            let Some($fixture) = crate::support::fixture().await else {
                return;
            };
            $body
        }
    };
}
pub(crate) use db_test;

/// The DSN of the shared container, for the tests that need a second database.
pub async fn container_dsn() -> Option<String> {
    CONTAINER.get()?.as_ref().map(|(_, dsn)| dsn.clone())
}

// ---------------------------------------------------------------------------- the seed

pub const ACCOUNT: &str = "me";
pub const ME: &str = "100";
pub const DM: &str = "7748159";
pub const GROUP: &str = "9900001";

/// The inbox store and the end-to-end-encrypted one. A task built for the wrong one
/// returns nothing and raises nothing, which is the most expensive failure mode in this
/// codebase — and the reason nothing in the read path keys on it.
pub const SYNC_GROUP_INBOX: i32 = 1;
pub const SYNC_GROUP_E2EE: i32 = 95;

/// A fixed instant, so an assertion about ordering never depends on how fast the test
/// ran.
pub fn base() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
}

pub fn at(seconds: i64) -> DateTime<Utc> {
    base() + TimeDelta::seconds(seconds)
}

pub async fn account(pool: &PgPool, id: &str, fb_user_id: &str, username: Option<&str>) {
    sqlx::query(
        "INSERT INTO account (id, fb_user_id, username) VALUES ($1, $2, $3) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(fb_user_id)
    .bind(username)
    .execute(pool)
    .await
    .expect("insert account");
}

/// The account every seeder below defaults to.
pub async fn me(pool: &PgPool) {
    account(pool, ACCOUNT, ME, Some("tester")).await;
}

pub struct Thread<'a> {
    pub key: &'a str,
    pub sync_group: i32,
    pub title: Option<&'a str>,
    pub is_group: bool,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub newest_seen_at: Option<DateTime<Utc>>,
    pub history_done: bool,
}

impl<'a> Thread<'a> {
    /// A plain-store DM, which is the shape most of this archive is.
    pub fn dm(key: &'a str) -> Self {
        Self {
            key,
            sync_group: SYNC_GROUP_INBOX,
            title: None,
            is_group: false,
            last_activity_at: Some(base()),
            newest_seen_at: None,
            history_done: true,
        }
    }

    pub fn group(key: &'a str, title: &'a str) -> Self {
        Self {
            title: Some(title),
            is_group: true,
            ..Self::dm(key)
        }
    }

    pub fn encrypted(key: &'a str) -> Self {
        Self {
            sync_group: SYNC_GROUP_E2EE,
            ..Self::dm(key)
        }
    }
}

pub async fn thread(pool: &PgPool, spec: Thread<'_>) {
    sqlx::query(
        "INSERT INTO thread (account_id, thread_key, sync_group, title, is_group, \
                             last_activity_at, newest_seen_at, history_done) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (account_id, thread_key) DO NOTHING",
    )
    .bind(ACCOUNT)
    .bind(spec.key)
    .bind(spec.sync_group)
    .bind(spec.title)
    .bind(spec.is_group)
    .bind(spec.last_activity_at)
    .bind(spec.newest_seen_at)
    .bind(spec.history_done)
    .execute(pool)
    .await
    .expect("insert thread");
}

pub async fn participant(
    pool: &PgPool,
    fb_user_id: &str,
    name: Option<&str>,
    handle: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO participant (account_id, fb_user_id, name, username) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (account_id, fb_user_id) DO NOTHING",
    )
    .bind(ACCOUNT)
    .bind(fb_user_id)
    .bind(name)
    .bind(handle)
    .execute(pool)
    .await
    .expect("insert participant");
}

pub async fn spoke_in(pool: &PgPool, thread_key: &str, fb_user_id: &str, last: DateTime<Utc>) {
    sqlx::query(
        "INSERT INTO thread_participant (account_id, thread_key, fb_user_id, \
                                         first_spoke_at, last_spoke_at) \
         VALUES ($1, $2, $3, $4, $4) \
         ON CONFLICT (account_id, thread_key, fb_user_id) \
         DO UPDATE SET last_spoke_at = EXCLUDED.last_spoke_at",
    )
    .bind(ACCOUNT)
    .bind(thread_key)
    .bind(fb_user_id)
    .bind(last)
    .execute(pool)
    .await
    .expect("insert thread_participant");
}

pub struct Said<'a> {
    pub thread_key: &'a str,
    pub message_id: &'a str,
    pub ts: DateTime<Utc>,
    pub sender_id: Option<&'a str>,
    pub text: Option<&'a str>,
    pub item_type: &'a str,
    pub sync_group: i32,
    pub reply_to_id: Option<&'a str>,
}

impl<'a> Said<'a> {
    pub fn new(thread_key: &'a str, message_id: &'a str, second: i64) -> Self {
        Self {
            thread_key,
            message_id,
            ts: at(second),
            sender_id: Some(ME),
            text: Some("hello"),
            item_type: "text",
            sync_group: SYNC_GROUP_INBOX,
            reply_to_id: None,
        }
    }

    pub fn text(mut self, text: &'a str) -> Self {
        self.text = Some(text);
        self
    }

    /// A metadata-only envelope: a time, a sender and an id, and no words. This is what
    /// an end-to-end-encrypted DM stores, and `text IS NULL` — never `sync_group = 95` —
    /// is how the archive finds them.
    pub fn envelope(mut self) -> Self {
        self.text = None;
        self
    }

    pub fn from(mut self, sender_id: &'a str) -> Self {
        self.sender_id = Some(sender_id);
        self
    }

    pub fn kind(mut self, item_type: &'a str) -> Self {
        self.item_type = item_type;
        self
    }
}

pub async fn said(pool: &PgPool, spec: Said<'_>) {
    sqlx::query(
        "INSERT INTO message (account_id, thread_key, message_id, ts, sender_id, text, \
                              item_type, reply_to_id, sync_group) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(ACCOUNT)
    .bind(spec.thread_key)
    .bind(spec.message_id)
    .bind(spec.ts)
    .bind(spec.sender_id)
    .bind(spec.text)
    .bind(spec.item_type)
    .bind(spec.reply_to_id)
    .bind(spec.sync_group)
    .execute(pool)
    .await
    .expect("insert message");
}

pub async fn reacted(pool: &PgPool, thread_key: &str, message_id: &str, actor: &str, emoji: &str) {
    sqlx::query(
        "INSERT INTO message_reaction (account_id, thread_key, message_id, actor_id, emoji, \
                                       reacted_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(ACCOUNT)
    .bind(thread_key)
    .bind(message_id)
    .bind(actor)
    .bind(emoji)
    .bind(base())
    .execute(pool)
    .await
    .expect("insert reaction");
}

pub async fn attached(pool: &PgPool, thread_key: &str, message_id: &str, mime: Option<&str>) {
    sqlx::query(
        "INSERT INTO message_attachment (account_id, thread_key, message_id, attachment_key, \
                                         kind, mime_type) \
         VALUES ($1, $2, $3, $4, 'blob', $5)",
    )
    .bind(ACCOUNT)
    .bind(thread_key)
    .bind(message_id)
    .bind(mime.unwrap_or("key"))
    .bind(mime)
    .execute(pool)
    .await
    .expect("insert attachment");
}

/// One visit to one thread: a contiguous excerpt as the client drew it.
///
/// `lines` are `(ordinal, ts, text, sender_label)`. A `None` timestamp is a line the
/// capture could not place in time, and every read path leaves those out.
pub async fn captured(
    pool: &PgPool,
    thread_key: &str,
    run_hash: &str,
    captured_at: DateTime<Utc>,
    lines: &[(i32, Option<DateTime<Utc>>, &str, &str)],
) {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO dom_capture (account_id, thread_key, captured_at, run_hash, message_count) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(ACCOUNT)
    .bind(thread_key)
    .bind(captured_at)
    .bind(run_hash)
    .bind(lines.len() as i32)
    .fetch_one(pool)
    .await
    .expect("insert dom_capture");
    for (ordinal, ts, text, sender_label) in lines {
        sqlx::query(
            "INSERT INTO dom_message (capture_id, ordinal, text, ts, sender_label) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(ordinal)
        .bind(text)
        .bind(ts)
        .bind(sender_label)
        .execute(pool)
        .await
        .expect("insert dom_message");
    }
}

/// One revision of one message, written directly rather than through `writes::record_revision`.
pub async fn revision(
    pool: &PgPool,
    thread_key: &str,
    message_id: &str,
    seq: i32,
    text: Option<&str>,
    superseded_at: Option<DateTime<Utc>>,
) {
    sqlx::query(
        "INSERT INTO message_revision (account_id, thread_key, message_id, seq, text, \
                                       first_seen_at, superseded_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(ACCOUNT)
    .bind(thread_key)
    .bind(message_id)
    .bind(seq)
    .bind(text)
    .bind(base())
    .bind(superseded_at)
    .execute(pool)
    .await
    .expect("insert revision");
}

pub async fn deleted(pool: &PgPool, thread_key: &str, message_id: &str, at: DateTime<Utc>) {
    sqlx::query(
        "UPDATE message SET deleted_at = $4 \
         WHERE account_id = $1 AND thread_key = $2 AND message_id = $3",
    )
    .bind(ACCOUNT)
    .bind(thread_key)
    .bind(message_id)
    .bind(at)
    .execute(pool)
    .await
    .expect("mark deleted");
}

pub async fn loop_run(pool: &PgPool, name: &str, thread_key: Option<&str>, error: Option<&str>) {
    sqlx::query(
        "INSERT INTO sync_state (account_id, loop, current_thread_key, last_run_at, \
                                 last_error, last_error_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(ACCOUNT)
    .bind(name)
    .bind(thread_key)
    .bind(base())
    .bind(error)
    .bind(error.map(|_| base()))
    .execute(pool)
    .await
    .expect("insert sync_state");
}
