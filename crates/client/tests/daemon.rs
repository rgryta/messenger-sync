//! The walks against a fake gateway and a throwaway Postgres: the retired Python harvester's crawl
//! rules, checked on what they write and how many tasks they spend.

mod support;

use chrono::{DateTime, Utc};
use messenger_client::collect::Collector;
use messenger_client::daemon::{DailyBudget, PassError, Settings, Tally, listen, walk};
use messenger_client::ls::SyncCursor;
use messenger_core::models::{Account, Thread};
use messenger_core::store::writes;
use serde_json::json;
use sqlx::postgres::PgPool;
use support::{Fake, MINUTE, T0, edit, history, message, thread, unsent, voice_blob};

const ONE: &str = "1000000000000001";
const TWO: &str = "1000000000000002";

fn at(ms: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(ms).unwrap()
}

fn minutes(range: std::ops::Range<i64>) -> Vec<i64> {
    range.map(|i| T0 + i * MINUTE).collect()
}

async fn database() -> Option<(PgPool, impl Drop)> {
    let (pool, _, turn) = support::database("client_daemon").await?;
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
    Some((pool, turn))
}

/// A thread with its crawl state set as a past pass would have left it.
async fn seed(
    pool: &PgPool,
    key: &str,
    last_activity: Option<i64>,
    oldest_seen: Option<i64>,
    newest_seen: Option<i64>,
    history_done: bool,
) {
    let mut conn = pool.acquire().await.unwrap();
    writes::upsert_thread(
        &mut conn,
        &Thread {
            account_id: "me".into(),
            thread_key: key.into(),
            sync_group: 1,
            title: None,
            is_group: false,
            last_activity_at: last_activity.map(at),
            raw: json!({}),
        },
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE thread SET oldest_seen_at = $2, newest_seen_at = $3, history_done = $4 \
         WHERE thread_key = $1",
    )
    .bind(key)
    .bind(oldest_seen.map(at))
    .bind(newest_seen.map(at))
    .bind(history_done)
    .execute(&mut *conn)
    .await
    .unwrap();
}

type State = (
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    bool,
    Option<DateTime<Utc>>,
);

/// (oldest_seen_at, newest_seen_at, history_done, forward_attempted_activity_at)
async fn state(pool: &PgPool, key: &str) -> State {
    sqlx::query_as(
        "SELECT oldest_seen_at, newest_seen_at, history_done, forward_attempted_activity_at \
         FROM thread WHERE thread_key = $1",
    )
    .bind(key)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// (forward_resume_at, forward_floor_at)
async fn resume(pool: &PgPool, key: &str) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    sqlx::query_as("SELECT forward_resume_at, forward_floor_at FROM thread WHERE thread_key = $1")
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn messages(pool: &PgPool, key: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM message WHERE thread_key = $1")
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn run(pool: &PgPool, fake: &mut Fake, budget: &mut DailyBudget) -> Result<Tally, PassError> {
    let mut tally = Tally::default();
    let cursors = [SyncCursor {
        database: 1,
        current: None,
        next: "cursor".into(),
    }];
    walk(
        pool,
        fake,
        &Settings::new("me"),
        budget,
        &mut Collector::new("me"),
        &cursors,
        &mut tally,
    )
    .await
    .map(|()| tally)
}

#[tokio::test]
async fn history_finishes_only_after_two_empty_pages() {
    let Some((pool, _turn)) = database().await else {
        return;
    };
    seed(&pool, ONE, None, None, None, false).await;
    let mut fake = Fake::new(history(ONE, minutes(0..30)));
    let tally = run(&pool, &mut fake, &mut DailyBudget::new(400, 120))
        .await
        .unwrap();

    // 20, 10, then the same window asked twice and answered empty twice.
    assert_eq!(tally.history_tasks, 4);
    assert_eq!((tally.finished, tally.stalled), (1, 0));
    let references: Vec<i64> = fake.tasks.iter().map(|t| t.reference_ms).collect();
    assert_eq!(references[2], T0 - 1);
    assert_eq!(references[3], T0 - 1);
    assert_eq!(fake.tasks[0].queue, format!("mrq.{ONE}"));
    let (oldest, _, done, _) = state(&pool, ONE).await;
    assert!(done);
    assert_eq!(oldest, Some(at(T0)));
    assert_eq!(messages(&pool, ONE).await, 30);
}

#[tokio::test]
async fn a_page_with_nothing_older_stalls_without_finishing() {
    let Some((pool, _turn)) = database().await else {
        return;
    };
    seed(&pool, ONE, None, Some(T0), None, false).await;
    // The server ignores the reference and answers with what the archive already has.
    let mut fake = Fake::new(|task: &support::Task| {
        minutes(0..5)
            .into_iter()
            .map(|ts| message(&task.thread, &format!("mid.$same{ts}"), ts, "200", "word"))
            .collect()
    });
    let tally = run(&pool, &mut fake, &mut DailyBudget::new(400, 120))
        .await
        .unwrap();

    assert_eq!(tally.history_tasks, 1);
    assert_eq!((tally.finished, tally.stalled), (0, 1));
    let (oldest, _, done, _) = state(&pool, ONE).await;
    assert!(!done);
    assert_eq!(oldest, Some(at(T0)));
}

#[tokio::test]
async fn the_forward_walk_stops_at_the_watermark() {
    let Some((pool, _turn)) = database().await else {
        return;
    };
    // Held through minute 0, which the second page reaches exactly; the listing says minute 40.
    let watermark = T0;
    let activity = T0 + 40 * MINUTE;
    seed(&pool, ONE, Some(activity), None, Some(watermark), true).await;
    let mut fake = Fake::new(history(ONE, minutes(0..40)));
    let tally = run(&pool, &mut fake, &mut DailyBudget::new(400, 120))
        .await
        .unwrap();

    // Minutes 39..20, then 19..0, whose oldest is the watermark itself.
    assert_eq!(tally.forward_tasks, 2);
    assert_eq!(tally.history_tasks, 0);
    assert!(
        fake.tasks[0].reference_ms > activity,
        "the first page is from now"
    );
    assert_eq!(fake.tasks[1].reference_ms, T0 + 20 * MINUTE);
    let (_, newest, _, answered) = state(&pool, ONE).await;
    assert_eq!(newest, Some(at(T0 + 39 * MINUTE)));
    assert_eq!(answered, Some(at(activity)));
    assert_eq!(tally.new_messages, 40);
}

#[tokio::test]
async fn history_never_spends_the_forward_reserve() {
    let Some((pool, _turn)) = database().await else {
        return;
    };
    seed(&pool, ONE, None, None, None, false).await;
    let mut fake = Fake::new(history(ONE, minutes(0..200)));
    let mut budget = DailyBudget::new(5, 3);
    let tally = run(&pool, &mut fake, &mut budget).await.unwrap();

    assert_eq!(tally.history_tasks, 2);
    assert_eq!(budget.remaining(), 3);
    let (_, _, done, _) = state(&pool, ONE).await;
    assert!(!done);
}

#[tokio::test]
async fn a_forward_walk_cut_short_by_the_budget_answers_nothing() {
    let Some((pool, _turn)) = database().await else {
        return;
    };
    seed(&pool, ONE, Some(T0 + 300 * MINUTE), None, None, true).await;
    seed(&pool, TWO, None, None, None, false).await;
    let mut fake = Fake::new(history(ONE, minutes(0..200)));
    let mut budget = DailyBudget::new(3, 3);
    let tally = run(&pool, &mut fake, &mut budget).await.unwrap();

    // Forward draws on the whole budget, history on nothing past the reserve.
    assert_eq!((tally.forward_tasks, tally.history_tasks), (3, 0));
    assert!(fake.tasks.iter().all(|t| t.thread == ONE));
    let (_, newest, _, answered) = state(&pool, ONE).await;
    assert_eq!(newest, Some(at(T0 + 199 * MINUTE)));
    assert_eq!(
        answered, None,
        "a walk the budget cut short answered nothing"
    );
    assert_eq!(budget.remaining(), 0);
    // Minutes 199..140 read: the next pass carries on below them, down to the beginning.
    assert_eq!(
        resume(&pool, ONE).await,
        (Some(at(T0 + 140 * MINUTE)), Some(DateTime::UNIX_EPOCH))
    );
}

#[tokio::test]
async fn a_forward_walk_cut_by_the_page_cap_resumes_without_a_hole() {
    let Some((pool, _turn)) = database().await else {
        return;
    };
    // Held through minute 0; 200 new minutes is more than one pass's 4 pages of 20.
    let activity = T0 + 200 * MINUTE;
    seed(&pool, ONE, Some(activity), None, Some(T0), true).await;
    let mut fake = Fake::new(history(ONE, minutes(0..200)));
    let mut budget = DailyBudget::new(400, 120);

    let tally = run(&pool, &mut fake, &mut budget).await.unwrap();
    assert_eq!(tally.forward_tasks, 4);
    assert_eq!(
        resume(&pool, ONE).await,
        (Some(at(T0 + 120 * MINUTE)), Some(at(T0)))
    );
    let (_, newest, _, answered) = state(&pool, ONE).await;
    assert_eq!(newest, Some(at(T0 + 199 * MINUTE)));
    assert_eq!(answered, Some(at(activity)));

    // The next pass starts where this one stopped, not from now.
    run(&pool, &mut fake, &mut budget).await.unwrap();
    assert_eq!(fake.tasks[4].reference_ms, T0 + 120 * MINUTE);
    assert_eq!(resume(&pool, ONE).await.0, Some(at(T0 + 40 * MINUTE)));

    let tally = run(&pool, &mut fake, &mut budget).await.unwrap();
    assert_eq!(
        tally.forward_tasks, 2,
        "minutes 39..20, then 19..0 at the watermark"
    );
    assert_eq!(resume(&pool, ONE).await, (None, None));
    assert_eq!(messages(&pool, ONE).await, 200);

    // Done: nothing is walked until the listing moves again.
    let tally = run(&pool, &mut fake, &mut budget).await.unwrap();
    assert_eq!(tally.forward_tasks, 0);
}

#[tokio::test]
async fn what_the_sync_stream_pushes_is_stored() {
    let Some((pool, _turn)) = database().await else {
        return;
    };
    let mut fake = Fake::new(|_: &support::Task| Vec::new());
    fake.on_open.insert(
        1,
        json!([
            thread(TWO, None, T0 + MINUTE),
            message(TWO, "mid.$live", T0 + MINUTE, "200", "live"),
            // A thread nothing listed: its row comes from the message.
            message(ONE, "mid.$unlisted", T0, "200", "live")
        ]),
    );
    let tally = run(&pool, &mut fake, &mut DailyBudget::new(400, 120))
        .await
        .unwrap();

    assert_eq!(fake.opened, [(1, "cursor".to_owned())]);
    assert_eq!(tally.new_messages, 2);
    assert_eq!(messages(&pool, ONE).await, 1);
    assert_eq!(messages(&pool, TWO).await, 1);
}

#[tokio::test]
async fn a_sync_stream_that_never_answers_spends_no_task() {
    let Some((pool, _turn)) = database().await else {
        return;
    };
    seed(&pool, ONE, None, None, None, false).await;
    let mut fake = Fake::new(history(ONE, minutes(0..30)));
    fake.silent = true;
    assert!(
        run(&pool, &mut fake, &mut DailyBudget::new(400, 120))
            .await
            .is_err()
    );
    assert!(fake.tasks.is_empty());
}

#[tokio::test]
async fn only_consecutive_empty_pages_finish_a_thread() {
    let Some((pool, _turn)) = database().await else {
        return;
    };
    seed(&pool, ONE, None, None, None, false).await;
    // A reply lost once, then a real page, then the true end.
    let mut page = 0;
    let mut fake = Fake::new(move |task: &support::Task| {
        page += 1;
        if page != 2 {
            return Vec::new();
        }
        minutes(0..10)
            .into_iter()
            .map(|ts| message(&task.thread, &format!("mid.$m{ts}"), ts, "200", "word"))
            .collect()
    });
    let tally = run(&pool, &mut fake, &mut DailyBudget::new(400, 120))
        .await
        .unwrap();

    assert_eq!(tally.history_tasks, 4);
    assert_eq!(tally.finished, 1);
    assert_eq!(state(&pool, ONE).await.0, Some(at(T0)));
}

#[tokio::test]
async fn between_passes_the_stream_is_stored_as_it_pushes() {
    let Some((pool, _turn)) = database().await else {
        return;
    };
    seed(&pool, ONE, Some(T0), Some(T0), Some(T0), true).await;
    {
        let mut conn = pool.acquire().await.unwrap();
        let mut batch = Collector::new("me");
        batch.feed(
            Some(1),
            &json!([
                message(ONE, "mid.$old", T0, "200", "helo"),
                message(ONE, "mid.$gone", T0 + MINUTE, "200", "oops"),
            ]),
        );
        messenger_client::collect::persist(&mut conn, &batch)
            .await
            .unwrap();
    }
    let mut fake = Fake::new(|_| Vec::new());
    // What the live stream pushes while no pass is running: a new message, then an edit and
    // an unsend of older ones.
    fake.push(
        1,
        json!([message(ONE, "mid.$new", T0 + 2 * MINUTE, "200", "fresh")]),
    );
    fake.push(
        1,
        json!([
            edit("mid.$old", "hello"),
            unsent(ONE, "mid.$gone", T0 + MINUTE, T0 + 3 * MINUTE)
        ]),
    );
    let heard = listen(&pool, &mut fake, "me", tokio::time::Instant::now()).await;
    assert_eq!(heard.syncs, 2);
    assert_eq!(heard.new_messages, 1);
    assert_eq!(heard.ended_early, None);

    assert_eq!(messages(&pool, ONE).await, 3);
    let edited: String =
        sqlx::query_scalar("SELECT text FROM message WHERE message_id = 'mid.$old'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(edited, "hello");
    let revisions: i64 = sqlx::query_scalar("SELECT count(*) FROM message_revision")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(revisions, 2);
    let gone: bool = sqlx::query_scalar(
        "SELECT deleted_at IS NOT NULL FROM message WHERE message_id = 'mid.$gone'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(gone);
}

#[tokio::test]
async fn an_expired_voice_link_is_refreshed_by_rereading_its_page() {
    let Some((pool, _turn)) = database().await else {
        return;
    };
    seed(&pool, ONE, None, None, None, true).await;
    let mut conn = pool.acquire().await.unwrap();
    let stored = |mid: &str, ts: i64| messenger_core::models::Message {
        account_id: "me".into(),
        thread_key: ONE.into(),
        message_id: mid.into(),
        ts: at(ts),
        sender_id: Some("200".into()),
        text: None,
        item_type: "text".into(),
        reply_to_id: None,
        attachments: json!([]),
        sync_group: 1,
        raw: json!({}),
    };
    writes::insert_messages(
        &mut conn,
        &[stored("mid.$voice", T0), stored("mid.$gone", T0 + MINUTE)],
    )
    .await
    .unwrap();
    let file = |mid: &str| messenger_core::models::Attachment {
        account_id: "me".into(),
        thread_key: ONE.into(),
        message_id: mid.into(),
        attachment_id: Some(format!("att-{mid}")),
        kind: "blob".into(),
        mime_type: Some("audio/mpeg".into()),
        url: Some(format!("https://cdn.invalid/old/{mid}")),
        preview_url: None,
        raw: json!({}),
    };
    writes::insert_attachments(&mut conn, &[file("mid.$voice"), file("mid.$gone")])
        .await
        .unwrap();
    sqlx::query("UPDATE message SET transcript_status = 'expired'")
        .execute(&mut *conn)
        .await
        .unwrap();

    // The page before the first clip holds it with a fresh link; the other page misses its clip.
    let mut fake = Fake::new(|task: &support::Task| {
        if task.reference_ms == T0 + 1 {
            vec![
                message(ONE, "mid.$voice", T0, "200", ""),
                voice_blob(
                    ONE,
                    "mid.$voice",
                    "att-mid.$voice",
                    "https://cdn.invalid/fresh",
                ),
            ]
        } else {
            Vec::new()
        }
    });
    let tally = run(&pool, &mut fake, &mut DailyBudget::new(400, 120))
        .await
        .unwrap();

    assert_eq!(tally.relink_tasks, 2);
    let references: Vec<i64> = fake.tasks.iter().map(|t| t.reference_ms).collect();
    assert_eq!(references, vec![T0 + MINUTE + 1, T0 + 1], "newest first");
    let state: Vec<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT m.message_id, m.transcript_status, a.url FROM message m \
         JOIN message_attachment a USING (account_id, thread_key, message_id) ORDER BY m.ts",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        state,
        vec![
            (
                "mid.$voice".into(),
                None,
                "https://cdn.invalid/fresh".into()
            ),
            (
                "mid.$gone".into(),
                Some("failed".into()),
                "https://cdn.invalid/old/mid.$gone".into()
            ),
        ]
    );
}
