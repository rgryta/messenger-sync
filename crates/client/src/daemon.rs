//! The harvest loop without a browser, ported from the retired Python harvester's `runner.py`.
//!
//! A pass loads messenger.com with the stored cookies, takes the inbox and encrypted-thread
//! snapshots over GraphQL, opens the gateway's sync streams from the snapshots' cursors, then
//! walks forward (new messages) and backward (history) one message-page task at a time. A
//! task's answer is pushed down the sync streams, not its own stream, so a task's results are
//! whatever those streams push within `task_settle` after it, as the Python harvester drained
//! the browser's events for `task_settle_seconds`. Anything else pushed in that window — a
//! live message in another thread — is collected and stored with it.
//!
//! Revisions and deletion detection are not ported yet.

use std::time::Duration;

use chrono::{DateTime, NaiveDate, Utc};
use messenger_core::models::Account;
use messenger_core::store::{e2ee, writes};
use serde_json::Value;
use sqlx::postgres::PgPool;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::collect::{self, Collector};
use crate::cookies::Jar;
use crate::gateway::{BASE, Event, Gateway, GatewayError, Socket, USER_AGENT};
use crate::ls::{self, FETCH_MESSAGES, SyncCursor};
use crate::page::{self, PageConfig, PageError, Preloader};
use crate::{graphql, session};

const HOST: &str = "www.messenger.com";
const SEC_CH_UA: &str = r#""Chromium";v="141", "Google Chrome";v="141", "Not-A.Brand";v="99""#;

/// `HarvestSettings`, with the Python's defaults.
#[derive(Debug, Clone)]
pub struct Settings {
    pub account: String,
    pub interval: Duration,
    pub jitter: f64,
    pub history_thread_budget: i64,
    pub history_pages_per_thread: usize,
    pub history_daily_tasks: usize,
    pub history_empty_pages_to_finish: usize,
    pub forward_thread_budget: i64,
    pub forward_pages_per_thread: usize,
    pub forward_daily_reserve: usize,
    pub task_settle: Duration,
    pub auth_retry: Duration,
}

impl Settings {
    pub fn new(account: &str) -> Self {
        Settings {
            account: account.to_owned(),
            interval: Duration::from_secs(900),
            jitter: 0.2,
            history_thread_budget: 8,
            history_pages_per_thread: 6,
            history_daily_tasks: 400,
            history_empty_pages_to_finish: 2,
            forward_thread_budget: 20,
            forward_pages_per_thread: 4,
            forward_daily_reserve: 120,
            task_settle: Duration::from_secs(12),
            auth_retry: Duration::from_secs(3600),
        }
    }
}

/// Message-page tasks spent today, reset when the UTC date turns over. Held in memory across
/// passes, so a restart resets it: a bound on politeness, not a correctness invariant.
#[derive(Debug)]
pub struct DailyBudget {
    limit: usize,
    /// Tasks the backward crawl may not touch, so catching up on new messages is still
    /// possible late in a day whose budget history has spent.
    reserve: usize,
    day: NaiveDate,
    spent: usize,
}

impl DailyBudget {
    pub fn new(limit: usize, reserve: usize) -> Self {
        DailyBudget {
            limit,
            reserve: reserve.min(limit),
            day: Utc::now().date_naive(),
            spent: 0,
        }
    }

    /// What the forward walk may spend: everything that is left.
    pub fn remaining(&mut self) -> usize {
        let today = Utc::now().date_naive();
        if today != self.day {
            (self.day, self.spent) = (today, 0);
        }
        self.limit.saturating_sub(self.spent)
    }

    /// What the backward crawl may spend: everything except the reserve.
    pub fn remaining_after_reserve(&mut self) -> usize {
        self.remaining().saturating_sub(self.reserve)
    }

    pub fn spend(&mut self, tasks: usize) {
        self.spent += tasks;
    }
}

/// What a pass did, which is what its log line is made of.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tally {
    pub threads: usize,
    pub new_messages: u64,
    pub forward_tasks: usize,
    pub history_tasks: usize,
    /// Pages re-read for a voice message's fresh link.
    pub relink_tasks: usize,
    pub finished: usize,
    pub stalled: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum PassError {
    /// Recovery is a human signing in again, so the loop waits `auth_retry`.
    #[error("not logged in: {0}")]
    LoggedOut(String),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error(transparent)]
    Gateway(GatewayError),
    #[error("{0}")]
    Other(String),
}

/// An error with every cause under it: reqwest's own message ("error decoding response
/// body") names the step, and only the source says what went wrong.
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

impl From<GatewayError> for PassError {
    fn from(e: GatewayError) -> Self {
        match e {
            GatewayError::Deauth => PassError::LoggedOut(e.to_string()),
            e => PassError::Gateway(e),
        }
    }
}

/// Jittered, with a floor: a small interval and a large jitter must not collapse into a
/// pass every few seconds.
/// The pause before the next pass after the live stream dropped.
const LIVE_RETRY: Duration = Duration::from_secs(60);

pub fn next_interval(settings: &Settings) -> Duration {
    let interval = settings.interval.as_secs_f64();
    let spread = interval * settings.jitter;
    let jitter = if spread > 0.0 {
        rand::random_range(-spread..=spread)
    } else {
        0.0
    };
    Duration::from_secs_f64((interval + jitter).max(60.0))
}

/// Consumes the gateway's events for a bounded time. Bounded rather than "until quiet": the
/// sync stream is never truly quiet.
async fn drain<G: Gateway>(
    gateway: &mut G,
    collector: &mut Collector,
    seconds: Duration,
) -> Result<(), GatewayError> {
    let deadline = Instant::now() + seconds;
    while let Some(event) = gateway.next_event(deadline).await? {
        if let Event::Sync { database, steps } = event {
            collector.feed(u8::try_from(database).ok(), &steps);
        }
    }
    Ok(())
}

async fn persist(pool: &PgPool, collector: &Collector) -> sqlx::Result<u64> {
    let mut conn = pool.acquire().await?;
    collect::persist(&mut conn, collector).await
}

/// A thread key as the task wants it, and the task's sync group.
fn task_target(thread_key: &str, sync_group: i32) -> Option<(i64, u8)> {
    Some((thread_key.parse().ok()?, u8::try_from(sync_group).ok()?))
}

/// Everything after the snapshots: open the sync streams, store what they deliver first,
/// then the forward walk and the history walk within the day's budget.
pub async fn walk<G: Gateway>(
    pool: &PgPool,
    gateway: &mut G,
    settings: &Settings,
    budget: &mut DailyBudget,
    collector: &mut Collector,
    cursors: &[SyncCursor],
    tally: &mut Tally,
) -> Result<(), PassError> {
    // A task sent before its sync stream has answered has nowhere to be pushed to.
    let deadline = Instant::now() + settings.task_settle;
    let mut waiting: Vec<u32> = Vec::new();
    for cursor in cursors {
        gateway.open_sync(cursor.database, &cursor.next).await?;
        waiting.push(cursor.database);
    }
    while !waiting.is_empty() {
        match gateway.next_event(deadline).await? {
            Some(Event::Sync { database, steps }) => {
                collector.feed(u8::try_from(database).ok(), &steps);
                waiting.retain(|d| *d != database);
            }
            Some(Event::TaskDone) => {}
            None => {
                return Err(PassError::Other(format!(
                    "sync for database(s) {waiting:?} never answered"
                )));
            }
        }
    }
    tally.new_messages += persist(pool, collector).await?;
    collector.clear_directory();

    // Forward before backward, and history may not spend the reserve: new messages first.
    let allowance = budget.remaining();
    if allowance > 0 {
        walk_forward(pool, gateway, settings, collector, allowance, tally).await?;
        budget.spend(tally.forward_tasks);
    }
    // Then fresh links for voice messages, ahead of history: a link lasts only days.
    let allowance = budget.remaining_after_reserve().min(RELINK_PER_PASS);
    if allowance > 0 {
        relink_voice(pool, gateway, settings, collector, allowance, tally).await?;
        budget.spend(tally.relink_tasks);
    }
    let allowance = budget.remaining_after_reserve();
    if allowance == 0 {
        tracing::info!("history: daily task ceiling reached, resting until tomorrow");
    } else {
        walk_history(pool, gateway, settings, collector, allowance, tally).await?;
        budget.spend(tally.history_tasks);
    }
    Ok(())
}

/// What [`listen`] did until it stopped.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Heard {
    pub syncs: usize,
    pub new_messages: u64,
    /// Why it stopped before `until`, if it did: the socket closed or failed.
    pub ended_early: Option<String>,
}

/// Between passes, the sync streams stay open and whatever they push is stored as it
/// arrives: new messages in real time, and the `editMessage` and unsend events that a pass
/// can only see if they happen during its few seconds on the socket. Returns at `until`,
/// or when the socket ends; the next pass reconnects either way.
pub async fn listen<G: Gateway>(
    pool: &PgPool,
    gateway: &mut G,
    account: &str,
    until: Instant,
) -> Heard {
    let mut heard = Heard::default();
    let mut collector = Collector::new(account);
    loop {
        match gateway.next_event(until).await {
            Ok(Some(Event::Sync { database, steps })) => {
                heard.syncs += 1;
                collector.begin_page();
                collector.clear_directory();
                collector.feed(u8::try_from(database).ok(), &steps);
                match persist(pool, &collector).await {
                    Ok(n) => heard.new_messages += n,
                    Err(e) => tracing::warn!("storing what the stream pushed failed: {e}"),
                }
            }
            Ok(Some(Event::TaskDone)) => {}
            Ok(None) => return heard,
            Err(e) => {
                heard.ended_early = Some(e.to_string());
                return heard;
            }
        }
    }
}

/// Picks up messages that arrived since the last pass: threads whose listing is ahead of the
/// newest message held, paged from now back to that watermark. A walk the page cap or the
/// budget cuts short is resumed next pass from where it stopped, down to the same watermark.
async fn walk_forward<G: Gateway>(
    pool: &PgPool,
    gateway: &mut G,
    settings: &Settings,
    collector: &mut Collector,
    allowance: usize,
    tally: &mut Tally,
) -> Result<(), PassError> {
    let account = settings.account.as_str();
    let moved = {
        let mut conn = pool.acquire().await?;
        writes::threads_with_new_activity(&mut conn, account, settings.forward_thread_budget)
            .await?
    };
    for row in moved {
        let Some((key, group)) = task_target(&row.thread_key, row.sync_group) else {
            tracing::warn!("a thread key or sync group a task cannot carry, skipped");
            continue;
        };
        let resuming = row.forward_resume_at.is_some();
        let floor = row
            .forward_floor_at
            .or(row.newest_seen_at)
            .unwrap_or(DateTime::UNIX_EPOCH);
        let mut reference = row.forward_resume_at.unwrap_or_else(Utc::now);
        let (mut pages, mut reached, mut out_of_budget) = (0, false, false);
        while pages < settings.forward_pages_per_thread {
            if tally.forward_tasks >= allowance {
                out_of_budget = true;
                break;
            }
            collector.begin_page();
            collector.expect = Some((row.thread_key.clone(), group));
            let payload = ls::fetch_messages(key, reference.timestamp_millis(), group);
            gateway
                .send_task(FETCH_MESSAGES, &format!("mrq.{key}"), payload)
                .await?;
            drain(gateway, collector, settings.task_settle).await?;
            collector.expect = None;
            tally.forward_tasks += 1;
            pages += 1;

            let decoded = collector.decoded_messages;
            tally.new_messages += persist(pool, collector).await?;
            // shortcut: `_reconcile` (revisions) and deletions not ported; add with `record_revision`.
            collector.clear_directory();
            let newest = collector.per_thread_newest.remove(&row.thread_key);
            let oldest = collector.per_thread_oldest.remove(&row.thread_key);
            if newest.is_some() {
                let mut conn = pool.acquire().await?;
                writes::set_forward_progress(&mut conn, account, &row.thread_key, newest, None)
                    .await?;
            }
            match oldest {
                Some(oldest) if decoded > 0 && oldest > floor => reference = oldest,
                // Reached what the archive already holds, or nothing older is left.
                _ => {
                    reached = true;
                    break;
                }
            }
        }
        if pages == 0 {
            return Ok(());
        }
        let mut conn = pool.acquire().await?;
        let resume = (!reached).then_some(reference);
        writes::set_forward_resume(&mut conn, account, &row.thread_key, resume, floor).await?;
        // A walk the budget cut short has not answered the activity report it was selected
        // on, and a resumed walk read only the gap, not what is new above it.
        if out_of_budget {
            return Ok(());
        }
        if resuming {
            continue;
        }
        writes::set_forward_progress(
            &mut conn,
            account,
            &row.thread_key,
            None,
            row.last_activity_at,
        )
        .await?;
    }
    Ok(())
}

/// Voice messages relinked per pass at most, so a backlog spreads over passes.
const RELINK_PER_PASS: usize = 20;

/// Plain voice messages whose stored link expired before the transcriber reached them,
/// newest first: one task each re-reads the page that holds the message (Meta answers with
/// the messages before the reference, so one millisecond past it), which stores a fresh
/// link and hands the message back to the transcriber.
async fn relink_voice<G: Gateway>(
    pool: &PgPool,
    gateway: &mut G,
    settings: &Settings,
    collector: &mut Collector,
    allowance: usize,
    tally: &mut Tally,
) -> Result<(), PassError> {
    let expired = {
        let mut conn = pool.acquire().await?;
        e2ee::expired_voice(&mut conn, &settings.account, allowance as i64).await?
    };
    for voice in expired {
        let Some((key, group)) = task_target(&voice.thread_key, voice.sync_group) else {
            tracing::warn!("a thread key or sync group a task cannot carry, skipped");
            continue;
        };
        collector.begin_page();
        collector.expect = Some((voice.thread_key.clone(), group));
        let payload = ls::fetch_messages(key, voice.ts.timestamp_millis() + 1, group);
        gateway
            .send_task(FETCH_MESSAGES, &format!("mrq.{key}"), payload)
            .await?;
        drain(gateway, collector, settings.task_settle).await?;
        collector.expect = None;
        tally.relink_tasks += 1;
        tally.new_messages += persist(pool, collector).await?;
        collector.clear_directory();
        // The page moves no walk: what it saw must not reach one.
        collector.per_thread_newest.remove(&voice.thread_key);
        collector.per_thread_oldest.remove(&voice.thread_key);
        let mut conn = pool.acquire().await?;
        if !e2ee::requeue_if_relinked(&mut conn, &voice).await? {
            tracing::warn!("a voice message's page came back without a fresh link; given up");
        }
    }
    Ok(())
}

/// Pages a budgeted number of threads backwards. Decoded messages decide, not inserted rows,
/// and an empty page has to repeat before it counts: `history_done` is a one-way door, and
/// one late reply must not close it on a thread with a decade left in it.
async fn walk_history<G: Gateway>(
    pool: &PgPool,
    gateway: &mut G,
    settings: &Settings,
    collector: &mut Collector,
    allowance: usize,
    tally: &mut Tally,
) -> Result<(), PassError> {
    let account = settings.account.as_str();
    let pending = {
        let mut conn = pool.acquire().await?;
        writes::threads_needing_history(&mut conn, account, settings.history_thread_budget).await?
    };
    for row in pending {
        let Some((key, group)) = task_target(&row.thread_key, row.sync_group) else {
            tracing::warn!("a thread key or sync group a task cannot carry, skipped");
            continue;
        };
        let mut reference: DateTime<Utc> = row.oldest_seen_at.unwrap_or_else(Utc::now);
        let mut empty_streak = 0;
        {
            let mut conn = pool.acquire().await?;
            writes::mark_loop_run(&mut conn, account, "history", Some(&row.thread_key), None)
                .await?;
        }
        for _ in 0..settings.history_pages_per_thread {
            if tally.history_tasks >= allowance {
                return Ok(());
            }
            collector.begin_page();
            collector.expect = Some((row.thread_key.clone(), group));
            let payload = ls::fetch_messages(key, reference.timestamp_millis() - 1, group);
            gateway
                .send_task(FETCH_MESSAGES, &format!("mrq.{key}"), payload)
                .await?;
            drain(gateway, collector, settings.task_settle).await?;
            collector.expect = None;
            tally.history_tasks += 1;

            let decoded = collector.decoded_messages;
            tally.new_messages += persist(pool, collector).await?;
            collector.clear_directory();
            let oldest = collector.per_thread_oldest.get(&row.thread_key).copied();
            let mut conn = pool.acquire().await?;

            if decoded == 0 {
                // Also what a late reply looks like: finished only when it repeats.
                empty_streak += 1;
                if empty_streak < settings.history_empty_pages_to_finish {
                    continue;
                }
                writes::set_history_progress(&mut conn, account, &row.thread_key, oldest, true)
                    .await?;
                tally.finished += 1;
                break;
            }
            empty_streak = 0;

            match oldest {
                Some(oldest) if oldest < reference => {
                    reference = oldest;
                    writes::set_history_progress(
                        &mut conn,
                        account,
                        &row.thread_key,
                        Some(oldest),
                        false,
                    )
                    .await?;
                    collector.per_thread_oldest.remove(&row.thread_key);
                }
                _ => {
                    // Messages came back but none older than where the crawl was: it is not
                    // advancing, and asking again would ask for the same window forever.
                    tracing::warn!(
                        decoded,
                        "a history page held nothing older than its reference, pausing that thread"
                    );
                    writes::set_history_progress(
                        &mut conn,
                        account,
                        &row.thread_key,
                        oldest,
                        false,
                    )
                    .await?;
                    tally.stalled += 1;
                    break;
                }
            }
        }
    }
    Ok(())
}

/// messenger.com over HTTPS, with the jar every response's cookies go into.
struct Web {
    http: reqwest::Client,
    jar: Jar,
    rotated: bool,
}

impl Web {
    fn take_cookies(&mut self, headers: &reqwest::header::HeaderMap) {
        for value in headers.get_all("set-cookie") {
            if let Ok(v) = value.to_str() {
                self.jar.set(v, HOST, Utc::now());
                self.rotated = true;
            }
        }
    }

    fn browser(&self, request: reqwest::RequestBuilder, path: &str) -> reqwest::RequestBuilder {
        request
            .header("user-agent", USER_AGENT)
            .header("accept-language", "pl-PL,pl;q=0.9,en;q=0.8")
            .header("sec-ch-ua", SEC_CH_UA)
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"Linux\"")
            .header("cookie", self.jar.header(HOST, path, Utc::now()))
    }

    /// The page, tried again after a transport failure. Meta's edge sometimes resets the
    /// 1.4 MB page mid-body (HTTP/2 `INTERNAL_ERROR`, seen 2026-11-14); a browser just
    /// reloads. A logged-out page is never retried: that answer is the session's.
    async fn page_with_retries(&mut self) -> Result<PageConfig, PassError> {
        let pauses = [Duration::from_secs(2), Duration::from_secs(10)];
        let mut attempt = 0;
        loop {
            match self.page().await {
                Err(PassError::Other(reason)) if attempt < pauses.len() => {
                    tracing::warn!("page load failed, trying again: {reason}");
                    tokio::time::sleep(pauses[attempt]).await;
                    attempt += 1;
                }
                other => return other,
            }
        }
    }

    async fn page(&mut self) -> Result<PageConfig, PassError> {
        let request = self
            .browser(self.http.get(format!("{BASE}/")), "/")
            .header(
                "accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .header("sec-fetch-dest", "document")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-site", "none")
            .header("sec-fetch-user", "?1")
            .header("upgrade-insecure-requests", "1");
        let response = request
            .send()
            .await
            .map_err(|e| PassError::Other(format!("page: {}", chain(&e))))?;
        // Held back until the page proves logged in: a logged-out reply expires the
        // session's cookies, and taking them would turn a passing hiccup into a dead jar
        // for every retry - how the Chromium profile was lost once.
        let set_cookies = response.headers().clone();
        if response.status().is_redirection() {
            return Err(PassError::LoggedOut("the page redirected".into()));
        }
        let html = response
            .text()
            .await
            .map_err(|e| PassError::Other(format!("page: {}", chain(&e))))?;
        let config = page::scrape(&html).map_err(|e| match e {
            PageError::LoggedOut => PassError::LoggedOut(e.to_string()),
            e => PassError::Other(format!("page: {e}")),
        })?;
        self.take_cookies(&set_cookies);
        Ok(config)
    }

    /// POSTs a GraphQL form as the page does and returns the answer's body.
    async fn post_graphql(
        &mut self,
        config: &PageConfig,
        friendly_name: &str,
        form: &[(&'static str, String)],
    ) -> Result<String, PassError> {
        let request = self
            .browser(
                self.http.post(format!("{BASE}/api/graphql/")),
                "/api/graphql/",
            )
            .header("accept", "*/*")
            .header("origin", BASE)
            .header("referer", format!("{BASE}/"))
            .header("sec-fetch-dest", "empty")
            .header("sec-fetch-mode", "cors")
            .header("sec-fetch-site", "same-origin")
            .header("x-asbd-id", "359341")
            .header("x-fb-friendly-name", friendly_name)
            .header("x-fb-lsd", config.lsd.clone().unwrap_or_default())
            .form(form);
        let response = request
            .send()
            .await
            .map_err(|e| PassError::Other(format!("{friendly_name}: {}", chain(&e))))?;
        self.take_cookies(response.headers());
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| PassError::Other(format!("{friendly_name}: {}", chain(&e))))?;
        if !status.is_success() {
            return Err(PassError::Other(format!("{friendly_name}: HTTP {status}")));
        }
        Ok(body)
    }

    async fn snapshot(
        &mut self,
        config: &PageConfig,
        preloader: &Preloader,
    ) -> Result<Value, PassError> {
        let database = preloader.database;
        let body = self
            .post_graphql(
                config,
                "LSPlatformGraphQLLightspeedRequestQuery",
                &graphql::snapshot_form(config, preloader),
            )
            .await
            .map_err(|e| PassError::Other(format!("snapshot {database}: {e}")))?;
        let payload = graphql::snapshot_payload(&body)
            .map_err(|e| PassError::Other(format!("snapshot {database}: {e}")))?;
        let data: Value = serde_json::from_str(&payload)
            .map_err(|e| PassError::Other(format!("snapshot {database} payload: {e}")))?;
        Ok(data.get("step").cloned().unwrap_or(Value::Null))
    }

    /// One persisted query of the history backup: `data.<field>` of its answer.
    async fn backup_call(
        &mut self,
        config: &PageConfig,
        doc: &graphql::Doc,
        field: &str,
        variables: &Value,
    ) -> Result<Option<Value>, PassError> {
        let body = self
            .post_graphql(config, doc.name, &graphql::doc_form(config, doc, variables))
            .await?;
        graphql::data_field(&body, field)
            .map_err(|e| PassError::Other(format!("{}: {e}", doc.name)))
    }
}

pub struct Client {
    pool: PgPool,
    settings: Settings,
    web: Web,
    budget: DailyBudget,
    /// The newest page's crypto auth token, for the encrypted chat (`chat::Chat::run`).
    cat: watch::Sender<Option<String>>,
}

impl Client {
    /// The database the client archives into.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// The logged-in page, for work outside the inbox loop (the history restore).
    pub async fn page(&mut self) -> Result<PageConfig, PassError> {
        let config = self.web.page_with_retries().await?;
        self.save_cookies().await?;
        Ok(config)
    }

    /// One persisted query of the history backup: `data.<field>` of its answer.
    pub async fn backup_call(
        &mut self,
        config: &PageConfig,
        doc: &graphql::Doc,
        field: &str,
        variables: &Value,
    ) -> Result<Option<Value>, PassError> {
        let answer = self.web.backup_call(config, doc, field, variables).await;
        self.save_cookies().await?;
        answer
    }

    pub fn new(pool: PgPool, settings: Settings, jar: Jar) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .build()?;
        let budget = DailyBudget::new(settings.history_daily_tasks, settings.forward_daily_reserve);
        Ok(Client {
            pool,
            settings,
            web: Web {
                http,
                jar,
                rotated: false,
            },
            budget,
            cat: watch::Sender::new(None),
        })
    }

    /// Each page's crypto auth token as it is loaded: the encrypted chat logs in with it.
    pub fn crypto_auth_tokens(&self) -> watch::Receiver<Option<String>> {
        self.cat.subscribe()
    }

    pub async fn run(mut self) {
        let account = self.settings.account.clone();
        loop {
            let result = self.pass().await;
            // Saved whatever the pass's outcome: a rotation Meta sent is the session now.
            if let Err(e) = self.save_cookies().await {
                tracing::error!("saving the rotated cookies failed: {e}");
            }
            let mut live = None;
            let outcome = match result {
                Ok((tally, socket)) => {
                    live = Some(socket);
                    tracing::info!(
                        "pass: {} thread(s), {} new message(s), {} forward + {} history + {} voice-link task(s), {} finished, {} stalled",
                        tally.threads,
                        tally.new_messages,
                        tally.forward_tasks,
                        tally.history_tasks,
                        tally.relink_tasks,
                        tally.finished,
                        tally.stalled
                    );
                    self.mark(&account, "harvest", None).await
                }
                Err(PassError::LoggedOut(reason)) => {
                    tracing::error!(
                        "session is dead: {reason}; waiting {}s before trying again",
                        self.settings.auth_retry.as_secs()
                    );
                    if let Err(e) = self.record_auth_error(&account, &reason).await {
                        tracing::error!("recording the auth error failed: {e}");
                    }
                    tokio::time::sleep(self.settings.auth_retry).await;
                    continue;
                }
                Err(e) => {
                    tracing::error!("harvest pass failed: {e}");
                    self.mark(&account, "harvest", Some(&e.to_string())).await
                }
            };
            if let Err(e) = outcome {
                tracing::error!("recording the pass failed: {e}");
            }
            let until = Instant::now() + next_interval(&self.settings);
            match live {
                Some(mut socket) => {
                    let heard = listen(&self.pool, &mut socket, &account, until).await;
                    socket.close().await;
                    if heard.new_messages > 0 {
                        tracing::info!(
                            "live: {} new message(s) from {} sync push(es)",
                            heard.new_messages,
                            heard.syncs
                        );
                    }
                    if let Some(why) = heard.ended_early {
                        // The next pass reconnects; a short pause keeps a socket that keeps
                        // dropping from turning into a tight loop of passes.
                        tracing::warn!("live stream ended early: {why}");
                        tokio::time::sleep(
                            LIVE_RETRY.min(until.saturating_duration_since(Instant::now())),
                        )
                        .await;
                    }
                }
                None => tokio::time::sleep_until(until).await,
            }
        }
    }

    async fn mark(&self, account: &str, name: &str, error: Option<&str>) -> sqlx::Result<()> {
        let mut conn = self.pool.acquire().await?;
        writes::mark_loop_run(&mut conn, account, name, None, error).await
    }

    async fn record_auth_error(&self, account: &str, reason: &str) -> sqlx::Result<()> {
        let mut conn = self.pool.acquire().await?;
        writes::record_auth_error(&mut conn, account, reason).await
    }

    async fn save_cookies(&mut self) -> sqlx::Result<()> {
        if !self.web.rotated {
            return Ok(());
        }
        let mut conn = self.pool.acquire().await?;
        session::save(&mut conn, &self.settings.account, &self.web.jar).await?;
        self.web.rotated = false;
        Ok(())
    }

    async fn pass(&mut self) -> Result<(Tally, Socket), PassError> {
        let settings = self.settings.clone();
        let account = settings.account.as_str();
        let mut tally = Tally::default();
        let mut collector = Collector::new(account);

        let config = self.web.page_with_retries().await?;
        if let Some(cat) = &config.crypto_auth_token {
            self.cat.send_replace(Some(cat.clone()));
        }
        self.save_cookies().await?;
        {
            let mut conn = self.pool.acquire().await?;
            let me = Account {
                id: account.to_owned(),
                fb_user_id: config.user_id.clone(),
                username: None,
                enabled: true,
            };
            writes::upsert_account(&mut conn, &me).await?;
            writes::clear_auth_error(&mut conn, account).await?;
        }

        // Both stores: the encrypted one's threads are never in the inbox listing.
        let mut cursors = Vec::new();
        for group in [collect::SYNC_GROUP_INBOX, collect::SYNC_GROUP_E2EE] {
            let Some(preloader) = config
                .preloaders
                .iter()
                .find(|p| p.database == u32::from(group))
            else {
                tracing::warn!("the page has no snapshot preloader for database {group}");
                continue;
            };
            let steps = self.web.snapshot(&config, preloader).await?;
            collector.feed(Some(group), &steps);
            match ls::sync_cursor(&steps) {
                Some(cursor) => cursors.push(cursor),
                None if group == collect::SYNC_GROUP_INBOX => {
                    return Err(PassError::Other(format!(
                        "the inbox snapshot carried no sync cursor (blocks {:?})",
                        ls::sync_block_shapes(&steps)
                    )));
                }
                None => {}
            }
        }
        self.save_cookies().await?;
        tally.threads = collector.threads.len() + collector.e2ee_keys.len();
        tally.new_messages += persist(&self.pool, &collector).await?;
        collector.clear_directory();
        self.mark(account, "threads", None).await?;

        let before = self.web.jar.clone();
        let mut socket = Socket::connect(&config, &mut self.web.jar).await?;
        self.web.rotated |= self.web.jar != before;
        let walked = walk(
            &self.pool,
            &mut socket,
            &settings,
            &mut self.budget,
            &mut collector,
            &cursors,
            &mut tally,
        )
        .await;
        match walked {
            Ok(()) => Ok((tally, socket)),
            Err(e) => {
                socket.close().await;
                Err(e)
            }
        }
    }
}
