//! `account` and `sync_state`: what is archived and whether the client is well.

use sqlx::postgres::PgPool;

use crate::models::{AccountStatus, LoopRow};

/// Per account: how much is stored, how much history is still owed, session health.
///
/// `textless_threads` and `textless_messages` both subtract what the retired DOM capture
/// read off the client's screen: a thread whose words came from a rendering is not one that holds
/// no text, however many empty envelopes sit beside them.
pub async fn account_status(pool: &PgPool) -> Result<Vec<AccountStatus>, sqlx::Error> {
    sqlx::query_as::<_, AccountStatus>(concat!(
        "
        SELECT a.id AS account_id, a.username, a.enabled,
               a.last_auth_error, a.last_auth_error_at,
               (SELECT count(*) FROM thread t WHERE t.account_id = a.id) AS threads,
               (SELECT count(*) FROM thread t
                 WHERE t.account_id = a.id
                   AND (",
        thread_has_no_text!(),
        ")
                   AND NOT (",
        has_rendered_lines!("t"),
        ")) AS textless_threads,
               (SELECT count(*) FROM message m
                 WHERE m.account_id = a.id AND ",
        is_a_message!(),
        "
                   AND m.text IS NULL AND NOT (",
        has_rendered_lines!("m"),
        ")) AS textless_messages,
               (SELECT count(*) FROM thread t
                 WHERE t.account_id = a.id AND NOT t.history_done) AS threads_pending_history,
               (SELECT count(*) FROM message m
                 WHERE m.account_id = a.id AND ",
        is_a_message!(),
        ") AS messages,
               (SELECT count(*) FROM message m
                 WHERE m.account_id = a.id AND NOT (",
        is_a_message!(),
        ")) AS system_events,
               (SELECT count(*) FROM participant p WHERE p.account_id = a.id) AS participants,
               (SELECT min(m.ts) FROM message m
                 WHERE m.account_id = a.id AND ",
        is_a_message!(),
        ") AS oldest_message_at,
               (SELECT max(m.ts) FROM message m
                 WHERE m.account_id = a.id AND ",
        is_a_message!(),
        ") AS newest_message_at
          FROM account a
         ORDER BY a.id
        "
    ))
    .fetch_all(pool)
    .await
}

pub async fn sync_loops(pool: &PgPool) -> Result<Vec<LoopRow>, sqlx::Error> {
    sqlx::query_as::<_, LoopRow>(
        "
        SELECT account_id, loop, current_thread_key, last_run_at, last_error, last_error_at
          FROM sync_state
         ORDER BY account_id, loop
        ",
    )
    .fetch_all(pool)
    .await
}
