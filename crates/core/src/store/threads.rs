//! `thread`: the conversation listing.

use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;

use crate::models::ThreadRow;

/// Conversations, most recently active first.
///
/// `since` narrows to threads that moved after that instant *and* counts only what
/// arrived after it, which is what makes "what did I miss" one call rather than one per
/// thread.
///
/// The `CROSS JOIN LATERAL` is load-bearing: it counts distinct rendered lines so a
/// thread whose text came off the client's screen is not reported as holding no text.
/// Without it a walked thread listed as "metadata only, no text" beside the lines the
/// capture had already read — a bug this listing had and must not get back.
pub async fn list_threads(
    pool: &PgPool,
    account: Option<&str>,
    since: Option<DateTime<Utc>>,
    is_group: Option<bool>,
    limit: i64,
) -> Result<Vec<ThreadRow>, sqlx::Error> {
    sqlx::query_as::<_, ThreadRow>(concat!(
        "
        SELECT t.account_id, t.thread_key, t.title, t.is_group, t.sync_group,
               t.last_activity_at, t.history_done,
               -- Whether this conversation holds any text at all, which is not the
               -- same as which store it was filed under.
               (",
        thread_has_no_text!(),
        ") AND r.lines = 0 AS has_no_text,
               -- Selected so a reader can see the difference between \"nothing has
               -- happened\" and \"something happened and we did not capture it\". The
               -- two are indistinguishable from `last_activity_at` alone, which is
               -- what makes a stale thread look current.
               GREATEST(t.newest_seen_at, r.newest) AS newest_seen_at,
               -- Beside `message_count`, not added to it: a rendered line and an
               -- envelope can be the same message, so a sum would count it twice.
               r.lines AS rendered_lines,
               (SELECT count(*) FROM message m
                 WHERE m.account_id = t.account_id AND m.thread_key = t.thread_key
                   AND ",
        is_a_message!(),
        "
                   AND ($2::timestamptz IS NULL OR m.ts > $2)) AS message_count,
               -- Who is in it, excluding the account holder: for a DM this is the one
               -- name that makes an otherwise \"(untitled)\" row identifiable, and for
               -- a group it is the members in order of who spoke last.
               (SELECT array_agg(COALESCE(p.name, p.username, tp.fb_user_id)
                                 ORDER BY tp.last_spoke_at DESC NULLS LAST)
                  FROM thread_participant tp
                  LEFT JOIN participant p
                         ON p.account_id = tp.account_id AND p.fb_user_id = tp.fb_user_id
                  LEFT JOIN account a ON a.id = tp.account_id
                 WHERE tp.account_id = t.account_id AND tp.thread_key = t.thread_key
                   AND (a.fb_user_id IS NULL OR tp.fb_user_id <> a.fb_user_id)
               ) AS counterparts,
               ",
        total_matches!(),
        "
          FROM thread t
          CROSS JOIN LATERAL (
               SELECT count(DISTINCT (d.ts, d.text, d.sender_label)) AS lines, max(d.ts) AS newest
                 FROM dom_capture c JOIN dom_message d ON d.capture_id = c.id
                WHERE c.account_id = t.account_id AND c.thread_key = t.thread_key
                  AND d.ts IS NOT NULL
          ) r
         WHERE ($1::text IS NULL OR t.account_id = $1)
           AND ($2::timestamptz IS NULL OR t.last_activity_at > $2)
           AND ($3::boolean IS NULL OR t.is_group = $3)
         ORDER BY t.last_activity_at DESC NULLS LAST, t.thread_key
         LIMIT $4
        "
    ))
    .bind(account)
    .bind(since)
    .bind(is_group)
    .bind(limit)
    .fetch_all(pool)
    .await
}
