//! `message` plus `dom_message`: one page of a conversation, its size, and the search.

use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;

use crate::models::{HistoryRow, SearchHit};

/// The window `get_history` pages through: envelopes and rendered lines together.
///
/// Two statements built from it, not one with a computed direction, because no caller
/// value may reach the SQL text.
///
/// With `after` the page is the *oldest* `limit` rows after it: a caller who names a
/// start wants to read forward from there, and handing back the end of the period
/// instead reads as though everything before it were missing. Without `after` it is the
/// newest `limit`, so opening a thread shows what is going on now rather than the day it
/// began; `before` walks back from there.
macro_rules! history_window {
    () => {
        concat!(
            "
        SELECT m.account_id, m.thread_key, m.message_id, m.ts, m.sender_id, m.text,
               m.item_type, m.sync_group, m.reply_to_id, m.deleted_at,
               -- Derived, never stored: \"was this edited\" is exactly \"is there a
               -- history of it\", so a column saying so could drift from the rows it
               -- describes.
               EXISTS (SELECT 1 FROM message_revision v
                        WHERE v.account_id = m.account_id AND v.thread_key = m.thread_key
                          AND v.message_id = m.message_id) AS edited,
               p.name AS sender_name, p.username AS sender_username,
               -- Reactions as \"thumbs-up x3, heart\", newest first. An archive that
               -- stored them and never showed them would be no better than one that
               -- dropped them.
               (SELECT string_agg(e.label, ', ' ORDER BY e.n DESC)
                  FROM (SELECT r.emoji ||
                               CASE WHEN count(*) > 1 THEN '\u{d7}' || count(*) ELSE '' END AS label,
                               count(*) AS n
                          FROM message_reaction r
                         WHERE r.account_id = m.account_id AND r.thread_key = m.thread_key
                           AND r.message_id = m.message_id
                         GROUP BY r.emoji) e) AS reactions,
               -- What is attached, by type. The URLs are Meta CDN links that expire,
               -- so the useful thing to show is that media exists and what it is.
               (SELECT string_agg(DISTINCT COALESCE(a.mime_type, a.kind), ', ')
                  FROM message_attachment a
                 WHERE a.account_id = m.account_id AND a.thread_key = m.thread_key
                   AND a.message_id = m.message_id) AS attachments,
               ",
            total_matches!(),
            "
          FROM message m
          LEFT JOIN participant p
            ON p.account_id = m.account_id AND p.fb_user_id = m.sender_id
         WHERE m.thread_key = $1
           AND ($2::text IS NULL OR m.account_id = $2)
           AND ($3::timestamptz IS NULL OR m.ts < $3)
           AND ($4::timestamptz IS NULL OR m.ts > $4)

        UNION ALL

        -- The words of an encrypted conversation. A row here is what the client drew,
        -- not what the protocol delivered, which is why it has no message id and no
        -- sender id: `item_type` says `rendered` so the renderer can say so too.
        -- Dated rows only - an undated one cannot be placed in this window at all.
        SELECT d.account_id, d.thread_key, NULL::text, d.ts, NULL::text, d.text,
               'rendered'::text, NULL::integer, NULL::text, NULL::timestamptz,
               false,
               d.sender_label, NULL::text,
               NULL::text, NULL::text,
               ",
            total_matches!(),
            "
          FROM (",
            rendered_lines!(),
            ") d
         WHERE d.thread_key = $1
           AND ($2::text IS NULL OR d.account_id = $2)
           AND ($3::timestamptz IS NULL OR d.ts < $3)
           AND ($4::timestamptz IS NULL OR d.ts > $4)

"
        )
    };
}

const HISTORY_FROM_OLDEST: &str = concat!(history_window!(), "ORDER BY ts LIMIT $5");
const HISTORY_NEWEST: &str = concat!(history_window!(), "ORDER BY ts DESC LIMIT $5");

/// A page of a window, handed back oldest first. See [`history_window`] for which page.
///
/// [`count_history`] says how many rows the same window holds in all.
///
/// Rendered lines are in here too, as rows of their own with `item_type = 'rendered'`.
/// They are the only place an encrypted conversation's words exist, so keeping them
/// behind a second tool meant the obvious question — "show me this conversation" — had
/// the wrong answer for every DM. They are NOT joined to the envelopes and never will
/// be: they carry no message id, and their clock is minute-precise, so two messages from
/// one person inside a minute are indistinguishable. Both appear, ordered by time, and
/// the renderer says which is which.
pub async fn get_history(
    pool: &PgPool,
    thread_key: &str,
    account: Option<&str>,
    before: Option<DateTime<Utc>>,
    after: Option<DateTime<Utc>>,
    limit: i64,
) -> Result<Vec<HistoryRow>, sqlx::Error> {
    let forward = after.is_some();
    let sql = if forward {
        HISTORY_FROM_OLDEST
    } else {
        HISTORY_NEWEST
    };
    let mut rows = sqlx::query_as::<_, HistoryRow>(sql)
        .bind(thread_key)
        .bind(account)
        .bind(before)
        .bind(after)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    if !forward {
        // The newest page is fetched descending and reversed here: the caller always
        // reads oldest first.
        rows.reverse();
    }
    Ok(rows)
}

/// Every row in the window [`get_history`] pages through, rendered lines included.
pub async fn count_history(
    pool: &PgPool,
    thread_key: &str,
    account: Option<&str>,
    before: Option<DateTime<Utc>>,
    after: Option<DateTime<Utc>>,
) -> Result<i64, sqlx::Error> {
    let total: Option<i64> = sqlx::query_scalar(concat!(
        "
        SELECT (SELECT count(*) FROM message m
                 WHERE m.thread_key = $1
                   AND ($2::text IS NULL OR m.account_id = $2)
                   AND ($3::timestamptz IS NULL OR m.ts < $3)
                   AND ($4::timestamptz IS NULL OR m.ts > $4))
             + (SELECT count(*) FROM (",
        rendered_lines!(),
        ") d
                 WHERE d.thread_key = $1
                   AND ($2::text IS NULL OR d.account_id = $2)
                   AND ($3::timestamptz IS NULL OR d.ts < $3)
                   AND ($4::timestamptz IS NULL OR d.ts > $4))
        "
    ))
    .bind(thread_key)
    .bind(account)
    .bind(before)
    .bind(after)
    .fetch_one(pool)
    .await?;
    Ok(total.unwrap_or(0))
}

/// Full-text search over stored text and rendered lines, best match first.
///
/// Deleted messages are excluded rather than returned withheld: a search hit is a
/// headline of the matching text, so returning one would print exactly what every other
/// view holds back, and a blank hit would be useless. The text stays reachable through
/// `revisions`.
///
/// `senders` cannot narrow rendered lines. A rendered row has a sender *label*, not an
/// id, so a person filter would have to match a display string — and a filter that
/// quietly matches differently per store is worse than one that declines. So when
/// `senders` is given, rendered lines are left out entirely.
// Eight arguments, because the query takes seven filters. A struct for them would be a
// struct with one caller, and the names would move from the call site into it.
#[allow(clippy::too_many_arguments)]
pub async fn search_messages(
    pool: &PgPool,
    query: &str,
    account: Option<&str>,
    thread_key: Option<&str>,
    senders: Option<&[String]>,
    before: Option<DateTime<Utc>>,
    after: Option<DateTime<Utc>>,
    limit: i64,
) -> Result<Vec<SearchHit>, sqlx::Error> {
    sqlx::query_as::<_, SearchHit>(concat!(
        "
        SELECT m.account_id, m.thread_key, m.message_id, m.ts, m.sender_id, m.text,
               m.item_type, t.title AS thread_title,
               p.name AS sender_name, p.username AS sender_username,
               ts_headline('simple', coalesce(m.text, ''),
                           websearch_to_tsquery('simple', $1)) AS headline,
               ts_rank(m.search, websearch_to_tsquery('simple', $1)) AS rank,
               ",
        total_matches!(),
        "
          FROM message m
          JOIN thread t ON t.account_id = m.account_id AND t.thread_key = m.thread_key
          LEFT JOIN participant p
            ON p.account_id = m.account_id AND p.fb_user_id = m.sender_id
         WHERE m.search @@ websearch_to_tsquery('simple', $1)
           AND m.deleted_at IS NULL
           AND ($2::text IS NULL OR m.account_id = $2)
           AND ($3::text IS NULL OR m.thread_key = $3)
           AND ($4::text[] IS NULL OR m.sender_id = ANY ($4))
           AND ($5::timestamptz IS NULL OR m.ts < $5)
           AND ($6::timestamptz IS NULL OR m.ts > $6)

        UNION ALL

        -- Rendered text, searched alongside. Without this, `search` silently missed
        -- every encrypted conversation: it matched only `message.search`, so the words
        -- the archive had worked hardest to get were the ones it could not find.
        SELECT d.account_id, d.thread_key, NULL::text, d.ts, NULL::text, d.text,
               'rendered'::text, t.title,
               d.sender_label, NULL::text,
               ts_headline('simple', coalesce(d.text, ''),
                           websearch_to_tsquery('simple', $1)),
               ts_rank(d.search, websearch_to_tsquery('simple', $1)),
               ",
        total_matches!(),
        "
          FROM (",
        rendered_lines!(),
        ") d
          JOIN thread t ON t.account_id = d.account_id AND t.thread_key = d.thread_key
         WHERE d.search @@ websearch_to_tsquery('simple', $1)
           AND $4::text[] IS NULL
           AND ($2::text IS NULL OR d.account_id = $2)
           AND ($3::text IS NULL OR d.thread_key = $3)
           AND ($5::timestamptz IS NULL OR d.ts < $5)
           AND ($6::timestamptz IS NULL OR d.ts > $6)

         ORDER BY rank DESC, ts DESC
         LIMIT $7
        "
    ))
    .bind(query)
    .bind(account)
    .bind(thread_key)
    .bind(senders)
    .bind(before)
    .bind(after)
    .bind(limit)
    .fetch_all(pool)
    .await
}
