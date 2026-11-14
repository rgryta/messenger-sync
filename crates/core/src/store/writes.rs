//! The client's writes: what a pass stores, and the crawl state that steers the next.
//!
//! Ported statement for statement from the retired Python `store.py`, and checked against
//! its recorded output by `tests/archive/writes.rs`, which replays one script of writes and
//! compares every table. Each function takes a connection rather than the pool because
//! the client writes a whole pass inside one transaction, parents before children
//! (`persist` in `crates/client/src/collect.rs`).
//!
//! The batch writers run one statement per row inside a transaction, as asyncpg's
//! `executemany` does, rather than one multi-row statement: a multi-row `ON CONFLICT DO
//! UPDATE` refuses a batch that names the same key twice, and one pass can.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sqlx::{Connection, PgConnection, Postgres, QueryBuilder};

use crate::models::{
    Account, Attachment, ForwardTarget, HistoryTarget, Member, Message, Participant, Reaction,
    Thread,
};

const INSERT_CHUNK: usize = 500;

type Span = (DateTime<Utc>, DateTime<Utc>);

/// `last_auth_error` is deliberately absent from the UPDATE clause: it is written when a
/// session dies, and a routine refresh must not erase it.
pub async fn upsert_account(conn: &mut PgConnection, account: &Account) -> sqlx::Result<()> {
    sqlx::query(
        "
        INSERT INTO account (id, fb_user_id, username, enabled, updated_at)
        VALUES ($1, $2, $3, $4, now())
        ON CONFLICT (id) DO UPDATE SET
          fb_user_id = EXCLUDED.fb_user_id,
          username   = COALESCE(EXCLUDED.username, account.username),
          enabled    = EXCLUDED.enabled,
          updated_at = now()
        ",
    )
    .bind(&account.id)
    .bind(&account.fb_user_id)
    .bind(&account.username)
    .bind(account.enabled)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn record_auth_error(
    conn: &mut PgConnection,
    account_id: &str,
    error: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE account SET last_auth_error = $2, last_auth_error_at = now() WHERE id = $1",
    )
    .bind(account_id)
    .bind(error)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn clear_auth_error(conn: &mut PgConnection, account_id: &str) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE account SET last_auth_error = NULL, last_auth_error_at = NULL WHERE id = $1",
    )
    .bind(account_id)
    .execute(conn)
    .await?;
    Ok(())
}

/// Names arrive from several instructions and not all carry both fields, so each is
/// COALESCEd: the thinner payload never blanks what the richer one stored.
pub async fn upsert_participants(
    conn: &mut PgConnection,
    participants: &[Participant],
) -> sqlx::Result<()> {
    if participants.is_empty() {
        return Ok(());
    }
    let mut tx = conn.begin().await?;
    for p in participants {
        sqlx::query(
            "
            INSERT INTO participant (account_id, fb_user_id, name, username, profile_pic_url,
                                     updated_at)
            VALUES ($1, $2, $3, $4, $5, now())
            ON CONFLICT (account_id, fb_user_id) DO UPDATE SET
              name            = COALESCE(EXCLUDED.name, participant.name),
              username        = COALESCE(EXCLUDED.username, participant.username),
              profile_pic_url = COALESCE(EXCLUDED.profile_pic_url, participant.profile_pic_url),
              updated_at      = now()
            ",
        )
        .bind(&p.account_id)
        .bind(&p.fb_user_id)
        .bind(&p.name)
        .bind(&p.username)
        .bind(&p.profile_pic_url)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

/// Insert or refresh a thread without touching crawl state.
///
/// `oldest_seen_at` and `history_done` belong to the history loop and are never written
/// here: assigning them across would rewind a crawl on every pass.
pub async fn upsert_thread(conn: &mut PgConnection, thread: &Thread) -> sqlx::Result<()> {
    sqlx::query(
        "
        INSERT INTO thread (account_id, thread_key, sync_group, title, is_group,
                            last_activity_at, raw)
        VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
        ON CONFLICT (account_id, thread_key) DO UPDATE SET
          sync_group       = EXCLUDED.sync_group,
          title            = COALESCE(EXCLUDED.title, thread.title),
          is_group         = EXCLUDED.is_group OR thread.is_group,
          last_activity_at = GREATEST(EXCLUDED.last_activity_at, thread.last_activity_at),
          raw              = CASE WHEN EXCLUDED.raw = '{}'::jsonb THEN thread.raw
                                  ELSE EXCLUDED.raw END
        ",
    )
    .bind(&thread.account_id)
    .bind(&thread.thread_key)
    .bind(thread.sync_group)
    .bind(&thread.title)
    .bind(thread.is_group)
    .bind(thread.last_activity_at)
    .bind(&thread.raw)
    .execute(conn)
    .await?;
    Ok(())
}

/// Record a thread we only know the key of. Encrypted threads are announced by key
/// alone, and without the row the first message of one would violate the foreign key.
pub async fn note_thread_seen(
    conn: &mut PgConnection,
    account_id: &str,
    thread_key: &str,
    sync_group: i32,
) -> sqlx::Result<()> {
    sqlx::query(
        "
        INSERT INTO thread (account_id, thread_key, sync_group)
        VALUES ($1, $2, $3)
        ON CONFLICT (account_id, thread_key) DO NOTHING
        ",
    )
    .bind(account_id)
    .bind(thread_key)
    .bind(sync_group)
    .execute(conn)
    .await?;
    Ok(())
}

/// Membership as Meta states it: marked `from_roster`, and never downgraded by a later
/// speech-derived write, because the two carry different weight.
pub async fn record_thread_members(
    conn: &mut PgConnection,
    members: &[Member],
) -> sqlx::Result<u64> {
    if members.is_empty() {
        return Ok(0);
    }
    let mut tx = conn.begin().await?;
    for m in members {
        sqlx::query(
            "
            INSERT INTO thread_participant (account_id, thread_key, fb_user_id,
                                            joined_at, is_admin, from_roster)
            VALUES ($1, $2, $3, $4::timestamptz, $5::boolean, true)
            ON CONFLICT (account_id, thread_key, fb_user_id) DO UPDATE SET
              joined_at   = COALESCE(EXCLUDED.joined_at, thread_participant.joined_at),
              is_admin    = EXCLUDED.is_admin OR thread_participant.is_admin,
              from_roster = true
            ",
        )
        .bind(&m.account_id)
        .bind(&m.thread_key)
        .bind(&m.fb_user_id)
        .bind(m.joined_at)
        .bind(m.is_admin)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(members.len() as u64)
}

/// One reaction per person per message. Upserted, unlike a message: a person can change
/// the emoji, so the latest delivery wins.
pub async fn insert_reactions(
    conn: &mut PgConnection,
    reactions: &[Reaction],
) -> sqlx::Result<u64> {
    if reactions.is_empty() {
        return Ok(0);
    }
    let mut tx = conn.begin().await?;
    for r in reactions {
        sqlx::query(
            "
            INSERT INTO message_reaction (account_id, thread_key, message_id, actor_id,
                                          emoji, reacted_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (account_id, thread_key, message_id, actor_id) DO UPDATE SET
              emoji      = EXCLUDED.emoji,
              reacted_at = GREATEST(EXCLUDED.reacted_at, message_reaction.reacted_at)
            ",
        )
        .bind(&r.account_id)
        .bind(&r.thread_key)
        .bind(&r.message_id)
        .bind(&r.actor_id)
        .bind(&r.emoji)
        .bind(r.reacted_at)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(reactions.len() as u64)
}

/// Attachments, keyed by whichever identifier the instruction carried. Returns how many
/// had one.
pub async fn insert_attachments(
    conn: &mut PgConnection,
    attachments: &[Attachment],
) -> sqlx::Result<u64> {
    // Nothing stable to key on: dropping it beats inventing a key that would duplicate
    // the row on every re-read of the range.
    let keyed: Vec<(&Attachment, &str)> = attachments
        .iter()
        .filter_map(|a| {
            let key = [&a.attachment_id, &a.url]
                .into_iter()
                .flatten()
                .find(|key| !key.is_empty())?;
            Some((a, key.as_str()))
        })
        .collect();
    if keyed.is_empty() {
        return Ok(0);
    }
    let mut tx = conn.begin().await?;
    for (a, key) in &keyed {
        sqlx::query(
            "
            INSERT INTO message_attachment (account_id, thread_key, message_id,
                                            attachment_key, kind, mime_type, url,
                                            preview_url, raw)
            VALUES ($1, $2, $3, $4, $5, $6::text, $7::text, $8::text, $9::jsonb)
            ON CONFLICT (account_id, thread_key, message_id, attachment_key) DO UPDATE SET
              mime_type   = COALESCE(EXCLUDED.mime_type, message_attachment.mime_type),
              url         = COALESCE(EXCLUDED.url, message_attachment.url),
              preview_url = COALESCE(EXCLUDED.preview_url, message_attachment.preview_url)
            ",
        )
        .bind(&a.account_id)
        .bind(&a.thread_key)
        .bind(&a.message_id)
        .bind(key)
        .bind(&a.kind)
        .bind(&a.mime_type)
        .bind(&a.url)
        .bind(&a.preview_url)
        .bind(&a.raw)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(keyed.len() as u64)
}

/// Note who spoke in each thread, from the messages just decoded: the earliest and
/// latest message per sender, widened onto what is stored. Derived rather than
/// declared, so a member who never spoke in the window we hold does not appear.
pub async fn record_thread_participants(
    conn: &mut PgConnection,
    messages: &[Message],
) -> sqlx::Result<()> {
    // (account, thread, sender) -> (first, last)
    let mut seen: HashMap<(&str, &str, &str), Span> = HashMap::new();
    for m in messages {
        let Some(sender) = m.sender_id.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };
        seen.entry((&m.account_id, &m.thread_key, sender))
            .and_modify(|(first, last)| {
                *first = (*first).min(m.ts);
                *last = (*last).max(m.ts);
            })
            .or_insert((m.ts, m.ts));
    }
    if seen.is_empty() {
        return Ok(());
    }
    let mut tx = conn.begin().await?;
    for ((account_id, thread_key, sender), (first, last)) in seen {
        sqlx::query(
            "
            INSERT INTO thread_participant (account_id, thread_key, fb_user_id,
                                            first_spoke_at, last_spoke_at)
            VALUES ($1, $2, $3, $4::timestamptz, $5::timestamptz)
            ON CONFLICT (account_id, thread_key, fb_user_id) DO UPDATE SET
              first_spoke_at = LEAST(thread_participant.first_spoke_at, EXCLUDED.first_spoke_at),
              last_spoke_at  = GREATEST(thread_participant.last_spoke_at, EXCLUDED.last_spoke_at)
            ",
        )
        .bind(account_id)
        .bind(thread_key)
        .bind(sender)
        .bind(first)
        .bind(last)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

/// Store messages, returning how many rows were genuinely new.
///
/// Insert-only: a stored message is never rewritten, since Messenger re-delivers it on
/// every overlapping range. The count is what the database inserted, not
/// `messages.len()`: it is how the history loop learns the crawl has met itself.
///
/// An encrypted envelope whose OTID is already stored is skipped: the client's own device
/// decrypted that message first and stored it under the OTID (`store::e2ee`). So is one
/// carrying the OTID of an unsend already applied, which is how LightSpeed re-issues an
/// unsent message.
pub async fn insert_messages(conn: &mut PgConnection, messages: &[Message]) -> sqlx::Result<u64> {
    let mut total = 0;
    for chunk in messages.chunks(INSERT_CHUNK) {
        let mut insert = QueryBuilder::<Postgres>::new(
            "
            WITH new_rows AS (
                INSERT INTO message (account_id, thread_key, message_id, ts, sender_id, text,
                                     item_type, reply_to_id, attachments, sync_group, raw)
                SELECT * FROM (
                ",
        );
        insert.push_values(chunk, |mut row, m| {
            row.push_bind(&m.account_id)
                .push_bind(&m.thread_key)
                .push_bind(&m.message_id)
                .push_bind(m.ts)
                .push_bind(&m.sender_id)
                .push_bind(&m.text)
                .push_bind(&m.item_type)
                .push_bind(&m.reply_to_id)
                .push_bind(&m.attachments)
                .push_unseparated("::jsonb")
                .push_bind(m.sync_group)
                .push_bind(&m.raw)
                .push_unseparated("::jsonb");
        });
        insert.push(
            "
                ) AS v (account_id, thread_key, message_id, ts, sender_id, text, item_type,
                        reply_to_id, attachments, sync_group, raw)
                WHERE v.sync_group <> 95 OR NOT EXISTS (
                  SELECT 1 FROM message m
                   WHERE m.account_id = v.account_id AND m.thread_key = v.thread_key
                     AND m.otid = v.raw->'op'->>11)
                  AND NOT EXISTS (
                  SELECT 1 FROM message m
                   WHERE m.account_id = v.account_id AND m.thread_key = v.thread_key
                     AND m.raw ? 'unsent_by'
                     AND m.raw->>'unsent_by' = v.raw->'op'->>11)
                ON CONFLICT (account_id, thread_key, message_id) DO NOTHING
                RETURNING 1
            )
            SELECT count(*) FROM new_rows
            ",
        );
        let inserted: i64 = insert.build_query_scalar().fetch_one(&mut *conn).await?;
        total += inserted as u64;
    }
    Ok(total)
}

/// NULL and '' are the same absence of text, and neither is an edit (`_same_text`).
fn same_text(a: Option<&str>, b: Option<&str>) -> bool {
    a.unwrap_or_default() == b.unwrap_or_default()
}

/// Record that a stored message now reads differently, and update it. Idempotent; returns
/// whether anything changed. `record_revision` in the Python `store.py`: a first sighting is not an
/// edit, the first revision keeps the old text with no start time, and the message row is
/// locked so the log can never contradict the message it describes.
pub async fn record_revision(
    conn: &mut PgConnection,
    account_id: &str,
    thread_key: &str,
    message_id: &str,
    text: Option<&str>,
) -> sqlx::Result<bool> {
    let mut tx = conn.begin().await?;
    let current: Option<(Option<String>,)> = sqlx::query_as(
        "
        SELECT text FROM message
         WHERE account_id = $1 AND thread_key = $2 AND message_id = $3 FOR UPDATE
        ",
    )
    .bind(account_id)
    .bind(thread_key)
    .bind(message_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((current,)) = current else {
        return Ok(false);
    };
    if same_text(current.as_deref(), text) {
        return Ok(false);
    }
    let mut seq: i32 = sqlx::query_scalar(
        "
        SELECT coalesce(max(seq), 0) FROM message_revision
         WHERE account_id = $1 AND thread_key = $2 AND message_id = $3
        ",
    )
    .bind(account_id)
    .bind(thread_key)
    .bind(message_id)
    .fetch_one(&mut *tx)
    .await?;
    if seq == 0 {
        sqlx::query(
            "
            INSERT INTO message_revision
                   (account_id, thread_key, message_id, seq, text, first_seen_at, superseded_at)
            VALUES ($1, $2, $3, 1, $4::text, NULL, now())
            ",
        )
        .bind(account_id)
        .bind(thread_key)
        .bind(message_id)
        .bind(&current)
        .execute(&mut *tx)
        .await?;
        seq = 1;
    } else {
        sqlx::query(
            "
            UPDATE message_revision SET superseded_at = now()
             WHERE account_id = $1 AND thread_key = $2 AND message_id = $3
               AND superseded_at IS NULL
            ",
        )
        .bind(account_id)
        .bind(thread_key)
        .bind(message_id)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "
        INSERT INTO message_revision
               (account_id, thread_key, message_id, seq, text, first_seen_at, superseded_at)
        VALUES ($1, $2, $3, $4, $5::text, now(), NULL)
        ",
    )
    .bind(account_id)
    .bind(thread_key)
    .bind(message_id)
    .bind(seq + 1)
    .bind(text)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "
        UPDATE message SET text = $4::text
         WHERE account_id = $1 AND thread_key = $2 AND message_id = $3
        ",
    )
    .bind(account_id)
    .bind(thread_key)
    .bind(message_id)
    .bind(text)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// A message's new text from LightSpeed's `editMessage`, which names no thread: the
/// message is found by id, and the old text kept as a revision. Returns whether anything
/// changed; an edit of a message the archive does not hold is dropped.
pub async fn apply_edit(
    conn: &mut PgConnection,
    account_id: &str,
    message_id: &str,
    text: &str,
) -> sqlx::Result<bool> {
    let thread: Option<String> = sqlx::query_scalar(
        "SELECT thread_key FROM message WHERE account_id = $1 AND message_id = $2 LIMIT 1",
    )
    .bind(account_id)
    .bind(message_id)
    .fetch_optional(&mut *conn)
    .await?;
    match thread {
        Some(thread) => record_revision(conn, account_id, &thread, message_id, Some(text)).await,
        None => Ok(false),
    }
}

/// An unsend from LightSpeed: the message is marked deleted, its text kept. `at` is when,
/// if LightSpeed said; else now.
pub async fn mark_unsent(
    conn: &mut PgConnection,
    account_id: &str,
    thread_key: &str,
    message_id: &str,
    at: Option<DateTime<Utc>>,
) -> sqlx::Result<bool> {
    let marked = sqlx::query(
        "
        UPDATE message SET deleted_at = COALESCE($4, now())
         WHERE account_id = $1 AND thread_key = $2 AND message_id = $3
           AND deleted_at IS NULL
        ",
    )
    .bind(account_id)
    .bind(thread_key)
    .bind(message_id)
    .bind(at)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(marked > 0)
}

/// Advance (never rewind) how far back a thread has been paged.
pub async fn set_history_progress(
    conn: &mut PgConnection,
    account_id: &str,
    thread_key: &str,
    oldest_seen_at: Option<DateTime<Utc>>,
    done: bool,
) -> sqlx::Result<()> {
    sqlx::query(
        "
        UPDATE thread
           SET oldest_seen_at = LEAST(COALESCE($3, oldest_seen_at),
                                      COALESCE(oldest_seen_at, $3)),
               history_done    = $4 OR history_done,
               last_harvest_at = now()
         WHERE account_id = $1 AND thread_key = $2
        ",
    )
    .bind(account_id)
    .bind(thread_key)
    .bind(oldest_seen_at)
    .bind(done)
    .execute(conn)
    .await?;
    Ok(())
}

/// Advance (never rewind) the newest message held for a thread, and which activity
/// report the walk answered.
///
/// `answered_activity_at` is the `last_activity_at` the walk was selected on, read
/// before the walk: stamping the current value would swallow a message that arrived
/// while the pages were in flight.
pub async fn set_forward_progress(
    conn: &mut PgConnection,
    account_id: &str,
    thread_key: &str,
    newest_seen_at: Option<DateTime<Utc>>,
    answered_activity_at: Option<DateTime<Utc>>,
) -> sqlx::Result<()> {
    sqlx::query(
        "
        UPDATE thread
           SET newest_seen_at = GREATEST(COALESCE($3, newest_seen_at),
                                         COALESCE(newest_seen_at, $3)),
               forward_attempted_activity_at =
                 GREATEST(COALESCE($4::timestamptz, forward_attempted_activity_at),
                          COALESCE(forward_attempted_activity_at, $4::timestamptz)),
               last_harvest_at = now()
         WHERE account_id = $1 AND thread_key = $2
        ",
    )
    .bind(account_id)
    .bind(thread_key)
    .bind(newest_seen_at)
    .bind(answered_activity_at)
    .execute(conn)
    .await?;
    Ok(())
}

/// Threads that have moved since we last read them: the listing is ahead of what we
/// hold, and of the activity report the last walk answered.
///
/// The second test is what stops a thread from qualifying forever: in the encrypted
/// store the listing's clock runs a little ahead of the newest message, so a thread
/// holding everything still looked behind on every pass. Deliberately not filtered on
/// `history_done`, which says nothing about new messages.
pub async fn threads_with_new_activity(
    conn: &mut PgConnection,
    account_id: &str,
    limit: i64,
) -> sqlx::Result<Vec<ForwardTarget>> {
    sqlx::query_as(
        "
        SELECT thread_key, sync_group, newest_seen_at, last_activity_at, title
          FROM thread
         WHERE account_id = $1
           AND last_activity_at IS NOT NULL
           AND (newest_seen_at IS NULL OR last_activity_at > newest_seen_at)
           AND (forward_attempted_activity_at IS NULL
                OR last_activity_at > forward_attempted_activity_at)
         ORDER BY last_activity_at DESC
         LIMIT $2
        ",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(conn)
    .await
}

/// Clear `history_done` so the backward crawl visits a thread (or every thread) again.
/// Returns how many were cleared.
///
/// The flag is monotonic in normal operation, but it was once set on evidence that
/// could not tell "no more history" from "the reply did not arrive in time", and
/// nothing else ever clears it.
pub async fn reopen_history(
    conn: &mut PgConnection,
    account_id: &str,
    thread_key: Option<&str>,
) -> sqlx::Result<u64> {
    let reopened = match thread_key {
        None => {
            sqlx::query(
                "UPDATE thread SET history_done = false WHERE account_id = $1 AND history_done",
            )
            .bind(account_id)
            .execute(conn)
            .await?
        }
        Some(thread_key) => {
            sqlx::query(
                "
                UPDATE thread SET history_done = false
                 WHERE account_id = $1 AND thread_key = $2 AND history_done
                ",
            )
            .bind(account_id)
            .bind(thread_key)
            .execute(conn)
            .await?
        }
    };
    Ok(reopened.rows_affected())
}

/// Least recently visited first, so no thread starves behind a busy one.
pub async fn threads_needing_history(
    conn: &mut PgConnection,
    account_id: &str,
    limit: i64,
) -> sqlx::Result<Vec<HistoryTarget>> {
    sqlx::query_as(
        "
        SELECT thread_key, sync_group, oldest_seen_at, title
          FROM thread
         WHERE account_id = $1 AND NOT history_done
         ORDER BY last_harvest_at NULLS FIRST, last_activity_at DESC NULLS LAST
         LIMIT $2
        ",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(conn)
    .await
}

pub async fn mark_loop_run(
    conn: &mut PgConnection,
    account_id: &str,
    loop_name: &str,
    thread_key: Option<&str>,
    error: Option<&str>,
) -> sqlx::Result<()> {
    sqlx::query(
        "
        INSERT INTO sync_state (account_id, loop, current_thread_key, last_run_at,
                                last_error, last_error_at)
        -- `$4::text`: the second use is a bare `IS NULL` test, which gives the planner no
        -- column to infer the parameter's type from.
        VALUES ($1, $2, $3::text, now(), $4::text,
                CASE WHEN $4::text IS NULL THEN NULL ELSE now() END)
        ON CONFLICT (account_id, loop) DO UPDATE SET
          current_thread_key = EXCLUDED.current_thread_key,
          last_run_at        = now(),
          last_error         = EXCLUDED.last_error,
          -- Not COALESCEd onto the old value: a success clears `last_error`, and keeping
          -- the time would leave the row claiming an error that is not there.
          last_error_at      = EXCLUDED.last_error_at
        ",
    )
    .bind(account_id)
    .bind(loop_name)
    .bind(thread_key)
    .bind(error)
    .execute(conn)
    .await?;
    Ok(())
}
