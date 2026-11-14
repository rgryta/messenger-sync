//! `message_revision`: one message's text over time.
//!
//! The write side is `writes::record_revision`; the retired Python's deletion detection
//! (`mark_present`, `mark_absent` and friends) was never ported. Losing an edit is a
//! different kind of bug from losing a message, which is why it has a module of its own.

use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;

use crate::models::Revision;

/// What [`resolve_message`] found.
///
/// `NULL` alone cannot carry both answers and the tool words them differently: a message
/// nobody holds is not the same as one that is simply not deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deletion {
    /// No such message in that thread.
    Unknown,
    Deleted(DateTime<Utc>),
    NotDeleted,
}

pub async fn list_revisions(
    pool: &PgPool,
    account_id: &str,
    thread_key: &str,
    message_id: &str,
) -> Result<Vec<Revision>, sqlx::Error> {
    sqlx::query_as::<_, Revision>(
        "
        SELECT seq, text, first_seen_at, superseded_at FROM message_revision
         WHERE account_id = $1 AND thread_key = $2 AND message_id = $3 ORDER BY seq
        ",
    )
    .bind(account_id)
    .bind(thread_key)
    .bind(message_id)
    .fetch_all(pool)
    .await
}

/// `deleted_at` for one message, or [`Deletion::Unknown`] when the message is unknown.
pub async fn resolve_message(
    pool: &PgPool,
    account_id: &str,
    thread_key: &str,
    message_id: &str,
) -> Result<Deletion, sqlx::Error> {
    let row: Option<Option<DateTime<Utc>>> = sqlx::query_scalar(
        "
        SELECT deleted_at FROM message
         WHERE account_id = $1 AND thread_key = $2 AND message_id = $3
        ",
    )
    .bind(account_id)
    .bind(thread_key)
    .bind(message_id)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        None => Deletion::Unknown,
        Some(None) => Deletion::NotDeleted,
        Some(Some(at)) => Deletion::Deleted(at),
    })
}
