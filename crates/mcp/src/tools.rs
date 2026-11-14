//! The seven tool bodies, as plain async functions over a pool.
//!
//! Read-only by construction: every function here reaches the database and nothing else.
//! There is no path from this module to Meta, which is what makes "this
//! server cannot post to Messenger" a structural claim rather than a promise — in Cargo
//! it is the absence of a dependency edge, which the linker enforces.
//!
//! The one exception is [`set_alias`], which writes — to two tables Meta never sees,
//! holding names the operator chose for their own people.
//!
//! Nothing here holds SQL: every statement lives in `messenger_core::store`.

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use messenger_core::store::{self, Deletion};
use sqlx::postgres::PgPool;

use crate::render::{self, py_repr};

/// An upper bound on any tool's `limit`. The caller is a language model, and a model
/// that asks for 100000 messages gets an answer that does not fit in its own context —
/// so the ceiling is enforced here rather than trusted to the prompt.
pub const MAX_LIMIT: i64 = 200;

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    /// The caller's fault, and reported back to them as text rather than logged.
    #[error("{0}")]
    Usage(String),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}

type Result<T> = std::result::Result<T, ToolError>;

impl From<messenger_core::db::DbError> for ToolError {
    fn from(error: messenger_core::db::DbError) -> Self {
        match error {
            messenger_core::db::DbError::Sql(error) => Self::Sql(error),
            other => Self::Usage(other.to_string()),
        }
    }
}

/// A zero or a negative reads as "unspecified" and falls back to the tool's own default,
/// exactly as `_clamp` does. A caller asking for 10_000 gets 200, not an error.
pub fn clamp(limit: Option<i64>, default: i64) -> i64 {
    match limit {
        Some(limit) if limit >= 1 => limit.min(MAX_LIMIT),
        _ => default,
    }
}

/// ISO 8601 or a Unix epoch, always returned as an aware UTC instant.
///
/// A naive value is read as UTC rather than left naive. It happened to behave correctly
/// — asyncpg reads naive as UTC and every rendered line is UTC — but that is right by
/// accident, and the accident stops holding the moment a column is declared `timestamp
/// with time zone` on one side of a comparison and not the other.
///
/// Normalising to UTC here rather than keeping the offset the caller wrote is safe
/// because no tool echoes the parsed moment back: every one of them only compares it.
pub fn parse_when(value: Option<&str>) -> Result<Option<DateTime<Utc>>> {
    let Some(raw) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let text = raw.trim();
    // Epoch seconds, because that is what a model tends to reach for when it has a
    // number rather than a date. Milliseconds are out of range for any real Messenger
    // date and would land in the far future, so they are not guessed at.
    let digits = text.strip_prefix('-').unwrap_or(text);
    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
        return match text.parse::<i64>().ok().and_then(|epoch| {
            DateTime::from_timestamp(epoch, 0).map(|moment| moment.with_timezone(&Utc))
        }) {
            Some(moment) => Ok(Some(moment)),
            None => Err(not_an_instant(raw)),
        };
    }
    let normalised = text.replace('Z', "+00:00");
    if let Ok(moment) = DateTime::parse_from_rfc3339(&normalised) {
        return Ok(Some(moment.with_timezone(&Utc)));
    }
    // `+0200` as well as `+02:00`, which `fromisoformat` also accepts.
    for format in ["%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%dT%H:%M%z"] {
        if let Ok(moment) = DateTime::parse_from_str(&normalised, format) {
            return Ok(Some(moment.with_timezone(&Utc)));
        }
    }
    for format in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(text, format) {
            return Ok(Some(Utc.from_utc_datetime(&naive)));
        }
    }
    if let Ok(date) = NaiveDate::parse_from_str(text, "%Y-%m-%d") {
        return Ok(Some(Utc.from_utc_datetime(
            &date.and_hms_opt(0, 0, 0).expect("midnight exists"),
        )));
    }
    Err(not_an_instant(raw))
}

fn not_an_instant(value: &str) -> ToolError {
    ToolError::Usage(format!(
        "{} is not an ISO-8601 instant (e.g. 2026-08-01 or 2026-08-01T12:00+00:00)",
        py_repr(value)
    ))
}

/// Resolve a person or alias to the ids that speak for them.
///
/// Raising on an unknown name rather than returning everything is deliberate: a filter
/// that silently does nothing turns "what did Zofia say" into the whole corpus, and the
/// caller has no way to notice.
async fn sender_ids(pool: &PgPool, person: Option<&str>) -> Result<Option<Vec<String>>> {
    let Some(person) = person.filter(|person| !person.is_empty()) else {
        return Ok(None);
    };
    let identities = store::resolve_people(pool, person).await?;
    if identities.is_empty() {
        return Err(ToolError::Usage(format!(
            "nobody is called {} — try the people tool to find the name",
            py_repr(person)
        )));
    }
    Ok(Some(
        identities
            .into_iter()
            .map(|identity| identity.fb_user_id)
            .collect(),
    ))
}

// ----------------------------------------------------------------------------- tools

pub async fn threads(
    pool: &PgPool,
    account: Option<&str>,
    since: Option<&str>,
    group: Option<bool>,
    limit: Option<i64>,
) -> Result<String> {
    let rows =
        store::list_threads(pool, account, parse_when(since)?, group, clamp(limit, 30)).await?;
    Ok(render::render_threads(&rows))
}

pub async fn messages(
    pool: &PgPool,
    thread_key: &str,
    account: Option<&str>,
    after: Option<&str>,
    before: Option<&str>,
    limit: Option<i64>,
) -> Result<String> {
    let after_at = parse_when(after)?;
    let before_at = parse_when(before)?;
    let rows = store::get_history(
        pool,
        thread_key,
        account,
        before_at,
        after_at,
        clamp(limit, 50),
    )
    .await?;
    let mut note = None;
    if let (Some(first), Some(last)) = (rows.first(), rows.last()) {
        let total = store::count_history(pool, thread_key, account, before_at, after_at).await?;
        note = render::window_note(
            total - rows.len() as i64,
            first.ts,
            last.ts,
            after_at.is_some(),
        );
    }
    // `windowed` asks whether the caller named a window, not whether one parsed, as the
    // Python's `before is not None or after is not None` on the raw arguments did.
    Ok(render::render_history(
        &rows,
        thread_key,
        before.is_some() || after.is_some(),
        note.as_deref(),
    ))
}

// The tool takes seven arguments because the Python tool did; a struct for them would
// have one caller and move the names out of the call site.
#[allow(clippy::too_many_arguments)]
pub async fn search(
    pool: &PgPool,
    query: &str,
    person: Option<&str>,
    thread_key: Option<&str>,
    account: Option<&str>,
    after: Option<&str>,
    before: Option<&str>,
    limit: Option<i64>,
) -> Result<String> {
    let senders = sender_ids(pool, person).await?;
    let rows = store::search_messages(
        pool,
        query,
        account,
        thread_key,
        senders.as_deref(),
        parse_when(before)?,
        parse_when(after)?,
        clamp(limit, 25),
    )
    .await?;
    Ok(render::render_search(&rows, query))
}

pub async fn people(pool: &PgPool, name: Option<&str>, limit: Option<i64>) -> Result<String> {
    let rows = store::find_people(pool, name, clamp(limit, 50)).await?;
    let aliases = store::list_aliases(pool).await?;
    Ok(render::render_people(&rows, &aliases))
}

pub async fn status(pool: &PgPool) -> Result<String> {
    let accounts = store::account_status(pool).await?;
    let loops = store::sync_loops(pool).await?;
    Ok(render::render_status(&accounts, &loops))
}

/// One message's text over time, and the deleted text if it was deleted.
///
/// `account` defaults to `"me"` because the retired Python tool's signature did
/// (`account: str = "me"`, where every other tool defaults to `None` and means "any
/// account"). Kept at the port so answers did not change; it means `revisions` finds
/// nothing on an archive whose `MESSENGER_ACCOUNT` label is not literally `me`.
pub async fn revisions(
    pool: &PgPool,
    thread_key: &str,
    message_id: &str,
    account: Option<&str>,
) -> Result<String> {
    let account = account.filter(|value| !value.is_empty()).unwrap_or("me");
    let deleted_at = match store::resolve_message(pool, account, thread_key, message_id).await? {
        Deletion::Unknown => {
            return Ok(format!("no message {message_id} in thread {thread_key}"));
        }
        Deletion::NotDeleted => None,
        Deletion::Deleted(at) => Some(at),
    };
    let rows = store::list_revisions(pool, account, thread_key, message_id).await?;
    Ok(render::render_revisions(
        &rows,
        &format!("{} revision(s) of {message_id}, oldest first", rows.len()),
        deleted_at,
    ))
}

/// Name a group of people, or delete the name by passing no members.
pub async fn set_alias(
    pool: &PgPool,
    alias: &str,
    members: &[String],
    note: Option<&str>,
) -> Result<String> {
    let mut pairs: Vec<(String, String)> = Vec::with_capacity(members.len());
    for member in members {
        let (account_id, fb_user_id) = member.split_once(':').unwrap_or((member.as_str(), ""));
        if account_id.is_empty() || fb_user_id.is_empty() {
            return Err(ToolError::Usage(format!(
                "member {} must be written as account:fb_user_id — the people \
                 tool prints each person's in that form",
                py_repr(member)
            )));
        }
        pairs.push((account_id.to_owned(), fb_user_id.to_owned()));
    }

    if pairs.is_empty() {
        let removed = store::delete_alias(pool, alias).await?;
        let outcome = if removed { "deleted" } else { "did not exist" };
        return Ok(format!("alias {} {outcome}", py_repr(alias)));
    }

    store::set_alias(pool, alias, &pairs, note).await?;
    let identities = store::resolve_people(pool, alias).await?;
    let named = identities
        .iter()
        .map(|identity| {
            let name = identity
                .name
                .as_deref()
                .filter(|value| !value.is_empty())
                .or(identity
                    .username
                    .as_deref()
                    .filter(|value| !value.is_empty()))
                .unwrap_or(&identity.fb_user_id);
            format!(
                "{name} [member {}:{}]",
                identity.account_id, identity.fb_user_id
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let named = if named.is_empty() {
        "(nobody found — check the ids)".to_owned()
    } else {
        named
    };
    Ok(format!("alias {} now names {named}", py_repr(alias)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_clamped_and_a_zero_reads_as_unspecified() {
        assert_eq!(clamp(None, 30), 30);
        assert_eq!(clamp(Some(0), 30), 30);
        assert_eq!(clamp(Some(-3), 25), 25);
        assert_eq!(clamp(Some(10), 50), 10);
        assert_eq!(clamp(Some(10_000), 50), MAX_LIMIT);
    }

    fn parsed(value: &str) -> String {
        parse_when(Some(value))
            .expect("a time")
            .expect("a value")
            .to_rfc3339()
    }

    #[test]
    fn an_offset_is_honoured_and_converted_to_utc() {
        assert_eq!(
            parsed("2026-08-01T12:00:00+02:00"),
            "2026-08-01T10:00:00+00:00"
        );
        assert_eq!(parsed("2026-08-01T12:00:00Z"), "2026-08-01T12:00:00+00:00");
        assert_eq!(parsed("2026-08-01T12:00+0200"), "2026-08-01T10:00:00+00:00");
    }

    #[test]
    fn a_naive_value_is_read_as_utc_not_as_local_time() {
        // `parsed.replace(tzinfo=UTC)`, even though the container sets TZ=Europe/Warsaw.
        assert_eq!(parsed("2026-08-01T12:00"), "2026-08-01T12:00:00+00:00");
        assert_eq!(parsed("2026-08-01 12:00:00"), "2026-08-01T12:00:00+00:00");
        assert_eq!(parsed("2026-08-01"), "2026-08-01T00:00:00+00:00");
    }

    #[test]
    fn an_epoch_is_accepted_because_a_model_reaches_for_one() {
        assert_eq!(parsed("1754049600"), "2025-08-01T12:00:00+00:00");
        assert_eq!(parsed("0"), "1970-01-01T00:00:00+00:00");
    }

    #[test]
    fn an_unreadable_value_names_itself_and_an_example() {
        let error = parse_when(Some("last tuesday")).unwrap_err();
        assert!(
            matches!(&error, ToolError::Usage(message)
                     if message == "'last tuesday' is not an ISO-8601 instant \
                                    (e.g. 2026-08-01 or 2026-08-01T12:00+00:00)"),
            "{error}"
        );
    }

    #[test]
    fn no_value_is_no_filter_rather_than_an_error() {
        assert!(parse_when(None).unwrap().is_none());
        assert!(parse_when(Some("")).unwrap().is_none());
    }
}
