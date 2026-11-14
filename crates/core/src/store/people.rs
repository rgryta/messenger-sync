//! `participant`: finding people, and resolving a name to the ids that speak for them.

use sqlx::postgres::PgPool;

use crate::models::{Identity, PersonRow};

/// People matching a handle, a name or an alias, with where to find them.
///
/// `fragment` is `None` for "everyone", which is what `people` with no argument asks
/// for.
pub async fn find_people(
    pool: &PgPool,
    fragment: Option<&str>,
    limit: i64,
) -> Result<Vec<PersonRow>, sqlx::Error> {
    sqlx::query_as::<_, PersonRow>(concat!(
        "
        SELECT p.account_id, p.fb_user_id, p.name, p.username,
               (SELECT string_agg(am.alias, ', ' ORDER BY am.alias)
                  FROM person_alias_member am
                 WHERE am.account_id = p.account_id AND am.fb_user_id = p.fb_user_id) AS aliases,
               (SELECT count(*) FROM message m
                 WHERE m.account_id = p.account_id AND m.sender_id = p.fb_user_id
                   AND ",
        is_a_message!(),
        ") AS message_count,
               -- The person -> conversation hop. Without it a caller had to full-text
               -- search for something the person said and read the thread key off the
               -- hit, because a DM has no title to look up.
               (SELECT array_agg(tp.thread_key ORDER BY tp.last_spoke_at DESC NULLS LAST)
                  FROM (SELECT thread_key, last_spoke_at
                          FROM thread_participant
                         WHERE account_id = p.account_id AND fb_user_id = p.fb_user_id
                         ORDER BY last_spoke_at DESC NULLS LAST
                         LIMIT 5) tp) AS thread_keys
          FROM participant p
         WHERE $1::text IS NULL
            OR p.fb_user_id = $1
            OR position(lower($1) IN lower(coalesce(p.username, ''))) > 0
            OR position(lower($1) IN lower(coalesce(p.name, ''))) > 0
            OR EXISTS (SELECT 1 FROM person_alias_member am
                        WHERE am.account_id = p.account_id AND am.fb_user_id = p.fb_user_id
                          AND position(lower($1) IN lower(am.alias)) > 0)
         ORDER BY message_count DESC, p.name, p.fb_user_id
         LIMIT $2
        "
    ))
    .bind(fragment)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Resolve an alias, an id or a whole name to the identities it names.
///
/// Whole-name, not a fragment: this is what a `person` filter and `set-alias` resolve
/// through, and a filter that matched loosely would silently widen the question.
///
/// The `ORDER BY` was not in the retired Python. There it was a bare `SELECT DISTINCT`, so
/// the row order — and therefore the names `set-alias` echoes back for a multi-person
/// alias — was whatever the plan happened to produce. Sorting makes that answer stable.
pub async fn resolve_people(pool: &PgPool, name: &str) -> Result<Vec<Identity>, sqlx::Error> {
    sqlx::query_as::<_, Identity>(
        "
        SELECT DISTINCT p.account_id, p.fb_user_id, p.name, p.username
          FROM participant p
          LEFT JOIN person_alias_member am
            ON am.account_id = p.account_id AND am.fb_user_id = p.fb_user_id
         WHERE lower(coalesce(am.alias, '')) = lower($1)
            OR lower(coalesce(p.username, '')) = lower($1)
            OR lower(coalesce(p.name, '')) = lower($1)
            OR p.fb_user_id = $1
         ORDER BY p.account_id, p.fb_user_id
        ",
    )
    .bind(name)
    .fetch_all(pool)
    .await
}
