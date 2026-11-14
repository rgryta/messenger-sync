//! `person_alias` and `person_alias_member` — the MCP role's only write authority.
//!
//! `0003_grant_mcp_role.sql` grants `messenger_mcp` SELECT everywhere and
//! INSERT/UPDATE/DELETE on exactly these two tables, so this file is the whole of what
//! the read surface can change. The names in them are the operator's own and Messenger
//! never sees them.

use sqlx::postgres::PgPool;

use crate::models::AliasRow;

/// Create or replace an alias and its member set.
///
/// Members are replaced wholesale: the argument is the intended set, not an add. The
/// note is *not* replaced by nothing — `COALESCE(EXCLUDED.note, person_alias.note)`
/// keeps the note an alias already had when a later call does not give one.
pub async fn set_alias(
    pool: &PgPool,
    alias: &str,
    members: &[(String, String)],
    note: Option<&str>,
) -> Result<(), sqlx::Error> {
    let accounts: Vec<String> = members.iter().map(|(account, _)| account.clone()).collect();
    let users: Vec<String> = members.iter().map(|(_, user)| user.clone()).collect();
    let mut tx = pool.begin().await?;
    sqlx::query(
        "
            INSERT INTO person_alias (alias, note) VALUES ($1, $2)
            ON CONFLICT (alias) DO UPDATE SET note = COALESCE(EXCLUDED.note, person_alias.note)
            ",
    )
    .bind(alias)
    .bind(note)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM person_alias_member WHERE alias = $1")
        .bind(alias)
        .execute(&mut *tx)
        .await?;
    if !members.is_empty() {
        // One statement for the whole set rather than a loop: `unnest` is what
        // asyncpg's `executemany` amounts to here, with one round trip instead of one
        // per member.
        sqlx::query(
            "INSERT INTO person_alias_member (alias, account_id, fb_user_id) \
             SELECT $1, account_id, fb_user_id \
               FROM unnest($2::text[], $3::text[]) AS m (account_id, fb_user_id) \
             ON CONFLICT DO NOTHING",
        )
        .bind(alias)
        .bind(&accounts)
        .bind(&users)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await
}

/// Remove an alias, reporting whether it existed. `person_alias_member` goes with it
/// through the CASCADE.
pub async fn delete_alias(pool: &PgPool, alias: &str) -> Result<bool, sqlx::Error> {
    let removed: Option<String> =
        sqlx::query_scalar("DELETE FROM person_alias WHERE alias = $1 RETURNING alias")
            .bind(alias)
            .fetch_optional(pool)
            .await?;
    Ok(removed.is_some())
}

/// Every alias in force, with the people it names.
pub async fn list_aliases(pool: &PgPool) -> Result<Vec<AliasRow>, sqlx::Error> {
    sqlx::query_as::<_, AliasRow>(
        "
        SELECT a.alias, a.note,
               (SELECT string_agg(coalesce(p.name, p.username, m.fb_user_id), ', ')
                  FROM person_alias_member m
                  LEFT JOIN participant p
                    ON p.account_id = m.account_id AND p.fb_user_id = m.fb_user_id
                 WHERE m.alias = a.alias) AS members
          FROM person_alias a
         ORDER BY a.alias
        ",
    )
    .fetch_all(pool)
    .await
}
