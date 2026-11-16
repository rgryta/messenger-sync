//! `participant`: finding people, and resolving a name to the ids that speak for them.

use std::sync::LazyLock;

use sqlx::postgres::PgPool;

use crate::models::{Identity, PersonRow};

/// Accents folded away before a name is compared, one-to-one, lowercase only: `lower()`
/// (SQL) and `to_lowercase()` (Rust) run first, so `Ł` becomes `ł` before it is mapped.
/// People type "Michal" for "Michał"; both sides fold, so either spelling finds the other.
const FOLD_FROM: &str = "ąćęłńóśźżáàâäãåéèêëěíìîïòôöõőúùûüůűýÿñňçčšžřďť";
const FOLD_TO: &str = "acelnoszzaaaaaaeeeeeiiiiooooouuuuuuyynnccszrdt";

/// A typed name, folded the way [`fold_sql`] folds a stored one.
fn fold(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .map(|c| {
            FOLD_FROM
                .chars()
                .zip(FOLD_TO.chars())
                .find(|&(from, _)| from == c)
                .map_or(c, |(_, to)| to)
        })
        .collect()
}

/// A stored column, folded in SQL. Defeats any index on it; the people tables are small.
fn fold_sql(column: &str) -> String {
    format!("translate(lower({column}), '{FOLD_FROM}', '{FOLD_TO}')")
}

static FIND_PEOPLE: LazyLock<String> = LazyLock::new(|| {
    format!(
        "
        SELECT p.account_id, p.fb_user_id, p.name, p.username,
               (SELECT string_agg(am.alias, ', ' ORDER BY am.alias)
                  FROM person_alias_member am
                 WHERE am.account_id = p.account_id AND am.fb_user_id = p.fb_user_id) AS aliases,
               (SELECT count(*) FROM message m
                 WHERE m.account_id = p.account_id AND m.sender_id = p.fb_user_id
                   AND {is_a_message}) AS message_count,
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
            OR position($3 IN {username}) > 0
            OR position($3 IN {name}) > 0
            OR EXISTS (SELECT 1 FROM person_alias_member am
                        WHERE am.account_id = p.account_id AND am.fb_user_id = p.fb_user_id
                          AND position($3 IN {alias}) > 0)
         ORDER BY message_count DESC, p.name, p.fb_user_id
         LIMIT $2
        ",
        is_a_message = is_a_message!(),
        username = fold_sql("coalesce(p.username, '')"),
        name = fold_sql("coalesce(p.name, '')"),
        alias = fold_sql("am.alias"),
    )
});

/// People matching a handle, a name or an alias, with where to find them.
///
/// `fragment` is `None` for "everyone", which is what `people` with no argument asks
/// for.
pub async fn find_people(
    pool: &PgPool,
    fragment: Option<&str>,
    limit: i64,
) -> Result<Vec<PersonRow>, sqlx::Error> {
    sqlx::query_as::<_, PersonRow>(FIND_PEOPLE.as_str())
        .bind(fragment)
        .bind(limit)
        .bind(fragment.map(fold))
        .fetch_all(pool)
        .await
}

static RESOLVE_PEOPLE: LazyLock<String> = LazyLock::new(|| {
    format!(
        "
        SELECT DISTINCT p.account_id, p.fb_user_id, p.name, p.username
          FROM participant p
          LEFT JOIN person_alias_member am
            ON am.account_id = p.account_id AND am.fb_user_id = p.fb_user_id
         WHERE {alias} = $2
            OR {username} = $2
            OR {name} = $2
            OR p.fb_user_id = $1
         ORDER BY p.account_id, p.fb_user_id
        ",
        alias = fold_sql("coalesce(am.alias, '')"),
        username = fold_sql("coalesce(p.username, '')"),
        name = fold_sql("coalesce(p.name, '')"),
    )
});

/// Resolve an alias, an id or a whole name to the identities it names.
///
/// Whole-name, not a fragment: this is what a `person` filter and `set-alias` resolve
/// through, and a filter that matched loosely would silently widen the question.
///
/// The `ORDER BY` was not in the retired Python. There it was a bare `SELECT DISTINCT`, so
/// the row order — and therefore the names `set-alias` echoes back for a multi-person
/// alias — was whatever the plan happened to produce. Sorting makes that answer stable.
pub async fn resolve_people(pool: &PgPool, name: &str) -> Result<Vec<Identity>, sqlx::Error> {
    sqlx::query_as::<_, Identity>(RESOLVE_PEOPLE.as_str())
        .bind(name)
        .bind(fold(name))
        .fetch_all(pool)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rust_fold_and_the_sql_table_agree() {
        assert_eq!(FOLD_FROM.chars().count(), FOLD_TO.chars().count());
        assert!(FOLD_TO.is_ascii());
        assert_eq!(fold(FOLD_FROM), FOLD_TO);
        assert_eq!(fold(&FOLD_FROM.to_uppercase()), FOLD_TO, "lowercases first");
        assert_eq!(fold("ŁUKASZ Michał"), "lukasz michal");
        assert!(fold_sql("x").contains(&format!("'{FOLD_FROM}', '{FOLD_TO}'")));
    }
}
