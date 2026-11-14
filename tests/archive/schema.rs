//! The schema applier and the constraints the archive leans on.
//!
//! Ported from the retired Python `tests/test_db.py`. The three tests there that exercise
//! `MIGRATIONS_DIR` — filename ordering, an empty directory being an error, and the image
//! layout being found when the checkout layout is absent — have no Rust equivalent and need
//! none: `include_str!` puts the files in the binary, so there is no path to get wrong and
//! `crates/core/src/db.rs`'s own unit tests check the embedded list against the directory
//! at compile-cwd instead.

use messenger_core::db::{applied_migrations, assert_migrations, ensure_schema};

use crate::support::db_test;

db_test!(ensure_schema_is_idempotent, |f| {
    // The fixture already applied them, so a second pass must apply nothing.
    let applied_again = ensure_schema(&f.pool).await.expect("ensure_schema");
    assert!(applied_again.is_empty(), "{applied_again:?}");
    let names = applied_migrations(&f.pool).await.expect("applied");
    let mut unique = names.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(names, unique, "one row per file, in filename order");
    assert!(names.contains(&"0001_init.sql".to_owned()), "{names:?}");
    assert!(
        names.contains(&"0013_dom_attempted_at.sql".to_owned()),
        "{names:?}"
    );
});

db_test!(assert_migrations_passes_on_a_current_schema, |f| {
    assert_migrations(&f.pool).await.expect("current");
});

db_test!(
    the_tablespace_migration_is_a_noop_without_the_tablespaces,
    |f| {
        // The test container has neither tablespace; the migration must not fail there,
        // and must leave the objects where they are.
        let applied = applied_migrations(&f.pool).await.expect("applied");
        assert!(
            applied.contains(&"0002_place_on_tablespaces.sql".to_owned()),
            "{applied:?}"
        );
        let misplaced: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_class \
             WHERE relname IN ('message','thread','dom_message') AND reltablespace <> 0",
        )
        .fetch_one(&f.pool)
        .await
        .expect("pg_class");
        assert_eq!(misplaced, 0);
    }
);

db_test!(
    the_mcp_grants_are_skipped_where_the_role_does_not_exist,
    |f| {
        // `0003_grant_mcp_role.sql` is guarded on `pg_roles`: a migration that only works on
        // the production box is one that gets skipped in tests and then surprises somebody.
        let applied = applied_migrations(&f.pool).await.expect("applied");
        assert!(
            applied.contains(&"0003_grant_mcp_role.sql".to_owned()),
            "{applied:?}"
        );
        let role: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_roles WHERE rolname = $1")
            .bind("messenger_mcp")
            .fetch_one(&f.pool)
            .await
            .expect("pg_roles");
        assert_eq!(role, 0, "the container must not have the production role");
    }
);

db_test!(the_search_column_indexes_text_without_stemming, |f| {
    // Ported from `test_search_is_generated_without_stemming`. 'simple', not 'english':
    // this corpus is mostly Polish, and an English stemmer silently drops hits on
    // everything that is not English.
    crate::support::me(&f.pool).await;
    crate::support::thread(&f.pool, crate::support::Thread::dm(crate::support::DM)).await;
    crate::support::said(
        &f.pool,
        crate::support::Said::new(crate::support::DM, "m1", 0).text("Poszedlem na zakupy"),
    )
    .await;
    for (word, expected) in [("zakupy", 1), ("zakup", 0)] {
        let found: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM message WHERE search @@ websearch_to_tsquery('simple', $1)",
        )
        .bind(word)
        .fetch_one(&f.pool)
        .await
        .expect("search");
        assert_eq!(found, expected, "{word}");
    }
});

db_test!(a_rendered_line_is_searchable_as_soon_as_it_is_stored, |f| {
    // `dom_message.search` is a generated column, and it is the only reason an encrypted
    // conversation can be found at all.
    crate::support::me(&f.pool).await;
    crate::support::thread(
        &f.pool,
        crate::support::Thread::encrypted(crate::support::DM),
    )
    .await;
    crate::support::captured(
        &f.pool,
        crate::support::DM,
        "run-1",
        crate::support::base(),
        &[(0, Some(crate::support::at(0)), "herbata", "Zofia")],
    )
    .await;
    let found: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM dom_message WHERE search @@ websearch_to_tsquery('simple', $1)",
    )
    .bind("herbata")
    .fetch_one(&f.pool)
    .await
    .expect("search");
    assert_eq!(found, 1);
});

db_test!(a_message_needs_its_thread, |f| {
    // Ported from `test_a_message_needs_its_thread`. A stranded row no listing can reach
    // is worse than a loud failure.
    crate::support::me(&f.pool).await;
    let error = sqlx::query(
        "INSERT INTO message (account_id, thread_key, message_id, ts, sync_group) \
         VALUES ('me', 'nope', 'm1', now(), 1)",
    )
    .execute(&f.pool)
    .await
    .expect_err("the foreign key must refuse this");
    // 23503 is foreign_key_violation, which is what the Python test asserted by exception class.
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23503"),
        "{error}"
    );
});

db_test!(a_revision_cannot_outlive_its_message, |f| {
    crate::support::me(&f.pool).await;
    crate::support::thread(&f.pool, crate::support::Thread::dm(crate::support::DM)).await;
    crate::support::said(
        &f.pool,
        crate::support::Said::new(crate::support::DM, "m1", 0),
    )
    .await;
    crate::support::revision(&f.pool, crate::support::DM, "m1", 1, Some("first"), None).await;
    sqlx::query("DELETE FROM message WHERE message_id = 'm1'")
        .execute(&f.pool)
        .await
        .expect("delete");
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM message_revision")
        .fetch_one(&f.pool)
        .await
        .expect("count");
    assert_eq!(left, 0);
});
