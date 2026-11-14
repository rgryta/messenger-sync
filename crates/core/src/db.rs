//! Connection pool and forward-only schema application.
//!
//! Every `db-migrations/pg/*.sql` runs in filename order and applied filenames are
//! recorded in `schema_migration`. The ingest role owns the schema and applies them;
//! the MCP role can only read, so it asserts rather than applies — a read-only process
//! that quietly created tables would be a role-separation bug wearing a convenience
//! feature's clothes.
//!
//! `sqlx::migrate!` cannot be used here. It wants its own `_sqlx_migrations` table
//! keyed by version number and checksum; ours is `schema_migration(filename,
//! applied_at)` and the live database already holds applied rows in that shape. Worse,
//! the macro would `CREATE TABLE` on startup, and the MCP role deliberately has no DDL
//! rights. So the applier is hand-written against the same table, and
//! [`assert_migrations`] reads and never writes.

use std::time::Duration;

use sqlx::postgres::{PgPool, PgPoolOptions};

/// The shipped migrations, embedded rather than read from disk.
///
/// The retired Python read them from disk and had to search two candidate directories,
/// because
/// `Path(__file__).parent.parent / "db-migrations"` is true in a checkout and false in
/// the image, where `Path.glob` on the missing path returned nothing and `ensure_schema`
/// applied nothing silently. `include_str!` removes the question: the files are in the
/// binary. `migrations_match_the_directory` fails if one is added here and not to this
/// list, or the other way round.
pub const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_init.sql",
        include_str!("../../../db-migrations/pg/0001_init.sql"),
    ),
    (
        "0002_place_on_tablespaces.sql",
        include_str!("../../../db-migrations/pg/0002_place_on_tablespaces.sql"),
    ),
    (
        "0003_grant_mcp_role.sql",
        include_str!("../../../db-migrations/pg/0003_grant_mcp_role.sql"),
    ),
    (
        "0004_forward_sync.sql",
        include_str!("../../../db-migrations/pg/0004_forward_sync.sql"),
    ),
    (
        "0005_thread_participants.sql",
        include_str!("../../../db-migrations/pg/0005_thread_participants.sql"),
    ),
    (
        "0006_reactions_and_attachments.sql",
        include_str!("../../../db-migrations/pg/0006_reactions_and_attachments.sql"),
    ),
    (
        "0007_roster_membership.sql",
        include_str!("../../../db-migrations/pg/0007_roster_membership.sql"),
    ),
    (
        "0008_message_revisions.sql",
        include_str!("../../../db-migrations/pg/0008_message_revisions.sql"),
    ),
    (
        "0009_forward_attempt.sql",
        include_str!("../../../db-migrations/pg/0009_forward_attempt.sql"),
    ),
    (
        "0010_dom_transcript.sql",
        include_str!("../../../db-migrations/pg/0010_dom_transcript.sql"),
    ),
    (
        "0011_dom_message_ts.sql",
        include_str!("../../../db-migrations/pg/0011_dom_message_ts.sql"),
    ),
    (
        "0012_dom_history_done.sql",
        include_str!("../../../db-migrations/pg/0012_dom_history_done.sql"),
    ),
    (
        "0013_dom_attempted_at.sql",
        include_str!("../../../db-migrations/pg/0013_dom_attempted_at.sql"),
    ),
    (
        "0014_e2ee_messages.sql",
        include_str!("../../../db-migrations/pg/0014_e2ee_messages.sql"),
    ),
    (
        "0015_unsent_by.sql",
        include_str!("../../../db-migrations/pg/0015_unsent_by.sql"),
    ),
    (
        "0016_transcripts.sql",
        include_str!("../../../db-migrations/pg/0016_transcripts.sql"),
    ),
];

const SCHEMA_MIGRATION_DDL: &str = "
CREATE TABLE IF NOT EXISTS schema_migration (
  filename   text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
)
";

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database is behind the code, and this process cannot migrate it: {0}")]
    MigrationsMissing(String),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}

/// A pool sized as the retired Python one was: `min_size=1, max_size=8`.
pub async fn create_pool(dsn: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .min_connections(1)
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(30))
        .connect(dsn)
        .await
}

/// Apply every not-yet-applied migration, returning the filenames applied now.
///
/// Idempotent: a second call applies nothing and leaves one `schema_migration` row per
/// file. The whole pass runs in one transaction, so a failure part-way leaves neither
/// the DDL nor the rows that would claim it had been applied.
///
/// Called only by `messenger-client`, at boot, and by the test harness. The MCP process
/// calls [`assert_migrations`].
pub async fn ensure_schema(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    let mut applied_now = Vec::new();
    let mut tx = pool.begin().await?;
    sqlx::query(SCHEMA_MIGRATION_DDL).execute(&mut *tx).await?;
    for (filename, sql) in MIGRATIONS {
        // The primary key is the concurrency guard: a second booter's INSERT blocks on
        // the first, then returns no row, and we skip the DDL rather than running it
        // twice into an "already exists" failure.
        let inserted: Option<String> = sqlx::query_scalar(
            "INSERT INTO schema_migration (filename) VALUES ($1) \
             ON CONFLICT (filename) DO NOTHING RETURNING filename",
        )
        .bind(filename)
        .fetch_optional(&mut *tx)
        .await?;
        if inserted.is_none() {
            continue;
        }
        // `*sql` to hand sqlx a `&'static str`: its `SqlSafeStr` bound is what refuses a
        // runtime-built query, and keeping that refusal is the point.
        sqlx::raw_sql(*sql).execute(&mut *tx).await?;
        applied_now.push((*filename).to_owned());
    }
    tx.commit().await?;
    Ok(applied_now)
}

/// Filenames recorded in `schema_migration`, in filename order.
///
/// Returns an empty list when the table does not exist yet — the state the MCP process
/// meets when it starts before the client has ever run, and it must be able to say
/// so rather than crash on a missing relation.
pub async fn applied_migrations(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    let exists: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.schema_migration')::text")
            .fetch_one(pool)
            .await?;
    if exists.is_none() {
        return Ok(Vec::new());
    }
    sqlx::query_scalar("SELECT filename FROM schema_migration ORDER BY filename")
        .fetch_all(pool)
        .await
}

/// One round trip, for `/healthz`.
///
/// A real `SELECT 1` rather than reporting the pool's existence,
/// because a pool whose database has gone away still exists. It lives here and not in
/// the server because all SQL lives in this crate.
pub async fn ping(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(pool)
        .await
        .map(|_| ())
}

/// Read-only check that every shipped migration is present. Never applies DDL.
pub async fn assert_migrations(pool: &PgPool) -> Result<(), DbError> {
    let present = applied_migrations(pool).await?;
    let missing: Vec<&str> = MIGRATIONS
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !present.iter().any(|applied| applied == name))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(DbError::MigrationsMissing(missing.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_match_the_directory() {
        // The list is embedded, so nothing at runtime would notice a fourteenth
        // migration file that was never added to it. This does.
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../db-migrations/pg");
        let mut on_disk: Vec<String> = std::fs::read_dir(dir)
            .expect("db-migrations/pg is missing")
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".sql"))
            .collect();
        on_disk.sort();
        let embedded: Vec<String> = MIGRATIONS.iter().map(|(n, _)| (*n).to_owned()).collect();
        assert_eq!(embedded, on_disk);
    }

    #[test]
    fn migrations_are_embedded_in_filename_order() {
        // Filename order is the migration order — applying 0003 before 0001 fails in
        // ways that look like schema corruption — so the embedded list must already be
        // in it: nothing sorts this at runtime.
        let mut sorted = MIGRATIONS.to_vec();
        sorted.sort_by_key(|(name, _)| *name);
        assert_eq!(sorted, MIGRATIONS.to_vec());
    }

    #[test]
    fn no_migration_is_empty() {
        // `migration_files` refuses an empty result for the same reason: this project
        // ships its schema as files, and nothing here is a legitimate no-op file.
        for (name, sql) in MIGRATIONS {
            assert!(!sql.trim().is_empty(), "{name} is empty");
        }
    }
}
