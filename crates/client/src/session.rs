//! The cookie jar in Postgres, so a rotation Meta sends survives a restart.
//!
//! Its own schema, `client`, with its own migrations, applied by this crate and nothing else:
//! `public` grants the MCP role read access to every new table, and this one is the login.
//! That is also why this SQL lives here and not in `messenger_core::store`: the MCP binary
//! links the core, and it must not hold the code that reads a session.

use sqlx::PgConnection;
use sqlx::postgres::PgPool;
use sqlx::types::Json;

use crate::cookies::Jar;

pub const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_session.sql",
        include_str!("../migrations/0001_session.sql"),
    ),
    (
        "0002_device.sql",
        include_str!("../migrations/0002_device.sql"),
    ),
];

const BOOTSTRAP: &str = "CREATE SCHEMA IF NOT EXISTS client; \
    CREATE TABLE IF NOT EXISTS client.schema_migration ( \
        filename text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())";

/// Applies every not-yet-applied client migration, returning their names. One transaction,
/// like `messenger_core::db::ensure_schema`: the primary key makes a second process starting
/// at the same moment skip rather than apply twice.
pub async fn migrate(pool: &PgPool) -> sqlx::Result<Vec<&'static str>> {
    let mut tx = pool.begin().await?;
    sqlx::raw_sql(BOOTSTRAP).execute(&mut *tx).await?;
    let mut applied = Vec::new();
    for (filename, sql) in MIGRATIONS {
        let inserted: Option<String> = sqlx::query_scalar(
            "INSERT INTO client.schema_migration (filename) VALUES ($1) \
             ON CONFLICT (filename) DO NOTHING RETURNING filename",
        )
        .bind(filename)
        .fetch_optional(&mut *tx)
        .await?;
        if inserted.is_some() {
            sqlx::raw_sql(*sql).execute(&mut *tx).await?;
            applied.push(*filename);
        }
    }
    tx.commit().await?;
    Ok(applied)
}

/// The stored jar, or `None` before the first save.
pub async fn load(conn: &mut PgConnection, account_id: &str) -> sqlx::Result<Option<Jar>> {
    let jar: Option<Json<Jar>> =
        sqlx::query_scalar("SELECT cookies FROM client.session WHERE account_id = $1")
            .bind(account_id)
            .fetch_optional(conn)
            .await?;
    Ok(jar.map(|Json(jar)| jar))
}

pub async fn save(conn: &mut PgConnection, account_id: &str, jar: &Jar) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO client.session (account_id, cookies) VALUES ($1, $2) \
         ON CONFLICT (account_id) DO UPDATE SET cookies = EXCLUDED.cookies, updated_at = now()",
    )
    .bind(account_id)
    .bind(Json(jar))
    .execute(conn)
    .await?;
    Ok(())
}
