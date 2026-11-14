//! Messenger without a browser, archiving into Postgres.
//!
//! Configuration, from the environment:
//!
//! - `MESSENGER_DSN`: the ingest role's DSN. This process applies the archive's migrations
//!   and its own `client` schema's.
//! - `MESSENGER_ACCOUNT`: the archive's account id.
//! - `MESSENGER_COOKIES_FROM` (first start only): a cookie export to adopt when the database
//!   holds no session yet, a JSON array in Playwright's `context.cookies()` shape. Ignored
//!   once one is stored.
//! - `MESSENGER_DEVICE_FROM` (cutover only): the browser's encrypted device, as the retired
//!   `scripts/export-device.py` (in git history) exported it, to adopt when the database
//!   holds none. Ignored once one is stored; delete the file once this logs the import.
//! - `RUST_LOG`: log filter, `info` by default.
//!
//! It logs counts only, never a message, a name or an id.

use std::process::ExitCode;

use messenger_client::chat::Chat;
use messenger_client::cookies::Jar;
use messenger_client::daemon::{Client, Settings};
use messenger_client::{device, session};
use messenger_core::db::{create_pool, ensure_schema};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let (Ok(dsn), Ok(account)) = (
        std::env::var("MESSENGER_DSN"),
        std::env::var("MESSENGER_ACCOUNT"),
    ) else {
        tracing::error!("MESSENGER_DSN and MESSENGER_ACCOUNT must be set");
        return ExitCode::from(2);
    };
    let pool = match create_pool(&dsn).await {
        Ok(pool) => pool,
        Err(e) => {
            tracing::error!("cannot reach the database: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = ensure_schema(&pool).await {
        tracing::error!("archive migrations failed: {e}");
        return ExitCode::FAILURE;
    }
    match session::migrate(&pool).await {
        Ok(applied) if !applied.is_empty() => {
            tracing::info!("applied client migrations: {}", applied.join(", "))
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!("client migrations failed: {e}");
            return ExitCode::FAILURE;
        }
    }
    if let Err(e) = adopt_device(&pool).await {
        tracing::error!("{e}");
        return ExitCode::FAILURE;
    }
    let stored_device = match device::load(&pool).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("loading the device failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut conn = match pool.acquire().await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("cannot reach the database: {e}");
            return ExitCode::FAILURE;
        }
    };
    let jar = match session::load(&mut conn, &account).await {
        Ok(Some(jar)) => jar,
        Ok(None) => {
            let Ok(path) = std::env::var("MESSENGER_COOKIES_FROM") else {
                tracing::error!("no session stored and MESSENGER_COOKIES_FROM not set");
                return ExitCode::from(2);
            };
            let jar = match std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|json| Jar::from_json(&json).map_err(|e| e.to_string()))
            {
                Ok(jar) => jar,
                Err(e) => {
                    tracing::error!("the cookie export does not read: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if jar.get("c_user").is_none() || jar.get("xs").is_none() {
                tracing::error!("the cookie export holds no session (c_user, xs)");
                return ExitCode::FAILURE;
            }
            if let Err(e) = session::save(&mut conn, &account, &jar).await {
                tracing::error!("saving the imported session failed: {e}");
                return ExitCode::FAILURE;
            }
            tracing::info!("adopted the session from the cookie export");
            jar
        }
        Err(e) => {
            tracing::error!("loading the session failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    drop(conn);
    let client = match Client::new(pool.clone(), Settings::new(&account), jar) {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("cannot build the HTTP client: {e}");
            return ExitCode::FAILURE;
        }
    };
    match stored_device {
        // The encrypted chat logs in with the token each LightSpeed pass's page carries.
        Some((keys, messenger)) => {
            let tokens = client.crypto_auth_tokens();
            let chat = Chat::new(pool, account, keys, messenger);
            tokio::join!(client.run(), chat.run(tokens));
        }
        None => client.run().await,
    }
    ExitCode::SUCCESS
}

/// Stores the browser's encrypted device on the first start that is given one.
async fn adopt_device(pool: &sqlx::PgPool) -> Result<(), String> {
    let applied = device::store::migrate(pool)
        .await
        .map_err(|e| format!("device migrations failed: {e}"))?;
    if !applied.is_empty() {
        tracing::info!("applied device migrations: {}", applied.join(", "));
    }
    if device::load(pool)
        .await
        .map_err(|e| format!("loading the device failed: {e}"))?
        .is_some()
    {
        return Ok(());
    }
    let Ok(path) = std::env::var("MESSENGER_DEVICE_FROM") else {
        tracing::warn!("no encrypted device stored and MESSENGER_DEVICE_FROM not set");
        return Ok(());
    };
    let json = std::fs::read(&path).map_err(|e| format!("the device export does not read: {e}"))?;
    let (mut keys, messenger) = device::import(&json).map_err(|e| e.to_string())?;
    // The browser's sessions are not carried over: their ratchet state was exposed once
    // (2026-11-14), and a receive-only device never ratchets it away. Without them every
    // contact device's next message fails to open, the retry receipt that follows hands
    // out a fresh pre-key, and the sender starts a new session.
    let dropped = std::mem::take(&mut keys.sessions).len();
    device::save(pool, &keys, &messenger)
        .await
        .map_err(|e| format!("saving the imported device failed: {e}"))?;
    tracing::info!(
        "adopted the encrypted device: {dropped} sessions dropped, {} identities, {} pre-keys, not imported {:?}",
        keys.identities.len(),
        keys.pre_keys.len(),
        keys.stats.not_imported
    );
    Ok(())
}
