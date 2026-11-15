//! Typed configuration for the read-only process.
//!
//! `McpSettings` is the whole of it. `messenger-ingest` reads its own variables in its
//! binary, so nothing of the client's is in the crate the MCP binary links.
//!
//! The variable names are the ones `deploy/compose.yaml` sets: `MESSENGER_DSN`,
//! `MESSENGER_HOST`, `MESSENGER_PORT` and `MESSENGER_MCP_LOG_LEVEL`.

use std::env;
use std::fmt;

/// A value that must not reach a log line. `Debug` prints the redaction, so a
/// `{settings:?}` anywhere cannot leak the DSN's password.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(**********)")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} is required")]
    Missing(&'static str),
    #[error("{name} is not a number: {value:?}")]
    NotANumber { name: &'static str, value: String },
    #[error("port must be between 1 and 65535")]
    PortOutOfRange,
}

/// rmcp's own default, repeated here so the allowlist is never empty.
///
/// An empty list means "allow every `Host`" to rmcp, so the parse below falls back to
/// this rather than to nothing: a compose file that forgets `MESSENGER_MCP_ALLOWED_HOSTS`
/// should fail closed and be obvious, not fail open and be invisible. The consequence is
/// that there is deliberately no way to spell "allow all" through the environment.
pub const DEFAULT_ALLOWED_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

#[derive(Debug, Clone)]
pub struct McpSettings {
    pub dsn: Secret,
    pub host: String,
    pub port: u16,
    pub log_level: String,
    /// `Host` headers the MCP endpoint will answer, as rmcp's DNS-rebinding guard.
    ///
    /// An entry without a port matches that hostname on any port; an entry with one
    /// requires an exact match. MCPHub addresses this server by container name
    /// (`http://messenger-mcp:8000/mcp`), so `messenger-mcp` is the production value —
    /// written without a port on purpose, because `MESSENGER_PORT` is already
    /// configurable and pinning the port in two places invites the two to disagree.
    pub allowed_hosts: Vec<String>,
}

/// Where the server listens, read on its own so `--health-check` can find the port
/// without a DSN it has no use for.
pub fn address_from_env() -> Result<(String, u16), ConfigError> {
    let port = match env::var("MESSENGER_PORT") {
        Ok(raw) => {
            let parsed: u32 = raw.trim().parse().map_err(|_| ConfigError::NotANumber {
                name: "MESSENGER_PORT",
                value: raw.clone(),
            })?;
            if !(1..=65535).contains(&parsed) {
                return Err(ConfigError::PortOutOfRange);
            }
            parsed as u16
        }
        Err(_) => 8000,
    };
    Ok((
        env::var("MESSENGER_HOST").unwrap_or_else(|_| "0.0.0.0".to_owned()),
        port,
    ))
}

/// `MESSENGER_MCP_ALLOWED_HOSTS` as a comma-separated list, falling back to
/// [`DEFAULT_ALLOWED_HOSTS`].
pub fn allowed_hosts_from_env() -> Vec<String> {
    parse_allowed_hosts(&env::var("MESSENGER_MCP_ALLOWED_HOSTS").unwrap_or_default())
}

/// Split out from the environment read so it can be tested without `set_var`, which is
/// process-global and unsafe in edition 2024.
///
/// Blank entries are dropped, and a value that is entirely blank or absent yields the
/// default rather than an empty list — see [`DEFAULT_ALLOWED_HOSTS`] for why that
/// matters.
pub fn parse_allowed_hosts(raw: &str) -> Vec<String> {
    let configured: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .collect();
    if configured.is_empty() {
        return DEFAULT_ALLOWED_HOSTS
            .iter()
            .map(|host| (*host).to_owned())
            .collect();
    }
    configured
}

impl McpSettings {
    /// Read the variables `deploy/compose.yaml` sets.
    pub fn from_env() -> Result<Self, ConfigError> {
        let (host, port) = address_from_env()?;
        Ok(Self {
            dsn: Secret(
                env::var("MESSENGER_DSN").map_err(|_| ConfigError::Missing("MESSENGER_DSN"))?,
            ),
            host,
            port,
            log_level: env::var("MESSENGER_MCP_LOG_LEVEL").unwrap_or_else(|_| "INFO".to_owned()),
            allowed_hosts: allowed_hosts_from_env(),
        })
    }

    pub fn for_dsn(dsn: impl Into<String>) -> Self {
        Self {
            dsn: Secret(dsn.into()),
            host: "0.0.0.0".to_owned(),
            port: 8000,
            log_level: "INFO".to_owned(),
            allowed_hosts: DEFAULT_ALLOWED_HOSTS
                .iter()
                .map(|host| (*host).to_owned())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dsn_never_appears_in_a_debug_line() {
        let settings = McpSettings::for_dsn("postgresql://messenger_mcp:hunter2@db/messenger");
        let rendered = format!("{settings:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(settings.dsn.expose().contains("hunter2"));
    }

    #[test]
    fn the_allowlist_is_comma_separated_and_trimmed() {
        assert_eq!(
            parse_allowed_hosts("messenger-mcp, messenger-mcp:8000 ,localhost"),
            ["messenger-mcp", "messenger-mcp:8000", "localhost"]
        );
    }

    #[test]
    fn an_unset_or_blank_allowlist_falls_back_to_loopback_not_to_nothing() {
        // rmcp reads an empty list as "allow every Host". A compose file that forgets
        // the variable must fail closed and be obvious, not fail open and be invisible.
        for raw in ["", "   ", ",", " , , "] {
            assert_eq!(
                parse_allowed_hosts(raw),
                DEFAULT_ALLOWED_HOSTS,
                "{raw:?} must not disable the guard"
            );
        }
    }

    #[test]
    fn a_single_host_replaces_the_default_rather_than_extending_it() {
        // Production sets exactly `messenger-mcp`; loopback is not silently kept
        // alongside it, so what the log line prints is the whole truth.
        assert_eq!(parse_allowed_hosts("messenger-mcp"), ["messenger-mcp"]);
    }
}
