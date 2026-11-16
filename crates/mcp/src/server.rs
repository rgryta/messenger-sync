//! The MCP server: streamable HTTP at `/mcp`, seven tools, no Messenger credential.
//!
//! The pool is opened before the listener binds and the shipped migrations are asserted
//! present — never applied. This process runs as a role with no DDL rights, and a schema
//! it cannot create is a schema it must not pretend to have.
//!
//! Six of the seven tools are reads. The seventh writes the two alias tables and nothing
//! else.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use messenger_core::config::McpSettings;
use messenger_core::db::{DbError, assert_migrations, create_pool, ping};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, ErrorData, Implementation, ServerCapabilities, ServerConfig,
};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use sqlx::postgres::PgPool;

use crate::tools::{self, ToolError};

/// What a client is told about the archive, hard wrap and trailing newline included.
pub const INSTRUCTIONS: &str = "\
Facebook Messenger conversations, from a permanent archive in PostgreSQL written by a
separate client. Timestamps are ISO 8601 UTC. Nothing here can send, react, or mark
anything read, and nothing here reads Messenger live — only what has already been
archived.

Two kinds of conversation are archived and they behave differently.

Group chats live in Messenger's regular store and are archived with their text.

One-to-one DMs are end-to-end encrypted. Since 2026-11-14 the archiving client is one
of the account's own devices and decrypts their text as it arrives, so newer messages
have their words like any other. Older ones are mostly envelopes: a time, a sender and
an id, and no words. In `messages` those render as `[text not captured]`, and because
`search` matches on stored text they can never appear in a `search` result — a search
that misses them is not evidence that nothing was said. Nothing will fill them in.

Some older words were read from the client's own rendering of the conversation before
then, and they come back from `messages` and `search` like anything else — there is no
separate tool. Those lines are marked `screen`, and they differ from the rest in three
ways worth knowing: their clock is precise to the minute rather than the second, they
carry no message id, and they cannot be narrowed by `person` in a search, because a
rendering names a sender but does not identify one.

So an older encrypted conversation can show two kinds of line: envelopes, which say
exactly when a message was sent and nothing about what it said, and `screen` lines,
which say what was said to the minute. They are not matched up with each other and
never will be — two messages from one person inside a minute are indistinguishable in a
rendering, and guessing would file one person's sentence under another person's
message. No new `screen` lines are being added. `status` reports how many
conversations hold no text.

History is paged backwards over days rather than fetched at once, so an empty answer can
mean \"not archived yet\" rather than \"never happened\". `threads` says which conversations
are still being paged, and `status` says how many remain.

Thread keys and message ids are printed in brackets on every line and are what
`messages` takes. Names come from an alias if one is set, else the display name, else
the handle — use `people` when a name is ambiguous, and `set-alias` to record what
someone is actually called.
";

/// Tool names are hyphenated and declared explicitly: MCPHub joins them to the server
/// name with `-`, so these read `messenger-threads` rather than
/// `messenger-msg_threads`, which would stutter and mix both separators. The Rust method
/// names below are incidental.
#[derive(Clone)]
pub struct MessengerMcp {
    pool: PgPool,
}

/// Turn a tool's answer into a protocol response.
///
/// A usage error is the caller's and goes back as `invalid_params` with its own text —
/// where the Python SDK rendered `Error executing tool messages` and dropped the reason. A
/// SQL error is ours: it is logged in full and the caller is told only that the read
/// failed, because a Postgres error string can carry the DSN and the data.
fn finish(result: std::result::Result<String, ToolError>) -> Result<CallToolResult, ErrorData> {
    match result {
        Ok(body) => Ok(CallToolResult::success(vec![ContentBlock::text(body)])),
        Err(ToolError::Usage(message)) => Err(ErrorData::invalid_params(message, None)),
        Err(ToolError::Sql(error)) => {
            tracing::error!(%error, "the archive could not be read");
            Err(ErrorData::internal_error(
                "the archive could not be read".to_string(),
                None,
            ))
        }
    }
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ThreadsArgs {
    pub since: Option<String>,
    pub group: Option<bool>,
    pub account: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MessagesArgs {
    pub thread_key: String,
    pub after: Option<String>,
    pub before: Option<String>,
    pub account: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RevisionsArgs {
    pub thread_key: String,
    pub message_id: String,
    pub account: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchArgs {
    pub query: String,
    pub person: Option<String>,
    pub thread_key: Option<String>,
    pub after: Option<String>,
    pub before: Option<String>,
    pub account: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct PeopleArgs {
    pub name: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct NoArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetAliasArgs {
    pub alias: String,
    pub members: Option<Vec<String>>,
    pub note: Option<String>,
}

// The annotations are declared so a client can tell a read from a write without parsing
// a description. A tool with no hints is assumed able to change things, so an
// unannotated read looks no safer than a write — and ChatGPT blocked read calls before
// they left.
#[tool_router]
impl MessengerMcp {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[tool(
        name = "threads",
        description = "List archived conversations with message counts and last activity, newest \
                       first. Encrypted one-to-one DMs are marked. `since` (ISO 8601) narrows to \
                       threads active since then and counts only what arrived after it - the way \
                       to catch up. `group` selects group chats or DMs.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn threads(
        &self,
        Parameters(args): Parameters<ThreadsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        finish(
            tools::threads(
                &self.pool,
                args.account.as_deref(),
                args.since.as_deref(),
                args.group,
                args.limit,
            )
            .await,
        )
    }

    #[tool(
        name = "messages",
        description = "Read one conversation's archived messages, oldest first. Takes the thread \
                       key printed by `threads`. With `after` you get the oldest `limit` rows \
                       after it, so you read a period forward from its start; without `after` you \
                       get the newest `limit`, and `before` walks back from there. \
                       `after`/`before` accept ISO 8601. When the period holds more than `limit`, \
                       the reply ends with how many more there are and the exact `after` (or \
                       `before`) to pass for the next page.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn messages(
        &self,
        Parameters(args): Parameters<MessagesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        finish(
            tools::messages(
                &self.pool,
                &args.thread_key,
                args.account.as_deref(),
                args.after.as_deref(),
                args.before.as_deref(),
                args.limit,
            )
            .await,
        )
    }

    #[tool(
        name = "revisions",
        description = "The edit history of one message, oldest first, and the deleted text if it \
                       was deleted. Other tools mark a message (edited) or [deleted] and withhold \
                       the earlier and deleted text; this is where to read it. Revision 1 is the \
                       earliest text this archive saw, not necessarily what was originally sent.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn revisions(
        &self,
        Parameters(args): Parameters<RevisionsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        finish(
            tools::revisions(
                &self.pool,
                &args.thread_key,
                &args.message_id,
                args.account.as_deref(),
            )
            .await,
        )
    }

    #[tool(
        name = "search",
        description = "Full-text search the archive, best match first. Ignores accents and \
                       forgives a typo or a different word ending; a \"quoted phrase\" or -word \
                       stays exact. `person` narrows by sender \
                       and takes an alias, a handle, a whole display name or a raw id; an unknown \
                       name is an error rather than a silently ignored filter. `after`/`before` \
                       (ISO 8601) narrow it to a period - which is what to use when the question \
                       is about a particular month, since ranking by relevance otherwise lets the \
                       best matches of all time crowd that month out.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn search(
        &self,
        Parameters(args): Parameters<SearchArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        finish(
            tools::search(
                &self.pool,
                &args.query,
                args.person.as_deref(),
                args.thread_key.as_deref(),
                args.account.as_deref(),
                args.after.as_deref(),
                args.before.as_deref(),
                args.limit,
            )
            .await,
        )
    }

    #[tool(
        name = "people",
        description = "Resolve part of a name, handle or alias to the people it matches, showing \
                       every name form held for each so an ambiguous match is visible rather than \
                       silently picked. Each result carries the `account:fb_user_id` handle that \
                       `set-alias` takes. The aliases in force are listed underneath.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn people(
        &self,
        Parameters(args): Parameters<PeopleArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        finish(tools::people(&self.pool, args.name.as_deref(), args.limit).await)
    }

    #[tool(
        name = "status",
        description = "How much is archived, how much history is still being paged backwards, and \
                       whether the Messenger session is still alive. Read this when an answer looks \
                       emptier than expected.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn status(&self, Parameters(_): Parameters<NoArgs>) -> Result<CallToolResult, ErrorData> {
        finish(tools::status(&self.pool).await)
    }

    #[tool(
        name = "set-alias",
        description = "Name a person or a group of people so later questions can use that name. \
                       Members are `account:fb_user_id` as printed by `people`. Passing no members \
                       deletes the alias. Local only - Messenger never sees this.",
        annotations(
            read_only_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn set_alias(
        &self,
        Parameters(args): Parameters<SetAliasArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        finish(
            tools::set_alias(
                &self.pool,
                &args.alias,
                &args.members.unwrap_or_default(),
                args.note.as_deref(),
            )
            .await,
        )
    }
}

#[tool_handler]
impl ServerHandler for MessengerMcp {
    /// Written out rather than left to `#[tool_handler(instructions = "…")]`: that
    /// argument takes a literal, and a literal folded to fit this file would drop the
    /// instructions' hard wrap.
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("messenger", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS.to_string())
    }
}

/// Own the pool and refuse an unmigrated database.
///
/// Separate from [`run`] so a test can call it without a listener.
pub async fn open_pool(settings: &McpSettings) -> Result<PgPool, DbError> {
    let pool = create_pool(settings.dsn.expose()).await?;
    if let Err(error) = assert_migrations(&pool).await {
        // Failing at startup names the problem; serving on regardless would fail one
        // query at a time and blame the caller. This process runs as a role with no DDL
        // rights, so a schema it cannot create is one it must not pretend to have.
        pool.close().await;
        return Err(error);
    }
    Ok(pool)
}

/// `/mcp` plus `/healthz`.
///
/// `/healthz` is a plain route on this router and only `/mcp` is nested onto the MCP
/// service, so the `Host` allowlist does not apply to the probe and `--health-check`
/// needs no entry of its own.
/// `tests/archive/server.rs::healthz_answers_a_host_the_mcp_endpoint_rejects` holds
/// that: if it ever stops being true the healthcheck starts failing for a reason nothing
/// about the container would explain.
pub fn build_router(pool: PgPool, allowed_hosts: Vec<String>) -> Router {
    let probe = pool.clone();
    let service = StreamableHttpService::new(
        move || Ok(MessengerMcp::new(pool.clone())),
        Arc::new(NeverSessionManager::default()),
        stateless_config(allowed_hosts),
    );
    Router::new()
        .route("/healthz", get(move || healthz(probe.clone())))
        .nest_service("/mcp", service)
}

/// One round trip to Postgres, not merely "the process is up".
///
/// A pool whose database has gone away still exists, and the container carries
/// `autoheal=true`: a probe that cannot tell the difference would leave a server that
/// answers every tool call with an error looking healthy.
async fn healthz(pool: PgPool) -> Response {
    match ping(&pool).await {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(error) => {
            let mut detail = error.to_string();
            detail.truncate(200);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "status": "database unreachable",
                    "detail": detail,
                })),
            )
                .into_response()
        }
    }
}

fn stateless_config(allowed_hosts: Vec<String>) -> StreamableHttpServerConfig {
    let mut config = StreamableHttpServerConfig::default();
    // There is no per-client state to keep, and statelessness takes session affinity off
    // the table behind MCPHub.
    config.legacy_session_mode = false;
    // rmcp's guard against DNS rebinding. An empty list would mean "answer any `Host`",
    // so the list handed in here is never empty — see `DEFAULT_ALLOWED_HOSTS`. MCPHub
    // addresses this server by container name, so production sets `messenger-mcp`.
    config.allowed_hosts = allowed_hosts;
    config
}

pub async fn run(settings: &McpSettings) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pool = open_pool(settings).await?;
    let address: SocketAddr = format!("{}:{}", settings.host, settings.port).parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    // Logged because the failure mode is a server that boots clean and then refuses
    // every tool call with a 403: one line here turns a baffling outage into an obvious
    // one. `/healthz` is outside this list, so a container can look healthy while every
    // call is rejected.
    tracing::info!(
        allowed_hosts = %settings.allowed_hosts.join(", "),
        "answering /mcp only for these Host headers"
    );
    tracing::info!(%address, "serving the messenger archive over MCP");
    axum::serve(listener, build_router(pool, settings.allowed_hosts.clone()))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// Probe our own `/healthz`, for the container healthcheck.
///
/// The image is `FROM scratch`, with no shell and no HTTP client, so the container
/// healthcheck in `deploy/compose.yaml` runs this binary with `--health-check` instead.
///
/// Hand-rolled over TCP rather than through an HTTP client crate: it reads one status
/// line from a loopback socket, and a dependency for that is a dependency to keep
/// patched for no gain.
pub async fn health_check(host: &str, port: u16) -> Result<(), String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    // The bind address may be the wildcard, which is not a destination.
    let host = match host {
        "0.0.0.0" | "::" | "" => "127.0.0.1",
        host => host,
    };
    let target = format!("{host}:{port}");
    let mut stream = tokio::net::TcpStream::connect(&target)
        .await
        .map_err(|error| format!("could not connect to {target}: {error}"))?;
    stream
        .write_all(
            format!("GET /healthz HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .map_err(|error| format!("could not send the probe: {error}"))?;

    let mut status = String::new();
    BufReader::new(stream)
        .read_line(&mut status)
        .await
        .map_err(|error| format!("no answer from {target}: {error}"))?;
    if status.contains(" 200 ") {
        return Ok(());
    }
    Err(format!("/healthz answered {}", status.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_names() -> Vec<String> {
        MessengerMcp::tool_router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect()
    }

    #[test]
    fn the_tool_surface_is_exactly_this() {
        // Seven: six reads and `set-alias`.
        let mut names = tool_names();
        names.sort();
        assert_eq!(
            names,
            vec![
                "messages",
                "people",
                "revisions",
                "search",
                "set-alias",
                "status",
                "threads",
            ]
        );
    }

    #[test]
    fn names_are_hyphenated_not_mixed() {
        // MCPHub joins server and tool with `-`; an underscore would read as
        // `messenger-set_alias`, mixing both separators in one identifier.
        for name in tool_names() {
            assert!(!name.contains('_'), "{name}");
        }
    }

    #[test]
    fn every_tool_describes_itself() {
        // MCPHub shows these descriptions; an unlabelled tool is an unusable one.
        for tool in MessengerMcp::tool_router().list_all() {
            assert!(tool.description.is_some(), "{}", tool.name);
        }
    }

    #[test]
    fn a_client_can_tell_which_tools_only_read() {
        // Ported from the retired Python `tests/test_mcp_server.py`. With no hints every
        // tool looks able to write, so a read was no safer on its face than `set-alias`
        // beside it.
        for tool in MessengerMcp::tool_router().list_all() {
            let annotations = tool
                .annotations
                .as_ref()
                .unwrap_or_else(|| panic!("{} has no annotations", tool.name));
            assert_eq!(
                annotations.read_only_hint,
                Some(tool.name != "set-alias"),
                "{}",
                tool.name
            );
        }
    }

    #[test]
    fn no_tool_offers_a_path_to_messenger() {
        // The archive tools read PostgreSQL. Offering a profile, a session or a capture
        // argument would imply this process could reach Messenger, which it cannot: the
        // code to do so is not linked into it.
        for tool in MessengerMcp::tool_router().list_all() {
            let schema = serde_json::to_string(&tool.input_schema).expect("a schema");
            for forbidden in ["profile", "capture", "scroll"] {
                assert!(
                    !schema.contains(forbidden),
                    "{}: {forbidden} in {schema}",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn the_instructions_keep_what_a_client_cannot_work_out() {
        // Spot checks on the facts a client cannot work out for itself, so a reflow here
        // is caught rather than shipped.
        assert!(INSTRUCTIONS.ends_with("someone is actually called.\n"));
        assert!(INSTRUCTIONS.contains("`[text not captured]`"));
        assert!(INSTRUCTIONS.contains("lines are marked `screen`"));
        assert!(INSTRUCTIONS.contains("Since 2026-11-14"));
    }

    #[tokio::test]
    async fn the_health_check_target_is_never_the_wildcard_address() {
        // Connecting to 0.0.0.0 is not a thing the healthcheck can do; port 1 is closed,
        // so the error names the address it actually tried.
        let error = health_check("0.0.0.0", 1).await.unwrap_err();
        assert!(error.contains("127.0.0.1:1"), "{error}");
    }
}
