//! The HTTP surface: `/mcp` behind the `Host` allowlist, `/healthz` outside it.
//!
//! Ported in spirit from the retired Python `tests/test_mcp_server.py`, which could only
//! list the tools —
//! the Python server was never exercised over HTTP by its own suite. The two failure
//! modes these cases exist for both produce a container that looks healthy and answers
//! nothing: an allowlist that rejects MCPHub's `Host`, and a `/healthz` that sits inside
//! the guard.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use messenger_core::config::McpSettings;
use messenger_core::db::create_pool;
use messenger_mcp::server::{build_router, open_pool};
use sqlx::postgres::PgPool;
use tower::ServiceExt;

use crate::support::db_test;

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
    "protocolVersion":"2025-06-18","capabilities":{},
    "clientInfo":{"name":"test","version":"0"}}}"#;

/// One JSON-RPC POST to `/mcp` with the given `Host`.
async fn call(pool: &PgPool, host: &str, allowed: &[&str]) -> StatusCode {
    let router = build_router(
        pool.clone(),
        allowed.iter().map(|h| (*h).to_owned()).collect(),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Host", host)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(Body::from(INITIALIZE))
        .expect("a request");
    router.oneshot(request).await.expect("a response").status()
}

async fn get(pool: &PgPool, path: &str, host: &str, allowed: &[&str]) -> StatusCode {
    let router = build_router(
        pool.clone(),
        allowed.iter().map(|h| (*h).to_owned()).collect(),
    );
    let request = Request::builder()
        .uri(path)
        .header("Host", host)
        .body(Body::empty())
        .expect("a request");
    router.oneshot(request).await.expect("a response").status()
}

db_test!(the_mcp_endpoint_answers_a_host_on_its_allowlist, |f| {
    // MCPHub addresses this server by container name, `http://messenger-mcp:8000/mcp`.
    // rmcp defaults to loopback only, which 403s every call while `/healthz` stays
    // green — a container that looks healthy and answers nothing.
    assert_eq!(
        call(&f.pool, "messenger-mcp:8000", &["messenger-mcp"]).await,
        StatusCode::OK
    );
});

db_test!(the_mcp_endpoint_refuses_a_host_that_is_not_on_it, |f| {
    assert_eq!(
        call(&f.pool, "evil.example.com", &["messenger-mcp"]).await,
        StatusCode::FORBIDDEN
    );
});

db_test!(healthz_answers_a_host_the_mcp_endpoint_rejects, |f| {
    // `--health-check` sends `Host: 127.0.0.1:8000`, which production's allowlist
    // (`messenger-mcp`) does not contain. If `/healthz` ever moves inside the guard the
    // healthcheck starts failing for a reason nothing about the container would explain.
    assert_eq!(
        get(&f.pool, "/healthz", "127.0.0.1:8000", &["messenger-mcp"]).await,
        StatusCode::OK
    );
    assert_eq!(
        call(&f.pool, "127.0.0.1:8000", &["messenger-mcp"]).await,
        StatusCode::FORBIDDEN,
        "the same Host on /mcp is still refused"
    );
});

db_test!(healthz_reports_a_database_that_has_gone_away, |f| {
    // A pool whose database has gone away still exists, and the container carries
    // `autoheal=true`: a probe that cannot tell the difference would leave a server that
    // answers every tool call with an error looking healthy.
    f.pool.close().await;
    assert_eq!(
        get(&f.pool, "/healthz", "localhost", &["localhost"]).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
});

db_test!(a_database_behind_the_code_is_refused_at_startup, |f| {
    // Serving on regardless would fail one query at a time and blame the caller. This
    // process runs as a role with no DDL rights, so a schema it cannot create is one it
    // must not pretend to have.
    let Some(dsn) = crate::support::container_dsn().await else {
        return;
    };
    sqlx::query("DROP DATABASE IF EXISTS unmigrated")
        .execute(&f.pool)
        .await
        .expect("drop");
    sqlx::query("CREATE DATABASE unmigrated")
        .execute(&f.pool)
        .await
        .expect("create");
    let empty = dsn.rsplit_once('/').expect("a dsn").0.to_owned() + "/unmigrated";
    let settings = McpSettings::for_dsn(&empty);
    let error = open_pool(&settings).await.expect_err("a refusal");
    assert!(
        error.to_string().contains("0001_init.sql"),
        "the refusal must name what is missing: {error}"
    );
    // The pool it opened is closed again, so the dropped database below is not in use.
    let pool = create_pool(&empty).await.expect("a pool");
    pool.close().await;
    sqlx::query("DROP DATABASE IF EXISTS unmigrated")
        .execute(&f.pool)
        .await
        .expect("drop again");
});
