//! The stored cookie jar against a throwaway Postgres.

mod support;

use messenger_client::cookies::Jar;
use messenger_client::session;
use sqlx::postgres::PgPoolOptions;

const DATABASE: &str = "client_session";

fn jar() -> Jar {
    Jar::from_json(
        r#"[{"name":"c_user","value":"100","domain":".messenger.com","path":"/","expires":-1,"secure":true,"httpOnly":false},
            {"name":"xs","value":"fake%3Atoken","domain":".messenger.com","path":"/","expires":2000000000,"secure":true,"httpOnly":true}]"#,
    )
    .unwrap()
}

#[tokio::test]
async fn migrations_apply_once() {
    let Some((pool, _, _turn)) = support::database(DATABASE).await else {
        return;
    };
    assert_eq!(
        session::migrate(&pool).await.unwrap(),
        ["0001_session.sql", "0002_device.sql"]
    );
    assert!(session::migrate(&pool).await.unwrap().is_empty());
    let mut conn = pool.acquire().await.unwrap();
    assert!(session::load(&mut conn, "me").await.unwrap().is_none());
}

#[tokio::test]
async fn a_saved_jar_loads_back_and_a_rotation_replaces_it() {
    let Some((pool, _, _turn)) = support::database(DATABASE).await else {
        return;
    };
    session::migrate(&pool).await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    let mut jar = jar();
    session::save(&mut conn, "me", &jar).await.unwrap();
    assert_eq!(
        session::load(&mut conn, "me").await.unwrap(),
        Some(jar.clone())
    );

    jar.set(
        "xs=rotated; Domain=.messenger.com; Path=/; Secure",
        "www.messenger.com",
        chrono::Utc::now(),
    );
    session::save(&mut conn, "me", &jar).await.unwrap();
    let loaded = session::load(&mut conn, "me").await.unwrap().unwrap();
    assert_eq!(loaded.get("xs"), Some("rotated"));
    assert_eq!(loaded, jar);
    assert!(session::load(&mut conn, "other").await.unwrap().is_none());
}

#[tokio::test]
async fn a_role_granted_like_the_live_mcp_cannot_read_the_session() {
    let Some((pool, server, _turn)) = support::database(DATABASE).await else {
        return;
    };
    // The live grants: SELECT on all of `public`, and on every future table there.
    for sql in [
        "DROP ROLE IF EXISTS messenger_mcp_probe",
        "CREATE ROLE messenger_mcp_probe LOGIN PASSWORD 'probe'",
        "GRANT CONNECT ON DATABASE client_session TO messenger_mcp_probe",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO messenger_mcp_probe",
    ] {
        sqlx::raw_sql(sql).execute(&pool).await.unwrap();
    }
    messenger_core::db::ensure_schema(&pool).await.unwrap();
    session::migrate(&pool).await.unwrap();
    sqlx::raw_sql("GRANT SELECT ON ALL TABLES IN SCHEMA public TO messenger_mcp_probe")
        .execute(&pool)
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    session::save(&mut conn, "me", &jar()).await.unwrap();

    let host = server.trim_start_matches("postgresql://postgres:postgres@");
    let probe = PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "postgresql://messenger_mcp_probe:probe@{host}/{DATABASE}"
        ))
        .await
        .unwrap();
    // The probe does read the archive, so the refusal below is about the schema.
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM thread")
        .fetch_one(&probe)
        .await
        .unwrap();
    for query in [
        "SELECT count(*) FROM client.session",
        "SELECT count(*) FROM client.schema_migration",
    ] {
        let error = sqlx::query_scalar::<_, i64>(query)
            .fetch_one(&probe)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("permission denied for schema client"),
            "{query}: {error}"
        );
    }
    probe.close().await;
    sqlx::raw_sql(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM messenger_mcp_probe",
    )
    .execute(&pool)
    .await
    .unwrap();
}
