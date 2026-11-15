//! The snapshot request and the payload it answers with (made-up values).

use messenger_client::graphql::{GraphqlError, snapshot_form, snapshot_payload};
use messenger_client::page::{PageConfig, Preloader};
use serde_json::Value;

fn config() -> (PageConfig, Preloader) {
    let preloader = Preloader {
        query_id: "7357407954267582".into(),
        device_id: "0f4b2c1e-1111-4222-8333-944455556666".into(),
        request_payload: r#"{"database":1,"version":12345678901234567890}"#.into(),
        database: 1,
    };
    let config = PageConfig {
        user_id: "100000000000001".into(),
        app_id: "2220391788200892".into(),
        device_id: "x".into(),
        version: "12345678901234567890".into(),
        dtsg: Some("dtsg".into()),
        lsd: Some("lsd".into()),
        revision: Some("1012345678".into()),
        preloaders: vec![preloader.clone()],
        crypto_auth_token: None,
        session_id: None,
        user_app_id: None,
    };
    (config, preloader)
}

#[test]
fn the_form_is_the_harvesters_snapshot_field_for_field() {
    let (config, preloader) = config();
    let form = snapshot_form(&config, &preloader);
    let get = |k: &str| {
        form.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| v.as_str())
            .unwrap()
    };
    assert_eq!(get("av"), "100000000000001");
    assert_eq!(get("__user"), "100000000000001");
    assert_eq!(get("__a"), "1");
    assert_eq!(get("__rev"), "1012345678");
    assert_eq!(get("fb_dtsg"), "dtsg");
    assert_eq!(get("lsd"), "lsd");
    assert_eq!(get("fb_api_caller_class"), "RelayModern");
    assert_eq!(
        get("fb_api_req_friendly_name"),
        "LSPlatformGraphQLLightspeedRequestQuery"
    );
    assert_eq!(get("doc_id"), "7357407954267582");
    let variables: Value = serde_json::from_str(get("variables")).unwrap();
    assert_eq!(
        variables["deviceId"],
        "0f4b2c1e-1111-4222-8333-944455556666"
    );
    assert_eq!(variables["requestId"], 0);
    assert_eq!(variables["requestType"], 1);
    // The payload rides as the exact string the page held, version and all.
    assert_eq!(
        variables["requestPayload"],
        r#"{"database":1,"version":12345678901234567890}"#
    );
}

#[test]
fn the_lightspeed_payload_is_found_and_failures_are_named() {
    let ok = r#"{"data":{"viewer":{"lightspeed_web_request":{"payload":"{\"step\":[]}","dependencies":[]}}},"extensions":{}}"#;
    assert_eq!(snapshot_payload(ok).unwrap(), r#"{"step":[]}"#);
    assert_eq!(
        snapshot_payload(&format!("for (;;);{ok}")).unwrap(),
        r#"{"step":[]}"#
    );
    assert_eq!(snapshot_payload("<html>"), Err(GraphqlError::NotJson));
    assert_eq!(
        snapshot_payload(r#"{"data":{"viewer":null}}"#),
        Err(GraphqlError::NoPayload)
    );
    assert!(matches!(
        snapshot_payload(r#"{"errors":[{"message":"Not logged in"}],"data":null}"#),
        Err(GraphqlError::Errors(e)) if e.contains("Not logged in")
    ));
}
