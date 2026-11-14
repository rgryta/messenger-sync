//! The page scrape against the shapes messenger.com ships (made-up values; structure as seen
//! by mautrix-meta's module parser and the harvester's own regexes).

use messenger_client::page::{PageError, define, scrape};

/// A cut of the page: scheduled server JS with `define` blocks, and a preloader whose request
/// payload is an escaped JSON string carrying a version past 2^63.
const PAGE: &str = r#"<script>requireLazy(["ServerJS"],function(s){(new s()).handle({"define":[
["CurrentUserInitialData",[],{"ACCOUNT_ID":"100000000000001","USER_ID":"100000000000001","NAME":"Test","APP_ID":"772021112871879"},270],
["DGWWebConfig",[],{"appId":"2220391788200892","appVersion":"0","dgwVersion":"2","endpoint":"","fbId":"0","authType":""},5795],
["MqttWebDeviceID",[],{"clientID":"0f4b2c1e-1111-4222-8333-944455556666"},5003],
["DTSGInitialData",[],{"token":"NAft-fake:12:1700000000"},258],
["LSD",[],{"token":"lsd-fake"},323],
["MessengerWebInitData",[],{"accountKey":"x","cryptoAuthToken":{"encrypted_serialized_cat":"cat-fake","expiration_time_in_seconds":1700086400}},4417]
]});});</script>
<script>{"__spin_r":1012345678,"__spin_b":"trunk"}</script>
<script>{"queryID":"7357407954267582","variables":{"deviceId":"0f4b2c1e-1111-4222-8333-944455556666","requestId":0,"requestPayload":"{\"database\":1,\"epoch_id\":0,\"last_applied_cursor\":null,\"sync_params\":\"{\\\"locale\\\":\\\"pl_PL\\\"}\",\"version\":12345678901234567890}","requestType":1}}</script>"#;

#[test]
fn every_value_the_gateway_needs_is_read() {
    let config = scrape(PAGE).unwrap();
    assert_eq!(config.user_id, "100000000000001");
    assert_eq!(config.app_id, "2220391788200892");
    assert_eq!(config.device_id, "0f4b2c1e-1111-4222-8333-944455556666");
    // Past i64: kept as text, not rounded through a number.
    assert_eq!(config.version, "12345678901234567890");
    assert_eq!(config.dtsg.as_deref(), Some("NAft-fake:12:1700000000"));
    assert_eq!(config.lsd.as_deref(), Some("lsd-fake"));
    assert_eq!(config.revision.as_deref(), Some("1012345678"));
    assert_eq!(config.crypto_auth_token.as_deref(), Some("cat-fake"));
}

#[test]
fn preloaders_keep_their_payload_as_exact_unescaped_text() {
    let config = scrape(PAGE).unwrap();
    assert_eq!(config.preloaders.len(), 1);
    let p = &config.preloaders[0];
    assert_eq!(p.query_id, "7357407954267582");
    assert_eq!(p.device_id, "0f4b2c1e-1111-4222-8333-944455556666");
    assert_eq!(p.database, 1);
    assert!(
        p.request_payload
            .starts_with(r#"{"database":1,"epoch_id":0"#),
        "{}",
        p.request_payload
    );
    // The version survives as written, past what a float holds.
    assert!(
        p.request_payload
            .ends_with(r#""version":12345678901234567890}"#)
    );
    // The nested sync params stay a string inside the payload.
    assert!(
        p.request_payload
            .contains(r#""sync_params":"{\"locale\":\"pl_PL\"}""#)
    );
}

#[test]
fn several_preloaders_are_all_found_and_broken_ones_skipped() {
    let second = PAGE.replace(r#"\"database\":1"#, r#"\"database\":95"#);
    let page = format!(
        "{PAGE}{second}{}",
        r#"{"queryID":"x1","variables":{"deviceId":"d"}}"#
    );
    let databases: Vec<u32> = scrape(&page)
        .unwrap()
        .preloaders
        .iter()
        .map(|p| p.database)
        .collect();
    assert_eq!(databases, [1, 95]);
}

#[test]
fn a_define_block_is_parsed_as_json_however_long() {
    let v = define(PAGE, "DGWWebConfig").unwrap();
    assert_eq!(v["dgwVersion"], "2");
    assert!(define(PAGE, "NoSuchModule").is_none());
}

#[test]
fn a_logged_out_page_and_missing_values_are_named() {
    let logged_out = PAGE.replace(r#""USER_ID":"100000000000001""#, r#""USER_ID":"0""#);
    assert_eq!(scrape(&logged_out), Err(PageError::LoggedOut));
    assert_eq!(scrape("<html>login</html>"), Err(PageError::LoggedOut));
    let no_device = PAGE.replace("MqttWebDeviceID", "SomethingElse");
    assert_eq!(
        scrape(&no_device),
        Err(PageError::Missing("MqttWebDeviceID.clientID"))
    );
    let no_version = PAGE.replace(r#"\"version\""#, r#"\"other\""#);
    assert_eq!(
        scrape(&no_version),
        Err(PageError::Missing("LightSpeed version"))
    );
}
