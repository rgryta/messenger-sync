//! The one GraphQL call the inbox needs: replaying the page's own
//! `LSPlatformGraphQLLightspeedRequestQuery` preloader returns a database's snapshot — its
//! threads and the cursors the socket continues from. The retired harvester's `__snapshot`
//! made this call from inside the page; mautrix-meta's `SyncDataGraphQL` makes it from outside.

use serde_json::{Value, json};

use crate::page::{PageConfig, Preloader};

/// The form body, field for field as the retired harvester's `__snapshot` sent it.
pub fn snapshot_form(config: &PageConfig, preloader: &Preloader) -> Vec<(&'static str, String)> {
    let variables = json!({
        "deviceId": preloader.device_id,
        "requestId": 0,
        "requestPayload": preloader.request_payload,
        "requestType": 1,
    });
    vec![
        ("av", config.user_id.clone()),
        ("__user", config.user_id.clone()),
        ("__a", "1".into()),
        ("__rev", config.revision.clone().unwrap_or_default()),
        ("fb_dtsg", config.dtsg.clone().unwrap_or_default()),
        ("lsd", config.lsd.clone().unwrap_or_default()),
        ("fb_api_caller_class", "RelayModern".into()),
        (
            "fb_api_req_friendly_name",
            "LSPlatformGraphQLLightspeedRequestQuery".into(),
        ),
        ("doc_id", preloader.query_id.clone()),
        ("variables", variables.to_string()),
    ]
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GraphqlError {
    #[error("the answer is not JSON")]
    NotJson,
    #[error("the answer carries errors: {0}")]
    Errors(String),
    #[error("the answer carries no lightspeed payload")]
    NoPayload,
}

/// The LightSpeed payload (a JSON string of steps) out of a GraphQL answer. Meta prefixes
/// some answers with `for (;;);` to defeat JSON hijacking; it is stripped.
pub fn snapshot_payload(body: &str) -> Result<String, GraphqlError> {
    let body = body.trim_start().strip_prefix("for (;;);").unwrap_or(body);
    let answer: Value = serde_json::from_str(body).map_err(|_| GraphqlError::NotJson)?;
    if let Some(errors) = answer.get("errors").filter(|e| !e.is_null()) {
        return Err(GraphqlError::Errors(
            errors.to_string().chars().take(300).collect(),
        ));
    }
    answer
        .pointer("/data/viewer/lightspeed_web_request/payload")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(GraphqlError::NoPayload)
}
