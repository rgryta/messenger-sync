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

/// A persisted query the history backup uses, by the friendly name and document id
/// mautrix-meta's `graphql.GraphQLDocs` lists. `once` marks the calls mautrix never
/// retries: each spends something on the server (a PIN attempt, an enrolment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Doc {
    pub name: &'static str,
    pub doc_id: &'static str,
    pub once: bool,
}

pub const BACKUP_IDS: Doc = Doc {
    name: "useMWEncryptedBackupsFetchBackupIdsV2Query",
    doc_id: "25220416984279164",
    once: false,
};
pub const VESTA_INIT: Doc = Doc {
    name: "VestaServerGraphQLLoginProviderInitQuery",
    doc_id: "28587565877599806",
    once: false,
};
pub const VESTA_BEGIN: Doc = Doc {
    name: "VestaServerGraphQLLoginProviderBeginLoginMutation",
    doc_id: "28781838094734033",
    once: true,
};
pub const VESTA_FINISH: Doc = Doc {
    name: "VestaServerGraphQLLoginProviderFinishLoginMutation",
    doc_id: "28557176640587196",
    once: true,
};
pub const VIRTUAL_DEVICE: Doc = Doc {
    name: "EBAddDeviceGraphQLEBFetchVirtualDeviceInfoQuery",
    doc_id: "27078903168382564",
    once: false,
};
pub const ADD_DEVICE: Doc = Doc {
    name: "EBAddDeviceMutation",
    doc_id: "26934669346130743",
    once: true,
};
pub const MESSAGE_RANGE: Doc = Doc {
    name: "EBMessageRangeQueryForThreadsQuery",
    doc_id: "28543107645309813",
    once: false,
};

/// The form body for a persisted query, as mautrix's `MakeGraphQLRequest` sends it.
pub fn doc_form(config: &PageConfig, doc: &Doc, variables: &Value) -> Vec<(&'static str, String)> {
    vec![
        ("av", config.user_id.clone()),
        ("__user", config.user_id.clone()),
        ("__a", "1".into()),
        ("__rev", config.revision.clone().unwrap_or_default()),
        ("fb_dtsg", config.dtsg.clone().unwrap_or_default()),
        ("lsd", config.lsd.clone().unwrap_or_default()),
        ("fb_api_caller_class", "RelayModern".into()),
        ("fb_api_req_friendly_name", doc.name.into()),
        ("server_timestamps", "true".into()),
        ("doc_id", doc.doc_id.into()),
        ("variables", variables.to_string()),
    ]
}

/// `data.<field>` of a GraphQL answer: `None` when the server answered `null`. An answer with
/// `errors`, or Meta's numeric `error` (a logged-out session among them), is an error.
pub fn data_field(body: &str, field: &str) -> Result<Option<Value>, GraphqlError> {
    let body = body.trim_start().strip_prefix("for (;;);").unwrap_or(body);
    let answer: Value = serde_json::from_str(body).map_err(|_| GraphqlError::NotJson)?;
    let failed = answer
        .get("errors")
        .filter(|e| !e.is_null() && e.as_array().is_none_or(|a| !a.is_empty()))
        .or_else(|| {
            answer
                .get("error")
                .filter(|e| !e.is_null() && **e != json!(0))
        });
    if let Some(errors) = failed {
        return Err(GraphqlError::Errors(
            errors.to_string().chars().take(300).collect(),
        ));
    }
    match answer.pointer(&format!("/data/{field}")) {
        None => Err(GraphqlError::NoPayload),
        Some(Value::Null) => Ok(None),
        Some(value) => Ok(Some(value.clone())),
    }
}
