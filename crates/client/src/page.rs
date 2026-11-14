//! What the messenger.com page tells a client before it can open the gateway.
//!
//! The page carries server-side `define` blocks — `["Name",[],{…},id]` inside its scheduled
//! JS — and GraphQL preloaders. Only a few values are needed: who is logged in, the gateway's
//! app id, this browser's device id, and the LightSpeed schema version. Rather than mautrix's
//! full module parser, each is read where it sits; `tests/page.rs` holds the shapes.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageConfig {
    pub user_id: String,
    /// `DGWWebConfig.appId`: the gateway's `x-dgw-appid`, and every LS request's `app_id`.
    pub app_id: String,
    /// `MqttWebDeviceID.clientID`: the gateway's `x-dgw-deviceid`.
    pub device_id: String,
    /// The LightSpeed schema version, kept as text: it can exceed 2^63.
    pub version: String,
    /// `DTSGInitialData.token`, for GraphQL calls.
    pub dtsg: Option<String>,
    /// `LSD.token`, GraphQL's second token.
    pub lsd: Option<String>,
    /// `__spin_r`, the site revision GraphQL calls name.
    pub revision: Option<String>,
    /// The page's LightSpeed GraphQL preloaders, one per database.
    pub preloaders: Vec<Preloader>,
    /// `MessengerWebInitData.cryptoAuthToken.encrypted_serialized_cat`: the encrypted chat's
    /// login token (see [`crate::e2ee`]).
    pub crypto_auth_token: Option<String>,
}

/// A `LSPlatformGraphQLLightspeedRequestQuery` the page would have run: replayed as is, it
/// returns that database's snapshot, with the cursors the socket continues from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preloader {
    pub query_id: String,
    pub device_id: String,
    /// The request payload, unescaped but never parsed: its 20-digit `version` would not
    /// survive a round trip through a float (the harvester measured an empty inbox when it
    /// did not).
    pub request_payload: String,
    pub database: u32,
}

/// `"queryID":"…","variables":{"deviceId":"…","requestId":N,"requestPayload":"…"`, the
/// harvester's own pattern, scanned without a regex engine.
fn preloaders(html: &str) -> Vec<Preloader> {
    let mut found = Vec::new();
    let mut rest = html;
    while let Some(at) = rest.find("\"queryID\":\"") {
        rest = &rest[at + "\"queryID\":\"".len()..];
        let Some((query_id, after)) = rest.split_once('"') else {
            break;
        };
        let Some(after) = after.strip_prefix(",\"variables\":{\"deviceId\":\"") else {
            continue;
        };
        let Some((device_id, after)) = after.split_once('"') else {
            continue;
        };
        let Some(after) = after.strip_prefix(",\"requestId\":") else {
            continue;
        };
        let after = after.trim_start_matches(|c: char| c.is_ascii_digit());
        let Some(after) = after.strip_prefix(",\"requestPayload\":") else {
            continue;
        };
        // The payload is a JSON string literal; let the JSON parser find its end.
        let Some(Ok(serde_json::Value::String(payload))) =
            serde_json::Deserializer::from_str(after)
                .into_iter::<serde_json::Value>()
                .next()
        else {
            continue;
        };
        let database = payload
            .split_once("\"database\":")
            .map(|(_, d)| {
                d.chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
            })
            .and_then(|d| d.parse().ok());
        if let Some(database) = database
            && query_id.chars().all(|c| c.is_ascii_digit())
        {
            found.push(Preloader {
                query_id: query_id.to_owned(),
                device_id: device_id.to_owned(),
                request_payload: payload,
                database,
            });
        }
    }
    found
}

fn revision(html: &str) -> Option<String> {
    let at = html.find("\"__spin_r\":")? + "\"__spin_r\":".len();
    let digits: String = html[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    (!digits.is_empty()).then_some(digits)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PageError {
    /// The cookies are no longer a session: the page is the login form.
    #[error("the page is not logged in")]
    LoggedOut,
    #[error("the page carries no {0}")]
    Missing(&'static str),
}

/// The object a `define` block holds: the JSON right after `"Name",[],`.
pub fn define(html: &str, name: &str) -> Option<Value> {
    let marker = format!("[\"{name}\",[],");
    let start = html.find(&marker)? + marker.len();
    serde_json::Deserializer::from_str(&html[start..])
        .into_iter::<Value>()
        .next()?
        .ok()
}

/// The LightSpeed version from the first preloader's request payload, which the page embeds
/// as an escaped JSON string: `"requestPayload":"{…\"version\":123…}"`.
fn version(html: &str) -> Option<String> {
    let payload = html.find("\"requestPayload\":\"")?;
    let rest = &html[payload..];
    let at = rest.find("\\\"version\\\":")? + "\\\"version\\\":".len();
    let digits: String = rest[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    (!digits.is_empty()).then_some(digits)
}

pub fn scrape(html: &str) -> Result<PageConfig, PageError> {
    let text = |v: Option<Value>, key: &str| -> Option<String> {
        match v?.get(key)? {
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    };
    let user_id = text(define(html, "CurrentUserInitialData"), "USER_ID")
        .filter(|id| id != "0")
        .ok_or(PageError::LoggedOut)?;
    Ok(PageConfig {
        user_id,
        app_id: text(define(html, "DGWWebConfig"), "appId")
            .ok_or(PageError::Missing("DGWWebConfig.appId"))?,
        device_id: text(define(html, "MqttWebDeviceID"), "clientID")
            .ok_or(PageError::Missing("MqttWebDeviceID.clientID"))?,
        version: version(html).ok_or(PageError::Missing("LightSpeed version"))?,
        dtsg: text(define(html, "DTSGInitialData"), "token"),
        lsd: text(define(html, "LSD"), "token"),
        revision: revision(html),
        preloaders: preloaders(html),
        crypto_auth_token: define(html, "MessengerWebInitData")
            .as_ref()
            .and_then(|init| init.get("cryptoAuthToken")?.get("encrypted_serialized_cat"))
            .and_then(Value::as_str)
            .filter(|cat| !cat.is_empty())
            .map(str::to_owned),
    })
}
