//! Read-only proof that the browser is not needed for the inbox: load messenger.com with the
//! adopted cookies, take the inbox and encrypted-thread snapshots over GraphQL as the page
//! would, then ask the gateway for one page of the newest thread's messages — and say what
//! came back as counts and stored-procedure names only, never a name, message or id.
//!
//!   messenger-connect-check <cookies.json> [device.json [seconds]]
//!
//! Given a device export too (`MESSENGER_DEVICE_FROM`'s format), it instead logs in to the
//! encrypted chat as that device after the page, and says what the server sends for a while
//! (8 s by default), as tags and attribute names. Each message is decrypted in memory and
//! described by shape only: payload kinds, what the content decoded to, a text's length. It
//! acknowledges nothing and saves no session, so the server keeps every message queued for
//! the device, and the browser still opens it with its own, unchanged sessions.
//!
//! It sends nothing that changes the account: no message, no read receipt, no presence. The
//! cookie and device files are only read; rotations Meta sends are applied in memory and
//! dropped.

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::time::Duration;

use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use messenger_client::armadillo::Content;
use messenger_client::cookies::Jar;
use messenger_client::dgw::Frame;
use messenger_client::ls::{self, FETCH_MESSAGES};
use messenger_client::{device, e2ee, graphql, inbox, page};
use serde_json::Value;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest, http::HeaderValue};

const BASE: &str = "https://www.messenger.com";
const HOST: &str = "www.messenger.com";
const GATEWAY: &str = "wss://gateway.messenger.com/ws/lightspeed";
/// mautrix-meta's `useragent.UserAgent`: a desktop Chrome on Linux.
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const SEC_CH_UA: &str = r#""Chromium";v="141", "Google Chrome";v="141", "Not-A.Brand";v="99""#;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: messenger-connect-check <cookies.json> [device.json]");
        return ExitCode::from(2);
    };
    match run(&path, std::env::args().nth(2).as_deref()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("FAILED: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Stored-procedure names and how often each appears, for a summary that holds no content.
fn summary(steps: &Value) -> String {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for name in ls::procedure_calls(steps) {
        *counts.entry(name).or_default() += 1;
    }
    counts
        .iter()
        .map(|(n, c)| format!("    {c:5}  {n}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn take_cookies(jar: &mut Jar, headers: &reqwest::header::HeaderMap) -> Vec<String> {
    let mut names = Vec::new();
    for value in headers.get_all("set-cookie") {
        if let Ok(v) = value.to_str() {
            names.push(v.split('=').next().unwrap_or("").to_owned());
            jar.set(v, HOST, Utc::now());
        }
    }
    names
}

async fn run(path: &str, device: Option<&str>) -> Result<(), String> {
    let mut jar = Jar::from_json(&std::fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("cookie file: {e}"))?;
    if jar.get("c_user").is_none() || jar.get("xs").is_none() {
        return Err("the cookie file holds no session (c_user, xs)".into());
    }
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;

    // 1. The page, as a browser navigation.
    let response = http
        .get(format!("{BASE}/"))
        .header("user-agent", USER_AGENT)
        .header(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .header("accept-language", "pl-PL,pl;q=0.9,en;q=0.8")
        .header("sec-ch-ua", SEC_CH_UA)
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", "\"Linux\"")
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-site", "none")
        .header("sec-fetch-user", "?1")
        .header("upgrade-insecure-requests", "1")
        .header("cookie", jar.header(HOST, "/", Utc::now()))
        .send()
        .await
        .map_err(|e| format!("page: {e}"))?;
    let status = response.status();
    let rotated = take_cookies(&mut jar, response.headers());
    println!("page: HTTP {status}, cookies set: {rotated:?}");
    if status.is_redirection() {
        return Err("the page redirected: the session is not accepted".into());
    }
    let html = response.text().await.map_err(|e| e.to_string())?;
    let config = page::scrape(&html).map_err(|e| format!("page scrape: {e}"))?;
    println!(
        "page: logged in, app id {}, LS version {} digits, dtsg {}, lsd {}, revision {}, preloaders for databases {:?}",
        config.app_id,
        config.version.len(),
        config.dtsg.is_some(),
        config.lsd.is_some(),
        config.revision.is_some(),
        config
            .preloaders
            .iter()
            .map(|p| p.database)
            .collect::<Vec<_>>(),
    );

    if let Some(device) = device {
        let seconds = std::env::args()
            .nth(3)
            .and_then(|s| s.parse().ok())
            .unwrap_or(8);
        return e2ee_login(&config, device, seconds).await;
    }

    // 2. The snapshots, as the page's own preloaders.
    let mut inbox = Vec::new();
    let mut cursor = None;
    for database in [1, 95] {
        let Some(preloader) = config.preloaders.iter().find(|p| p.database == database) else {
            println!("snapshot {database}: the page has no preloader for it");
            continue;
        };
        let response = http
            .post(format!("{BASE}/api/graphql/"))
            .header("user-agent", USER_AGENT)
            .header("accept", "*/*")
            .header("accept-language", "pl-PL,pl;q=0.9,en;q=0.8")
            .header("origin", BASE)
            .header("referer", format!("{BASE}/"))
            .header("sec-ch-ua", SEC_CH_UA)
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"Linux\"")
            .header("sec-fetch-dest", "empty")
            .header("sec-fetch-mode", "cors")
            .header("sec-fetch-site", "same-origin")
            .header("x-asbd-id", "359341")
            .header(
                "x-fb-friendly-name",
                "LSPlatformGraphQLLightspeedRequestQuery",
            )
            .header("x-fb-lsd", config.lsd.clone().unwrap_or_default())
            .header("cookie", jar.header(HOST, "/api/graphql/", Utc::now()))
            .form(&graphql::snapshot_form(&config, preloader))
            .send()
            .await
            .map_err(|e| format!("snapshot {database}: {e}"))?;
        let status = response.status();
        let rotated = take_cookies(&mut jar, response.headers());
        let body = response.text().await.map_err(|e| e.to_string())?;
        let payload = graphql::snapshot_payload(&body)
            .map_err(|e| format!("snapshot {database} (HTTP {status}): {e}"))?;
        let steps: Value = serde_json::from_str::<Value>(&payload)
            .map_err(|e| format!("snapshot {database} payload: {e}"))?
            .get("step")
            .cloned()
            .unwrap_or(Value::Null);
        let threads = ls::threads(&steps);
        println!(
            "snapshot {database}: HTTP {status}, cookies set {rotated:?}, {} threads listed, procedures:\n{}",
            threads.len(),
            summary(&steps)
        );
        if database == 1 {
            inbox = threads;
            cursor = ls::sync_cursor(&steps);
            if cursor.is_none() {
                println!(
                    "snapshot 1: sync block argument types {:?}",
                    ls::sync_block_shapes(&steps)
                );
            }
        }
    }

    // 3. The inbox's sync stream, continued from the snapshot's cursor, as mautrix does: task
    //    results are pushed down it, not answered on the task's own stream.
    let cursor = cursor.ok_or("the inbox snapshot carried no sync cursor")?;
    println!(
        "sync: database {} cursor present (current {:?} chars, next {} chars)",
        cursor.database,
        cursor.current.as_ref().map(String::len),
        cursor.next.len()
    );
    let Some((thread, _)) = inbox.iter().max_by_key(|(_, at)| at.unwrap_or(0)).cloned() else {
        return Err("the inbox snapshot listed no thread to page".into());
    };
    let thread: i64 = thread
        .parse()
        .map_err(|_| "a thread key that is not a number")?;
    let logging_id = format!("{:032x}", rand::random::<u128>());
    let url = format!(
        "{GATEWAY}?x-dgw-appid={}&x-dgw-appversion=0&x-dgw-authtype=1%3A0&x-dgw-version=5&x-dgw-uuid={}&x-dgw-tier=prod&x-dgw-loggingid={}&x-dgw-deviceid={}",
        config.app_id, config.user_id, logging_id, config.device_id
    );
    let mut request = url.into_client_request().map_err(|e| e.to_string())?;
    let headers = request.headers_mut();
    let header = |v: &str| HeaderValue::from_str(v).expect("header text");
    headers.insert(
        "cookie",
        header(&jar.header("gateway.messenger.com", "/ws/lightspeed", Utc::now())),
    );
    headers.insert("user-agent", header(USER_AGENT));
    headers.insert("origin", header(BASE));
    headers.insert("sec-fetch-dest", header("empty"));
    headers.insert("sec-fetch-mode", header("websocket"));
    headers.insert("sec-fetch-site", header("same-site"));
    let (mut socket, upgrade) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| format!("gateway: {e}"))?;
    println!("gateway: connected (HTTP {})", upgrade.status());

    // Stream 0 stays open: the database-1 sync. Stream 1 is the one-off message-page task,
    // sent once the sync has answered.
    let query = ls::database_query(
        cursor.database,
        &cursor.next,
        &config.version,
        ls::epoch_id(Utc::now().timestamp_millis(), 0),
    );
    let mut out = Vec::new();
    Frame::Establish {
        stream: 0,
        parameters: b"{}".to_vec(),
    }
    .encode(&mut out);
    Frame::Data {
        stream: 0,
        ack_id: 0,
        requires_ack: true,
        content_type: None,
        payload: ls::sync_request(&config.app_id, &query, 1),
    }
    .encode(&mut out);
    socket
        .send(Message::binary(out))
        .await
        .map_err(|e| e.to_string())?;

    let mut sync_steps: Vec<Value> = Vec::new();
    let mut task_steps: Vec<Value> = Vec::new();
    let mut events: Vec<String> = Vec::new();
    let mut task_sent = false;
    // Long enough for the sync answer, the task and the pushes it causes; then stop.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    loop {
        let message = match tokio::time::timeout_at(deadline, socket.next()).await {
            Err(_) => break,
            Ok(None) => return Err("the gateway closed the connection".into()),
            Ok(Some(m)) => m.map_err(|e| format!("gateway read: {e}"))?,
        };
        let Message::Binary(bytes) = message else {
            if let Message::Close(frame) = message {
                return Err(format!("the gateway closed: {frame:?}"));
            }
            continue;
        };
        for frame in Frame::decode_all(&bytes).map_err(|e| e.to_string())? {
            match frame {
                Frame::Ping => {
                    let mut pong = Vec::new();
                    Frame::Pong.encode(&mut pong);
                    socket
                        .send(Message::binary(pong))
                        .await
                        .map_err(|e| e.to_string())?;
                }
                Frame::Establish { stream, parameters } => {
                    events.push(format!(
                        "stream {stream} established {}",
                        String::from_utf8_lossy(&parameters)
                    ));
                }
                Frame::Ack { stream, ack } => events.push(format!("stream {stream} acked {ack}")),
                Frame::Data {
                    stream,
                    ack_id,
                    requires_ack,
                    payload,
                    ..
                } => {
                    let mut reply = Vec::new();
                    if requires_ack {
                        Frame::Ack {
                            stream,
                            ack: ack_id,
                        }
                        .encode(&mut reply);
                    }
                    if stream == 1 {
                        Frame::EndOfData {
                            stream,
                            reason: None,
                        }
                        .encode(&mut reply);
                    }
                    if !reply.is_empty() {
                        socket
                            .send(Message::binary(reply))
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    let response: ls::Response = serde_json::from_slice(&payload)
                        .map_err(|e| format!("stream {stream} data: {e}"))?;
                    let steps = response
                        .steps()
                        .map_err(|e| format!("stream {stream} payload: {e}"))?;
                    events.push(format!(
                        "stream {stream} data (request {:?}, {} procedure calls)",
                        response.request_id,
                        ls::procedure_calls(&steps).len()
                    ));
                    if stream == 0 {
                        sync_steps.push(steps);
                    } else {
                        task_steps.push(steps);
                    }
                    if stream == 0 && !task_sent {
                        task_sent = true;
                        let queue = format!("mrq.{thread}");
                        let task = ls::task_request(
                            &config.app_id,
                            &config.version,
                            2,
                            ls::epoch_id(Utc::now().timestamp_millis(), 1),
                            &[(
                                FETCH_MESSAGES,
                                &queue,
                                ls::fetch_messages(thread, Utc::now().timestamp_millis(), 1),
                            )],
                        );
                        let mut out = Vec::new();
                        Frame::Establish {
                            stream: 1,
                            parameters: b"{}".to_vec(),
                        }
                        .encode(&mut out);
                        Frame::Data {
                            stream: 1,
                            ack_id: 0,
                            requires_ack: true,
                            content_type: None,
                            payload: task,
                        }
                        .encode(&mut out);
                        socket
                            .send(Message::binary(out))
                            .await
                            .map_err(|e| e.to_string())?;
                        events.push("message-page task sent on stream 1".into());
                    }
                }
                Frame::Deauth => return Err("the gateway de-authorised the session".into()),
                Frame::EndOfData { stream, reason } => {
                    events.push(format!("stream {stream} ended ({reason:?})"))
                }
                Frame::Drain { reason } => events.push(format!("drain ({reason})")),
                _ => {}
            }
        }
    }
    let _ = socket.close(None).await;
    for event in &events {
        println!("  {event}");
    }
    println!(
        "sync stream (database 1), everything pushed in 25 s:\n{}",
        summary(&Value::Array(sync_steps))
    );
    println!(
        "message-page task stream:\n{}",
        summary(&Value::Array(task_steps))
    );
    Ok(())
}

/// Logs in to the encrypted chat as the exported device and listens for a few seconds.
async fn e2ee_login(config: &page::PageConfig, path: &str, seconds: u64) -> Result<(), String> {
    let json = std::fs::read(path).map_err(|e| format!("device file: {e}"))?;
    let (keys, messenger) = device::import(&json).map_err(|e| e.to_string())?;
    let cat = config
        .crypto_auth_token
        .as_deref()
        .ok_or("the page carries no crypto auth token")?;
    let (mut conn, first) = e2ee::connect(&keys, &messenger, cat)
        .await
        .map_err(|e| format!("e2ee: {e}"))?;
    let names: Vec<&str> = first.attrs.iter().map(|(k, _)| k.as_str()).collect();
    println!("e2ee: first node <{}> with attributes {names:?}", first.tag);
    if first.tag != "success" {
        let reason = first.attrs.iter().find(|(k, _)| k == "reason");
        println!("e2ee: login refused, reason {:?}", reason.map(|(_, v)| v));
        return Err("the encrypted chat refused the login".into());
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut store = keys.signal_store();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    while let Ok(next) = tokio::time::timeout_at(deadline, conn.recv()).await {
        match next.map_err(|e| format!("e2ee: {e}"))? {
            Some(node) => {
                if node.tag == "message" {
                    describe(&mut store, &node, &messenger.fbid);
                }
                let label = match node.attrs.iter().find(|(k, _)| k == "type") {
                    Some((_, value)) if node.tag != "message" => {
                        format!("{} type={value:?}", node.tag)
                    }
                    _ => node.tag.clone(),
                };
                *counts.entry(label).or_default() += 1;
            }
            None => {
                println!("e2ee: the server closed the connection");
                break;
            }
        }
    }
    println!("e2ee: in {seconds} s the server sent {counts:?}");
    conn.close().await.map_err(|e| format!("e2ee close: {e}"))?;
    Ok(())
}

/// A received message by shape: never its text, id or people.
fn describe(
    store: &mut whatsapp_client::signal::Store,
    node: &whatsapp_client::binary::Node,
    me: &str,
) {
    let attrs: Vec<&str> = node.attrs.iter().map(|(k, _)| k.as_str()).collect();
    let encs: Vec<String> = node
        .children()
        .iter()
        .map(|c| match (c.get("type"), c.get("v")) {
            (Some(t), Some(v)) => format!("{}:{t}/v{v}", c.tag),
            _ => c.tag.clone(),
        })
        .collect();
    let opened = match inbox::receive(store, node, me) {
        Ok(r) => {
            let parts: Vec<String> = r
                .parts
                .iter()
                .map(|p| match p {
                    inbox::Part::Failed(why) => format!("failed ({why})"),
                    inbox::Part::Content(Content::Text { text, reply_to }) => format!(
                        "text of {} chars{}",
                        text.chars().count(),
                        if reply_to.is_some() { ", a reply" } else { "" }
                    ),
                    inbox::Part::Content(Content::Media { kind, caption, .. }) => {
                        format!(
                            "{kind}{}",
                            if caption.is_some() {
                                " with a caption"
                            } else {
                                ""
                            }
                        )
                    }
                    inbox::Part::Content(Content::Edit { text, .. }) => {
                        format!("an edit to {} chars", text.chars().count())
                    }
                    inbox::Part::Content(Content::Revoke { .. }) => "an unsend".into(),
                    inbox::Part::Content(Content::Reaction { emoji, .. }) => {
                        format!(
                            "a reaction{}",
                            if emoji.is_empty() { " removed" } else { "" }
                        )
                    }
                    inbox::Part::Content(Content::Other(what)) => format!("other: {what}"),
                })
                .collect();
            format!(
                "from me {}, sender device {}, timestamp {}, parts {parts:?}",
                r.from_me,
                r.sender.device,
                r.timestamp.is_some()
            )
        }
        Err(e) => format!("not read: {e}"),
    };
    println!("e2ee: <message> attributes {attrs:?}, children {encs:?}: {opened}");
}
