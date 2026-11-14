//! The gateway socket: one websocket to `gateway.messenger.com`, multiplexing LightSpeed
//! streams over the DGW framing in `dgw`.
//!
//! The sequence is the one `messenger-connect-check` proved live. A database's sync stream
//! stays open for the whole connection, and it is where everything arrives, including the
//! answer to a message-page task: that is pushed down the sync stream, while the task's own
//! one-off stream says only `taskExists`/`removeTask`. Stream ids count from 0, LS request
//! ids from 1. The client pings every 10 s and gives up after 30 s of silence, as mautrix's
//! `dgw/socket.go` does.
//!
//! [`Gateway`] is the part the daemon uses, so its walks run against a fake in the tests.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::time::{Instant, Interval};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest, http::HeaderValue};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::cookies::Jar;
use crate::dgw::Frame;
use crate::ls;
use crate::page::PageConfig;

const URL: &str = "wss://gateway.messenger.com/ws/lightspeed";
const HOST: &str = "gateway.messenger.com";
pub const BASE: &str = "https://www.messenger.com";
/// mautrix-meta's `useragent.UserAgent`: a desktop Chrome on Linux.
pub const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const PING_INTERVAL: Duration = Duration::from_secs(10);
const PONG_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum Event {
    /// Steps pushed on the sync stream of `database`.
    Sync { database: u32, steps: Value },
    /// A one-off task stream answered and was closed.
    TaskDone,
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// The session is no longer authorised.
    #[error("the gateway de-authorised the session")]
    Deauth,
    #[error("the gateway connection ended: {0}")]
    Closed(String),
    #[error("gateway: {0}")]
    Socket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("gateway framing: {0}")]
    Frame(#[from] crate::dgw::DgwError),
}

#[allow(async_fn_in_trait)] // only used with concrete types: the socket, and the tests' fake
pub trait Gateway {
    /// Opens the persistent sync stream continuing `database` from `cursor`.
    async fn open_sync(&mut self, database: u32, cursor: &str) -> Result<(), GatewayError>;
    /// Sends one task on a new one-off stream.
    async fn send_task(
        &mut self,
        label: &str,
        queue: &str,
        payload: Value,
    ) -> Result<(), GatewayError>;
    /// The next event, or `None` once `deadline` has passed.
    async fn next_event(&mut self, deadline: Instant) -> Result<Option<Event>, GatewayError>;
}

enum Stream {
    Sync(u32),
    Task,
}

pub struct Socket {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    app_id: String,
    version: String,
    next_stream: u16,
    next_request: u16,
    epochs: i64,
    streams: HashMap<u16, Stream>,
    pending: VecDeque<Event>,
    ping: Interval,
    last_heard: Instant,
}

impl Socket {
    /// Connects as `messenger-connect-check` does. Cookies the upgrade sets go into `jar`.
    pub async fn connect(config: &PageConfig, jar: &mut Jar) -> Result<Self, GatewayError> {
        let logging_id = format!("{:032x}", rand::random::<u128>());
        let url = format!(
            "{URL}?x-dgw-appid={}&x-dgw-appversion=0&x-dgw-authtype=1%3A0&x-dgw-version=5&x-dgw-uuid={}&x-dgw-tier=prod&x-dgw-loggingid={}&x-dgw-deviceid={}",
            config.app_id, config.user_id, logging_id, config.device_id
        );
        let mut request = url.into_client_request()?;
        let headers = request.headers_mut();
        let header = |v: &str| {
            HeaderValue::from_str(v)
                .map_err(|_| GatewayError::Closed("a header value is not text".into()))
        };
        headers.insert(
            "cookie",
            header(&jar.header(HOST, "/ws/lightspeed", Utc::now()))?,
        );
        headers.insert("user-agent", header(USER_AGENT)?);
        headers.insert("origin", header(BASE)?);
        headers.insert("sec-fetch-dest", header("empty")?);
        headers.insert("sec-fetch-mode", header("websocket")?);
        headers.insert("sec-fetch-site", header("same-site")?);
        let (ws, upgrade) = tokio_tungstenite::connect_async(request).await?;
        for value in upgrade.headers().get_all("set-cookie") {
            if let Ok(v) = value.to_str() {
                jar.set(v, HOST, Utc::now());
            }
        }
        Ok(Socket {
            ws,
            app_id: config.app_id.clone(),
            version: config.version.clone(),
            next_stream: 0,
            next_request: 1,
            epochs: 0,
            streams: HashMap::new(),
            pending: VecDeque::new(),
            ping: tokio::time::interval_at(Instant::now() + PING_INTERVAL, PING_INTERVAL),
            last_heard: Instant::now(),
        })
    }

    pub async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }

    async fn send(&mut self, frames: &[Frame]) -> Result<(), GatewayError> {
        let mut out = Vec::new();
        for frame in frames {
            frame.encode(&mut out);
        }
        self.ws.send(Message::binary(out)).await?;
        Ok(())
    }

    /// mautrix's epoch counter is 10 bits wide.
    fn epoch(&mut self) -> i64 {
        self.epochs += 1;
        ls::epoch_id(Utc::now().timestamp_millis(), self.epochs & 0x3ff)
    }

    fn request_id(&mut self) -> u16 {
        let id = self.next_request;
        self.next_request = self.next_request.wrapping_add(1).max(1);
        id
    }

    /// A new stream carrying one request that must be acknowledged.
    async fn open(&mut self, kind: Stream, payload: Vec<u8>) -> Result<(), GatewayError> {
        let stream = self.next_stream;
        self.next_stream = self.next_stream.wrapping_add(1);
        self.streams.insert(stream, kind);
        self.send(&[
            Frame::Establish {
                stream,
                parameters: b"{}".to_vec(),
            },
            Frame::Data {
                stream,
                ack_id: 0,
                requires_ack: true,
                content_type: None,
                payload,
            },
        ])
        .await
    }

    /// Every frame of one websocket message: replies go out together, events queue up.
    async fn handle(&mut self, bytes: &[u8]) -> Result<(), GatewayError> {
        let mut reply = Vec::new();
        for frame in Frame::decode_all(bytes)? {
            match frame {
                Frame::Ping => reply.push(Frame::Pong),
                Frame::Deauth => return Err(GatewayError::Deauth),
                Frame::Drain { reason } => {
                    return Err(GatewayError::Closed(format!("drain ({reason})")));
                }
                Frame::Data {
                    stream,
                    ack_id,
                    requires_ack,
                    payload,
                    ..
                } => {
                    if requires_ack {
                        reply.push(Frame::Ack {
                            stream,
                            ack: ack_id,
                        });
                    }
                    match self.streams.get(&stream) {
                        Some(Stream::Sync(database)) => {
                            let database = *database;
                            let steps = serde_json::from_slice::<ls::Response>(&payload)
                                .ok()
                                .and_then(|r| r.steps().ok());
                            match steps {
                                Some(steps) => {
                                    self.pending.push_back(Event::Sync { database, steps })
                                }
                                None => tracing::warn!(
                                    stream,
                                    "skipped a sync push that does not parse"
                                ),
                            }
                        }
                        Some(Stream::Task) => {
                            // A one-off stream is done once it has answered.
                            self.streams.remove(&stream);
                            reply.push(Frame::EndOfData {
                                stream,
                                reason: None,
                            });
                            self.pending.push_back(Event::TaskDone);
                        }
                        None => {}
                    }
                }
                Frame::EndOfData { stream, .. } => {
                    if let Some(Stream::Task) = self.streams.get(&stream) {
                        self.streams.remove(&stream);
                        self.pending.push_back(Event::TaskDone);
                    }
                }
                _ => {}
            }
        }
        if !reply.is_empty() {
            self.send(&reply).await?;
        }
        Ok(())
    }
}

impl Gateway for Socket {
    async fn open_sync(&mut self, database: u32, cursor: &str) -> Result<(), GatewayError> {
        let (epoch, request_id) = (self.epoch(), self.request_id());
        let query = ls::database_query(database, cursor, &self.version, epoch);
        let request = ls::sync_request(&self.app_id, &query, request_id);
        self.open(Stream::Sync(database), request).await
    }

    async fn send_task(
        &mut self,
        label: &str,
        queue: &str,
        payload: Value,
    ) -> Result<(), GatewayError> {
        let (request_id, epoch) = (self.request_id(), self.epoch());
        let request = ls::task_request(
            &self.app_id,
            &self.version,
            request_id,
            epoch,
            &[(label, queue, payload)],
        );
        self.open(Stream::Task, request).await
    }

    async fn next_event(&mut self, deadline: Instant) -> Result<Option<Event>, GatewayError> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(Some(event));
            }
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => return Ok(None),
                _ = self.ping.tick() => {
                    if self.last_heard.elapsed() > PONG_TIMEOUT {
                        return Err(GatewayError::Closed("nothing heard for 30 s".into()));
                    }
                    self.send(&[Frame::Ping]).await?;
                }
                message = self.ws.next() => {
                    self.last_heard = Instant::now();
                    match message {
                        None => return Err(GatewayError::Closed("end of stream".into())),
                        Some(Err(e)) => return Err(e.into()),
                        Some(Ok(Message::Binary(bytes))) => self.handle(&bytes).await?,
                        Some(Ok(Message::Close(frame))) => {
                            return Err(GatewayError::Closed(format!("{frame:?}")));
                        }
                        Some(Ok(_)) => {}
                    }
                }
            }
        }
    }
}
