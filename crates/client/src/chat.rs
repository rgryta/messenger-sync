//! The encrypted chat, kept connected as the adopted device: what arrives is decrypted,
//! stored, then acknowledged.
//!
//! Ported from whatsmeow (`client.go`, `keepalive.go`, `message.go`, `receipt.go`,
//! `connectionevents.go`, `pair.go`) as mautrix-meta runs it for Messenger. Receive-only:
//! it never sends a message, a read receipt or presence. What it does send is what any
//! device must, or the server drops it: the `active` IQ after login, a keepalive every
//! 20-30 s, answers to the server's pings, an ack for every receipt and notification, and
//! for each message a delivery receipt, `inactive` like whatsmeow's default, so nothing
//! reads as seen.
//!
//! Order per message: decrypt, save the session it moved, store the event, then receipt.
//! A crash before the receipt means the server sends it again; the session already moved
//! past it, so it no longer opens, and is acknowledged without a second copy.

use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use messenger_core::store::e2ee::{self as archive, Stored};
use sqlx::PgPool;
use tokio::sync::watch;
use tokio::time::Instant;
use whatsapp_client::baileys::Device;
use whatsapp_client::binary::{Content, Node, Value};
use whatsapp_client::conn::{ConnError, Outbox};
use whatsapp_client::prekeys;
use whatsapp_client::signal::curve::KeyPair;
use whatsapp_client::signal::{Address, Store};
use whatsapp_client::stanza::{self, bytes, pre_key_node, signed_pre_key_node};
use whatsapp_client::store::{self as keys, StoreError};

use crate::device::Messenger;
use crate::e2ee;
use crate::inbox::{self, Part};

const KEEPALIVE_MIN: Duration = Duration::from_secs(20);
const KEEPALIVE_MAX: Duration = Duration::from_secs(30);
/// Silence for this long means the connection is gone, whatever the socket says.
const LOST_AFTER: Duration = Duration::from_secs(90);
/// whatsmeow's `NackParsingError`: a stanza that cannot be read at all.
const NACK_PARSING_ERROR: u16 = 487;
/// The loop's name in `sync_state`, for the status tool.
pub const LOOP: &str = "e2ee";
/// whatsmeow gives up on a message after this many retry receipts.
const MAX_RETRIES: u32 = 5;
/// whatsmeow's `MinPreKeyCount` and `WantedPreKeyCount`: top up below the first, to the second.
const MIN_PRE_KEYS: u32 = 5;
const WANTED_PRE_KEYS: u32 = 50;

#[derive(Debug, thiserror::Error)]
pub enum ChatError {
    #[error(transparent)]
    Conn(#[from] ConnError),
    #[error(transparent)]
    Keys(#[from] StoreError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
}

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// Closed or lost: connect again.
    Closed,
    /// Another client logged in as this device.
    Replaced,
    /// The server no longer accepts this device.
    LoggedOut,
}

/// What [`Chat::handle`] did with a stanza, for the log's counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handled {
    Stored,
    /// Held until its thread is known.
    Held,
    /// Opened, but nothing in it for the archive, or it repeated what was stored.
    Nothing,
    /// Did not open.
    Failed,
    Other,
}

pub struct Chat {
    pool: PgPool,
    account: String,
    messenger: Messenger,
    device: Device,
    signal: Store,
    /// Retry receipts sent per message id. In memory, as whatsmeow keeps it: a restart
    /// starts over from the count the resent message carries.
    retries: HashMap<String, u32>,
}

impl Chat {
    pub fn new(pool: PgPool, account: String, device: Device, messenger: Messenger) -> Self {
        let signal = device.signal_store();
        Self {
            pool,
            account,
            messenger,
            device,
            signal,
            retries: HashMap::new(),
        }
    }

    /// Stays connected, reconnecting after anything but a logout or a takeover, with the
    /// newest crypto auth token the page gave (`cat`).
    pub async fn run(mut self, mut cat: watch::Receiver<Option<String>>) {
        let mut backoff = Duration::from_secs(2);
        loop {
            let Some(token) = cat.borrow_and_update().clone() else {
                // No page loaded yet: wait for the first.
                if cat.changed().await.is_err() {
                    return;
                }
                continue;
            };
            let started = Instant::now();
            match self.serve(&token, &mut cat).await {
                Ok(Ended::LoggedOut) => {
                    return self
                        .park("the encrypted chat no longer accepts this device")
                        .await;
                }
                Ok(Ended::Replaced) => {
                    return self.park("another client logged in as this device").await;
                }
                Ok(Ended::Closed) => tracing::warn!("encrypted chat closed"),
                Err(e) => {
                    tracing::error!("encrypted chat failed: {e}");
                    let _ = self.mark(Some(&e.to_string())).await;
                }
            }
            if started.elapsed() > Duration::from_secs(300) {
                backoff = Duration::from_secs(2);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }

    /// Records why, then waits: reconnecting would only repeat the refusal, and a second
    /// client fighting the first for the device would desync both.
    async fn park(&self, why: &str) {
        tracing::error!("{why}; not reconnecting");
        let _ = self.mark(Some(why)).await;
        std::future::pending::<()>().await;
    }

    async fn mark(&self, error: Option<&str>) -> sqlx::Result<()> {
        let mut conn = self.pool.acquire().await?;
        messenger_core::store::writes::mark_loop_run(&mut conn, &self.account, LOOP, None, error)
            .await
    }

    async fn serve(
        &mut self,
        cat: &str,
        tokens: &mut watch::Receiver<Option<String>>,
    ) -> Result<Ended, ChatError> {
        let (mut conn, first) = e2ee::connect(&self.device, &self.messenger, cat).await?;
        if first.tag != "success" {
            let reason = first.get("reason").map(ToString::to_string);
            tracing::error!(
                "encrypted chat refused the login: <{}> reason {reason:?}",
                first.tag
            );
            return Ok(if reason.as_deref() == Some("401") {
                Ended::LoggedOut
            } else {
                Ended::Closed
            });
        }
        tracing::info!("encrypted chat: logged in");
        self.mark(None).await?;
        let active = iq(&mut conn, "passive", "set", vec![Node::new("active")]);
        conn.send(&active).await?;
        self.place_held().await?;
        let mut last_heard = Instant::now();
        let mut next_ping = Instant::now() + keepalive_interval();
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(next_ping) => {
                    if last_heard.elapsed() > LOST_AFTER {
                        tracing::warn!("encrypted chat: nothing heard for {}s", LOST_AFTER.as_secs());
                        return Ok(Ended::Closed);
                    }
                    let ping = iq(&mut conn, "w:p", "get", Vec::new());
                    conn.send(&ping).await?;
                    self.mark(None).await?;
                    next_ping = Instant::now() + keepalive_interval();
                }
                // A new page means LightSpeed may have brought threads that held messages
                // were waiting for.
                Ok(()) = tokens.changed() => {
                    self.place_held().await?;
                }
                node = conn.recv() => {
                    let Some(node) = node? else {
                        tracing::warn!("encrypted chat: the server closed the socket");
                        return Ok(Ended::Closed);
                    };
                    last_heard = Instant::now();
                    if let Some(ended) = ended(&node) {
                        tracing::warn!("encrypted chat: the server ended it: {}", describe_end(&node));
                        return Ok(ended);
                    }
                    self.handle(&mut conn, &node).await?;
                }
            }
        }
    }

    async fn place_held(&self) -> sqlx::Result<()> {
        let mut conn = self.pool.acquire().await?;
        let placed = archive::place_held(&mut conn, &self.account).await?;
        if placed > 0 {
            tracing::info!("placed {placed} held encrypted message(s)");
        }
        Ok(())
    }

    /// One stanza: answers what needs an answer, stores what a message says.
    pub async fn handle(
        &mut self,
        out: &mut impl Outbox,
        node: &Node,
    ) -> Result<Handled, ChatError> {
        match node.tag.as_str() {
            // `appdata` is an encrypted sync between the account's own devices ("delete for
            // me", for one) and is handled as a message, as whatsmeow does (`client.go`). Left
            // unanswered, the server ends the stream five minutes after every login.
            "message" | "appdata" => self.message(out, node).await,
            "notification" => {
                out.send(&ack(node, None)).await?;
                if pre_keys_left(node).is_some_and(|left| left < MIN_PRE_KEYS) {
                    self.upload_pre_keys(out).await?;
                }
                Ok(Handled::Other)
            }
            "receipt" | "call" => {
                out.send(&ack(node, None)).await?;
                Ok(Handled::Other)
            }
            "iq" if is_ping(node) => {
                out.send(&pong(node)).await?;
                Ok(Handled::Other)
            }
            _ => Ok(Handled::Other),
        }
    }

    async fn message(&mut self, out: &mut impl Outbox, node: &Node) -> Result<Handled, ChatError> {
        let received = match inbox::receive(&mut self.signal, node, &self.messenger.fbid) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("a message stanza not read: {e}");
                out.send(&ack(node, Some(NACK_PARSING_ERROR))).await?;
                return Ok(Handled::Failed);
            }
        };
        let opened = received.parts.iter().any(|p| matches!(p, Part::Content(_)));
        if !opened {
            for part in &received.parts {
                if let Part::Failed(why) = part {
                    tracing::warn!("a message did not open: {why}");
                }
            }
            self.ask_again(out, node, received.from_me).await?;
            out.send(&ack(node, None)).await?;
            return Ok(Handled::Failed);
        }
        self.save_keys(&received.sender).await?;
        let handled = match inbox::event(&received, Utc::now()) {
            None => Handled::Nothing,
            Some(event) => {
                let mut conn = self.pool.acquire().await?;
                match archive::thread_with(&mut conn, &self.account, &received.chat).await? {
                    Some(thread) => {
                        match archive::store(&mut conn, &self.account, &thread, &event).await? {
                            Stored::Applied => Handled::Stored,
                            Stored::Unchanged | Stored::NoTarget => Handled::Nothing,
                        }
                    }
                    None => {
                        archive::hold(&mut conn, &self.account, &received.chat, &event).await?;
                        Handled::Held
                    }
                }
            }
        };
        out.send(&receipt(node, received.from_me)).await?;
        Ok(handled)
    }

    /// whatsmeow's `sendRetryReceipt`: asks the sender to encrypt the message again. From the
    /// second attempt on it carries a fresh pre-key bundle, so a sender whose session with
    /// this device is gone or broken starts a new one.
    async fn ask_again(
        &mut self,
        out: &mut impl Outbox,
        node: &Node,
        from_me: bool,
    ) -> Result<(), ChatError> {
        let id = node.get("id").map(ToString::to_string).unwrap_or_default();
        let in_message = match node.children() {
            [enc] if enc.tag == "enc" => enc
                .get("count")
                .and_then(|c| c.to_string().parse::<u32>().ok())
                .unwrap_or(0),
            _ => 0,
        };
        let count = self.retries.entry(id).or_insert(0);
        *count += 1;
        // A message that is itself a resend, after a restart lost the count.
        if *count == 1 && in_message > 0 {
            *count = in_message + 1;
        }
        let count = *count;
        if count >= MAX_RETRIES {
            tracing::warn!("no more retry receipts for a message after {count}");
            return Ok(());
        }
        let fresh = if count > 1 {
            self.fresh_pre_keys(1).await?.pop()
        } else {
            None
        };
        let receipt = retry_receipt(
            node,
            from_me,
            count,
            self.device.registration_id,
            fresh.as_ref().map(|(id, key)| RetryKeys {
                identity: &self.device.identity,
                pre_key: (*id, key),
                signed_pre_key: &self.device.signed_pre_key,
            }),
        );
        out.send(&receipt).await?;
        Ok(())
    }

    /// New one-time pre-keys, saved and counted as uploaded before anything is sent, so a
    /// crash can never hand the same id out twice.
    async fn fresh_pre_keys(&mut self, count: u32) -> Result<Vec<(u32, KeyPair)>, StoreError> {
        let plan = prekeys::plan(
            self.device.next_pre_key_id,
            self.device.first_unuploaded_pre_key_id,
            count,
            KeyPair::generate,
        );
        keys::save_pre_keys(&self.pool, &plan.new_keys).await?;
        keys::set_pre_key_counters(
            &self.pool,
            plan.next_pre_key_id,
            plan.first_unuploaded_pre_key_id,
        )
        .await?;
        self.device.next_pre_key_id = plan.next_pre_key_id;
        self.device.first_unuploaded_pre_key_id = plan.first_unuploaded_pre_key_id;
        for (id, key) in &plan.new_keys {
            self.signal.pre_keys.insert(*id, key.clone());
        }
        Ok(plan.new_keys)
    }

    /// Tops the server stock of one-time pre-keys up, as the browser did.
    async fn upload_pre_keys(&mut self, out: &mut impl Outbox) -> Result<(), ChatError> {
        let fresh = self.fresh_pre_keys(WANTED_PRE_KEYS).await?;
        let listed: Vec<(u32, &KeyPair)> = fresh.iter().map(|(id, key)| (*id, key)).collect();
        let upload = prekeys::upload_node(
            self.device.registration_id,
            &self.device.identity.public,
            &listed,
            &self.device.signed_pre_key,
        )
        .attr("id", out.next_tag());
        out.send(&upload).await?;
        tracing::info!("uploaded {} one-time pre-keys", fresh.len());
        Ok(())
    }

    /// Saves what a decryption changed: the sender's session and identity, and any
    /// one-time pre-key it used up, which must never serve a second session.
    async fn save_keys(&mut self, sender: &Address) -> Result<(), StoreError> {
        if let Some(record) = self.signal.sessions.get(sender) {
            keys::save_session(&self.pool, sender, record).await?;
        }
        if let Some(identity) = self.signal.identities.get(sender) {
            keys::save_identity(&self.pool, sender, identity).await?;
        }
        for id in std::mem::take(&mut self.signal.used_pre_keys) {
            keys::remove_pre_key(&self.pool, id).await?;
        }
        Ok(())
    }
}

fn keepalive_interval() -> Duration {
    let spread = (KEEPALIVE_MAX - KEEPALIVE_MIN).as_millis() as u64;
    KEEPALIVE_MIN + Duration::from_millis(rand::random::<u64>() % (spread + 1))
}

/// A closing stanza by tag, attributes and child tags: codes and reasons, never content.
fn describe_end(node: &Node) -> String {
    let attrs: Vec<String> = node.attrs.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let children: Vec<String> = node
        .children()
        .iter()
        .map(|c| {
            let attrs: Vec<String> = c.attrs.iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!("<{} {}>", c.tag, attrs.join(" "))
        })
        .collect();
    format!("<{} {}> {}", node.tag, attrs.join(" "), children.join(" "))
}

/// The end a stanza announces, if it announces one.
pub fn ended(node: &Node) -> Option<Ended> {
    match node.tag.as_str() {
        "stream:error" => Some(if node.child("conflict").is_some() {
            Ended::Replaced
        } else if node.get("code").map(ToString::to_string).as_deref() == Some("401") {
            Ended::LoggedOut
        } else {
            Ended::Closed
        }),
        "failure" => Some(
            if node.get("reason").map(ToString::to_string).as_deref() == Some("401") {
                Ended::LoggedOut
            } else {
                Ended::Closed
            },
        ),
        "xmlstreamend" => Some(Ended::Closed),
        _ => None,
    }
}

fn attr(node: &Node, key: &str) -> Option<Value> {
    node.get(key).cloned()
}

fn with(mut node: Node, key: &str, value: Option<Value>) -> Node {
    if let Some(value) = value {
        node = node.attr(key, value);
    }
    node
}

/// whatsmeow's `sendAck`.
pub fn ack(node: &Node, error: Option<u16>) -> Node {
    let mut out = Node::new("ack").attr("class", node.tag.as_str());
    out = with(out, "id", attr(node, "id"));
    out = with(out, "to", attr(node, "from"));
    out = with(out, "participant", attr(node, "participant"));
    out = with(out, "recipient", attr(node, "recipient"));
    if node.tag != "message" {
        out = with(out, "type", attr(node, "type"));
    }
    if let Some(code) = error {
        out = out.attr("error", code.to_string());
    }
    out
}

/// whatsmeow's `sendMessageReceipt` with active receipts off: `inactive` for others'
/// messages, `sender` (or `peer_msg`) for our own devices'.
pub fn receipt(node: &Node, from_me: bool) -> Node {
    let mut out = Node::new("receipt");
    out = with(out, "id", attr(node, "id"));
    out = with(out, "to", attr(node, "from"));
    out = with(out, "recipient", attr(node, "recipient"));
    out = with(out, "participant", attr(node, "participant"));
    let kind = if !from_me {
        "inactive"
    } else if node.get("type").map(ToString::to_string).as_deref() == Some("peer_msg") {
        "peer_msg"
    } else {
        "sender"
    };
    out.attr("type", kind)
}

fn is_ping(node: &Node) -> bool {
    let is = |key, want: &str| node.get(key).map(ToString::to_string).as_deref() == Some(want);
    is("type", "get") && is("xmlns", "urn:xmpp:ping")
}

/// The answer to the server's ping (`pair.go`, `handleIQ`).
pub fn pong(node: &Node) -> Node {
    let out = Node::new("iq").attr("type", "result");
    let out = with(out, "to", attr(node, "from"));
    with(out, "id", attr(node, "id"))
}

fn iq(out: &mut impl Outbox, xmlns: &str, kind: &str, content: Vec<Node>) -> Node {
    let mut node = Node::new("iq")
        .attr("id", out.next_tag())
        .attr("xmlns", xmlns)
        .attr("type", kind)
        .attr("to", stanza::server());
    if !content.is_empty() {
        node.content = Content::Nodes(content);
    }
    node
}

/// The server count of this device's one-time pre-keys, from an `encrypt` notification.
fn pre_keys_left(node: &Node) -> Option<u32> {
    if node.get("type").map(ToString::to_string).as_deref() != Some("encrypt") {
        return None;
    }
    node.child("count")?.get("value")?.to_string().parse().ok()
}

/// The keys a retry receipt carries from its second attempt on.
pub struct RetryKeys<'a> {
    pub identity: &'a KeyPair,
    pub pre_key: (u32, &'a KeyPair),
    pub signed_pre_key: &'a whatsapp_client::baileys::SignedPreKey,
}

/// whatsmeow's retry receipt. A Messenger device has no WhatsApp pairing record, so its
/// `device-identity` is empty, as whatsmeow marshals a missing account.
pub fn retry_receipt(
    node: &Node,
    from_me: bool,
    count: u32,
    registration_id: u32,
    keys: Option<RetryKeys<'_>>,
) -> Node {
    let mut out = Node::new("receipt");
    out = with(out, "id", attr(node, "id"));
    out = with(out, "to", attr(node, "from"));
    out = with(out, "recipient", attr(node, "recipient"));
    out = with(out, "participant", attr(node, "participant"));
    out = out.attr("type", "retry");
    if from_me && node.get("type").map(ToString::to_string).as_deref() == Some("peer_msg") {
        out = out.attr("category", "peer");
    }
    let mut retry = Node::new("retry").attr("count", count.to_string());
    retry = with(retry, "id", attr(node, "id"));
    retry = with(retry, "t", attr(node, "t"));
    let mut content = vec![
        retry.attr("v", "1"),
        bytes("registration", registration_id.to_be_bytes().to_vec()),
    ];
    if let Some(keys) = keys {
        content.push(Node {
            content: Content::Nodes(vec![
                bytes("type", vec![5]),
                bytes("identity", keys.identity.public.bytes().to_vec()),
                pre_key_node(keys.pre_key.0, keys.pre_key.1),
                signed_pre_key_node(keys.signed_pre_key),
                bytes("device-identity", Vec::new()),
            ]),
            ..Node::new("keys")
        });
    }
    out.content = Content::Nodes(content);
    out
}
