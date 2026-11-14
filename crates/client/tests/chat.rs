//! What the encrypted chat answers, against whatsmeow's stanza shapes, and how a stanza it
//! cannot open is handled: acknowledged, nothing stored.

mod support;

use std::collections::{BTreeMap, HashMap};

use messenger_client::chat::{Chat, Ended, Handled, ack, ended, pong, receipt};
use messenger_client::device::Messenger;
use whatsapp_client::baileys::{Device, ImportStats, SignedPreKey};
use whatsapp_client::binary::{Content, Jid, JidForm, Node};
use whatsapp_client::conn::{ConnError, Outbox};
use whatsapp_client::signal::curve::KeyPair;

const DATABASE: &str = "client_chat";
const ME: &str = "100000000000001";
const PEER: &str = "100000000000002";

fn fb(user: &str, device: u16) -> Jid {
    Jid {
        user: user.into(),
        server: "msgr".into(),
        form: JidForm::Fb { device },
    }
}

fn attrs(node: &Node) -> Vec<(String, String)> {
    node.attrs
        .iter()
        .map(|(k, v)| (k.clone(), v.to_string()))
        .collect()
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn message(recipient: bool) -> Node {
    let from = if recipient { fb(ME, 1) } else { fb(PEER, 3) };
    let mut node = Node::new("message")
        .attr("from", from)
        .attr("type", "text")
        .attr("id", "7240000000000000001")
        .attr("t", "1763100000");
    if recipient {
        node = node.attr("recipient", fb(PEER, 0));
    }
    let mut enc = Node::new("enc").attr("v", "3").attr("type", "msg");
    enc.content = Content::Bytes(vec![0x33, 0x0A]);
    node.content = Content::Nodes(vec![enc]);
    node
}

#[test]
fn acks_and_receipts_have_whatsmeows_shape() {
    // A message's ack carries no type; a receipt's carries the receipt's.
    assert_eq!(
        attrs(&ack(&message(false), None)),
        pairs(&[
            ("class", "message"),
            ("id", "7240000000000000001"),
            ("to", &format!("{PEER}:3@msgr")),
        ])
    );
    let read = Node::new("receipt")
        .attr("id", "1")
        .attr("from", fb(PEER, 3))
        .attr("type", "read");
    assert_eq!(
        attrs(&ack(&read, Some(487))),
        pairs(&[
            ("class", "receipt"),
            ("id", "1"),
            ("to", &format!("{PEER}:3@msgr")),
            ("type", "read"),
            ("error", "487"),
        ])
    );
    // Delivered, never read: `inactive` for theirs, `sender` for our own devices'.
    assert_eq!(
        attrs(&receipt(&message(false), false)),
        pairs(&[
            ("id", "7240000000000000001"),
            ("to", &format!("{PEER}:3@msgr")),
            ("type", "inactive"),
        ])
    );
    assert_eq!(
        attrs(&receipt(&message(true), true)),
        pairs(&[
            ("id", "7240000000000000001"),
            ("to", &format!("{ME}:1@msgr")),
            ("recipient", &format!("{PEER}@msgr")),
            ("type", "sender"),
        ])
    );
}

#[test]
fn the_server_says_when_to_stop() {
    let mut replaced = Node::new("stream:error");
    replaced.content = Content::Nodes(vec![Node::new("conflict").attr("type", "replaced")]);
    assert_eq!(ended(&replaced), Some(Ended::Replaced));
    assert_eq!(
        ended(&Node::new("stream:error").attr("code", "401")),
        Some(Ended::LoggedOut)
    );
    assert_eq!(
        ended(&Node::new("stream:error").attr("code", "515")),
        Some(Ended::Closed)
    );
    assert_eq!(ended(&Node::new("xmlstreamend")), Some(Ended::Closed));
    assert_eq!(ended(&message(false)), None);
}

#[derive(Default)]
struct Recorder {
    sent: Vec<Node>,
}

impl Outbox for Recorder {
    async fn send(&mut self, node: &Node) -> Result<(), ConnError> {
        self.sent.push(node.clone());
        Ok(())
    }

    fn next_tag(&mut self) -> String {
        format!("tag-{}", self.sent.len())
    }
}

fn device() -> Device {
    Device {
        noise: KeyPair::generate(),
        identity: KeyPair::generate(),
        registration_id: 1,
        signed_pre_key: SignedPreKey {
            id: 1,
            key_pair: KeyPair::generate(),
            signature: vec![0; 64],
        },
        adv_secret: Vec::new(),
        account: None,
        me: None,
        platform: None,
        routing_info: None,
        next_pre_key_id: 1,
        first_unuploaded_pre_key_id: 1,
        pre_keys: Vec::new(),
        sessions: Vec::new(),
        identities: Vec::new(),
        sender_keys: HashMap::new(),
        app_state_keys: BTreeMap::new(),
        lid_mappings: BTreeMap::new(),
        stats: ImportStats::default(),
    }
}

#[tokio::test]
async fn pings_are_answered_and_an_unopened_message_is_asked_for_again() {
    let Some((pool, _, _turn)) = support::database(DATABASE).await else {
        return;
    };
    messenger_core::db::ensure_schema(&pool).await.unwrap();
    messenger_client::device::store::migrate(&pool)
        .await
        .unwrap();
    let messenger = Messenger {
        fbid: ME.into(),
        device_id: 52,
        device_uuid: "00000000-0000-4000-8000-000000000000".into(),
    };
    let mut chat = Chat::new(pool.clone(), "me".into(), device(), messenger);
    let mut out = Recorder::default();

    let ping = Node::new("iq")
        .attr("id", "p1")
        .attr("from", Jid::pair("", "s.whatsapp.net"))
        .attr("type", "get")
        .attr("xmlns", "urn:xmpp:ping");
    assert_eq!(chat.handle(&mut out, &ping).await.unwrap(), Handled::Other);
    assert_eq!(out.sent, [pong(&ping)]);
    assert_eq!(
        attrs(&out.sent[0]),
        pairs(&[("type", "result"), ("to", "@s.whatsapp.net"), ("id", "p1")])
    );

    out.sent.clear();
    let unopened = message(false);
    assert_eq!(
        chat.handle(&mut out, &unopened).await.unwrap(),
        Handled::Failed
    );
    // A retry receipt, then the ack; nothing stored.
    assert_eq!(out.sent.len(), 2);
    assert_eq!(out.sent[1], ack(&unopened, None));
    let first = &out.sent[0];
    assert_eq!(
        attrs(first),
        pairs(&[
            ("id", "7240000000000000001"),
            ("to", &format!("{PEER}:3@msgr")),
            ("type", "retry"),
        ])
    );
    let tags = |n: &Node| {
        n.children()
            .iter()
            .map(|c| c.tag.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(tags(first), ["retry", "registration"]);
    assert_eq!(
        attrs(&first.children()[0]),
        pairs(&[
            ("count", "1"),
            ("id", "7240000000000000001"),
            ("t", "1763100000"),
            ("v", "1"),
        ])
    );
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM message")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);

    // The second attempt carries a fresh one-time pre-key, saved before it is handed out.
    out.sent.clear();
    chat.handle(&mut out, &unopened).await.unwrap();
    let keys = out.sent[0].child("keys").expect("keys on a second retry");
    assert_eq!(
        tags(keys),
        ["type", "identity", "key", "skey", "device-identity"]
    );
    let saved: i64 = sqlx::query_scalar("SELECT count(*) FROM device.pre_key")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(saved, 1);

    // The server says it is nearly out of pre-keys: acknowledged, then topped up to 50.
    out.sent.clear();
    let mut low = Node::new("notification")
        .attr("id", "n1")
        .attr("from", Jid::pair("", "s.whatsapp.net"))
        .attr("type", "encrypt");
    low.content = Content::Nodes(vec![Node::new("count").attr("value", "3")]);
    chat.handle(&mut out, &low).await.unwrap();
    assert_eq!(out.sent[0], ack(&low, None));
    let upload = &out.sent[1];
    assert_eq!(upload.tag, "iq");
    let list = upload.child("list").expect("a pre-key list");
    assert_eq!(list.children().len(), 50);
    let saved: i64 = sqlx::query_scalar("SELECT count(*) FROM device.pre_key")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(saved, 51);
}

#[tokio::test]
async fn an_appdata_sync_is_answered_like_a_message() {
    let Some((pool, _, _turn)) = support::database(DATABASE).await else {
        return;
    };
    messenger_core::db::ensure_schema(&pool).await.unwrap();
    messenger_client::device::store::migrate(&pool)
        .await
        .unwrap();
    let messenger = Messenger {
        fbid: ME.into(),
        device_id: 52,
        device_uuid: "00000000-0000-4000-8000-000000000000".into(),
    };
    let mut chat = Chat::new(pool.clone(), "me".into(), device(), messenger);
    let mut out = Recorder::default();
    let mut appdata = message(true);
    appdata.tag = "appdata".into();
    assert_eq!(
        chat.handle(&mut out, &appdata).await.unwrap(),
        Handled::Failed
    );
    // Never ignored: the server waits five minutes for this, then ends the stream.
    let last = out.sent.last().expect("an answer");
    assert_eq!(last.tag, "ack");
    assert_eq!(
        last.get("class").map(ToString::to_string).as_deref(),
        Some("appdata")
    );
}
