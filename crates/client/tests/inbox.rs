//! Reading a `<message>` stanza: addresses, chat and direction, and what a payload that does
//! not open says. Decryption itself is whatsapp-client's, tested there.

use std::collections::HashMap;

use messenger_client::armadillo::Content as Said;
use messenger_client::inbox::{InboxError, Part, Received, event, receive};
use messenger_core::models::E2eeWhat;
use whatsapp_client::binary::{Content, Jid, JidForm, Node};
use whatsapp_client::signal::curve::KeyPair;
use whatsapp_client::signal::{Address, Store};

const ME: &str = "100000000000001";
const PEER: &str = "100000000000002";

fn store() -> Store {
    Store {
        identity: KeyPair::generate(),
        registration_id: 1,
        signed_pre_keys: HashMap::new(),
        pre_keys: HashMap::new(),
        sessions: HashMap::new(),
        identities: HashMap::new(),
        used_pre_keys: Vec::new(),
    }
}

fn fb(user: &str, device: u16) -> Jid {
    Jid {
        user: user.into(),
        server: "msgr".into(),
        form: JidForm::Fb { device },
    }
}

fn enc(kind: &str) -> Node {
    let mut node = Node::new("enc").attr("v", "3").attr("type", kind);
    node.content = Content::Bytes(vec![0x33, 0x0A, 0x00]);
    node
}

fn message(from: Jid, recipient: Option<Jid>, encs: Vec<Node>) -> Node {
    let mut node = Node::new("message")
        .attr("id", "7240000000000000001")
        .attr("from", from)
        .attr("t", "1763100000")
        .attr("type", "text");
    if let Some(recipient) = recipient {
        node = node.attr("recipient", recipient);
    }
    node.content = Content::Nodes(encs);
    node
}

#[test]
fn a_message_from_a_contact_is_their_chat() {
    let received = receive(
        &mut store(),
        &message(fb(PEER, 3), None, vec![enc("msg")]),
        ME,
    )
    .unwrap();
    assert_eq!(received.id, "7240000000000000001");
    assert_eq!(
        received.sender,
        Address {
            name: PEER.into(),
            device: 3
        }
    );
    assert_eq!(received.chat, PEER);
    assert!(!received.from_me);
    assert_eq!(received.timestamp, Some(1_763_100_000));
    // A payload that does not open is reported, not dropped.
    assert!(
        matches!(&received.parts[..], [Part::Failed(why)] if why.starts_with("msg: ")),
        "{:?}",
        received.parts
    );
}

#[test]
fn one_of_our_own_devices_sending_names_the_recipient_as_the_chat() {
    let received = receive(
        &mut store(),
        &message(fb(ME, 1), Some(fb(PEER, 0)), vec![enc("skmsg")]),
        ME,
    )
    .unwrap();
    assert!(received.from_me);
    assert_eq!(received.chat, PEER);
    assert_eq!(
        received.parts,
        [Part::Failed("skmsg payloads are not ported".into())]
    );
}

#[test]
fn stanzas_this_client_cannot_place_are_refused() {
    assert_eq!(
        receive(
            &mut store(),
            &message(fb(PEER, 3), Some(fb(ME, 0)), vec![]),
            ME
        ),
        Err(InboxError::RecipientNotFromMe)
    );
    let group = Jid::pair("1234", "g.us");
    assert_eq!(
        receive(&mut store(), &message(group, None, vec![]), ME),
        Err(InboxError::UnsupportedServer("g.us".into()))
    );
    assert_eq!(
        receive(&mut store(), &Node::new("message"), ME),
        Err(InboxError::Missing("id"))
    );
}

#[test]
fn the_archive_takes_the_first_part_that_opened() {
    let received = Received {
        id: "7240000000000000001".into(),
        sender: Address {
            name: PEER.into(),
            device: 3,
        },
        chat: PEER.into(),
        from_me: false,
        timestamp: Some(1_763_100_000),
        parts: vec![
            Part::Failed("msg: no session".into()),
            Part::Content(Said::Media {
                kind: "image",
                caption: Some("sunset".into()),
                reply_to: Some("7240000000000000000".into()),
            }),
        ],
    };
    let now = chrono::Utc::now();
    let e = event(&received, now).unwrap();
    assert_eq!(e.otid, "7240000000000000001");
    assert_eq!(e.sender_id, PEER);
    assert_eq!(e.ts.timestamp(), 1_763_100_000);
    assert_eq!(
        e.what,
        E2eeWhat::Message {
            text: Some("sunset".into()),
            reply_to: Some("7240000000000000000".into()),
            media: Some("image".into()),
        }
    );
    // Nothing that opened, nothing to keep.
    let failed = Received {
        parts: vec![Part::Failed("skmsg payloads are not ported".into())],
        ..received
    };
    assert_eq!(event(&failed, now), None);
}
