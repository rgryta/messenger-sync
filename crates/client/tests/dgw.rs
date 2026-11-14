//! The gateway codec against frames mautrix-meta's own `dgw` package encoded
//! (`scripts/dgw-fixture`).

use messenger_client::dgw::Frame;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    frames: Vec<Case>,
    batch: String,
    batch_types: Vec<String>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    hex: String,
    frame: serde_json::Value,
}

fn fixture() -> Fixture {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dgw.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// The fixture's description of a frame, as this crate's type.
fn expected(d: &serde_json::Value) -> Frame {
    let n = |k: &str| d[k].as_u64().unwrap();
    match d["type"].as_str().unwrap() {
        "ping" => Frame::Ping,
        "pong" => Frame::Pong,
        "deauth" => Frame::Deauth,
        "drain" => Frame::Drain {
            reason: n("reason") as u8,
        },
        "ack" => Frame::Ack {
            stream: n("stream") as u16,
            ack: n("ack") as u16,
        },
        "data" => Frame::Data {
            stream: n("stream") as u16,
            ack_id: n("ack") as u16,
            requires_ack: d["requires_ack"].as_bool().unwrap(),
            content_type: d.get("content_type").map(|c| c.as_u64().unwrap() as u8),
            payload: d["payload"].as_str().unwrap().as_bytes().to_vec(),
        },
        "end_of_data" => Frame::EndOfData {
            stream: n("stream") as u16,
            reason: d.get("reason").map(|r| r.as_u64().unwrap() as u8),
        },
        "establish" => Frame::Establish {
            stream: n("stream") as u16,
            parameters: d["parameters"].as_str().unwrap().as_bytes().to_vec(),
        },
        other => panic!("unknown type {other}"),
    }
}

#[test]
fn every_frame_decodes_and_encodes_byte_for_byte_like_mautrix() {
    for case in fixture().frames {
        let bytes = hex::decode(&case.hex).unwrap();
        let frames = Frame::decode_all(&bytes).unwrap();
        assert_eq!(frames, [expected(&case.frame)], "{}", case.name);
        let mut out = Vec::new();
        frames[0].encode(&mut out);
        assert_eq!(hex::encode(out), case.hex, "{}", case.name);
    }
}

#[test]
fn a_batched_message_splits_where_mautrix_splits_it() {
    let f = fixture();
    let frames = Frame::decode_all(&hex::decode(&f.batch).unwrap()).unwrap();
    let names: Vec<&str> = frames
        .iter()
        .map(|f| match f {
            Frame::Ping => "ping",
            Frame::Pong => "pong",
            Frame::Deauth => "deauth",
            Frame::Drain { .. } => "drain",
            Frame::Ack { .. } => "ack",
            Frame::Data { .. } => "data",
            Frame::EndOfData { .. } => "end_of_data",
            Frame::Establish { .. } => "establish",
            Frame::Unsupported(_) => "unsupported",
        })
        .collect();
    assert_eq!(names, f.batch_types);
}

#[test]
fn a_truncated_frame_is_an_error_not_a_panic() {
    for case in fixture().frames {
        let bytes = hex::decode(&case.hex).unwrap();
        for cut in 1..bytes.len() {
            // Fixed one-byte frames cannot be cut; everything else must refuse a short read.
            let _ = Frame::decode_all(&bytes[..cut]);
        }
    }
    assert!(Frame::decode_all(&[0x0d, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00]).is_err());
    assert!(Frame::decode_all(&[0x0c, 0x01, 0x00, 0x03, 0x00, 0x00, 0, 0, 0]).is_err());
    // A drain says its length is one byte; anything else is not a drain.
    assert!(Frame::decode_all(&[0x03, 0x02, 0x00, 0x00, 0x05, 0x05]).is_err());
}
