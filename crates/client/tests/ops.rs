//! The decoders against the retired Python harvester's own output (`fixtures/ops.json`, made
//! by the since-deleted `scripts/ops-fixture.py`): every case, decoded or refused, must come
//! out exactly as its `ops.py` made it.

use messenger_client::ops;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Case {
    kind: String,
    op: Vec<Value>,
    thread_key: Option<String>,
    sync_group: u8,
    expected: Value,
}

fn decode(case: &Case) -> Value {
    let op = case.op.as_slice();
    match case.kind.as_str() {
        "message" => ops::message(op, case.thread_key.as_deref(), case.sync_group).map(|m| {
            json!({"thread_key": m.thread_key, "message_id": m.message_id, "ts_ms": m.ts_ms,
                   "sender_id": m.sender_id, "text": m.text, "reply_to_id": m.reply_to_id,
                   "sync_group": m.sync_group})
        }),
        "thread" => ops::thread(op, case.sync_group).map(|t| {
            json!({"thread_key": t.thread_key, "sync_group": t.sync_group, "title": t.title,
                   "is_group": t.is_group, "last_activity_ms": t.last_activity_ms})
        }),
        "e2ee" => ops::e2ee_thread_key(op).map(Value::String),
        "participant" => ops::participant(op).map(|p| {
            json!({"fb_user_id": p.fb_user_id, "name": p.name, "username": p.username,
                   "profile_pic_url": p.profile_pic_url})
        }),
        "reaction" => ops::reaction(op).map(|r| {
            json!({"thread_key": r.thread_key, "message_id": r.message_id, "actor_id": r.actor_id,
                   "emoji": r.emoji, "reacted_ms": r.reacted_ms})
        }),
        "attachment" => ops::attachment(op).map(|a| {
            json!({"thread_key": a.thread_key, "message_id": a.message_id,
                   "attachment_id": a.attachment_id, "kind": a.kind, "mime_type": a.mime_type,
                   "url": a.url, "preview_url": a.preview_url})
        }),
        "member" => ops::member(op).map(|m| {
            json!({"thread_key": m.thread_key, "fb_user_id": m.fb_user_id,
                   "joined_ms": m.joined_ms, "is_admin": m.is_admin})
        }),
        other => panic!("unknown kind {other}"),
    }
    .unwrap_or(Value::Null)
}

#[test]
fn every_case_decodes_or_is_refused_exactly_as_the_python_did() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ops.json");
    let cases: Vec<Case> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(cases.len() >= 50);
    let mut decoded = 0;
    for (i, case) in cases.iter().enumerate() {
        let got = decode(case);
        assert_eq!(
            got,
            case.expected,
            "case {i} ({}, {:?})",
            case.kind,
            ops::name(&case.op)
        );
        decoded += usize::from(!got.is_null());
    }
    // Both outcomes are exercised: the corpus is not all refusals.
    assert!(decoded >= 25, "{decoded}");
}
