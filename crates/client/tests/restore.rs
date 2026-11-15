//! What a restored archive message becomes for the archive: the same events the live
//! encrypted chat stores, keyed by the message's OTID.

use std::collections::BTreeMap;

use messenger_client::armadillo::Content;
use messenger_client::restore::{events, fbid, shape};
use messenger_client::securehistory::archive::{BackfillMessage, BackfillReaction};
use messenger_core::models::E2eeWhat;

fn message(content: Content, reactions: Vec<BackfillReaction>) -> BackfillMessage {
    BackfillMessage {
        id: "7000000000000000001".into(),
        sender: "100000000000002".into(),
        timestamp_ms: 1_700_000_000_000,
        content,
        edit_timestamp_ms: None,
        reactions,
        media_paths: BTreeMap::new(),
    }
}

#[test]
fn text_becomes_a_message_with_its_reply() {
    let found = events(
        "7000000000000000001",
        &message(
            Content::Text {
                text: "hello".into(),
                reply_to: Some("7000000000000000000".into()),
            },
            vec![],
        ),
    );
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].otid, "7000000000000000001");
    assert_eq!(found[0].sender_id, "100000000000002");
    assert_eq!(found[0].ts.timestamp_millis(), 1_700_000_000_000);
    assert_eq!(
        found[0].what,
        E2eeWhat::Message {
            text: Some("hello".into()),
            reply_to: Some("7000000000000000000".into()),
            media: None,
            media_ref: None,
        }
    );
}

#[test]
fn media_keeps_its_kind_and_caption_and_reactions_follow() {
    let found = events(
        "7000000000000000001",
        &message(
            Content::Media {
                kind: "image",
                caption: Some("a view".into()),
                reply_to: None,
                media: None,
            },
            vec![BackfillReaction {
                sender: "100000000000003@msgr".into(),
                timestamp_ms: 1_700_000_001_000,
                emoji: "👍".into(),
            }],
        ),
    );
    assert_eq!(found.len(), 2);
    assert_eq!(
        found[0].what,
        E2eeWhat::Message {
            text: Some("a view".into()),
            reply_to: None,
            media: Some("image".into()),
            media_ref: None,
        }
    );
    assert_eq!(found[1].sender_id, "100000000000003");
    assert_eq!(
        found[1].what,
        E2eeWhat::Reaction {
            target: "7000000000000000001".into(),
            emoji: "👍".into(),
        }
    );
}

#[test]
fn content_the_archive_does_not_keep_stores_nothing() {
    assert!(
        events(
            "7000000000000000001",
            &message(Content::Other("admin message".into()), vec![])
        )
        .is_empty()
    );
}

#[test]
fn a_sender_is_its_fbid_whatever_wraps_it() {
    assert_eq!(fbid("100000000000002"), "100000000000002");
    assert_eq!(fbid("100000000000002@msgr"), "100000000000002");
    assert_eq!(fbid("100000000000002.0:3@msgr"), "100000000000002");
}

#[test]
fn an_answer_is_logged_by_its_shape_not_its_values() {
    let answer = serde_json::json!({
        "id": "1234567890",
        "virtual_devices": [{"device_type": "HSM", "client_generated_id": "secret"}],
        "is_registered": true,
        "count": 3,
        "gone": null,
    });
    let logged = shape(&answer);
    assert_eq!(
        logged,
        r#"{count: number, gone: null, id: str(10), is_registered: true, virtual_devices: [{client_generated_id: str(6), device_type: "HSM"}]}"#
    );
    assert!(!logged.contains("1234567890") && !logged.contains("secret"));
}

#[test]
fn a_backup_answer_with_nulls_reads_as_go_reads_it() {
    // The live answer's shape (2026-11-15), with synthetic values: Go reads `null` as "".
    let answer = serde_json::json!({
        "backup_tenancy": "0123456789",
        "encryption_management_delegator_id": null,
        "has_otc_eligible_devices": true,
        "id": "100000000000001",
        "is_user_opted_out": false,
        "virtual_devices": [
            {"client_generated_id": "aaaaaaaaaaaaaaaaaaaaaaaa", "creation_time": 1, "device_type": "GOOGLE_ONE_AUTO_BACKUP", "id": "100000000000002", "migration_status": null},
            {"client_generated_id": "bbbbbbbbbbbbbbbbbbbbbbbb", "creation_time": 2, "device_type": "HSM", "id": "100000000000003", "migration_status": "x"},
        ],
    });
    let backup: messenger_client::securehistory::Backup = serde_json::from_value(answer).unwrap();
    assert_eq!(backup.delegator_id, "");
    assert_eq!(backup.vesta_id(), Some("bbbbbbbbbbbbbbbbbbbbbbbb"));
}
