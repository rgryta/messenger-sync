//! Archived-message decryption against pages mautrix-meta's own securehistory package
//! decrypted (`scripts/securehistory-archive-fixture`): every message must come out as the
//! same protobuf bytes Go produced, and convert to what Go's `convertArchiveMessage` makes of
//! it. Then the same pages tampered with, which must fail where Go fails.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use messenger_client::armadillo::Content;
use messenger_client::securehistory::archive::{
    ArchiveError, DecryptedMessage, decrypt_archive_message, message_range_variables,
    parse_message_range,
};
use messenger_client::securehistory::minos::MinosError;
use messenger_client::securehistory::{Device, MessageRange};
use prost::Message;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Fixture {
    device: Device,
    variables: Variables,
    pages: Vec<Page>,
}

#[derive(Deserialize)]
struct Variables {
    app_id: String,
    thread_id: String,
    before: bool,
    timestamp_ms: i64,
    count: i64,
    expected: serde_json::Value,
}

#[derive(Deserialize, Clone)]
struct Page {
    name: String,
    thread_id: String,
    self_user_id: i64,
    is_group: bool,
    response: serde_json::Value,
    decrypted: Vec<Decrypted>,
    converted: Vec<Converted>,
}

#[derive(Deserialize, Clone)]
struct Protobuf {
    timestamp_ms: i64,
    message: String,
}

#[derive(Deserialize, Clone)]
struct Attachment {
    attachment_cdn_url: String,
    attachment_object_id: String,
}

#[derive(Deserialize, Clone)]
struct Decrypted {
    id: String,
    message: Protobuf,
    supplementals: BTreeMap<String, Protobuf>,
    attachments: Option<Vec<Attachment>>,
    tags: Option<Vec<String>>,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
struct Reaction {
    sender: String,
    timestamp_ms: i64,
    emoji: String,
}

#[derive(Deserialize, Clone)]
struct Converted {
    id: String,
    outcome: String,
    #[serde(default)]
    sender: String,
    #[serde(default)]
    timestamp_ms: i64,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    reply_to: String,
    #[serde(default)]
    edit_timestamp_ms: i64,
    reactions: Vec<Reaction>,
}

fn fixture() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/securehistory_archive.json"
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn page_range(page: &Page, device: &Device) -> MessageRange {
    parse_message_range(page.response.to_string().as_bytes(), device).unwrap()
}

fn decrypt(page: &Page, device: &Device, range: &MessageRange) -> Vec<DecryptedMessage> {
    range.decrypt(device, &page.thread_id, page.self_user_id, page.is_group)
}

fn outcome(
    page: &Page,
    device: &Device,
    range: &MessageRange,
    id: &str,
) -> Result<DecryptedMessage, ArchiveError> {
    range
        .decrypt_each(device, &page.thread_id, page.self_user_id, page.is_group)
        .into_iter()
        .find(|(m, _)| m == id)
        .unwrap_or_else(|| panic!("{id} is not on the page"))
        .1
}

/// The page's JSON, `edit`ed, as the range it parses to.
fn tampered(
    page: &Page,
    device: &Device,
    edit: impl FnOnce(&mut serde_json::Value),
) -> MessageRange {
    let mut response = page.response.clone();
    let range = &mut response["encrypted_backup"]["mailbox"]["messages_from_selected_threads"][0];
    edit(range);
    parse_message_range(response.to_string().as_bytes(), device).unwrap()
}

/// The page's message with `id`, in the JSON.
fn message<'a>(range: &'a mut serde_json::Value, id: &str) -> &'a mut serde_json::Value {
    range["encrypted_messages"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|m| m["otid"] == id)
        .unwrap()
}

/// Flips the low bit of the `at`th byte (from the end when negative) of a base64 field.
fn flip(field: &mut serde_json::Value, at: isize) {
    let mut bytes = STANDARD.decode(field.as_str().unwrap()).unwrap();
    let at = if at < 0 {
        bytes.len() - at.unsigned_abs()
    } else {
        at as usize
    };
    bytes[at] ^= 1;
    *field = STANDARD.encode(bytes).into();
}

fn encoded(message: &impl Message) -> String {
    STANDARD.encode(message.encode_to_vec())
}

#[test]
fn every_page_decrypts_to_the_bytes_go_decrypted() {
    let fixture = fixture();
    for page in &fixture.pages {
        let range = page_range(page, &fixture.device);
        let got = decrypt(page, &fixture.device, &range);
        let ids: Vec<&str> = got.iter().map(|m| m.id.as_str()).collect();
        let want: Vec<&str> = page.decrypted.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, want, "{}: messages decrypted", page.name);
        for (got, want) in got.iter().zip(&page.decrypted) {
            let id = &want.id;
            assert_eq!(encoded(&got.message.message), want.message.message, "{id}");
            assert_eq!(got.message.timestamp_ms, want.message.timestamp_ms, "{id}");
            let supplementals: BTreeMap<&str, (String, i64)> = got
                .supplementals
                .iter()
                .map(|(k, v)| (k.as_str(), (encoded(&v.message), v.timestamp_ms)))
                .collect();
            let expected: BTreeMap<&str, (String, i64)> = want
                .supplementals
                .iter()
                .map(|(k, v)| (k.as_str(), (v.message.clone(), v.timestamp_ms)))
                .collect();
            assert_eq!(supplementals, expected, "{id}: supplementals");
            let attachments: Vec<(&str, &str)> = got
                .attachments
                .iter()
                .map(|a| (a.url.as_str(), a.object_id.as_str()))
                .collect();
            let expected: Vec<(&str, &str)> = want
                .attachments
                .iter()
                .flatten()
                .map(|a| {
                    (
                        a.attachment_cdn_url.as_str(),
                        a.attachment_object_id.as_str(),
                    )
                })
                .collect();
            assert_eq!(attachments, expected, "{id}: attachments");
            assert_eq!(
                got.tags,
                want.tags.clone().unwrap_or_default(),
                "{id}: tags"
            );
        }
    }
}

/// What Go's fixture calls a content: its `ConsumerApplication_Content_*` type, and the text
/// or caption it carries.
fn go_kind(content: &Content) -> (&str, String) {
    match content {
        Content::Text { text, .. } => ("MessageText", text.clone()),
        Content::Media { kind, caption, .. } => {
            let kind = match *kind {
                "image" => "ImageMessage",
                "video" => "VideoMessage",
                "audio" => "AudioMessage",
                "document" => "DocumentMessage",
                "sticker" => "StickerMessage",
                other => panic!("no fixture has a {other}"),
            };
            (kind, caption.clone().unwrap_or_default())
        }
        Content::Other(what) if what == "armadillo sub-protocol" => ("Armadillo", String::new()),
        other => panic!("no fixture converts to {other:?}"),
    }
}

fn reply_to(content: &Content) -> Option<&str> {
    match content {
        Content::Text { reply_to, .. } | Content::Media { reply_to, .. } => reply_to.as_deref(),
        _ => None,
    }
}

#[test]
fn every_message_converts_as_go_converts_it() {
    let fixture = fixture();
    for page in &fixture.pages {
        let range = page_range(page, &fixture.device);
        let got = decrypt(page, &fixture.device, &range);
        assert_eq!(got.len(), page.converted.len());
        for (message, want) in got.iter().zip(&page.converted) {
            let id = &want.id;
            assert_eq!(&message.id, id);
            let converted = message.convert();
            match want.outcome.as_str() {
                "skipped" => assert_eq!(converted, Ok(None), "{id}"),
                "error" => assert!(converted.is_err(), "{id}: {converted:?}"),
                _ => {
                    let got = converted
                        .unwrap()
                        .unwrap_or_else(|| panic!("{id}: skipped"));
                    assert_eq!(got.id, *id);
                    assert_eq!(got.sender, want.sender, "{id}");
                    assert_eq!(got.timestamp_ms, want.timestamp_ms, "{id}");
                    assert_eq!(
                        go_kind(&got.content),
                        (want.kind.as_str(), want.text.clone()),
                        "{id}"
                    );
                    assert_eq!(
                        reply_to(&got.content).unwrap_or_default(),
                        want.reply_to,
                        "{id}"
                    );
                    assert_eq!(
                        got.edit_timestamp_ms.unwrap_or_default(),
                        want.edit_timestamp_ms,
                        "{id}"
                    );
                    let reactions: Vec<Reaction> = got
                        .reactions
                        .iter()
                        .map(|r| Reaction {
                            sender: r.sender.clone(),
                            timestamp_ms: r.timestamp_ms,
                            emoji: r.emoji.clone(),
                        })
                        .collect();
                    assert_eq!(reactions, want.reactions, "{id}");
                    let paths: Vec<(&String, &String)> = got.media_paths.iter().collect();
                    let expected: Vec<(&String, &String)> = message
                        .attachments
                        .iter()
                        .map(|a| (&a.object_id, &a.url))
                        .collect();
                    assert_eq!(paths, expected, "{id}");
                }
            }
        }
    }
}

#[test]
fn echo_media_reads_back_as_the_attachment_it_described() {
    let fixture = fixture();
    let page = &fixture.pages[0];
    let range = page_range(page, &fixture.device);
    let got = decrypt(page, &fixture.device, &range);
    let content = |id: &str| {
        got.iter()
            .find(|m| m.id == id)
            .unwrap()
            .convert()
            .unwrap()
            .unwrap()
            .content
    };
    let Content::Media {
        media: Some(audio), ..
    } = content("e-audio")
    else {
        panic!("e-audio is not media");
    };
    assert!(audio.voice_note);
    assert_eq!(audio.seconds, Some(15));
    assert_eq!(audio.file_length, Some(123456));
    assert_eq!(
        audio.direct_path.as_deref(),
        Some("/v/t62.0-24/synthetic_audio.enc")
    );
    let Content::Media {
        media: Some(image), ..
    } = content("e-image")
    else {
        panic!("e-image is not media");
    };
    assert_eq!(
        image.direct_path.as_deref(),
        Some("/v/t62.0-24/synthetic_second.enc")
    );
    let Content::Text { text, reply_to } = content("e-text") else {
        panic!("e-text is not text");
    };
    assert_eq!(
        (text.as_str(), reply_to.as_deref()),
        ("edited text", Some("m-v0"))
    );
}

#[test]
fn the_range_query_variables_are_the_ones_go_sends() {
    let fixture = fixture();
    let v = &fixture.variables;
    let got = message_range_variables(
        &fixture.device,
        &v.app_id,
        &v.thread_id,
        v.before,
        v.timestamp_ms,
        v.count,
    )
    .unwrap();
    // Compared as text: the payload string inside must be the same bytes.
    assert_eq!(got.to_string(), v.expected.to_string());
    let device = &fixture.device;
    let refused = |thread: &str, timestamp: i64, count: i64| {
        message_range_variables(device, &v.app_id, thread, v.before, timestamp, count).is_err()
    };
    assert!(refused("0", 1, 1));
    assert!(refused("x", 1, 1));
    assert!(refused(&v.thread_id, -1, 1));
    assert!(refused(&v.thread_id, 1 << 48, 1));
    assert!(refused(&v.thread_id, 1, 0));
    assert!(message_range_variables(device, "", &v.thread_id, true, 1, 1).is_err());
}

#[test]
fn a_range_response_is_refused_where_go_refuses_it() {
    let fixture = fixture();
    let page = &fixture.pages[0];
    let device = &fixture.device;
    let with = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut response = page.response.clone();
        edit(&mut response["encrypted_backup"]["mailbox"]["messages_from_selected_threads"][0]);
        parse_message_range(response.to_string().as_bytes(), device)
    };
    assert!(matches!(
        with(&|r| r["should_delete_mailbox"] = true.into()),
        Err(ArchiveError::MailboxDeleted)
    ));
    assert!(matches!(
        with(&|r| {
            r["exception_string"] = "gone".into();
            r["thread_not_found"] = true.into();
        }),
        Err(ArchiveError::ThreadMissing)
    ));
    assert!(matches!(
        with(&|r| r["exception_string"] = "no".into()),
        Err(ArchiveError::Rejected)
    ));
    assert!(matches!(
        with(&|r| r["backup_id"] = "2999999999999999".into()),
        Err(ArchiveError::OtherBackup)
    ));
    assert!(matches!(
        with(&|r| r["message_range_info"]["has_more_after"] = serde_json::Value::Null),
        Err(ArchiveError::MissingPagination)
    ));
    assert!(with(&|r| r["backup_id"] = "".into()).is_ok());
    assert!(matches!(
        parse_message_range(b"null", device),
        Err(ArchiveError::MissingRange)
    ));
    assert!(matches!(
        parse_message_range(
            br#"{"encrypted_backup":{"mailbox":{"messages_from_selected_threads":[]}}}"#,
            device
        ),
        Err(ArchiveError::MissingRange)
    ));
}

#[test]
fn unknown_versions_are_refused_as_go_refuses_them() {
    let fixture = fixture();
    let page = &fixture.pages[0];
    let range = page_range(page, &fixture.device);
    let error = |id: &str| outcome(page, &fixture.device, &range, id).unwrap_err();
    assert!(
        matches!(error("m-bad-version"), ArchiveError::VersionName(v) if v == "ENCRYPTION_FROM_THE_FUTURE")
    );
    assert!(matches!(error("m-wrong-epoch"), ArchiveError::MissingEpoch));
    assert!(matches!(
        error("m-keyless-supplemental"),
        ArchiveError::MissingSupplementalKey
    ));
    assert!(matches!(error("e-unsupported"), ArchiveError::Echo(_)));
    assert!(matches!(error("e-bad-sender"), ArchiveError::Echo(_)));
    assert!(matches!(error("e-mismatched-id"), ArchiveError::Echo(_)));
    let minos: Vec<&str> = page.decrypted.iter().map(|m| m.id.as_str()).collect();
    let skipped_minos = |n: usize| {
        // The page's Minos messages after the four that decrypt, in the order they were made.
        let ids: Vec<String> = range
            .messages
            .iter()
            .filter(|m| {
                m.protobufs
                    .as_ref()
                    .is_some_and(|p| p.minos_message.is_some())
            })
            .map(|m| m.id.clone())
            .filter(|id| !minos.contains(&id.as_str()))
            .collect();
        error(&ids[n])
    };
    assert!(matches!(
        skipped_minos(0),
        ArchiveError::Minos(MinosError::ServerOrigin)
    ));
    assert!(matches!(
        skipped_minos(1),
        ArchiveError::Minos(MinosError::Mismatch)
    ));
    assert!(matches!(
        skipped_minos(2),
        ArchiveError::Minos(MinosError::CipherVersion(3))
    ));
    assert!(matches!(
        skipped_minos(3),
        ArchiveError::Minos(MinosError::MetadataVersion)
    ));
    // Archive cipher versions 1 and 5 do not exist.
    let epoch = fixture.device.epochs.values().next().unwrap();
    let anon = std::str::from_utf8(&epoch.anon_id).unwrap();
    for version in [1, 5, -1] {
        assert!(matches!(
            decrypt_archive_message(&epoch.root_key, anon, &page.thread_id, version, &[0; 64]),
            Err(ArchiveError::Version(v)) if v == version
        ));
    }
}

#[test]
fn tampered_ciphertexts_and_signatures_fail() {
    let fixture = fixture();
    let device = &fixture.device;
    let page = &fixture.pages[0];
    let check = |id: &str, edit: &dyn Fn(&mut serde_json::Value)| {
        let range = tampered(page, device, |r| edit(message(r, id)));
        let got = outcome(page, device, &range, id);
        // Nothing else on the page is affected.
        assert_eq!(
            decrypt(page, device, &range).len(),
            page.decrypted.len() - 1,
            "{id}"
        );
        got.unwrap_err()
    };
    assert!(matches!(
        check("m-v3", &|m| flip(
            &mut m["protobuf_stanzas"]["top_level_protobuf"]["encrypted_protobuf_stanza"],
            -1
        )),
        ArchiveError::Decrypt(_)
    ));
    // The salt the key is stretched with: another key, which does not open the rest.
    assert!(matches!(
        check("m-v2", &|m| flip(
            &mut m["protobuf_stanzas"]["top_level_protobuf"]["encrypted_protobuf_stanza"],
            3
        )),
        ArchiveError::Decrypt(_)
    ));
    assert!(matches!(
        check("m-v0", &|m| flip(
            &mut m["protobuf_stanzas"]["supplemental_protobufs"][0]["sk_ciphertext"],
            -2
        )),
        ArchiveError::SupplementalKey(_)
    ));
    assert!(matches!(
        check("e-text", &|m| flip(
            &mut m["echo_document"]["echo_document_string"],
            30
        )),
        ArchiveError::Decrypt(_)
    ));
    let minos = page.decrypted[page.decrypted.len() - 2].id.clone();
    assert!(matches!(
        check(&minos, &|m| flip(
            &mut m["protobuf_stanzas"]["top_level_protobuf_v2"]["transport_sender_message_signature"],
            10
        )),
        ArchiveError::Minos(MinosError::Signature)
    ));
    // The signature covers the ciphertext, so a changed ciphertext fails it first.
    assert!(matches!(
        check(&minos, &|m| flip(
            &mut m["protobuf_stanzas"]["top_level_protobuf_v2"]["encrypted_protobuf"],
            -1
        )),
        ArchiveError::Minos(MinosError::Signature)
    ));
    // The wrong DM thread: the message is authenticated against both user ids.
    let other_self = Page {
        self_user_id: page.self_user_id + 2,
        ..page.clone()
    };
    let range = page_range(page, device);
    assert!(matches!(
        outcome(&other_self, device, &range, &minos),
        Err(ArchiveError::Minos(MinosError::Open))
    ));
}

#[test]
fn a_tampered_message_key_fails_every_message_under_it() {
    let fixture = fixture();
    let device = &fixture.device;
    let page = &fixture.pages[1];
    let range = tampered(page, device, |r| {
        flip(
            &mut r["minos_decryption_keys"][0]["keys"]["mek_info"]["encrypted_mek"],
            -1,
        )
    });
    let id = &page.decrypted[0].id;
    assert!(matches!(
        outcome(page, device, &range, id),
        Err(ArchiveError::Minos(MinosError::Open))
    ));
    let range = tampered(page, device, |r| {
        flip(
            &mut r["minos_decryption_keys"][0]["keys"]["mek_creator_info"]["transport_keys"]["ephm_signature"],
            5,
        )
    });
    assert!(matches!(
        outcome(page, device, &range, id),
        Err(ArchiveError::Minos(MinosError::TransportSignature(_)))
    ));
    let range = tampered(page, device, |r| {
        r["minos_decryption_keys"][0]["keys"]["mek_info"]["mek_encryption_version"] = 3.into()
    });
    assert!(matches!(
        outcome(page, device, &range, id),
        Err(ArchiveError::Minos(MinosError::MekMetadata))
    ));
    // The archive stanza beside it is unaffected.
    assert_eq!(decrypt(page, device, &range).len(), 1);
}
