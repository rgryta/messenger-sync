//! The armadillo decoder against payloads built field by field from whatsmeow's protobufs,
//! with an encoder written here rather than the decoder's own structs.

use messenger_client::armadillo::{ArmadilloError, Content, MediaRef, decode};

fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// A length-delimited field.
fn field(number: u64, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint(number << 3 | 2, &mut out);
    varint(bytes.len() as u64, &mut out);
    out.extend_from_slice(bytes);
    out
}

fn int_field(number: u64, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    varint(number << 3, &mut out);
    varint(value, &mut out);
    out
}

fn sub_protocol(payload: &[u8], version: u64) -> Vec<u8> {
    [field(1, payload), int_field(2, version)].concat()
}

fn message_text(text: &str) -> Vec<u8> {
    field(1, text.as_bytes())
}

fn key(id: &str) -> Vec<u8> {
    [field(1, b"100000000000002@msgr"), field(3, id.as_bytes())].concat()
}

/// `ConsumerApplication{payload}` inside `MessageApplication` inside `MessageTransport`, with
/// optional `MessageApplication.metadata`, at the versions Messenger uses.
fn wrap(consumer_payload: &[u8], metadata: Option<&[u8]>) -> Vec<u8> {
    let consumer = field(1, consumer_payload);
    let sub_protocol_payload = field(2, &sub_protocol(&consumer, 1));
    let mut application = field(1, &field(4, &sub_protocol_payload));
    if let Some(metadata) = metadata {
        application.extend(field(2, metadata));
    }
    let transport_payload = field(1, &sub_protocol(&application, 2));
    // A transport carries padding beside the payload too.
    [
        field(1, &transport_payload),
        field(2, &field(1, &field(1, &[0; 7]))),
    ]
    .concat()
}

fn content(number: u64, body: &[u8]) -> Vec<u8> {
    field(1, &field(number, body))
}

#[test]
fn text_and_its_reply_target_read_through_every_layer() {
    let quoted = field(10, &field(1, b"mid.$reply-target"));
    assert_eq!(
        decode(&wrap(&content(1, &message_text("czesc")), Some(&quoted))),
        Ok(Content::Text {
            text: "czesc".into(),
            reply_to: Some("mid.$reply-target".into()),
        })
    );
    // A link preview carries its text one level down.
    assert_eq!(
        decode(&wrap(
            &content(5, &field(1, &message_text("see https://x.example"))),
            None
        )),
        Ok(Content::Text {
            text: "see https://x.example".into(),
            reply_to: None,
        })
    );
}

#[test]
fn edits_unsends_and_reactions_name_their_target() {
    let edit = [field(1, &key("mid.$a")), field(2, &message_text("fixed"))].concat();
    assert_eq!(
        decode(&wrap(&content(19, &edit), None)),
        Ok(Content::Edit {
            target: "mid.$a".into(),
            text: "fixed".into(),
        })
    );
    let revoke = field(2, &field(1, &field(1, &key("mid.$b"))));
    assert_eq!(
        decode(&wrap(&revoke, None)),
        Ok(Content::Revoke {
            target: "mid.$b".into()
        })
    );
    let reaction = [field(1, &key("mid.$c")), field(2, "👍".as_bytes())].concat();
    assert_eq!(
        decode(&wrap(&content(16, &reaction), None)),
        Ok(Content::Reaction {
            target: "mid.$c".into(),
            emoji: "👍".into(),
        })
    );
}

#[test]
fn attachments_are_named_with_their_caption() {
    let image = field(2, &message_text("sunset"));
    assert_eq!(
        decode(&wrap(&content(2, &image), None)),
        Ok(Content::Media {
            kind: "image",
            caption: Some("sunset".into()),
            reply_to: None,
            media: None,
        })
    );
    // An audio message whose body is only its media reference.
    assert_eq!(
        decode(&wrap(
            &content(8, &field(1, &sub_protocol(b"media", 1))),
            None
        )),
        Ok(Content::Media {
            kind: "audio",
            caption: None,
            reply_to: None,
            media: None,
        })
    );
}

#[test]
fn transport_only_and_unknown_versions_are_told_apart() {
    // Only a sender-key distribution in the transport's ancillary part: nothing to archive.
    let skdm = field(2, &field(2, &field(2, &field(1, b"group"))));
    assert!(matches!(decode(&skdm), Ok(Content::Other(_))));
    // Instagram's application version is not Messenger's.
    let instagram = field(1, &field(1, &sub_protocol(&[], 3)));
    assert_eq!(
        decode(&instagram),
        Err(ArmadilloError::Version("MessageApplication", 3))
    );
    assert_eq!(
        decode(&[0xFF, 0xFF]),
        Err(ArmadilloError::Decode("MessageTransport"))
    );
}

/// `WAMediaTransport` as the CDN reference, wrapped as each kind's transport wraps it.
fn transport(seconds: Option<u64>) -> Vec<u8> {
    let integral = [
        field(1, &[0x11; 32]),
        field(2, &[0x22; 32]),
        field(3, &[0x33; 32]),
        field(4, b"/v/t62.7117-24/fake-path"),
        int_field(5, 1_763_100_000),
    ]
    .concat();
    let ancillary = [int_field(1, 12_345), field(2, b"audio/ogg; codecs=opus")].concat();
    let wa_media = [field(1, &integral), field(2, &ancillary)].concat();
    let mut kind = field(1, &field(1, &wa_media));
    if let Some(s) = seconds {
        kind.extend(field(2, &int_field(1, s)));
    }
    kind
}

#[test]
fn a_voice_note_carries_its_file_reference_and_length() {
    let audio = [
        field(1, &sub_protocol(&transport(Some(7)), 1)),
        int_field(2, 1),
    ]
    .concat();
    assert_eq!(
        decode(&wrap(&content(8, &audio), None)),
        Ok(Content::Media {
            kind: "audio",
            caption: None,
            reply_to: None,
            media: Some(MediaRef {
                direct_path: Some("/v/t62.7117-24/fake-path".into()),
                media_key: vec![0x22; 32],
                file_sha256: Some(vec![0x11; 32]),
                file_enc_sha256: Some(vec![0x33; 32]),
                mime_type: Some("audio/ogg; codecs=opus".into()),
                file_length: Some(12_345),
                seconds: Some(7),
                voice_note: true,
            }),
        })
    );
    // An image's ancillary field 1 is its height, not a duration.
    let image = [
        field(1, &sub_protocol(&transport(Some(1080)), 1)),
        field(2, &message_text("sunset")),
    ]
    .concat();
    let Ok(Content::Media {
        media: Some(m),
        caption,
        ..
    }) = decode(&wrap(&content(2, &image), None))
    else {
        panic!("an image with its reference");
    };
    assert_eq!((m.seconds, m.voice_note), (None, false));
    assert_eq!(caption.as_deref(), Some("sunset"));
}
