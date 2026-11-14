//! The encrypted chat's login payload, against the field numbers whatsmeow's `waWa6` gives.

use messenger_client::e2ee::client_payload;

/// The protobuf's top-level fields as (number, wire type), in order.
fn fields(mut bytes: &[u8]) -> Vec<(u64, u64)> {
    fn varint(bytes: &mut &[u8]) -> u64 {
        let (mut value, mut shift) = (0, 0);
        loop {
            let byte = bytes[0];
            *bytes = &bytes[1..];
            value |= u64::from(byte & 0x7F) << shift;
            shift += 7;
            if byte < 0x80 {
                return value;
            }
        }
    }
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let key = varint(&mut bytes);
        match key & 7 {
            0 => {
                varint(&mut bytes);
            }
            2 => {
                let len = varint(&mut bytes) as usize;
                bytes = &bytes[len..];
            }
            other => panic!("wire type {other}"),
        }
        out.push((key >> 3, key & 7));
    }
    out
}

#[test]
fn the_login_names_messenger_and_carries_the_token() {
    let payload = client_payload(100000000000001, 52, "cat-fake");
    assert_eq!(
        fields(&payload),
        // username, passive, user agent, connect type and reason, device, product, fb cat,
        // fb user agent, pull
        [
            (1, 0),
            (3, 0),
            (5, 2),
            (12, 0),
            (13, 0),
            (18, 0),
            (20, 0),
            (21, 2),
            (22, 2),
            (33, 0)
        ]
    );
    assert!(payload.windows(8).any(|w| w == b"cat-fake"));
    // Product 1 is MESSENGER: field 20 as a varint, then the value.
    assert!(payload.windows(3).any(|w| w == [0xA0, 0x01, 0x01]));
}
