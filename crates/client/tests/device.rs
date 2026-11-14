//! Adopting the browser's encrypted device: a synthetic export with made-up keys, read and
//! checked, and stored against a throwaway Postgres.

mod support;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use curve25519_dalek::{EdwardsPoint, Scalar};
use messenger_client::device;
use messenger_client::session;
use prost::Message;
use serde_json::{Value, json};
use sha2::{Digest, Sha512};
use whatsapp_client::baileys::Device;
use whatsapp_client::signal::Address;
use whatsapp_client::signal::curve::{KeyPair, PrivateKey};

const DATABASE: &str = "client_device";
const FBID: &str = "100000000000001";
const CONTACT: &str = "100000000000002";
const REGISTRATION_ID: u32 = 4321;

#[derive(Clone, PartialEq, Message)]
struct PreKeyRecordStructure {
    #[prost(uint32, tag = "1")]
    id: u32,
    #[prost(bytes = "vec", tag = "2")]
    public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    private_key: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct SignedPreKeyRecordStructure {
    #[prost(uint32, tag = "1")]
    id: u32,
    #[prost(bytes = "vec", tag = "2")]
    public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    private_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    signature: Vec<u8>,
    #[prost(fixed64, tag = "5")]
    timestamp: u64,
}

#[derive(Clone, PartialEq, Message)]
struct SessionStructure {
    #[prost(uint32, tag = "1")]
    session_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    local_identity_public: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    remote_identity_public: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    root_key: Vec<u8>,
    #[prost(uint32, tag = "10")]
    remote_registration_id: u32,
    #[prost(uint32, tag = "11")]
    local_registration_id: u32,
}

/// libsignal's session record, as the browser stores it.
#[derive(Clone, PartialEq, Message)]
struct RecordStructure {
    #[prost(message, optional, tag = "1")]
    current_session: Option<SessionStructure>,
}

/// libsignal's XEdDSA signature, with a fixed nonce: a test needs no randomness.
fn sign(private: &PrivateKey, message: &[u8]) -> Vec<u8> {
    let mut k = private.serialize();
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let a = Scalar::from_bytes_mod_order(k);
    let ed_public = EdwardsPoint::mul_base(&a).compress();
    let r = Scalar::from_hash(
        Sha512::new()
            .chain_update([0xFF; 32])
            .chain_update(k)
            .chain_update(message)
            .chain_update([0; 64]),
    );
    let cap_r = EdwardsPoint::mul_base(&r).compress();
    let h = Scalar::from_hash(
        Sha512::new()
            .chain_update(cap_r.as_bytes())
            .chain_update(ed_public.as_bytes())
            .chain_update(message),
    );
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(cap_r.as_bytes());
    signature[32..].copy_from_slice((h * a + r).as_bytes());
    signature[63] = (signature[63] & 0x7F) | (ed_public.as_bytes()[31] & 0x80);
    signature.to_vec()
}

fn bytes(raw: &[u8]) -> Value {
    json!({"$bytes": B64.encode(raw)})
}

fn meta(key: &str, value: Value) -> Value {
    json!({"key": key, "value": {key: value}})
}

fn pair(keys: &KeyPair) -> Value {
    json!({"publicKey": bytes(keys.public.bytes()), "privateKey": bytes(&keys.private.serialize())})
}

struct Fixture {
    identity: KeyPair,
    export: Value,
}

/// An export shaped like the browser's: raw 32-byte keys in `meta`, libsignal records
/// elsewhere, and one pre-key already used.
fn fixture() -> Fixture {
    let identity = KeyPair::generate();
    let noise = KeyPair::generate();
    let signed = KeyPair::generate();
    let contact = KeyPair::generate();
    let pre_keys: Vec<Value> = (1..=3)
        .map(|id| {
            let keys = KeyPair::generate();
            let record = PreKeyRecordStructure {
                id,
                public_key: keys.public.serialize().to_vec(),
                private_key: keys.private.serialize().to_vec(),
            };
            json!({"keyId": id, "encoded": bytes(&record.encode_to_vec()), "isDeleted": id == 2})
        })
        .collect();
    let signed_record = SignedPreKeyRecordStructure {
        id: 1,
        public_key: signed.public.serialize().to_vec(),
        private_key: signed.private.serialize().to_vec(),
        signature: sign(&identity.private, &signed.public.serialize()),
        timestamp: 1_700_000_000_000,
    };
    let session = SessionStructure {
        session_version: 3,
        local_identity_public: identity.public.serialize().to_vec(),
        remote_identity_public: contact.public.serialize().to_vec(),
        root_key: vec![7; 32],
        remote_registration_id: 99,
        local_registration_id: REGISTRATION_ID,
    };
    let jid = format!("{CONTACT}:7@msgr");
    let export = json!({
        "meta": [
            meta("fbid", json!(FBID)),
            meta("deviceId", json!(52)),
            meta("deviceUUID", json!("00000000-0000-4000-8000-000000000000")),
            meta("regId", json!(REGISTRATION_ID)),
            meta("lastPrekeyId", json!(3)),
            meta("lastSignedPrekeyId", json!(1)),
            meta("identityKeyPair", pair(&identity)),
            meta("authKeyPair", pair(&noise)),
            meta("clockSkew", json!(0)),
        ],
        "identity": [{
            "deviceJid": jid,
            "userJid": format!("{CONTACT}@msgr"),
            "identity": bytes(&contact.public.serialize()),
        }],
        "session": [{"id": jid, "session": bytes(&RecordStructure { current_session: Some(session) }.encode_to_vec())}],
        "prekey": pre_keys,
        "prekeyGeneration": [],
        "signedPrekey": [{"keyId": 1, "encoded": bytes(&signed_record.encode_to_vec())}],
        "senderKeySessions": [],
        "personalSenderKeyStatuses": [],
        "contacts": [],
    });
    Fixture { identity, export }
}

fn import(export: &Value) -> Result<(device::Messenger, Device), String> {
    device::import(&serde_json::to_vec(export).unwrap())
        .map(|(keys, messenger)| (messenger, keys))
        .map_err(|e| e.to_string())
}

#[test]
fn a_well_formed_export_reads_into_the_device() {
    let f = fixture();
    let (messenger, keys) = import(&f.export).unwrap();
    assert_eq!(messenger.fbid, FBID);
    assert_eq!(messenger.device_id, 52);
    assert_eq!(keys.me.as_ref().unwrap().id, format!("{FBID}:52@msgr"));
    assert_eq!(keys.registration_id, REGISTRATION_ID);
    assert_eq!(keys.identity.public.bytes(), f.identity.public.bytes());
    assert_eq!(keys.signed_pre_key.id, 1);
    // The used one-time pre-key is left out.
    let mut ids: Vec<u32> = keys.pre_keys.iter().map(|(id, _)| *id).collect();
    ids.sort();
    assert_eq!(ids, [1, 3]);
    assert_eq!(keys.next_pre_key_id, 4);
    let contact = Address {
        name: CONTACT.into(),
        device: 7,
    };
    assert_eq!(keys.sessions.len(), 1);
    assert_eq!(keys.sessions[0].0, contact);
    assert!(keys.sessions[0].1.has_current_session());
    assert_eq!(keys.identities.len(), 1);
    assert_eq!(keys.identities[0].0, contact);
}

#[test]
fn a_broken_or_foreign_export_is_refused() {
    type Case = (&'static str, fn(&mut Value));
    let cases: [Case; 6] = [
        ("appears twice", |e| {
            let row = e["meta"][3].clone();
            e["meta"].as_array_mut().unwrap().push(row);
        }),
        ("did not sign it", |e| {
            let other = KeyPair::generate();
            e["meta"][6] = meta("identityKeyPair", pair(&other));
        }),
        ("does not belong", |e| {
            let other = KeyPair::generate();
            e["meta"][7]["value"]["authKeyPair"]["publicKey"] = bytes(other.public.bytes());
        }),
        ("another registration id", |e| {
            e["meta"][3] = meta("regId", json!(1))
        }),
        ("is not a user:device@msgr address", |e| {
            e["identity"][0]["deviceJid"] = json!("100:1@s.whatsapp.net")
        }),
        ("signed pre-key is missing", |e| {
            e["meta"][5] = meta("lastSignedPrekeyId", json!(2))
        }),
    ];
    for (expected, mutate) in cases {
        let mut export = fixture().export;
        mutate(&mut export);
        let error = import(&export).err().unwrap_or_default();
        assert!(error.contains(expected), "{expected:?} not in {error:?}");
    }
}

#[tokio::test]
async fn an_imported_device_is_stored_and_loads_back() {
    let Some((pool, _, _turn)) = support::database(DATABASE).await else {
        return;
    };
    session::migrate(&pool).await.unwrap();
    device::store::migrate(&pool).await.unwrap();
    assert!(device::load(&pool).await.unwrap().is_none());

    let (messenger, keys) = import(&fixture().export).unwrap();
    device::save(&pool, &keys, &messenger).await.unwrap();
    // A second import replaces the first rather than failing on its rows.
    let f = fixture();
    let (messenger, keys) = import(&f.export).unwrap();
    device::save(&pool, &keys, &messenger).await.unwrap();

    let (loaded, loaded_messenger) = device::load(&pool).await.unwrap().unwrap();
    assert_eq!(loaded_messenger, messenger);
    assert_eq!(loaded.identity.public.bytes(), f.identity.public.bytes());
    assert_eq!(loaded.noise.public.bytes(), keys.noise.public.bytes());
    assert_eq!(loaded.registration_id, REGISTRATION_ID);
    assert_eq!(loaded.pre_keys.len(), 2);
    assert_eq!(loaded.sessions.len(), 1);
    assert_eq!(loaded.identities.len(), 1);
    assert_eq!(loaded.me.unwrap().id, format!("{FBID}:52@msgr"));
}
