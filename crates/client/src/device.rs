//! The Messenger web client's encrypted device, adopted rather than registered again.
//!
//! Messenger's end-to-end layer is WhatsApp's: the same Noise login, Signal sessions and
//! pre-keys. So the device is whatsapp-client's [`Device`], kept in its `device` schema by its
//! [`store`]. What Messenger adds (whose device it is, and Meta's UUID for it) is kept beside it
//! in `client.device`.
//!
//! [`import`] reads the browser's Signal store as the retired `scripts/export-device.py` (in
//! git history) decrypted it at cutover. Every key is checked against its partner before
//! anything is kept: a private key against its public key, the signed pre-key against the
//! identity's signature, each session against this device's identity and registration id.

use std::collections::{BTreeMap, HashMap};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use prost::Message;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sqlx::postgres::PgPool;
use whatsapp_client::baileys::{Device, ImportStats, Me, SignedPreKey};
use whatsapp_client::signal::curve::{KeyPair, PrivateKey, PublicKey};
use whatsapp_client::signal::{Address, SessionRecord};
pub use whatsapp_client::store;

/// What Messenger knows the device by, beside its keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Messenger {
    pub fbid: String,
    pub device_id: u32,
    pub device_uuid: String,
}

#[derive(Debug, thiserror::Error)]
#[error("device export: {0}")]
pub struct ImportError(String);

fn fail(reason: impl Into<String>) -> ImportError {
    ImportError(reason.into())
}

#[derive(Deserialize)]
struct Export {
    meta: Vec<MetaRow>,
    identity: Vec<IdentityRow>,
    session: Vec<SessionRow>,
    prekey: Vec<PreKeyRow>,
    #[serde(rename = "signedPrekey")]
    signed_prekey: Vec<SignedPreKeyRow>,
    #[serde(rename = "senderKeySessions", default)]
    sender_key_sessions: Vec<serde_json::Value>,
}

/// `{"key": "regId", "value": {"regId": 1234}}`: the value is wrapped in its own key.
#[derive(Deserialize)]
struct MetaRow {
    key: String,
    value: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct IdentityRow {
    #[serde(rename = "deviceJid")]
    device_jid: String,
    identity: Bytes,
}

#[derive(Deserialize)]
struct SessionRow {
    id: String,
    session: Bytes,
}

#[derive(Deserialize)]
struct PreKeyRow {
    #[serde(rename = "keyId")]
    key_id: u32,
    encoded: Bytes,
    #[serde(rename = "isDeleted", default)]
    is_deleted: bool,
}

#[derive(Deserialize)]
struct SignedPreKeyRow {
    #[serde(rename = "keyId")]
    key_id: u32,
    encoded: Bytes,
}

#[derive(Deserialize)]
struct KeyPairJson {
    #[serde(rename = "publicKey")]
    public_key: Bytes,
    #[serde(rename = "privateKey")]
    private_key: Bytes,
}

#[derive(Deserialize)]
struct Bytes {
    #[serde(rename = "$bytes")]
    b64: String,
}

impl Bytes {
    fn get(&self, what: &str) -> Result<Vec<u8>, ImportError> {
        B64.decode(&self.b64)
            .map_err(|e| fail(format!("{what}: {e}")))
    }
}

// libsignal's storage protobufs, only the fields read here.
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
}

#[derive(Clone, PartialEq, Message)]
struct SessionStructure {
    #[prost(bytes = "vec", tag = "2")]
    local_identity_public: Vec<u8>,
    #[prost(uint32, tag = "11")]
    local_registration_id: u32,
}

/// What the browser stores per contact device: libsignal's whole session record.
#[derive(Clone, PartialEq, Message)]
struct RecordStructure {
    #[prost(message, optional, tag = "1")]
    current_session: Option<SessionStructure>,
    #[prost(message, repeated, tag = "2")]
    previous_sessions: Vec<SessionStructure>,
}

/// 32 raw bytes, or 33 with libsignal's type byte.
fn public_key(raw: &[u8]) -> Result<PublicKey, String> {
    match raw.len() {
        32 => PublicKey::from_djb(raw),
        _ => PublicKey::deserialize(raw),
    }
    .map_err(|e| e.to_string())
}

fn key_pair(public: &[u8], private: &[u8]) -> Result<KeyPair, String> {
    let private = PrivateKey::deserialize(private).map_err(|e| e.to_string())?;
    let public = public_key(public)?;
    if private.public_key().bytes() != public.bytes() {
        return Err("the private key does not belong to the public key".into());
    }
    Ok(KeyPair { public, private })
}

/// `user:device@msgr` as Signal addresses it: by the user alone, as whatsmeow's
/// `SignalAddress` does for a JID with no agent.
fn address(jid: &str) -> Result<Address, ImportError> {
    let bad = || fail(format!("{jid:?} is not a user:device@msgr address"));
    let local = jid.strip_suffix("@msgr").ok_or_else(bad)?;
    let (user, device) = local.split_once(':').ok_or_else(bad)?;
    if user.is_empty() || !user.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    Ok(Address {
        name: user.to_string(),
        device: device.parse().map_err(|_| bad())?,
    })
}

fn meta_value<T: DeserializeOwned>(
    meta: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<T, ImportError> {
    let value = meta
        .get(key)
        .ok_or_else(|| fail(format!("meta {key} is missing")))?;
    serde_json::from_value(value.clone()).map_err(|e| fail(format!("meta {key}: {e}")))
}

/// Reads an export and checks every key. It prints and logs nothing from it.
pub fn import(json: &[u8]) -> Result<(Device, Messenger), ImportError> {
    let export: Export =
        serde_json::from_slice(json).map_err(|e| fail(format!("does not read: {e}")))?;

    let mut meta = HashMap::new();
    for row in export.meta {
        let value = row.value.get(&row.key).cloned().ok_or_else(|| {
            fail(format!(
                "meta {}: the value is not filed under its key",
                row.key
            ))
        })?;
        if meta.insert(row.key.clone(), value).is_some() {
            // Only a store read with its superseded versions repeats a key.
            return Err(fail(format!("meta {} appears twice", row.key)));
        }
    }
    let fbid: String = meta_value(&meta, "fbid")?;
    let device_id: u32 = meta_value(&meta, "deviceId")?;
    let device_uuid: String = meta_value(&meta, "deviceUUID")?;
    let registration_id: u32 = meta_value(&meta, "regId")?;
    let last_pre_key_id: u32 = meta_value(&meta, "lastPrekeyId")?;
    let last_signed_pre_key_id: u32 = meta_value(&meta, "lastSignedPrekeyId")?;
    let pair = |key: &str| -> Result<KeyPair, ImportError> {
        let pair: KeyPairJson = meta_value(&meta, key)?;
        key_pair(&pair.public_key.get(key)?, &pair.private_key.get(key)?)
            .map_err(|e| fail(format!("meta {key}: {e}")))
    };
    let identity = pair("identityKeyPair")?;
    let noise = pair("authKeyPair")?;
    let me = format!("{fbid}:{device_id}@msgr");
    address(&me)?;

    let signed = export
        .signed_prekey
        .iter()
        .find(|row| row.key_id == last_signed_pre_key_id)
        .ok_or_else(|| fail("the current signed pre-key is missing"))?;
    let record =
        SignedPreKeyRecordStructure::decode(signed.encoded.get("signed pre-key")?.as_slice())
            .map_err(|e| fail(format!("signed pre-key: {e}")))?;
    if record.id != signed.key_id {
        return Err(fail("the signed pre-key is filed under another id"));
    }
    let signed_pre_key = SignedPreKey {
        id: record.id,
        key_pair: key_pair(&record.public_key, &record.private_key)
            .map_err(|e| fail(format!("signed pre-key: {e}")))?,
        signature: record.signature,
    };
    if !identity.public.verify_signature(
        &signed_pre_key.key_pair.public.serialize(),
        &signed_pre_key.signature,
    ) {
        return Err(fail("signed pre-key: the identity key did not sign it"));
    }

    let mut pre_keys = BTreeMap::new();
    for row in export.prekey.iter().filter(|row| !row.is_deleted) {
        let record = PreKeyRecordStructure::decode(row.encoded.get("pre-key")?.as_slice())
            .map_err(|e| fail(format!("pre-key: {e}")))?;
        if record.id != row.key_id {
            return Err(fail("a pre-key is filed under another id"));
        }
        let pair = key_pair(&record.public_key, &record.private_key)
            .map_err(|e| fail(format!("pre-key {}: {e}", record.id)))?;
        if pre_keys.insert(record.id, pair).is_some() {
            return Err(fail(format!("pre-key {} appears twice", record.id)));
        }
    }

    let local_identity = identity.public.serialize();
    let mut sessions = HashMap::new();
    let mut archived = 0;
    for row in &export.session {
        let at = address(&row.id)?;
        let bytes = row.session.get("session")?;
        let stored = RecordStructure::decode(bytes.as_slice())
            .map_err(|e| fail(format!("a session: {e}")))?;
        for state in stored
            .current_session
            .iter()
            .chain(&stored.previous_sessions)
        {
            if state.local_identity_public != local_identity {
                return Err(fail("a session was made with another identity key"));
            }
            if state.local_registration_id != registration_id {
                return Err(fail("a session carries another registration id"));
            }
        }
        let record =
            SessionRecord::deserialize(&bytes).map_err(|e| fail(format!("a session: {e}")))?;
        archived += record.archived_sessions();
        if sessions.insert(at, record).is_some() {
            return Err(fail("a session appears twice"));
        }
    }

    let mut identities = HashMap::new();
    for row in &export.identity {
        let key = public_key(&row.identity.get("identity")?)
            .map_err(|e| fail(format!("an identity: {e}")))?;
        if identities.insert(address(&row.device_jid)?, key).is_some() {
            return Err(fail("an identity appears twice"));
        }
    }

    let mut stats = ImportStats {
        current_sessions: sessions
            .values()
            .filter(|r| r.has_current_session())
            .count(),
        archived_sessions: archived,
        ..ImportStats::default()
    };
    if !export.sender_key_sessions.is_empty() {
        // Group sender keys: the server sends them again with the next group message.
        stats
            .not_imported
            .insert("senderKeySessions".into(), export.sender_key_sessions.len());
    }
    let device = Device {
        noise,
        identity,
        registration_id,
        signed_pre_key,
        // WhatsApp's pairing secret. A Messenger device has none.
        adv_secret: Vec::new(),
        account: None,
        me: Some(Me {
            id: me,
            lid: None,
            name: None,
        }),
        platform: None,
        routing_info: None,
        next_pre_key_id: last_pre_key_id + 1,
        first_unuploaded_pre_key_id: last_pre_key_id + 1,
        pre_keys: pre_keys.into_iter().collect(),
        sessions: sessions.into_iter().collect(),
        identities: identities.into_iter().collect(),
        sender_keys: HashMap::new(),
        app_state_keys: BTreeMap::new(),
        lid_mappings: BTreeMap::new(),
        stats,
    };
    Ok((
        device,
        Messenger {
            fbid,
            device_id,
            device_uuid,
        },
    ))
}

/// Replaces everything stored with this device. Needs [`store::migrate`] and the client
/// migrations applied.
pub async fn save(
    pool: &PgPool,
    device: &Device,
    messenger: &Messenger,
) -> Result<(), store::StoreError> {
    // The `client.device` row goes last, and [`load`] needs it: after a crash between the two
    // writes, no device reads back, and the next start imports again.
    sqlx::query("DELETE FROM client.device")
        .execute(pool)
        .await?;
    store::save(pool, device).await?;
    sqlx::query(
        "INSERT INTO client.device (id, fbid, device_id, device_uuid) VALUES (1, $1, $2, $3)",
    )
    .bind(&messenger.fbid)
    .bind(messenger.device_id as i32)
    .bind(&messenger.device_uuid)
    .execute(pool)
    .await?;
    Ok(())
}

/// The stored device, or `None` before one is imported.
pub async fn load(pool: &PgPool) -> Result<Option<(Device, Messenger)>, store::StoreError> {
    let Some((fbid, device_id, device_uuid)) = sqlx::query_as::<_, (String, i32, String)>(
        "SELECT fbid, device_id, device_uuid FROM client.device WHERE id = 1",
    )
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };
    let Some(device) = store::load(pool).await? else {
        return Ok(None);
    };
    Ok(Some((
        device,
        Messenger {
            fbid,
            device_id: device_id as u32,
            device_uuid,
        },
    )))
}
