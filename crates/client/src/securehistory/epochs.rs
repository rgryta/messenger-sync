//! Epoch keys (mautrix's `epochs.go`). Every epoch has a root key; the virtual device's
//! secrets open one of them, and edges lead to the rest: a backward edge seals the previous
//! epoch's keys under a key derived from the newer one, a forward edge seals the next epoch's
//! entropy to an epoch storage key (X25519 twice, HKDF, AES-GCM).

use std::collections::{BTreeMap, HashMap};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hkdf::Hkdf;
use sha2::Sha256;
use whatsapp_client::signal::curve::{KeyError, PrivateKey, PublicKey};

use super::aead::{self, SealError};
use super::device::{DeviceError, go_base64, valid_epoch_anon_id};
use super::{Device, Epoch, EpochDerivationSet, EpochEdge, SyncEpoch, VirtualDevice};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EpochError {
    #[error("invalid Messenger backup epoch")]
    Invalid,
    #[error("Messenger backup epoch key is too long")]
    KeyLength,
    #[error("missing Messenger backup epoch metadata")]
    Metadata,
    #[error(transparent)]
    Secret(#[from] DeviceError),
    #[error("invalid Messenger backup epoch anonymous ID")]
    AnonId,
    #[error("invalid Messenger backup epoch root key")]
    RootKey,
    #[error("missing Messenger backup forward epoch edge")]
    ForwardEdge,
    #[error("missing Messenger backup forward epoch")]
    ForwardEpoch,
    #[error("cycle in Messenger backup epoch chain")]
    Cycle,
    #[error("missing or unsupported Messenger backup epoch edge")]
    BackwardEdge,
    #[error("invalid recovered Messenger backup epoch")]
    Recovered,
    #[error("invalid Messenger backup forward epoch")]
    Forward,
    #[error("backup epoch PSK fingerprint mismatch")]
    PskFingerprint,
    #[error("failed to decrypt Messenger backup epoch entropy: {0}")]
    Entropy(EnvelopeError),
    #[error("failed to decrypt Messenger backup epoch: {0}")]
    Value(SealError),
    #[error("Messenger backup epoch value is not base64")]
    ValueEncoding,
    #[error("backup epoch source mismatch")]
    SourceMismatch,
    #[error("invalid Messenger backup epoch destination")]
    Destination,
    #[error("Messenger backup epoch anonymous ID is not a sequence number")]
    Sequence,
    #[error("backup forward epoch mismatch")]
    ForwardMismatch,
    #[error("backup backward epoch mismatch")]
    BackwardMismatch,
    #[error("backup epoch destination fingerprint mismatch")]
    DestinationFingerprint,
}

/// Why a forward edge's sealed entropy did not open.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("invalid or unsupported Messenger backup public-key envelope")]
    Format,
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error("message authentication failed")]
    Open,
}

/// HKDF-SHA256, `None` when `size` exceeds what HKDF can expand to.
fn hkdf(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], size: usize) -> Option<Vec<u8>> {
    let mut out = vec![0; size];
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut out)
        .ok()
        .map(|()| out)
}

/// The 18-byte debug fingerprint the server pins keys with (base64 in edges).
pub(crate) fn fingerprint(key: &[u8], name: &str) -> Vec<u8> {
    let info = format!("meb/debug/fingerprint/{name}");
    hkdf(key, None, info.as_bytes(), 18).expect("18 bytes")
}

fn matches_fingerprint(key: &[u8], name: &str, expected: &str) -> bool {
    STANDARD.encode(fingerprint(key, name)) == expected
}

/// Derives a `size`-byte key named `name` from an epoch's root key, bound to its anonymous id.
pub fn derive_epoch_key(epoch: &Epoch, name: &str, size: usize) -> Result<Vec<u8>, EpochError> {
    if epoch.root_key.len() != 32 || !valid_epoch_anon_id(&epoch.anon_id) {
        return Err(EpochError::Invalid);
    }
    let info = format!("{name}_{}", STANDARD.encode(&epoch.anon_id));
    hkdf(&epoch.root_key, None, info.as_bytes(), size).ok_or(EpochError::KeyLength)
}

impl VirtualDevice {
    /// Every epoch the virtual device reaches: its base epoch from its secrets, the epochs
    /// after it up to the latest over forward edges, and those before it over backward edges.
    pub fn derive_epochs(&self) -> Result<BTreeMap<String, Epoch>, EpochError> {
        let info = &self.info;
        let Some(secrets) = &info.secrets else {
            return Err(EpochError::Metadata);
        };
        if info.epoch_id.is_empty() || info.last_epoch_id.is_empty() {
            return Err(EpochError::Metadata);
        }
        let anon_id = self.decrypt_secret(&secrets.epoch_anon_id, "epoch_anon_id")?;
        if !valid_epoch_anon_id(&anon_id) {
            return Err(EpochError::AnonId);
        }
        let root_key = self.decrypt_secret(&secrets.epoch_root_key, "epoch_root_key")?;
        if root_key.len() != 32 {
            return Err(EpochError::RootKey);
        }
        // Later entries win, as in Go's map.
        let server: HashMap<&str, &SyncEpoch> =
            info.epochs.iter().map(|e| (e.id.as_str(), e)).collect();
        let base = Epoch {
            id: info.epoch_id.clone(),
            anon_id,
            root_key,
        };
        let mut epochs = BTreeMap::from([(base.id.clone(), base.clone())]);
        if base.id != info.last_epoch_id {
            let private_key = self.decrypt_secret(
                &secrets.epoch_storage_private_key,
                "epoch_storage_private_key",
            )?;
            let mut current = base.clone();
            while current.id != info.last_epoch_id {
                let Some(at) = server
                    .get(current.id.as_str())
                    .filter(|e| !e.next_id.is_empty())
                else {
                    return Err(EpochError::ForwardEdge);
                };
                if epochs.contains_key(&at.next_id) {
                    return Err(EpochError::Cycle);
                }
                let next = server
                    .get(at.next_id.as_str())
                    .ok_or(EpochError::ForwardEpoch)?;
                current = derive_next_epoch(
                    &current,
                    next,
                    &info.epoch_storage_public_key,
                    &private_key,
                    "",
                )?;
                epochs.insert(current.id.clone(), current.clone());
            }
        }
        let mut current = base;
        while let Some(at) = server
            .get(current.id.as_str())
            .filter(|e| !e.previous_id.is_empty())
        {
            if epochs.contains_key(&at.previous_id) {
                return Err(EpochError::Cycle);
            }
            let (Some(previous), Some(data)) =
                (server.get(at.previous_id.as_str()), &at.encrypted_data)
            else {
                return Err(EpochError::BackwardEdge);
            };
            let key = derive_epoch_key(&current, "epoch_data_storage", 32)?;
            let anon_id = decrypt_epoch_value(&key, &data.anon_id)?;
            let root_key = decrypt_epoch_value(&key, &data.root_key)?;
            if !valid_epoch_anon_id(&anon_id) || root_key.len() != 32 {
                return Err(EpochError::Recovered);
            }
            current = Epoch {
                id: previous.id.clone(),
                anon_id,
                root_key,
            };
            epochs.insert(current.id.clone(), current.clone());
        }
        Ok(epochs)
    }
}

/// The epoch after `current`: its entropy, sealed to the storage key with a pre-shared key
/// chained from `current`, mixed with the rest of that chain. A non-empty `psk_fingerprint`
/// must match the pre-shared key.
fn derive_next_epoch(
    current: &Epoch,
    next: &SyncEpoch,
    public_key: &[u8],
    private_key: &[u8],
    psk_fingerprint: &str,
) -> Result<Epoch, EpochError> {
    if !valid_epoch_anon_id(next.anon_id.as_bytes()) || current.root_key.len() != 32 {
        return Err(EpochError::Forward);
    }
    let mut info = b"epoch_chaining_".to_vec();
    info.extend_from_slice(&current.anon_id);
    info.push(b'_');
    info.extend_from_slice(current.id.as_bytes());
    let chain = hkdf(&current.root_key, None, &info, 64).expect("64 bytes");
    let (salt, psk) = chain.split_at(32);
    if !psk_fingerprint.is_empty()
        && !matches_fingerprint(psk, "MEBCryptoPreSharedKey", psk_fingerprint)
    {
        return Err(EpochError::PskFingerprint);
    }
    let aad = format!("epoch__{}", next.anon_id);
    let entropy = decrypt_public(
        public_key,
        private_key,
        &next.auth_public_key,
        psk,
        aad.as_bytes(),
        &next.encrypted_key,
    )
    .map_err(EpochError::Entropy)?;
    let root_key = hkdf(&entropy, Some(salt), b"epoch_root_key", 32).expect("32 bytes");
    Ok(Epoch {
        id: next.id.clone(),
        anon_id: next.anon_id.as_bytes().to_vec(),
        root_key,
    })
}

/// An epoch's anonymous id as the sequence number it is, as Go's `strconv.ParseUint`.
fn sequence(anon_id: &[u8]) -> Result<u64, EpochError> {
    if anon_id.is_empty() || !anon_id.iter().all(u8::is_ascii_digit) {
        return Err(EpochError::Sequence);
    }
    std::str::from_utf8(anon_id)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or(EpochError::Sequence)
}

impl Device {
    /// This device with the epochs `set` leads to added, each edge checked against the
    /// fingerprints the server sent. Edges may start from epochs earlier edges added; on any
    /// failure nothing is kept.
    pub fn with_epochs(&self, set: Option<&EpochDerivationSet>) -> Result<Device, EpochError> {
        let mut updated = self.clone();
        for edge in set.map(|s| s.edges.as_slice()).unwrap_or_default() {
            updated.apply_edge(edge)?;
        }
        Ok(updated)
    }

    fn apply_edge(&mut self, edge: &EpochEdge) -> Result<(), EpochError> {
        let source = match self.epochs.get(&edge.from.id) {
            Some(source)
                if STANDARD.encode(&source.anon_id) == edge.from.anon_id
                    && matches_fingerprint(
                        &source.root_key,
                        "MEBEpochRootKey",
                        &edge.from_fingerprint,
                    ) =>
            {
                source.clone()
            }
            _ => return Err(EpochError::SourceMismatch),
        };
        let anon_id = go_base64(edge.to.anon_id.as_bytes())
            .filter(|anon| valid_epoch_anon_id(anon) && !edge.to.id.is_empty())
            .ok_or(EpochError::Destination)?;
        let from_sequence = sequence(&source.anon_id)?;
        let to_sequence = sequence(&anon_id)?;
        let target = if let Some(forward) = &edge.forward {
            if to_sequence != from_sequence.wrapping_add(1)
                || self.storage_public_key != forward.storage_public_key
                || forward.psk_fingerprint.is_empty()
            {
                return Err(EpochError::ForwardMismatch);
            }
            let next = SyncEpoch {
                id: edge.to.id.clone(),
                anon_id: String::from_utf8(anon_id).expect("validated as ASCII digits"),
                auth_public_key: forward.auth_public_key.clone(),
                encrypted_key: forward.encrypted_entropy.clone(),
                ..SyncEpoch::default()
            };
            derive_next_epoch(
                &source,
                &next,
                &self.storage_public_key,
                &self.storage_private_key,
                &forward.psk_fingerprint,
            )?
        } else {
            if from_sequence != to_sequence.wrapping_add(1) || edge.backward.is_empty() {
                return Err(EpochError::BackwardMismatch);
            }
            let key = derive_epoch_key(&source, "epoch_data_storage", 32)?;
            Epoch {
                id: edge.to.id.clone(),
                anon_id,
                root_key: decrypt_epoch_value(&key, &edge.backward)?,
            }
        };
        if target.root_key.len() != 32
            || !matches_fingerprint(&target.root_key, "MEBEpochRootKey", &edge.to_fingerprint)
        {
            return Err(EpochError::DestinationFingerprint);
        }
        self.epochs.insert(target.id.clone(), target);
        Ok(())
    }
}

/// Opens a forward edge's envelope: version byte 1, the ephemeral key, then AES-256-GCM under
/// a zero nonce. The key is HKDF over both agreements (with the sender's auth key and with the
/// ephemeral key), salted with the pre-shared key, with the bound context as info and AAD.
fn decrypt_public(
    public_key: &[u8],
    private_key: &[u8],
    sender_key: &[u8],
    psk: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    if ciphertext.len() < 49 || ciphertext[0] != 1 || public_key.len() != 32 || psk.len() > 32 {
        return Err(EnvelopeError::Format);
    }
    let private = PrivateKey::deserialize(private_key)?;
    let sender = PublicKey::from_djb(sender_key)?;
    let ephemeral = PublicKey::from_djb(&ciphertext[1..33])?;
    let mut secret = private.agreement(&sender)?.to_vec();
    secret.extend_from_slice(&private.agreement(&ephemeral)?);
    let mut inner = vec![1];
    inner.extend_from_slice(sender_key);
    inner.extend_from_slice(public_key);
    inner.extend_from_slice(&ciphertext[1..33]);
    inner.extend_from_slice(aad);
    let key = hkdf(&secret, Some(psk), &inner, 32).expect("32 bytes");
    Aes256Gcm::new_from_slice(&key)
        .expect("32-byte key")
        .decrypt(
            &Nonce::default(),
            Payload {
                msg: &ciphertext[33..],
                aad: &inner,
            },
        )
        .map_err(|_| EnvelopeError::Open)
}

/// Opens a backward edge's value: sealed data holding base64 text.
fn decrypt_epoch_value(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, EpochError> {
    let value =
        aead::decrypt_data(key, ciphertext, b"epoch_data_metadata").map_err(EpochError::Value)?;
    go_base64(&value).ok_or(EpochError::ValueEncoding)
}
