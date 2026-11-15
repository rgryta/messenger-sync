//! Minos, the archive's newer per-message format (`top_level_protobuf_v2`): each message is
//! sealed under a message encryption key (MEK), and each MEK reaches this mailbox sealed with
//! hybrid HPKE (X25519 + ML-KEM-768) to a key pair derived from an epoch's root key.
//! Ported from mautrix's `minos.go` and `minos_cipher.go`, the decrypt side only, and the
//! per-message checks of `MessageRange.Decrypt` in `history.go`.

use std::collections::HashMap;

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::{Decapsulate, DecapsulationKey, KeyExport, MlKem768};
use prost::Message;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use super::archive::DecryptedProtobuf;
use super::proto::BackupMessage;
use super::{Device, Epoch, MinosKeyEntry, MinosProtobuf};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MinosError {
    #[error("missing Messenger Minos message metadata")]
    Metadata,
    #[error("unsupported Messenger Minos server-origin message")]
    ServerOrigin,
    #[error("invalid Messenger Minos message timestamp")]
    Timestamp,
    #[error("invalid Messenger Minos message ID")]
    MessageId,
    #[error("unsupported Messenger Minos metadata version")]
    MetadataVersion,
    #[error("missing or mismatched Messenger Minos message key")]
    MessageKey,
    #[error("invalid Messenger Minos message: {0}")]
    Decode(prost::DecodeError),
    #[error("mismatched Messenger Minos sender or timestamp")]
    Mismatch,
    #[error("incomplete Minos MEK")]
    IncompleteMek,
    #[error("invalid Minos MEK metadata")]
    MekMetadata,
    #[error("missing Minos recipient epoch")]
    RecipientEpoch,
    #[error("missing Minos recipient epoch head")]
    RecipientHead,
    #[error("invalid Minos sender epoch head")]
    SenderHead,
    #[error("invalid Minos transport MEK signature: {0}")]
    TransportSignature(Box<MinosError>),
    #[error("unsupported Minos MEK sender")]
    Sender,
    #[error("invalid Minos epoch")]
    Epoch,
    #[error("invalid Minos HPKE envelope")]
    Envelope,
    #[error("X25519 agreement produced the all-zero secret")]
    Agreement,
    #[error("Minos ciphertext does not open")]
    Open,
    #[error("invalid Minos message encryption key")]
    Key,
    #[error("unsupported Minos message encryption version {0}")]
    CipherVersion(i64),
    #[error("invalid Minos signing key or signature")]
    SignatureFormat,
    #[error("invalid Minos signing public key")]
    SigningKey,
    #[error("invalid Minos signature")]
    Signature,
    #[error("invalid Minos AES-GCM ciphertext length")]
    CiphertextLength,
    #[error("invalid Minos DNDK key or ciphertext length")]
    DndkLength,
    #[error("minos DNDK key commitment mismatch")]
    Commitment,
}

const MINOS_KDF_SALT: [u8; 32] = [
    0x62, 0xb9, 0x88, 0x19, 0xba, 0xde, 0x10, 0x74, 0xe9, 0x0f, 0x97, 0x2d, 0x80, 0x88, 0x21, 0x0b,
    0xcb, 0xf8, 0x62, 0x29, 0xb0, 0xd1, 0x19, 0x0f, 0xb0, 0x96, 0x6a, 0x43, 0xb1, 0x43, 0x91, 0xf3,
];

/// The DHKEM(X25519) suite id, and the HPKE suite the MEK envelope is sealed with.
const KEM_SUITE: &[u8] = b"KEM\x00\x20";
const HPKE_SUITE: &[u8] = b"HPKE\x00\x02\x00\x01\x00\x02";

/// HKDF-SHA256 extract-and-expand, as Go's `hkdf.Key`; `length` is always far below the limit.
pub(crate) fn hkdf_key(secret: &[u8], salt: Option<&[u8]>, info: &[u8], length: usize) -> Vec<u8> {
    let mut out = vec![0; length];
    Hkdf::<Sha256>::new(salt, secret)
        .expand(info, &mut out)
        .expect("HKDF-SHA256 output length is below 255 blocks");
    out
}

fn minos_kdf(root: &[u8], info: &str, length: usize) -> Vec<u8> {
    hkdf_key(root, Some(&MINOS_KDF_SALT), info.as_bytes(), length)
}

fn hpke_extract(suite: &[u8], salt: &[u8], label: &str, input: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(salt).expect("HMAC takes any key");
    mac.update(b"HPKE-v1");
    mac.update(suite);
    mac.update(label.as_bytes());
    mac.update(input);
    mac.finalize().into_bytes().into()
}

fn hpke_expand(suite: &[u8], key: &[u8; 32], label: &str, info: &[u8], length: u16) -> Vec<u8> {
    let mut context = length.to_be_bytes().to_vec();
    context.extend_from_slice(b"HPKE-v1");
    context.extend_from_slice(suite);
    context.extend_from_slice(label.as_bytes());
    context.extend_from_slice(info);
    let mut out = vec![0; length.into()];
    Hkdf::<Sha256>::from_prk(key)
        .expect("a 32-byte PRK")
        .expand(&context, &mut out)
        .expect("HKDF-SHA256 output length is below 255 blocks");
    out
}

/// `%x` of a byte string.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Go's `strconv.ParseUint(s, 10, 64)`: digits only, no sign.
pub(crate) fn parse_uint(text: &str) -> Option<u64> {
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// An X25519 agreement, refused when it is all zero as Go's `ecdh` refuses it.
fn agree(secret: &StaticSecret, public: &[u8; 32]) -> Result<[u8; 32], MinosError> {
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    if shared.was_contributory() {
        Ok(*shared.as_bytes())
    } else {
        Err(MinosError::Agreement)
    }
}

/// The epoch's mailbox key pair: an X25519 key and an ML-KEM-768 key, both from one seed.
fn mailbox_keys(epoch: &Epoch) -> Result<(StaticSecret, DecapsulationKey<MlKem768>), MinosError> {
    let number = std::str::from_utf8(&epoch.anon_id)
        .ok()
        .and_then(parse_uint)
        .filter(|_| epoch.root_key.len() == 32)
        .ok_or(MinosError::Epoch)?;
    let seed = minos_kdf(
        &epoch.root_key,
        &format!("minos.kdf.export_root_key.encryption_keypair:epoch_number={number}"),
        32,
    );
    let prk = hpke_extract(KEM_SUITE, &[], "dkp_prk", &seed);
    let x25519: [u8; 32] = hpke_expand(KEM_SUITE, &prk, "sk", &[], 32)
        .try_into()
        .expect("32 bytes");
    let mut kem_seed = hkdf_key(&seed, None, b"mlkem768.derive_keypair.d", 32);
    kem_seed.extend(hkdf_key(&seed, None, b"mlkem768.derive_keypair.z", 32));
    let kem_seed = ml_kem::Seed::try_from(kem_seed.as_slice()).expect("64 bytes");
    Ok((
        StaticSecret::from(x25519),
        DecapsulationKey::from_seed(kem_seed),
    ))
}

/// Opens a MEK envelope: `0x03`, the sender's ephemeral X25519 key, the ML-KEM ciphertext,
/// then AES-256-GCM under the combined secret. `auth_pk` authenticates the sender.
fn open_hpke(
    sk: &StaticSecret,
    kem: &DecapsulationKey<MlKem768>,
    auth_pk: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, MinosError> {
    if auth_pk.len() != 33 || auth_pk[0] != 3 || ciphertext.len() < 1137 || ciphertext[0] != 3 {
        return Err(MinosError::Envelope);
    }
    let ephemeral: &[u8; 32] = ciphertext[1..33].try_into().expect("32 bytes");
    let auth: &[u8; 32] = auth_pk[1..].try_into().expect("32 bytes");
    let mut dh_input = agree(sk, ephemeral)?.to_vec();
    dh_input.extend(agree(sk, auth)?);
    let mut kem_context = ephemeral.to_vec();
    kem_context.extend(PublicKey::from(sk).as_bytes());
    kem_context.extend(auth);
    let eae_prk = hpke_extract(KEM_SUITE, &[], "eae_prk", &dh_input);
    let dh_secret = hpke_expand(KEM_SUITE, &eae_prk, "shared_secret", &kem_context, 32);
    let kem_ciphertext = &ciphertext[33..1121];
    let kem_secret = kem
        .decapsulate_slice(kem_ciphertext)
        .expect("1088 bytes is an ML-KEM-768 ciphertext");
    let combined = [
        dh_secret.as_slice(),
        kem_secret.as_slice(),
        ephemeral,
        kem_ciphertext,
        kem.encapsulation_key().to_bytes().as_slice(),
    ]
    .concat();
    let shared = hkdf_key(&combined, None, b"hawk_final", 32);
    let context = [
        &[2][..],
        &hpke_extract(HPKE_SUITE, &[], "psk_id_hash", &[]),
        &hpke_extract(HPKE_SUITE, &[], "info_hash", &[]),
    ]
    .concat();
    let secret = hpke_extract(HPKE_SUITE, &shared, "secret", &[]);
    let key = hpke_expand(HPKE_SUITE, &secret, "key", &context, 32);
    let nonce = hpke_expand(HPKE_SUITE, &secret, "base_nonce", &context, 12);
    Aes256Gcm::new_from_slice(&key)
        .expect("32-byte key")
        .decrypt(
            &Nonce::try_from(nonce.as_slice()).expect("12 bytes"),
            Payload {
                msg: &ciphertext[1121..],
                aad,
            },
        )
        .map_err(|_| MinosError::Open)
}

/// Opens the MEK a key entry carries for this device, from a Minos sender (another
/// mailbox) or a transport sender (a device, whose ephemeral key `transport_signing_pk`
/// signs).
pub(crate) fn decrypt_minos_mek(
    device: &Device,
    entry: &MinosKeyEntry,
    transport_signing_pk: &[u8],
) -> Result<Vec<u8>, MinosError> {
    let keys = entry.keys.as_ref().ok_or(MinosError::IncompleteMek)?;
    let (Some(mek), Some(recipient), Some(creator)) =
        (&keys.mek_info, &keys.recipient_info, &keys.creator_info)
    else {
        return Err(MinosError::IncompleteMek);
    };
    if mek.id.len() != 12
        || mek.roster_hash.len() != 32
        || !(1..=2).contains(&mek.encryption_version)
    {
        return Err(MinosError::MekMetadata);
    }
    let epoch = device
        .epochs
        .get(&recipient.epoch_id)
        .filter(|e| e.anon_id == recipient.epoch_anon)
        .ok_or(MinosError::RecipientEpoch)?;
    let (suffix, recipient_context) = if mek.encryption_version == 2 {
        if recipient.epoch_head.len() != 32 {
            return Err(MinosError::RecipientHead);
        }
        (
            "_v2",
            format!(";recipient_epoch={}", hex(&recipient.epoch_head)),
        )
    } else {
        ("", String::new())
    };
    let (mek_id, roster) = (hex(&mek.id), hex(&mek.roster_hash));
    let (auth_pk, aad) = match (&creator.minos, &creator.transport) {
        (Some(minos), None) => {
            if minos.epoch_head.len() != 32 {
                return Err(MinosError::SenderHead);
            }
            let aad = format!(
                "minos.hpke.mek_distribution_from_minos{suffix}:mek_id={mek_id}{recipient_context};recipient_roster_hash={roster};sender_epoch={}",
                hex(&minos.epoch_head)
            );
            (&minos.auth_public_key, aad)
        }
        (None, Some(transport)) => {
            let auth = &transport.ephemeral_public_key;
            let signed = format!(
                "minos.structured_signature.mek_distribution.ephemeral_auth:ephemeral_auth_pubkey={};mek_id={mek_id}",
                hex(auth)
            );
            if verify_signature(
                transport_signing_pk,
                &transport.signature,
                signed.as_bytes(),
            )
            .is_err()
            {
                let signed = format!(
                    "minos.structured_signature.mek_distribution:ephemeral_auth_pubkey={};mek_id={mek_id}",
                    hex(auth)
                );
                verify_signature(
                    transport_signing_pk,
                    &transport.signature,
                    signed.as_bytes(),
                )
                .map_err(|e| MinosError::TransportSignature(Box::new(e)))?;
            }
            let aad = format!(
                "minos.hpke.mek_distribution_from_transport{suffix}:mek_id={mek_id}{recipient_context};recipient_roster_hash={roster};sender_transport_pubkey={}",
                hex(transport_signing_pk)
            );
            (auth, aad)
        }
        _ => return Err(MinosError::Sender),
    };
    let (sk, kem) = mailbox_keys(epoch)?;
    open_hpke(&sk, &kem, auth_pk, &mek.encrypted, aad.as_bytes())
}

/// ed25519's group order, little-endian: Go's `ed25519.Verify` takes only an `s` below it.
const GROUP_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// An XEdDSA signature (libsignal's) by a Curve25519 key, both carried with a `0x04` prefix.
pub(crate) fn verify_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), MinosError> {
    if public_key.len() != 33 || public_key[0] != 4 || signature.len() != 65 || signature[0] != 4 {
        return Err(MinosError::SignatureFormat);
    }
    let key: &[u8; 32] = public_key[1..].try_into().expect("32 bytes");
    // Go refuses a small-order key by agreeing with it under the zero private key.
    agree(&StaticSecret::from([0; 32]), key).map_err(|_| MinosError::SigningKey)?;
    let signature = &signature[1..];
    let mut s: [u8; 32] = signature[32..].try_into().expect("32 bytes");
    s[31] &= 0x7f;
    let canonical = s.iter().rev().cmp(GROUP_ORDER.iter().rev()).is_lt();
    let curve = whatsapp_client::signal::curve::PublicKey::from_djb(key)
        .expect("32 bytes is a Curve25519 key");
    if canonical && curve.verify_signature(message, signature) {
        Ok(())
    } else {
        Err(MinosError::Signature)
    }
}

/// What a Minos message's encryption authenticates besides its bytes.
pub(crate) struct MinosMessageMetadata<'a> {
    pub mek_id: &'a [u8],
    pub message_id: &'a str,
    pub thread_id: &'a [u8],
    pub timestamp: u64,
}

/// Opens a Minos message under its MEK: a 17-byte MEK (type 1) opens with AES-128-GCM, a
/// 33-byte one (type 2) with DNDK; the encryption version picks the key and data labels.
pub(crate) fn decrypt_minos_message(
    metadata: &MinosMessageMetadata,
    stanza: &MinosProtobuf,
    mek: &[u8],
) -> Result<Vec<u8>, MinosError> {
    match (mek.first(), mek.len()) {
        (Some(1), 17) | (Some(2), 33) => {}
        _ => return Err(MinosError::Key),
    }
    if stanza.encryption_version != 1 && stanza.encryption_version != 2 {
        return Err(MinosError::CipherVersion(stanza.encryption_version));
    }
    let signed = [
        b"minos.unstructured_signature.message:".as_slice(),
        &stanza.encrypted,
    ]
    .concat();
    verify_signature(&stanza.transport_signing_pk, &stanza.signature, &signed)?;
    let (mek_id, thread, id, ts) = (
        hex(metadata.mek_id),
        hex(metadata.thread_id),
        metadata.message_id,
        metadata.timestamp,
    );
    let (info, aad) = if stanza.encryption_version == 2 {
        (
            format!(
                "minos.kdf.mek.single_message_key:;message_id={id};thread_id={thread};timestamp={ts}"
            ),
            format!(
                "minos.symmetric_enc.message_v2:mek_id={mek_id};message_id={id};sender_transport_pk={};thread_id={thread};timestamp={ts}",
                hex(&stanza.transport_signing_pk)
            ),
        )
    } else {
        (
            "minos.kdf.mek.sender_key".to_string(),
            format!(
                "minos.symmetric_enc.message:mek_id={mek_id};message_id={id};thread_id={thread};timestamp={ts}"
            ),
        )
    };
    let key = minos_kdf(mek, &info, mek.len() - 1);
    if mek[0] == 2 {
        return decrypt_dndk(&key, &stanza.encrypted, aad.as_bytes());
    }
    if stanza.encrypted.len() < 28 {
        return Err(MinosError::CiphertextLength);
    }
    Aes128Gcm::new_from_slice(&key)
        .expect("16-byte key")
        .decrypt(
            &Nonce::try_from(&stanza.encrypted[..12]).expect("12 bytes"),
            Payload {
                msg: &stanza.encrypted[12..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| MinosError::Open)
}

/// AES-GCM with a key derived per message and committed to (DNDK): a 15-byte derivation
/// input, a 9-byte nonce, the AES-256-GCM ciphertext, then the 32-byte key commitment.
fn decrypt_dndk(key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, MinosError> {
    if key.len() != 32 || ciphertext.len() < 72 {
        return Err(MinosError::DndkLength);
    }
    let block = aes::Aes256::new_from_slice(key).expect("32-byte key");
    let mut blocks = [[0u8; 16]; 5];
    for (i, out) in blocks.iter_mut().enumerate() {
        let mut input = [0u8; 16];
        input[..15].copy_from_slice(&ciphertext[..15]);
        input[15] = 224 + i as u8;
        let mut cell = aes::Block::from(input);
        block.encrypt_block(&mut cell);
        out.copy_from_slice(&cell);
    }
    let (mut derived, mut commitment) = ([0u8; 32], [0u8; 32]);
    for i in 0..16 {
        derived[i] = blocks[0][i] ^ blocks[1][i];
        derived[i + 16] = blocks[0][i] ^ blocks[2][i];
        commitment[i] = blocks[0][i] ^ blocks[3][i];
        commitment[i + 16] = blocks[0][i] ^ blocks[4][i];
    }
    let (body, tail) = ciphertext.split_at(ciphertext.len() - 32);
    if !bool::from(commitment.ct_eq(tail)) {
        return Err(MinosError::Commitment);
    }
    let mut nonce = [0u8; 12];
    nonce[..9].copy_from_slice(&ciphertext[15..24]);
    Aes256Gcm::new_from_slice(&derived)
        .expect("32-byte key")
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &body[24..],
                aad,
            },
        )
        .map_err(|_| MinosError::Open)
}

/// Decrypts a page's Minos stanzas: its key entries by id, and each MEK once opened.
pub(crate) struct MinosReader<'a> {
    device: &'a Device,
    keys: HashMap<&'a str, &'a MinosKeyEntry>,
    meks: HashMap<String, Vec<u8>>,
    thread_id: &'a str,
    /// What Minos authenticates as the thread: a DM's two user ids, lower first, else the id.
    minos_thread_id: String,
    self_user_id: i64,
    is_group: bool,
}

impl<'a> MinosReader<'a> {
    pub(crate) fn new(
        device: &'a Device,
        keys: &'a [MinosKeyEntry],
        thread_id: &'a str,
        self_user_id: i64,
        is_group: bool,
    ) -> Self {
        let minos_thread_id = if is_group {
            thread_id.to_string()
        } else {
            let own = self_user_id.to_string();
            if own.as_str() < thread_id {
                format!("{own}:{thread_id}")
            } else {
                format!("{thread_id}:{own}")
            }
        };
        Self {
            device,
            keys: keys.iter().map(|k| (k.id.as_str(), k)).collect(),
            meks: HashMap::new(),
            thread_id,
            minos_thread_id,
            self_user_id,
            is_group,
        }
    }

    /// One Minos stanza, `message_id` being the message's otid (or a supplemental's).
    pub(crate) fn decrypt(
        &mut self,
        stanza: &MinosProtobuf,
        message_id: &str,
    ) -> Result<DecryptedProtobuf, MinosError> {
        if stanza.actor_token.is_empty()
            || message_id.is_empty()
            || self.thread_id.is_empty()
            || (!self.is_group && self.self_user_id <= 0)
        {
            return Err(MinosError::Metadata);
        }
        if !stanza.server_origin_content_type.is_null() {
            return Err(MinosError::ServerOrigin);
        }
        let timestamp = stanza.timestamp;
        let authenticated = match stanza.metadata_version {
            _ if timestamp < 0 => return Err(MinosError::Timestamp),
            1 => timestamp as u64,
            2 => parse_uint(message_id).ok_or(MinosError::MessageId)? >> 22,
            _ => return Err(MinosError::MetadataVersion),
        };
        let entry = self
            .keys
            .get(stanza.mek_fbid.as_str())
            .copied()
            .filter(|k| {
                k.keys
                    .as_ref()
                    .and_then(|k| k.mek_info.as_ref())
                    .is_some_and(|m| m.id == stanza.mek_id)
            })
            .ok_or(MinosError::MessageKey)?;
        if !self.meks.contains_key(&stanza.mek_fbid) {
            let mek = decrypt_minos_mek(self.device, entry, &stanza.transport_signing_pk)?;
            self.meks.insert(stanza.mek_fbid.clone(), mek);
        }
        let plaintext = decrypt_minos_message(
            &MinosMessageMetadata {
                mek_id: &stanza.mek_id,
                message_id,
                thread_id: self.minos_thread_id.as_bytes(),
                timestamp: authenticated,
            },
            stanza,
            &self.meks[&stanza.mek_fbid],
        )?;
        let message = BackupMessage::decode(plaintext.as_slice()).map_err(MinosError::Decode)?;
        if message.timestamp_ms() != Some(timestamp) || message.sender_id() != stanza.actor_token {
            return Err(MinosError::Mismatch);
        }
        Ok(DecryptedProtobuf {
            message,
            timestamp_ms: timestamp,
        })
    }
}
