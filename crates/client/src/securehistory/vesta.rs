//! PIN recovery against Meta's HSM ("Vesta"), the crypto half of mautrix's `vesta.go`: the
//! checks on what the HSM sends, the shapes of its three GraphQL answers, and opening the
//! recovery payload with the keys an [`opaque`](super::opaque) login yields. The requests
//! themselves are not here.
//!
//! The flow: `vestaInit` returns the HSM's RSA and ed25519 keys, each signed by one of the
//! [trust roots](TRUST_ROOTS) ([`verify_hsm_key`]); `vestaBegin` answers KE1 with KE2 ("L2"),
//! signed by that ed25519 key ([`verify_l2`]); `vestaFinish` takes KE3 and returns the
//! payload ([`unpack_login_payload`]).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Sign, PublicKey};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};

/// The RSA keys (PKIX DER, base64) that sign the HSM's keys, from mautrix's `roots.go`.
pub const TRUST_ROOTS: [&str; 4] = [
    "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",
];

/// Whether one of the [`TRUST_ROOTS`] signed `key` (RSA PKCS#1 v1.5 over its SHA-256).
pub fn verify_hsm_key(key: &[u8], signature: &[u8]) -> bool {
    verify_hsm_key_with(&TRUST_ROOTS, key, signature)
}

/// [`verify_hsm_key`] against the given roots; tests use it with a synthetic one. A root
/// that does not parse as an RSA key is skipped, as Go does.
pub fn verify_hsm_key_with(roots: &[&str], key: &[u8], signature: &[u8]) -> bool {
    let digest = Sha256::digest(key);
    roots.iter().any(|root| {
        STANDARD
            .decode(root)
            .ok()
            .and_then(|der| PublicKey::from_public_key_der(&der).ok())
            .is_some_and(|root| {
                root.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, signature)
                    .is_ok()
            })
    })
}

/// Whether the HSM's ed25519 key signed L2 (KE2); what it signs is `[2] ++ l2`.
pub fn verify_l2(ed25519_key: &[u8], l2: &[u8], signature: &[u8]) -> bool {
    let Some(key) = <[u8; 32]>::try_from(ed25519_key)
        .ok()
        .and_then(|k| VerifyingKey::from_bytes(&k).ok())
    else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    let mut signed = Vec::with_capacity(1 + l2.len());
    signed.push(2);
    signed.extend_from_slice(l2);
    key.verify(&signed, &signature).is_ok()
}

/// `vesta.LoginPayload`: the backup key data, sealed under the login's session key.
#[derive(Clone, PartialEq, prost::Message)]
pub struct LoginPayload {
    #[prost(bytes = "vec", required, tag = "1")]
    pub backup_key_data_encrypted: Vec<u8>,
    #[prost(bytes = "vec", required, tag = "2")]
    pub rk_nonce: Vec<u8>,
}

/// `vesta.WaBackupKeyData`: the recovery code, sealed under the login's export key.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WaBackupKeyData {
    #[prost(bytes = "vec", required, tag = "1")]
    pub aes_k: Vec<u8>,
    #[prost(bytes = "vec", required, tag = "2")]
    pub k_nonce: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PayloadError {
    #[error("invalid recovery payload: {0}")]
    Payload(prost::DecodeError),
    #[error("invalid recovery key data: {0}")]
    KeyData(prost::DecodeError),
    #[error("invalid recovery payload key or nonce")]
    KeyOrNonce,
    #[error("recovery payload does not open")]
    Open,
}

/// Opens `vestaFinish`'s payload: the session key opens the key data, whose export-key
/// layer holds the recovery code.
pub fn unpack_login_payload(
    payload: &[u8],
    session_key: &[u8],
    export_key: &[u8],
) -> Result<Vec<u8>, PayloadError> {
    use prost::Message;
    let outer = LoginPayload::decode(payload).map_err(PayloadError::Payload)?;
    let plaintext = open(
        session_key,
        &outer.rk_nonce,
        &outer.backup_key_data_encrypted,
    )?;
    let inner = WaBackupKeyData::decode(plaintext.as_slice()).map_err(PayloadError::KeyData)?;
    open(export_key, &inner.k_nonce, &inner.aes_k)
}

/// AES-128-GCM under the first half of a 64-byte OPAQUE key, as mautrix's `decryptGCM`.
fn open(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PayloadError> {
    if key.len() != 64 || nonce.len() != 12 {
        return Err(PayloadError::KeyOrNonce);
    }
    let cipher = Aes128Gcm::new_from_slice(&key[..16]).map_err(|_| PayloadError::KeyOrNonce)?;
    let nonce = Nonce::try_from(nonce).map_err(|_| PayloadError::KeyOrNonce)?;
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| PayloadError::Open)
}

/// A failed recovery as the HSM reports it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Messenger recovery failed: {code}{}", remaining(.attempts_remaining))]
pub struct RecoveryError {
    pub code: String,
    pub attempts_remaining: Option<i64>,
}

fn remaining(attempts: &Option<i64>) -> String {
    attempts.map_or_else(String::new, |n| format!(" ({n} attempts remaining)"))
}

/// `fbid_based_auth_layer_vesta_login_init`: the HSM's keys and whether a PIN is set.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct VestaInit {
    #[serde(default, with = "b64url", rename = "base64url_encoded_island_rsa_pub")]
    pub rsa_key: Vec<u8>,
    #[serde(
        default,
        with = "b64url",
        rename = "base64url_encoded_island_rsa_pub_signature"
    )]
    pub rsa_signature: Vec<u8>,
    #[serde(
        default,
        with = "b64url",
        rename = "base64url_encoded_island_ed25519_pub"
    )]
    pub ed25519_key: Vec<u8>,
    #[serde(
        default,
        with = "b64url",
        rename = "base64url_encoded_island_ed25519_pub_signature"
    )]
    pub ed25519_signature: Vec<u8>,
    #[serde(default, deserialize_with = "or_default", rename = "is_registered")]
    pub registered: bool,
    #[serde(default)]
    pub attempts_remaining: Option<i64>,
}

/// `fbid_based_auth_layer_vesta_begin_login`: KE2 ("L2") and its signature.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct VestaBegin {
    #[serde(default, with = "b64url", rename = "base64url_encoded_opaque_l2")]
    pub l2: Vec<u8>,
    #[serde(default, with = "b64url", rename = "base64url_encoded_opaque_l2_sig")]
    pub signature: Vec<u8>,
}

/// `fbid_based_auth_layer_vesta_finish_login_v2`: the payload, or `XFBVestaError`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct VestaFinish {
    #[serde(default, deserialize_with = "or_default", rename = "__typename")]
    pub kind: String,
    #[serde(default, with = "b64url", rename = "base64url_encoded_login_payload")]
    pub payload: Vec<u8>,
    #[serde(default, deserialize_with = "or_default", rename = "login_success")]
    pub success: bool,
    #[serde(default, deserialize_with = "or_default", rename = "vesta_error_code")]
    pub error_code: String,
    #[serde(default)]
    pub attempts_remaining: Option<i64>,
    #[serde(default, deserialize_with = "or_default")]
    pub trigger_post_login_register: bool,
}

/// A JSON `null` as the type's default, as Go leaves a field untouched on `null`.
fn or_default<'de, D: Deserializer<'de>, T: Default + Deserialize<'de>>(
    d: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// Go's `jsonbytes.UnpaddedURLBytes`: unpadded URL-safe base64, `null` as empty.
mod b64url {
    use base64::Engine;
    use base64::alphabet::URL_SAFE;
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    use serde::{Deserialize, Deserializer};

    /// Go's `RawURLEncoding`: no padding, and stray low bits in the last character allowed.
    const RAW_URL: GeneralPurpose = GeneralPurpose::new(
        &URL_SAFE,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        match Option::<String>::deserialize(d)? {
            None => Ok(Vec::new()),
            Some(text) => RAW_URL.decode(text).map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A root that stopped parsing would be skipped silently, so check they all parse.
    #[test]
    fn trust_roots_parse() {
        for root in TRUST_ROOTS {
            let der = STANDARD.decode(root).unwrap();
            PublicKey::from_public_key_der(&der).unwrap();
        }
    }
}
