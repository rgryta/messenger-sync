//! The backup's sealed-data format, shared by secrets, epochs and archived messages
//! (mautrix's `decryptData`): a 16-byte salt that HChaCha20 turns the key into an AES-256
//! key with, a 12-byte GCM nonce, then the ciphertext of a big-endian length-prefixed
//! plaintext.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    #[error("ciphertext is too short")]
    TooShort,
    #[error("invalid key length")]
    Key,
    #[error("ciphertext does not open")]
    Open,
    #[error("plaintext is missing its length prefix")]
    NoPrefix,
    #[error("length prefix exceeds plaintext")]
    BadPrefix,
}

/// Opens `ciphertext` sealed under `key` (32 bytes) with `aad`.
pub fn decrypt_data(key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SealError> {
    if ciphertext.len() < 44 {
        return Err(SealError::TooShort);
    }
    let key: [u8; 32] = key.try_into().map_err(|_| SealError::Key)?;
    let salt: [u8; 16] = ciphertext[..16].try_into().expect("16 bytes");
    let derived = chacha20::hchacha::<chacha20::R20>(&key.into(), &salt.into());
    let cipher = Aes256Gcm::new_from_slice(derived.as_slice()).map_err(|_| SealError::Key)?;
    let nonce = Nonce::try_from(&ciphertext[16..28]).map_err(|_| SealError::TooShort)?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext[28..],
                aad,
            },
        )
        .map_err(|_| SealError::Open)?;
    if plaintext.len() < 4 {
        return Err(SealError::NoPrefix);
    }
    let length = u32::from_be_bytes(plaintext[..4].try_into().expect("4 bytes")) as usize;
    if length > plaintext.len() - 4 {
        return Err(SealError::BadPrefix);
    }
    Ok(plaintext[4..4 + length].to_vec())
}
