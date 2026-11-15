//! The backup's virtual device: the id and key the recovery code derives, the query that
//! fetches what the server holds for it, and opening the secrets sealed under its key
//! (mautrix's `device.go`). The request itself is the caller's: this builds its variables and
//! reads its result.

use base64::Engine;
use base64::alphabet::STANDARD as ALPHABET;
use base64::engine::general_purpose::STANDARD;
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use hkdf::Hkdf;
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;

use super::{Backup, VirtualDevice, VirtualDeviceInfo, aead};

/// The GraphQL query that fetches the virtual device, and the field its result sits under.
pub const FETCH_QUERY: &str = "EBAddDeviceGraphQLEBFetchVirtualDeviceInfoQuery";
pub const FETCH_FIELD: &str = "fetch_virtual_device_info_for_device_addition_v2";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeviceError {
    #[error("no Messenger PIN backup found")]
    NoPinBackup,
    #[error("invalid Messenger recovery account")]
    Account,
    #[error("invalid Messenger recovery code or account")]
    Code,
    #[error("backup device query failed: {0}")]
    Rejected(String),
    #[error("backup device query failed")]
    Failed,
    #[error("invalid backup device query result: {0}")]
    Response(String),
    #[error("failed to decrypt Messenger backup {0}")]
    Secret(String),
}

/// Whether `id` is an epoch's anonymous id: one to eleven ASCII digits.
pub fn valid_epoch_anon_id(id: &[u8]) -> bool {
    !id.is_empty() && id.len() <= 11 && id.iter().all(u8::is_ascii_digit)
}

/// Derives the virtual device's id and blob key from the 40-character recovery code and the
/// backup owner's id. Codes starting with `1` carry a 35-byte secret and an 8-byte id, codes
/// starting with `2` a 34-byte secret and a 16-byte id.
pub fn derive_virtual_device(
    code: &[u8],
    owner_id: &str,
) -> Result<(Vec<u8>, Vec<u8>), DeviceError> {
    if code.len() != 40 || (code[0] != b'1' && code[0] != b'2') || owner_id.is_empty() {
        return Err(DeviceError::Code);
    }
    let (secret_len, id_len) = if code[0] == b'1' { (35, 8) } else { (34, 16) };
    // Go's `%c` writes a byte as the code point of the same value.
    let info = format!(
        "BackupRecoveryCode_v{}_{}_{owner_id}",
        char::from(code[0]),
        char::from(code[1])
    );
    let mut derived = vec![0; id_len + 32];
    Hkdf::<Sha256>::new(None, &code[2..2 + secret_len])
        .expand(info.as_bytes(), &mut derived)
        .expect("at most 48 bytes, far below HKDF's limit");
    let key = derived.split_off(id_len);
    Ok((derived, key))
}

/// The virtual device query, ready to send: the derived id and key wait here for the result.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    pub id: Vec<u8>,
    pub blob_key: Vec<u8>,
    /// The variables of [`FETCH_QUERY`].
    pub variables: serde_json::Value,
}

/// Prepares the virtual device query for `backup`, as mautrix's `GetVirtualDevice` does
/// before its request: the owner is the backup's delegator if it has one, else the user.
pub fn fetch_request(
    backup: &Backup,
    user_id: i64,
    code: &[u8],
) -> Result<FetchRequest, DeviceError> {
    if backup.id.is_empty() {
        return Err(DeviceError::NoPinBackup);
    } else if user_id <= 0 && backup.delegator_id.is_empty() {
        return Err(DeviceError::Account);
    }
    let owner_id = if backup.delegator_id.is_empty() {
        user_id.to_string()
    } else {
        backup.delegator_id.clone()
    };
    let (id, blob_key) = derive_virtual_device(code, &owner_id)?;
    let variables = json!({
        "request_uuid": owner_id,
        "virtual_device_id": STANDARD.encode(&id),
    });
    Ok(FetchRequest {
        id,
        blob_key,
        variables,
    })
}

#[derive(Deserialize)]
struct FetchResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<FetchResponseError>,
    #[serde(default)]
    data: Option<VirtualDeviceInfo>,
}

#[derive(Deserialize)]
struct FetchResponseError {
    #[serde(default)]
    code: String,
}

impl FetchRequest {
    /// Reads the query's result, the value under [`FETCH_FIELD`] (`null` when absent).
    pub fn finish(self, result: &serde_json::Value) -> Result<VirtualDevice, DeviceError> {
        if result.is_null() {
            return Err(DeviceError::Failed);
        }
        let response =
            FetchResponse::deserialize(result).map_err(|e| DeviceError::Response(e.to_string()))?;
        match response {
            FetchResponse {
                ok: true,
                data: Some(info),
                ..
            } => Ok(VirtualDevice {
                id: self.id,
                blob_key: self.blob_key,
                info,
            }),
            FetchResponse {
                error: Some(error), ..
            } => Err(DeviceError::Rejected(error.code)),
            _ => Err(DeviceError::Failed),
        }
    }
}

impl VirtualDevice {
    /// Opens one of the device's secrets: sealed under the blob key with either AAD the
    /// server uses, holding the value as base64 text.
    pub fn decrypt_secret(&self, ciphertext: &[u8], name: &str) -> Result<Vec<u8>, DeviceError> {
        for aad in [
            format!("virtual_device:{name}"),
            "secret_values_metadata".to_owned(),
        ] {
            if let Ok(value) = aead::decrypt_data(&self.blob_key, ciphertext, aad.as_bytes())
                && let Some(decoded) = go_base64(&value)
            {
                return Ok(decoded);
            }
        }
        Err(DeviceError::Secret(name.to_owned()))
    }
}

/// Decodes standard base64 as Go's `base64.StdEncoding` does: line breaks are skipped and
/// the unused bits of the last character are not checked.
pub(crate) fn go_base64(text: &[u8]) -> Option<Vec<u8>> {
    const LENIENT: GeneralPurpose = GeneralPurpose::new(
        &ALPHABET,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    let text: Vec<u8> = text
        .iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect();
    LENIENT.decode(text).ok()
}
