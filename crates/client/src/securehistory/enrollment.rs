//! Enrolling a history device (mautrix's `enrollment.go`): fresh device, storage and auth
//! keys, bound to the latest epoch and signed by the device key and the account's Armadillo
//! identity, and the OCMF client state rotated. The mutation itself is the caller's: this
//! builds its variables and reads its result.

use std::collections::BTreeMap;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};
use whatsapp_client::signal::curve::{KeyPair, PrivateKey};

use super::device::{DeviceError, valid_epoch_anon_id};
use super::epochs::{EpochError, derive_epoch_key, fingerprint};
use super::{Device, Epoch, VirtualDevice, b64};

/// The GraphQL mutation that adds the device, and the field its result sits under.
pub const ADD_DEVICE_QUERY: &str = "EBAddDeviceMutation";
pub const ADD_DEVICE_FIELD: &str = "xfb_eb_add_device";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnrollError {
    #[error("missing Messenger backup or connected device identity")]
    Identity,
    #[error("missing latest Messenger backup epoch")]
    LatestEpoch,
    #[error(transparent)]
    Secret(#[from] DeviceError),
    #[error(transparent)]
    Epoch(#[from] EpochError),
    #[error("invalid Messenger backup OCMF state")]
    Ocmf,
    #[error("invalid Messenger backup enrollment")]
    Invalid,
    #[error("backup enrollment returned no result")]
    NoResult,
    /// The server refused the device, with its error code.
    #[error("Messenger backup enrollment rejected: {0}")]
    Rejected(String),
    #[error("backup enrollment returned no device ID")]
    NoDeviceId,
    #[error("invalid backup enrollment result: {0}")]
    Response(String),
}

/// What the server is told about the new device: the mutation's `device_info`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub backup_id: String,
    pub base_epoch_id: String,
    #[serde(with = "b64")]
    pub device_epoch_hmac: Vec<u8>,
    #[serde(with = "b64")]
    pub device_public_key: Vec<u8>,
    pub device_registration_id: String,
    #[serde(with = "b64", rename = "epoch_storage_pubkey")]
    pub epoch_storage_public_key: Vec<u8>,
    #[serde(with = "b64", rename = "epoch_storage_pubkey_sig")]
    pub epoch_storage_signature: Vec<u8>,
    #[serde(with = "b64", rename = "epoch_auth_pubkey")]
    pub epoch_auth_public_key: Vec<u8>,
    #[serde(with = "b64", rename = "epoch_auth_pubkey_sig")]
    pub epoch_auth_signature: Vec<u8>,
    #[serde(with = "b64")]
    pub epoch_root_key_fingerprint: Vec<u8>,
    #[serde(with = "b64")]
    pub ocmf_rotation_token: Vec<u8>,
    #[serde(with = "b64")]
    pub virtual_device_id: Vec<u8>,
    #[serde(with = "b64")]
    pub armadillo_public_key: Vec<u8>,
    #[serde(with = "b64")]
    pub armadillo_key_signature: Vec<u8>,
    #[serde(with = "b64")]
    pub labyrinth_key_signature: Vec<u8>,
    pub occam_only_eligible: bool,
    pub trace_id: String,
}

/// A prepared enrolment: the device to keep (its id comes from the server) and what to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    pub device: Device,
    pub info: DeviceInfo,
}

#[derive(Deserialize)]
struct AddDeviceResponse {
    #[serde(default, deserialize_with = "super::nullable::deserialize")]
    device_id: String,
    #[serde(default, deserialize_with = "super::nullable::deserialize")]
    code: String,
}

impl Enrollment {
    /// The variables of [`ADD_DEVICE_QUERY`].
    pub fn variables(&self) -> Result<serde_json::Value, EnrollError> {
        if !self.device.id.is_empty() {
            return Err(EnrollError::Invalid);
        }
        Ok(json!({
            "input": {
                "device_info": self.info,
                "family_device_id": "",
                "ls_device_id": "",
                "request_uuid": self.info.trace_id,
            }
        }))
    }

    /// Reads the mutation's result, the value under [`ADD_DEVICE_FIELD`] (`null` when
    /// absent): the enrolled device, now with its id.
    pub fn finish(self, result: &serde_json::Value) -> Result<Device, EnrollError> {
        if result.is_null() {
            return Err(EnrollError::NoResult);
        }
        let response = AddDeviceResponse::deserialize(result)
            .map_err(|e| EnrollError::Response(e.to_string()))?;
        if !response.code.is_empty() {
            return Err(EnrollError::Rejected(response.code));
        } else if response.device_id.is_empty() {
            return Err(EnrollError::NoDeviceId);
        }
        Ok(Device {
            id: response.device_id,
            ..self.device
        })
    }
}

impl VirtualDevice {
    /// Prepares a history device for the backup, bound to its latest epoch, with the
    /// account's Armadillo identity key pair vouching for it.
    pub fn prepare_device(
        &self,
        backup_id: &str,
        registration_id: &str,
        armadillo: &KeyPair,
        epochs: BTreeMap<String, Epoch>,
    ) -> Result<Enrollment, EnrollError> {
        self.prepare_device_with(
            backup_id,
            registration_id,
            armadillo,
            epochs,
            &mut |bytes| rand::Rng::fill_bytes(&mut rand::rng(), bytes),
        )
    }

    /// [`Self::prepare_device`] with its randomness from `random`, which fills each buffer it
    /// is handed. Draws are made in mautrix's order (OCMF factor, device, storage and auth
    /// keys, four signature nonces, trace id), so replaying Go's draws gives Go's output.
    pub fn prepare_device_with(
        &self,
        backup_id: &str,
        registration_id: &str,
        armadillo: &KeyPair,
        epochs: BTreeMap<String, Epoch>,
        random: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Enrollment, EnrollError> {
        let Some(secrets) = &self.info.secrets else {
            return Err(EnrollError::Identity);
        };
        if backup_id.is_empty() || registration_id.is_empty() {
            return Err(EnrollError::Identity);
        }
        let epoch = epochs
            .get(&self.info.last_epoch_id)
            .filter(|e| valid_epoch_anon_id(&e.anon_id) && e.root_key.len() == 32)
            .ok_or(EnrollError::LatestEpoch)?
            .clone();
        let mailbox_root_key =
            self.decrypt_secret(&secrets.mailbox_root_key, "mailbox_root_key")?;
        let ocmf = self.decrypt_secret(&secrets.ocmf_client_state, "ocmf_client_state")?;
        let (ocmf_client_state, token) = evolve_ocmf(&ocmf, random)?;
        let device_key = new_key_pair(random);
        let storage_key = new_key_pair(random);
        let auth_key = new_key_pair(random);
        let mut public_key = vec![255, 1];
        public_key.extend_from_slice(device_key.public.bytes());
        let device_epoch_key = derive_epoch_key(&epoch, "epoch_devices", 32)?;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&device_epoch_key)
            .expect("HMAC takes any key length");
        mac.update(&public_key);
        let labyrinth_signature = sign(&armadillo.private, &public_key, random);
        let storage_public_key = storage_key.public.bytes().to_vec();
        let epoch_storage_signature =
            sign_device_key(&device_key, b'0', &storage_public_key, random);
        let epoch_auth_signature =
            sign_device_key(&device_key, b'1', auth_key.public.bytes(), random);
        let armadillo_key_signature =
            sign_device_key(&device_key, b'3', armadillo.public.bytes(), random);
        let info = DeviceInfo {
            backup_id: backup_id.to_owned(),
            base_epoch_id: epoch.id.clone(),
            device_epoch_hmac: mac.finalize().into_bytes().to_vec(),
            device_public_key: public_key,
            device_registration_id: registration_id.to_owned(),
            epoch_storage_public_key: storage_public_key.clone(),
            epoch_storage_signature,
            epoch_auth_public_key: auth_key.public.bytes().to_vec(),
            epoch_auth_signature,
            epoch_root_key_fingerprint: fingerprint(&epoch.root_key, "MEBEpochRootKey"),
            ocmf_rotation_token: token,
            virtual_device_id: self.id.clone(),
            armadillo_public_key: armadillo.public.bytes().to_vec(),
            armadillo_key_signature,
            labyrinth_key_signature: labyrinth_signature.to_vec(),
            occam_only_eligible: true,
            trace_id: uuid_v4(random),
        };
        let device = Device {
            id: String::new(),
            backup_id: backup_id.to_owned(),
            storage_public_key,
            storage_private_key: storage_key.private.serialize().to_vec(),
            mailbox_root_key,
            ocmf_client_state,
            epochs,
        };
        Ok(Enrollment { device, info })
    }
}

/// A Curve25519 key pair as whatsmeow's `keys.NewKeyPair` makes it: the private key stored
/// clamped.
fn new_key_pair(random: &mut dyn FnMut(&mut [u8])) -> KeyPair {
    let mut bytes = [0u8; 32];
    random(&mut bytes);
    let private = PrivateKey::deserialize(&clamp_integer(bytes)).expect("32 bytes");
    KeyPair {
        public: private.public_key(),
        private,
    }
}

/// A device-key signature over a domain byte and `message`, behind the `0xFF 0x03` prefix.
fn sign_device_key(
    key: &KeyPair,
    domain: u8,
    message: &[u8],
    random: &mut dyn FnMut(&mut [u8]),
) -> Vec<u8> {
    let mut signed = vec![domain];
    signed.extend_from_slice(message);
    let mut out = vec![255, 3];
    out.extend_from_slice(&sign(&key.private, &signed, random));
    out
}

/// XEdDSA as libsignal (and whatsmeow) signs with a Curve25519 key: the clamped key as the
/// Ed25519 scalar, the Edwards key's sign bit carried in the signature's top bit. The nonce
/// hashes the key as stored, unclamped, exactly as Go's `ecc.CalculateSignature` does.
fn sign(private: &PrivateKey, message: &[u8], random: &mut dyn FnMut(&mut [u8])) -> [u8; 64] {
    let mut nonce = [0u8; 64];
    random(&mut nonce);
    let key = private.serialize();
    let a = Scalar::from_bytes_mod_order(clamp_integer(key));
    let public = EdwardsPoint::mul_base(&a).compress();
    let mut diversifier = [0xFF; 32];
    diversifier[0] = 0xFE;
    let r = Scalar::from_hash(
        Sha512::new()
            .chain_update(diversifier)
            .chain_update(key)
            .chain_update(message)
            .chain_update(nonce),
    );
    let cap_r = EdwardsPoint::mul_base(&r).compress();
    let h = Scalar::from_hash(
        Sha512::new()
            .chain_update(cap_r.as_bytes())
            .chain_update(public.as_bytes())
            .chain_update(message),
    );
    let s = h * a + r;
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(cap_r.as_bytes());
    signature[32..].copy_from_slice(s.as_bytes());
    signature[63] |= public.as_bytes()[31] & 0x80;
    signature
}

/// Rotates the OCMF client state, a non-zero ristretto255 scalar: multiplies it by a random
/// factor, and returns the new state with the factor's inverse, the token that undoes it.
fn evolve_ocmf(
    state: &[u8],
    random: &mut dyn FnMut(&mut [u8]),
) -> Result<(Vec<u8>, Vec<u8>), EnrollError> {
    let bytes: [u8; 32] = state.try_into().map_err(|_| EnrollError::Ocmf)?;
    let current = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .filter(|s| *s != Scalar::ZERO)
        .ok_or(EnrollError::Ocmf)?;
    let mut factor = Scalar::ZERO;
    while factor == Scalar::ZERO {
        let mut wide = [0u8; 64];
        random(&mut wide);
        factor = Scalar::from_bytes_mod_order_wide(&wide);
    }
    Ok((
        (current * factor).to_bytes().to_vec(),
        factor.invert().to_bytes().to_vec(),
    ))
}

/// A random (version 4) UUID, as google/uuid's `NewString` writes it.
fn uuid_v4(random: &mut dyn FnMut(&mut [u8])) -> String {
    let mut b = [0u8; 16];
    random(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}
