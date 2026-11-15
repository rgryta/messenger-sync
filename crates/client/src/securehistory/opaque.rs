//! The client side of the OPAQUE PIN login that Meta's HSM ("Vesta") runs, ported from
//! mautrix's `securehistory/opaque` and the bytemare libraries it is built on
//! (`bytemare/opaque` 16a10d1, `bytemare/voprf` f0af88d, `bytemare/cryptotools` f9985b0).
//!
//! That is a 2021 draft of OPAQUE, not RFC 9807, so `opaque-ke` does not speak it: ristretto255
//! with SHA-512 throughout, a VOPRF06 OPRF, the OPRF output hardened with PBKDF2-SHA512
//! (100 000 rounds, salt `OPAQUE_PBKDF2_SALT`, 64 bytes), a Base-mode envelope that holds only
//! the client's private key, and a 3DH key exchange with 32-byte nonces. Every step below
//! follows those libraries byte for byte; `tests/securehistory_opaque.rs` checks it against
//! vectors from the Go code.
//!
//! Messages: KE1 is `blinded (32) || nonce (32) || 00 00 || ephemeral key (32)`; KE2 is
//! `evaluation (32) || server key (32) || envelope (129) || nonce (32) || ephemeral key (32)
//! || info length (2) || info || MAC (64)`, the envelope being
//! `mode (1) || nonce (32) || sealed client key (32) || tag (64)`; KE3 is the client's MAC.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

const HASH: usize = 64;
/// A KE2 with no server info.
const KE2_MIN: usize = 323;
/// Where the envelope, the server's nonce, ephemeral key and info length start in KE2.
const ENVELOPE: usize = 64;
const SERVER_NONCE: usize = 193;
const SERVER_EPK: usize = 225;
const INFO_LEN: usize = 257;
/// Envelope mode `Base`: the envelope seals only the client's private key.
const MODE_BASE: u8 = 1;
/// The VOPRF06 context: mode Base (0), suite RistrettoSha512 (1).
const HASH_TO_GROUP_DST: &[u8] = b"VOPRF06-HashToGroup-\x00\x00\x01";
const FINALIZE_DST: &[u8] = b"VOPRF06-Finalize-\x00\x00\x01";
const PBKDF2_SALT: &[u8] = b"OPAQUE_PBKDF2_SALT";
const PBKDF2_ROUNDS: u32 = 100_000;

/// Why a login failed. The messages are mautrix's, so logs read the same.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpaqueError {
    #[error("empty recovery PIN")]
    EmptyPin,
    /// KE2 has the wrong length or layout.
    #[error("invalid OPAQUE response")]
    Malformed,
    /// A point in KE2 does not decode, or is the identity.
    #[error("invalid OPAQUE response point")]
    BadPoint,
    /// The server echoed the blinded PIN back instead of evaluating it.
    #[error("reflected OPAQUE evaluation")]
    Reflected,
    /// The envelope or the server's MAC does not verify: almost always a wrong PIN.
    #[error("incorrect recovery PIN")]
    InvalidPin,
    /// The envelope opened, but what it holds is not a canonical scalar.
    #[error("invalid OPAQUE client key")]
    ClientKey,
}

/// A login between KE1 and KE3: the PIN and the secrets drawn for it.
pub struct Login {
    pin: Zeroizing<Vec<u8>>,
    blind: Scalar,
    esk: Scalar,
    ke1: Vec<u8>,
}

impl Drop for Login {
    fn drop(&mut self) {
        self.blind.zeroize();
        self.esk.zeroize();
    }
}

/// A finished login: KE3 for the server, and the two keys the recovery payload is sealed with.
pub struct LoginResult {
    pub message: Vec<u8>,
    pub session_key: Zeroizing<Vec<u8>>,
    pub export_key: Zeroizing<Vec<u8>>,
}

/// Starts a login with fresh randomness: the login to finish, and KE1 to send.
pub fn begin(pin: &[u8]) -> Result<(Login, Vec<u8>), OpaqueError> {
    // As cryptotools draws scalars: 64 random bytes reduced mod the group order.
    let scalar = || Scalar::from_bytes_mod_order_wide(&rand::random::<[u8; 64]>());
    begin_with(pin, scalar(), scalar(), rand::random())
}

/// [`begin`] with the OPRF blind, the ephemeral key and the nonce given, so tests can
/// reproduce a login exactly.
pub fn begin_with(
    pin: &[u8],
    blind: Scalar,
    esk: Scalar,
    nonce: [u8; 32],
) -> Result<(Login, Vec<u8>), OpaqueError> {
    if pin.is_empty() {
        return Err(OpaqueError::EmptyPin);
    }
    let blinded = hash_to_group(pin) * blind;
    let epk = RISTRETTO_BASEPOINT_POINT * esk;
    let mut ke1 = Vec::with_capacity(98);
    ke1.extend_from_slice(blinded.compress().as_bytes());
    ke1.extend_from_slice(&nonce);
    ke1.extend_from_slice(&[0, 0]); // no client info
    ke1.extend_from_slice(epk.compress().as_bytes());
    let login = Login {
        pin: Zeroizing::new(pin.to_vec()),
        blind,
        esk,
        ke1: ke1.clone(),
    };
    Ok((login, ke1))
}

impl Login {
    /// Checks the server's KE2 and answers it: KE3, the session key and the export key.
    pub fn finish(self, ke2: &[u8]) -> Result<LoginResult, OpaqueError> {
        let n = ke2.len();
        if n < KE2_MIN
            || n - KE2_MIN > 255 * HASH
            || ke2[ENVELOPE] != MODE_BASE
            || usize::from(u16::from_be_bytes([ke2[INFO_LEN], ke2[INFO_LEN + 1]])) != n - KE2_MIN
        {
            return Err(OpaqueError::Malformed);
        }
        let evaluation = &ke2[..32];
        let server_pk = &ke2[32..ENVELOPE];
        let envelope = &ke2[ENVELOPE..SERVER_NONCE];
        let server_epk = &ke2[SERVER_EPK..INFO_LEN];
        let server_mac = &ke2[n - HASH..];
        let evaluated = point(evaluation)?;
        let server_pk_point = point(server_pk)?;
        let server_epk_point = point(server_epk)?;
        if evaluation == &self.ke1[..32] {
            return Err(OpaqueError::Reflected);
        }

        // OPRF finalize: unblind, then hash the PIN with the result.
        let unblinded = evaluated * self.blind.invert();
        let mut h = Sha512::new();
        length_prefixed(&mut h, &self.pin);
        length_prefixed(&mut h, unblinded.compress().as_bytes());
        length_prefixed(&mut h, FINALIZE_DST);
        let output: Zeroizing<[u8; HASH]> = Zeroizing::new(h.finalize().into());
        let mut hardened = Zeroizing::new([0u8; HASH]);
        pbkdf2::pbkdf2_hmac::<Sha512>(&*output, PBKDF2_SALT, PBKDF2_ROUNDS, &mut *hardened);

        // Open the envelope; its tag covers the envelope and the server's key.
        let (inner, tag) = envelope.split_at(65);
        let (_, kdf) = Hkdf::<Sha512>::extract(Some(&inner[1..33]), &*hardened);
        let auth_key = expand(&kdf, b"AuthKey", HASH);
        let export_key = expand(&kdf, b"ExportKey", HASH);
        let mut mac = hmac(&auth_key);
        mac.update(inner);
        mac.update(server_pk);
        mac.verify_slice(tag).map_err(|_| OpaqueError::InvalidPin)?;
        let pad = expand(&kdf, b"Pad", 32);
        let mut sk = Zeroizing::new([0u8; 32]);
        for (i, byte) in sk.iter_mut().enumerate() {
            *byte = inner[33 + i] ^ pad[i];
        }
        let sk: Scalar =
            Option::from(Scalar::from_canonical_bytes(*sk)).ok_or(OpaqueError::ClientKey)?;
        let client_pk = (RISTRETTO_BASEPOINT_POINT * sk).compress();

        // 3DH: both ephemeral keys, the server's static key with our ephemeral one, and the
        // server's ephemeral key with our static one.
        let mut ikm = Zeroizing::new(Vec::with_capacity(96));
        for p in [
            server_epk_point * self.esk,
            server_pk_point * self.esk,
            server_epk_point * sk,
        ] {
            ikm.extend_from_slice(p.compress().as_bytes());
        }
        let mut transcript = Sha512::new();
        transcript.update(b"3DH");
        length_prefixed(&mut transcript, client_pk.as_bytes());
        transcript.update(&self.ke1);
        length_prefixed(&mut transcript, server_pk);
        transcript.update(&ke2[..SERVER_EPK]); // credential response, then the server's nonce
        transcript.update(server_epk);
        let context = transcript.clone().finalize();
        let (_, kdf) = Hkdf::<Sha512>::extract(None, &ikm);
        let handshake = expand(&kdf, &label(b"handshake secret", &context), HASH);
        let session_key = expand(&kdf, &label(b"session secret", &context), HASH);
        let handshake = Hkdf::<Sha512>::from_prk(&handshake).expect("a 64-byte PRK suits SHA-512");
        let server_mac_key = expand(&handshake, &label(b"server mac", &[]), HASH);
        let client_mac_key = expand(&handshake, &label(b"client mac", &[]), HASH);
        // The server info is encrypted, but nothing reads it: it only enters the transcript.
        transcript.update(&ke2[INFO_LEN..n - HASH]);
        let mut mac = hmac(&server_mac_key);
        mac.update(&transcript.clone().finalize());
        mac.verify_slice(server_mac)
            .map_err(|_| OpaqueError::InvalidPin)?;
        transcript.update(server_mac);
        let mut mac = hmac(&client_mac_key);
        mac.update(&transcript.finalize());
        Ok(LoginResult {
            message: mac.finalize().into_bytes().to_vec(),
            session_key,
            export_key,
        })
    }
}

/// A KE2 point: canonical, and not the identity.
fn point(bytes: &[u8]) -> Result<RistrettoPoint, OpaqueError> {
    CompressedRistretto::from_slice(bytes)
        .ok()
        .and_then(|c| c.decompress())
        .filter(|p| !p.is_identity())
        .ok_or(OpaqueError::BadPoint)
}

/// The PIN's OPRF input point: `expand_message_xmd` (SHA-512, 64 bytes) into ristretto255's
/// one-way map.
fn hash_to_group(input: &[u8]) -> RistrettoPoint {
    let dst_len = [HASH_TO_GROUP_DST.len() as u8];
    let b0 = Sha512::new()
        .chain_update([0u8; 128])
        .chain_update(input)
        .chain_update([0, HASH as u8, 0])
        .chain_update(HASH_TO_GROUP_DST)
        .chain_update(dst_len)
        .finalize();
    let b1 = Sha512::new()
        .chain_update(b0)
        .chain_update([1])
        .chain_update(HASH_TO_GROUP_DST)
        .chain_update(dst_len)
        .finalize();
    RistrettoPoint::from_uniform_bytes(&b1.into())
}

/// Writes a two-byte big-endian length, then the data.
fn length_prefixed(h: &mut Sha512, data: &[u8]) {
    h.update((data.len() as u16).to_be_bytes());
    h.update(data);
}

/// The draft's `HkdfLabel`: output length, `"OPAQUE " || label` and the context, each with
/// a length prefix.
fn label(label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 7 + label.len() + context.len());
    out.extend_from_slice(&(HASH as u16).to_be_bytes());
    out.push((7 + label.len()) as u8);
    out.extend_from_slice(b"OPAQUE ");
    out.extend_from_slice(label);
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out
}

fn expand(kdf: &Hkdf<Sha512>, info: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; len]);
    kdf.expand(info, &mut out)
        .expect("lengths here are at most 64, well under HKDF's limit");
    out
}

fn hmac(key: &[u8]) -> Hmac<Sha512> {
    <Hmac<Sha512> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length")
}
