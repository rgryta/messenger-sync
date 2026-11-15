//! Secure history's PIN login and Vesta payload against vectors from mautrix-meta's own Go
//! code (`scripts/securehistory-opaque-fixture`): its `opaque.Login` with fixed randomness
//! against a bytemare server, its `verifyHSMKey` and its `unpackLoginPayload`.

use curve25519_dalek::scalar::Scalar;
use messenger_client::securehistory::opaque::{self, OpaqueError};
use messenger_client::securehistory::vesta::{self, PayloadError, RecoveryError};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    blind: String,
    client_esk: String,
    client_nonce: String,
    logins: Vec<Login>,
    failures: Vec<Failure>,
    hsm: Hsm,
    l2: L2,
    payloads: Vec<Payload>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Login {
    name: String,
    pin: String,
    ke1: String,
    ke2: String,
    ke3: String,
    session_key: String,
    export_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Failure {
    name: String,
    pin: String,
    ke2: String,
    error: String,
    invalid_pin: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Hsm {
    root: String,
    key: String,
    signature: String,
    real_roots_agree: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2 {
    key: String,
    l2: String,
    signature: String,
    bad_signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    name: String,
    payload: String,
    session_key: String,
    export_key: String,
    code: Option<String>,
    error: Option<String>,
}

fn fixture() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/securehistory_opaque.json"
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn bytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn scalar(s: &str) -> Scalar {
    Scalar::from_canonical_bytes(bytes(s).try_into().unwrap()).unwrap()
}

/// Starts a login with the fixture's randomness.
fn begin(f: &Fixture, pin: &str) -> (opaque::Login, Vec<u8>) {
    let nonce = bytes(&f.client_nonce).try_into().unwrap();
    opaque::begin_with(
        pin.as_bytes(),
        scalar(&f.blind),
        scalar(&f.client_esk),
        nonce,
    )
    .unwrap()
}

#[test]
fn logins_match_go() {
    let f = fixture();
    assert!(!f.logins.is_empty());
    for case in &f.logins {
        let (login, ke1) = begin(&f, &case.pin);
        assert_eq!(hex::encode(&ke1), case.ke1, "{}: KE1", case.name);
        let result = login.finish(&bytes(&case.ke2)).unwrap();
        assert_eq!(hex::encode(&result.message), case.ke3, "{}: KE3", case.name);
        assert_eq!(
            hex::encode(&*result.session_key),
            case.session_key,
            "{}",
            case.name
        );
        assert_eq!(
            hex::encode(&*result.export_key),
            case.export_key,
            "{}",
            case.name
        );
    }
}

#[test]
fn failures_match_go() {
    let f = fixture();
    assert!(f.failures.len() >= 10);
    for case in &f.failures {
        let (login, _) = begin(&f, &case.pin);
        let Err(err) = login.finish(&bytes(&case.ke2)) else {
            panic!("{}: KE2 accepted", case.name);
        };
        assert_eq!(
            err == OpaqueError::InvalidPin,
            case.invalid_pin,
            "{}",
            case.name
        );
        // Go may append the cause after a colon; the message itself must match.
        assert!(
            case.error.starts_with(&err.to_string()),
            "{}: Go said {:?}, Rust {:?}",
            case.name,
            case.error,
            err.to_string()
        );
    }
}

#[test]
fn empty_pin_is_refused() {
    assert_eq!(opaque::begin(b"").err(), Some(OpaqueError::EmptyPin));
}

#[test]
fn fresh_logins_differ() {
    let (_, a) = opaque::begin(b"123456").unwrap();
    let (_, b) = opaque::begin(b"123456").unwrap();
    assert_eq!(a.len(), 98);
    assert_ne!(a, b);
}

#[test]
fn hsm_key_signatures() {
    let f = fixture();
    let (key, sig) = (bytes(&f.hsm.key), bytes(&f.hsm.signature));
    assert!(vesta::verify_hsm_key_with(&[&f.hsm.root], &key, &sig));
    // Only the synthetic root signed it: the real ones refuse it, as Go's check did.
    assert_eq!(vesta::verify_hsm_key(&key, &sig), f.hsm.real_roots_agree);
    assert!(!f.hsm.real_roots_agree);
    let mut tampered = sig.clone();
    tampered[10] ^= 1;
    assert!(!vesta::verify_hsm_key_with(&[&f.hsm.root], &key, &tampered));
    assert!(!vesta::verify_hsm_key_with(
        &[&f.hsm.root],
        b"other key",
        &sig
    ));
    assert!(!vesta::verify_hsm_key_with(
        &["not base64!", &f.hsm.root[..40]],
        &key,
        &sig
    ));
}

#[test]
fn l2_signatures() {
    let f = fixture();
    let (key, l2) = (bytes(&f.l2.key), bytes(&f.l2.l2));
    assert!(vesta::verify_l2(&key, &l2, &bytes(&f.l2.signature)));
    assert!(!vesta::verify_l2(&key, &l2, &bytes(&f.l2.bad_signature)));
    assert!(!vesta::verify_l2(&key[..31], &l2, &bytes(&f.l2.signature)));
    assert!(!vesta::verify_l2(&key, &l2[1..], &bytes(&f.l2.signature)));
}

#[test]
fn payloads_match_go() {
    let f = fixture();
    for case in &f.payloads {
        let got = vesta::unpack_login_payload(
            &bytes(&case.payload),
            &bytes(&case.session_key),
            &bytes(&case.export_key),
        );
        match (&case.code, &case.error, got) {
            (Some(code), None, Ok(got)) => assert_eq!(&hex::encode(got), code, "{}", case.name),
            (None, Some(error), Err(err)) => {
                let expected = match err {
                    PayloadError::Payload(_) => "invalid recovery payload:",
                    PayloadError::KeyData(_) => "invalid recovery key data:",
                    PayloadError::KeyOrNonce => "invalid recovery payload key or nonce",
                    PayloadError::Open => "cipher: message authentication failed",
                };
                assert!(
                    error.starts_with(expected),
                    "{}: Go said {error:?}",
                    case.name
                );
            }
            (_, _, got) => panic!("{}: Go and Rust disagree: {got:?}", case.name),
        }
    }
}

#[test]
fn vesta_responses_decode() {
    let init: vesta::VestaInit = serde_json::from_str(
        r#"{"base64url_encoded_island_rsa_pub":"-_8","base64url_encoded_island_rsa_pub_signature":null,
            "base64url_encoded_island_ed25519_pub":"AQID","is_registered":true,"attempts_remaining":3}"#,
    )
    .unwrap();
    assert_eq!(init.rsa_key, [0xfb, 0xff]);
    assert!(init.rsa_signature.is_empty() && init.ed25519_signature.is_empty());
    assert_eq!(init.ed25519_key, [1, 2, 3]);
    assert!(init.registered);
    assert_eq!(init.attempts_remaining, Some(3));

    // Go's RawURLEncoding refuses padding.
    assert!(
        serde_json::from_str::<vesta::VestaBegin>(r#"{"base64url_encoded_opaque_l2":"AQI="}"#)
            .is_err()
    );
    let begin: vesta::VestaBegin = serde_json::from_str(
        r#"{"base64url_encoded_opaque_l2":"AQI","base64url_encoded_opaque_l2_sig":"BA"}"#,
    )
    .unwrap();
    assert_eq!((begin.l2, begin.signature), (vec![1, 2], vec![4]));

    let finish: vesta::VestaFinish = serde_json::from_str(
        r#"{"__typename":"XFBVestaError","base64url_encoded_login_payload":null,
            "login_success":false,"vesta_error_code":"WRONG_PIN","attempts_remaining":4,
            "trigger_post_login_register":null}"#,
    )
    .unwrap();
    assert_eq!(finish.kind, "XFBVestaError");
    assert!(!finish.success && !finish.trigger_post_login_register && finish.payload.is_empty());
    let err = RecoveryError {
        code: finish.error_code,
        attempts_remaining: finish.attempts_remaining,
    };
    assert_eq!(
        err.to_string(),
        "Messenger recovery failed: WRONG_PIN (4 attempts remaining)"
    );
    let err = RecoveryError {
        code: "no attempts remaining".into(),
        attempts_remaining: None,
    };
    assert_eq!(
        err.to_string(),
        "Messenger recovery failed: no attempts remaining"
    );
}
