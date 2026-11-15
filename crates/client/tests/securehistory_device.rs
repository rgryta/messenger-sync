//! The virtual device, epoch and enrolment crypto against `fixtures/securehistory_device.json`,
//! which mautrix-meta's own Go code produced from synthetic keys
//! (`scripts/securehistory-device-fixture`): outputs must match Go's byte for byte, and what
//! Go rejects must be rejected for the same reason.

use std::collections::BTreeMap;
use std::fmt::Display;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use curve25519_dalek::scalar::Scalar;
use messenger_client::securehistory::device::{
    DeviceError, FETCH_FIELD, derive_virtual_device, fetch_request, valid_epoch_anon_id,
};
use messenger_client::securehistory::enrollment::{DeviceInfo, EnrollError, Enrollment};
use messenger_client::securehistory::epochs::derive_epoch_key;
use messenger_client::securehistory::{
    Backup, Device, Epoch, EpochDerivationSet, VirtualDevice, VirtualDeviceInfo,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use whatsapp_client::signal::curve::{KeyPair, PrivateKey, PublicKey};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/securehistory_device.json")).unwrap()
}

/// A Go `[]byte` as JSON writes it: base64, or `null` for none.
fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_str()
        .map(|text| STANDARD.decode(text).unwrap())
        .unwrap_or_default()
}

fn parse<T: DeserializeOwned>(value: &Value) -> T {
    serde_json::from_value(value.clone()).unwrap()
}

/// The same failure: Go's own message, before any wrapped library error, is Rust's.
fn same_reason(name: &str, go: &str, rust: impl Display) {
    let rust = rust.to_string();
    assert!(!go.is_empty(), "{name}: Go accepted it");
    assert_eq!(
        go.split(": ").next(),
        rust.split(": ").next(),
        "{name}: Go said {go:?}, Rust {rust:?}"
    );
}

/// The device the epoch and enrolment cases share.
fn virtual_device(fixture: &Value) -> VirtualDevice {
    let vd = &fixture["virtual_device"];
    VirtualDevice {
        id: bytes(&vd["id"]),
        blob_key: bytes(&vd["blob_key"]),
        info: parse(&vd["info"]),
    }
}

#[test]
fn virtual_device_ids_and_keys_match_go() {
    let fixture = fixture();
    for case in fixture["derive_virtual_device"].as_array().unwrap() {
        let code = case["code"].as_str().unwrap();
        let user = case["user_id"].as_str().unwrap();
        let error = case["error"].as_str().unwrap();
        match derive_virtual_device(code.as_bytes(), user) {
            Ok((id, key)) => {
                assert!(error.is_empty(), "{code}: Go rejected it: {error}");
                assert_eq!(id, bytes(&case["id"]), "{code}");
                assert_eq!(key, bytes(&case["blob_key"]), "{code}");
            }
            Err(e) => same_reason(code, error, e),
        }
    }
    // Both code versions are covered, with their different id lengths.
    let ids: Vec<usize> = fixture["derive_virtual_device"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["error"] == "")
        .map(|c| bytes(&c["id"]).len())
        .collect();
    assert_eq!(ids, [8, 16, 16]);
}

#[test]
fn secrets_open_under_either_aad_as_go() {
    let fixture = fixture();
    let secrets = &fixture["decrypt_secret"];
    let device = VirtualDevice {
        blob_key: bytes(&secrets["blob_key"]),
        ..VirtualDevice::default()
    };
    for case in secrets["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let error = case["error"].as_str().unwrap();
        match device.decrypt_secret(&bytes(&case["ciphertext"]), name) {
            Ok(value) => {
                assert!(error.is_empty(), "Go rejected it: {error}");
                assert_eq!(value, bytes(&case["value"]));
            }
            Err(e) => assert_eq!(e.to_string(), error),
        }
    }
}

#[test]
fn epochs_derive_as_go_over_forward_and_backward_edges() {
    let fixture = fixture();
    let expected: BTreeMap<String, Epoch> = parse(&fixture["virtual_device"]["epochs"]);
    assert_eq!(expected.len(), 5, "two backward, the base, two forward");
    assert_eq!(virtual_device(&fixture).derive_epochs().unwrap(), expected);
}

#[test]
fn epoch_derivation_fails_where_go_fails() {
    let fixture = fixture();
    let good = virtual_device(&fixture);
    for case in fixture["derive_epochs_failures"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let device = VirtualDevice {
            info: parse::<VirtualDeviceInfo>(&case["input"]),
            ..good.clone()
        };
        match device.derive_epochs() {
            Ok(_) => panic!("{name}: Rust accepted what Go rejected"),
            Err(e) => same_reason(name, case["error"].as_str().unwrap(), e),
        }
    }
}

#[test]
fn derivation_sets_apply_as_go() {
    let fixture = fixture();
    let apply = &fixture["apply_epochs"];
    let device: Device = parse(&apply["device"]);
    let set: EpochDerivationSet = parse(&apply["set"]);
    assert!(set.edges[0].forward.is_some() && set.edges[2].forward.is_none());
    let result: Device = parse(&apply["result"]);
    assert_eq!(device.with_epochs(Some(&set)).unwrap(), result);
    assert_eq!(device.with_epochs(None).unwrap(), device);
}

#[test]
fn derivation_sets_fail_where_go_fails() {
    let fixture = fixture();
    let device: Device = parse(&fixture["apply_epochs"]["device"]);
    for case in fixture["apply_epochs_failures"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let set: EpochDerivationSet = parse(&case["input"]);
        match device.with_epochs(Some(&set)) {
            Ok(_) => panic!("{name}: Rust accepted what Go rejected"),
            Err(e) => same_reason(name, case["error"].as_str().unwrap(), e),
        }
    }
    // A failing edge keeps nothing the edges before it added.
    let mut set: EpochDerivationSet = parse(&fixture["apply_epochs"]["set"]);
    set.edges[2].backward.clear();
    assert!(device.with_epochs(Some(&set)).is_err());
}

#[test]
fn epoch_keys_need_a_valid_epoch() {
    let epoch = Epoch {
        id: "1".into(),
        anon_id: b"12".to_vec(),
        root_key: vec![7; 32],
    };
    assert_eq!(derive_epoch_key(&epoch, "x", 32).unwrap().len(), 32);
    for anon in [&b""[..], b"123456789012", b"1a", b"-1"] {
        assert!(!valid_epoch_anon_id(anon));
        let bad = Epoch {
            anon_id: anon.to_vec(),
            ..epoch.clone()
        };
        assert!(derive_epoch_key(&bad, "x", 32).is_err());
    }
    assert!(valid_epoch_anon_id(b"12345678901"));
}

fn armadillo(prepare: &Value) -> KeyPair {
    let private = PrivateKey::deserialize(&bytes(&prepare["armadillo_private"])).unwrap();
    let public = private.public_key();
    assert_eq!(public.bytes()[..], bytes(&prepare["armadillo_public"])[..]);
    KeyPair { public, private }
}

/// Every signature in `info` verifies, over what mautrix signs.
fn assert_signatures_verify(info: &DeviceInfo) {
    let device = PublicKey::from_djb(&info.device_public_key[2..]).unwrap();
    assert_eq!(info.device_public_key[..2], [255, 1]);
    for (domain, key, signature) in [
        (
            b'0',
            &info.epoch_storage_public_key,
            &info.epoch_storage_signature,
        ),
        (
            b'1',
            &info.epoch_auth_public_key,
            &info.epoch_auth_signature,
        ),
        (
            b'3',
            &info.armadillo_public_key,
            &info.armadillo_key_signature,
        ),
    ] {
        assert_eq!(signature[..2], [255, 3]);
        let mut message = vec![domain];
        message.extend_from_slice(key);
        assert!(
            device.verify_signature(&message, &signature[2..]),
            "{}",
            domain as char
        );
    }
    let armadillo = PublicKey::from_djb(&info.armadillo_public_key).unwrap();
    assert!(armadillo.verify_signature(&info.device_public_key, &info.labyrinth_key_signature));
}

#[test]
fn enrolment_replaying_go_randomness_matches_go_byte_for_byte() {
    let fixture = fixture();
    let prepare = &fixture["prepare_device"];
    let epochs = virtual_device(&fixture).derive_epochs().unwrap();
    let stream = bytes(&prepare["random"]);
    let mut used = 0;
    let enrollment = virtual_device(&fixture)
        .prepare_device_with(
            prepare["backup_id"].as_str().unwrap(),
            prepare["registration_id"].as_str().unwrap(),
            &armadillo(prepare),
            epochs,
            &mut |buffer| {
                buffer.copy_from_slice(&stream[used..used + buffer.len()]);
                used += buffer.len();
            },
        )
        .unwrap();
    assert_eq!(used, stream.len(), "Rust drew less randomness than Go");
    assert_eq!(
        serde_json::to_value(&enrollment.info).unwrap(),
        prepare["info"]
    );
    assert_eq!(enrollment.device, parse::<Device>(&prepare["device"]));
    // Go's signatures are XEdDSA that libsignal's verification accepts.
    assert_signatures_verify(&parse(&prepare["info"]));
}

#[test]
fn enrolment_with_fresh_randomness_signs_and_rotates() {
    let fixture = fixture();
    let device = virtual_device(&fixture);
    let epochs = device.derive_epochs().unwrap();
    let armadillo = armadillo(&fixture["prepare_device"]);
    let first = device
        .prepare_device(
            "200000000000001",
            "300000000000001",
            &armadillo,
            epochs.clone(),
        )
        .unwrap();
    let second = device
        .prepare_device("200000000000001", "300000000000001", &armadillo, epochs)
        .unwrap();
    assert_ne!(first.info.device_public_key, second.info.device_public_key);
    assert_signatures_verify(&first.info);
    // The new OCMF state times the rotation token is the state the backup held.
    let old = device
        .decrypt_secret(
            &device.info.secrets.as_ref().unwrap().ocmf_client_state,
            "ocmf_client_state",
        )
        .unwrap();
    let scalar = |b: &[u8]| Scalar::from_canonical_bytes(b.try_into().unwrap()).unwrap();
    assert_eq!(
        scalar(&first.device.ocmf_client_state) * scalar(&first.info.ocmf_rotation_token),
        scalar(&old)
    );
    let trace = &first.info.trace_id;
    assert_eq!((trace.len(), &trace[14..15]), (36, "4"));
    assert!("89ab".contains(&trace[19..20]));
}

#[test]
fn enrolment_fails_where_go_fails() {
    let fixture = fixture();
    let good = virtual_device(&fixture);
    let armadillo = armadillo(&fixture["prepare_device"]);
    for case in fixture["prepare_device_failures"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let input = &case["input"];
        let device = VirtualDevice {
            info: parse(&input["info"]),
            ..good.clone()
        };
        let result = device.prepare_device(
            input["backup_id"].as_str().unwrap(),
            input["registration_id"].as_str().unwrap(),
            &armadillo,
            parse(&input["epochs"]),
        );
        match result {
            Ok(_) => panic!("{name}: Rust accepted what Go rejected"),
            Err(e) => same_reason(name, case["error"].as_str().unwrap(), e),
        }
    }
}

#[test]
fn virtual_device_query_is_built_and_read_as_go() {
    let fixture = fixture();
    let vd = &fixture["virtual_device"];
    let code = vd["code"].as_str().unwrap().as_bytes();
    let user: i64 = vd["user_id"].as_str().unwrap().parse().unwrap();
    let backup = Backup {
        id: "200000000000001".into(),
        ..Backup::default()
    };
    let request = fetch_request(&backup, user, code).unwrap();
    assert_eq!(request.id, bytes(&vd["id"]));
    assert_eq!(
        request.variables,
        json!({"request_uuid": vd["user_id"], "virtual_device_id": vd["id"]})
    );
    // A delegator owns the device instead of the user, even with no user id.
    let delegated = Backup {
        delegator_id: "400000000000001".into(),
        ..backup.clone()
    };
    let other = fetch_request(&delegated, 0, code).unwrap();
    assert_eq!(other.variables["request_uuid"], "400000000000001");
    let expected = &fixture["derive_virtual_device"][2];
    assert_eq!(other.id, bytes(&expected["id"]));

    assert_eq!(
        fetch_request(&Backup::default(), user, code).unwrap_err(),
        DeviceError::NoPinBackup
    );
    assert_eq!(
        fetch_request(&backup, 0, code).unwrap_err(),
        DeviceError::Account
    );
    assert_eq!(
        fetch_request(&backup, user, &code[1..]).unwrap_err(),
        DeviceError::Code
    );

    let result = json!({"ok": true, "data": vd["info"]});
    let device = request.clone().finish(&result).unwrap();
    assert_eq!(device.blob_key, bytes(&vd["blob_key"]));
    assert_eq!(device.info.last_epoch_id, "910000000000105");
    assert_eq!(
        request
            .clone()
            .finish(&json!({"ok": false, "error": {"code": "E1"}}))
            .unwrap_err(),
        DeviceError::Rejected("E1".into())
    );
    assert_eq!(
        request.clone().finish(&json!({"ok": true})).unwrap_err(),
        DeviceError::Failed
    );
    assert_eq!(
        request.finish(&Value::Null).unwrap_err(),
        DeviceError::Failed
    );
    assert_eq!(
        FETCH_FIELD,
        "fetch_virtual_device_info_for_device_addition_v2"
    );
}

#[test]
fn add_device_mutation_is_built_and_read_as_go() {
    let fixture = fixture();
    let prepare = &fixture["prepare_device"];
    let enrollment = Enrollment {
        device: parse(&prepare["device"]),
        info: parse(&prepare["info"]),
    };
    assert_eq!(
        enrollment.variables().unwrap(),
        json!({"input": {
            "device_info": prepare["info"],
            "family_device_id": "",
            "ls_device_id": "",
            "request_uuid": prepare["info"]["trace_id"],
        }})
    );
    let device = enrollment
        .clone()
        .finish(&json!({"device_id": "600000000000001", "is_retryable": false}))
        .unwrap();
    assert_eq!(device.id, "600000000000001");
    assert_eq!(device.epochs, enrollment.device.epochs);
    assert_eq!(
        enrollment
            .clone()
            .finish(&json!({"code": "1675030", "message": "x", "is_retryable": true}))
            .unwrap_err(),
        EnrollError::Rejected("1675030".into())
    );
    assert_eq!(
        enrollment.clone().finish(&json!({})).unwrap_err(),
        EnrollError::NoDeviceId
    );
    assert_eq!(
        enrollment.clone().finish(&Value::Null).unwrap_err(),
        EnrollError::NoResult
    );
    let enrolled = Enrollment {
        device,
        ..enrollment
    };
    assert_eq!(enrolled.variables().unwrap_err(), EnrollError::Invalid);
}
