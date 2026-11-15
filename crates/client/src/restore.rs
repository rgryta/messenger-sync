//! Restoring the text of encrypted chats from Messenger's encrypted backup ("secure
//! storage"), once, with the account's PIN: the archive holds the envelopes of every
//! encrypted message stored before this client could decrypt them, and only the backup still
//! has their text. Runs the steps of mautrix-meta's `login_history.go`: find the backup,
//! recover it with the PIN against Meta's HSM, unlock its virtual device, and enrol a history
//! device whose keys then read the archived messages.
//!
//! The backup lookup is the risky call: mautrix saw Meta end sessions after it, at login and
//! per sent message. It is made once per run, by hand, never by the inbox loop. The PIN is
//! asked once per run, after the server says how many attempts remain, and never stored.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sqlx::PgPool;
use whatsapp_client::signal::curve::KeyPair;
use zeroize::Zeroizing;

use crate::daemon::{Client, PassError};
use crate::graphql;
use crate::page::PageConfig;
use crate::securehistory::{Backup, Device, device, enrollment, opaque, vesta};

#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error(transparent)]
    Pass(#[from] PassError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error("the account has no PIN-protected history backup")]
    NoBackup,
    #[error("{0}")]
    Recovery(vesta::RecoveryError),
    #[error("the recovery server's keys or signatures do not verify")]
    Untrusted,
    #[error("no PIN given")]
    NoPin,
    #[error("a history device was enrolled but Meta never confirmed it; clear it by hand")]
    Unconfirmed,
    #[error("{0}")]
    Step(String),
}

fn step(what: &str) -> impl Fn(&dyn std::fmt::Display) -> RestoreError + '_ {
    move |e| RestoreError::Step(format!("{what}: {e}"))
}

/// The enrolled history device, if one is stored.
pub async fn stored_device(pool: &PgPool, account: &str) -> Result<Option<Device>, RestoreError> {
    let row: Option<(Value,)> =
        sqlx::query_as("SELECT device FROM client.history_device WHERE account_id = $1")
            .bind(account)
            .fetch_optional(pool)
            .await?;
    row.map(|(device,)| serde_json::from_value(device).map_err(|e| step("stored device")(&e)))
        .transpose()
}

/// Keeps the history device, replacing the one stored.
pub async fn store_device(pool: &PgPool, account: &str, device: &Device) -> Result<(), RestoreError> {
    let json = serde_json::to_value(device).map_err(|e| step("device")(&e))?;
    sqlx::query(
        "INSERT INTO client.history_device (account_id, device) VALUES ($1, $2)
         ON CONFLICT (account_id) DO UPDATE SET device = EXCLUDED.device, updated_at = now()",
    )
    .bind(account)
    .bind(json)
    .execute(pool)
    .await?;
    Ok(())
}

async fn forget_device(pool: &PgPool, account: &str) -> Result<(), RestoreError> {
    sqlx::query("DELETE FROM client.history_device WHERE account_id = $1")
        .bind(account)
        .execute(pool)
        .await?;
    Ok(())
}

async fn call(
    client: &mut Client,
    config: &PageConfig,
    doc: &graphql::Doc,
    field: &str,
    variables: &Value,
) -> Result<Value, RestoreError> {
    Ok(client
        .backup_call(config, doc, field, variables)
        .await?
        .unwrap_or(Value::Null))
}

/// Recovers the backup with the PIN and enrols a history device, returning it confirmed.
/// `pin` is called once, with the attempts the server says remain, and returns the PIN or
/// nothing to stop before any attempt is spent.
pub async fn enroll(
    client: &mut Client,
    account: &str,
    identity: &KeyPair,
    pin: impl FnOnce(Option<i64>) -> Option<Zeroizing<String>>,
) -> Result<Device, RestoreError> {
    if let Some(device) = stored_device(client.pool(), account).await? {
        return if device.id.is_empty() {
            Err(RestoreError::Unconfirmed)
        } else {
            Ok(device)
        };
    }
    let config = client.page().await?;
    let registration_id = config
        .session_id
        .clone()
        .ok_or_else(|| RestoreError::Step("the page carries no web session id".into()))?;
    let user_id: i64 = config
        .user_id
        .parse()
        .map_err(|e| step("user id")(&e))?;

    let backup: Backup = serde_json::from_value(
        call(client, &config, &graphql::BACKUP_IDS, "xfb_backup", &json!({})).await?,
    )
    .unwrap_or_default();
    let Some(vesta_id) = backup.vesta_id().filter(|_| !backup.id.is_empty()) else {
        return Err(RestoreError::NoBackup);
    };
    let mut variables = json!({
        "fbid": vesta_id,
        "product_use_case": "MSGR_ENC_BACKUP",
        "vesta_client_api_version": 6,
    });

    let init: vesta::VestaInit = serde_json::from_value(
        call(
            client,
            &config,
            &graphql::VESTA_INIT,
            "fbid_based_auth_layer_vesta_login_init",
            &json!({ "request": variables }),
        )
        .await?,
    )
    .map_err(|e| step("recovery init")(&e))?;
    if !init.registered {
        return Err(RestoreError::NoBackup);
    }
    if init.attempts_remaining == Some(0) {
        return Err(RestoreError::Recovery(vesta::RecoveryError {
            code: "no attempts remaining".into(),
            attempts_remaining: Some(0),
        }));
    }
    if !vesta::verify_hsm_key(&init.rsa_key, &init.rsa_signature)
        || !vesta::verify_hsm_key(&init.ed25519_key, &init.ed25519_signature)
        || init.ed25519_key.len() != 32
    {
        return Err(RestoreError::Untrusted);
    }

    let pin = pin(init.attempts_remaining).ok_or(RestoreError::NoPin)?;
    if pin.len() != 6 || !pin.bytes().all(|b| b.is_ascii_digit()) {
        return Err(RestoreError::Step("the PIN is six digits".into()));
    }
    let (login, l1) = opaque::begin(pin.as_bytes()).map_err(|e| step("PIN login")(&e))?;
    drop(pin);
    variables["vesta_client_protocol_version"] = json!(1);
    variables["base64url_encoded_opaque_l1"] = json!(URL_SAFE_NO_PAD.encode(l1));
    let begin: vesta::VestaBegin = serde_json::from_value(
        call(
            client,
            &config,
            &graphql::VESTA_BEGIN,
            "fbid_based_auth_layer_vesta_begin_login",
            &json!({ "input": variables }),
        )
        .await?,
    )
    .map_err(|e| step("recovery begin")(&e))?;
    if !vesta::verify_l2(&init.ed25519_key, &begin.l2, &begin.signature) {
        return Err(RestoreError::Untrusted);
    }
    let result = login.finish(&begin.l2).map_err(|e| step("PIN login")(&e))?;

    let object = variables.as_object_mut().expect("built as an object");
    object.remove("base64url_encoded_opaque_l1");
    object.insert(
        "base64url_encoded_opaque_l3".into(),
        json!(URL_SAFE_NO_PAD.encode(&result.message)),
    );
    let finish: vesta::VestaFinish = serde_json::from_value(
        call(
            client,
            &config,
            &graphql::VESTA_FINISH,
            "fbid_based_auth_layer_vesta_finish_login_v2",
            &json!({ "input": variables }),
        )
        .await?,
    )
    .map_err(|e| step("recovery finish")(&e))?;
    if finish.kind == "XFBVestaError" || !finish.success {
        return Err(RestoreError::Recovery(vesta::RecoveryError {
            code: finish.error_code,
            attempts_remaining: finish.attempts_remaining,
        }));
    }
    let code = Zeroizing::new(
        vesta::unpack_login_payload(&finish.payload, &result.session_key, &result.export_key)
            .map_err(|e| step("recovery payload")(&e))?,
    );

    let fetch = device::fetch_request(&backup, user_id, &code).map_err(|e| step("virtual device")(&e))?;
    let answer = call(
        client,
        &config,
        &graphql::VIRTUAL_DEVICE,
        device::FETCH_FIELD,
        &fetch.variables,
    )
    .await?;
    let virtual_device = fetch.finish(&answer).map_err(|e| step("virtual device")(&e))?;
    let epochs = virtual_device
        .derive_epochs()
        .map_err(|e| step("epochs")(&e))?;
    let enrolment = virtual_device
        .prepare_device(&backup.id, &registration_id, identity, epochs)
        .map_err(|e| step("enrolment")(&e))?;

    // Kept before Meta is asked, as mautrix does: an enrolment that succeeds while the
    // answer is lost must not leave keys only the server has.
    store_device(client.pool(), account, &enrolment.device).await?;
    let variables = enrolment.variables().map_err(|e| step("enrolment")(&e))?;
    let answer = call(
        client,
        &config,
        &graphql::ADD_DEVICE,
        enrollment::ADD_DEVICE_FIELD,
        &variables,
    )
    .await?;
    match enrolment.finish(&answer) {
        Ok(device) => {
            store_device(client.pool(), account, &device).await?;
            Ok(device)
        }
        Err(e @ enrollment::EnrollError::Rejected(_)) => {
            forget_device(client.pool(), account).await?;
            Err(step("enrolment")(&e))
        }
        Err(e) => Err(step("enrolment")(&e)),
    }
}
