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

use messenger_core::models::{E2eeEvent, E2eeWhat};
use messenger_core::store::e2ee::{self, Stored};

use crate::armadillo::Content;
use crate::daemon::{Client, PassError};
use crate::graphql;
use crate::page::PageConfig;
use crate::securehistory::{Backup, Device, archive, device, enrollment, opaque, vesta};

#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error(transparent)]
    Pass(#[from] PassError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error("the account has no PIN-protected history backup ({0})")]
    NoBackup(String),
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
pub async fn store_device(
    pool: &PgPool,
    account: &str,
    device: &Device,
) -> Result<(), RestoreError> {
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

/// What an answer looks like without what it says: field names and types, string lengths,
/// and the values of a few fields that are kinds, not identities. Logged so a failed restore
/// shows where Meta's answer differs from what mautrix expects, with no id or key in the log.
pub fn shape(value: &Value) -> String {
    const SHOWN: [&str; 3] = ["device_type", "__typename", "is_registered"];
    fn walk(value: &Value, key: Option<&str>, out: &mut String) {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(_) => out.push_str("number"),
            Value::String(s) if key.is_some_and(|k| SHOWN.contains(&k)) => {
                out.push_str(&format!("{s:?}"))
            }
            Value::String(s) => out.push_str(&format!("str({})", s.len())),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    walk(item, key, out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(k);
                    out.push_str(": ");
                    walk(v, Some(k), out);
                }
                out.push('}');
            }
        }
    }
    let mut out = String::new();
    walk(value, None, &mut out);
    out
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
    let user_id: i64 = config.user_id.parse().map_err(|e| step("user id")(&e))?;

    let answer = call(
        client,
        &config,
        &graphql::BACKUP_IDS,
        "xfb_backup",
        &json!({}),
    )
    .await?;
    tracing::info!("backup lookup answered: {}", shape(&answer));
    if answer.is_null() {
        return Err(RestoreError::NoBackup("the lookup answered null".into()));
    }
    let backup: Backup = serde_json::from_value(answer).map_err(|e| step("backup lookup")(&e))?;
    let kinds: Vec<&str> = backup.devices.iter().map(|d| d.kind.as_str()).collect();
    let Some(vesta_id) = backup.vesta_id().filter(|_| !backup.id.is_empty()) else {
        return Err(RestoreError::NoBackup(format!(
            "backup id {}, device kinds {kinds:?}",
            if backup.id.is_empty() {
                "missing"
            } else {
                "present"
            }
        )));
    };
    let mut variables = json!({
        "fbid": vesta_id,
        "product_use_case": "MSGR_ENC_BACKUP",
        "vesta_client_api_version": 6,
    });

    let answer = call(
        client,
        &config,
        &graphql::VESTA_INIT,
        "fbid_based_auth_layer_vesta_login_init",
        &json!({ "request": variables }),
    )
    .await?;
    tracing::info!("recovery init answered: {}", shape(&answer));
    let init: vesta::VestaInit =
        serde_json::from_value(answer).map_err(|e| step("recovery init")(&e))?;
    if !init.registered {
        return Err(RestoreError::NoBackup(
            "the PIN server has no PIN registered for it".into(),
        ));
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

    let fetch =
        device::fetch_request(&backup, user_id, &code).map_err(|e| step("virtual device")(&e))?;
    let answer = call(
        client,
        &config,
        &graphql::VIRTUAL_DEVICE,
        device::FETCH_FIELD,
        &fetch.variables,
    )
    .await?;
    let virtual_device = fetch
        .finish(&answer)
        .map_err(|e| step("virtual device")(&e))?;
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

/// What a restore run read and kept.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Restored {
    pub threads: usize,
    pub pages: usize,
    pub messages: usize,
    pub stored: usize,
    pub failed: usize,
}

/// Archived messages asked for per page.
pub const PAGE_SIZE: i64 = 50;

/// The encrypted one-to-one threads and the person each is with: the archive files a chat
/// under that person's id.
async fn encrypted_threads(pool: &PgPool, account: &str) -> sqlx::Result<Vec<(String, String)>> {
    sqlx::query_as(
        "
        SELECT t.thread_key, min(p.fb_user_id)
          FROM thread t
          JOIN account a ON a.id = t.account_id
          JOIN thread_participant p
            ON p.account_id = t.account_id AND p.thread_key = t.thread_key
           AND p.fb_user_id <> a.fb_user_id
         WHERE t.account_id = $1 AND t.sync_group = 95 AND NOT t.is_group
         GROUP BY t.thread_key, t.last_activity_at
        HAVING count(DISTINCT p.fb_user_id) = 1
         ORDER BY t.last_activity_at DESC NULLS LAST
        ",
    )
    .bind(account)
    .fetch_all(pool)
    .await
}

/// A sender as the archive names it (`<fbid>`, or a JID around it), as the fbid alone.
pub fn fbid(sender: &str) -> String {
    sender
        .split(['@', ':', '.'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn at(ms: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default()
}

/// The archive's events for one restored message: the message, then its reactions.
pub fn events(otid: &str, message: &archive::BackfillMessage) -> Vec<E2eeEvent> {
    let what = match &message.content {
        Content::Text { text, reply_to } => Some(E2eeWhat::Message {
            text: Some(text.clone()),
            reply_to: reply_to.clone(),
            media: None,
            media_ref: None,
        }),
        Content::Media {
            kind,
            caption,
            reply_to,
            ..
        } => Some(E2eeWhat::Message {
            text: caption.clone(),
            reply_to: reply_to.clone(),
            media: Some((*kind).into()),
            // The archive's attachments are CDN references, not the chat's media keys.
            media_ref: None,
        }),
        _ => None,
    };
    let mut events = Vec::new();
    if let Some(what) = what {
        events.push(E2eeEvent {
            otid: otid.to_owned(),
            ts: at(message.timestamp_ms),
            sender_id: fbid(&message.sender),
            what,
        });
    }
    for reaction in &message.reactions {
        events.push(E2eeEvent {
            otid: otid.to_owned(),
            ts: at(reaction.timestamp_ms),
            sender_id: fbid(&reaction.sender),
            what: E2eeWhat::Reaction {
                target: otid.to_owned(),
                emoji: reaction.emoji.clone(),
            },
        });
    }
    events
}

/// Reads every encrypted one-to-one thread's archive, newest page first, and stores what
/// opens: text fills the envelope already held for it (matched by OTID), and a message the
/// archive holds but the inbox never listed is added. Epoch keys a page brings are kept.
pub async fn fetch_all(
    client: &mut Client,
    account: &str,
    mut device: Device,
) -> Result<Restored, RestoreError> {
    let config = client.page().await?;
    let app_id = config
        .user_app_id
        .clone()
        .ok_or_else(|| RestoreError::Step("the page carries no app id".into()))?;
    let self_id: i64 = config.user_id.parse().map_err(|e| step("user id")(&e))?;
    let threads = encrypted_threads(client.pool(), account).await?;
    let mut done = Restored {
        threads: threads.len(),
        ..Restored::default()
    };
    for (thread_key, peer) in threads {
        let mut reference = chrono::Utc::now().timestamp_millis() + 60_000;
        loop {
            let variables = archive::message_range_variables(
                &device, &app_id, &peer, true, reference, PAGE_SIZE,
            )
            .map_err(|e| step("page request")(&e))?;
            let viewer = call(
                client,
                &config,
                &graphql::MESSAGE_RANGE,
                "viewer",
                &variables,
            )
            .await?;
            let bytes = serde_json::to_vec(&viewer).map_err(|e| step("page")(&e))?;
            let range =
                archive::parse_message_range(&bytes, &device).map_err(|e| step("page")(&e))?;
            done.pages += 1;
            if range.thread_missing {
                break;
            }
            if range
                .epochs
                .as_ref()
                .is_some_and(|set| !set.edges.is_empty())
            {
                device = device
                    .with_epochs(range.epochs.as_ref())
                    .map_err(|e| step("epochs")(&e))?;
                store_device(client.pool(), account, &device).await?;
            }
            let mut conn = client.pool().acquire().await?;
            for (otid, result) in range.decrypt_each(&device, &peer, self_id, false) {
                done.messages += 1;
                let converted = result
                    .map_err(|e| e.to_string())
                    .and_then(|m| m.convert().map_err(|e| e.to_string()));
                match converted {
                    Ok(Some(message)) => {
                        for event in events(&otid, &message) {
                            if e2ee::store(&mut conn, account, &thread_key, &event).await?
                                == Stored::Applied
                            {
                                done.stored += 1;
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(reason) => {
                        done.failed += 1;
                        tracing::debug!("archived message skipped: {reason}");
                    }
                }
            }
            drop(conn);
            let (more, next) = range.range.as_ref().map_or((false, 0), |r| {
                (r.has_more_before.unwrap_or(false), r.before)
            });
            if !more || next >= reference {
                break;
            }
            reference = next;
            // A person scrolling back would not ask faster.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        tracing::info!(
            "restore: a thread done; {} page(s), {} stored, {} skipped so far",
            done.pages,
            done.stored,
            done.failed
        );
    }
    Ok(done)
}
