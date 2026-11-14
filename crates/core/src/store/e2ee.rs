//! Encrypted-chat messages the client's own device decrypted, into the archive.
//!
//! The decrypted message and its LightSpeed envelope share the OTID (migration 0014), so the
//! text lands on the envelope's row when that is stored first, and on a row of its own,
//! keyed by the OTID, when not. Every target an edit, unsend, reaction or reply names is an
//! OTID too, and resolves to whichever row holds it. Only blanks are filled: a stored text
//! changes only through an edit, which keeps the old one as a revision.

use serde_json::json;
use sqlx::{Connection, PgConnection};

use crate::models::{Attachment, E2eeEvent, E2eeWhat, Reaction};
use crate::store::writes::{insert_attachments, insert_reactions, record_revision};

/// What became of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    /// Written: a new row, a filled envelope, an edit, an unsend or a reaction.
    Applied,
    /// Already there, so nothing changed.
    Unchanged,
    /// It names a message the archive does not hold.
    NoTarget,
}

/// The one-to-one encrypted thread with `peer`, found through its participants.
pub async fn thread_with(
    conn: &mut PgConnection,
    account_id: &str,
    peer: &str,
) -> sqlx::Result<Option<String>> {
    sqlx::query_scalar(
        "
        SELECT t.thread_key FROM thread t
          JOIN account a ON a.id = t.account_id
         WHERE t.account_id = $1 AND t.sync_group = 95 AND NOT t.is_group
           AND EXISTS (
             SELECT 1 FROM thread_participant p
              WHERE p.account_id = t.account_id AND p.thread_key = t.thread_key
                AND p.fb_user_id = $2)
           -- Nobody else: the account is in every one-to-one thread, so without this a note
           -- to self (peer = the account) would land in whichever chat was active last.
           AND NOT EXISTS (
             SELECT 1 FROM thread_participant p
              WHERE p.account_id = t.account_id AND p.thread_key = t.thread_key
                AND p.fb_user_id NOT IN ($2, a.fb_user_id))
         ORDER BY t.last_activity_at DESC NULLS LAST
         LIMIT 1
        ",
    )
    .bind(account_id)
    .bind(peer)
    .fetch_optional(conn)
    .await
}

/// The message_id of the row holding `otid`: the envelope's `mid.$…`, or the OTID itself.
pub async fn resolve(
    conn: &mut PgConnection,
    account_id: &str,
    thread_key: &str,
    otid: &str,
) -> sqlx::Result<Option<String>> {
    sqlx::query_scalar(
        "
        SELECT message_id FROM message
         WHERE account_id = $1 AND thread_key = $2 AND otid = $3
         ORDER BY ts
         LIMIT 1
        ",
    )
    .bind(account_id)
    .bind(thread_key)
    .bind(otid)
    .fetch_optional(conn)
    .await
}

/// Stores one event in `thread_key`, in one transaction.
pub async fn store(
    conn: &mut PgConnection,
    account_id: &str,
    thread_key: &str,
    event: &E2eeEvent,
) -> sqlx::Result<Stored> {
    let mut tx = conn.begin().await?;
    let stored = match &event.what {
        E2eeWhat::Message {
            text,
            reply_to,
            media,
        } => {
            let reply_to = match reply_to {
                Some(otid) => Some(
                    resolve(&mut tx, account_id, thread_key, otid)
                        .await?
                        .unwrap_or_else(|| otid.clone()),
                ),
                None => None,
            };
            let stored = store_message(
                &mut tx,
                account_id,
                thread_key,
                event,
                text.as_deref(),
                reply_to.as_deref(),
            )
            .await?;
            if let Some(kind) = media {
                let message_id = resolve(&mut tx, account_id, thread_key, &event.otid)
                    .await?
                    .unwrap_or_else(|| event.otid.clone());
                // The media itself needs the encrypted download, not ported yet: the kind
                // is kept so the archive says an attachment was there.
                insert_attachments(
                    &mut tx,
                    &[Attachment {
                        account_id: account_id.into(),
                        thread_key: thread_key.into(),
                        message_id,
                        attachment_id: Some(event.otid.clone()),
                        kind: "e2ee".into(),
                        mime_type: None,
                        url: None,
                        preview_url: None,
                        raw: json!({ "media": kind }),
                    }],
                )
                .await?;
            }
            stored
        }
        E2eeWhat::Edit { target, text } => {
            match resolve(&mut tx, account_id, thread_key, target).await? {
                Some(id) => {
                    if record_revision(&mut tx, account_id, thread_key, &id, Some(text)).await? {
                        Stored::Applied
                    } else {
                        Stored::Unchanged
                    }
                }
                None => Stored::NoTarget,
            }
        }
        E2eeWhat::Unsend { target } => {
            match resolve(&mut tx, account_id, thread_key, target).await? {
                Some(id) => {
                    let marked = sqlx::query(
                        "
                        UPDATE message SET
                          deleted_at = $4,
                          -- LightSpeed re-issues an unsent message's envelope under the
                          -- unsend's OTID; `insert_messages` skips it by this.
                          raw = raw || jsonb_build_object('unsent_by', $5::text)
                         WHERE account_id = $1 AND thread_key = $2 AND message_id = $3
                           AND deleted_at IS NULL
                        ",
                    )
                    .bind(account_id)
                    .bind(thread_key)
                    .bind(&id)
                    .bind(event.ts)
                    .bind(&event.otid)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                    if marked > 0 {
                        Stored::Applied
                    } else {
                        Stored::Unchanged
                    }
                }
                None => Stored::NoTarget,
            }
        }
        E2eeWhat::Reaction { target, emoji } => {
            match resolve(&mut tx, account_id, thread_key, target).await? {
                Some(id) if emoji.is_empty() => {
                    sqlx::query(
                        "
                        DELETE FROM message_reaction
                         WHERE account_id = $1 AND thread_key = $2 AND message_id = $3
                           AND actor_id = $4
                        ",
                    )
                    .bind(account_id)
                    .bind(thread_key)
                    .bind(&id)
                    .bind(&event.sender_id)
                    .execute(&mut *tx)
                    .await?;
                    Stored::Applied
                }
                Some(id) => {
                    insert_reactions(
                        &mut tx,
                        &[Reaction {
                            account_id: account_id.into(),
                            thread_key: thread_key.into(),
                            message_id: id,
                            actor_id: event.sender_id.clone(),
                            emoji: emoji.clone(),
                            reacted_at: event.ts,
                        }],
                    )
                    .await?;
                    Stored::Applied
                }
                None => Stored::NoTarget,
            }
        }
    };
    tx.commit().await?;
    Ok(stored)
}

/// The text on the envelope's row when there is one, else a row of its own.
async fn store_message(
    conn: &mut PgConnection,
    account_id: &str,
    thread_key: &str,
    event: &E2eeEvent,
    text: Option<&str>,
    reply_to: Option<&str>,
) -> sqlx::Result<Stored> {
    let filled = sqlx::query(
        "
        UPDATE message SET
          text        = COALESCE(text, $4),
          reply_to_id = COALESCE(reply_to_id, $5),
          sender_id   = COALESCE(sender_id, $6)
         WHERE account_id = $1 AND thread_key = $2 AND otid = $3
           AND (text IS NULL AND $4::text IS NOT NULL
                OR reply_to_id IS NULL AND $5::text IS NOT NULL
                OR sender_id IS NULL)
        ",
    )
    .bind(account_id)
    .bind(thread_key)
    .bind(&event.otid)
    .bind(text)
    .bind(reply_to)
    .bind(&event.sender_id)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if filled > 0 {
        return Ok(Stored::Applied);
    }
    let inserted = sqlx::query(
        "
        INSERT INTO message (account_id, thread_key, message_id, ts, sender_id, text,
                             reply_to_id, sync_group, raw)
        SELECT $1, $2, $3, $4, $5, $6, $7, 95, $8
         WHERE NOT EXISTS (
           SELECT 1 FROM message
            WHERE account_id = $1 AND thread_key = $2 AND otid = $3)
        ON CONFLICT (account_id, thread_key, message_id) DO NOTHING
        ",
    )
    .bind(account_id)
    .bind(thread_key)
    .bind(&event.otid)
    .bind(event.ts)
    .bind(&event.sender_id)
    .bind(text)
    .bind(reply_to)
    .bind(json!({ "otid": event.otid, "source": "e2ee" }))
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(if inserted > 0 {
        Stored::Applied
    } else {
        Stored::Unchanged
    })
}

/// Keeps an event whose thread is not known yet.
pub async fn hold(
    conn: &mut PgConnection,
    account_id: &str,
    peer_id: &str,
    event: &E2eeEvent,
) -> sqlx::Result<()> {
    sqlx::query(
        "
        INSERT INTO e2ee_unplaced (account_id, peer_id, otid, event)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (account_id, peer_id, otid) DO NOTHING
        ",
    )
    .bind(account_id)
    .bind(peer_id)
    .bind(&event.otid)
    .bind(sqlx::types::Json(event))
    .execute(conn)
    .await?;
    Ok(())
}

/// Stores every held event whose thread is now known, oldest first; returns how many.
pub async fn place_held(conn: &mut PgConnection, account_id: &str) -> sqlx::Result<u64> {
    let held: Vec<(String, String, sqlx::types::Json<E2eeEvent>)> = sqlx::query_as(
        "
        SELECT peer_id, otid, event FROM e2ee_unplaced
         WHERE account_id = $1
         ORDER BY received_at
        ",
    )
    .bind(account_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut placed = 0;
    for (peer, otid, event) in held {
        let Some(thread_key) = thread_with(conn, account_id, &peer).await? else {
            continue;
        };
        store(conn, account_id, &thread_key, &event.0).await?;
        sqlx::query(
            "DELETE FROM e2ee_unplaced WHERE account_id = $1 AND peer_id = $2 AND otid = $3",
        )
        .bind(account_id)
        .bind(&peer)
        .bind(&otid)
        .execute(&mut *conn)
        .await?;
        placed += 1;
    }
    Ok(placed)
}
