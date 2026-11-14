-- Reactions and attachments, which arrive as their own instructions.
--
-- `message.attachments` and `message.reply_to_id` have existed since 0001 and were
-- never written, because the decoder only ever read `upsertMessage`. Media does not
-- travel inside the message: a photo or GIF arrives as `insertBlobAttachment` and a
-- link preview as `insertXmaAttachment`, each naming the message it belongs to.
-- Reactions arrive as `upsertReaction`. So a thread could be read back with no sign
-- that anybody had responded, and every media message decoded to NULL text —
-- rendered identically to an empty message.
--
-- Separate tables rather than the `attachments` jsonb column: an attachment arrives
-- in a different instruction from its message and often in a different page, and
-- `message` is insert-only by design so that a re-read range never rewrites history.
-- Appending to a jsonb column would mean updating stored messages.
CREATE TABLE IF NOT EXISTS message_reaction (
    account_id  text NOT NULL,
    thread_key  text NOT NULL,
    message_id  text NOT NULL,
    actor_id    text NOT NULL,
    emoji       text NOT NULL,
    reacted_at  timestamptz NOT NULL,
    -- One reaction per person per message: re-reading a range re-delivers the same
    -- reaction, and a changed emoji replaces rather than accumulates.
    PRIMARY KEY (account_id, thread_key, message_id, actor_id),
    FOREIGN KEY (account_id, thread_key)
        REFERENCES thread (account_id, thread_key) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS message_reaction_message_idx
    ON message_reaction (account_id, thread_key, message_id);

CREATE TABLE IF NOT EXISTS message_attachment (
    account_id    text NOT NULL,
    thread_key    text NOT NULL,
    message_id    text NOT NULL,
    -- Blob attachments carry an id; XMA previews do not, so the URL stands in. One
    -- of the two is always present, which is what makes the key total.
    attachment_key text NOT NULL,
    kind          text NOT NULL,
    mime_type     text,
    url           text,
    preview_url   text,
    raw           jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (account_id, thread_key, message_id, attachment_key),
    FOREIGN KEY (account_id, thread_key)
        REFERENCES thread (account_id, thread_key) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS message_attachment_message_idx
    ON message_attachment (account_id, thread_key, message_id);
