-- Encrypted messages, decrypted by the client's own device rather than read off a screen.
--
-- An encrypted message has two ids. LightSpeed's envelope (sync group 95, no text) carries
-- Meta's `mid.$…` as its message_id and, as argument 9 of `upsertMessage`, the offline
-- threading id (OTID) the sending client chose. The encrypted stanza's id IS that OTID
-- (mautrix-meta sends with `ID: otid`). So the OTID is what joins the decrypted text to its
-- envelope, whichever of the two is stored first.
--
-- Generated, so every writer gets it without change: an envelope's from its stored op, a
-- row written from a decrypted message from `raw.otid`. Not unique: one thread already
-- holds two envelopes with the same OTID.
ALTER TABLE message
  ADD COLUMN IF NOT EXISTS otid text
  GENERATED ALWAYS AS (COALESCE(raw->>'otid', raw->'op'->>11)) STORED;

CREATE INDEX IF NOT EXISTS message_otid_idx ON message (account_id, thread_key, otid);

-- Decrypted messages whose thread is not known yet: a one-to-one chat is filed under a
-- thread key only LightSpeed knows, found through its participants. They wait here until a
-- pass brings the thread in. Rows in the shape `message` takes, minus the thread.
CREATE TABLE IF NOT EXISTS e2ee_unplaced (
  account_id  text        NOT NULL,
  peer_id     text        NOT NULL,
  otid        text        NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  -- What happened, as `messenger_client::inbox` decoded it.
  event       jsonb       NOT NULL,
  PRIMARY KEY (account_id, peer_id, otid)
);
