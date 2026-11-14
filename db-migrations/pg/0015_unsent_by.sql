-- An unsent encrypted message comes back from LightSpeed as a fresh envelope under the
-- unsend's OTID, not the message's. The decrypted unsend records that OTID on the message as
-- `raw.unsent_by`, and `insert_messages` skips an envelope carrying it; this keeps the check
-- an index lookup. Partial: only unsent encrypted messages have the key.
CREATE INDEX IF NOT EXISTS message_unsent_by_idx
  ON message (account_id, thread_key, (raw->>'unsent_by'))
  WHERE raw ? 'unsent_by';
