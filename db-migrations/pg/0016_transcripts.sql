-- Voice messages in encrypted chats, as text. The client's worker fetches each one by the
-- reference its attachment keeps, has the whisper.cpp server transcribe it, and stores the
-- words here: not typed, so a column of its own, which the MCP shows quoted. Statuses as
-- whatsapp-sync's: `pending` until tried, `done`, or `failed` when the file is gone or the
-- audio cannot be read (never retried).
ALTER TABLE message ADD COLUMN IF NOT EXISTS transcript text;
ALTER TABLE message ADD COLUMN IF NOT EXISTS transcript_status text
  CHECK (transcript_status IN ('pending', 'done', 'failed'));
CREATE INDEX IF NOT EXISTS message_transcript_pending_idx
  ON message (ts DESC) WHERE transcript_status = 'pending';

-- Voice messages already stored with their file reference (since 0.1.1) are queued too.
UPDATE message m SET transcript_status = 'pending'
  FROM message_attachment a
 WHERE a.account_id = m.account_id AND a.thread_key = m.thread_key
   AND a.message_id = m.message_id AND a.kind = 'e2ee'
   AND a.raw->>'kind' = 'audio' AND a.raw ? 'media' AND m.transcript_status IS NULL;

-- Search covers transcripts too. A generated column's expression cannot be changed in
-- place, so it is rebuilt: one rewrite of the table, and its index rebuilt where 0002 put
-- it. 'simple' as before: the corpus is mostly Polish.
ALTER TABLE message DROP COLUMN IF EXISTS search;
ALTER TABLE message ADD COLUMN search tsvector GENERATED ALWAYS AS
  (to_tsvector('simple', coalesce(text, '') || ' ' || coalesce(transcript, ''))) STORED;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_tablespace WHERE spcname = 'nvme_indexes') THEN
    CREATE INDEX IF NOT EXISTS message_search_idx ON message USING gin (search)
      TABLESPACE nvme_indexes;
  ELSE
    CREATE INDEX IF NOT EXISTS message_search_idx ON message USING gin (search);
  END IF;
END $$;
