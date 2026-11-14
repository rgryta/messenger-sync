-- Keep what a message used to say, and mark the ones that go away.
--
-- The forward walk already re-reads recent ranges; `insert_messages` is insert-only
-- and discarded the answer. Nothing here spends a harvest task: the comparison rides
-- the pages that walk already fetches, which matters because the daily task ceiling
-- is genuinely reached and every task this stole would slow a backfill that is not
-- finished.
--
-- Grants: `provision-messenger-db.sql` already carries ALTER DEFAULT PRIVILEGES FOR
-- ROLE messenger_ingest, so messenger_mcp can read a new table without a grants
-- migration. One was added for this once, found to be unnecessary, and deleted.
--
-- No backfill. Prior texts were never stored and cannot be recovered.

CREATE TABLE IF NOT EXISTS message_revision (
  account_id    text        NOT NULL,
  thread_key    text        NOT NULL,
  message_id    text        NOT NULL,
  seq           int         NOT NULL,
  text          text,
  -- NULL on seq 1 and only there, meaning unknown: nothing records when a message was
  -- first stored, so the earliest text held has no honest start time.
  first_seen_at timestamptz,
  superseded_at timestamptz,
  PRIMARY KEY (account_id, thread_key, message_id, seq),
  FOREIGN KEY (account_id, thread_key, message_id)
    REFERENCES message (account_id, thread_key, message_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS message_revision_seq_idx
  ON message_revision (account_id, thread_key, message_id, seq);

-- At most one current revision per message: a revision log that can disagree with the
-- message it describes leaves no way to tell which of the two is lying.
CREATE UNIQUE INDEX IF NOT EXISTS message_revision_one_current_idx
  ON message_revision (account_id, thread_key, message_id)
  WHERE superseded_at IS NULL;

-- Two strikes before a deletion is claimed. An empty answer is only probably the
-- truth here -- the same reasoning that makes a history walk wait for two empty pages
-- before calling itself finished -- and deleted_at hides a message from every default
-- view, so a false positive quietly removes real history.
ALTER TABLE message ADD COLUMN IF NOT EXISTS deleted_at    timestamptz;
ALTER TABLE message ADD COLUMN IF NOT EXISTS missing_since timestamptz;

DO $$
DECLARE
  has_archive boolean := EXISTS (SELECT 1 FROM pg_tablespace WHERE spcname = 'archive_data');
  has_nvme    boolean := EXISTS (SELECT 1 FROM pg_tablespace WHERE spcname = 'nvme_indexes');
BEGIN
  IF NOT (has_archive AND has_nvme) THEN
    RAISE NOTICE 'archive_data/nvme_indexes absent; leaving the new objects on the default tablespace';
    RETURN;
  END IF;
  SET LOCAL lock_timeout = '5s';
  EXECUTE 'ALTER TABLE message_revision SET TABLESPACE archive_data';
  EXECUTE 'ALTER INDEX message_revision_seq_idx SET TABLESPACE nvme_indexes';
  EXECUTE 'ALTER INDEX message_revision_one_current_idx SET TABLESPACE nvme_indexes';
END $$;
