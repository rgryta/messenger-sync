-- Forward sync: a watermark, so a finished thread can still receive new messages.
--
-- Before this, `thread` recorded only how far BACKWARDS a crawl had reached
-- (`oldest_seen_at`) and whether that crawl had finished (`history_done`). The
-- history loop selects `WHERE NOT history_done`, so a completed thread was never
-- queried again, and a warm browser profile delivers no messages unprompted. The
-- archive therefore filled once and then stopped growing.
--
-- `newest_seen_at` is the newest message this archive holds for the thread.
-- Comparing it against `last_activity_at` — which the thread listing refreshes on
-- every pass — is how a thread announces that somebody has said something since we
-- last looked.
ALTER TABLE thread
    ADD COLUMN IF NOT EXISTS newest_seen_at timestamptz;

-- Backfill from what is already stored, so an existing archive does not re-page
-- every thread it already holds on the first pass after this migration.
UPDATE thread t
   SET newest_seen_at = m.newest
  FROM (SELECT account_id, thread_key, max(ts) AS newest
          FROM message
         GROUP BY account_id, thread_key) m
 WHERE m.account_id = t.account_id
   AND m.thread_key = t.thread_key
   AND t.newest_seen_at IS NULL;

-- The forward loop's selection: threads whose listed activity is ahead of the
-- newest message we hold. Partial rather than full, because the answer is normally
-- a handful of rows out of a decade of conversations.
CREATE INDEX IF NOT EXISTS thread_forward_idx
    ON thread (account_id, last_activity_at DESC NULLS LAST)
 WHERE last_activity_at IS NOT NULL;

-- `get_history` filters on `thread_key` with `account_id` optional, so the composite
-- index led by `account_id` cannot serve the common single-account call. Irrelevant
-- at today's row counts and not irrelevant at a decade of them.
CREATE INDEX IF NOT EXISTS message_thread_only_idx
    ON message (thread_key, ts DESC);
