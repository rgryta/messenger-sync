-- Voice messages that are not end-to-end encrypted (older history, and group chats) are
-- transcribed too: the worker fetches their stored CDN link as it is. That link expires
-- after a few days. A voice message whose link has expired is `expired`, not `failed`, so
-- a re-read that stores a fresh link can clear it and hand it back to the worker.
ALTER TABLE message DROP CONSTRAINT IF EXISTS message_transcript_status_check;
ALTER TABLE message ADD CONSTRAINT message_transcript_status_check
  CHECK (transcript_status IN ('pending', 'done', 'failed', 'expired'));
