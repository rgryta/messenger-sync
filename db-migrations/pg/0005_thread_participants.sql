-- Who is in a conversation.
--
-- A one-to-one thread has no title — the real client renders the other person's
-- name — so `thread.title IS NULL` by construction for every DM, and the archive
-- displayed all of them as "(untitled)". There was no person → conversation hop at
-- all: a caller who wanted Kasia's DM had to full-text search for something she said
-- and read the thread key off the hit.
--
-- Membership here is derived from who has actually spoken in the thread. A silent
-- member never appears, which is a real limitation — but it rests on `sender_id`,
-- which the decoder reads positionally with a guard and which every stored message
-- carries. See 0007, which adds the roster instruction as a better source; this
-- remains the fallback for anything the roster does not cover.
CREATE TABLE IF NOT EXISTS thread_participant (
    account_id    text NOT NULL,
    thread_key    text NOT NULL,
    fb_user_id    text NOT NULL,
    -- When this person was first and last seen speaking here. `last_spoke_at` is what
    -- orders a group's members by who is actually active in it.
    first_spoke_at timestamptz,
    last_spoke_at  timestamptz,
    PRIMARY KEY (account_id, thread_key, fb_user_id),
    FOREIGN KEY (account_id, thread_key)
        REFERENCES thread (account_id, thread_key) ON DELETE CASCADE
);

-- The person → conversations direction, which is the one that was impossible.
CREATE INDEX IF NOT EXISTS thread_participant_person_idx
    ON thread_participant (account_id, fb_user_id, last_spoke_at DESC NULLS LAST);

-- Backfill from what is already archived, so this is not empty until every thread
-- has been re-paged.
INSERT INTO thread_participant (account_id, thread_key, fb_user_id,
                                first_spoke_at, last_spoke_at)
SELECT account_id, thread_key, sender_id, min(ts), max(ts)
  FROM message
 WHERE sender_id IS NOT NULL
 GROUP BY account_id, thread_key, sender_id
ON CONFLICT (account_id, thread_key, fb_user_id) DO NOTHING;
