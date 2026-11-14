-- Whether a conversation's rendered history has been walked to its beginning.
--
-- Capture used to read one screen and two scrolls, which is the newest ~25-45 lines
-- whatever the thread's size. Measured against the envelopes it is meant to give words
-- to:
--
--   22,433 envelopes -> 44 rendered lines    0.2%, one day
--   22,356 ->  45                            0.2%
--   11,041 ->  18                            0.2%
--      245 ->  26                           10.6%
--       35 ->  30                           85.7%
--
-- Small conversations were nearly done and large ones had barely started, and nothing
-- would ever have improved: a thread was only revisited when it MOVED, so one that went
-- quiet kept whatever single screen it happened to be shown, for good.
--
-- So capture now walks backwards, resuming from the oldest line it already holds, the
-- way `history_done` lets the envelope crawl resume. This flag is the other half: a
-- thread is offered for capture while it has new messages at the tail OR its history is
-- not finished, and this is what says "finished".
--
-- Set only when the conversation refuses to scroll further - the one honest signal that
-- there is nothing older to see. NOT set when a pass merely used up its screen budget,
-- which is the normal way a long walk ends and means "continue next time".
--
-- Nothing clears it automatically, matching `history_done`: reaching the beginning of a
-- conversation is not a thing that stops being true. New messages at the tail are a
-- separate condition and are not affected by it.

ALTER TABLE thread
    ADD COLUMN IF NOT EXISTS dom_history_done boolean NOT NULL DEFAULT false;

-- The walk asks for threads that are unfinished, in a table where most threads have no
-- rendered text at all and never will, so the useful index is the partial one.
CREATE INDEX IF NOT EXISTS thread_dom_unfinished_idx
    ON thread (account_id, last_activity_at DESC)
    WHERE NOT dom_history_done;
