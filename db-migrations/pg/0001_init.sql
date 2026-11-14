-- Messenger archive schema.
--
-- Shaped by what LightSpeed ops actually carry rather than by what the Messenger UI
-- shows. Every row keeps the op that produced it in `raw`: Meta reshapes these
-- without notice, and re-parsing a stored op is free where re-fetching history is
-- slow, rate-limited and eventually impossible.

CREATE TABLE IF NOT EXISTS schema_migration (
    filename    text PRIMARY KEY,
    applied_at  timestamptz NOT NULL DEFAULT now()
);

-- One row per Messenger account being archived. `account_id` is a short label
-- chosen by the operator, not Meta's id, so a second account can be added later
-- without merging corpora.
CREATE TABLE IF NOT EXISTS account (
    id                text PRIMARY KEY,
    fb_user_id        text NOT NULL,
    username          text,
    enabled           boolean NOT NULL DEFAULT true,
    -- A dead session is a human event: the profile has to be re-authenticated by
    -- hand in a real browser. Recorded here so `status` can say so out loud rather
    -- than the archive going quietly stale.
    last_auth_error   text,
    last_auth_error_at timestamptz,
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS thread (
    account_id        text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    thread_key        text NOT NULL,
    -- 1 = regular inbox, 95 = end-to-end encrypted. A message-range task built for
    -- the wrong group returns nothing at all and raises nothing, so the group a
    -- thread was discovered in is load-bearing state, not a label.
    sync_group        integer NOT NULL,
    title             text,
    is_group          boolean NOT NULL DEFAULT false,
    last_activity_at  timestamptz,
    -- Backward paging state. `oldest_seen_at` is the reference timestamp the next
    -- message-range task starts from; `history_done` is set only when a task comes
    -- back with nothing new, which is the single trustworthy end-of-history signal.
    oldest_seen_at    timestamptz,
    history_done      boolean NOT NULL DEFAULT false,
    last_harvest_at   timestamptz,
    raw               jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (account_id, thread_key)
);

CREATE INDEX IF NOT EXISTS thread_activity_idx
    ON thread (account_id, last_activity_at DESC NULLS LAST);

-- Threads still owing history, least recently visited first. Partial, because the
-- finished ones are the majority once the archive settles.
CREATE INDEX IF NOT EXISTS thread_history_pending_idx
    ON thread (account_id, last_harvest_at NULLS FIRST)
    WHERE NOT history_done;

CREATE TABLE IF NOT EXISTS participant (
    account_id        text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    fb_user_id        text NOT NULL,
    name              text,
    username          text,
    profile_pic_url   text,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, fb_user_id)
);

CREATE TABLE IF NOT EXISTS message (
    account_id        text NOT NULL,
    thread_key        text NOT NULL,
    -- Meta's `mid.$...`. Stable across re-delivery, which is what makes the
    -- harvester safe to re-run over the same range.
    message_id        text NOT NULL,
    ts                timestamptz NOT NULL,
    sender_id         text,
    text              text,
    -- Kept so a caller can tell a real message from a system event without
    -- re-deriving it. See `messenger_sync.store.SYSTEM_ITEM_TYPES`.
    item_type         text NOT NULL DEFAULT 'text',
    reply_to_id       text,
    attachments       jsonb NOT NULL DEFAULT '[]'::jsonb,
    sync_group        integer NOT NULL,
    raw               jsonb NOT NULL DEFAULT '{}'::jsonb,
    search            tsvector GENERATED ALWAYS AS
        -- 'simple', not 'english': this corpus is mostly Polish, and an English
        -- stemmer silently drops hits on everything that is not English.
        (to_tsvector('simple', coalesce(text, ''))) STORED,
    PRIMARY KEY (account_id, thread_key, message_id),
    FOREIGN KEY (account_id, thread_key)
        REFERENCES thread (account_id, thread_key) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS message_thread_ts_idx
    ON message (account_id, thread_key, ts DESC);

CREATE INDEX IF NOT EXISTS message_ts_idx
    ON message (account_id, ts DESC);

CREATE INDEX IF NOT EXISTS message_search_idx
    ON message USING gin (search);

CREATE INDEX IF NOT EXISTS message_sender_idx
    ON message (account_id, sender_id);

-- Named groups of people, so a caller can ask about "the sailing crew" without
-- knowing ids. Purely local: Meta never sees these.
CREATE TABLE IF NOT EXISTS person_alias (
    alias       text PRIMARY KEY,
    note        text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS person_alias_member (
    alias       text NOT NULL REFERENCES person_alias (alias) ON DELETE CASCADE,
    account_id  text NOT NULL,
    fb_user_id  text NOT NULL,
    PRIMARY KEY (alias, account_id, fb_user_id)
);

-- One row per harvest loop, so `status` can report when each last ran and what it
-- last failed at without inventing a metrics stack.
CREATE TABLE IF NOT EXISTS sync_state (
    account_id        text NOT NULL REFERENCES account (id) ON DELETE CASCADE,
    loop              text NOT NULL,
    current_thread_key text,
    last_run_at       timestamptz,
    last_error        text,
    last_error_at     timestamptz,
    PRIMARY KEY (account_id, loop)
);
