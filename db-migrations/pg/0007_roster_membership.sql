-- Membership as Meta states it, not as we infer it.
--
-- 0005 derived membership from who had spoken, because no roster instruction had
-- been captured. One has now: `addParticipantIdToGroupThread` is delivered for
-- one-to-one threads as well as groups — in a live capture it covered all 67
-- conversations, 51 of them two-member DMs. That is strictly better evidence: it
-- names a person who has never said anything in the window we hold.
--
-- Speech-derived membership stays as a fallback, so these columns are nullable and
-- a row can come from either source.
ALTER TABLE thread_participant
    ADD COLUMN IF NOT EXISTS joined_at timestamptz,
    ADD COLUMN IF NOT EXISTS is_admin  boolean NOT NULL DEFAULT false,
    -- Which evidence put the row here, so a later reader can tell a stated member
    -- from an inferred one.
    ADD COLUMN IF NOT EXISTS from_roster boolean NOT NULL DEFAULT false;
