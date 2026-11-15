-- A forward walk the page cap or the day's budget cut short: where it stopped, and the
-- watermark it still has to reach. The next pass carries on from there instead of
-- starting again from now, which left a hole between the two walks.
ALTER TABLE thread
    ADD COLUMN IF NOT EXISTS forward_resume_at timestamptz,
    ADD COLUMN IF NOT EXISTS forward_floor_at timestamptz;
