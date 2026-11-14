-- When each rendered message was sent, as an instant.
--
-- `0010` stored `time_label` verbatim and said parsing it "still would not be an
-- instant". That was wrong, and measuring the labels is what showed it. Messenger
-- writes the clock in three forms, and together they are complete rather than
-- ambiguous -- measured over 218 captured rows:
--
--   "O 14:00"                        49 rows   the capture's own date
--   "O czwartek 17:35"               76 rows   the most recent Thursday before it
--   "w 29 pazdziernika 2026 14:32"   93 rows   already absolute
--
-- The relative two are relative to WHEN THE CAPTURE RAN, which `dom_capture.captured_at`
-- records, so resolving them is arithmetic. And the forms do not overlap: the client
-- switches to an absolute date at about the point a weekday would stop identifying a
-- single day. The earlier note feared owning weekday names per locale; that cost is one
-- map per language, against a timestamp on every rendered message.
--
-- Precision is the minute, because that is all the client draws. That is enough for
-- ordering and for `after`/`before` paging, and deliberately NOT enough to glue a
-- rendered line onto a `message` row: two messages from one person inside one minute
-- are indistinguishable here. `0010`'s rule stands -- rendered text is never joined to
-- `message` -- and this column does not weaken it. It makes the rendered record
-- readable on its own terms instead of only as an excerpt.
--
-- NULL where the label did not parse, which is honest about a locale or a format this
-- does not know yet, and is why the column is nullable.

ALTER TABLE dom_message ADD COLUMN IF NOT EXISTS ts timestamptz;

-- Paging reads this per thread and in time order, which means the capture has to come
-- along: `dom_message` has no thread of its own.
CREATE INDEX IF NOT EXISTS dom_message_ts_idx ON dom_message (capture_id, ts);
