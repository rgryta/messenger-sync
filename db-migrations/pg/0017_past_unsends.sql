-- Unsends LightSpeed delivered before the client acted on them: a `deleteThenInsertMessage`
-- whose argument 17 (`IsUnsent`) is true, stored as a message and never marked. Marked now,
-- at the unsend time its argument 18 carries, else the message's own time.
UPDATE message
   SET deleted_at = CASE WHEN raw->'op'->20->>1 ~ '^[0-9]+$'
                         THEN to_timestamp((raw->'op'->20->>1)::bigint / 1000.0)
                         ELSE ts END
 WHERE raw->'op'->>1 = 'deleteThenInsertMessage'
   AND raw->'op'->>19 = 'true'
   AND deleted_at IS NULL;
