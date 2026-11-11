-- Capture policy (docs/capture-policy.md): when `sharing_mode` last became
-- `new`. Kept across writes that leave it `new`, cleared when it changes, so
-- the sessions pipeline can refuse a session that started before the
-- operator mandated "new sessions only". Rows already at `new` take their
-- last write time (the best record there is).
ALTER TABLE capture_policies ADD COLUMN IF NOT EXISTS sharing_mode_since timestamptz NULL;
UPDATE capture_policies
   SET sharing_mode_since = updated_at
 WHERE settings->>'sharing_mode' = 'new' AND sharing_mode_since IS NULL;
