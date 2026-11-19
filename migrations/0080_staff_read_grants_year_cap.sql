-- Staff read grants (0061, docs/staff-read-grants.md): raise the hard expiry
-- cap from 90 to 365 days, matching Cloud (cloud#6414, drizzle 0429), so the
-- internal customer agents' read-only tokens need renewing once a year rather
-- than every quarter. The default lifetime stays 90 days in code
-- (STAFF_READ_GRANT_DEFAULT_DAYS); 365 is only the ceiling and must be asked
-- for explicitly.
--
-- Widening only: every existing row satisfies <= 90 days, so it satisfies
-- <= 365 days and re-validation cannot fail. Drop and add run in one ALTER
-- TABLE statement, so there is no moment without the constraint. Re-running
-- is safe (DROP ... IF EXISTS). Reverting to 90 days would fail while any
-- grant longer than 90 days exists; revoke and delete those first.
ALTER TABLE staff_read_grants
  DROP CONSTRAINT IF EXISTS staff_read_grant_lifetime,
  ADD CONSTRAINT staff_read_grant_lifetime
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '365 days');
