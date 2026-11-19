-- Events shim agent links (docs/events-shim.md): the last failed attempt to release each queued sender.
-- The wake sweeper tries never-attempted entries first, then the least recently attempted, so one failing
-- Relaycast workspace cannot keep newer releases from ever being tried.
ALTER TABLE events_shim_sender_releases ADD COLUMN attempted_at timestamptz;
