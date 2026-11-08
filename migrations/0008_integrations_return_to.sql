-- Just-in-time integration connects: the callback page returns the user to
-- where the connect started (a flow page in the dashboard). Same-origin with
-- SELFHOST_DASHBOARD_URL, validated before it is stored. Additive; no write hold.
ALTER TABLE selfhost_integration_oauth_states ADD COLUMN IF NOT EXISTS return_to text;
