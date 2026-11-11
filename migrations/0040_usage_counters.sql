-- Usage page (owner-only, behind SELFHOST_FEATURES=usage): daily aggregate
-- counts per organization. Nothing is recorded while the feature is off.
-- Counts only: no content, prompts, emails or names. Active users are kept as
-- an HMAC of the user id under a per-install secret (usage_state.salt) that
-- is never returned by any API.

CREATE TABLE IF NOT EXISTS usage_state (
  id smallint PRIMARY KEY DEFAULT 1,
  salt text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT usage_state_singleton CHECK (id = 1)
);

CREATE TABLE IF NOT EXISTS usage_daily_counters (
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  day date NOT NULL,
  metric text NOT NULL,
  value bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (organization_id, day, metric),
  CONSTRAINT usage_daily_counters_metric CHECK (metric IN ('searches'))
);

CREATE TABLE IF NOT EXISTS usage_daily_users (
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  day date NOT NULL,
  user_hash text NOT NULL,
  PRIMARY KEY (organization_id, day, user_hash)
);
