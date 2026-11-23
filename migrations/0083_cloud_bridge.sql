-- Session bridge for organizations moved from Agent Relay Cloud
-- (docs/identity.md). Cloud signs a short-lived assertion for a browser that
-- holds a live Cloud session; Control turns it into its own browser session,
-- but only for an organization the operator has listed here, for a bounded
-- window, after its import was applied and verified.

-- One bridge window per organization. set_by is the operator-declared label
-- of who opened or last changed the window: the bootstrap credential that
-- writes these rows carries no person identity of its own.
CREATE TABLE IF NOT EXISTS cloud_bridge_organizations (
  organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  opens_at timestamptz NOT NULL DEFAULT now(),
  closes_at timestamptz NOT NULL,
  set_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (closes_at > opens_at)
);

-- Spent assertion ids. An assertion is single use: its jti is inserted
-- before the sign-in and a second insert of the same jti is a replay. Rows
-- are kept until shortly after the assertion could no longer verify anyway,
-- then swept.
CREATE TABLE IF NOT EXISTS cloud_bridge_assertions (
  jti text PRIMARY KEY,
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS cloud_bridge_assertions_expires_at
  ON cloud_bridge_assertions (expires_at);
