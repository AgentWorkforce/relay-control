-- Durable post-commit teardown intent. Tombstones survive parent deletion so
-- a Relaycast outage cannot lose release work. No token/secret is stored here.
CREATE TABLE selfhost_mcp_oauth_revocations (
  id uuid PRIMARY KEY,
  grant_id uuid NOT NULL UNIQUE,
  token_family_id uuid NOT NULL,
  user_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  client_id text NOT NULL,
  agent_name text NOT NULL,
  agent_remote_id text,
  reason text NOT NULL,
  created_at timestamptz NOT NULL,
  completed_at timestamptz
);
