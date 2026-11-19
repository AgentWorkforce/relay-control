-- Cursor cloud agents (docs/cursor-cloud-agents.md). A Cursor cloud agent
-- proves which run it is with a Cursor-signed OIDC token; these tables link
-- the Cursor account behind it to a Control user and record each run's own
-- relay participant.

-- Which Cursor account (the token's `sub`: user:<id> or service_account:<id>)
-- belongs to which Control user in a workspace. A link is confirmed by the
-- user in the browser (method confirmed: code_hash/code_expires_at hold the
-- pending one-time code until then) or made automatically for an
-- operator-trusted Cursor team whose token carries the user's own email
-- (method trusted_team). A Cursor account is confirmed for at most one user
-- per workspace.
CREATE TABLE IF NOT EXISTS cursor_cloud_links (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cursor_subject text NOT NULL,
  method text NOT NULL CHECK (method IN ('confirmed', 'trusted_team')),
  code_hash text UNIQUE,
  code_expires_at timestamptz,
  confirmed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, user_id, cursor_subject)
);
CREATE UNIQUE INDEX IF NOT EXISTS cursor_cloud_links_confirmed_subject
  ON cursor_cloud_links (workspace_id, cursor_subject) WHERE confirmed_at IS NOT NULL;

-- One relay participant per Cursor cloud agent run (cloud_agent_id) under an
-- OAuth grant. The participant itself is a hosted_relay_participants row; a
-- revoked grant's runs are released by the OAuth teardown worker.
CREATE TABLE IF NOT EXISTS cursor_cloud_runs (
  grant_id uuid NOT NULL REFERENCES mcp_oauth_grants(id) ON DELETE CASCADE,
  cloud_agent_id text NOT NULL,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  agent_name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (grant_id, cloud_agent_id),
  UNIQUE (grant_id, agent_name)
);
