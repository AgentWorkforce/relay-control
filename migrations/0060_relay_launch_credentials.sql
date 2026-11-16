-- Relay launch credentials (docs/identity.md, "Gate-only installs
-- (relaygate)"): on a gate-only install (SELFHOST_RELAYGATE_PUBLIC_URL set)
-- every agent launch journaled in relay_spawns gets one single-use `sh_lt_`
-- credential, bound to its workspace, node, agent name and launching user.
-- The launched agent presents it once to relaygate, which introspects it at
-- POST /internal/v1/auth/introspect; the first active answer burns it
-- (redeemed_at set, ciphertext cleared). Only the sha256 hash is looked up;
-- the sealed copy exists only for the Control node-socket bridge to attach to
-- the launch it forwards to the node. No rows are written when the gate URL
-- is unset.
CREATE TABLE IF NOT EXISTS relay_launch_credentials (
  id uuid PRIMARY KEY,
  spawn_id uuid NOT NULL UNIQUE REFERENCES relay_spawns(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  node_name text NOT NULL,
  agent_name text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  token_ciphertext text,
  expires_at timestamptz NOT NULL,
  redeemed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS relay_launch_credentials_workspace ON relay_launch_credentials (workspace_id, created_at);
