-- Relay node credentials (docs/relay-node-credential.md, "Gate-only
-- installs"): on a gate-only install (SELFHOST_RELAYGATE_PUBLIC_URL set) a
-- relay node enrols through POST /relay-node/v1/nodes and Control keeps the
-- Relaycast node token Relaycast answers instead of returning it to the node
-- host. The node then connects to Control's GET /relay-node/v1/ws bridge,
-- which opens the upstream Relaycast node socket with this token. One row per
-- (workspace, node name); a re-enrolment rotates the token in place. The node
-- token is only ever stored sealed under the active encryption key
-- (token_ciphertext), never in clear and never hashed for lookup. No rows are
-- written when the gate URL is unset.
CREATE TABLE IF NOT EXISTS relay_node_credentials (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  node_name text NOT NULL,
  relaycast_node_id text NOT NULL,
  api_token_id uuid NOT NULL REFERENCES workspace_api_tokens(id) ON DELETE CASCADE,
  token_ciphertext text NOT NULL,
  enrolled_at timestamptz NOT NULL DEFAULT now(),
  last_heartbeat_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, node_name)
);
