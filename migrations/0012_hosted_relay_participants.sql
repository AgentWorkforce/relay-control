-- Hosted MCP relay participants: the Relaycast agent an MCP session (or an
-- explicitly named caller) messages as. Ported from Cloud's
-- hosted_relay_participants. The control plane owns the owner binding and
-- the encrypted agent token; Relaycast owns the agent row and its name.

CREATE TABLE IF NOT EXISTS selfhost_hosted_relay_participants (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE CASCADE,
  relaycast_workspace_id text NOT NULL,
  -- sha256 of the MCP session id; null for a participant used only by name.
  session_hash text,
  agent_name text NOT NULL,
  agent_remote_id text NOT NULL,
  -- Keyring envelope (crypto.encryptSecret); never the plain token.
  token_ciphertext text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, user_id, agent_name),
  UNIQUE (relaycast_workspace_id, agent_remote_id)
);

-- One hosted participant per MCP session.
CREATE UNIQUE INDEX IF NOT EXISTS selfhost_hosted_relay_participants_session
  ON selfhost_hosted_relay_participants (workspace_id, user_id, session_hash)
  WHERE session_hash IS NOT NULL;
