-- Links a hosted MCP session to an Agent Relay Desktop identity, ported from
-- Cloud's desktop_relay_session_bindings. join_relay desktop_address writes
-- the row; the session then acts as that synced identity, so DMs and channel
-- posts reach the Desktop natively instead of a hosted inbox. session_hash is
-- the sha256 of the Mcp-Session-Id, never the id itself. The composite key
-- keeps a binding inside its owner and workspace, and a re-sync that drops
-- the identity removes every binding to it.
CREATE UNIQUE INDEX IF NOT EXISTS desktop_relay_identities_owned_id_unique
  ON desktop_relay_identities (workspace_id, user_id, id);

CREATE TABLE IF NOT EXISTS desktop_relay_session_bindings (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL,
  user_id uuid NOT NULL,
  session_hash text NOT NULL,
  desktop_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (workspace_id, user_id, desktop_identity_id)
    REFERENCES desktop_relay_identities (workspace_id, user_id, id) ON DELETE CASCADE,
  UNIQUE (workspace_id, user_id, session_hash)
);
