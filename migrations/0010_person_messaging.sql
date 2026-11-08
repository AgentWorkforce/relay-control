-- Person messaging: the control plane owns the member id and the encrypted
-- human-agent token. Relaycast owns the human agent row and the @name handle.

CREATE TABLE IF NOT EXISTS selfhost_person_identities (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE CASCADE,
  agent_name text NOT NULL,
  agent_remote_id text NOT NULL,
  token_ciphertext text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, user_id),
  UNIQUE (workspace_id, agent_name)
);

CREATE TABLE IF NOT EXISTS selfhost_person_messages (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE CASCADE,
  peer_name text NOT NULL,
  client_message_id text NOT NULL,
  relay_message_id text,
  conversation_id text,
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, user_id, client_message_id)
);
