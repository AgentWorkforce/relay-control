-- Replicas agent bridge (src/replicas). One row per Replicas launch or
-- existing-chat binding that a workspace owner/admin asked Control to bring
-- onto Relay, ported from the hosted control plane's replicas_spawns.
--
-- The Replicas API key is not stored here: it stays sealed in
-- remote_agent_connections (provider 'replicas'). token_ciphertext is the
-- bound agent's Relaycast token, helper_ciphertext/helper_hash the
-- per-binding capability written into the replica, hook_ciphertext the
-- relay-events webhook secret. Release clears all of them before any
-- provider cleanup runs.
--
-- RESTRICT parents: a launch row is the only locator of paid compute, so
-- deleting a workspace, organization or user must never cascade it away.
CREATE TABLE IF NOT EXISTS replica_spawns (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  client_request_id text NOT NULL,
  -- How the row was created: a launch (spawn_replica), an existing chat
  -- (bind_replica), or a later per-replica enrolment ('environment_identity',
  -- reserved; nothing writes it yet).
  source text CHECK (source IN ('spawn', 'bind', 'environment_identity')),
  input jsonb NOT NULL,
  replica_id text,
  chat_id text,
  state text NOT NULL CHECK (state IN ('creating', 'preparing', 'binding', 'dispatching', 'bound', 'rejected', 'gone')),
  relay_workspace_id text,
  agent_name text,
  agent_remote_id text,
  token_ciphertext text,
  helper_ciphertext text,
  helper_hash text,
  hook_ciphertext text,
  subscription_id text,
  mention_subscription_id text,
  task_message_id text,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS replica_spawns_request
  ON replica_spawns (workspace_id, user_id, client_request_id);

-- One live bridge per provider replica.
CREATE UNIQUE INDEX IF NOT EXISTS replica_spawns_replica
  ON replica_spawns (replica_id) WHERE state <> 'gone';

-- The provider replica id as a per-workspace key, so a row can be found (or
-- enrolled) by workspace and replica alone.
CREATE UNIQUE INDEX IF NOT EXISTS replica_spawns_workspace_replica
  ON replica_spawns (workspace_id, replica_id) WHERE state <> 'gone';

-- Relay messages injected into a bound replica's chat, keyed by the Relay
-- message id so a redelivered webhook never injects twice.
CREATE TABLE IF NOT EXISTS replica_deliveries (
  spawn_id uuid NOT NULL REFERENCES replica_spawns(id) ON DELETE CASCADE,
  message_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('sending', 'sent', 'retrying', 'rejected', 'unknown')),
  provider_message_id text,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (spawn_id, message_id)
);
