-- Native person-side Capy identity custody. No route/worker is enabled here.
-- The existing remote_agent_connections table remains the only provider key.
CREATE TABLE capy_bindings (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  thread_id text NOT NULL,
  state text NOT NULL CHECK (state IN ('preparing','bound','retired')),
  generation integer NOT NULL DEFAULT 1 CHECK (generation > 0),
  connection_digest text NOT NULL,
  relaycast_workspace_id text NOT NULL,
  -- Retained encrypted cleanup credential for this exact original Relay route.
  relaycast_key_ciphertext text,
  agent_name text NOT NULL,
  agent_remote_id text,
  token_ciphertext text,
  registration_attempted boolean NOT NULL DEFAULT false,
  lease_owner uuid,
  lease_until timestamptz,
  cleanup_pending boolean NOT NULL DEFAULT false,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (workspace_id,organization_id) REFERENCES workspaces(id,organization_id) ON DELETE RESTRICT,
  CHECK (state <> 'bound' OR (agent_remote_id IS NOT NULL AND token_ciphertext IS NOT NULL)),
  CHECK (state <> 'retired' OR token_ciphertext IS NULL)
);
-- One active owner globally; a second workspace must not adopt the same thread.
CREATE UNIQUE INDEX capy_bindings_active_thread ON capy_bindings(thread_id) WHERE state <> 'retired';
CREATE INDEX capy_bindings_owner ON capy_bindings(workspace_id,user_id);
CREATE INDEX capy_bindings_cleanup ON capy_bindings(updated_at) WHERE cleanup_pending;
