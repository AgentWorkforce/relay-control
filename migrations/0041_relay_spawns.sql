-- Agent launches through the shared-sessions MCP endpoint (SELFHOST_FEATURES
-- launch; docs/agent-launch.md), ported from Cloud's hosted_relay_spawns. A
-- row is journaled before a launch is sent and is bound to its workspace,
-- user, MCP authority, Relaycast workspace and hosted actor, so status and
-- release can only reach a launch the same connection started. Rows stay for
-- idempotency and audit after failure or release.
CREATE TABLE IF NOT EXISTS relay_spawns (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  authority_hash text NOT NULL,
  relaycast_workspace_id text NOT NULL,
  actor_id text NOT NULL,
  idempotency_hash text NOT NULL,
  request_hash text NOT NULL,
  agent_name text NOT NULL,
  cli text NOT NULL,
  node_id text NOT NULL,
  state text NOT NULL,
  invocation_id text,
  worker_id text,
  worker_address text,
  release_invocation_id text,
  task_unconfirmed boolean NOT NULL DEFAULT false,
  revision integer NOT NULL DEFAULT 0,
  audit jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT relay_spawns_state CHECK (state IN ('reserved','accepted','unknown','ready','failed','releasing','released')),
  CONSTRAINT relay_spawns_cli CHECK (cli ~ '^[a-z0-9][a-z0-9-]{0,31}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS relay_spawns_idempotency ON relay_spawns (idempotency_hash);
CREATE INDEX IF NOT EXISTS relay_spawns_workspace ON relay_spawns (workspace_id, created_at);
