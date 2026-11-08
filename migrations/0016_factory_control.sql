-- Factory sessions control core (port of Cloud PR 6168, control-plane side).
-- See docs/design/factory-control-routes.md §5 and docs/factory-sessions.md.
--
-- Every table carries (workspace_id, organization_id) with a composite FK to
-- selfhost_workspaces ON DELETE RESTRICT: a workspace deletion that skips
-- cleanupWorkspaceFactory fails loudly instead of orphaning remote agents.
-- Secrets are crypto.encryptSecret text envelopes; reply bearers are stored
-- only as sha256 hashes. No history captures or acquisition tables (deferred).

CREATE TABLE IF NOT EXISTS selfhost_factory_connections (
  workspace_id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE RESTRICT,
  key_envelope text NOT NULL,
  key_hint text NOT NULL,
  validated_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (workspace_id, organization_id)
    REFERENCES selfhost_workspaces(id, organization_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS selfhost_factory_bindings (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE RESTRICT,
  session_id text NOT NULL,
  computer_id text NOT NULL,
  state text NOT NULL DEFAULT 'preparing',
  -- Incremented on every state change; fences post-effect delivery updates.
  generation bigint NOT NULL DEFAULT 0,
  relay_agent_name text NOT NULL,
  relay_agent_id text,
  hosted_token_envelope text,
  hook_secret_envelope text,
  helper_secret_envelope text,
  -- Nullable until Relaycast subscriptions ship (deferred).
  subscription_id text,
  mention_subscription_id text,
  history_queued_at timestamptz,
  retired_at timestamptz,
  -- Why a retired row is kept: its remote agent release has not completed.
  remote_cleanup_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (workspace_id, organization_id)
    REFERENCES selfhost_workspaces(id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT selfhost_factory_bindings_state CHECK (state IN ('preparing', 'bound', 'retired'))
);

-- One live binding per Factory session across the installation. Retired rows
-- are not uniqueness holders, so a retired former owner never blocks a
-- successor (6168 follow-up).
CREATE UNIQUE INDEX IF NOT EXISTS selfhost_factory_bindings_live_session
  ON selfhost_factory_bindings (session_id)
  WHERE state <> 'retired';

CREATE INDEX IF NOT EXISTS selfhost_factory_bindings_live_owner
  ON selfhost_factory_bindings (workspace_id, user_id)
  WHERE state <> 'retired';

CREATE TABLE IF NOT EXISTS selfhost_factory_deliveries (
  binding_id uuid NOT NULL REFERENCES selfhost_factory_bindings(id) ON DELETE CASCADE,
  message_id text NOT NULL,
  workspace_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  relay_delivery_id text NOT NULL,
  -- Pinned recipient of any reply: the Relay sender of this message.
  sender_agent_name text NOT NULL,
  sender_agent_id text,
  -- Encrypted {sender, text}; cleared on retire, purge and terminal states.
  payload_envelope text,
  state text NOT NULL DEFAULT 'pending',
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_until timestamptz,
  lease_owner uuid,
  claim_generation bigint,
  factory_message_id text,
  code text,
  reply_hash text UNIQUE,
  reply_expires_at timestamptz,
  reply_result jsonb,
  reply_body_hash text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (binding_id, message_id),
  FOREIGN KEY (workspace_id, organization_id)
    REFERENCES selfhost_workspaces(id, organization_id) ON DELETE RESTRICT,
  CONSTRAINT selfhost_factory_deliveries_state
    CHECK (state IN ('pending', 'sending', 'delivered', 'unknown', 'rejected'))
);

CREATE INDEX IF NOT EXISTS selfhost_factory_deliveries_due
  ON selfhost_factory_deliveries (state, next_attempt_at)
  WHERE state IN ('pending', 'sending');

-- Dormant: written only by the history schedule intent. Nothing is exported.
CREATE TABLE IF NOT EXISTS selfhost_factory_history_syncs (
  workspace_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  session_id text NOT NULL,
  binding_id uuid,
  user_id uuid REFERENCES selfhost_users(id) ON DELETE RESTRICT,
  pending_envelope text,
  redactions_envelope text,
  source_version text,
  active_job_id uuid,
  active_job_lease_until timestamptz,
  next_due_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, session_id),
  FOREIGN KEY (workspace_id, organization_id)
    REFERENCES selfhost_workspaces(id, organization_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS selfhost_factory_history_syncs_due
  ON selfhost_factory_history_syncs (next_due_at)
  WHERE active_job_id IS NULL;
