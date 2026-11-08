-- Relay Chief registry: one chief per project, pre-provisioned slots bound by an
-- operator. Control only ever sees an opaque slot ID; the mapping to a host
-- lives with the infrastructure.

CREATE TABLE selfhost_chiefs (
  id text PRIMARY KEY,
  -- RESTRICT: removing a tenant must not silently release a slot's binding.
  organization_id uuid NOT NULL REFERENCES selfhost_organizations(id) ON DELETE RESTRICT,
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE RESTRICT,
  name text NOT NULL,
  repository text NOT NULL,
  request_id uuid NOT NULL,
  digest text NOT NULL,
  config jsonb NOT NULL,
  placement text NOT NULL,
  state text NOT NULL DEFAULT 'awaiting_capacity'
    CHECK (state IN ('awaiting_capacity', 'awaiting_binding', 'ready')),
  readiness jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  ready_at timestamptz,
  -- Idempotency is bound to the authenticated tenant plus the request ID.
  UNIQUE (organization_id, workspace_id, request_id)
);

CREATE INDEX selfhost_chiefs_workspace_idx ON selfhost_chiefs (organization_id, workspace_id, created_at DESC);
CREATE INDEX selfhost_chiefs_capacity_idx ON selfhost_chiefs (created_at) WHERE state = 'awaiting_capacity';

CREATE TABLE selfhost_chief_repositories (
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE RESTRICT,
  repository_id text NOT NULL,
  repository text NOT NULL,
  chief_id text NOT NULL REFERENCES selfhost_chiefs(id) ON DELETE CASCADE,
  UNIQUE (workspace_id, repository_id),
  UNIQUE (workspace_id, repository)
);

CREATE TABLE selfhost_chief_slots (
  slot_id text PRIMARY KEY CHECK (slot_id ~ '^slot-[a-z0-9]{8,32}$'),
  state text NOT NULL DEFAULT 'free' CHECK (state IN ('free', 'assigned')),
  chief_id text UNIQUE REFERENCES selfhost_chiefs(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  assigned_at timestamptz,
  CONSTRAINT selfhost_chief_slot_assignment CHECK ((state = 'free') = (chief_id IS NULL))
);

-- A slot is single-use because its data volume keeps the previous chief's
-- ledger. Nothing may reassign or remove an assigned slot; a wipe-and-reuse path
-- has to be introduced deliberately, by changing this trigger.
CREATE FUNCTION selfhost_chief_slot_single_use() RETURNS trigger AS $$
BEGIN
  IF OLD.state = 'assigned' THEN
    RAISE EXCEPTION 'chief slot % is single-use', OLD.slot_id;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER selfhost_chief_slot_single_use
  BEFORE UPDATE OR DELETE ON selfhost_chief_slots
  FOR EACH ROW EXECUTE FUNCTION selfhost_chief_slot_single_use();

-- Scoped to one chief, unlike workspace API tokens. Stored only as a hash.
CREATE TABLE selfhost_chief_service_credentials (
  id uuid PRIMARY KEY,
  chief_id text NOT NULL REFERENCES selfhost_chiefs(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);

CREATE UNIQUE INDEX selfhost_chief_service_credentials_active_idx
  ON selfhost_chief_service_credentials (chief_id) WHERE revoked_at IS NULL;
