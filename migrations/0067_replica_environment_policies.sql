-- Environment-level Replicas MCP (src/replicas/environments.ts). A Replicas
-- workspace authenticates to POST /api/v1/replicas/mcp with its
-- workspace_identity token; these tables decide whether that identity is
-- admitted and which tenant workspace and person it acts for.
--
-- Policies are discovered (disabled) when an owner/admin connects Replicas
-- and are only enabled by an explicit admin action. No token, email address
-- or provider key is stored here; creator_email_hint is a masked hint
-- (first character and domain) shown to admins.

CREATE TABLE IF NOT EXISTS replica_environment_policies (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  issuer text NOT NULL,
  provider_organization_id text NOT NULL,
  environment_id text NOT NULL,
  environment_name text NOT NULL DEFAULT '',
  enabled boolean NOT NULL DEFAULT false,
  registered_mcp_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, environment_id)
);

-- One tenant workspace per provider environment: a token can never be
-- admitted into two workspaces.
CREATE UNIQUE INDEX IF NOT EXISTS replica_environment_policies_enabled
  ON replica_environment_policies (issuer, provider_organization_id, environment_id) WHERE enabled;

-- Which provider creator acts as which person. A creator without a row (or a
-- token without a creator) is refused.
CREATE TABLE IF NOT EXISTS replica_environment_creators (
  policy_id uuid NOT NULL REFERENCES replica_environment_policies(id) ON DELETE CASCADE,
  creator_id text NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  creator_email_hint text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (policy_id, creator_id)
);

-- Unmapped creators seen on an enabled policy, so an admin can learn which
-- creator_id to map. Bounded to the 50 most recent per policy; mapping a
-- creator deletes its row.
CREATE TABLE IF NOT EXISTS replica_environment_creator_requests (
  policy_id uuid NOT NULL REFERENCES replica_environment_policies(id) ON DELETE CASCADE,
  creator_id text NOT NULL,
  creator_email_hint text,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  count integer NOT NULL DEFAULT 1,
  PRIMARY KEY (policy_id, creator_id)
);

-- The workspace-level grant "every environment of the connected
-- organization, including ones discovered later".
CREATE TABLE IF NOT EXISTS replica_environment_settings (
  workspace_id uuid PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
  all_environments boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- A released environment-identity binding: the same provider workspace is
-- refused until an admin revives it through the recover route.
CREATE TABLE IF NOT EXISTS replica_identity_tombstones (
  issuer text NOT NULL,
  provider_organization_id text NOT NULL,
  provider_workspace_id text NOT NULL,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  released_at timestamptz NOT NULL DEFAULT now(),
  reason text NOT NULL,
  PRIMARY KEY (issuer, provider_organization_id, provider_workspace_id)
);

-- Environment-identity bindings are keyed by the provider identity.
ALTER TABLE replica_spawns ADD COLUMN IF NOT EXISTS environment_id text;
ALTER TABLE replica_spawns ADD COLUMN IF NOT EXISTS provider_organization_id text;
ALTER TABLE replica_spawns ADD COLUMN IF NOT EXISTS issuer text;

CREATE UNIQUE INDEX IF NOT EXISTS replica_spawns_identity
  ON replica_spawns (issuer, provider_organization_id, replica_id)
  WHERE source = 'environment_identity' AND state <> 'gone';
