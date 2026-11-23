-- Owner-named trusted delegates (AgentWorkforce/relay docs/design/owner-trusted-delegates.md,
-- §16.3). A person names which of their agents may relay their approval, for
-- which action classes and targets, until when. Control attests one approval
-- in one message to one recipient with a signed (Ed25519) statement, and
-- consumes single-use approvals atomically at redeem.
--
-- Nothing here grants authority by default: delegation_policies has no row
-- for a workspace until an admin writes one, and a missing row means
-- delegation_enabled = false.

-- Workspace switch and limits. Admin-only writes (PUT .../delegates/policy).
CREATE TABLE IF NOT EXISTS delegation_policies (
  workspace_id uuid PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
  delegation_enabled boolean NOT NULL DEFAULT false,
  max_expiry_days integer NOT NULL DEFAULT 90,
  -- NULL: every class may be delegated. Otherwise the allowed subset.
  allowed_classes text[],
  -- Classes that need an owner-minted (tier O) approval, on top of the
  -- protocol defaults (secret_change, destructive, spend).
  require_tier_o text[] NOT NULL DEFAULT '{}',
  -- §5.4: how a PR's CODEOWNERS rules must match its changed paths.
  code_owner_match text NOT NULL DEFAULT 'any_path',
  updated_by uuid,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT delegation_policies_max_expiry CHECK (max_expiry_days BETWEEN 1 AND 90),
  CONSTRAINT delegation_policies_code_owner_match CHECK (code_owner_match IN ('any_path', 'all_paths'))
);

-- Org-wide delegation settings (§16.3 GET/PUT /api/v1/orgs/{org}/delegation-policy),
-- set by org owners and admins. They apply to every workspace in the org and
-- no workspace policy overrides them. No row means the defaults.
CREATE TABLE IF NOT EXISTS delegation_org_policies (
  organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  -- §15.9 (Khaliq): days audit quotes are kept before redaction to their hash.
  quote_retention_days integer NOT NULL DEFAULT 90,
  updated_by uuid,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT delegation_org_policies_quote_retention CHECK (quote_retention_days BETWEEN 1 AND 3650)
);

-- §5.4: owners of targets that are not repos (service:env, secret paths,
-- channels). Each pattern maps to a repo (whose CODEOWNERS applies) or to a
-- list of people. Admin-only (GET/PUT .../delegates/target-owners). A target
-- with no entry accepts only the recipient's own owner.
CREATE TABLE IF NOT EXISTS delegation_target_owners (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  position integer NOT NULL,
  pattern text NOT NULL,
  repo text,
  owner_ids uuid[],
  updated_by uuid,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, position),
  CONSTRAINT delegation_target_owners_kind CHECK (repo IS NOT NULL OR owner_ids IS NOT NULL)
);

-- One-time claim codes: the owner starts a claim, and an agent with no other
-- Control binding presents the code with its own Relaycast token within 10
-- minutes. Only the code's SHA-256 is stored.
CREATE TABLE IF NOT EXISTS delegation_claims (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  agent_id text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS delegation_claims_workspace_idx
  ON delegation_claims (workspace_id, user_id, created_at);

-- Agent ids bound to a person by a completed claim. The immutable Relaycast
-- agent id is the key; the name is the one Relaycast reported at claim time
-- and is re-checked against the live roster on every use.
CREATE TABLE IF NOT EXISTS delegation_agent_bindings (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  relaycast_workspace_id text NOT NULL,
  agent_id text NOT NULL,
  agent_name text NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  claim_id text NOT NULL REFERENCES delegation_claims(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (relaycast_workspace_id, agent_id)
);

CREATE INDEX IF NOT EXISTS delegation_agent_bindings_workspace_idx
  ON delegation_agent_bindings (workspace_id, user_id);

-- Grants: the owner's standing record. Revocation is a timestamp, never a
-- delete, so audit references stay resolvable.
CREATE TABLE IF NOT EXISTS delegation_grants (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL,
  owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  delegate_agent_id text NOT NULL,
  delegate_agent_name text NOT NULL,
  -- [{ "class": "merge", "targets": ["owner/*"] }, ...]
  scopes jsonb NOT NULL,
  require_tier_o text[] NOT NULL DEFAULT '{}',
  -- active, revoked or expired (a lapsed grant is marked expired when the
  -- pair gets a new grant; expiry is also checked at every use).
  status text NOT NULL DEFAULT 'active',
  expires_at timestamptz NOT NULL,
  created_auth_method text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  revoked_by uuid,
  revoked_reason text,
  CONSTRAINT delegation_grants_auth_method CHECK (created_auth_method IN ('session', 'desktop_bearer')),
  CONSTRAINT delegation_grants_status CHECK (status IN ('active', 'revoked', 'expired'))
);

-- One active grant per (owner, delegate); widening is a new grant after revoking.
CREATE UNIQUE INDEX IF NOT EXISTS delegation_grants_active_pair
  ON delegation_grants (workspace_id, owner_user_id, delegate_agent_id)
  WHERE status = 'active';

-- Approvals Control knows about: tier O approvals minted by the owner, and
-- tier D approvals recorded at their first attestation (approval_id derived
-- from the workspace and message id). Single-use consumption is the atomic
-- UPDATE ... WHERE consumed_at IS NULL in redeem.
CREATE TABLE IF NOT EXISTS delegation_approvals (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tier text NOT NULL,
  grant_id text REFERENCES delegation_grants(id) ON DELETE CASCADE,
  message_id text,
  actions jsonb NOT NULL,
  single_use boolean NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  consumed_by_agent_id text,
  consumed_action jsonb,
  invalidated_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT delegation_approvals_tier CHECK (tier IN ('D', 'O'))
);

CREATE INDEX IF NOT EXISTS delegation_approvals_grant_idx
  ON delegation_approvals (grant_id) WHERE grant_id IS NOT NULL;

-- Each issued attestation (jti). Redeem requires one for the same approval
-- and recipient, so an approval id seen by another agent cannot be redeemed.
CREATE TABLE IF NOT EXISTS delegation_attestations (
  jti text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  approval_id text NOT NULL REFERENCES delegation_approvals(id) ON DELETE CASCADE,
  grant_id text NOT NULL REFERENCES delegation_grants(id) ON DELETE CASCADE,
  message_id text NOT NULL,
  recipient_agent_id text NOT NULL,
  delegate_agent_id text NOT NULL,
  kid text NOT NULL,
  -- The recipient's accept mode and the standing found; redeem re-checks standing.
  accept text NOT NULL,
  standing text NOT NULL,
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS delegation_attestations_approval_idx
  ON delegation_attestations (approval_id, recipient_agent_id);

-- Append-only per-workspace delegation log (§8). Quote text is kept for the
-- org's quote_retention_days (default 90) and then redacted to its SHA-256
-- (quote_hash stays).
CREATE TABLE IF NOT EXISTS delegation_audit_events (
  id bigserial PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  event text NOT NULL,
  actor_user_id uuid,
  actor_agent_id text,
  auth_method text,
  owner_user_id uuid,
  grant_id text,
  approval_id text,
  message_id text,
  recipient_agent_id text,
  reason text,
  data jsonb NOT NULL DEFAULT '{}'::jsonb,
  quote text,
  quote_hash text,
  quote_redacted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS delegation_audit_events_workspace_idx
  ON delegation_audit_events (workspace_id, id);
CREATE INDEX IF NOT EXISTS delegation_audit_events_owner_idx
  ON delegation_audit_events (workspace_id, owner_user_id, id);
CREATE INDEX IF NOT EXISTS delegation_audit_events_quote_idx
  ON delegation_audit_events (created_at) WHERE quote IS NOT NULL;
