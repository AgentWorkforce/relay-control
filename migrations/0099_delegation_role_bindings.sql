-- Delegation role bindings, the self-hosted twin of Cloud's
-- 0455_delegation_role_bindings (cloud#6665). A trust rule becomes a binding:
-- - a principal: `relay_agents`, `connector_kind`, a custom group, or one agent;
-- - a role: `trusted`, `standard`, `read_only`, `custom` or `excluded`;
-- - an optional repo scope and expiry.
-- An owner can hold several bindings.
--
-- Additive (expand). Every new column is nullable or defaulted, so an existing
-- row reads as a legacy rule: `principal_kind` 'all_agents' with a null `role`
-- means every class and spawn coverage, exactly as before. The previous build
-- ignores these columns and the two new tables. The one-live-rule-per-owner
-- index is replaced by one live binding per (owner, principal). That is a
-- superset of the old guarantee for legacy rows, which all have principal
-- ('all_agents', NULL), so the previous build's concurrent-PUT race is still
-- decided by the new index.
--
-- No data changes here. Existing live rules become Trusted only through the
-- role-seed operator endpoint, which defaults to a dry run.
ALTER TABLE delegation_trust_rules ADD COLUMN IF NOT EXISTS principal_kind text NOT NULL DEFAULT 'all_agents';
ALTER TABLE delegation_trust_rules ADD COLUMN IF NOT EXISTS principal_ref text;
ALTER TABLE delegation_trust_rules ADD COLUMN IF NOT EXISTS role text;
ALTER TABLE delegation_trust_rules ADD COLUMN IF NOT EXISTS classes text[];
ALTER TABLE delegation_trust_rules ADD COLUMN IF NOT EXISTS pr_ops_limit text[];
ALTER TABLE delegation_trust_rules ADD COLUMN IF NOT EXISTS required_conditions jsonb;
ALTER TABLE delegation_trust_rules ADD COLUMN IF NOT EXISTS targets text[];
ALTER TABLE delegation_trust_rules ADD COLUMN IF NOT EXISTS expires_at timestamptz;

CREATE UNIQUE INDEX IF NOT EXISTS delegation_trust_rules_live_principal
  ON delegation_trust_rules (workspace_id, owner_user_id, principal_kind, coalesce(principal_ref, ''))
  WHERE revoked_at IS NULL;
DROP INDEX IF EXISTS delegation_trust_rules_live_owner;

-- An owner's named group of agents. The list only filters: every member must
-- still prove out as the owner's through the ownership chain at each use.
CREATE TABLE IF NOT EXISTS delegation_groups (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS delegation_groups_owner
  ON delegation_groups (workspace_id, owner_user_id) WHERE revoked_at IS NULL;

-- A member by immutable agent id. A removed member keeps its row (removed_at), for audit.
CREATE TABLE IF NOT EXISTS delegation_group_members (
  group_id text NOT NULL REFERENCES delegation_groups(id) ON DELETE CASCADE,
  agent_id text NOT NULL,
  added_at timestamptz NOT NULL DEFAULT now(),
  removed_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS delegation_group_members_live
  ON delegation_group_members (group_id, agent_id) WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS delegation_group_members_agent
  ON delegation_group_members (agent_id) WHERE removed_at IS NULL;
