-- Set-once owner trust rules for owner-named trusted delegates (docs/owner-delegates.md,
-- "Trust rule"), the self-hosted twin of Cloud's 0453_delegation_trust_rules. One
-- live rule per owner per workspace trusts every agent the owner connected (a
-- completed, unreleased claim, or a live MCP OAuth grant of the owner pinned to
-- the agent's immutable id) and every agent those launch through Control, for
-- every class the workspace policy allows, with no expiry, until revoked. The
-- rule acts through system grants (delegation_grants.trust_rule_id), so attest,
-- redeem and gates still decide on grant rows.
--
-- Additive only: the previous build ignores the table and both columns, every
-- existing grant has trust_rule_id NULL, and the two constraints below admit
-- every row the previous build can write.
CREATE TABLE IF NOT EXISTS delegation_trust_rules (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- Classes that still need an owner-minted (tier O) approval under the rule,
  -- copied to its system grants. Empty by default: no Tier O beyond the
  -- protocol defaults and the workspace policy.
  require_tier_o text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  revoked_reason text,
  revoked_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL
);

-- One live rule per (workspace, owner): concurrent first PUTs converge on it.
CREATE UNIQUE INDEX IF NOT EXISTS delegation_trust_rules_live_owner
  ON delegation_trust_rules (workspace_id, owner_user_id) WHERE revoked_at IS NULL;

-- Set only on a system grant the owner's trust rule created; never on an owner-made grant.
ALTER TABLE delegation_grants ADD COLUMN IF NOT EXISTS trust_rule_id text
  REFERENCES delegation_trust_rules(id) ON DELETE CASCADE;
-- The ownership chain proven when the system grant was created, for audit.
ALTER TABLE delegation_grants ADD COLUMN IF NOT EXISTS trust_path jsonb;

CREATE INDEX IF NOT EXISTS delegation_grants_trust_rule_idx
  ON delegation_grants (trust_rule_id) WHERE trust_rule_id IS NOT NULL;

-- A system grant is created by Control itself (auth method `system`); every
-- owner-made grant keeps a person's session or Desktop bearer.
ALTER TABLE delegation_grants DROP CONSTRAINT IF EXISTS delegation_grants_auth_method;
ALTER TABLE delegation_grants ADD CONSTRAINT delegation_grants_auth_method CHECK (
  created_auth_method IN ('session', 'desktop_bearer')
  OR (trust_rule_id IS NOT NULL AND created_auth_method = 'system'));

-- Only a rule-backed grant outlives the 90-day cap (GRANT_MAX_DAYS plus the
-- 60 s slack grantFitsPolicy allows); the exemption is keyed on the rule link,
-- never on the date. Every stored grant already fits: grant routes cap expiry
-- at 90 days. Added NOT VALID, then validated, so the check takes only a brief lock.
DO $$ BEGIN
  ALTER TABLE delegation_grants ADD CONSTRAINT delegation_grants_expiry_cap
    CHECK (trust_rule_id IS NOT NULL OR expires_at <= created_at + interval '90 days 60 seconds') NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
ALTER TABLE delegation_grants VALIDATE CONSTRAINT delegation_grants_expiry_cap;
