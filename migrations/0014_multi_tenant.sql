-- Multi-tenant relaycontrol (design G). Single-organisation self-host becomes
-- a request-time configuration gate (SELFHOST_TENANCY=single, the default)
-- instead of a schema constraint, so one installation can serve many
-- organisations when SELFHOST_TENANCY=multi.
--
-- 0002 stays as history: fresh installs still run it and this migration then
-- undoes its singleton constraints. The org-generic FK it added
-- (selfhost_device_approved_membership) is kept.
--
-- Reversible only while exactly one organisation exists (DG-005); the
-- reverse SQL is in docs/identity.md. Nothing here deletes data.

DROP INDEX IF EXISTS selfhost_single_organization_idx;
DROP INDEX IF EXISTS selfhost_organizations_singleton_idx;
ALTER TABLE selfhost_organizations
  DROP CONSTRAINT IF EXISTS selfhost_organizations_single_slot;
ALTER TABLE selfhost_organizations
  DROP COLUMN IF EXISTS installation_slot;

-- Remembered selection (hosted Cloud's users.last_*): where a sign-in or the
-- desktop picker lands when the person belongs to several organisations.
ALTER TABLE selfhost_users
  ADD COLUMN IF NOT EXISTS last_organization_id uuid
    REFERENCES selfhost_organizations(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS last_workspace_id uuid
    REFERENCES selfhost_workspaces(id) ON DELETE SET NULL;

-- Operator-assigned auto-join email domains (DG-002). The domain is the
-- primary key, so a domain maps to at most one organisation by
-- construction. Only the bootstrap bearer assigns or removes rows
-- (PUT/DELETE /api/v1/organizations/{id}/domains/{domain}); in single mode
-- SELFHOST_AUTO_JOIN_DOMAINS, when set, replaces the bootstrap
-- organisation's rows on every bootstrap pass. Stored lowercase IDNA-ascii.
CREATE TABLE IF NOT EXISTS selfhost_organization_domains (
  domain text PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT selfhost_organization_domain_normalized CHECK (domain = lower(domain) AND domain <> '')
);
CREATE INDEX IF NOT EXISTS selfhost_organization_domains_org_idx
  ON selfhost_organization_domains (organization_id);

-- Runtime kill switches for multi mode. NULL follows the environment
-- (SELFHOST_PERSONAL_ORG_ON_SIGNIN, SELFHOST_SELF_SERVE_ORGANIZATIONS).
ALTER TABLE selfhost_installation_bootstrap
  ADD COLUMN IF NOT EXISTS personal_org_signup_enabled boolean,
  ADD COLUMN IF NOT EXISTS self_serve_organizations_enabled boolean;

-- Telemetry scoping. An issue report filed through
-- /api/v1/organizations/{id}/telemetry/issues remembers that organisation so,
-- with SELFHOST_TENANCY=multi, its admins see and export only their own
-- reports; digests, error bursts and service-filed reports stay
-- installation-wide (NULL) and are visible to the bootstrap bearer only.
ALTER TABLE selfhost_telemetry_outbox
  ADD COLUMN IF NOT EXISTS organization_id uuid
    REFERENCES selfhost_organizations(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS selfhost_telemetry_outbox_organization_idx
  ON selfhost_telemetry_outbox (organization_id, created_at)
  WHERE organization_id IS NOT NULL;
