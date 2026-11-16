-- Staff read grants (docs/staff-read-grants.md): an owner of the operator
-- organization mints an audited, time-boxed, read-only credential `sh_sr_`
-- pinned to one customer workspace, without becoming a member of it. The
-- credential is honoured only by the shared-sessions MCP facade (the seven
-- shared-session read tools and describe_capabilities) and by token
-- introspection. It is stored only as a sha256 hash, is never refreshed and
-- has no token_sessions row: token_sessions requires a membership, and a
-- grant must never authenticate through one.
--
-- The staff rule (owner of the operator organization, primary email on one
-- of its assigned domains when it has any) is re-read on every use, so it is
-- not stored here. staff_organization_id records the operator organization
-- at mint. revoked_by is the revoking person, kept as a plain id so the row
-- outlives that person. Rows imported from another edition are history only
-- and arrive revoked.
CREATE TABLE IF NOT EXISTS staff_read_grants (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  staff_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  staff_organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  reason text NOT NULL CONSTRAINT staff_read_grant_reason CHECK (length(btrim(reason)) > 0 AND length(reason) <= 500),
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  revoked_by uuid,
  last_used_at timestamptz,
  CONSTRAINT staff_read_grant_workspace FOREIGN KEY (workspace_id, organization_id)
    REFERENCES workspaces(id, organization_id) ON DELETE CASCADE,
  CONSTRAINT staff_read_grant_lifetime CHECK (expires_at > created_at AND expires_at <= created_at + interval '90 days')
);

CREATE INDEX IF NOT EXISTS staff_read_grants_workspace_created
  ON staff_read_grants (workspace_id, created_at);
