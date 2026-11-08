-- Operator capture policy (docs/capture-policy.md): one row per organization,
-- served to every member through GET /api/v1/workspaces/{ws}/access/me.
-- An absent row means "unset" ({version:1, revision:1, settings:{}}).
-- `revision` is monotonic per organization: clearing the policy keeps the row
-- with empty settings and a higher revision instead of deleting it.

CREATE TABLE IF NOT EXISTS selfhost_capture_policies (
  organization_id uuid PRIMARY KEY REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  revision integer NOT NULL DEFAULT 1 CHECK (revision >= 1),
  settings jsonb NOT NULL DEFAULT '{}'::jsonb,
  set_by_user_id uuid NULL REFERENCES selfhost_users(id) ON DELETE SET NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
