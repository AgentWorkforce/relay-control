-- admin lane: workspace environment variables (write-only secrets) and an
-- append-only admin audit trail. Values are AES-256-GCM ciphertext produced by
-- src/crypto.ts encryptSecret with the SELFHOST_ENCRYPTION_KEY keyring.
CREATE TABLE IF NOT EXISTS selfhost_workspace_env_vars (
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  name text NOT NULL,
  value_ciphertext text NOT NULL,
  masked_value text NOT NULL,
  value_bytes integer NOT NULL,
  created_by_user_id uuid REFERENCES selfhost_users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES selfhost_users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, name),
  CONSTRAINT selfhost_env_var_name CHECK (name ~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'),
  CONSTRAINT selfhost_env_var_ciphertext CHECK (value_ciphertext LIKE 'v2.%'),
  CONSTRAINT selfhost_env_var_bytes CHECK (value_bytes BETWEEN 1 AND 32768)
);

CREATE TABLE IF NOT EXISTS selfhost_admin_audit_events (
  id uuid PRIMARY KEY,
  organization_id uuid REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  workspace_id uuid REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  actor_kind text NOT NULL,
  actor_id text,
  action text NOT NULL,
  target text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT selfhost_admin_audit_actor_kind CHECK (actor_kind IN ('user', 'service', 'bootstrap'))
);

CREATE INDEX IF NOT EXISTS selfhost_admin_audit_workspace_idx
  ON selfhost_admin_audit_events (workspace_id, created_at DESC);
