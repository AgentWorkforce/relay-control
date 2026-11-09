-- Per-run, path-scoped Relayfile credentials for Flows workers
-- (docs/flows-relayfile-credential.md). The Flows credential broker mints an
-- opaque `sh_fr_` bearer for one run; Relayfile verifies it through
-- POST /internal/v1/auth/introspect. Only the sha256 of the token is stored,
-- with its 10-char prefix for support. run_id has no foreign key: the run may
-- live in relayfile-control's Flows store, not here. At most one credential
-- per run is active; issuing again revokes the earlier one. Rows are kept
-- after revocation and expiry for audit.
CREATE TABLE IF NOT EXISTS flow_run_relayfile_credentials (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  run_id uuid NOT NULL,
  token_hash text NOT NULL UNIQUE,
  token_prefix text NOT NULL,
  aud text NOT NULL,
  mount_paths text[] NOT NULL,
  scopes text[] NOT NULL,
  read_only boolean NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS flow_run_relayfile_credentials_run_idx
  ON flow_run_relayfile_credentials (run_id);

CREATE UNIQUE INDEX IF NOT EXISTS flow_run_relayfile_credentials_active_run_unique
  ON flow_run_relayfile_credentials (run_id) WHERE revoked_at IS NULL;
