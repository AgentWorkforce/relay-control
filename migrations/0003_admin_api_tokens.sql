-- admin lane: workspace API tokens (hosted "deployment API tokens").
-- Only the SHA-256 of each token is stored; the token is shown once.
CREATE TABLE IF NOT EXISTS selfhost_workspace_api_tokens (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  label text NOT NULL,
  purpose text NOT NULL,
  scopes text[] NOT NULL,
  token_hash text NOT NULL UNIQUE,
  token_prefix text NOT NULL,
  created_by_user_id uuid REFERENCES selfhost_users(id) ON DELETE SET NULL,
  expires_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  revoked_by_user_id uuid REFERENCES selfhost_users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT selfhost_api_token_purpose
    CHECK (purpose IN ('agent-runtime', 'workflow', 'deployment')),
  CONSTRAINT selfhost_api_token_label CHECK (char_length(label) BETWEEN 1 AND 128)
);

CREATE INDEX IF NOT EXISTS selfhost_workspace_api_tokens_workspace_idx
  ON selfhost_workspace_api_tokens (workspace_id, created_at DESC);
