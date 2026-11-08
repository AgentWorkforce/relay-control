-- admin lane: self-host provider connections (replaces hosted Nango).
-- Every secret column holds src/crypto.ts v2 ciphertext.

-- Bring-your-own OAuth app per provider, entered by a workspace admin.
CREATE TABLE IF NOT EXISTS selfhost_integration_oauth_apps (
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  provider text NOT NULL,
  client_id text NOT NULL,
  client_secret_ciphertext text NOT NULL,
  client_secret_masked text NOT NULL,
  scopes text[],
  created_by_user_id uuid REFERENCES selfhost_users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES selfhost_users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, provider),
  CONSTRAINT selfhost_oauth_app_secret_ciphertext CHECK (client_secret_ciphertext LIKE 'v2.%')
);

-- One default connection per (workspace, provider), as in hosted
-- workspace_integrations where name IS NULL.
CREATE TABLE IF NOT EXISTS selfhost_integration_connections (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  provider text NOT NULL,
  auth_mode text NOT NULL,
  status text NOT NULL,
  credentials_ciphertext text NOT NULL,
  token_type text,
  scopes text[],
  access_token_expires_at timestamptz,
  refresh_token_expires_at timestamptz,
  account_id text,
  account_label text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_refreshed_at timestamptz,
  last_error text,
  created_by_user_id uuid REFERENCES selfhost_users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES selfhost_users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, provider),
  CONSTRAINT selfhost_connection_auth_mode CHECK (auth_mode IN ('oauth2', 'api_key')),
  CONSTRAINT selfhost_connection_status CHECK (status IN ('ready', 'error')),
  CONSTRAINT selfhost_connection_ciphertext CHECK (credentials_ciphertext LIKE 'v2.%')
);

-- Single-use OAuth authorization-code state. Only the SHA-256 of the state
-- value is stored; the PKCE verifier is encrypted.
CREATE TABLE IF NOT EXISTS selfhost_integration_oauth_states (
  state_hash text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  provider text NOT NULL,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE CASCADE,
  code_verifier_ciphertext text,
  redirect_uri text NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS selfhost_integration_oauth_states_expiry_idx
  ON selfhost_integration_oauth_states (expires_at);
