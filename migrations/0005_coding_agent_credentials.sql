-- Coding agents (hosted: Settings > Connections > "Coding agents", backed by
-- provider_credentials). One row per stored model-provider credential in a
-- workspace. The secret is AES-256-GCM ciphertext from src/crypto.ts
-- encryptSecret with the SELFHOST_ENCRYPTION_KEY keyring; only a masked
-- preview and metadata are ever returned to a browser.
--
-- Two independent selections per (workspace, provider), as hosted:
--   is_active      "LLM call access": the credential delivered to flow runs
--                  for programmatic model calls.
--   harness_active "Sandbox access": the subscription login mounted for the
--                  coding-agent CLI (Claude setup token).
CREATE TABLE IF NOT EXISTS selfhost_coding_agent_credentials (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  created_by_user_id uuid REFERENCES selfhost_users(id) ON DELETE SET NULL,
  model_provider text NOT NULL,
  harness text NOT NULL,
  auth_type text NOT NULL,
  display_name text NOT NULL,
  label text,
  account_email text,
  secret_ciphertext text NOT NULL,
  secret_preview text NOT NULL,
  key_fingerprint text NOT NULL,
  is_active boolean NOT NULL DEFAULT false,
  harness_active boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'connected',
  last_error text,
  last_checked_at timestamptz,
  last_authenticated_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT selfhost_coding_agent_provider CHECK (
    model_provider IN ('anthropic', 'openai', 'openrouter', 'xai', 'google', 'daytona')
  ),
  CONSTRAINT selfhost_coding_agent_auth_type CHECK (auth_type IN ('byo_api_key', 'oauth_token')),
  CONSTRAINT selfhost_coding_agent_setup_token_provider CHECK (
    auth_type <> 'oauth_token' OR model_provider = 'anthropic'
  ),
  CONSTRAINT selfhost_coding_agent_harness_auth CHECK (
    NOT harness_active OR auth_type = 'oauth_token'
  ),
  CONSTRAINT selfhost_coding_agent_status CHECK (status IN ('connected', 'error')),
  CONSTRAINT selfhost_coding_agent_ciphertext CHECK (secret_ciphertext LIKE 'v2.%')
);

CREATE INDEX IF NOT EXISTS selfhost_coding_agent_workspace_idx
  ON selfhost_coding_agent_credentials (workspace_id, model_provider, updated_at DESC);

-- At most one LLM-call credential and one sandbox credential per provider.
CREATE UNIQUE INDEX IF NOT EXISTS selfhost_coding_agent_one_llm
  ON selfhost_coding_agent_credentials (workspace_id, model_provider)
  WHERE is_active;
CREATE UNIQUE INDEX IF NOT EXISTS selfhost_coding_agent_one_sandbox
  ON selfhost_coding_agent_credentials (workspace_id, model_provider)
  WHERE harness_active;

-- The same key stored twice under one label is one credential (hosted dedupe).
CREATE UNIQUE INDEX IF NOT EXISTS selfhost_coding_agent_fingerprint
  ON selfhost_coding_agent_credentials (workspace_id, model_provider, auth_type, key_fingerprint);
