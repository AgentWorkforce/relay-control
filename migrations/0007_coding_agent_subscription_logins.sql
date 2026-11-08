-- Coding agents: subscription logins (hosted provider_oauth). Codex (OpenAI)
-- and Grok (xAI) device logins produce an auth file the CLI reads; it is kept
-- as an envelope-encrypted object (src/admin/credential-blobs.ts) in the
-- customer's object storage, or inline in selfhost_coding_agent_credential_blobs
-- when no bucket is configured. The credential row keeps only its location.
--
-- Additive except constraint swaps on a small table: no write hold needed.
-- Forward-only and idempotent.

ALTER TABLE selfhost_coding_agent_credentials
  ALTER COLUMN secret_ciphertext DROP NOT NULL,
  ADD COLUMN IF NOT EXISTS blob_backend text,
  ADD COLUMN IF NOT EXISTS blob_location text,
  ADD COLUMN IF NOT EXISTS blob_version integer,
  ADD COLUMN IF NOT EXISTS provider_account_id text,
  ADD COLUMN IF NOT EXISTS credential_expires_at timestamptz,
  ADD COLUMN IF NOT EXISTS refresh_attempts integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_refreshed_at timestamptz;

ALTER TABLE selfhost_coding_agent_credentials
  DROP CONSTRAINT IF EXISTS selfhost_coding_agent_auth_type,
  DROP CONSTRAINT IF EXISTS selfhost_coding_agent_harness_auth,
  DROP CONSTRAINT IF EXISTS selfhost_coding_agent_ciphertext,
  DROP CONSTRAINT IF EXISTS selfhost_coding_agent_status,
  DROP CONSTRAINT IF EXISTS selfhost_coding_agent_secret_storage,
  DROP CONSTRAINT IF EXISTS selfhost_coding_agent_oauth_provider;
ALTER TABLE selfhost_coding_agent_credentials
  ADD CONSTRAINT selfhost_coding_agent_auth_type
    CHECK (auth_type IN ('byo_api_key', 'oauth_token', 'provider_oauth')),
  ADD CONSTRAINT selfhost_coding_agent_harness_auth
    CHECK (NOT harness_active OR auth_type IN ('oauth_token', 'provider_oauth')),
  ADD CONSTRAINT selfhost_coding_agent_ciphertext
    CHECK (secret_ciphertext IS NULL OR secret_ciphertext LIKE 'v2.%'),
  ADD CONSTRAINT selfhost_coding_agent_status
    CHECK (status IN ('connected', 'error', 'refresh_failed')),
  -- API keys and setup tokens keep their ciphertext inline; subscription
  -- logins keep an object location instead.
  ADD CONSTRAINT selfhost_coding_agent_secret_storage CHECK (
    (auth_type = 'provider_oauth' AND secret_ciphertext IS NULL
       AND blob_backend IN ('postgres', 'gcs', 's3') AND blob_location IS NOT NULL AND blob_version IS NOT NULL)
    OR (auth_type <> 'provider_oauth' AND secret_ciphertext IS NOT NULL)
  ),
  ADD CONSTRAINT selfhost_coding_agent_oauth_provider
    CHECK (auth_type <> 'provider_oauth' OR model_provider IN ('openai', 'xai'));

-- One stored login per provider account (a second login of the same account
-- replaces the blob).
CREATE UNIQUE INDEX IF NOT EXISTS selfhost_coding_agent_oauth_account
  ON selfhost_coding_agent_credentials (workspace_id, model_provider, provider_account_id)
  WHERE auth_type = 'provider_oauth';

CREATE TABLE IF NOT EXISTS selfhost_coding_agent_credential_blobs (
  object_key text PRIMARY KEY,
  envelope text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT selfhost_coding_agent_blob_envelope CHECK (envelope LIKE '{%')
);

-- Hosted provider_oauth_device_sessions: one row per started device login.
CREATE TABLE IF NOT EXISTS selfhost_coding_agent_device_sessions (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE CASCADE,
  model_provider text NOT NULL,
  session_fingerprint text NOT NULL,
  encrypted_device_state text,
  poll_interval_seconds integer NOT NULL,
  next_poll_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  provider_credential_id uuid,
  expires_at timestamptz NOT NULL,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT selfhost_device_session_provider CHECK (model_provider IN ('openai', 'xai')),
  CONSTRAINT selfhost_device_session_status
    CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'expired')),
  CONSTRAINT selfhost_device_session_state CHECK (encrypted_device_state IS NULL OR encrypted_device_state LIKE 'v2.%')
);
CREATE INDEX IF NOT EXISTS selfhost_device_session_lookup
  ON selfhost_coding_agent_device_sessions (user_id, workspace_id, session_fingerprint);
CREATE INDEX IF NOT EXISTS selfhost_device_session_expiry
  ON selfhost_coding_agent_device_sessions (expires_at);

-- Short-lived, run-scoped references a flows worker presents (with its own
-- worker credential) to read and write back the run's CLI login files.
CREATE TABLE IF NOT EXISTS selfhost_cli_credential_refs (
  ref_hash text PRIMARY KEY,
  run_id uuid NOT NULL REFERENCES selfhost_workflow_runs(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  credential_ids uuid[] NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS selfhost_cli_credential_refs_run ON selfhost_cli_credential_refs (run_id);
