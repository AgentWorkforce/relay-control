-- Preserve Cloud relay_managed coding-agent rows during identity import.
-- These rows are metadata-only: Cloud mints a provider/run-scoped house-proxy
-- surrogate at launch, and that issuer is not part of relay-control. Control
-- must therefore neither require nor accept imported secret/blob material.
-- There is nothing to refresh or rotate until a gateway issuer is added.

ALTER TABLE coding_agent_credentials
  ALTER COLUMN secret_preview DROP NOT NULL,
  ALTER COLUMN key_fingerprint DROP NOT NULL,
  DROP CONSTRAINT IF EXISTS selfhost_coding_agent_auth_type,
  DROP CONSTRAINT IF EXISTS coding_agent_auth_type,
  DROP CONSTRAINT IF EXISTS selfhost_coding_agent_secret_storage,
  DROP CONSTRAINT IF EXISTS coding_agent_secret_storage;

ALTER TABLE coding_agent_credentials
  ADD CONSTRAINT coding_agent_auth_type
    CHECK (auth_type IN ('byo_api_key', 'oauth_token', 'provider_oauth', 'relay_managed')),
  ADD CONSTRAINT coding_agent_secret_storage CHECK (
    (auth_type = 'provider_oauth' AND secret_ciphertext IS NULL
       AND blob_backend IN ('postgres', 'gcs', 's3') AND blob_location IS NOT NULL AND blob_version IS NOT NULL)
    OR (auth_type = 'relay_managed' AND secret_ciphertext IS NULL
       AND secret_preview IS NULL AND key_fingerprint IS NULL
       AND blob_backend IS NULL AND blob_location IS NULL AND blob_version IS NULL
       AND provider_account_id IS NULL AND credential_expires_at IS NULL
       AND refresh_attempts = 0 AND last_refreshed_at IS NULL)
    OR (auth_type IN ('byo_api_key', 'oauth_token') AND secret_ciphertext IS NOT NULL)
  );
