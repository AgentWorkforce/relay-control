-- Coding agents: Daytona is no longer a self-hosted provider. Self-hosted runs
-- do not execute in Daytona sandboxes, and DAYTONA_* stays a refused
-- workspace-variable family (src/admin/env-policy.ts). Existing Daytona rows
-- are DELETED, not ignored: they could never be selected or delivered again,
-- and keeping their ciphertext would only retain a customer secret for no use.
-- The delete is a no-op when none exist. Forward-only and idempotent.
DELETE FROM selfhost_coding_agent_credentials WHERE model_provider = 'daytona';

ALTER TABLE selfhost_coding_agent_credentials
  DROP CONSTRAINT IF EXISTS selfhost_coding_agent_provider;
ALTER TABLE selfhost_coding_agent_credentials
  ADD CONSTRAINT selfhost_coding_agent_provider CHECK (
    model_provider IN ('anthropic', 'openai', 'openrouter', 'xai', 'google')
  );
