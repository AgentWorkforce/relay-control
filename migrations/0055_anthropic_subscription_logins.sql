-- Imported Cloud Claude Pro/Max logins use the same provider_oauth object
-- storage and run-reference path as Codex and Grok. Claude has no Control
-- device flow: the identity import writes its existing .credentials.json.
ALTER TABLE coding_agent_credentials
  DROP CONSTRAINT IF EXISTS selfhost_coding_agent_oauth_provider,
  DROP CONSTRAINT IF EXISTS coding_agent_oauth_provider,
  ADD CONSTRAINT coding_agent_oauth_provider
    CHECK (auth_type <> 'provider_oauth' OR model_provider IN ('anthropic', 'openai', 'xai'));
