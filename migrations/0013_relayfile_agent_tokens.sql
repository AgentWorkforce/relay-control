-- Relayfile agent tokens: a workspace API token purpose that relayfile
-- verifies through POST /internal/v1/auth/introspect. Each one names the
-- agent it speaks for and the single audience (relayfile origin, normalized)
-- it may be presented to. Other purposes carry neither.

ALTER TABLE selfhost_workspace_api_tokens
  ADD COLUMN agent_name text,
  ADD COLUMN aud text;

ALTER TABLE selfhost_workspace_api_tokens
  DROP CONSTRAINT selfhost_api_token_purpose;

ALTER TABLE selfhost_workspace_api_tokens
  ADD CONSTRAINT selfhost_api_token_purpose
    CHECK (purpose IN ('agent-runtime', 'workflow', 'deployment', 'relayfile-agent')),
  ADD CONSTRAINT selfhost_api_token_agent_binding
    CHECK (
      (purpose = 'relayfile-agent' AND agent_name IS NOT NULL AND aud IS NOT NULL)
      OR (purpose <> 'relayfile-agent' AND agent_name IS NULL AND aud IS NULL)
    );

-- One live relayfile agent token per agent name in a workspace.
CREATE UNIQUE INDEX IF NOT EXISTS selfhost_workspace_api_tokens_agent_name
  ON selfhost_workspace_api_tokens (workspace_id, agent_name)
  WHERE purpose = 'relayfile-agent' AND revoked_at IS NULL;
