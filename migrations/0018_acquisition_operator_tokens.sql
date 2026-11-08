-- Acquisition operator tokens: a workspace API token purpose that an operator
-- service presents to RelayHistory, verified through POST
-- /internal/v1/auth/introspect as a `service` principal. Each one carries the
-- single audience (normalized origin) it may be presented to and never an
-- agent name. Numbered 0018: 0014 is taken by selfhost/multi-tenant and
-- 0015-0017 are reserved by another lane.

ALTER TABLE selfhost_workspace_api_tokens
  DROP CONSTRAINT selfhost_api_token_purpose,
  DROP CONSTRAINT selfhost_api_token_agent_binding;

ALTER TABLE selfhost_workspace_api_tokens
  ADD CONSTRAINT selfhost_api_token_purpose
    CHECK (purpose IN ('agent-runtime', 'workflow', 'deployment', 'relayfile-agent', 'acquisition-operator')),
  ADD CONSTRAINT selfhost_api_token_agent_binding
    CHECK (
      (purpose = 'relayfile-agent' AND agent_name IS NOT NULL AND aud IS NOT NULL)
      OR (purpose = 'acquisition-operator' AND agent_name IS NULL AND aud IS NOT NULL)
      OR (purpose NOT IN ('relayfile-agent', 'acquisition-operator') AND agent_name IS NULL AND aud IS NULL)
    );
