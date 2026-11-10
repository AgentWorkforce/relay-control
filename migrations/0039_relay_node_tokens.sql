-- Relay node tokens: a workspace API token purpose that an agent-relay-node
-- host presents to this service's /relay-node/v1 broker instead of the
-- workspace's Relaycast key (docs/relay-node-credential.md). Each one is
-- bound to one node name, kept in agent_name, and never carries an aud.
-- Several live tokens may share a node name (rotation), so the relayfile-agent
-- partial unique index is left as it is. Constraint names lost their
-- selfhost_ prefix in 0033.

ALTER TABLE workspace_api_tokens
  DROP CONSTRAINT api_token_purpose,
  DROP CONSTRAINT api_token_agent_binding;

ALTER TABLE workspace_api_tokens
  ADD CONSTRAINT api_token_purpose
    CHECK (purpose IN ('agent-runtime', 'workflow', 'deployment', 'relayfile-agent', 'acquisition-operator', 'relay-node')),
  ADD CONSTRAINT api_token_agent_binding
    CHECK (
      (purpose = 'relayfile-agent' AND agent_name IS NOT NULL AND aud IS NOT NULL)
      OR (purpose = 'acquisition-operator' AND agent_name IS NULL AND aud IS NOT NULL)
      OR (purpose = 'relay-node' AND agent_name IS NOT NULL AND aud IS NULL)
      OR (purpose NOT IN ('relayfile-agent', 'acquisition-operator', 'relay-node') AND agent_name IS NULL AND aud IS NULL)
    );
