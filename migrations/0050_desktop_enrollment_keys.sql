-- Desktop enrollment keys (docs/identity.md, "Desktop enrollment keys"): an
-- owner or admin mints a single-use `sh_ek_` key bound to one member; an
-- installer exchanges it once at POST /api/v1/auth/enrollment/token for an
-- ordinary device session. The key is never a bearer, so its scopes stay
-- empty and agent_name/aud stay NULL.
ALTER TABLE workspace_api_tokens DROP CONSTRAINT api_token_purpose, DROP CONSTRAINT api_token_agent_binding;
ALTER TABLE workspace_api_tokens ADD CONSTRAINT api_token_purpose CHECK (purpose IN ('agent-runtime','workflow','deployment','relayfile-agent','acquisition-operator','relay-node','desktop-enrollment')),
  ADD CONSTRAINT api_token_agent_binding CHECK (
    (purpose='relayfile-agent' AND agent_name IS NOT NULL AND aud IS NOT NULL)
    OR (purpose='acquisition-operator' AND agent_name IS NULL AND aud IS NOT NULL)
    OR (purpose='relay-node' AND agent_name IS NOT NULL AND aud IS NULL)
    OR (purpose NOT IN ('relayfile-agent','acquisition-operator','relay-node') AND agent_name IS NULL AND aud IS NULL));

-- user_id: the member the key signs in. ON DELETE CASCADE rather than SET
-- NULL, which api_token_enrollment_user would refuse for these rows.
-- exchanged_session_id: the session the single exchange produced.
ALTER TABLE workspace_api_tokens
  ADD COLUMN user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  ADD COLUMN mcp_consent text CONSTRAINT api_token_mcp_consent CHECK (mcp_consent IN ('admin')),
  ADD COLUMN exchanged_at timestamptz,
  ADD COLUMN exchanged_session_id uuid REFERENCES token_sessions(id) ON DELETE SET NULL,
  ADD COLUMN exchanged_host_name text,
  ADD CONSTRAINT api_token_enrollment_user CHECK (
    (purpose = 'desktop-enrollment' AND user_id IS NOT NULL)
    OR (purpose <> 'desktop-enrollment' AND user_id IS NULL AND mcp_consent IS NULL
        AND exchanged_at IS NULL AND exchanged_session_id IS NULL AND exchanged_host_name IS NULL));

CREATE INDEX workspace_api_tokens_enrollment_user
  ON workspace_api_tokens (user_id) WHERE purpose = 'desktop-enrollment';

-- The enrollment key a session was exchanged from. Refresh rotates the row
-- in place, so it stays set for the session's life; revoking the key
-- revokes the sessions it provisioned.
ALTER TABLE token_sessions
  ADD COLUMN provisioned_by_token_id uuid REFERENCES workspace_api_tokens(id) ON DELETE SET NULL;
CREATE INDEX token_sessions_provisioned_by_token
  ON token_sessions (provisioned_by_token_id) WHERE provisioned_by_token_id IS NOT NULL;
