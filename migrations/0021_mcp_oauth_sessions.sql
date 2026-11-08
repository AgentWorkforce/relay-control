-- OAuth bearers are a separate credential class. Never put these hashes in
-- selfhost_token_sessions: that table authenticates general control-plane users.
ALTER TABLE selfhost_mcp_oauth_grants
  ADD CONSTRAINT selfhost_mcp_oauth_grant_family_pair UNIQUE (id, token_family_id);

CREATE TABLE selfhost_mcp_oauth_sessions (
  id uuid PRIMARY KEY,
  grant_id uuid NOT NULL,
  token_family_id uuid NOT NULL,
  user_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  scopes text[] NOT NULL CHECK (cardinality(scopes) > 0 AND scopes <@ ARRAY['relay:mcp','relay:events','relay:agents','openid']::text[]),
  access_token_hash text NOT NULL UNIQUE CHECK (access_token_hash ~ '^[0-9a-f]{64}$'),
  refresh_token_hash text NOT NULL UNIQUE CHECK (refresh_token_hash ~ '^[0-9a-f]{64}$'),
  access_token_expires_at timestamptz NOT NULL,
  refresh_token_expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  revoked_reason text,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  last_refreshed_at timestamptz,
  FOREIGN KEY (grant_id, organization_id, workspace_id, user_id)
    REFERENCES selfhost_mcp_oauth_grants(id, organization_id, workspace_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (grant_id, token_family_id)
    REFERENCES selfhost_mcp_oauth_grants(id, token_family_id) ON DELETE CASCADE
);
CREATE INDEX selfhost_mcp_oauth_sessions_family_idx ON selfhost_mcp_oauth_sessions (token_family_id);

-- Keep revoked session receipts across membership departure; identity must call
-- the organization-wide revocation hook in its deletion transaction before mount.
ALTER TABLE selfhost_mcp_oauth_sessions
  ADD CONSTRAINT selfhost_mcp_oauth_session_receipt_owner UNIQUE (id, grant_id, organization_id, workspace_id, user_id);
ALTER TABLE selfhost_mcp_oauth_authorization_codes
  ADD COLUMN redirect_uri_required boolean NOT NULL DEFAULT true,
  ADD CONSTRAINT selfhost_mcp_oauth_code_receipt_has_grant CHECK (issued_session_id IS NULL OR grant_id IS NOT NULL),
  ADD CONSTRAINT selfhost_mcp_oauth_code_receipt_owner
    FOREIGN KEY (issued_session_id, grant_id, organization_id, workspace_id, user_id)
    REFERENCES selfhost_mcp_oauth_sessions(id, grant_id, organization_id, workspace_id, user_id);
