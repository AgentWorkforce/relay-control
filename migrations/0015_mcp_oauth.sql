-- Cloud MCP OAuth issuer state. No endpoint, runtime flag or token authority
-- is enabled by this migration. OAuth-session discrimination is integrated
-- separately; issued_session_id is a receipt, not a credential or identity.
CREATE TABLE selfhost_mcp_oauth_clients (
  client_id text PRIMARY KEY,
  client_name text,
  redirect_uris text[] NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE selfhost_mcp_oauth_grants (
  id uuid PRIMARY KEY,
  client_id text NOT NULL REFERENCES selfhost_mcp_oauth_clients(client_id),
  client_name text,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL,
  agent_name text NOT NULL CHECK (length(agent_name) BETWEEN 1 AND 128),
  agent_remote_id text,
  scopes text[] NOT NULL CHECK (cardinality(scopes) > 0 AND scopes <@ ARRAY['relay:mcp','relay:events','relay:agents','openid']::text[]),
  resource text NOT NULL,
  setup_handoff_id text UNIQUE,
  token_family_id uuid NOT NULL UNIQUE,
  continued_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  revoked_reason text,
  UNIQUE (id, organization_id, workspace_id, user_id),
  FOREIGN KEY (workspace_id, organization_id) REFERENCES selfhost_workspaces(id, organization_id) ON DELETE CASCADE
);
CREATE INDEX selfhost_mcp_oauth_grants_owner_idx
  ON selfhost_mcp_oauth_grants (organization_id, workspace_id, user_id, created_at);

CREATE TABLE selfhost_mcp_oauth_authorization_codes (
  code_hash text PRIMARY KEY CHECK (code_hash ~ '^[0-9a-f]{64}$'),
  client_id text NOT NULL REFERENCES selfhost_mcp_oauth_clients(client_id),
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL,
  agent_name text NOT NULL CHECK (length(agent_name) BETWEEN 1 AND 128),
  redirect_uri text NOT NULL,
  code_challenge text NOT NULL,
  scopes text[] NOT NULL CHECK (cardinality(scopes) > 0 AND scopes <@ ARRAY['relay:mcp','relay:events','relay:agents','openid']::text[]),
  resource text NOT NULL,
  oidc_nonce text,
  grant_id uuid,
  issued_session_id uuid,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (workspace_id, organization_id) REFERENCES selfhost_workspaces(id, organization_id) ON DELETE CASCADE,
  FOREIGN KEY (grant_id, organization_id, workspace_id, user_id)
    REFERENCES selfhost_mcp_oauth_grants(id, organization_id, workspace_id, user_id)
);
CREATE INDEX selfhost_mcp_oauth_codes_expiry_idx ON selfhost_mcp_oauth_authorization_codes (expires_at);

CREATE TABLE selfhost_mcp_oauth_retired_refresh_tokens (
  token_hash text PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  grant_id uuid NOT NULL,
  user_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  retired_at timestamptz NOT NULL,
  FOREIGN KEY (grant_id, organization_id, workspace_id, user_id)
    REFERENCES selfhost_mcp_oauth_grants(id, organization_id, workspace_id, user_id) ON DELETE CASCADE
);
CREATE INDEX selfhost_mcp_oauth_retired_grant_idx
  ON selfhost_mcp_oauth_retired_refresh_tokens (grant_id, retired_at);
