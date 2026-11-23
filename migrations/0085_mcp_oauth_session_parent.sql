-- MCP OAuth stable refresh for Google Connected Apps clients (docs/mcp-oauth.md).
-- parent_session_id: the root session (issued by an authorization code) of a
-- refreshed access session. The refresh token stays on the root; each refresh
-- adds one child row whose own refresh token is never returned. A code replay
-- of a continued grant revokes the root and its children, and continuation
-- detection counts root sessions only. NULL for every root session.
ALTER TABLE mcp_oauth_sessions ADD COLUMN IF NOT EXISTS parent_session_id uuid
  REFERENCES mcp_oauth_sessions(id) ON DELETE CASCADE;
-- Child rows only: the revoke and prune lookups never search for NULL.
CREATE INDEX IF NOT EXISTS mcp_oauth_sessions_parent_idx ON mcp_oauth_sessions (parent_session_id)
  WHERE parent_session_id IS NOT NULL;

-- Existing rows keep NULL: they are all root sessions.
