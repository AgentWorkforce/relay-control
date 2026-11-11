-- Shared-session read audit (docs/shared-session-read-audit.md): one row per
-- MCP shared-session read tool call (open_shared_sessions,
-- search_shared_sessions, get_shared_session, get_shared_session_context,
-- list_session_timings), successful or failed. Records who asked, from which
-- calling chat, what they asked for and which sessions (with their recorded
-- owners) came back. Never transcript content.
--
-- Append-only: rows are never updated (a trigger refuses UPDATE). Rows are
-- kept until an operator deletes them; see the doc for purging.

CREATE TABLE IF NOT EXISTS shared_session_read_audit (
  id uuid PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  -- No foreign key: the record outlives a member's removal.
  caller_user_id text NOT NULL,
  identity_kind text NOT NULL,
  auth_mode text NOT NULL,
  desktop_provider text,
  oauth_client_id text,
  oauth_grant_id text,
  mcp_session_id text,
  native_session_id text,
  native_session_provider text,
  native_session_verified boolean NOT NULL DEFAULT false,
  tool_name text NOT NULL,
  outcome text NOT NULL,
  error_message text,
  query_text text,
  agent_filter text,
  requested_session_id text,
  requested_source text,
  filters jsonb NOT NULL DEFAULT '{}'::jsonb,
  result_count integer NOT NULL DEFAULT 0,
  result_sessions jsonb NOT NULL DEFAULT '[]'::jsonb,
  result_sessions_truncated boolean NOT NULL DEFAULT false,
  correlation_id text,
  duration_ms integer NOT NULL DEFAULT 0,
  CONSTRAINT shared_session_read_audit_identity_kind CHECK (identity_kind IN ('desktop', 'hosted', 'oauth')),
  CONSTRAINT shared_session_read_audit_outcome CHECK (outcome IN ('ok', 'error')),
  CONSTRAINT shared_session_read_audit_query_length CHECK (query_text IS NULL OR length(query_text) <= 500),
  CONSTRAINT shared_session_read_audit_result_count CHECK (result_count >= 0)
);

CREATE INDEX IF NOT EXISTS shared_session_read_audit_workspace_time_idx
  ON shared_session_read_audit (workspace_id, occurred_at, id);

CREATE OR REPLACE FUNCTION shared_session_read_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'shared_session_read_audit is append-only';
END;
$$;

DROP TRIGGER IF EXISTS shared_session_read_audit_no_update ON shared_session_read_audit;
CREATE TRIGGER shared_session_read_audit_no_update
  BEFORE UPDATE ON shared_session_read_audit
  FOR EACH ROW EXECUTE FUNCTION shared_session_read_audit_append_only();
