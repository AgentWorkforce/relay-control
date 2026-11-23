-- MCP OAuth undelivered refresh responses (docs/mcp-oauth.md).
-- current_pair_used_at: first authenticated use of the session's current access
-- token; NULL means the current pair has never been used. Rotation clears it.
ALTER TABLE mcp_oauth_sessions ADD COLUMN IF NOT EXISTS current_pair_used_at timestamptz;

-- successor_token_hash: the exact refresh-token hash the retiring rotation issued.
-- refresh_token_expires_at: the retired token's own expiry.
ALTER TABLE mcp_oauth_retired_refresh_tokens ADD COLUMN IF NOT EXISTS successor_token_hash text;
ALTER TABLE mcp_oauth_retired_refresh_tokens ADD COLUMN IF NOT EXISTS refresh_token_expires_at timestamptz;
-- reissued_at: the last re-issue from that token; it restarts the race grace window only.
ALTER TABLE mcp_oauth_retired_refresh_tokens ADD COLUMN IF NOT EXISTS reissued_at timestamptz;

-- Existing rows keep NULL. Retired rows without a successor are never re-issued,
-- so behaviour for pairs rotated before the upgrade is unchanged.
