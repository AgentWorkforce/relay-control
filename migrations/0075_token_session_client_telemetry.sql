-- Fleet rollout C1: what an Agent Relay Desktop reports about itself on the
-- GET /api/v1/workspaces/{id}/access/me read it already makes (sign-in,
-- workspace refresh and every 15 minutes). Recorded on the device-client
-- session row (device flow, Desktop browser sign-in and its exchange,
-- enrollment-key exchange); never on browser, OAuth, API-token or staff
-- read sessions. client_version and client_platform come from the
-- `AgentRelayDesktop/<version> (<platform>)` User-Agent,
-- policy_revision_applied from X-Agent-Relay-Policy-Revision, and
-- policy_seen_at is when the session last presented them (rewritten at most
-- every 10 minutes unless a value changed). All nullable: older clients send
-- neither header, and whether the applied revision matches the workspace
-- policy is computed by the fleet read model, not stored here.
ALTER TABLE token_sessions
  ADD COLUMN IF NOT EXISTS client_version text,
  ADD COLUMN IF NOT EXISTS client_platform text,
  ADD COLUMN IF NOT EXISTS policy_revision_applied integer,
  ADD COLUMN IF NOT EXISTS policy_seen_at timestamptz;
