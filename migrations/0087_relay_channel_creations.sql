-- Relay channel creations by an MCP OAuth assistant connection (subscribe_relay_channel
-- create: true): at most 5 per agent per clock hour, as in Cloud. An assistant can be
-- talked into creating channels by the posts it reads, so its creations are limited.
-- One row per workspace, agent name and hour window; rows older than two hours are
-- removed when the same workspace creates again.
CREATE TABLE IF NOT EXISTS relay_channel_creations (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  agent_name text NOT NULL,
  window_start timestamptz NOT NULL,
  count integer NOT NULL DEFAULT 0,
  PRIMARY KEY (workspace_id, agent_name, window_start)
);
