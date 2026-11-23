-- Per-connection event settings (SELFHOST_GROK_ROUTINES_CLOUD_COPY; docs/grok-bot.md,
-- "Workspace members' agents in channels"). Only the keys self-host honours.
--
-- trust_workspace_members_in_channels: Cloud's trustWorkspaceMembersInChannels.
-- NULL (or no row) is unset and reads as on. It is the person's choice only:
-- the trust itself is computed per event when get_event reads it, never
-- stored, and SELFHOST_TRUST_WORKSPACE_MEMBERS_IN_CHANNELS=off turns it off for
-- the whole installation whatever is saved here.
--
-- last_inbox_read_at: when a manual get_recent_events last refreshed this
-- connection's hosted inbox; at most one refresh per ten seconds.
CREATE TABLE mcp_grant_event_settings (
  grant_id uuid PRIMARY KEY REFERENCES mcp_oauth_grants(id) ON DELETE CASCADE,
  trust_workspace_members_in_channels boolean,
  last_inbox_read_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);
