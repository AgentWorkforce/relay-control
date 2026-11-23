-- Addressed relay channel posts as relay.channel_message events
-- (SELFHOST_GROK_ROUTINES_CLOUD_COPY; docs/grok-bot.md, "Channel posts").
--
-- Events belong to the OAuth grant rather than to a routine: every hosted
-- participant connection on the MCP endpoint reads get_event and
-- get_recent_events, routine or not. Revoking or deleting the grant still
-- deletes its events; disconnecting a routine deletes them explicitly.
ALTER TABLE grok_bot_events
  DROP CONSTRAINT grok_bot_events_grant_id_fkey,
  ADD CONSTRAINT grok_bot_events_grant_id_fkey FOREIGN KEY (grant_id) REFERENCES mcp_oauth_grants(id) ON DELETE CASCADE;

-- The channel wake guards are counted in the database, so these stay in clear
-- beside the encrypted payload: Relaycast ids and fixed values only, never
-- message text. wake_reserved_at marks an event that spent a wake-up (a webhook
-- routine's pending wake, or a polling schedule's pickup); only those count
-- toward the caps (20 per channel, 6 per thread, 2 agent posts per thread, per
-- 10 minutes).
ALTER TABLE grok_bot_events
  ADD COLUMN channel_id text,
  ADD COLUMN reply_thread_id text,
  ADD COLUMN sender_kind text CHECK (sender_kind IS NULL OR sender_kind IN ('human', 'agent')),
  ADD COLUMN addressed text CHECK (addressed IS NULL OR addressed IN ('mention', 'bot-thread', 'post')),
  ADD COLUMN wake_reserved_at timestamptz,
  ADD CONSTRAINT grok_bot_events_channel_fields CHECK (name = 'relay.channel_message'
    OR (channel_id IS NULL AND reply_thread_id IS NULL AND sender_kind IS NULL AND addressed IS NULL AND wake_reserved_at IS NULL));

CREATE INDEX grok_bot_events_channel_wakes ON grok_bot_events(channel_id, wake_reserved_at) WHERE wake_reserved_at IS NOT NULL;
CREATE INDEX grok_bot_events_reply_thread ON grok_bot_events(grant_id, reply_thread_id) WHERE reply_thread_id IS NOT NULL;
