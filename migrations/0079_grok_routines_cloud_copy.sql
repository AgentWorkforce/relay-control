-- Grok Bot routines, Cloud copy (docs/specs/grok-bot-dynamic-prompt.md, Phase 1).
-- Only used while SELFHOST_GROK_ROUTINES_CLOUD_COPY is on; existing rows keep
-- the #136 behaviour (webhook, no stored settings).

-- A polling routine has no webhook credential; a webhook connection exists
-- before its credential is saved on the setup page.
ALTER TABLE grok_bot_routines
  ALTER COLUMN credentials_ciphertext DROP NOT NULL,
  ADD COLUMN delivery_mode text NOT NULL DEFAULT 'webhook' CHECK (delivery_mode IN ('webhook', 'polling')),
  ADD COLUMN reply_mode text NOT NULL DEFAULT 'notes-only' CHECK (reply_mode IN ('notes-only', 'acknowledge', 'answer')),
  ADD COLUMN from_filter text CHECK (from_filter IS NULL OR length(from_filter) BETWEEN 1 AND 512),
  ADD COLUMN polling_since timestamptz,
  -- sha256 of the routine URL, so one Grok routine is saved under at most one grant.
  ADD COLUMN routine_url_hash text;
CREATE UNIQUE INDEX grok_bot_routines_routine_url ON grok_bot_routines(routine_url_hash) WHERE routine_url_hash IS NOT NULL;

-- Cloud's copied prompt reads a durable event log (get_event, get_recent_events)
-- and never acknowledges Relaycast deliveries itself. The worker ingests each
-- delivery here (message text encrypted with the Control keyring), then
-- acknowledges it. Rows are bound to the exact grant and removed with it.
CREATE TABLE grok_bot_events (
  grant_id uuid NOT NULL REFERENCES mcp_oauth_grants(id) ON DELETE CASCADE,
  event_id text NOT NULL CHECK (event_id ~ '^evt_[a-f0-9]{32}$'),
  seq bigint GENERATED ALWAYS AS IDENTITY,
  name text NOT NULL CHECK (name IN ('relay.message', 'relay.channel_message')),
  sender text,
  occurred_at timestamptz NOT NULL,
  trusted_reason text CHECK (trusted_reason IS NULL OR trusted_reason IN ('your agent')),
  payload_ciphertext text NOT NULL,
  notified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (grant_id, event_id)
);
CREATE UNIQUE INDEX grok_bot_events_seq ON grok_bot_events(grant_id, seq);
CREATE INDEX grok_bot_events_created ON grok_bot_events(created_at);
