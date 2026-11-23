-- Grok Bot routines, Cloud copy (docs/specs/grok-bot-dynamic-prompt.md, Phase 1).
-- Existing rows keep the inbox-batch behaviour (cloud_copy false) whatever
-- SELFHOST_GROK_ROUTINES_CLOUD_COPY says; a row becomes a Cloud-copy row only
-- when it is saved, or connected for polling, with the flag on.

-- A polling routine has no webhook credential.
ALTER TABLE grok_bot_routines
  ALTER COLUMN credentials_ciphertext DROP NOT NULL,
  ADD COLUMN cloud_copy boolean NOT NULL DEFAULT false,
  ADD COLUMN delivery_mode text NOT NULL DEFAULT 'webhook' CHECK (delivery_mode IN ('webhook', 'polling')),
  ADD COLUMN reply_mode text NOT NULL DEFAULT 'notes-only' CHECK (reply_mode IN ('notes-only', 'acknowledge', 'answer')),
  ADD COLUMN from_filter text CHECK (from_filter IS NULL OR length(from_filter) BETWEEN 1 AND 512),
  ADD COLUMN polling_since timestamptz,
  -- sha256 of the routine URL, so one Grok routine is saved under at most one grant.
  ADD COLUMN routine_url_hash text,
  ADD CONSTRAINT grok_bot_routines_polling_copy CHECK (delivery_mode <> 'polling' OR cloud_copy),
  ADD CONSTRAINT grok_bot_routines_credentials CHECK (delivery_mode = 'polling' OR credentials_ciphertext IS NOT NULL);
CREATE UNIQUE INDEX grok_bot_routines_routine_url ON grok_bot_routines(routine_url_hash) WHERE routine_url_hash IS NOT NULL;

-- Cloud's copied prompt reads a durable event log (get_event, get_recent_events)
-- and never acknowledges Relaycast deliveries itself. The worker ingests each
-- delivery here (message text encrypted with the Control keyring), then
-- acknowledges it. Events belong to the routine row and go with it; the worker
-- also deletes any older than seven days. grant_seq is the grant's own cursor.
CREATE TABLE grok_bot_events (
  grant_id uuid NOT NULL REFERENCES grok_bot_routines(grant_id) ON DELETE CASCADE,
  event_id text NOT NULL CHECK (event_id ~ '^evt_[a-f0-9]{32}$'),
  grant_seq bigint NOT NULL CHECK (grant_seq >= 1),
  name text NOT NULL CHECK (name IN ('relay.message', 'relay.channel_message')),
  sender text,
  occurred_at timestamptz NOT NULL,
  trusted_reason text CHECK (trusted_reason IS NULL OR trusted_reason IN ('your agent')),
  payload_ciphertext text NOT NULL,
  notified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (grant_id, event_id),
  UNIQUE (grant_id, grant_seq)
);
CREATE INDEX grok_bot_events_created ON grok_bot_events(created_at);
