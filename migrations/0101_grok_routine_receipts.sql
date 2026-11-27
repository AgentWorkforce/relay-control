-- Correlate a sender's Relaycast receipt with this service's Grok routine
-- wake, and remember replies sent through the Grok connection so a late wake
-- does not answer the same message twice. Existing encrypted events stay
-- readable; only events ingested after this migration gain the index.
ALTER TABLE grok_bot_events
  ADD COLUMN message_id text,
  ADD COLUMN wake_sent_at timestamptz,
  ADD COLUMN wake_attempts integer NOT NULL DEFAULT 0,
  ADD COLUMN answered_at timestamptz,
  ADD COLUMN reply_message_id text;

CREATE INDEX grok_bot_events_message
  ON grok_bot_events(grant_id, message_id)
  WHERE message_id IS NOT NULL;

-- A manual inbox check can reply before the routine scanner has inserted its
-- event. Keep that correlation separately, then copy it onto the event when
-- the delayed scan arrives.
CREATE TABLE grok_bot_answered_messages (
  grant_id uuid NOT NULL REFERENCES grok_bot_routines(grant_id) ON DELETE CASCADE,
  message_id text NOT NULL,
  answered_at timestamptz NOT NULL DEFAULT now(),
  reply_message_id text NOT NULL,
  PRIMARY KEY (grant_id, message_id)
);
CREATE INDEX grok_bot_answered_messages_answered ON grok_bot_answered_messages(answered_at);
