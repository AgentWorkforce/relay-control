-- Messaging wake-ups belong to the exact MCP grant, never a name alone.
CREATE TABLE grok_bot_routines (
  grant_id uuid PRIMARY KEY REFERENCES mcp_oauth_grants(id) ON DELETE CASCADE,
  credentials_ciphertext text NOT NULL,
  notified_delivery_ids text[] NOT NULL DEFAULT '{}',
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  failures integer NOT NULL DEFAULT 0,
  last_delivered_at timestamptz,
  last_error text,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX grok_bot_routines_due ON grok_bot_routines(next_attempt_at);
