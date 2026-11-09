-- Single-use consent tokens for the "approve Agent Relay Desktop on <host>"
-- screen. A shared row rather than process memory, so the approve/deny form
-- post may reach any Control replica and survives a rolling restart. Only the
-- sha256 of the token is stored; attempt_key binds it to one person and one
-- sign-in attempt. Consuming deletes the row, so it is claimed exactly once.
CREATE TABLE IF NOT EXISTS desktop_consent_tokens (
  id uuid PRIMARY KEY,
  token_hash text NOT NULL UNIQUE,
  attempt_key text NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS desktop_consent_tokens_expiry_idx
  ON desktop_consent_tokens (expires_at);
