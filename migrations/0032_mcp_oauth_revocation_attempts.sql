-- Teardown attempts are claimed in a short transaction and retried with
-- exponential backoff, so a slow Relaycast never holds tenant locks. A
-- completed row records why it finished; no token/secret is stored here.
ALTER TABLE selfhost_mcp_oauth_revocations
  ADD COLUMN attempts integer NOT NULL DEFAULT 0,
  ADD COLUMN next_attempt_at timestamptz,
  ADD COLUMN claimed_at timestamptz,
  ADD COLUMN outcome text CHECK (outcome IN
    ('released','no_remote','kept','workspace_mismatch','decrypt_failed','metadata_mismatch','operator_abandoned'));

CREATE INDEX selfhost_mcp_oauth_revocations_pending_idx
  ON selfhost_mcp_oauth_revocations (created_at, id) WHERE completed_at IS NULL;
