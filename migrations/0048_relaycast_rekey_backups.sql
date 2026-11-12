-- relaycast-rekey (README, "Re-keying Relaycast credentials"): before the
-- re-key overwrites a stored Relaycast credential with its ar_ replacement,
-- the old ciphertext is kept here so `relaycast-rekey --undo <run-id>` can
-- put it back. Both ciphertext columns hold keyring envelopes
-- (crypto.encryptSecret), never plain values. key_generation is the
-- Relaycast workspace key generation the rotation produced (workspace keys
-- only), so an undo can push the old key back above it.
CREATE TABLE relaycast_rekey_backups (
  id uuid PRIMARY KEY,
  run_id uuid NOT NULL,
  table_name text NOT NULL,
  row_id text NOT NULL,
  column_name text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('workspace', 'agent', 'webhook')),
  relaycast_workspace_id text,
  old_ciphertext text NOT NULL,
  new_ciphertext text NOT NULL,
  key_generation bigint,
  created_at timestamptz NOT NULL DEFAULT now(),
  restored_at timestamptz,
  UNIQUE (run_id, table_name, row_id, column_name)
);
CREATE INDEX relaycast_rekey_backups_run ON relaycast_rekey_backups(run_id, created_at);
