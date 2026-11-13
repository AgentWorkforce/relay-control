-- Each webhook inbox's temporary Agent Relay (Relaycast) workspace, made on first use
-- (POST /api/v1/events-shim/t/<mcp token>/workspace) through Relaycast's internal admin
-- API with a 7-day deadline. The key is encrypted with the keyring. Activity on the inbox
-- moves the deadline back; Relaycast deletes the workspace at it.
ALTER TABLE events_shims ADD COLUMN relay_workspace_id text;
ALTER TABLE events_shims ADD COLUMN relay_workspace_key_ciphertext text;
ALTER TABLE events_shims ADD COLUMN relay_workspace_expires_at timestamptz;
ALTER TABLE events_shims ADD CONSTRAINT events_shims_relay_workspace_complete
  CHECK ((relay_workspace_id IS NULL) = (relay_workspace_key_ciphertext IS NULL)
     AND (relay_workspace_id IS NULL) = (relay_workspace_expires_at IS NULL));
