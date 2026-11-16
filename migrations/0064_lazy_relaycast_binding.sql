-- Cloud workspaces can exist before Agent Relay (Relaycast) has provisioned
-- their rw_ workspace and key. Control binds the pair atomically on first use;
-- a half-bound row is never valid.
ALTER TABLE workspaces
  ALTER COLUMN relaycast_workspace_id DROP NOT NULL,
  ALTER COLUMN relaycast_api_key_ciphertext DROP NOT NULL,
  ADD CONSTRAINT workspaces_relaycast_binding_pair
    CHECK (
      (relaycast_workspace_id IS NULL AND relaycast_api_key_ciphertext IS NULL)
      OR
      (relaycast_workspace_id IS NOT NULL AND relaycast_api_key_ciphertext IS NOT NULL)
    );
