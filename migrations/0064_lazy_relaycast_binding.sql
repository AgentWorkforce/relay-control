-- Cloud workspaces can exist before Agent Relay (Relaycast) has provisioned
-- their rw_ workspace and key. Control binds the pair atomically on first use;
-- a half-bound row is never valid.
ALTER TABLE workspaces
  ALTER COLUMN relaycast_workspace_id DROP NOT NULL,
  ALTER COLUMN relaycast_api_key_ciphertext DROP NOT NULL,
  ADD COLUMN relaycast_binding_claim_id uuid,
  ADD COLUMN relaycast_binding_claimed_at timestamptz,
  ADD COLUMN relaycast_binding_claim_name text,
  -- Relaycast's keyed create replays the workspace API key. This is therefore
  -- a credential-recovery capability, not a predictable request identifier.
  -- Control generates it once with a CSPRNG and encrypts it under the keyring.
  ADD COLUMN relaycast_binding_idempotency_key_ciphertext text,
  ADD CONSTRAINT workspaces_relaycast_binding_pair
    CHECK (
      (relaycast_workspace_id IS NULL AND relaycast_api_key_ciphertext IS NULL)
      OR
      (relaycast_workspace_id IS NOT NULL AND relaycast_api_key_ciphertext IS NOT NULL)
    ),
  ADD CONSTRAINT workspaces_relaycast_binding_claim_pair
    CHECK (
      (relaycast_binding_claim_id IS NULL AND relaycast_binding_claimed_at IS NULL)
      OR
      (relaycast_binding_claim_id IS NOT NULL AND relaycast_binding_claimed_at IS NOT NULL)
    ),
  ADD CONSTRAINT workspaces_relaycast_binding_request_pair
    CHECK (
      (
        relaycast_binding_claim_name IS NULL
        AND relaycast_binding_idempotency_key_ciphertext IS NULL
      )
      OR
      (
        relaycast_binding_claim_name IS NOT NULL
        AND relaycast_binding_idempotency_key_ciphertext IS NOT NULL
        AND relaycast_workspace_id IS NULL
        AND relaycast_api_key_ciphertext IS NULL
      )
    );
