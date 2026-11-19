-- Per-device person messaging credentials (docs/identity.md, "Person messaging credential"): each signed-in
-- device of a person gets its own device-scoped Relaycast token for the person's human agent, minted with the
-- workspace key. One row per (workspace, person, device); the token is encrypted with the keyring like
-- person_identities.token_ciphertext. A row is served only while it is not revoked, still names the person's
-- current agent on the workspace's current Relaycast workspace, and is outside the renewal margin of expires_at.
CREATE TABLE IF NOT EXISTS person_device_credentials (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- Derived server-side: `web` for the browser session, otherwise `<slug of the name>-<8 hex of the sign-in>`.
  device_id text NOT NULL,
  device_name text NOT NULL,
  device_kind text NOT NULL CHECK (device_kind IN ('desktop', 'cli', 'web')),
  -- The sign-in session the token belongs to; NULL for the web device. Session rows are never deleted by the
  -- application (sign-out sets revoked_at), so the cascade only fires with the user, membership or workspace.
  session_id uuid REFERENCES token_sessions(id) ON DELETE CASCADE,
  relaycast_workspace_id text NOT NULL,
  -- The person agent the token was minted for; agent_name is the path segment the upstream revoke addresses.
  agent_name text NOT NULL,
  agent_remote_id text NOT NULL,
  token_ciphertext text NOT NULL,
  expires_at timestamptz NOT NULL,
  -- When the stored token was minted. A client report of a refused token forces at most one mint per device per
  -- 30 seconds, decided against this column so every replica agrees.
  minted_at timestamptz NOT NULL DEFAULT now(),
  -- Set in the same transaction that ends the sign-in session, removes the member or abandons a mint.
  revoked_at timestamptz,
  -- Set once Relaycast confirmed the device token is gone (revoked, or 404), or when the agent itself was deleted.
  upstream_revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, user_id, device_id)
);

-- Ending a sign-in session revokes the live rows bound to it.
CREATE INDEX IF NOT EXISTS person_device_credentials_live_session_idx
  ON person_device_credentials (session_id)
  WHERE revoked_at IS NULL;

-- The upstream revocation sweep reads revoked rows Relaycast has not confirmed yet, least recently tried first
-- (a failed attempt moves updated_at), so one unreachable Relaycast workspace cannot hold up the rest.
CREATE INDEX IF NOT EXISTS person_device_credentials_upstream_pending_idx
  ON person_device_credentials (updated_at)
  WHERE revoked_at IS NOT NULL AND upstream_revoked_at IS NULL;
