-- Copilot Desktop MCP (ported from Cloud migrations 0348/0349). Numbered 0020
-- provisionally; renumbered above main's highest migration when this change
-- is marked ready for review.

-- Parent-session provenance. A renewable Desktop session is "verified" only
-- when it was redeemed (S256 verifier) from a browser-consent handoff that
-- named the Desktop host. Sessions issued before this migration, device-flow
-- sessions and handoffs without a consented host name stay unverified.
ALTER TABLE selfhost_token_sessions
  ADD COLUMN IF NOT EXISTS desktop_host_name text,
  ADD COLUMN IF NOT EXISTS desktop_verified_at timestamptz;

-- Desktop-provider MCP credentials: a child token session (scopes rth:read +
-- mcp:desktop, 15-minute renewable lease) bound to the verified parent that
-- minted it. The secret is chosen by Desktop and stored only as the child
-- session's access_token_hash. Removing the child session removes the
-- binding; removing the parent removes both.
CREATE TABLE IF NOT EXISTS selfhost_desktop_mcp_credentials (
  token_session_id uuid PRIMARY KEY
    REFERENCES selfhost_token_sessions(id) ON DELETE CASCADE,
  parent_session_id uuid NOT NULL
    REFERENCES selfhost_token_sessions(id) ON DELETE CASCADE,
  installation_id uuid NOT NULL,
  provider text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (parent_session_id, installation_id, provider),
  CONSTRAINT selfhost_desktop_mcp_credentials_provider
    CHECK (provider ~ '^[a-z][a-z0-9-]{0,63}$')
);

CREATE INDEX IF NOT EXISTS selfhost_desktop_mcp_credentials_parent_idx
  ON selfhost_desktop_mcp_credentials (parent_session_id);

-- Desktop relay identities synced by a Desktop source (one installation) for
-- its owner. The agent token is a keyring envelope (crypto.encryptSecret);
-- never the plain token. native_session_* links a provider chat (Copilot)
-- to the identity it acts as.
CREATE TABLE IF NOT EXISTS selfhost_desktop_relay_identities (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  user_id uuid NOT NULL,
  relaycast_workspace_id text NOT NULL,
  source_id uuid NOT NULL,
  agent_name text NOT NULL,
  agent_remote_id text NOT NULL,
  address text NOT NULL,
  token_ciphertext text NOT NULL,
  native_session_kind text,
  native_session_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, user_id, source_id, agent_remote_id),
  UNIQUE (relaycast_workspace_id, agent_remote_id),
  CONSTRAINT selfhost_desktop_relay_identities_native
    CHECK ((native_session_kind IS NULL) = (native_session_id IS NULL)),
  FOREIGN KEY (workspace_id, organization_id)
    REFERENCES selfhost_workspaces(id, organization_id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, user_id)
    REFERENCES selfhost_organization_memberships(organization_id, user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS selfhost_desktop_relay_identities_native_idx
  ON selfhost_desktop_relay_identities (workspace_id, user_id, native_session_kind, native_session_id)
  WHERE native_session_id IS NOT NULL;

-- The Ed25519 public key a Desktop source signs Copilot tool-call proofs
-- with. One key per (workspace, user, source); replaced on every sync.
CREATE TABLE IF NOT EXISTS selfhost_desktop_attestation_keys (
  workspace_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  user_id uuid NOT NULL,
  source_id uuid NOT NULL,
  kid text NOT NULL,
  public_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, user_id, source_id),
  FOREIGN KEY (workspace_id, organization_id)
    REFERENCES selfhost_workspaces(id, organization_id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, user_id)
    REFERENCES selfhost_organization_memberships(organization_id, user_id) ON DELETE CASCADE
);

-- Spent attestation nonces: each Copilot proof is accepted once. Rows outlive
-- the proof (exp + 120 s) and are pruned after expires_at.
CREATE TABLE IF NOT EXISTS selfhost_mcp_attestation_tool_uses (
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE CASCADE,
  tool_use_id text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, user_id, tool_use_id)
);

CREATE INDEX IF NOT EXISTS selfhost_mcp_attestation_tool_uses_expiry_idx
  ON selfhost_mcp_attestation_tool_uses (expires_at);
