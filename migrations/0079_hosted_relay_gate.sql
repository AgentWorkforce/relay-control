-- Hosted participants on gate-only installs (SELFHOST_RELAYGATE_PUBLIC_URL
-- set; docs/identity.md, "Hosted participants on gate-only installs"). Every
-- hosted MCP participant (ChatGPT, Grok Bot, Muse, Cursor cloud agents, any
-- MCP client that joins through the hosted MCP endpoint) enrols at relaygate
-- with a single-use `sh_ht_` credential and holds an rg_ token, so relaygate's
-- policy decides what it may do. relaygate introspects the credential at
-- POST /internal/v1/auth/introspect; the first active answer burns it. Only
-- the sha256 hash is stored: relay-control presents the plaintext to
-- relaygate itself, once, right after minting it. No rows are written when the
-- gate URL is unset.
CREATE TABLE IF NOT EXISTS relay_hosted_credentials (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  agent_name text NOT NULL,
  -- The hosted MCP client (connector kind) relaygate's policy matches on.
  client text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  redeemed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS relay_hosted_credentials_workspace ON relay_hosted_credentials (workspace_id, created_at);

-- relaygate's agent id for a participant enrolled through relaygate; its
-- token_ciphertext then seals an rg_ token, and agent_remote_id stays the
-- upstream Relaycast agent id. NULL: registered in Relaycast directly (no
-- gate, or created before this install enforced the gate for hosted
-- participants; such a row is re-enrolled through relaygate on its next use).
ALTER TABLE hosted_relay_participants ADD COLUMN IF NOT EXISTS relaygate_agent_id text;
