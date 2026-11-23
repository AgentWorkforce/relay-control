-- Workspace agent identities (docs/identity.md, "Workspace agent identity
-- tokens"): an owner or admin names an agent of the workspace and mints one or
-- more `sh_wk_` tokens of purpose `agent-identity` (scope relay:agent) for it.
-- The token reaches only the Relay messaging tools of the hosted MCP server
-- and acts there as that named agent, never as a person.
--
-- One agent_identities row per (workspace, case-blind name). Minting again for
-- the same name rotates: a new token row points at the same identity, older
-- tokens stay live until revoked or expired, and the Relay participant stays
-- the same because it is keyed on the identity, not on the token.
CREATE TABLE IF NOT EXISTS agent_identities (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  agent_name text NOT NULL,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_identities_workspace_name
  ON agent_identities (workspace_id, lower(agent_name));

-- agent_identity_id: the identity an agent-identity token acts as; NULL for
-- every other purpose. agent_name carries the identity's name as minted, so
-- the token list shows it without a join. aud stays NULL: the token mints no
-- downstream audience-bound credential.
ALTER TABLE workspace_api_tokens
  ADD COLUMN agent_identity_id uuid REFERENCES agent_identities(id) ON DELETE CASCADE;

ALTER TABLE workspace_api_tokens DROP CONSTRAINT api_token_purpose, DROP CONSTRAINT api_token_agent_binding;
ALTER TABLE workspace_api_tokens ADD CONSTRAINT api_token_purpose CHECK (purpose IN ('agent-runtime','workflow','deployment','relayfile-agent','acquisition-operator','relay-node','desktop-enrollment','enrollment-operator','agent-identity')),
  ADD CONSTRAINT api_token_agent_binding CHECK (
    (purpose='relayfile-agent' AND agent_name IS NOT NULL AND aud IS NOT NULL)
    OR (purpose='acquisition-operator' AND agent_name IS NULL AND aud IS NOT NULL)
    OR (purpose='relay-node' AND agent_name IS NOT NULL AND aud IS NULL)
    OR (purpose='agent-identity' AND agent_name IS NOT NULL AND aud IS NULL)
    OR (purpose NOT IN ('relayfile-agent','acquisition-operator','relay-node','agent-identity') AND agent_name IS NULL AND aud IS NULL)),
  ADD CONSTRAINT api_token_agent_identity CHECK (
    (purpose = 'agent-identity') = (agent_identity_id IS NOT NULL)),
  -- An agent identity token always expires.
  ADD CONSTRAINT api_token_agent_identity_expiry CHECK (
    purpose <> 'agent-identity' OR expires_at IS NOT NULL);

CREATE INDEX IF NOT EXISTS workspace_api_tokens_agent_identity
  ON workspace_api_tokens (agent_identity_id) WHERE agent_identity_id IS NOT NULL;

-- A hosted Relay participant is owned by exactly one of a person (user_id) or
-- an agent identity (agent_identity_id). An agent identity holds at most one
-- participant per workspace: its registered Relay agent.
ALTER TABLE hosted_relay_participants
  ALTER COLUMN user_id DROP NOT NULL,
  ADD COLUMN agent_identity_id uuid REFERENCES agent_identities(id) ON DELETE CASCADE,
  ADD CONSTRAINT hosted_relay_participant_owner CHECK (
    (user_id IS NULL) <> (agent_identity_id IS NULL));

CREATE UNIQUE INDEX IF NOT EXISTS hosted_relay_participants_agent_identity
  ON hosted_relay_participants (workspace_id, agent_identity_id) WHERE agent_identity_id IS NOT NULL;
