-- desktop-auth lane, browser sign-in: Agent Relay Desktop's welcome screen
-- signs in through GET /api/v1/cli/login, which hands the loopback listener a
-- 15-minute session bound to the S256 code_challenge it sent. The verifier
-- redeems that session once at POST /api/v1/auth/desktop/session for a
-- renewable pair in the same token family.
ALTER TABLE selfhost_token_sessions
  ADD COLUMN IF NOT EXISTS desktop_exchange_challenge text,
  ADD COLUMN IF NOT EXISTS desktop_exchanged_at timestamptz;

-- Whose computer a Relaycast node is (POST /api/v1/fleet/nodes/claim): the
-- Desktop claims its own spawn node so spawns onto it are accepted. A claim
-- is proven with the node's own token against Relaycast and recorded for the
-- claimant; revoking the membership drops the ownership with it.
CREATE TABLE IF NOT EXISTS selfhost_fleet_node_owners (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  relaycast_workspace_id text NOT NULL,
  node_id text NOT NULL,
  node_name text NOT NULL,
  user_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, node_id),
  UNIQUE (relaycast_workspace_id, node_id),
  FOREIGN KEY (workspace_id, organization_id)
    REFERENCES selfhost_workspaces(id, organization_id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, user_id)
    REFERENCES selfhost_organization_memberships(organization_id, user_id) ON DELETE CASCADE
);
