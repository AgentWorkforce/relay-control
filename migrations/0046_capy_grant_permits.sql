-- A reply permit belongs to one OAuth grant, never to its base persona.
-- Native binding custody and inbound delivery are independent of this permit.
ALTER TABLE capy_bindings ADD CONSTRAINT capy_bindings_permit_owner
  UNIQUE (id,organization_id,workspace_id,user_id);
CREATE TABLE capy_grant_permits (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  user_id uuid NOT NULL,
  grant_id uuid NOT NULL,
  binding_id uuid NOT NULL,
  binding_generation integer NOT NULL CHECK (binding_generation > 0),
  agent_remote_id text NOT NULL CHECK (length(agent_remote_id) > 0),
  agent_name text NOT NULL CHECK (length(agent_name) > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  revoke_reason text,
  FOREIGN KEY (grant_id,organization_id,workspace_id,user_id)
    REFERENCES mcp_oauth_grants(id,organization_id,workspace_id,user_id) ON DELETE CASCADE,
  FOREIGN KEY (binding_id,organization_id,workspace_id,user_id)
    REFERENCES capy_bindings(id,organization_id,workspace_id,user_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX capy_grant_permits_live ON capy_grant_permits(grant_id,binding_id) WHERE revoked_at IS NULL;
