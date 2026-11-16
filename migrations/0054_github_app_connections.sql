-- GitHub App connections import the installation anchor, not an unrefreshable
-- Nango access token. Minted tokens use the existing encrypted cache column.
-- An installation may be shared by workspaces of one organization, never
-- across organizations. The primary key serializes concurrent owner claims.
CREATE TABLE github_app_installations (
  installation_id text PRIMARY KEY CHECK (installation_id ~ '^[1-9][0-9]{0,19}$'),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  UNIQUE (installation_id, organization_id)
);
ALTER TABLE integration_connections ADD COLUMN installation_id text;
ALTER TABLE integration_connections ADD COLUMN github_app_organization_id uuid;
ALTER TABLE integration_connections ADD COLUMN github_app_refresh_id uuid;
ALTER TABLE integration_connections ADD COLUMN github_app_refresh_until timestamptz;
ALTER TABLE integration_connections DROP CONSTRAINT connection_auth_mode;
ALTER TABLE integration_connections ADD CONSTRAINT connection_auth_mode
  CHECK (auth_mode IN ('oauth2', 'api_key', 'github_app'));
ALTER TABLE integration_connections ADD CONSTRAINT connection_github_installation
  CHECK (auth_mode <> 'github_app' OR
    (provider = 'github' AND installation_id IS NOT NULL AND installation_id ~ '^[1-9][0-9]{0,19}$'
      AND github_app_organization_id IS NOT NULL));
ALTER TABLE integration_connections ADD CONSTRAINT connection_github_installation_owner
  FOREIGN KEY (installation_id, github_app_organization_id)
  REFERENCES github_app_installations (installation_id, organization_id);
ALTER TABLE integration_connections ADD CONSTRAINT connection_github_workspace_owner
  FOREIGN KEY (workspace_id, github_app_organization_id)
  REFERENCES workspaces (id, organization_id);
