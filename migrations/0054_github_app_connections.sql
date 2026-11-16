-- GitHub App connections import the installation anchor, not an unrefreshable
-- Nango access token. Minted tokens use the existing encrypted cache column.
ALTER TABLE integration_connections ADD COLUMN installation_id text;
ALTER TABLE integration_connections DROP CONSTRAINT connection_auth_mode;
ALTER TABLE integration_connections ADD CONSTRAINT connection_auth_mode
  CHECK (auth_mode IN ('oauth2', 'api_key', 'github_app'));
ALTER TABLE integration_connections ADD CONSTRAINT connection_github_installation
  CHECK (auth_mode <> 'github_app' OR
    (provider = 'github' AND installation_id IS NOT NULL AND installation_id ~ '^[1-9][0-9]{0,19}$'));
