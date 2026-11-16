-- Replicas failure paths.
--
-- replica_environment_policies.create_unconfirmed: set (and committed) before
-- Control asks the provider to create an environment MCP entry, cleared once
-- the entry is found by name or the provider definitely rejected the create.
-- While set, automatic runs (startup, sweep) only relist and never create
-- again; a person-driven sync or enable may create again only when a complete
-- listing shows no entry.
--
-- replica_environment_policies.discovery_missing_since: first time a complete
-- environment listing no longer showed an enabled environment. Admission and
-- the sync default selection skip such a policy until it is listed again. The
-- opt-out is never touched.
--
-- remote_agent_connections.access_revoked_at / access_error: latched when the
-- provider answers 401/403 to the stored Replicas key; cleared by a 2xx
-- environment listing or whoami, or a re-connect. access_error holds
-- Control-authored text only, never a provider body.
ALTER TABLE replica_environment_policies ADD COLUMN IF NOT EXISTS create_unconfirmed boolean NOT NULL DEFAULT false;
ALTER TABLE replica_environment_policies ADD COLUMN IF NOT EXISTS discovery_missing_since timestamptz NULL;
ALTER TABLE remote_agent_connections ADD COLUMN IF NOT EXISTS access_revoked_at timestamptz NULL;
ALTER TABLE remote_agent_connections ADD COLUMN IF NOT EXISTS access_error text NULL;
