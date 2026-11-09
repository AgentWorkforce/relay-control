-- Drops the leftover selfhost_ prefix from every Control table, index,
-- constraint and sequence. Renames only: no row is read or rewritten, and the
-- runner applies this inside its single migration transaction, so an install
-- either moves completely or not at all. A name collision (for example an
-- unrelated table already called users) aborts the whole upgrade.
--
-- The migration ledger is renamed by the runner in src/migrations.ts, which has
-- to find it before it can read which migrations have been applied.
SET LOCAL lock_timeout = '30s';

ALTER TABLE selfhost_admin_audit_events RENAME TO admin_audit_events;
ALTER TABLE selfhost_admin_email_grants RENAME TO admin_email_grants;
ALTER TABLE selfhost_amp_bindings RENAME TO amp_bindings;
ALTER TABLE selfhost_amp_connections RENAME TO amp_connections;
ALTER TABLE selfhost_amp_deliveries RENAME TO amp_deliveries;
ALTER TABLE selfhost_amp_history_syncs RENAME TO amp_history_syncs;
ALTER TABLE selfhost_capture_policies RENAME TO capture_policies;
ALTER TABLE selfhost_cli_credential_refs RENAME TO cli_credential_refs;
ALTER TABLE selfhost_coding_agent_credential_blobs RENAME TO coding_agent_credential_blobs;
ALTER TABLE selfhost_coding_agent_credentials RENAME TO coding_agent_credentials;
ALTER TABLE selfhost_coding_agent_device_sessions RENAME TO coding_agent_device_sessions;
ALTER TABLE selfhost_desktop_attestation_keys RENAME TO desktop_attestation_keys;
ALTER TABLE selfhost_desktop_feed_assets RENAME TO desktop_feed_assets;
ALTER TABLE selfhost_desktop_feed_audit_events RENAME TO desktop_feed_audit_events;
ALTER TABLE selfhost_desktop_feed_current RENAME TO desktop_feed_current;
ALTER TABLE selfhost_desktop_feed_install_tokens RENAME TO desktop_feed_install_tokens;
ALTER TABLE selfhost_desktop_feed_profile_keys RENAME TO desktop_feed_profile_keys;
ALTER TABLE selfhost_desktop_feed_profiles RENAME TO desktop_feed_profiles;
ALTER TABLE selfhost_desktop_feed_publisher_tokens RENAME TO desktop_feed_publisher_tokens;
ALTER TABLE selfhost_desktop_feed_releases RENAME TO desktop_feed_releases;
ALTER TABLE selfhost_desktop_feed_workspace_bindings RENAME TO desktop_feed_workspace_bindings;
ALTER TABLE selfhost_desktop_mcp_credentials RENAME TO desktop_mcp_credentials;
ALTER TABLE selfhost_desktop_relay_identities RENAME TO desktop_relay_identities;
ALTER TABLE selfhost_device_authorizations RENAME TO device_authorizations;
ALTER TABLE selfhost_email_login_tokens RENAME TO email_login_tokens;
ALTER TABLE selfhost_factory_bindings RENAME TO factory_bindings;
ALTER TABLE selfhost_factory_connections RENAME TO factory_connections;
ALTER TABLE selfhost_factory_deliveries RENAME TO factory_deliveries;
ALTER TABLE selfhost_factory_history_syncs RENAME TO factory_history_syncs;
ALTER TABLE selfhost_fleet_node_owners RENAME TO fleet_node_owners;
ALTER TABLE selfhost_flow_definitions RENAME TO flow_definitions;
ALTER TABLE selfhost_hosted_relay_participants RENAME TO hosted_relay_participants;
ALTER TABLE selfhost_installation_bootstrap RENAME TO installation_bootstrap;
ALTER TABLE selfhost_integration_connections RENAME TO integration_connections;
ALTER TABLE selfhost_integration_oauth_apps RENAME TO integration_oauth_apps;
ALTER TABLE selfhost_integration_oauth_states RENAME TO integration_oauth_states;
ALTER TABLE selfhost_login_attempts RENAME TO login_attempts;
ALTER TABLE selfhost_mcp_attestation_tool_uses RENAME TO mcp_attestation_tool_uses;
ALTER TABLE selfhost_mcp_oauth_authorization_codes RENAME TO mcp_oauth_authorization_codes;
ALTER TABLE selfhost_mcp_oauth_clients RENAME TO mcp_oauth_clients;
ALTER TABLE selfhost_mcp_oauth_grants RENAME TO mcp_oauth_grants;
ALTER TABLE selfhost_mcp_oauth_retired_refresh_tokens RENAME TO mcp_oauth_retired_refresh_tokens;
ALTER TABLE selfhost_mcp_oauth_revocations RENAME TO mcp_oauth_revocations;
ALTER TABLE selfhost_mcp_oauth_sessions RENAME TO mcp_oauth_sessions;
ALTER TABLE selfhost_organization_domains RENAME TO organization_domains;
ALTER TABLE selfhost_organization_invitations RENAME TO organization_invitations;
ALTER TABLE selfhost_organization_memberships RENAME TO organization_memberships;
ALTER TABLE selfhost_organizations RENAME TO organizations;
ALTER TABLE selfhost_password_credentials RENAME TO password_credentials;
ALTER TABLE selfhost_password_registrations RENAME TO password_registrations;
ALTER TABLE selfhost_password_reset_tokens RENAME TO password_reset_tokens;
ALTER TABLE selfhost_password_setup_tokens RENAME TO password_setup_tokens;
ALTER TABLE selfhost_person_identities RENAME TO person_identities;
ALTER TABLE selfhost_person_messages RENAME TO person_messages;
ALTER TABLE selfhost_person_revocations RENAME TO person_revocations;
ALTER TABLE selfhost_run_events RENAME TO run_events;
ALTER TABLE selfhost_run_objects RENAME TO run_objects;
ALTER TABLE selfhost_run_steps RENAME TO run_steps;
ALTER TABLE selfhost_session_erasures RENAME TO session_erasures;
ALTER TABLE selfhost_telemetry_counters RENAME TO telemetry_counters;
ALTER TABLE selfhost_telemetry_error_index RENAME TO telemetry_error_index;
ALTER TABLE selfhost_telemetry_errors RENAME TO telemetry_errors;
ALTER TABLE selfhost_telemetry_outbox RENAME TO telemetry_outbox;
ALTER TABLE selfhost_telemetry_state RENAME TO telemetry_state;
ALTER TABLE selfhost_token_sessions RENAME TO token_sessions;
ALTER TABLE selfhost_users RENAME TO users;
ALTER TABLE selfhost_work_assignments RENAME TO work_assignments;
ALTER TABLE selfhost_worker_enrollment_tokens RENAME TO worker_enrollment_tokens;
ALTER TABLE selfhost_workers RENAME TO workers;
ALTER TABLE selfhost_workflow_runs RENAME TO workflow_runs;
ALTER TABLE selfhost_workspace_api_tokens RENAME TO workspace_api_tokens;
ALTER TABLE selfhost_workspace_env_vars RENAME TO workspace_env_vars;
ALTER TABLE selfhost_workspaces RENAME TO workspaces;

DO $$
DECLARE
  item record;
BEGIN
  -- Renaming a constraint also renames the index that backs it.
  FOR item IN
    SELECT con.conname, rel.relname
      FROM pg_constraint con
      JOIN pg_class rel ON rel.oid = con.conrelid
     WHERE con.connamespace = current_schema()::regnamespace
       AND con.conname LIKE 'selfhost\_%' ESCAPE '\'
  LOOP
    EXECUTE format('ALTER TABLE %I.%I RENAME CONSTRAINT %I TO %I',
      current_schema(), item.relname, item.conname, substr(item.conname, 10));
  END LOOP;

  FOR item IN
    SELECT relname, relkind
      FROM pg_class
     WHERE relnamespace = current_schema()::regnamespace
       AND relkind IN ('i', 'S')
       AND relname LIKE 'selfhost\_%' ESCAPE '\'
  LOOP
    EXECUTE format('ALTER %s %I.%I RENAME TO %I',
      CASE item.relkind WHEN 'i' THEN 'INDEX' ELSE 'SEQUENCE' END,
      current_schema(), item.relname, substr(item.relname, 10));
  END LOOP;
END $$;
