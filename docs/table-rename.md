# Table rename (migration 0033)

Migration `0033_drop_selfhost_table_prefix.sql` removes the `selfhost_` prefix
from every table, and from indexes, constraints and sequences that carry it.
Rows are not rewritten. `control_schema_migrations` is the one table that does
not simply lose the prefix: `schema_migrations` is already the ledger name used by
another service, so it is qualified. The migration runner renames it before
it reads the ledger.

Older migration files still use the old names, because applied migrations are
checksummed and must not change.

| Old name | New name |
|---|---|
| `selfhost_admin_audit_events` | `admin_audit_events` |
| `selfhost_admin_email_grants` | `admin_email_grants` |
| `selfhost_amp_bindings` | `amp_bindings` |
| `selfhost_amp_connections` | `amp_connections` |
| `selfhost_amp_deliveries` | `amp_deliveries` |
| `selfhost_amp_history_syncs` | `amp_history_syncs` |
| `selfhost_capture_policies` | `capture_policies` |
| `selfhost_cli_credential_refs` | `cli_credential_refs` |
| `selfhost_coding_agent_credential_blobs` | `coding_agent_credential_blobs` |
| `selfhost_coding_agent_credentials` | `coding_agent_credentials` |
| `selfhost_coding_agent_device_sessions` | `coding_agent_device_sessions` |
| `selfhost_desktop_attestation_keys` | `desktop_attestation_keys` |
| `selfhost_desktop_feed_assets` | `desktop_feed_assets` |
| `selfhost_desktop_feed_audit_events` | `desktop_feed_audit_events` |
| `selfhost_desktop_feed_current` | `desktop_feed_current` |
| `selfhost_desktop_feed_install_tokens` | `desktop_feed_install_tokens` |
| `selfhost_desktop_feed_profile_keys` | `desktop_feed_profile_keys` |
| `selfhost_desktop_feed_profiles` | `desktop_feed_profiles` |
| `selfhost_desktop_feed_publisher_tokens` | `desktop_feed_publisher_tokens` |
| `selfhost_desktop_feed_releases` | `desktop_feed_releases` |
| `selfhost_desktop_feed_workspace_bindings` | `desktop_feed_workspace_bindings` |
| `selfhost_desktop_mcp_credentials` | `desktop_mcp_credentials` |
| `selfhost_desktop_relay_identities` | `desktop_relay_identities` |
| `selfhost_device_authorizations` | `device_authorizations` |
| `selfhost_email_login_tokens` | `email_login_tokens` |
| `selfhost_factory_bindings` | `factory_bindings` |
| `selfhost_factory_connections` | `factory_connections` |
| `selfhost_factory_deliveries` | `factory_deliveries` |
| `selfhost_factory_history_syncs` | `factory_history_syncs` |
| `selfhost_fleet_node_owners` | `fleet_node_owners` |
| `selfhost_flow_definitions` | `flow_definitions` |
| `selfhost_hosted_relay_participants` | `hosted_relay_participants` |
| `selfhost_installation_bootstrap` | `installation_bootstrap` |
| `selfhost_integration_connections` | `integration_connections` |
| `selfhost_integration_oauth_apps` | `integration_oauth_apps` |
| `selfhost_integration_oauth_states` | `integration_oauth_states` |
| `selfhost_login_attempts` | `login_attempts` |
| `selfhost_mcp_attestation_tool_uses` | `mcp_attestation_tool_uses` |
| `selfhost_mcp_oauth_authorization_codes` | `mcp_oauth_authorization_codes` |
| `selfhost_mcp_oauth_clients` | `mcp_oauth_clients` |
| `selfhost_mcp_oauth_grants` | `mcp_oauth_grants` |
| `selfhost_mcp_oauth_retired_refresh_tokens` | `mcp_oauth_retired_refresh_tokens` |
| `selfhost_mcp_oauth_revocations` | `mcp_oauth_revocations` |
| `selfhost_mcp_oauth_sessions` | `mcp_oauth_sessions` |
| `selfhost_organization_domains` | `organization_domains` |
| `selfhost_organization_invitations` | `organization_invitations` |
| `selfhost_organization_memberships` | `organization_memberships` |
| `selfhost_organizations` | `organizations` |
| `selfhost_password_credentials` | `password_credentials` |
| `selfhost_password_registrations` | `password_registrations` |
| `selfhost_password_reset_tokens` | `password_reset_tokens` |
| `selfhost_password_setup_tokens` | `password_setup_tokens` |
| `selfhost_person_identities` | `person_identities` |
| `selfhost_person_messages` | `person_messages` |
| `selfhost_person_revocations` | `person_revocations` |
| `selfhost_run_events` | `run_events` |
| `selfhost_run_objects` | `run_objects` |
| `selfhost_run_steps` | `run_steps` |
| `selfhost_schema_migrations` | `control_schema_migrations` |
| `selfhost_session_erasures` | `session_erasures` |
| `selfhost_telemetry_counters` | `telemetry_counters` |
| `selfhost_telemetry_error_index` | `telemetry_error_index` |
| `selfhost_telemetry_errors` | `telemetry_errors` |
| `selfhost_telemetry_outbox` | `telemetry_outbox` |
| `selfhost_telemetry_state` | `telemetry_state` |
| `selfhost_token_sessions` | `token_sessions` |
| `selfhost_users` | `users` |
| `selfhost_work_assignments` | `work_assignments` |
| `selfhost_worker_enrollment_tokens` | `worker_enrollment_tokens` |
| `selfhost_workers` | `workers` |
| `selfhost_workflow_runs` | `workflow_runs` |
| `selfhost_workspace_api_tokens` | `workspace_api_tokens` |
| `selfhost_workspace_env_vars` | `workspace_env_vars` |
| `selfhost_workspaces` | `workspaces` |

## Upgrading

Run the migrate step from an image that includes migration 0033 (`npm run migrate` or the chart migration
Job), then roll the API to that image. The rename takes `ACCESS EXCLUSIVE`
locks for a moment and waits at most 30 seconds for them, so old API pods
report errors between the migration and their replacement.

Do not run an older image's migrate step against a renamed database. It looks
for the old ledger, finds nothing, and would create a new, empty schema under
the old names. If that happens the next migrate from a current image refuses
to continue, because both ledgers exist.

This project has no rollback migrations. To undo the rename, restore the
database from before the migration.
