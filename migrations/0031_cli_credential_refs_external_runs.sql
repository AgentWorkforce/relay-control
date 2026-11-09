-- Flows runs are moving to relayfile-control's own database, so a credential
-- reference can name a run this database has never seen. References still
-- expire on their own and stay bound to the workspace.
ALTER TABLE selfhost_cli_credential_refs
  DROP CONSTRAINT IF EXISTS selfhost_cli_credential_refs_run_id_fkey;
