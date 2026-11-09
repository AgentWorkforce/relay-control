-- A session is only unique within its organization, workspace and source
-- (docs/session-erasure.md). The hard-delete routes cannot have run before this
-- migration because the pipeline erase did not exist, so the table is empty. If
-- it is not, the NOT NULL columns fail the migration rather than guess a target.

ALTER TABLE selfhost_session_erasures
  ADD COLUMN workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  ADD COLUMN source text NOT NULL,
  DROP CONSTRAINT selfhost_session_erasures_pkey,
  ADD PRIMARY KEY (organization_id, workspace_id, source, session_id);
