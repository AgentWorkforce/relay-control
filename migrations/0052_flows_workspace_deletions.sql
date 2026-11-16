-- Workspace deletes owed to relayfile-control, which holds the Flows data
-- (docs/flows-workspace-delete.md). Written in the transaction that deletes
-- the workspace, so no FK: the row must outlive it. Removed only once
-- relayfile-control confirms (200, or 404 for nothing held there).
CREATE TABLE flows_workspace_deletions (
  workspace_id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  queued_at timestamptz NOT NULL DEFAULT now(),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  attempts integer NOT NULL DEFAULT 0,
  last_error text
);
CREATE INDEX flows_workspace_deletions_due ON flows_workspace_deletions(next_attempt_at);
