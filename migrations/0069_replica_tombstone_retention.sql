-- Replica identity tombstones outlive their workspace: deleting a workspace
-- keeps every tombstone with workspace_id NULL (instead of cascading it away),
-- so a released or workspace-deleted provider workspace stays refused until an
-- owner/admin of the workspace now holding that provider organization's
-- connection revives it. The primary key (issuer, provider_organization_id,
-- provider_workspace_id) is unchanged and remains the admission lookup index.
ALTER TABLE replica_identity_tombstones ALTER COLUMN workspace_id DROP NOT NULL;
ALTER TABLE replica_identity_tombstones DROP CONSTRAINT IF EXISTS replica_identity_tombstones_workspace_id_fkey;
ALTER TABLE replica_identity_tombstones
  ADD CONSTRAINT replica_identity_tombstones_workspace_id_fkey
  FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE SET NULL;
