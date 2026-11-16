-- Preserve the hosted Cloud relay-workspace identity while an app workspace
-- moves to Control. Control's relaycast_workspace_id is its live Relaycast
-- binding; this compatibility id is the stable rw_<8hex> key used by
-- Relayfile and Nango and must not be repurposed as that binding.
ALTER TABLE workspaces
  ADD COLUMN cloud_relay_workspace_id text,
  ADD CONSTRAINT workspaces_cloud_relay_workspace_id_format
    CHECK (cloud_relay_workspace_id IS NULL OR cloud_relay_workspace_id ~ '^rw_[0-9a-f]{8}$'),
  ADD CONSTRAINT workspaces_cloud_relay_workspace_id_unique
    UNIQUE (cloud_relay_workspace_id);
