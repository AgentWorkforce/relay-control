-- Workspace policy v2 (docs/workspace-policy.md): the spawn, join, delivery
-- and analytics sections, and the person-only consent list, stored beside the
-- capture policy in the organization's existing capture_policies row. No new
-- table. The capture section stays in `settings`.
--
-- Two revision counters on the row:
-- - `revision` (v1) is the capture policy revision. Agent Relay Desktop sends
--   it with every upload (X-Agent-Relay-Capture-Policy-Revision, 409 when
--   stale), so it changes only when the capture settings change.
-- - `workspace_revision` (v2) is the revision of the whole workspace policy
--   document. It changes on every write through either route.
-- Both start at 1 (unset); the first write makes either one 2.

ALTER TABLE capture_policies
  ADD COLUMN IF NOT EXISTS workspace_settings jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE capture_policies
  ADD COLUMN IF NOT EXISTS workspace_revision integer NOT NULL DEFAULT 1 CHECK (workspace_revision >= 1);
ALTER TABLE capture_policies
  ADD COLUMN IF NOT EXISTS consent text[] NOT NULL DEFAULT '{}';
