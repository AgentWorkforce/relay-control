-- Operator session hard delete (docs/session-erasure.md). One row per erased
-- session: the stable request id sent to the session pipeline, who first asked,
-- and when the completed erase was audited. Ids only, never session content.
-- The pipeline's receipt stays the source of truth for the erase itself.

CREATE TABLE IF NOT EXISTS selfhost_session_erasures (
  organization_id uuid NOT NULL REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  session_id text NOT NULL,
  request_id uuid NOT NULL,
  actor_kind text NOT NULL,
  actor_id text NULL,
  requested_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz NULL,
  PRIMARY KEY (organization_id, session_id)
);
