-- Release gates on delegation (relay docs/design/owner-trusted-delegates.md
-- §11a). The job that publishes redeems the approval itself, under its own
-- short-lived workflow OIDC token, right before its first publish step. A
-- gate is the owner's registration of exactly which workflow may do that.

CREATE TABLE IF NOT EXISTS delegation_gates (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- The OIDC issuer whose tokens this gate trusts: a same-named repository on
  -- another trusted issuer is a different repository.
  issuer text NOT NULL DEFAULT 'https://token.actions.githubusercontent.com',
  repo text NOT NULL,
  -- The workflow file and ref the run started from (the token's workflow_ref).
  workflow_ref text NOT NULL,
  -- Set when the publishing job runs inside a reusable workflow: that
  -- workflow's file and ref (the token's job_workflow_ref), required to match too.
  job_workflow_ref text,
  -- Exactly one of ref (exact) and ref_pattern (`refs/tags/<literal prefix>*`).
  ref text,
  ref_pattern text,
  event text NOT NULL,
  target_prefix text NOT NULL,
  created_auth_method text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT delegation_gates_auth_method CHECK (created_auth_method IN ('session', 'desktop_bearer')),
  CONSTRAINT delegation_gates_ref CHECK ((ref IS NULL) <> (ref_pattern IS NULL))
);

CREATE INDEX IF NOT EXISTS delegation_gates_repo_idx
  ON delegation_gates (workspace_id, repo) WHERE deleted_at IS NULL;

-- The run a gate redeem consumed an action for (single use is per action,
-- §5.1). Any later redeem of that action in the same run (another job of it,
-- or a later attempt) succeeds as same_run; any other run is refused as consumed.
CREATE TABLE IF NOT EXISTS delegation_gate_redemptions (
  approval_id text NOT NULL REFERENCES delegation_approvals(id) ON DELETE CASCADE,
  class text NOT NULL,
  target text NOT NULL,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  gate_id text NOT NULL REFERENCES delegation_gates(id) ON DELETE CASCADE,
  issuer text NOT NULL,
  repository text NOT NULL,
  run_id text NOT NULL,
  run_attempt integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (approval_id, class, target)
);
