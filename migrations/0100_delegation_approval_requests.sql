-- One-tap Tier O approval requests, the self-hosted twin of Cloud's
-- 0456_delegation_approval_requests (cloud#6704). A delegate asks its owner to
-- approve exact actions; the owner approves or denies through their own human
-- session, and only then does Control mint the Tier O approval
-- (delegation_approvals), as POST delegates/approvals does. A request row
-- grants nothing by itself.
--
-- Additive (expand): one new table, nothing existing changes. The previous
-- build never reads it.
CREATE TABLE IF NOT EXISTS delegation_approval_requests (
  id text PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  -- Who is asked: the requesting delegate's own owner.
  owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- The Relaycast identity that asked, as it was at the time.
  requester_agent_id text NOT NULL,
  requester_agent_name text NOT NULL,
  actions jsonb NOT NULL,
  -- The requester's reason, shown to the owner. Never an owner quote.
  note text,
  single_use boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'pending',
  approval_id text REFERENCES delegation_approvals(id) ON DELETE SET NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz,
  decided_auth_method text,
  CONSTRAINT delegation_approval_requests_status_check CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
  CONSTRAINT delegation_approval_requests_decided_check CHECK ((status = 'pending') = (decided_at IS NULL))
);

CREATE INDEX IF NOT EXISTS delegation_approval_requests_owner_idx
  ON delegation_approval_requests (workspace_id, owner_user_id, created_at);
