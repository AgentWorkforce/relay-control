-- bootstrap-signup lane: first-boot bootstrap state, organization invites
-- and email sign-in links. Forward-only and idempotent.

-- What the first-boot bootstrap (SELFHOST_BOOTSTRAP_*) has already done, so
-- a restart repeats nothing: the admin email it last granted owner to, and
-- the workspace it provisioned. One row per installation.
CREATE TABLE IF NOT EXISTS selfhost_installation_bootstrap (
  installation_slot smallint PRIMARY KEY DEFAULT 1,
  organization_id uuid REFERENCES selfhost_organizations(id) ON DELETE SET NULL,
  admin_email text,
  admin_granted_at timestamptz,
  workspace_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT selfhost_installation_bootstrap_slot CHECK (installation_slot = 1)
);

-- A single-use, expiring invite to the installation's organization. Only the
-- SHA-256 of the token is stored; the link is shown once (and re-issued by
-- rotating the token).
CREATE TABLE IF NOT EXISTS selfhost_organization_invitations (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  email text NOT NULL,
  role text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  invited_by_user_id uuid REFERENCES selfhost_users(id) ON DELETE SET NULL,
  expires_at timestamptz NOT NULL,
  accepted_at timestamptz,
  accepted_by_user_id uuid REFERENCES selfhost_users(id) ON DELETE SET NULL,
  revoked_at timestamptz,
  revoked_by_user_id uuid REFERENCES selfhost_users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT selfhost_invitation_role CHECK (role IN ('owner', 'admin', 'member')),
  CONSTRAINT selfhost_invitation_email_normalized CHECK (email = lower(email))
);

-- At most one open (not accepted, not revoked) invite per email.
CREATE UNIQUE INDEX IF NOT EXISTS selfhost_invitations_open_email_idx
  ON selfhost_organization_invitations (organization_id, email)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- Email sign-in links (only when SMTP and SELFHOST_EMAIL_LOGIN are set).
CREATE TABLE IF NOT EXISTS selfhost_email_login_tokens (
  id uuid PRIMARY KEY,
  email text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  invite_token_hash text,
  next_path text,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT selfhost_email_login_email_normalized CHECK (email = lower(email))
);

CREATE INDEX IF NOT EXISTS selfhost_email_login_expiry_idx
  ON selfhost_email_login_tokens (expires_at)
  WHERE consumed_at IS NULL;
