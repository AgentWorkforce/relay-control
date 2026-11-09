-- Email + password sign-in (docs/identity.md, "Password sign-in").
-- No table stores a password, a pepper or a token in clear: passwords are
-- argon2id PHC strings, tokens are SHA-256 hashes (src/crypto.ts hashSecret).

-- One password per person. `pepper_version` names the pepper (from
-- SELFHOST_PASSWORD_PEPPER_FILE) the hash was made with, NULL = none;
-- `params` mirrors the argon2id m/t/p in the PHC string for operators.
-- `lockout_notice_at` is when the owner was last emailed about an account
-- lockout (at most one notice per 24 hours).
CREATE TABLE IF NOT EXISTS selfhost_password_credentials (
  user_id uuid PRIMARY KEY REFERENCES selfhost_users(id) ON DELETE CASCADE,
  password_hash text NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
  pepper_version integer CHECK (pepper_version IS NULL OR pepper_version >= 1),
  params text NOT NULL,
  lockout_notice_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- A registration waiting for its email to be verified. It holds no
-- password: the address is proven first, then the single-use verification
-- token is exchanged for a short-lived set-password token (below).
CREATE TABLE IF NOT EXISTS selfhost_password_registrations (
  id uuid PRIMARY KEY,
  email text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  invite_token_hash text,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT selfhost_password_registrations_email_normalized CHECK (email = lower(email))
);

CREATE INDEX IF NOT EXISTS selfhost_password_registrations_email_idx
  ON selfhost_password_registrations (email)
  WHERE consumed_at IS NULL;

-- A single-use set-password token (sh_ps_, at most 15 minutes) minted when a
-- verification link is redeemed. Spending it, creating the account and
-- writing the credential happen in one transaction.
CREATE TABLE IF NOT EXISTS selfhost_password_setup_tokens (
  id uuid PRIMARY KEY,
  email text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  invite_token_hash text,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT selfhost_password_setup_tokens_email_normalized CHECK (email = lower(email))
);

CREATE INDEX IF NOT EXISTS selfhost_password_setup_tokens_email_idx
  ON selfhost_password_setup_tokens (email)
  WHERE consumed_at IS NULL;

-- A single-use password reset token (at most 30 minutes).
CREATE TABLE IF NOT EXISTS selfhost_password_reset_tokens (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS selfhost_password_reset_tokens_user_idx
  ON selfhost_password_reset_tokens (user_id)
  WHERE used_at IS NULL;

-- Password sign-in attempts per subject, shared by every replica:
--   "account-key:<email>|<client key>"  backoff after 5 attempts (30 s doubling, 15 min cap)
--   "account:<email>"                   15 minute lock after 50 attempts within an hour
--   "ip:<client key>"                   backoff after 30 attempts
-- (the client key is the address, IPv6 bucketed by /64). Each attempt is
-- reserved (counted) before the password is checked; an attempt refused
-- inside a lock counts nothing. A success clears the account-key and
-- account rows and refunds the IP reservation; a completed reset clears
-- every row of the account. Backoff rows idle for an hour start over.
CREATE TABLE IF NOT EXISTS selfhost_login_attempts (
  subject text PRIMARY KEY,
  failures integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
  first_failure_at timestamptz NOT NULL DEFAULT now(),
  last_failure_at timestamptz NOT NULL DEFAULT now(),
  locked_until timestamptz
);

-- SELFHOST_ADMIN_EMAILS grants, recorded once per address so a later
-- demotion by an owner is not undone at the next sign-in.
CREATE TABLE IF NOT EXISTS selfhost_admin_email_grants (
  email text PRIMARY KEY CHECK (email = lower(email)),
  organization_id uuid NOT NULL REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner', 'admin')),
  granted_at timestamptz NOT NULL DEFAULT now()
);
