-- First-time setup without email (docs/identity.md, "First-time setup key"
-- and "Temporary passwords"). Nothing here stores a key or a password in
-- clear: setup keys are SHA-256 hashes (src/crypto.ts hashSecret, the key is
-- 256 bits of randomness), temporary passwords are argon2id PHC strings.

-- A one-time setup key for the bootstrap admin (SELFHOST_BOOTSTRAP_ADMIN_EMAIL).
-- `source` = 'configured' (SELFHOST_SETUP_KEY[_FILE], recorded the first time
-- the server sees it) or 'minted' (POST /api/v1/installation/setup-key with
-- the bootstrap bearer). A key works until it is used, revoked, or 24 hours
-- after it was recorded, and only while the admin has never signed in and
-- has no password.
CREATE TABLE IF NOT EXISTS setup_keys (
  id uuid PRIMARY KEY,
  email text NOT NULL CHECK (email = lower(email)),
  key_hash text NOT NULL UNIQUE,
  source text NOT NULL CHECK (source IN ('configured', 'minted')),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS setup_keys_live_idx
  ON setup_keys (email)
  WHERE used_at IS NULL AND revoked_at IS NULL;

-- A temporary password an owner or admin set for a member or an invitee.
-- Signing in with it never issues a session: the person must choose a new
-- password first, which spends it. At most one is live per address.
CREATE TABLE IF NOT EXISTS temporary_passwords (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email text NOT NULL CHECK (email = lower(email)),
  password_hash text NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
  pepper_version integer CHECK (pepper_version IS NULL OR pepper_version >= 1),
  params text NOT NULL,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS temporary_passwords_live_email_idx
  ON temporary_passwords (email)
  WHERE used_at IS NULL AND revoked_at IS NULL;
