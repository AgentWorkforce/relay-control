CREATE TABLE selfhost_users (
  id uuid PRIMARY KEY,
  email text NOT NULL UNIQUE,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT selfhost_users_email_normalized CHECK (email = lower(email))
);

CREATE TABLE selfhost_organizations (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE selfhost_organization_memberships (
  organization_id uuid NOT NULL REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE CASCADE,
  role text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, user_id),
  CONSTRAINT selfhost_membership_role CHECK (role IN ('owner', 'admin', 'member'))
);

CREATE TABLE selfhost_workspaces (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  name text NOT NULL,
  relaycast_workspace_id text NOT NULL,
  relaycast_api_key_ciphertext text NOT NULL,
  runtime_config jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, organization_id),
  UNIQUE (organization_id, relaycast_workspace_id)
);

CREATE INDEX selfhost_workspaces_organization_idx
  ON selfhost_workspaces (organization_id);

CREATE TABLE selfhost_token_sessions (
  id uuid PRIMARY KEY,
  token_family_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  label text,
  scopes text[] NOT NULL,
  access_token_hash text NOT NULL UNIQUE,
  refresh_token_hash text NOT NULL UNIQUE,
  access_token_expires_at timestamptz NOT NULL,
  refresh_token_expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  revoked_reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_refreshed_at timestamptz,
  FOREIGN KEY (organization_id, user_id)
    REFERENCES selfhost_organization_memberships(organization_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (workspace_id, organization_id)
    REFERENCES selfhost_workspaces(id, organization_id) ON DELETE CASCADE
);

CREATE INDEX selfhost_token_access_idx ON selfhost_token_sessions (access_token_hash);
CREATE INDEX selfhost_token_refresh_idx ON selfhost_token_sessions (refresh_token_hash);

CREATE TABLE selfhost_device_authorizations (
  id uuid PRIMARY KEY,
  device_code_hash text NOT NULL UNIQUE,
  user_code text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'pending',
  client_name text,
  interval_seconds integer NOT NULL,
  last_polled_at timestamptz,
  expires_at timestamptz NOT NULL,
  approved_at timestamptz,
  approved_by_user_id uuid REFERENCES selfhost_users(id) ON DELETE SET NULL,
  organization_id uuid REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  workspace_id uuid,
  api_token_session_id uuid REFERENCES selfhost_token_sessions(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (workspace_id, organization_id)
    REFERENCES selfhost_workspaces(id, organization_id) ON DELETE CASCADE,
  CONSTRAINT selfhost_device_status
    CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'consumed')),
  CONSTRAINT selfhost_device_interval CHECK (interval_seconds BETWEEN 0 AND 60)
);

CREATE INDEX selfhost_device_expiry_idx
  ON selfhost_device_authorizations (expires_at)
  WHERE status IN ('pending', 'approved');
