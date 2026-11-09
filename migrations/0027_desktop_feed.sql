-- Desktop feed (docs/desktop-feed.md): profile registry, workspace bindings,
-- releases and their declared assets, publisher and install tokens, and the
-- feed-specific audit log. Token values are never stored, only hashSecret
-- (sha256 hex). No private key material lives here: hosted signing goes
-- through the configured signer (AWS KMS), and the public keys registered for
-- import verification are public.

CREATE TABLE IF NOT EXISTS selfhost_desktop_feed_profiles (
  id text PRIMARY KEY CHECK (id ~ '^[a-z0-9]{1,32}$'),
  organization_id uuid NOT NULL REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  asset_prefix text NOT NULL CHECK (asset_prefix ~ '^[A-Za-z0-9][A-Za-z0-9_+-]{0,63}$'),
  quota_bytes bigint NOT NULL DEFAULT 20000000000 CHECK (quota_bytes >= 0),
  beta_keep integer NOT NULL DEFAULT 10 CHECK (beta_keep >= 1),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Public keys an import may be signed with (key_id fk_<profile>_<label>).
CREATE TABLE IF NOT EXISTS selfhost_desktop_feed_profile_keys (
  profile_id text NOT NULL REFERENCES selfhost_desktop_feed_profiles(id) ON DELETE CASCADE,
  key_id text NOT NULL CHECK (key_id ~ '^fk_[a-z0-9]{1,32}_[a-z0-9]{1,16}$'),
  public_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (profile_id, key_id)
);

CREATE TABLE IF NOT EXISTS selfhost_desktop_feed_workspace_bindings (
  profile_id text NOT NULL REFERENCES selfhost_desktop_feed_profiles(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (profile_id, workspace_id)
);

CREATE INDEX IF NOT EXISTS selfhost_desktop_feed_bindings_workspace_idx
  ON selfhost_desktop_feed_workspace_bindings (workspace_id);

CREATE TABLE IF NOT EXISTS selfhost_desktop_feed_releases (
  id uuid PRIMARY KEY,
  profile_id text NOT NULL REFERENCES selfhost_desktop_feed_profiles(id) ON DELETE CASCADE,
  version text NOT NULL,
  channel text NOT NULL CHECK (channel IN ('stable', 'beta')),
  state text NOT NULL CHECK (state IN ('draft', 'published')),
  origin text NOT NULL CHECK (origin IN ('publish', 'import')),
  notes text NOT NULL,
  -- RFC 8785 canonical form of the create body (idempotent retry check).
  create_body text,
  -- Import drafts: the received envelope text, stored verbatim at publish.
  -- Published releases: the envelope served byte-for-byte.
  envelope text,
  declared_bytes bigint NOT NULL CHECK (declared_bytes >= 0),
  published_at timestamptz,
  publish_seq bigint,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (profile_id, version)
);

CREATE INDEX IF NOT EXISTS selfhost_desktop_feed_releases_channel_idx
  ON selfhost_desktop_feed_releases (profile_id, channel, state, publish_seq DESC);

CREATE SEQUENCE IF NOT EXISTS selfhost_desktop_feed_publish_seq;

-- The channel's current release (what GET /manifest serves).
CREATE TABLE IF NOT EXISTS selfhost_desktop_feed_current (
  profile_id text NOT NULL REFERENCES selfhost_desktop_feed_profiles(id) ON DELETE CASCADE,
  channel text NOT NULL CHECK (channel IN ('stable', 'beta')),
  release_id uuid NOT NULL REFERENCES selfhost_desktop_feed_releases(id) ON DELETE CASCADE,
  PRIMARY KEY (profile_id, channel)
);

CREATE TABLE IF NOT EXISTS selfhost_desktop_feed_assets (
  release_id uuid NOT NULL REFERENCES selfhost_desktop_feed_releases(id) ON DELETE CASCADE,
  profile_id text NOT NULL REFERENCES selfhost_desktop_feed_profiles(id) ON DELETE CASCADE,
  position integer NOT NULL,
  name text NOT NULL,
  platform text NOT NULL,
  arch text NOT NULL,
  os_floor integer,
  kind text NOT NULL,
  size bigint NOT NULL CHECK (size >= 1),
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  -- Assigned at upload (hosted) or taken from the signed manifest (import).
  asset_id text CHECK (asset_id ~ '^a_[0-9A-Za-z]{1,64}$'),
  uploaded_size bigint,
  uploaded_sha256 text,
  storage_key text,
  uploaded_at timestamptz,
  PRIMARY KEY (release_id, name)
);

CREATE UNIQUE INDEX IF NOT EXISTS selfhost_desktop_feed_assets_id_idx
  ON selfhost_desktop_feed_assets (profile_id, asset_id) WHERE asset_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS selfhost_desktop_feed_publisher_tokens (
  id uuid PRIMARY KEY,
  profile_id text NOT NULL REFERENCES selfhost_desktop_feed_profiles(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  token_prefix text NOT NULL,
  label text,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  last_used_at timestamptz,
  -- Mint order; breaks created_at ties when deciding which tokens stay active.
  seq bigint GENERATED ALWAYS AS IDENTITY
);

CREATE INDEX IF NOT EXISTS selfhost_desktop_feed_publisher_tokens_profile_idx
  ON selfhost_desktop_feed_publisher_tokens (profile_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS selfhost_desktop_feed_install_tokens (
  id uuid PRIMARY KEY,
  token_hash text NOT NULL UNIQUE,
  token_prefix text NOT NULL,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  profile_id text NOT NULL REFERENCES selfhost_desktop_feed_profiles(id) ON DELETE CASCADE,
  label text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  last_used_at timestamptz
);

CREATE INDEX IF NOT EXISTS selfhost_desktop_feed_install_tokens_owner_idx
  ON selfhost_desktop_feed_install_tokens (user_id, workspace_id, profile_id, created_at DESC);

CREATE TABLE IF NOT EXISTS selfhost_desktop_feed_audit_events (
  id uuid PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  organization_id uuid REFERENCES selfhost_organizations(id) ON DELETE CASCADE,
  workspace_id uuid,
  actor_kind text NOT NULL CHECK (actor_kind IN ('user', 'install_token', 'publisher_token', 'service', 'anonymous')),
  actor_id text,
  action text NOT NULL,
  profile text,
  channel text,
  version text,
  asset_id text,
  client_ip inet,
  status integer NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS selfhost_desktop_feed_audit_profile_idx
  ON selfhost_desktop_feed_audit_events (profile, occurred_at DESC);
CREATE INDEX IF NOT EXISTS selfhost_desktop_feed_audit_denied_idx
  ON selfhost_desktop_feed_audit_events (workspace_id, occurred_at DESC) WHERE action = 'desktop_feed.denied';
