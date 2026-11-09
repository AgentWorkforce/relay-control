-- Amp control plane (port of hosted Cloud drizzle 0403_amp_connection).
-- Numbered 0017 because 0013-0016 are reserved by other open branches; the
-- number is renumbered at merge time if those land first.
--
-- Differences from 0403, all deliberate:
-- * Secrets are text keyring envelopes (crypto.encryptSecret), never jsonb.
-- * Workspace rows are tied to their organization by a composite foreign key.
-- * The per-binding helper capability (helper_hash / helper_envelope) is gone:
--   each delivery carries its own reply capability (sha256 only, expiring).
-- * hook_ciphertext is nullable: it holds the whsec_ secret minted at bind
--   and is cleared when the binding retires. Bind creates the two Relaycast
--   subscriptions (DM/thread and mention) itself, as Cloud does.
-- * Deliveries are a Postgres outbox with leases (no SQS / Cloudflare queue).
-- * History sync (src/amp/history.ts) is scheduled from the bindings row, not
--   a queue: history_queued_at coalesces requests, history_lease_owner /
--   history_lease_until form the run lease (also the retry delay after a
--   failure) and history_error is kept apart from delivery's last_error.
--   last_synced_at is the watermark, advanced only after a full upload.
--   History is inactive until a push-only RelayHistory session can be issued
--   (AmpDeps.pushSession); these columns then only record the blocked reason.
-- * Every statement is idempotent (IF NOT EXISTS), so re-running the file on a
--   database that applied an earlier revision of it adds only what is missing.

CREATE TABLE IF NOT EXISTS selfhost_amp_connections (
  workspace_id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE RESTRICT,
  -- Keyring envelope of the sgamp_ key; never the plain key.
  key_ciphertext text NOT NULL,
  key_hint text NOT NULL,
  validated_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (workspace_id, organization_id)
    REFERENCES selfhost_workspaces(id, organization_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS selfhost_amp_history_syncs (
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  thread_id text NOT NULL,
  versions jsonb NOT NULL DEFAULT '{}'::jsonb,
  pending_ciphertext text,
  redactions_ciphertext text,
  PRIMARY KEY (workspace_id, thread_id)
);

CREATE TABLE IF NOT EXISTS selfhost_amp_bindings (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE RESTRICT,
  thread_id text NOT NULL,
  state text NOT NULL DEFAULT 'preparing' CHECK (state IN ('preparing', 'bound', 'retired')),
  -- Bumped on every retire so an in-flight outbox claim can no longer finalize.
  generation integer NOT NULL DEFAULT 1,
  relaycast_workspace_id text,
  agent_name text NOT NULL,
  agent_remote_id text,
  token_ciphertext text,
  -- Standard Webhooks whsec_ secret for relay-events, minted when the row is
  -- created and registered with both subscriptions; null once retired.
  hook_ciphertext text,
  -- Relaycast subscription ids (DM/thread, mention), set at bind and cleared
  -- one by one only after the subscription is deleted upstream.
  subscription_id text,
  mention_subscription_id text,
  last_synced_at timestamptz,
  history_queued_at timestamptz,
  history_lease_owner uuid,
  history_lease_until timestamptz,
  history_error text,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (workspace_id, organization_id)
    REFERENCES selfhost_workspaces(id, organization_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS selfhost_amp_bindings_thread
  ON selfhost_amp_bindings (thread_id);
CREATE INDEX IF NOT EXISTS selfhost_amp_bindings_workspace_user
  ON selfhost_amp_bindings (workspace_id, user_id);

-- Earlier revisions of this file created the table without the history lease.
ALTER TABLE selfhost_amp_bindings ADD COLUMN IF NOT EXISTS history_lease_owner uuid;
ALTER TABLE selfhost_amp_bindings ADD COLUMN IF NOT EXISTS history_lease_until timestamptz;
ALTER TABLE selfhost_amp_bindings ADD COLUMN IF NOT EXISTS history_error text;

CREATE INDEX IF NOT EXISTS selfhost_amp_bindings_history_queued
  ON selfhost_amp_bindings (history_queued_at) WHERE state = 'bound' AND history_queued_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS selfhost_amp_deliveries (
  id uuid PRIMARY KEY,
  binding_id uuid NOT NULL REFERENCES selfhost_amp_bindings(id) ON DELETE CASCADE,
  message_id text NOT NULL,
  -- Keyring envelope of {sender, text}; the text is dropped once the delivery is final
  -- and the whole envelope is cleared when the binding is retired.
  payload_ciphertext text,
  state text NOT NULL CHECK (state IN ('pending', 'sending', 'delivered', 'unknown', 'rejected')),
  code text,
  attempts integer NOT NULL DEFAULT 0,
  lease_owner uuid,
  lease_until timestamptz,
  claim_generation integer,
  -- sha256 of the amp_reply_ bearer; the bearer itself is never stored.
  reply_hash text UNIQUE,
  reply_expires_at timestamptz,
  reply_request_id uuid,
  reply_body_hash text,
  reply_message_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (binding_id, message_id)
);

CREATE INDEX IF NOT EXISTS selfhost_amp_deliveries_pending
  ON selfhost_amp_deliveries (created_at) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS selfhost_amp_deliveries_sending
  ON selfhost_amp_deliveries (lease_until) WHERE state = 'sending';
