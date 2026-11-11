-- Events shim (docs/events-shim.md): webhook inboxes that wake an agent.
-- Tokens are capabilities stored only as sha256 hashes; the hook token,
-- signing secrets and the wake bearer are encrypted with the keyring.
CREATE TABLE events_shims (
  id uuid PRIMARY KEY,
  mcp_token_hash text NOT NULL UNIQUE,
  hook_token_hash text NOT NULL UNIQUE,
  manage_token_hash text NOT NULL UNIQUE,
  hook_token_ciphertext text NOT NULL,
  secrets_ciphertext text,
  wake_url text,
  wake_secret_ciphertext text,
  wake_linked_at timestamptz,
  wake_broken_at timestamptz,
  wake_broken_reason text,
  created_at timestamptz NOT NULL,
  last_used_at timestamptz NOT NULL,
  agent_seen_at timestamptz,
  next_seq integer NOT NULL DEFAULT 1 CHECK (next_seq > 0),
  -- The signed-in person who created it; the inbox goes with them.
  workspace_id uuid REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  CHECK ((wake_url IS NULL) = (wake_secret_ciphertext IS NULL))
);
CREATE INDEX events_shims_last_used ON events_shims(last_used_at);
CREATE INDEX events_shims_creator ON events_shims(user_id, workspace_id);

-- One row per accepted post (duplicates included), for the per-hour/day limits.
CREATE TABLE events_shim_posts (
  shim_id uuid NOT NULL REFERENCES events_shims(id) ON DELETE CASCADE,
  at timestamptz NOT NULL
);
CREATE INDEX events_shim_posts_shim_at ON events_shim_posts(shim_id, at);

CREATE TABLE events_shim_events (
  id uuid PRIMARY KEY,
  shim_id uuid NOT NULL REFERENCES events_shims(id) ON DELETE CASCADE,
  seq integer NOT NULL,
  received_at timestamptz NOT NULL,
  mode text NOT NULL CHECK (mode IN ('open','github','stripe','linear','bearer')),
  event_type text,
  idempotency_key text,
  content_type text NOT NULL,
  body text NOT NULL,
  headers jsonb NOT NULL DEFAULT '{}',
  delivery text NOT NULL DEFAULT 'pending' CHECK (delivery IN ('pending','woken','read')),
  delivered_at timestamptz,
  wake_error text,
  UNIQUE (shim_id, seq)
);
CREATE INDEX events_shim_events_delivery ON events_shim_events(shim_id, delivery, seq);

-- Idempotency keys live in their own ledger so feed pruning never forgets
-- one; a key stops counting (and is deleted) once older than the dedupe window.
CREATE TABLE events_shim_idempotency_keys (
  shim_id uuid NOT NULL REFERENCES events_shims(id) ON DELETE CASCADE,
  key text NOT NULL,
  event_id uuid NOT NULL,
  seq integer NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (shim_id, key)
);
CREATE INDEX events_shim_idempotency_keys_created ON events_shim_idempotency_keys(created_at);
