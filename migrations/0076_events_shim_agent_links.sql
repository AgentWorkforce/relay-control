-- Events shim (docs/events-shim.md, "Linking an inbox to a bound agent"): an inbox linked to one of its
-- creator's bound cloud agents (Capy binding, Replica, Amp binding). Each post reaches that agent as a relay
-- DM from the inbox's own hosted relay identity (sender_*; the token encrypted with the keyring).
-- binding_id, binding_generation and agent_remote_id pin the binding and the relay agent it was bound as, so a
-- reused name never receives posts. secret_hash is the sha256 of the inbox's wake-target secret.
-- No foreign key to events_shims: when an expired inbox is deleted, the row stays until the wake sweeper
-- releases its sender on the relay it was registered on.
CREATE TABLE events_shim_agent_links (
  shim_id uuid PRIMARY KEY,
  -- The inbox id again, under the name relaycast-rekey addresses rows by (sender_token_ciphertext is a Relaycast credential).
  id uuid GENERATED ALWAYS AS (shim_id) STORED NOT NULL UNIQUE,
  workspace_id uuid NOT NULL,
  user_id uuid NOT NULL,
  relaycast_workspace_id text NOT NULL,
  agent_name text NOT NULL,
  agent_kind text NOT NULL CHECK (agent_kind IN ('capy', 'replica', 'amp')),
  binding_id uuid NOT NULL,
  binding_generation integer,
  agent_remote_id text NOT NULL,
  sender_name text NOT NULL,
  sender_remote_id text NOT NULL,
  sender_token_ciphertext text NOT NULL,
  secret_hash text NOT NULL,
  linked_at timestamptz NOT NULL
);

-- Senders whose link row is gone (unlinked, replaced by a relink, or a link that failed) and whose
-- release did not succeed yet; the wake sweeper retries each until it is released or its Relaycast
-- workspace is no longer held by any workspace.
CREATE TABLE events_shim_sender_releases (
  sender_remote_id text PRIMARY KEY,
  sender_name text NOT NULL,
  relaycast_workspace_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
