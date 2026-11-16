// Synthetic stand-in for the Cloud `public` tables the import reads. Columns
// follow Cloud's drizzle schema (packages/core/src/db/schema.ts and
// packages/web/lib/db/schema.ts) for the columns the mapping uses. Every value
// below is invented test data.
import { createCipheriv, randomBytes } from "node:crypto";

export const CLOUD_FIXTURE_DDL = `
CREATE TABLE users (
  id uuid PRIMARY KEY, primary_email text, name text, avatar_url text,
  last_organization_id uuid, last_workspace_id uuid,
  created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE TABLE auth_identities (
  id uuid PRIMARY KEY, user_id uuid NOT NULL, provider text NOT NULL, provider_user_id text NOT NULL,
  email text, email_verified boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE TABLE organizations (
  id uuid PRIMARY KEY, slug text NOT NULL UNIQUE, name text NOT NULL, created_by_user_id uuid NOT NULL,
  created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE TABLE organization_memberships (
  organization_id uuid NOT NULL, user_id uuid NOT NULL, role text NOT NULL, status text NOT NULL,
  joined_at timestamptz NOT NULL, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, user_id)
);
CREATE TABLE workspaces (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL, slug text NOT NULL, name text NOT NULL,
  default_runtime jsonb, relay_workspace_id text, relayhistory_origin text, relayhistory_dashboard_url text,
  deletion_requested_at timestamptz,
  created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE TABLE relay_workspaces (
  id text PRIMARY KEY, owner_user_id uuid NOT NULL, name text NOT NULL,
  relaycast_api_key text NOT NULL DEFAULT '', relaycast_api_key_generation integer NOT NULL DEFAULT 1,
  relaycast_workspace_id text UNIQUE,
  permissions_json text NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE TABLE organization_invites (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL, email text NOT NULL, role text NOT NULL,
  token text NOT NULL UNIQUE, invited_by_user_id uuid NOT NULL, expires_at timestamptz NOT NULL,
  accepted_at timestamptz, canceled_at timestamptz,
  created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE TABLE workspace_person_identities (
  id uuid PRIMARY KEY, workspace_id uuid NOT NULL, user_id uuid NOT NULL, relay_workspace_id text NOT NULL,
  agent_name text NOT NULL, agent_remote_id text NOT NULL, token_envelope jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE hosted_relay_participants (
  id uuid PRIMARY KEY, workspace_id uuid NOT NULL, user_id uuid NOT NULL, relay_workspace_id text NOT NULL,
  session_hash text, agent_name text NOT NULL, agent_remote_id text NOT NULL, token_envelope jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE desktop_relay_identities (
  id uuid PRIMARY KEY, workspace_id uuid NOT NULL, user_id uuid NOT NULL, relay_workspace_id text NOT NULL,
  source_id text NOT NULL, agent_name text NOT NULL, agent_remote_id text NOT NULL, address text NOT NULL,
  native_session_kind text, native_session_id text, token_envelope jsonb NOT NULL, web_session_id text,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE provider_credentials (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL, workspace_id uuid NOT NULL, user_id uuid NOT NULL,
  harness text NOT NULL, model_provider text NOT NULL DEFAULT '', auth_type text NOT NULL DEFAULT 'provider_oauth',
  label text, key_fingerprint text, display_name text NOT NULL, account_email text,
  is_active boolean NOT NULL DEFAULT false, harness_active boolean NOT NULL DEFAULT false, status text NOT NULL,
  last_authenticated_at timestamptz, last_used_at timestamptz, last_error text,
  created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE TABLE fleet_node_owners (
  id uuid PRIMARY KEY, workspace_id uuid NOT NULL, relay_workspace_id text NOT NULL, node_id text NOT NULL,
  user_id uuid NOT NULL, source text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
`;

/** Cloud's credential envelope (packages/core/src/auth/credential-encryption.ts). */
export function cloudEnvelope(plaintext: string, hexKey: string): { v: 1; iv: string; tag: string; ciphertext: string } {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(hexKey, "hex"), iv, { authTagLength: 16 });
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return { v: 1, iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex"), ciphertext: ciphertext.toString("base64") };
}

/** Deterministic synthetic UUIDs: id(1) -> 00000000-0000-4000-8000-000000000001. */
export const id = (n: number) => `00000000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;

export const ORG_A = id(0xa1);
export const ORG_B = id(0xb1);

/**
 * Seed SQL covering every skip rule once. Returns the statements and the
 * expected import outcome so tests can assert it.
 */
export function cloudFixtureSeed(cloudHexKey: string, staleKey = randomBytes(32).toString("hex")): string {
  const env = (token: string, key = cloudHexKey) => `'${JSON.stringify(cloudEnvelope(token, key))}'::jsonb`;
  const t = "'2026-01-01T00:00:00.123456Z'";
  return `
INSERT INTO users (id, primary_email, name, last_organization_id, last_workspace_id, created_at, updated_at) VALUES
  ('${id(1)}', ' Alice@Example.TEST ', 'Alice', '${ORG_A}', '${id(0x201)}', ${t}, ${t}),
  ('${id(2)}', 'bob@example.test', NULL, NULL, NULL, ${t}, ${t}),
  ('${id(3)}', NULL, 'Carol', NULL, NULL, ${t}, ${t}),
  ('${id(4)}', NULL, 'No Email', NULL, NULL, ${t}, ${t}),
  ('${id(5)}', 'ALICE@example.test', 'Alice dup', '${ORG_B}', NULL, '2026-02-01T00:00:00Z', ${t}),
  ('${id(6)}', 'dave@example.test', 'Dave', NULL, NULL, ${t}, ${t});
INSERT INTO auth_identities (id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at) VALUES
  ('${id(0x31)}', '${id(3)}', 'google', 'g-3', 'Carol@Example.test', true, ${t}, ${t}),
  ('${id(0x41)}', '${id(4)}', 'google', 'g-4', 'not-an-email', true, ${t}, ${t});
INSERT INTO organizations (id, slug, name, created_by_user_id, created_at, updated_at) VALUES
  ('${ORG_A}', 'org-a', 'Org A', '${id(1)}', ${t}, ${t}),
  ('${ORG_B}', 'org-b', 'Org B', '${id(2)}', ${t}, ${t});
INSERT INTO organization_memberships (organization_id, user_id, role, status, joined_at, created_at, updated_at) VALUES
  ('${ORG_A}', '${id(1)}', 'owner', 'active', ${t}, ${t}, ${t}),
  ('${ORG_A}', '${id(2)}', 'member', 'active', ${t}, ${t}, ${t}),
  ('${ORG_A}', '${id(3)}', 'admin', 'active', ${t}, ${t}, ${t}),
  ('${ORG_A}', '${id(4)}', 'member', 'active', ${t}, ${t}, ${t}),
  ('${ORG_A}', '${id(6)}', 'member', 'suspended', ${t}, ${t}, ${t}),
  ('${ORG_B}', '${id(2)}', 'owner', 'active', ${t}, ${t}, ${t}),
  ('${ORG_B}', '${id(1)}', 'member', 'active', ${t}, ${t}, ${t}),
  ('${ORG_B}', '${id(5)}', 'admin', 'active', ${t}, ${t}, ${t}),
  ('${ORG_B}', '${id(6)}', 'billing', 'active', ${t}, ${t}, ${t});
INSERT INTO relay_workspaces (id, owner_user_id, name, relaycast_api_key, relaycast_workspace_id, created_at, updated_at) VALUES
  ('rw_0000a201', '${id(1)}', 'a1', 'rk_live_synthetic_a1', 'rc-ws-a1', ${t}, ${t}),
  ('rw_0000a202', '${id(1)}', 'a2', '', 'rc-ws-a2', ${t}, ${t}),
  ('rw_0000b201', '${id(2)}', 'b1', 'rk_live_synthetic_b1', 'rc-ws-b1', ${t}, ${t}),
  ('rw_legacy-01', '${id(2)}', 'b2', 'rk_live_synthetic_b2', 'rc-ws-b2', ${t}, ${t});
INSERT INTO workspaces (id, organization_id, slug, name, default_runtime, relay_workspace_id, relayhistory_origin, deletion_requested_at, created_at, updated_at) VALUES
  ('${id(0x201)}', '${ORG_A}', 'a1', 'A one', '{"id":"sandbox","config":{"size":2}}', 'rw_0000a201', 'https://History.Example.test/', NULL, ${t}, ${t}),
  ('${id(0x202)}', '${ORG_A}', 'a2', 'A two (no key)', NULL, 'rw_0000a202', NULL, NULL, ${t}, ${t}),
  ('${id(0x203)}', '${ORG_A}', 'a3', 'A three (unbound)', NULL, NULL, NULL, NULL, ${t}, ${t}),
  ('${id(0x204)}', '${ORG_A}', 'a4', 'A four (deleting)', NULL, 'rw_0000a201', NULL, ${t}, ${t}, ${t}),
  ('${id(0x205)}', '${ORG_B}', 'b1', 'B one', NULL, 'rw_0000b201', NULL, NULL, ${t}, ${t}),
  ('${id(0x206)}', '${ORG_B}', 'b2', 'B legacy rw', NULL, 'rw_legacy-01', NULL, NULL, ${t}, ${t});
INSERT INTO organization_invites (id, organization_id, email, role, token, invited_by_user_id, expires_at, accepted_at, canceled_at, created_at, updated_at) VALUES
  ('${id(0x301)}', '${ORG_A}', 'New@Example.test', 'member', 'tok-1', '${id(1)}', '2030-01-01T00:00:00Z', NULL, NULL, ${t}, ${t}),
  ('${id(0x302)}', '${ORG_A}', 'new@example.test', 'admin', 'tok-2', '${id(5)}', '2030-01-01T00:00:00Z', NULL, NULL, '2026-03-01T00:00:00Z', ${t}),
  ('${id(0x303)}', '${ORG_A}', 'bob@example.test', 'member', 'tok-3', '${id(1)}', '2030-01-01T00:00:00Z', NULL, NULL, ${t}, ${t}),
  ('${id(0x304)}', '${ORG_A}', 'gone@example.test', 'member', 'tok-4', '${id(1)}', '2030-01-01T00:00:00Z', NULL, ${t}, ${t}, ${t}),
  ('${id(0x305)}', '${ORG_B}', 'erin@example.test', 'member', 'tok-5', '${id(4)}', '2030-01-01T00:00:00Z', NULL, NULL, ${t}, ${t});
INSERT INTO workspace_person_identities (id, workspace_id, user_id, relay_workspace_id, agent_name, agent_remote_id, token_envelope, created_at, updated_at) VALUES
  ('${id(0x401)}', '${id(0x201)}', '${id(1)}', 'rw_0000a201', 'alice', 'ag-1', ${env("tok_person_alice")}, ${t}, ${t}),
  ('${id(0x402)}', '${id(0x202)}', '${id(2)}', 'rw_0000a202', 'bob', 'ag-2', ${env("tok_person_bob")}, ${t}, ${t}),
  ('${id(0x403)}', '${id(0x205)}', '${id(2)}', 'rw_0000b201', 'bob', 'ag-3', ${env("tok_person_bob_b", staleKey)}, ${t}, ${t});
INSERT INTO hosted_relay_participants (id, workspace_id, user_id, relay_workspace_id, session_hash, agent_name, agent_remote_id, token_envelope, created_at) VALUES
  ('${id(0x501)}', '${id(0x205)}', '${id(1)}', 'rw_0000b201', 'sh-1', 'alice-mcp', 'ag-5', ${env("tok_hosted_1")}, ${t}),
  ('${id(0x502)}', '${id(0x205)}', '${id(5)}', 'rw_0000b201', NULL, 'alice-mcp', 'ag-6', ${env("tok_hosted_2")}, '2026-01-02T00:00:00Z'),
  ('${id(0x503)}', '${id(0x201)}', '${id(2)}', 'rw_0000beef', NULL, 'bob-mcp', 'ag-7', ${env("tok_hosted_3")}, ${t});
INSERT INTO desktop_relay_identities (id, workspace_id, user_id, relay_workspace_id, source_id, agent_name, agent_remote_id, address, native_session_kind, native_session_id, token_envelope, created_at, updated_at) VALUES
  ('${id(0x601)}', '${id(0x201)}', '${id(1)}', 'rw_0000a201', '${id(0x9001).toUpperCase()}', 'alice-desk', 'ag-8', 'alice-desk@host', 'copilot', 'chat-1', ${env("tok_desk_1")}, ${t}, ${t}),
  ('${id(0x602)}', '${id(0x201)}', '${id(2)}', 'rw_0000a201', 'not-a-uuid', 'bob-desk', 'ag-9', 'bob-desk@host', 'copilot', NULL, ${env("tok_desk_2")}, ${t}, ${t}),
  ('${id(0x603)}', '${id(0x201)}', '${id(6)}', 'rw_0000a201', '${id(0x9003)}', 'dave-desk', 'ag-10', 'dave-desk@host', NULL, NULL, ${env("tok_desk_3")}, ${t}, ${t});
INSERT INTO provider_credentials (id, organization_id, workspace_id, user_id, harness, model_provider, auth_type, display_name, is_active, harness_active, status, created_at, updated_at) VALUES
  ('${id(0x801)}', '${ORG_A}', '${id(0x201)}', '${id(1)}', 'claude', 'anthropic', 'relay_managed', 'Relay Claude', true, true, 'connected', ${t}, '2026-01-03T00:00:00Z'),
  ('${id(0x802)}', '${ORG_A}', '${id(0x201)}', '${id(2)}', 'claude', 'anthropic', 'relay_managed', 'Relay Claude (bob)', true, false, 'connected', ${t}, ${t}),
  ('${id(0x803)}', '${ORG_A}', '${id(0x201)}', '${id(1)}', 'codex', 'openai', 'byo_api_key', 'My key', true, false, 'connected', ${t}, ${t}),
  ('${id(0x804)}', '${ORG_A}', '${id(0x202)}', '${id(1)}', 'claude', 'anthropic', 'relay_managed', 'Unbound', false, false, 'connected', ${t}, ${t});
INSERT INTO fleet_node_owners (id, workspace_id, relay_workspace_id, node_id, user_id, source, created_at) VALUES
  ('${id(0x701)}', '${id(0x201)}', 'rw_0000a201', 'node-1', '${id(3)}', 'claim', ${t}),
  ('${id(0x702)}', '${id(0x203)}', 'rw_0000a203', 'node-2', '${id(1)}', 'claim', ${t});
`;
}

/**
 * Expected outcome of importing the full fixture (every org).
 * imported = rows written; skipped = reason -> count.
 */
export const EXPECTED_FULL: Record<string, { imported: number; skipped: Record<string, number> }> = {
  users: { imported: 4, skipped: { no_valid_email: 1, merged_into_survivor: 1 } },
  organizations: { imported: 2, skipped: {} },
  organization_memberships: {
    imported: 5,
    skipped: { user_not_imported: 1, inactive_membership: 1, unsupported_role: 1, merged_duplicate_membership: 1 },
  },
  workspaces: {
    imported: 3,
    skipped: { no_relaycast_key: 1, no_relay_workspace: 1, workspace_being_deleted: 1 },
  },
  organization_invitations: {
    imported: 2,
    skipped: { superseded_open_invite: 1, already_member: 1, canceled: 1 },
  },
  person_identities: { imported: 1, skipped: { workspace_not_imported: 1, cloud_decrypt_failed: 1 } },
  hosted_relay_participants: { imported: 1, skipped: { duplicate_after_merge: 1, stale_relay_workspace: 1 } },
  desktop_relay_identities: { imported: 1, skipped: { source_id_not_uuid: 1, not_a_member: 1 } },
  fleet_node_owners: { imported: 1, skipped: { workspace_not_imported: 1 } },
  // Pre-0058 target: the two relay_managed rows are refused by the importer.
  coding_agent_credentials: {
    imported: 0,
    skipped: { workspace_not_imported: 1, secret_in_cloud_credential_store: 1, target_lacks_relay_managed: 2 },
  },
};
