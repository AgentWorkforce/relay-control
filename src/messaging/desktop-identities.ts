import { createHash, randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import { decryptSecret, encryptSecret, type EncryptionKeyring } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";
import { attestationKeyId, COPILOT_ATTESTATION_CAPABILITY, decodeBase64Url } from "../mcp/copilot-attestation.js";
import { MessagingHttpError } from "./http.js";
import { createRelaycastClient, RelaycastCallError, type RelaycastClient } from "./relaycast.js";

/**
 * Desktop identity sync, ported from Cloud's
 * `packages/web/app/api/v1/workspaces/[workspaceId]/messaging/desktop-identities/route.ts`
 * and `lib/messaging/desktop-identities.ts`.
 *
 * Agent Relay Desktop registers each native chat as a relay agent with its own
 * token (metadata.source "relay-desktop", owner_hash sha256(user id)) and
 * syncs that identity here so the MCP endpoint can act as it. A row is kept
 * only after Relaycast confirms the token controls exactly the named agent
 * and that the agent belongs to the caller. Tokens are encrypted at rest and
 * never returned. The optional Ed25519 attestation key verifies Copilot
 * tool-call proofs for that Desktop source.
 */

export const DESKTOP_SOURCE = "relay-desktop";
export const NATIVE_SESSION_IDENTITY_CAPABILITY_VERSION = 1;
export const COPILOT_SESSION_ATTESTATION_CAPABILITY_VERSION = 1;

/** What GET advertises. copilot_session_attestation exists because MCP verifies it (src/mcp/copilot-attestation.ts). */
export const DESKTOP_IDENTITY_CAPABILITIES = {
  native_session_identity: NATIVE_SESSION_IDENTITY_CAPABILITY_VERSION,
  copilot_session_attestation: COPILOT_SESSION_ATTESTATION_CAPABILITY_VERSION,
} as const;

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const uuid = z.string().regex(UUID).transform(value => value.toLowerCase());

const nativeSession = z.union([
  z.object({ kind: z.enum(["codex", "grok", "pi", "claude", "copilot"]), id: uuid }).strict(),
  z.object({ kind: z.literal("opencode"), id: z.string().regex(/^ses_[A-Za-z0-9]{4,128}$/) }).strict(),
]);

const identity = z.object({
  name: z.string().regex(NAME),
  address: z.string().min(3).max(512),
  agent_id: z.string().min(1).max(200),
  token: z.string().min(12).max(512),
  // Accepted for Cloud wire compatibility; self-host has no Claude web-session binding.
  web_session_id: z.string().max(200).optional(),
  native_session: nativeSession.optional(),
}).strict().refine(value => value.address.startsWith(`${value.name}@`), { message: "address must belong to name" });

const attestationKey = z.object({
  kid: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
  alg: z.literal("Ed25519"),
  public_key: z.string().max(64),
}).strict().refine(value => {
  const raw = decodeBase64Url(value.public_key);
  return Boolean(raw && raw.byteLength === 32 && attestationKeyId(raw) === value.kid);
}, { message: "attestation key does not match kid" });

const syncBody = z.object({
  source_id: uuid,
  identities: z.array(identity).max(200),
  attestation_key: attestationKey.optional(),
}).strict();

type Identity = z.infer<typeof identity>;
type AttestationKey = z.infer<typeof attestationKey>;

type Access = {
  principal: { userId: string; scopes: string[] };
  workspace: { id: string; organizationId: string; relaycastWorkspaceId: string; relaycastApiKey: string };
};

export const ownerHash = (userId: string) => createHash("sha256").update(userId).digest("hex");

const transient = (error: unknown) =>
  error instanceof RelaycastCallError && (error.status === 0 || error.status === 429 || error.status >= 500);
const refused = (error: unknown) =>
  error instanceof RelaycastCallError && (error.status === 401 || error.status === 403 || error.status === 404);

class SyncError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

type Verified = Identity & { remoteId: string };
type Skipped = { agent_id: string; reason: "unverified" | "not_owned" };

async function verify(client: RelaycastClient, access: Access, items: Identity[]): Promise<{ verified: Verified[]; skipped: Skipped[] }> {
  const owner = ownerHash(access.principal.userId);
  const verified: Verified[] = [];
  const skipped: Skipped[] = [];
  for (const item of items) {
    const [authenticated, remote] = await Promise.allSettled([
      client.authenticatedAgent(item.token),
      client.getAgent(access.workspace.relaycastApiKey, item.name),
    ]);
    if (authenticated.status === "rejected" && refused(authenticated.reason)) {
      skipped.push({ agent_id: item.agent_id, reason: "unverified" });
      continue;
    }
    for (const outcome of [authenticated, remote]) {
      if (outcome.status === "rejected") {
        if (transient(outcome.reason)) {
          throw new SyncError(503, "upstream_unavailable", "Agent Relay could not verify desktop identities right now. Try again shortly.");
        }
        throw outcome.reason;
      }
    }
    const auth = (authenticated as PromiseFulfilledResult<Awaited<ReturnType<RelaycastClient["authenticatedAgent"]>>>).value;
    const named = (remote as PromiseFulfilledResult<Awaited<ReturnType<RelaycastClient["getAgent"]>>>).value;
    if (!named || auth.id !== item.agent_id || auth.name !== item.name || auth.address !== item.address ||
        named.id !== item.agent_id || auth.metadata.source !== DESKTOP_SOURCE || named.metadata.source !== DESKTOP_SOURCE) {
      skipped.push({ agent_id: item.agent_id, reason: "unverified" });
      continue;
    }
    if (auth.metadata.owner_hash !== owner) {
      skipped.push({ agent_id: item.agent_id, reason: "not_owned" });
      continue;
    }
    verified.push({ ...item, remoteId: auth.id });
  }
  return { verified, skipped };
}

async function replace(
  database: Database,
  keyring: EncryptionKeyring,
  access: Access,
  sourceId: string,
  rows: Verified[],
  key: AttestationKey | undefined,
): Promise<void> {
  const { workspace, principal } = access;
  await database.transaction(async (tx: SqlExecutor) => {
    // Serialize syncs for one owner+source.
    await tx.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [`desktop-identities:${workspace.id}:${principal.userId}:${sourceId}`]);
    if (rows.length > 0) {
      const conflict = await tx.query<{ id: string }>(
        `SELECT id FROM desktop_relay_identities
          WHERE relaycast_workspace_id = $1 AND agent_remote_id = ANY($2::text[])
            AND NOT (workspace_id = $3 AND user_id = $4 AND source_id = $5)
          LIMIT 1`,
        [workspace.relaycastWorkspaceId, rows.map(row => row.remoteId), workspace.id, principal.userId, sourceId],
      );
      if (conflict.rows.length > 0) {
        throw new SyncError(409, "identity_conflict", "That relay identity is already synced by another owner or desktop.");
      }
    }
    await tx.query(
      `DELETE FROM desktop_relay_identities
        WHERE workspace_id = $1 AND user_id = $2 AND source_id = $3
          AND NOT (agent_remote_id = ANY($4::text[]) AND relaycast_workspace_id = $5)`,
      [workspace.id, principal.userId, sourceId, rows.map(row => row.remoteId), workspace.relaycastWorkspaceId],
    );
    for (const row of rows) {
      await tx.query(
        `INSERT INTO desktop_relay_identities
           (id, workspace_id, organization_id, user_id, relaycast_workspace_id, source_id, agent_name,
            agent_remote_id, address, token_ciphertext, native_session_kind, native_session_id)
         VALUES ($12, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (workspace_id, user_id, source_id, agent_remote_id) DO UPDATE
           SET relaycast_workspace_id = EXCLUDED.relaycast_workspace_id,
               agent_name = EXCLUDED.agent_name,
               address = EXCLUDED.address,
               token_ciphertext = EXCLUDED.token_ciphertext,
               native_session_kind = EXCLUDED.native_session_kind,
               native_session_id = EXCLUDED.native_session_id,
               updated_at = now()`,
        [
          workspace.id, workspace.organizationId, principal.userId, workspace.relaycastWorkspaceId, sourceId,
          row.name, row.remoteId, row.address, encryptSecret(row.token, keyring.active),
          row.native_session?.kind ?? null, row.native_session?.id ?? null, randomUUID(),
        ],
      );
    }
    await tx.query(
      `DELETE FROM desktop_attestation_keys WHERE workspace_id = $1 AND user_id = $2 AND source_id = $3`,
      [workspace.id, principal.userId, sourceId],
    );
    if (key && rows.length > 0) {
      await tx.query(
        `INSERT INTO desktop_attestation_keys (workspace_id, organization_id, user_id, source_id, kid, public_key)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [workspace.id, workspace.organizationId, principal.userId, sourceId, key.kid, key.public_key],
      );
    }
  });
}

export async function syncDesktopIdentities(input: {
  database: Database;
  keyring: EncryptionKeyring;
  client: RelaycastClient;
  access: Access;
  sourceId: string;
  identities: Identity[];
  attestationKey?: AttestationKey;
}): Promise<{ synced: number; skipped?: Skipped[]; identities: Array<{ agent_id: string; linked_mcp: null; linked_at: null }> }> {
  const { access } = input;
  if (input.identities.length === 0) {
    await replace(input.database, input.keyring, access, input.sourceId, [], undefined);
    return { synced: 0, identities: [] };
  }
  if (!access.workspace.relaycastWorkspaceId || !access.workspace.relaycastApiKey) {
    throw new SyncError(409, "relay_not_connected", "This workspace is not connected to Agent Relay.");
  }
  const addresses = new Set(input.identities.map(item => item.address));
  const ids = new Set(input.identities.map(item => item.agent_id));
  if (addresses.size !== input.identities.length || ids.size !== input.identities.length) {
    throw new SyncError(400, "invalid_request", "Desktop identities must have unique addresses and agent IDs.");
  }
  const { verified, skipped } = await verify(input.client, access, input.identities);
  await replace(input.database, input.keyring, access, input.sourceId, verified, input.attestationKey);
  return {
    synced: verified.length,
    ...(skipped.length > 0 ? { skipped } : {}),
    identities: verified.map(row => ({ agent_id: row.agent_id, linked_mcp: null, linked_at: null })),
  };
}

type JsonWriter = (response: ServerResponse, status: number, body: unknown, noStore?: boolean) => void;

export async function handleDesktopIdentityRoutes(
  request: IncomingMessage,
  response: ServerResponse,
  path: string,
  method: string,
  deps: {
    workspaceAccess: (request: IncomingMessage, workspaceId: string) => Promise<Access>;
    requestObject: (request: IncomingMessage) => Promise<Record<string, unknown>>;
    json: JsonWriter;
    database: Database;
    keyring: EncryptionKeyring;
    fetchImpl?: typeof fetch;
    relaycastUrl: string;
    /** True for a header bearer, or a /cloud cookie request from an allowed origin. */
    csrfAllowed: (request: IncomingMessage) => boolean;
  },
): Promise<boolean> {
  const match = /^\/api\/v1\/workspaces\/([^/]+)\/messaging\/desktop-identities$/.exec(path);
  if (!match) return false;
  if (method !== "GET" && method !== "PUT") {
    throw new MessagingHttpError(405, "method_not_allowed", "Method not allowed");
  }
  let workspaceId: string;
  try {
    workspaceId = decodeURIComponent(match[1]!);
  } catch {
    throw new MessagingHttpError(404, "workspace_not_found", "Workspace not found");
  }
  const access = await deps.workspaceAccess(request, workspaceId);
  if (!access.principal.scopes.includes("cli:auth")) {
    throw new MessagingHttpError(403, "forbidden", "Desktop identities require a browser session or cli:auth");
  }

  if (method === "GET") {
    const sourceId = new URL(request.url ?? "/", "http://local").searchParams.get("source_id");
    if (!sourceId || !UUID.test(sourceId)) {
      throw new MessagingHttpError(400, "invalid_request", "source_id must be a UUID");
    }
    try {
      const rows = await deps.database.query<{ agent_remote_id: string }>(
        `SELECT agent_remote_id FROM desktop_relay_identities
          WHERE workspace_id = $1 AND user_id = $2 AND source_id = $3 AND relaycast_workspace_id = $4
          ORDER BY created_at, agent_remote_id`,
        [access.workspace.id, access.principal.userId, sourceId.toLowerCase(), access.workspace.relaycastWorkspaceId],
      );
      deps.json(response, 200, {
        identities: rows.rows.map(row => ({ agent_id: row.agent_remote_id, linked_mcp: null, linked_at: null })),
        capabilities: DESKTOP_IDENTITY_CAPABILITIES,
      }, true);
    } catch {
      throw new MessagingHttpError(502, "upstream_unavailable", "Desktop identity links are unavailable");
    }
    return true;
  }

  if (!deps.csrfAllowed(request)) {
    throw new MessagingHttpError(403, "csrf_rejected", "Cross-origin desktop identity sync refused");
  }
  const parsed = syncBody.safeParse(await deps.requestObject(request));
  if (!parsed.success) throw new MessagingHttpError(400, "invalid_request", "Invalid desktop identity sync");
  const client = createRelaycastClient({ internalOrigin: deps.relaycastUrl, fetchImpl: deps.fetchImpl });
  try {
    const result = await syncDesktopIdentities({
      database: deps.database,
      keyring: deps.keyring,
      client,
      access,
      sourceId: parsed.data.source_id,
      identities: parsed.data.identities,
      attestationKey: parsed.data.attestation_key,
    });
    deps.json(response, 200, result, true);
  } catch (error) {
    if (error instanceof SyncError) throw new MessagingHttpError(error.status, error.code, error.message);
    throw new MessagingHttpError(502, "upstream_unavailable", "Desktop identity sync failed");
  }
  return true;
}

export class DesktopIdentityUnavailable extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DesktopIdentityUnavailable";
  }
}

export const DESKTOP_IDENTITY_MESSAGES = {
  unverified: "Agent Relay cannot verify this chat's desktop identity. Keep the app open and retry after session registration.",
  duplicate: "This chat is synced by multiple desktops. Resolve the duplicate before using relay tools.",
  sourceMismatch: "The native chat does not match this desktop identity.",
  otherRelay: "The desktop identity does not belong to this workspace's current relay.",
  gone: "The synced desktop identity is no longer available. Open Agent Relay Desktop to re-sync it.",
  notSynced: "This native chat is not synced to your desktop account and workspace.",
} as const;

export type LinkedDesktopIdentity = { name: string; address: string; agentId: string; token: string };

/**
 * The synced identity one verified native chat acts as. Re-checks the stored
 * token with Relaycast on every call (still the same relay-desktop agent,
 * still owned by this user). Throws DesktopIdentityUnavailable; never falls
 * back to a hosted participant.
 */
export async function linkedDesktopIdentity(input: {
  database: SqlExecutor;
  keyring: EncryptionKeyring;
  client: RelaycastClient;
  workspaceId: string;
  userId: string;
  relaycastWorkspaceId: string;
  nativeSession: { kind: string; id: string };
  sourceId?: string;
}): Promise<LinkedDesktopIdentity> {
  const result = await input.database.query<{
    source_id: string;
    relaycast_workspace_id: string;
    agent_name: string;
    agent_remote_id: string;
    address: string;
    token_ciphertext: string;
  }>(
    `SELECT source_id, relaycast_workspace_id, agent_name, agent_remote_id, address, token_ciphertext
       FROM desktop_relay_identities
      WHERE workspace_id = $1 AND user_id = $2 AND native_session_kind = $3 AND native_session_id = $4`,
    [input.workspaceId, input.userId, input.nativeSession.kind, input.nativeSession.id],
  );
  if (result.rows.length > 1) throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.duplicate);
  const row = result.rows[0];
  if (!row) throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.notSynced);
  if (input.sourceId !== undefined && row.source_id !== input.sourceId) {
    throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.sourceMismatch);
  }
  if (row.relaycast_workspace_id !== input.relaycastWorkspaceId) {
    throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.otherRelay);
  }
  let token: string;
  try {
    token = decryptSecret(row.token_ciphertext, input.keyring);
  } catch {
    throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.gone);
  }
  let agent;
  try {
    agent = await input.client.authenticatedAgent(token);
  } catch (error) {
    if (refused(error)) throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.gone);
    throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.unverified);
  }
  if (agent.id !== row.agent_remote_id || agent.name !== row.agent_name || agent.address !== row.address ||
      agent.metadata.source !== DESKTOP_SOURCE || agent.metadata.owner_hash !== ownerHash(input.userId)) {
    throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.gone);
  }
  return { name: row.agent_name, address: row.address, agentId: row.agent_remote_id, token };
}

export { COPILOT_ATTESTATION_CAPABILITY };
