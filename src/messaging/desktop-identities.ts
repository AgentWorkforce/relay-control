import { createHash, randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import { decryptSecret, encryptSecret, type EncryptionKeyring } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";
import { normalizeDesktopSourceId } from "../desktop-source-id.js";
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
 * never returned. The optional Ed25519 attestation key verifies Claude Code
 * and Copilot tool-call proofs for that Desktop source.
 *
 * Gate-only installs (relaygatePublicUrl set): the Desktop enrols each chat
 * at relaygate and holds an rg_ token. relaygate's GET /v1/whoami then
 * confirms the token (agent id, name and, when relaygate reports it, the
 * enrolling user); whoami is the proof. The upstream Relaycast agent card of
 * that name is advisory: relaygate stamps metadata.relaygate.agent_id only
 * when it first registers the upstream agent (a takeover or a metadata
 * update can leave it missing), so the card may be absent or lack the field,
 * and only a field naming a different agent id rejects the identity. The
 * stored agent_remote_id is relaygate's agent id.
 *
 * Every skipped or rejected identity logs "desktop identity skipped" with
 * the agent name, reason and failed check; never the token.
 *
 * A hosted MCP session links to one synced identity with join_relay
 * desktop_address (table desktop_relay_session_bindings, migration 0035);
 * sync reports that link back to the Desktop as linked_mcp / linked_at.
 */

export const DESKTOP_SOURCE = "relay-desktop";
/** Cloud's LINKED_MCP: what identity sync reports for an identity a hosted MCP session is linked to. */
export const LINKED_MCP = "agent-relay-sessions";
export const NATIVE_SESSION_IDENTITY_CAPABILITY_VERSION = 1;
export const CLAUDE_SESSION_ATTESTATION_CAPABILITY_VERSION = 1;
export const COPILOT_SESSION_ATTESTATION_CAPABILITY_VERSION = 1;
export const CURSOR_SESSION_ATTESTATION_CAPABILITY_VERSION = 1;

/**
 * What GET advertises. Each attestation flag exists because MCP verifies and
 * enforces that proof (src/mcp/claude-attestation.ts, src/mcp/copilot-attestation.ts).
 */
export const DESKTOP_IDENTITY_CAPABILITIES = {
  native_session_identity: NATIVE_SESSION_IDENTITY_CAPABILITY_VERSION,
  claude_session_attestation: CLAUDE_SESSION_ATTESTATION_CAPABILITY_VERSION,
  copilot_session_attestation: COPILOT_SESSION_ATTESTATION_CAPABILITY_VERSION,
  cursor_session_attestation: CURSOR_SESSION_ATTESTATION_CAPABILITY_VERSION,
} as const;

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const uuid = z.string().regex(UUID).transform(value => value.toLowerCase());
const sourceId = z.string().min(1).max(200).transform(normalizeDesktopSourceId);

const nativeSession = z.union([
  z.object({ kind: z.enum(["codex", "grok", "pi", "claude", "copilot", "cursor"]), id: uuid }).strict(),
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
  source_id: sourceId,
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
/** Why one identity was skipped: the public reason plus the failed check (logged only, never returned). */
type SkipCause = { reason: Skipped["reason"]; check: string; status?: number };

/** Operator log sink; fields never carry a token, a whoami body or any secret. */
export type DesktopIdentityLog = (message: string, fields: Record<string, unknown>) => void;
export const DESKTOP_IDENTITY_SKIPPED = "desktop identity skipped";
const defaultLog: DesktopIdentityLog = (message, fields) => console.warn(`[selfhost-api] ${message}`, fields);

/** The first failing check of an ordered [failed, check] list, or null. */
function firstFailed(checks: Array<readonly [boolean, string]>): string | null {
  for (const [failed, check] of checks) if (failed) return check;
  return null;
}

/** The upstream HTTP status of a refused Relaycast or relaygate call, else undefined. */
const refusedStatus = (error: unknown) => (error instanceof RelaycastCallError ? error.status : undefined);

/** The relaygate agent id on an upstream Relaycast agent card (metadata.relaygate.agent_id), or null. */
export function relaygateAgentId(metadata: Record<string, unknown>): string | null {
  const gate = metadata.relaygate;
  if (!gate || typeof gate !== "object" || Array.isArray(gate)) return null;
  const id = (gate as Record<string, unknown>).agent_id;
  return typeof id === "string" && id.length > 0 ? id : null;
}

function unavailable(outcomes: PromiseSettledResult<unknown>[]): void {
  for (const outcome of outcomes) {
    if (outcome.status === "rejected") {
      if (transient(outcome.reason)) {
        throw new SyncError(503, "upstream_unavailable", "Agent Relay could not verify desktop identities right now. Try again shortly.");
      }
      throw outcome.reason;
    }
  }
}

/**
 * Gate-only installs: the Desktop enrolled the chat at relaygate and holds an
 * rg_ token Relaycast does not accept. relaygate's whoami is the proof: it
 * must name the same agent id and name (and the caller, once relaygate
 * reports user_id). The upstream Relaycast agent card is checked only when it
 * carries metadata.relaygate.agent_id: a different id there rejects the
 * identity; a missing card or field does not (relaygate stamps it only on
 * first registration).
 */
async function verifyGated(
  gate: RelaycastClient, client: RelaycastClient, access: Access, item: Identity,
): Promise<SkipCause | null> {
  const [whoami, remote] = await Promise.allSettled([
    gate.whoami(item.token),
    client.getAgent(access.workspace.relaycastApiKey, item.name),
  ]);
  if (whoami.status === "rejected" && refused(whoami.reason)) {
    const status = refusedStatus(whoami.reason);
    return { reason: "unverified", check: `whoami_refused:${status}`, ...(status !== undefined ? { status } : {}) };
  }
  unavailable([whoami, remote]);
  const who = (whoami as PromiseFulfilledResult<Awaited<ReturnType<RelaycastClient["whoami"]>>>).value;
  const named = (remote as PromiseFulfilledResult<Awaited<ReturnType<RelaycastClient["getAgent"]>>>).value;
  if (who.agentId !== item.agent_id) return { reason: "unverified", check: "whoami_agent_id" };
  if (who.name !== item.name) return { reason: "unverified", check: "whoami_name" };
  if (who.userId !== null && who.userId !== access.principal.userId) return { reason: "not_owned", check: "whoami_user_id" };
  const carded = named ? relaygateAgentId(named.metadata) : null;
  if (carded !== null && carded !== item.agent_id) return { reason: "unverified", check: "card_relaygate_agent_id" };
  return null;
}

async function verify(
  client: RelaycastClient, access: Access, items: Identity[], gate: RelaycastClient | undefined,
  log: DesktopIdentityLog | undefined, sourceId: string,
): Promise<{ verified: Verified[]; skipped: Skipped[] }> {
  const owner = ownerHash(access.principal.userId);
  const verified: Verified[] = [];
  const skipped: Skipped[] = [];
  const skip = (item: Identity, cause: SkipCause) => {
    skipped.push({ agent_id: item.agent_id, reason: cause.reason });
    log?.(DESKTOP_IDENTITY_SKIPPED, {
      workspace_id: access.workspace.id, user_id: access.principal.userId, source_id: sourceId,
      agent_name: item.name, agent_id: item.agent_id, reason: cause.reason, check: cause.check,
      ...(cause.status !== undefined ? { status: cause.status } : {}),
    });
  };
  for (const item of items) {
    if (gate) {
      const cause = await verifyGated(gate, client, access, item);
      if (cause) skip(item, cause);
      else verified.push({ ...item, remoteId: item.agent_id });
      continue;
    }
    const [authenticated, remote] = await Promise.allSettled([
      client.authenticatedAgent(item.token),
      client.getAgent(access.workspace.relaycastApiKey, item.name),
    ]);
    if (authenticated.status === "rejected" && refused(authenticated.reason)) {
      const status = refusedStatus(authenticated.reason);
      skip(item, { reason: "unverified", check: `authenticated_refused:${status}`, ...(status !== undefined ? { status } : {}) });
      continue;
    }
    unavailable([authenticated, remote]);
    const auth = (authenticated as PromiseFulfilledResult<Awaited<ReturnType<RelaycastClient["authenticatedAgent"]>>>).value;
    const named = (remote as PromiseFulfilledResult<Awaited<ReturnType<RelaycastClient["getAgent"]>>>).value;
    const unverified = firstFailed([
      [!named, "card_missing"],
      [auth.id !== item.agent_id || named?.id !== item.agent_id, "agent_id"],
      [auth.name !== item.name, "name"],
      [auth.address !== item.address, "address"],
      [auth.metadata.source !== DESKTOP_SOURCE || named?.metadata.source !== DESKTOP_SOURCE, "source"],
    ]);
    if (unverified) {
      skip(item, { reason: "unverified", check: unverified });
      continue;
    }
    if (auth.metadata.owner_hash !== owner) {
      skip(item, { reason: "not_owned", check: "owner_hash" });
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
  /** Gate-only installs: the client bound to relaygate's origin; identities then hold rg_ tokens. */
  gate?: RelaycastClient;
  access: Access;
  sourceId: string;
  identities: Identity[];
  attestationKey?: AttestationKey;
  /** Logs each skipped identity ("desktop identity skipped"); never given the token. */
  log?: DesktopIdentityLog;
}): Promise<{ synced: number; skipped?: Skipped[]; identities: DesktopIdentityLink[] }> {
  const { access } = input;
  const source = normalizeDesktopSourceId(input.sourceId);
  if (input.identities.length === 0) {
    await replace(input.database, input.keyring, access, source, [], undefined);
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
  const { verified, skipped } = await verify(input.client, access, input.identities, input.gate, input.log, source);
  await replace(input.database, input.keyring, access, source, verified, input.attestationKey);
  const links = await desktopIdentityLinks(input.database, access.workspace.id, access.principal.userId, source);
  return {
    synced: verified.length,
    ...(skipped.length > 0 ? { skipped } : {}),
    identities: reportLinks(verified.map(row => row.remoteId), links),
  };
}

export type DesktopIdentityLink = { agent_id: string; linked_mcp: typeof LINKED_MCP | null; linked_at: string | null };

/** The newest hosted MCP session link of each identity one Desktop source has synced, by agent id. */
async function desktopIdentityLinks(database: SqlExecutor, workspaceId: string, userId: string, sourceId: string) {
  const rows = await database.query<{ agent_remote_id: string; linked_at: Date | string }>(
    `SELECT i.agent_remote_id, max(b.created_at) AS linked_at
       FROM desktop_relay_session_bindings b
       JOIN desktop_relay_identities i ON i.id = b.desktop_identity_id
      WHERE b.workspace_id = $1 AND b.user_id = $2
        AND i.workspace_id = $1 AND i.user_id = $2 AND i.source_id = $3
      GROUP BY i.agent_remote_id`,
    [workspaceId, userId, sourceId],
  );
  return new Map(rows.rows.map(row => [row.agent_remote_id, new Date(row.linked_at)] as const));
}

function reportLinks(agentIds: string[], links: Map<string, Date>): DesktopIdentityLink[] {
  return agentIds.map(agentId => {
    const linkedAt = links.get(agentId);
    return { agent_id: agentId, linked_mcp: linkedAt ? LINKED_MCP : null, linked_at: linkedAt?.toISOString() ?? null };
  });
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
    /** Gate-only installs: relaygate's public URL; desktop identities are then verified through it. */
    relaygatePublicUrl?: string | null;
    /** True for a header bearer, or a /cloud cookie request from an allowed origin. */
    csrfAllowed: (request: IncomingMessage) => boolean;
    /** Logs each skipped identity; defaults to console.warn with the [selfhost-api] prefix. */
    log?: DesktopIdentityLog;
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
    const parsedSourceId = sourceId.safeParse(new URL(request.url ?? "/", "http://local").searchParams.get("source_id"));
    if (!parsedSourceId.success) {
      throw new MessagingHttpError(400, "invalid_request", "source_id must be 1 to 200 characters");
    }
    const source = parsedSourceId.data;
    try {
      const rows = await deps.database.query<{ agent_remote_id: string }>(
        `SELECT agent_remote_id FROM desktop_relay_identities
          WHERE workspace_id = $1 AND user_id = $2 AND source_id = $3 AND relaycast_workspace_id = $4
          ORDER BY created_at, agent_remote_id`,
        [access.workspace.id, access.principal.userId, source, access.workspace.relaycastWorkspaceId],
      );
      const links = await desktopIdentityLinks(deps.database, access.workspace.id, access.principal.userId, source);
      deps.json(response, 200, {
        identities: reportLinks(rows.rows.map(row => row.agent_remote_id), links),
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
  const gate = deps.relaygatePublicUrl
    ? createRelaycastClient({ internalOrigin: deps.relaygatePublicUrl, fetchImpl: deps.fetchImpl })
    : undefined;
  try {
    const result = await syncDesktopIdentities({
      database: deps.database,
      keyring: deps.keyring,
      client,
      ...(gate ? { gate } : {}),
      access,
      sourceId: parsed.data.source_id,
      identities: parsed.data.identities,
      attestationKey: parsed.data.attestation_key,
      log: deps.log ?? defaultLog,
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
  unverified: "Agent Relay cannot verify this chat's desktop identity. This call does not say which registered chat made it. "
    + "Relay tools act as a chat only after Agent Relay Desktop has registered that chat on this computer and the chat calls "
    + "through Desktop's integration for its client. Turn that integration on in Agent Relay Desktop (or reconnect it), then retry from this chat.",
  cursorUnverified: "Agent Relay cannot verify this chat's desktop identity. This Cursor call carried no signed chat proof. "
    + "A Cursor chat sends and reads relay messages as its own agent only through Agent Relay Desktop's Cursor helper: turn on "
    + "the Cursor integration in Agent Relay Desktop so Cursor's agent-relay MCP server runs the helper and the chat is registered, "
    + "then retry from this chat.",
  duplicate: "This chat is synced by multiple desktops. Resolve the duplicate before using relay tools.",
  sourceMismatch: "The native chat does not match this desktop identity.",
  otherRelay: "The desktop identity does not belong to this workspace's current relay.",
  gone: "The synced desktop identity is no longer available. Open Agent Relay Desktop to re-sync it.",
  notSynced: "This native chat is not synced to your desktop account and workspace. Agent Relay Desktop registers and syncs a chat "
    + "when the chat starts through its integration; check the app is signed in to this workspace, then retry.",
} as const;

export type LinkedDesktopIdentity = { id: string; name: string; address: string; agentId: string; token: string };

/** One owner's stored desktop identity row; the token stays encrypted until verified. */
export type DesktopIdentityRow = {
  id: string;
  sourceId: string;
  relaycastWorkspaceId: string;
  agentName: string;
  agentRemoteId: string;
  address: string;
  tokenCiphertext: string;
};

const IDENTITY_COLUMNS = `i.id, i.source_id, i.relaycast_workspace_id, i.agent_name, i.agent_remote_id, i.address, i.token_ciphertext`;

function identityRow(row: Record<string, unknown>): DesktopIdentityRow {
  return {
    id: String(row.id),
    sourceId: String(row.source_id),
    relaycastWorkspaceId: String(row.relaycast_workspace_id),
    agentName: String(row.agent_name),
    agentRemoteId: String(row.agent_remote_id),
    address: String(row.address),
    tokenCiphertext: String(row.token_ciphertext),
  };
}

/** This owner's synced identity at an exact address; workspace and user are always in the predicate. */
export async function findDesktopIdentityByAddress(
  database: SqlExecutor, workspaceId: string, userId: string, address: string,
): Promise<DesktopIdentityRow | null> {
  const result = await database.query(
    `SELECT ${IDENTITY_COLUMNS} FROM desktop_relay_identities i
      WHERE i.workspace_id = $1 AND i.user_id = $2 AND i.address = $3
      ORDER BY i.updated_at DESC, i.id
      LIMIT 1`,
    [workspaceId, userId, address],
  );
  return result.rows[0] ? identityRow(result.rows[0]) : null;
}

/** This owner's newest synced identity with an exact agent name, for the alias hint when an address misses. */
export async function findDesktopIdentityByName(
  database: SqlExecutor, workspaceId: string, userId: string, name: string,
): Promise<DesktopIdentityRow | null> {
  const result = await database.query(
    `SELECT ${IDENTITY_COLUMNS} FROM desktop_relay_identities i
      WHERE i.workspace_id = $1 AND i.user_id = $2 AND i.agent_name = $3
      ORDER BY i.updated_at DESC, i.id
      LIMIT 1`,
    [workspaceId, userId, name],
  );
  return result.rows[0] ? identityRow(result.rows[0]) : null;
}

/** The synced identity a hosted MCP session (by the hash of its Mcp-Session-Id) is linked to. */
export async function findDesktopIdentityBySession(
  database: SqlExecutor, workspaceId: string, userId: string, sessionHash: string,
): Promise<DesktopIdentityRow | null> {
  const result = await database.query(
    `SELECT ${IDENTITY_COLUMNS} FROM desktop_relay_session_bindings b
       JOIN desktop_relay_identities i ON i.id = b.desktop_identity_id
      WHERE b.workspace_id = $1 AND b.user_id = $2 AND b.session_hash = $3
        AND i.workspace_id = $1 AND i.user_id = $2
      LIMIT 1`,
    [workspaceId, userId, sessionHash],
  );
  return result.rows[0] ? identityRow(result.rows[0]) : null;
}

export const DESKTOP_BINDING_GONE = "The desktop identity is no longer synced to this owner and workspace.";

/**
 * Links a hosted MCP session to one of this owner's synced identities. The
 * identity row is locked so a concurrent sync that drops it either runs
 * first (this refuses) or waits and cascades the new binding away. A re-link
 * refreshes created_at: sync reports it to the Desktop as linked_at.
 */
export async function bindDesktopSession(database: Database | SqlExecutor, input: {
  workspaceId: string; userId: string; sessionHash: string; identityId: string;
}): Promise<void> {
  const run = async (tx: SqlExecutor) => {
    const owned = await tx.query(
      `SELECT id FROM desktop_relay_identities WHERE id = $1 AND workspace_id = $2 AND user_id = $3 FOR UPDATE`,
      [input.identityId, input.workspaceId, input.userId],
    );
    if (owned.rows.length === 0) throw new DesktopIdentityUnavailable(DESKTOP_BINDING_GONE);
    await tx.query(
      `INSERT INTO desktop_relay_session_bindings (id, workspace_id, user_id, session_hash, desktop_identity_id)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (workspace_id, user_id, session_hash) DO UPDATE
         SET desktop_identity_id = EXCLUDED.desktop_identity_id, created_at = now()`,
      [randomUUID(), input.workspaceId, input.userId, input.sessionHash, input.identityId],
    );
  };
  // Inside a caller's transaction the row lock is held until it commits.
  return "transaction" in database ? database.transaction(run) : run(database);
}

/** Removes a hosted MCP session's desktop link; the synced identity is unchanged. */
export async function unbindDesktopSession(database: SqlExecutor, input: {
  workspaceId: string; userId: string; sessionHash: string;
}): Promise<void> {
  await database.query(
    `DELETE FROM desktop_relay_session_bindings WHERE workspace_id = $1 AND user_id = $2 AND session_hash = $3`,
    [input.workspaceId, input.userId, input.sessionHash],
  );
}

/**
 * Re-checks a stored identity with Relaycast: on this workspace's current
 * relay, and its token still controls the same relay-desktop agent owned by
 * this user. With `gate` (gate-only installs) the stored rg_ token is checked
 * with relaygate's whoami instead (the proof); the upstream Relaycast agent
 * card is compared only when it carries metadata.relaygate.agent_id, and a
 * missing card or field is accepted. Throws DesktopIdentityUnavailable; on
 * the gate path each rejection is logged ("desktop identity skipped").
 */
export async function verifyDesktopIdentity(input: {
  keyring: EncryptionKeyring;
  client: RelaycastClient;
  /** Gate-only installs: the client bound to relaygate's origin. */
  gate?: RelaycastClient;
  /** The workspace Relaycast key; required with `gate` for the upstream agent card. */
  relaycastApiKey?: string;
  userId: string;
  relaycastWorkspaceId: string;
  row: DesktopIdentityRow;
  /** Self-host workspace id, logged with a rejected gate identity when known. */
  workspaceId?: string;
  /** Logs each rejected gate identity ("desktop identity skipped"); never given the token. */
  log?: DesktopIdentityLog;
}): Promise<LinkedDesktopIdentity> {
  const { row } = input;
  if (row.relaycastWorkspaceId !== input.relaycastWorkspaceId) {
    throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.otherRelay);
  }
  let token: string;
  try {
    token = decryptSecret(row.tokenCiphertext, input.keyring);
  } catch {
    throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.gone);
  }
  if (input.gate) {
    const reject = (message: string, cause: SkipCause): never => {
      input.log?.(DESKTOP_IDENTITY_SKIPPED, {
        ...(input.workspaceId !== undefined ? { workspace_id: input.workspaceId } : {}),
        user_id: input.userId, agent_name: row.agentName, agent_id: row.agentRemoteId,
        reason: cause.reason, check: cause.check, ...(cause.status !== undefined ? { status: cause.status } : {}),
      });
      throw new DesktopIdentityUnavailable(message);
    };
    if (!input.relaycastApiKey) {
      return reject(DESKTOP_IDENTITY_MESSAGES.unverified, { reason: "unverified", check: "relaycast_api_key_missing" });
    }
    const [whoami, remote] = await Promise.allSettled([
      input.gate.whoami(token),
      input.client.getAgent(input.relaycastApiKey, row.agentName),
    ]);
    if (whoami.status === "rejected") {
      if (refused(whoami.reason)) {
        const status = refusedStatus(whoami.reason);
        return reject(DESKTOP_IDENTITY_MESSAGES.gone,
          { reason: "unverified", check: `whoami_refused:${status}`, ...(status !== undefined ? { status } : {}) });
      }
      return reject(DESKTOP_IDENTITY_MESSAGES.unverified, { reason: "unverified", check: "whoami_unavailable" });
    }
    if (remote.status === "rejected") {
      return reject(DESKTOP_IDENTITY_MESSAGES.unverified, { reason: "unverified", check: "card_unavailable" });
    }
    const who = whoami.value;
    const carded = remote.value ? relaygateAgentId(remote.value.metadata) : null;
    const failed = firstFailed([
      [who.agentId !== row.agentRemoteId, "whoami_agent_id"],
      [who.name !== row.agentName, "whoami_name"],
      [who.userId !== null && who.userId !== input.userId, "whoami_user_id"],
      [carded !== null && carded !== row.agentRemoteId, "card_relaygate_agent_id"],
    ]);
    if (failed) {
      return reject(DESKTOP_IDENTITY_MESSAGES.gone, { reason: failed === "whoami_user_id" ? "not_owned" : "unverified", check: failed });
    }
    return { id: row.id, name: row.agentName, address: row.address, agentId: row.agentRemoteId, token };
  }
  let agent;
  try {
    agent = await input.client.authenticatedAgent(token);
  } catch (error) {
    if (refused(error)) throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.gone);
    throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.unverified);
  }
  if (agent.id !== row.agentRemoteId || agent.name !== row.agentName || agent.address !== row.address ||
      agent.metadata.source !== DESKTOP_SOURCE || agent.metadata.owner_hash !== ownerHash(input.userId)) {
    throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.gone);
  }
  return { id: row.id, name: row.agentName, address: row.address, agentId: row.agentRemoteId, token };
}

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
  /** Gate-only installs: the client bound to relaygate's origin. */
  gate?: RelaycastClient;
  /** The workspace Relaycast key; required with `gate`. */
  relaycastApiKey?: string;
  workspaceId: string;
  userId: string;
  relaycastWorkspaceId: string;
  nativeSession: { kind: string; id: string };
  sourceId?: string;
  /** Logs each rejected gate identity; passed to verifyDesktopIdentity. */
  log?: DesktopIdentityLog;
}): Promise<LinkedDesktopIdentity> {
  const result = await input.database.query(
    `SELECT ${IDENTITY_COLUMNS} FROM desktop_relay_identities i
      WHERE i.workspace_id = $1 AND i.user_id = $2 AND i.native_session_kind = $3 AND i.native_session_id = $4`,
    [input.workspaceId, input.userId, input.nativeSession.kind, input.nativeSession.id],
  );
  if (result.rows.length > 1) throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.duplicate);
  const row = result.rows[0] ? identityRow(result.rows[0]) : null;
  if (!row) throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.notSynced);
  if (input.sourceId !== undefined &&
      normalizeDesktopSourceId(row.sourceId) !== normalizeDesktopSourceId(input.sourceId)) {
    throw new DesktopIdentityUnavailable(DESKTOP_IDENTITY_MESSAGES.sourceMismatch);
  }
  return verifyDesktopIdentity({ keyring: input.keyring, client: input.client,
    ...(input.gate ? { gate: input.gate } : {}),
    ...(input.relaycastApiKey !== undefined ? { relaycastApiKey: input.relaycastApiKey } : {}),
    ...(input.log ? { log: input.log } : {}),
    userId: input.userId, workspaceId: input.workspaceId, relaycastWorkspaceId: input.relaycastWorkspaceId, row });
}

export { COPILOT_ATTESTATION_CAPABILITY };
