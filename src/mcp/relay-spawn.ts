import { randomUUID } from "node:crypto";
import {
  DEFAULT_MEMORY_POLICY, memoryLowMessage, memoryRefusal, type MemoryAssessment, type MemoryPolicy,
} from "@agent-relay/spawn-placement";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SqlExecutor } from "../database.js";
import {
  RELAY_HARNESS_ID_PATTERN, RELAY_NODE_PAGE_LIMIT, RelaycastCallError, type RelaycastClient, type RelaySpawnInvocation, type RelaySpawnTarget,
} from "../messaging/relaycast.js";
import { LAUNCH_ROLE_REFUSAL } from "./catalog.js";
import type { McpContext } from "./context.js";
import type { RelayLaunchCheck } from "./relay-launch-check.js";
import { relayLaunchCredentials, type RelayLaunchCredentials } from "./relay-launch-credentials.js";
import { ownerHash, relayFailure, relayService, RelayToolError, type SpawnActor } from "./relay-participants.js";
import {
  alternativesFor, notAllowedMessage, rankTargets, type PlacedTarget, type PlacementRanking, type SpawnNodeOwner,
} from "./spawn-placement/index.js";

/**
 * Agent launches (SELFHOST_FEATURES launch; docs/agent-launch.md), ported
 * from Cloud's `lib/mcp/relay-spawn-service.ts` and `relay-spawn-tools.ts`.
 *
 * Launches reach only existing nodes enrolled in this workspace's own
 * Relaycast workspace: targets are read with this workspace's key and owners
 * from fleet_node_owners rows for this workspace and Relaycast workspace, so
 * a node from another workspace or another installation is never listed or
 * reachable. Every call rechecks the owner's current role and OAuth grant
 * when present. A launch is journaled (relay_spawns) before it
 * is sent and is sent at most once per journal row.
 *
 * Who reaches a journal row (status, release, idempotent replay):
 * - An OAuth connection: the same workspace, user, grant authority, Relaycast
 *   workspace and approved actor. Another grant of the same person never
 *   reaches it.
 * - Any other (native) connection: the same workspace, user, Relaycast
 *   workspace and actor, which is the person's own launcher participant. The
 *   stored authority is not compared, so a launch stays reachable after the
 *   client restarts with a new Mcp-Session-Id, including rows written while
 *   the authority still carried the session id. New native rows store an
 *   authority of the auth mode alone. An OAuth actor is never a launcher, so a
 *   native connection never reaches an OAuth row, and an OAuth connection
 *   never matches a native row's authority.
 *
 * The idempotency hash covers the whole owner, authority included, so an
 * OAuth key never matches another grant's launch; a native key made after the
 * authority stopped carrying the session id is recognised from a later
 * session of the same person.
 *
 * On a gate-only install (SELFHOST_RELAYGATE_PUBLIC_URL) each new journal row
 * also gets a one-time `sh_lt_` launch credential
 * (./relay-launch-credentials.ts), minted before the launch is sent. It is
 * never part of the invocation body sent to Relaycast. Before any of that,
 * relaygate checks the launch (./relay-launch-check.ts): a denied, classified
 * or unanswered check refuses the launch before a row is reserved.
 */

export const targetsInput = z.object({
  harness: z.string().regex(RELAY_HARNESS_ID_PATTERN).optional()
    .describe("The harness you intend to launch (for example codex or claude), so each target's memory is judged for it."),
}).strict();

/** Characters that render invisibly or break lines: bidi overrides, zero-width, C0/C1 controls, U+2028/U+2029. */
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const INVISIBLE_ALL = new RegExp(INVISIBLE.source, "gu");
/** Roster- or profile-controlled text made safe to echo: invisible characters become visible \u{...} escapes. */
export function displayName(value: string): string {
  return value.replace(INVISIBLE_ALL, char => `\\u{${char.codePointAt(0)!.toString(16)}}`);
}

export const spawnInput = z.object({
  name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/),
  cli: z.string().regex(RELAY_HARNESS_ID_PATTERN).describe("Harness advertised by the selected target_node, for example codex, claude, opencode or grok. Lowercase letters, digits and hyphens, at most 32 characters."),
  // Node names are free text, so only length and invisible characters are bounded. Control, format and line/paragraph
  // separator characters are refused here; roster names echoed back in refusals are escaped instead (displayName).
  target_node: z.string().trim().min(1).max(128)
    .refine(value => !INVISIBLE.test(value), "target_node must not contain control, format or line separator characters.")
    .describe("Required: the target_node id of an allowed live launch target in the current workspace fleet (from list_relay_spawn_targets). " +
      "A value matching no node id is accepted as a node name: leading and trailing spaces are trimmed and names of nodes in every state " +
      "are compared case-insensitively, with curly and straight apostrophes treated alike. It resolves only when exactly one node has " +
      "that name and it is live; when several do, the one whose stored name matches exactly (case-sensitive) is used if it is live. " +
      "Otherwise it is refused: an offline match as offline, several matches as ambiguous, and a value matching nothing with the " +
      "valid ids and names. A node whose stored name has surrounding spaces is refused by id or by name. When not every node could " +
      "be read, a name match is refused; pass the node's id. An idempotency key covers the exact target_node given, so " +
      "switching between a node's name and its id is a different launch."),
  task: z.string().min(1).max(8192).refine(value => value.trim().length > 0 && Buffer.byteLength(value, "utf8") <= 8192 && !value.includes("\0"),
    "Task must be nonempty and at most 8192 UTF-8 bytes."),
  worker_cwd: z.string().max(1024).refine(value => /^(\/|[A-Za-z]:[\\/])/.test(value) && !/[\x00-\x1f\x7f$`]/.test(value)
    && !value.split(/[\\/]/).includes(".."), "Use a literal absolute directory on the selected machine.").optional()
    .describe("worker_cwd (strongly recommended): absolute working directory for the agent on the target machine. If omitted, the node applies the machine default."),
  idempotency_key: z.string().regex(/^[A-Za-z0-9_-]{8,64}$/).optional()
    .describe("Use a stable key for this launch. Reuse it after a lost response; a new request without a key may describe another launch."),
}).strict();
type SpawnInput = z.infer<typeof spawnInput>;

// ---------------------------------------------------------------------------
// Journal: relay_spawns (migration 0041).

export type SpawnState = "reserved" | "accepted" | "unknown" | "ready" | "failed" | "releasing" | "released";
export type SpawnOwner = { workspaceId: string; userId: string; authorityHash: string; relaycastWorkspaceId: string; actorId: string };
export type SpawnFailure = { code: string; message: string; node: string; harness: string; retryable: boolean; observed_at: string };
export type SpawnAudit = { event: string; at: string; failure?: SpawnFailure };
export type SpawnRow = SpawnOwner & {
  id: string; idempotencyHash: string; requestHash: string; agentName: string; cli: string; nodeId: string; state: SpawnState;
  invocationId: string | null; workerId: string | null; workerAddress: string | null; releaseInvocationId: string | null;
  taskUnconfirmed: boolean; revision: number; audit: SpawnAudit[]; updatedAt: Date;
};
type SpawnPatch = Partial<Pick<SpawnRow, "state" | "invocationId" | "workerId" | "workerAddress" | "releaseInvocationId" | "taskUnconfirmed">> &
  { failure?: SpawnFailure; event?: string; clearReleaseInvocation?: boolean };

const COLUMNS = `id, workspace_id, user_id, authority_hash, relaycast_workspace_id, actor_id, idempotency_hash, request_hash,
  agent_name, cli, node_id, state, invocation_id, worker_id, worker_address, release_invocation_id, task_unconfirmed,
  revision, audit, updated_at`;
const OWNED = `workspace_id = $1 AND user_id = $2 AND authority_hash = $3 AND relaycast_workspace_id = $4 AND actor_id = $5`;
const ownedParams = (owner: SpawnOwner) =>
  [owner.workspaceId, owner.userId, owner.authorityHash, owner.relaycastWorkspaceId, owner.actorId];
/** A native lookup: the owner without its authority (see the header comment). */
const NATIVE_OWNED = `workspace_id = $1 AND user_id = $2 AND relaycast_workspace_id = $3 AND actor_id = $4`;
/**
 * How a lookup matches the owner. `compareAuthority: false` is for native
 * connections only; OAuth lookups always compare the grant authority. It is
 * kept apart from SpawnOwner so the owner hashed into idempotency keys is
 * unchanged.
 */
export type SpawnLookup = { compareAuthority: boolean };
const COMPARE_AUTHORITY: SpawnLookup = { compareAuthority: true };
function ownedClause(owner: SpawnOwner, lookup: SpawnLookup): { clause: string; params: unknown[] } {
  return lookup.compareAuthority ? { clause: OWNED, params: ownedParams(owner) }
    : { clause: NATIVE_OWNED, params: [owner.workspaceId, owner.userId, owner.relaycastWorkspaceId, owner.actorId] };
}

function rowFrom(row: Record<string, unknown>): SpawnRow {
  const nullable = (value: unknown) => typeof value === "string" ? value : null;
  return {
    id: String(row.id), workspaceId: String(row.workspace_id), userId: String(row.user_id), authorityHash: String(row.authority_hash),
    relaycastWorkspaceId: String(row.relaycast_workspace_id), actorId: String(row.actor_id),
    idempotencyHash: String(row.idempotency_hash), requestHash: String(row.request_hash), agentName: String(row.agent_name),
    cli: String(row.cli), nodeId: String(row.node_id), state: String(row.state) as SpawnState,
    invocationId: nullable(row.invocation_id), workerId: nullable(row.worker_id), workerAddress: nullable(row.worker_address),
    releaseInvocationId: nullable(row.release_invocation_id), taskUnconfirmed: row.task_unconfirmed === true,
    revision: Number(row.revision), audit: (typeof row.audit === "string" ? JSON.parse(row.audit) : row.audit) as SpawnAudit[],
    updatedAt: new Date(row.updated_at as string | Date),
  };
}

/**
 * A worker identity is recorded once: at readiness, or when release binds a
 * correlated registration while moving an unbound launch to `releasing`.
 */
function assertSpawnPatch(row: SpawnRow, patch: SpawnPatch): void {
  const recordsIdentity = patch.workerId !== undefined || patch.workerAddress !== undefined;
  const unbound = (row.state === "accepted" || row.state === "unknown") && !row.workerId;
  if (patch.state === "ready" && (!unbound || !patch.workerId || !patch.workerAddress)) {
    throw new RelayToolError("Launch readiness requires one verified worker identity.");
  }
  const releaseBinding = patch.state === "releasing" && unbound && Boolean(patch.workerId && patch.workerAddress);
  if (recordsIdentity && patch.state !== "ready" && !releaseBinding) {
    throw new RelayToolError("Worker identity may be recorded only at readiness or when releasing an unbound launch.");
  }
}

export function spawnStore(database: { query: SqlExecutor["query"]; transaction<T>(run: (tx: SqlExecutor) => Promise<T>): Promise<T> },
  options: { beforeReserve?: (tx: SqlExecutor) => Promise<void> } = {}) {
  async function find(owner: SpawnOwner, id: string, lookup: SpawnLookup = COMPARE_AUTHORITY): Promise<SpawnRow | null> {
    const { clause, params } = ownedClause(owner, lookup);
    const result = await database.query(`SELECT ${COLUMNS} FROM relay_spawns WHERE ${clause} AND id = $${params.length + 1}`,
      [...params, id]);
    return result.rows[0] ? rowFrom(result.rows[0]) : null;
  }
  return {
    find,
    async findKey(owner: SpawnOwner, hash: string, lookup: SpawnLookup = COMPARE_AUTHORITY): Promise<SpawnRow | null> {
      const { clause, params } = ownedClause(owner, lookup);
      const result = await database.query(
        `SELECT ${COLUMNS} FROM relay_spawns WHERE ${clause} AND idempotency_hash = $${params.length + 1}`, [...params, hash]);
      return result.rows[0] ? rowFrom(result.rows[0]) : null;
    },
    /** One transaction per reservation, never held over a network call. */
    reserve(row: Omit<SpawnRow, "updatedAt">): Promise<{ row: SpawnRow; created: boolean }> {
      return database.transaction(async (tx) => {
        // Commit the active-launch fence atomically with live OAuth admission.
        // Revocation either sees this row or prevents its reservation; teardown
        // cannot delete an actor between the last grant check and journaling.
        await options.beforeReserve?.(tx);
        await tx.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`relay-spawn:${row.workspaceId}`]);
        const existing = await tx.query(`SELECT ${COLUMNS} FROM relay_spawns WHERE idempotency_hash = $1`, [row.idempotencyHash]);
        if (existing.rows[0]) {
          const found = rowFrom(existing.rows[0]);
          if (found.requestHash !== row.requestHash) throw new RelayToolError("This idempotency key already describes a different launch.");
          return { row: found, created: false };
        }
        const inserted = await tx.query(
          `INSERT INTO relay_spawns (id, workspace_id, user_id, authority_hash, relaycast_workspace_id, actor_id, idempotency_hash,
             request_hash, agent_name, cli, node_id, state, revision, audit)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 0, $13::jsonb) RETURNING ${COLUMNS}`,
          [row.id, row.workspaceId, row.userId, row.authorityHash, row.relaycastWorkspaceId, row.actorId, row.idempotencyHash,
            row.requestHash, row.agentName, row.cli, row.nodeId, row.state, JSON.stringify(row.audit)],
        );
        return { row: rowFrom(inserted.rows[0]!), created: true };
      });
    },
    /** Revision compare-and-swap; a lost race returns the current row. */
    async update(row: SpawnRow, patch: SpawnPatch): Promise<SpawnRow> {
      assertSpawnPatch(row, patch);
      const { failure, event, clearReleaseInvocation, ...columns } = patch;
      const audit = [...row.audit, { event: event ?? patch.state ?? "updated", at: new Date().toISOString(), ...(failure ? { failure } : {}) }];
      const changed = await database.query(
        `UPDATE relay_spawns SET state = COALESCE($8, state), invocation_id = COALESCE($9, invocation_id),
           worker_id = COALESCE($10, worker_id), worker_address = COALESCE($11, worker_address),
           release_invocation_id = CASE WHEN $15 THEN NULL ELSE COALESCE($12, release_invocation_id) END, task_unconfirmed = COALESCE($13, task_unconfirmed),
           audit = $14::jsonb, revision = revision + 1, updated_at = now()
         WHERE ${OWNED} AND id = $6 AND revision = $7 RETURNING ${COLUMNS}`,
        [...ownedParams(row), row.id, row.revision, columns.state ?? null, columns.invocationId ?? null, columns.workerId ?? null,
          columns.workerAddress ?? null, columns.releaseInvocationId ?? null, columns.taskUnconfirmed ?? null, JSON.stringify(audit),
          clearReleaseInvocation === true],
      );
      if (changed.rows[0]) return rowFrom(changed.rows[0]);
      const current = await find(row, row.id);
      if (!current) throw new RelayToolError("Launch ownership changed.");
      return current;
    },
  };
}
type SpawnStore = ReturnType<typeof spawnStore>;

// ---------------------------------------------------------------------------
// Service.

export class RelaySpawnAdmissionError extends Error {
  constructor(readonly details: Record<string, unknown>) {
    super(String(details.message));
  }
}

const eligible = (target: RelaySpawnTarget) => target.name !== "self" && target.live && target.handlersLive && !target.stale &&
  (target.maxAgents === 0 || target.maxAgents > target.activeAgents + target.reservedAgents) && target.capabilities.length > 0;

/** How a node name is compared for the name fallback: trimmed (as Relaycast's selector is), NFC, curly apostrophes as straight ones, case-insensitive. */
export function nodeNameKey(name: string): string {
  return name.trim().normalize("NFC").replace(/[\u2018\u2019\u02bc]/g, "'").toLowerCase();
}
/** Live targets a caller could name instead. "self" is the native selector, never a target. */
const MAX_LISTED_TARGETS = 20;
const listable = (online: RelaySpawnTarget[]) => online.filter(target => target.live && target.name !== "self");
function validTargets(online: RelaySpawnTarget[]): Array<{ id: string; name: string }> {
  return listable(online).slice(0, MAX_LISTED_TARGETS).map(target => ({ id: target.id, name: displayName(target.name) }));
}
/** "id (name), ..." capped at MAX_LISTED_TARGETS, saying how many were left out. */
function listTargets(targets: RelaySpawnTarget[], empty = "none are live"): string {
  if (!targets.length) return empty;
  const shown = targets.slice(0, MAX_LISTED_TARGETS).map(target => `${target.id} (${displayName(target.name)})`).join(", ");
  return targets.length > MAX_LISTED_TARGETS
    ? `${shown} (and ${targets.length - MAX_LISTED_TARGETS} more; call list_relay_spawn_targets)` : shown;
}
/**
 * Relaycast's spawn selector trims the requested name and compares it exactly with the stored names of nodes in
 * every state. A stored name with surrounding whitespace is therefore never reached by its own name: the launch
 * would go to a node named like its trimmed form, or nowhere. Such a node is refused, by id or by name, and is
 * never offered as an alternative. An unpadded name always reaches exactly its own node.
 */
const padded = (node: { name: string }) => node.name !== node.name.trim();
/** Roster- and profile-controlled text in a placed target, made safe to echo. */
function displayPlaced(target: PlacedTarget): PlacedTarget {
  return { ...target, name: displayName(target.name), machine: displayName(target.machine), why: displayName(target.why),
    owner: target.owner ? { ...target.owner, name: displayName(target.owner.name) } : null };
}

function failureMessage(code: string, node: string, harness: string, advertised?: string[]): string {
  return code === "spawn_capacity_exceeded" ? `Node "${node}" is at capacity`
    : code === "spawn_memory_low" ? `Node "${node}" does not have the memory for another agent`
    : code === "spawn_target_offline" ? `Node "${node}" is offline`
    : code === "spawn_harness_unavailable" ? `Node "${node}" does not provide spawn:${harness}` +
      (advertised?.length ? `; it advertises ${advertised.join(", ")}` : "")
    : code === "spawn_target_unavailable" ? `Node "${node}" is unavailable for spawn`
    : code === "relaygate_denied" ? "relaygate denied this launch"
    : code === "relaygate_classified" ? "relaygate classified the task; it cannot be sent to a node"
    : code === "relaygate_unavailable" ? "relaygate is unavailable; retry later"
    : `Agent launch on "${node}" failed`;
}
const SPAWN_CODES = new Set(["spawn_failed", "spawn_capacity_exceeded", "spawn_target_unavailable", "spawn_target_offline",
  "spawn_harness_unavailable", "spawn_memory_low", "capacity_changed"]);
const RETRYABLE_CODES = ["spawn_capacity_exceeded", "spawn_target_offline", "spawn_target_unavailable", "spawn_memory_low", "capacity_changed"];
function failure(code: string | null, node: string, harness: string): SpawnFailure {
  const known = code && SPAWN_CODES.has(code) ? code : "spawn_failed";
  return { code: known, message: failureMessage(known, node, harness), node, harness, observed_at: new Date().toISOString(),
    retryable: RETRYABLE_CODES.includes(known) };
}

/** The upstream refusal code Relaycast attached to a rejected spawn, when it is one we know. */
function upstreamSpawnCode(error: RelaycastCallError): string | null {
  try {
    const parsed = JSON.parse(error.body) as { error?: { code?: unknown; details?: { code?: unknown } } };
    const code = parsed.error?.details?.code ?? parsed.error?.code;
    return typeof code === "string" && SPAWN_CODES.has(code) ? code : null;
  } catch {
    return null;
  }
}

/** Whether the current release attempt (since the last failed one) was already dispatched. */
function releaseDispatched(row: SpawnRow): boolean {
  const events = row.audit.map(entry => entry.event);
  return events.slice(events.lastIndexOf("release_failed") + 1).includes("release_dispatch");
}

function result(row: SpawnRow) {
  const recorded = [...row.audit].reverse().find(entry => entry.failure)?.failure ?? failure(null, row.nodeId, row.cli);
  return {
    spawn_id: row.id, name: row.agentName, cli: row.cli, target_node: row.nodeId, status: row.state,
    ready: row.state === "ready", address: row.state === "ready" ? row.workerAddress : null,
    ...(row.taskUnconfirmed ? { warning: "spawn_task_unconfirmed" } : {}),
    ...(row.state === "releasing" && row.audit.at(-1)?.event === "release_failed"
      ? { note: "The last exact release failed and the worker may still be running. Call release_relay_agent again to retry." } : {}),
    ...(row.state === "failed" ? { error: recorded } : {}),
    ...(row.state === "unknown" || row.state === "reserved"
      ? { note: "Launch outcome is unconfirmed. Do not retry with a new idempotency key; keep this spawn_id." } : {}),
  };
}

export type RelaySpawnDeps = {
  client: RelaycastClient;
  workspaceKey: string;
  store: SpawnStore;
  /** Claimed owners of these nodes in this workspace and Relaycast workspace. */
  owners(nodeIds: string[]): Promise<Map<string, SpawnNodeOwner>>;
  withActor<T>(fn: (actor: SpawnActor) => Promise<T>): Promise<T>;
  /** Gate-only installs only: one-time `sh_lt_` credential per launch. */
  launchCredentials?: RelayLaunchCredentials;
  /** Gate-only installs only: relaygate's POST /v1/check before anything is reserved or sent. */
  launchCheck?: RelayLaunchCheck;
  /** The spawn memory policy (docs/specs/spawn-placement-memory.md); absent means the defaults in observe. */
  memoryPolicy?: MemoryPolicy;
  /** When this workspace's in-flight launches (reserved or accepted, last minute) were reserved, per node. */
  pendingLaunches?(): Promise<Map<string, Date[]>>;
  now?(): Date;
};

/** Shadow accounting for observe and rank: what enforce would have refused. Counts only, no names or ids. */
function recordMemoryShadow(policy: MemoryPolicy, harness: string, memory: MemoryAssessment | undefined): void {
  if (policy.mode === "off" || policy.mode === "enforce" || !memory || memory.admissible) return;
  console.info("[selfhost-mcp] spawn_memory_policy_shadow", { mode: policy.mode, tier: memory.tier, reason: memory.reason, harness });
}

export function relaySpawnService(context: Pick<McpContext, "authMode" | "role" | "principal" | "workspace" | "relay" | "oauth">,
  deps: RelaySpawnDeps) {
  const userId = context.principal.userId;
  const sessionId = context.relay.sessionId;

  function authorize(): void {
    const role = context.oauth ? context.oauth.access.principal.role : context.role;
    if (context.authMode === "oauth" && !context.oauth) throw new RelayToolError(LAUNCH_ROLE_REFUSAL);
    if (role !== "owner" && role !== "admin") throw new RelayToolError(LAUNCH_ROLE_REFUSAL);
  }
  function owner(actor: SpawnActor): SpawnOwner {
    if (!context.oauth && !sessionId) throw new RelayToolError("Initialize MCP and retain Mcp-Session-Id before starting agents.");
    // Property order is part of the idempotency hash: keep it.
    return { workspaceId: context.workspace.id, userId, relaycastWorkspaceId: actor.relaycastWorkspaceId, actorId: actor.id,
      authorityHash: ownerHash(JSON.stringify(context.oauth
        ? [context.authMode, context.oauth.access.grantId]
        // Native: no session id, so a later session of the same person derives the same owner.
        : [context.authMode])) };
  }
  /** OAuth compares the grant authority; a native connection is matched by its launcher actor instead. */
  const ownership: SpawnLookup = { compareAuthority: Boolean(context.oauth) };
  const run = <T>(fn: (actor: SpawnActor, owned: SpawnOwner) => Promise<T>): Promise<T> => {
    if (!context.oauth) authorize();
    return deps.withActor(actor => { authorize(); return fn(actor, owner(actor)); });
  };
  async function lookup(owned: SpawnOwner, id: string): Promise<SpawnRow> {
    if (!z.string().uuid().safeParse(id).success) throw new RelayToolError("Use a spawn_id returned by spawn_relay_agent.");
    const row = await deps.store.find(owned, id, ownership);
    if (!row) {
      throw new RelayToolError(context.oauth ? "This launch is not owned by this connection in the current workspace."
        : "This launch was not started by you in the current workspace.");
    }
    return row;
  }

  /** Readiness needs the invocation's caller, node and output and a registration correlated to both. */
  async function refresh(actor: SpawnActor, row: SpawnRow): Promise<SpawnRow> {
    if (row.state === "releasing" && row.releaseInvocationId) {
      const release = await deps.client.getRelayInvocation(actor.token, "release", row.releaseInvocationId);
      if (release.callerId !== actor.id) throw new RelayToolError("Release provenance could not be verified.");
      // A failed exact release keeps the worker binding; the next release_relay_agent sends a new attempt.
      if (release.status === "failed") return deps.store.update(row, { event: "release_failed", clearReleaseInvocation: true });
      if (release.status === "completed") {
        const agent = await deps.client.getSpawnedAgent(deps.workspaceKey, row.agentName);
        if (!agent || agent.id !== row.workerId || agent.status === "released") return deps.store.update(row, { state: "released" });
      }
      return row;
    }
    if (!["accepted", "unknown"].includes(row.state) || !row.invocationId) return row;
    const invocation: RelaySpawnInvocation = await deps.client.getRelayInvocation(actor.token, "spawn", row.invocationId);
    if (invocation.callerId !== actor.id || invocation.nodeId !== row.nodeId) {
      throw new RelayToolError("Launch provenance could not be verified.");
    }
    if (invocation.status === "failed") {
      return deps.store.update(row, { state: "failed", failure: failure(invocation.errorDetailsCode ?? invocation.errorCode, row.nodeId, row.cli) });
    }
    if (invocation.status !== "completed") return row;
    if (!invocation.spawned || !invocation.ready || invocation.name !== row.agentName) {
      return row.state === "unknown" ? row : deps.store.update(row, { state: "unknown" });
    }
    const agent = await deps.client.getSpawnedAgent(deps.workspaceKey, row.agentName);
    if (!agent || !correlated(row, agent)) {
      throw new RelayToolError("The launched agent identity is not yet verified. Check status again; do not launch a replacement.");
    }
    return deps.store.update(row, { state: "ready", workerId: agent.id, workerAddress: agent.address!,
      taskUnconfirmed: invocation.taskUnconfirmed });
  }

  const memoryPolicy = deps.memoryPolicy ?? DEFAULT_MEMORY_POLICY;
  /** Ranking inputs: the policy, the clock and this workspace's launches still starting. */
  async function placementOptions(harness: string | null) {
    const pending = memoryPolicy.mode === "off" || !deps.pendingLaunches ? new Map<string, Date[]>()
      : await deps.pendingLaunches().catch(() => new Map<string, Date[]>());
    return { policy: memoryPolicy, now: deps.now?.() ?? new Date(), harness, pending };
  }

  return {
    async targets(raw: unknown = {}) {
      const parsed = targetsInput.safeParse(raw ?? {});
      if (!parsed.success) throw new RelayToolError("Invalid input. harness is a harness id: lowercase letters, digits and hyphens, at most 32 characters.");
      if (context.oauth) await context.relay.database.transaction(tx => context.oauth!.lock(tx));
      authorize();
      const targets = (await deps.client.listSpawnTargets(deps.workspaceKey)).filter(eligible);
      const ranking = rankTargets(targets, await deps.owners(targets.map(target => target.id)), userId,
        await placementOptions(parsed.data.harness ?? null));
      return {
        // Roster- and profile-controlled text is escaped, as in refusals.
        targets: ranking.targets.map(displayPlaced),
        ...(ranking.policy.mode === "off" ? {} : { memory_policy: ranking.policy.mode }),
        note: "Ranked best first. Choose an allowed target, preferring an allowed desktop with the task's repository and free slots, " +
          "and pass its target_node to spawn_relay_agent. Existing machines only; permission and capacity are rechecked at launch." +
          (ranking.policy.mode === "off" ? "" : " Pass the harness you intend to launch so memory is judged for it; " +
            "a target with admissible false would refuse that launch now."),
      };
    },

    async spawn(raw: unknown, requestId: string | number) {
      const parsed = spawnInput.safeParse(raw);
      if (!parsed.success) {
        throw new RelayToolError("Invalid launch input. Use a harness id the target advertises, an explicit target, a literal absolute directory and a task of at most 8192 UTF-8 bytes.");
      }
      const input: SpawnInput = parsed.data;
      return run(async (actor, owned) => {
        const key = input.idempotency_key ?? (sessionId ? ownerHash(JSON.stringify([sessionId, requestId])) : randomUUID());
        const launch = { name: input.name, cli: input.cli, task: input.task, target_node: input.target_node,
          ...(input.worker_cwd ? { worker_cwd: input.worker_cwd } : {}) };
        const idempotencyHash = ownerHash(JSON.stringify(["selfhost-spawn:v1", owned, key]));
        const requestHash = ownerHash(JSON.stringify(launch));
        const previous = await deps.store.findKey(owned, idempotencyHash, ownership);
        if (previous) {
          if (previous.requestHash !== requestHash) throw new RelayToolError("This idempotency key already describes a different launch.");
          if (previous.state !== "failed") return result(previous);
          // A replayed failure offers alternatives as of now, from the live read only (no every-state read). They are
          // advice, so an unreachable roster must not block receipt recovery. The receipt already names its node:
          // that id is excluded, however target_node was spelled.
          const alternatives = await (async () => {
            const live = (await deps.client.listSpawnTargets(deps.workspaceKey)).filter(eligible);
            const ranking = rankTargets(live, await deps.owners(live.map(item => item.id)), userId, await placementOptions(input.cli));
            const recorded = ranking.targets.find(item => item.target_node === previous.nodeId);
            return alternativesFor({ ...ranking, ranked: ranking.ranked.filter(entry => !padded(entry.candidate.placed)) }, input.cli,
              { id: previous.nodeId, repositories: recorded?.repositories }).map(displayPlaced);
          })().catch(() => null);
          return alternatives ? { ...result(previous), alternatives } : result(previous);
        }
        const online = await deps.client.listSpawnTargets(deps.workspaceKey);
        // Ids first. Only an id miss on the live page reads nodes of every state, so offline nodes never displace
        // live ones and a launch by a live id never depends on that read. Each read is one page; anything beyond it
        // is not seen. The every-state read is incomplete when it fails (a retry may help) or when Relaycast reports
        // another page (permanent for this roster: pass an id instead). Either way it cannot rule out an unseen node.
        const byId = online.find(item => item.id === input.target_node);
        const allStates = byId ? null : await deps.client.listAllSpawnTargets(deps.workspaceKey).catch(() => {
          // Counts only, no names or ids: how often launches run without offline information.
          console.warn("[selfhost-mcp] spawn_every_state_roster_failed");
          return null;
        });
        const everyState = allStates?.targets ?? null;
        const unread: "failed" | "partial" | null = byId ? null : !allStates ? "failed" : allStates.complete ? null : "partial";
        const offlineUnread = unread !== null;
        const idHolder = everyState?.find(item => item.id === input.target_node);
        // Names, on an id miss only: an id held by a node in any state seen is never reread as a name. Relaycast's
        // selector matches stored names of every state, so names are compared over every state: the value resolves
        // only when exactly one node of any state carries its normalized key and that node is live. A lone offline
        // match keeps its offline refusal and several matches are ambiguous, so an offline node's own name never
        // launches on a live look-alike. Without the every-state read neither can be ruled out, so a single live
        // name match is held back and refused as retryable instead.
        const nameKey = nodeNameKey(input.target_node);
        // One entry per id, the live page's view first.
        const roster = everyState ? [...new Map([...everyState, ...online].map(node => [node.id, node] as const)).values()] : listable(online);
        const named = byId || idHolder ? [] : roster.filter(item => item.name !== "self" && nodeNameKey(item.name) === nameKey);
        // Tiebreak: when several nodes share the key, the one whose stored name equals the trimmed input exactly
        // (case-sensitive, byte for byte) is the node Relaycast's exact selector reaches, so it is used when live.
        // Otherwise the ambiguity refusal stands: an exact match that is offline is never swapped for a live variant.
        const exact = named.length > 1 ? named.filter(item => item.name === input.target_node) : [];
        const tiebreak = exact.length === 1 && online.some(item => item.id === exact[0]!.id && item.live) ? exact[0] : undefined;
        const lone = named.length === 1 ? named[0] : tiebreak;
        const liveLone = lone ? online.find(item => item.id === lone.id && item.live) : undefined;
        const ambiguous = named.length > 1 && !tiebreak;
        // Without a complete every-state read, a live name match cannot rule out an unseen node holding it as an id.
        const unconfirmed = offlineUnread && liveLone !== undefined;
        const target = byId ?? liveLone;
        const offline = idHolder ?? (lone && !liveLone ? lone : undefined);
        const owners = await deps.owners([...online.filter(eligible), ...(target ? [target] : []), ...(offline ? [offline] : [])]
          .map(item => item.id));
        const options = await placementOptions(input.cli);
        const ranking: PlacementRanking = rankTargets(online.filter(eligible), owners, userId, options);
        // A padded name is never offered: it would be refused the same way.
        const offered: PlacementRanking = { ...ranking, ranked: ranking.ranked.filter(entry => !padded(entry.candidate.placed)) };
        const alternativesTo = (id: string, repositories?: readonly string[]) =>
          alternativesFor(offered, input.cli, { id, repositories }).map(displayPlaced);
        const refuse = (code: string, refused: RelaySpawnTarget | undefined, placed?: PlacedTarget, memory?: MemoryAssessment,
          override: { message?: string; retryable?: boolean; valid_targets?: Array<{ id: string; name: string }> } = {}) => {
          const name = displayName(refused?.name ?? input.target_node);
          const shown = placed ? displayPlaced(placed) : undefined;
          const alternatives = alternativesTo(refused?.id ?? input.target_node, placed?.repositories);
          const advertised = code === "spawn_harness_unavailable" && refused
            ? refused.capabilities.map(capability => capability.slice("spawn:".length)) : undefined;
          return new RelaySpawnAdmissionError({
            code, message: override.message ?? (code === "spawn_target_not_allowed" && shown ? notAllowedMessage(shown)
              : code === "spawn_memory_low" && memory ? memoryLowMessage(name, input.cli, memory) : failureMessage(code, name, input.cli, advertised)),
            node: name, harness: input.cli, ...(advertised ? { advertised } : {}),
            ...(code === "spawn_target_not_allowed" ? { owner: shown?.owner ?? null } : {}),
            active: refused?.activeAgents ?? null, reserved: refused?.reservedAgents ?? null, max: refused?.maxAgents ?? null,
            observed_at: new Date().toISOString(),
            retryable: override.retryable ??
              !["spawn_harness_unavailable", "spawn_target_not_allowed", "relaygate_denied", "relaygate_classified"].includes(code),
            ...(memory ? { memory: { reason: memory.reason, available_bytes: memory.available_bytes,
              projected_available_bytes: memory.projected_available_bytes, total_bytes: memory.total_bytes, floor_bytes: memory.floor_bytes,
              need_bytes: memory.need_bytes, memory_cap: memory.memory_cap, held: memory.held, sampled_at: memory.observed_at } } : {}),
            ...(override.valid_targets ? { valid_targets: override.valid_targets } : {}),
            alternatives,
            ...(memory && alternatives.length === 0 ? { retry_after_seconds: ranking.policy.retryAfterSeconds } : {}),
          });
        };
        const requested = displayName(input.target_node);
        if (ambiguous) {
          // Several nodes share the normalized key (for example case variants), live or offline. Relaycast keeps stored names
          // unique and selects by the exact trimmed name, so each of their ids reaches exactly one machine.
          throw refuse("spawn_target_unavailable", undefined, undefined, undefined, { retryable: false, valid_targets: validTargets(online),
            message: `target_node "${requested}" matches no node id and the names of ${named.length} nodes; ` +
              `pass one of their ids as target_node: ${listTargets(named)}` });
        }
        if (unconfirmed) {
          throw refuse("spawn_target_unavailable", undefined, undefined, undefined, { retryable: unread === "failed",
            message: unread === "failed"
              ? `target_node "${requested}" matches a live node's name, but offline nodes could not be read to confirm ` +
                "that no node has it as an id. Try again, or pass the node's id."
              : `target_node "${requested}" matches a live node's name, but this workspace has more nodes than one read ` +
                "returns, so it cannot be confirmed that no node has it as an id. Pass the node's id." });
        }
        // Permission first, even for an offline node: a node you may not use is never retryable.
        const known = target ?? offline ?? undefined;
        if (!known) {
          // Neither an id nor a live name: say what the caller could pass instead. Retrying the same value will not
          // help, unless offline nodes could not be read: then it may be an offline node's id, and a retry can tell.
          const valid = listTargets(listable(online));
          throw refuse("spawn_target_unavailable", undefined, undefined, undefined, { retryable: unread === "failed",
            valid_targets: validTargets(online), message: unread === "failed"
              ? `target_node "${requested}" matches no live node id or name, and offline nodes could not be read to check whether ` +
                `it is an offline node's id. Try again, or pass one of these live ids and names: ${valid}`
              : unread === "partial"
                ? `target_node "${requested}" matches no live node id or name among the nodes read; this workspace has more nodes ` +
                  `than one read returns. Pass the node's id; live ids and names: ${valid}`
                : `target_node "${requested}" matches no live node id or name; valid ids and names: ${valid}` });
        }
        const placed = ranking.targets.find(item => item.target_node === known.id) ?? rankTargets([known], owners, userId, options).targets[0]!;
        if (!placed.allowed) throw refuse("spawn_target_not_allowed", known, placed);
        // The launch goes out by name and Relaycast trims it, so a padded name cannot select its own node.
        // Offline too, by id or by name: renaming, not waiting, is what helps.
        const paddedNode = padded(known) ? known : undefined;
        if (paddedNode) {
          throw refuse("spawn_target_unavailable", paddedNode, placed, undefined, { retryable: false,
            message: `Node "${displayName(paddedNode.name)}" (${paddedNode.id}) has whitespace around its name. Relaycast trims the name a ` +
              "launch selects by, so this node cannot be chosen and a launch could start on a node named without it. " +
              "The owner must rename it without surrounding whitespace." });
        }
        if (!target && known.live) {
          // Live, but seen only in the every-state read: past the live page this server ranks and checks capacity on.
          throw refuse("spawn_target_unavailable", known, placed, undefined, { retryable: true,
            message: `Node "${displayName(known.name)}" (${known.id}) is live but past the first ${RELAY_NODE_PAGE_LIMIT} live nodes ` +
              "this server reads, so it cannot be checked for this launch. Try again, or pass the id of a node from list_relay_spawn_targets." });
        }
        if (!target || !target.live) throw refuse("spawn_target_offline", known, placed);
        if (!target.handlersLive || target.stale || target.name === "self") throw refuse("spawn_target_unavailable", target, placed);
        if (!target.capabilities.includes(`spawn:${input.cli}`)) throw refuse("spawn_harness_unavailable", target, placed);
        if (!eligible(target)) throw refuse("spawn_capacity_exceeded", target, placed);
        // Memory last: under enforce a fresh sample without room refuses (fail open when unknown); otherwise counted only.
        const assessed = ranking.ranked.find(entry => entry.candidate.id === target!.id);
        const short = assessed ? memoryRefusal(assessed, ranking.policy) : null;
        if (short) throw refuse("spawn_memory_low", target, placed, short);
        recordMemoryShadow(ranking.policy, input.cli, assessed?.memory);
        // Gate-only installs: relaygate sees the exact task first. Refused before reserve, so nothing is journaled or cached.
        if (deps.launchCheck) {
          const outcome = await deps.launchCheck.check({ userId, organizationId: context.workspace.organizationId,
            workspaceId: context.workspace.id, nodeName: target.name, task: input.task });
          if (outcome.decision === "deny") throw refuse(outcome.code, target, placed);
          if (outcome.decision === "unavailable") throw refuse("relaygate_unavailable", target, placed);
        }

        const now = new Date().toISOString();
        const reserved = await deps.store.reserve({ ...owned, id: randomUUID(), idempotencyHash, requestHash,
          agentName: input.name, cli: input.cli, nodeId: target.id, state: "reserved", invocationId: null, workerId: null,
          workerAddress: null, releaseInvocationId: null, taskUnconfirmed: false, revision: 0,
          audit: [{ event: "reserved", at: now }] });
        if (!reserved.created) return result(reserved.row);
        let row = reserved.row;
        // Minted before the launch is sent and kept sealed; the invocation below never carries it.
        // A launch that could not get its credential is never sent: fail the row so it is not left reserved.
        if (deps.launchCredentials) {
          try {
            await deps.launchCredentials.issue({ spawnId: row.id, workspaceId: context.workspace.id,
              organizationId: context.workspace.organizationId, userId, nodeName: target.name, agentName: input.name });
          } catch (error) {
            await deps.store.update(row, { state: "failed", failure: failure(null, displayName(target.name), input.cli) });
            throw error;
          }
        }
        try {
          // A verified desktop chat rides along as the requester (never hashed or stored): the node treats its DMs as native input.
          const invocation = await deps.client.spawnRelayAgent(actor.token, { ...launch, target_node: target.name },
            `selfhost-spawn:${row.id}`, actor.requester);
          row = await deps.store.update(row, { state: "accepted", invocationId: invocation.id });
        } catch (error) {
          // Never send a second launch, even when the response is lost.
          const rejected = error instanceof RelaycastCallError && !error.outcomeUnknown;
          row = await deps.store.update(row, rejected
            ? { state: "failed", failure: failure(upstreamSpawnCode(error), displayName(target.name), input.cli) }
            : { state: "unknown" });
        }
        if (row.state === "failed") await deps.launchCredentials?.discard(row.id);
        return row.state === "failed"
          ? { ...result(row), alternatives: alternativesTo(target.id, placed.repositories) }
          : result(row);
      });
    },

    status: (id: string) => run(async (actor, owned) => result(await refresh(actor, await lookup(owned, id)))),

    release: (id: string) => run(async (actor, owned) => {
      let row = await lookup(owned, id);
      if (["accepted", "unknown"].includes(row.state) && row.invocationId) row = await refresh(actor, row);
      if (row.state === "failed" || row.state === "released") return result(row);
      const remote = await deps.client.getSpawnedAgent(deps.workspaceKey, row.agentName);
      if (["accepted", "unknown"].includes(row.state) && row.invocationId && !row.workerId) {
        if (!remote || !correlated(row, remote)) {
          throw new RelayToolError("No verified launch identity is available yet. Check status again; the launch remains reserved until it fails or its worker can be released.");
        }
        row = await deps.store.update(row, { state: "releasing", workerId: remote.id, workerAddress: remote.address! });
      } else if (row.state === "releasing") {
        row = await refresh(actor, row);
        if (row.state === "released") return result(row);
      }
      if (!["ready", "releasing"].includes(row.state) || !row.workerId) {
        throw new RelayToolError("Launch must have a verified identity before release. Check status again; unconfirmed launches remain reserved.");
      }
      if (remote && remote.id !== row.workerId) throw new RelayToolError("The agent name now belongs to a different launch. Release was blocked.");
      // A release already dispatched whose receipt was lost is replayed with the same key below,
      // so its receipt can be recovered; roster absence alone is never treated as proof.
      const dispatched = row.state === "releasing" && !row.releaseInvocationId && releaseDispatched(row);
      if (!dispatched && (!remote || remote.status === "released")) {
        // Absence from the roster is not proof the worker stopped.
        throw new RelayToolError("The original agent is absent without a verified release. Keep this spawn_id and ask an operator to confirm termination; release was not dispatched.");
      }
      if (row.state === "ready") row = await deps.store.update(row, { state: "releasing" });
      if (!row.releaseInvocationId) {
        const attempt = row.audit.filter(entry => entry.event === "release_failed").length;
        // Journal the dispatch before sending, so a lost response is replayed with this same key.
        if (!releaseDispatched(row)) {
          row = await deps.store.update(row, { event: "release_dispatch" });
        }
        const release = await deps.client.releaseSpawnedAgent(actor.token, row.agentName, row.workerId!,
          attempt === 0 ? `selfhost-release:${row.id}` : `selfhost-release:${row.id}:${attempt}`);
        if (release.status === "completed") return result(await deps.store.update(row, { state: "released", ...(release.id ? { releaseInvocationId: release.id } : {}) }));
        if (!release.id) throw new RelayToolError("Release receipt was not confirmed. Retry release_relay_agent with the same spawn_id.");
        row = await deps.store.update(row, { releaseInvocationId: release.id });
      }
      return result(await refresh(actor, row));
    }),
  };
}

function correlated(row: SpawnRow, agent: { id: string; name: string; address: string | null; status: string | null; metadata: Record<string, unknown> }) {
  const fleet = agent.metadata.fleet;
  return !!row.invocationId && typeof fleet === "object" && fleet !== null &&
    (fleet as Record<string, unknown>).invocation_id === row.invocationId &&
    (fleet as Record<string, unknown>).node_id === row.nodeId &&
    agent.name === row.agentName && !!agent.address?.startsWith(`${row.agentName}@`) && agent.status !== "released";
}

// ---------------------------------------------------------------------------
// Dependencies and tools.

export function relaySpawnDeps(context: McpContext): RelaySpawnDeps {
  const { database, client } = context.relay;
  const workspaceId = context.workspace.id;
  const relaycastWorkspaceId = context.workspace.relaycastWorkspaceId;
  return {
    client,
    workspaceKey: context.workspace.relaycastApiKey,
    store: spawnStore(database, context.oauth ? { beforeReserve: async tx => {
      await context.oauth!.lock(tx);
      if (!["owner", "admin"].includes(context.oauth!.access.principal.role ?? "")) throw new RelayToolError(LAUNCH_ROLE_REFUSAL);
    } } : {}),
    async owners(nodeIds) {
      if (nodeIds.length === 0) return new Map();
      // Only this workspace's claims on this workspace's relay; the membership FK drops a departed owner's claim.
      const result = await database.query<{ node_id: string; user_id: string; name: string | null }>(
        `SELECT o.node_id, o.user_id, u.name FROM fleet_node_owners o JOIN users u ON u.id = o.user_id
          WHERE o.workspace_id = $1 AND o.relaycast_workspace_id = $2 AND o.node_id = ANY($3::text[])`,
        [workspaceId, relaycastWorkspaceId, [...new Set(nodeIds)]],
      );
      return new Map(result.rows.map(row => [String(row.node_id), { userId: String(row.user_id),
        name: typeof row.name === "string" ? row.name : null }]));
    },
    withActor: fn => relayService(context).withSpawnActor(fn),
    ...(context.relay.relaygatePublicUrl ? { launchCredentials: relayLaunchCredentials(database, context.relay.keyring) } : {}),
    ...(context.relay.launchCheck ? { launchCheck: context.relay.launchCheck } : {}),
    ...(context.relay.spawnMemoryPolicy ? { memoryPolicy: context.relay.spawnMemoryPolicy } : {}),
    async pendingLaunches() {
      // Launches still starting on each node, which a node's memory sample may not reflect yet.
      const result = await database.query<{ node_id: string; created_at: Date | string }>(
        `SELECT node_id, created_at FROM relay_spawns
          WHERE workspace_id = $1 AND relaycast_workspace_id = $2 AND state IN ('reserved', 'accepted')
            AND created_at > now() - interval '60 seconds'`,
        [workspaceId, relaycastWorkspaceId]);
      const pending = new Map<string, Date[]>();
      for (const row of result.rows) {
        const list = pending.get(String(row.node_id)) ?? [];
        list.push(new Date(row.created_at));
        pending.set(String(row.node_id), list);
      }
      return pending;
    },
  };
}

const RELEASE_HINT = "Agent launch operation failed. Keep the same idempotency_key and any spawn_id for receipt recovery; do not launch a replacement to guess the outcome.";

export function registerRelaySpawnTools(server: McpServer, context: McpContext, deps: RelaySpawnDeps = relaySpawnDeps(context)): void {
  const run = async (fn: (service: ReturnType<typeof relaySpawnService>) => Promise<unknown>) => {
    try {
      const data = await fn(relaySpawnService(context, deps));
      const failed = typeof data === "object" && data !== null && "status" in data && (data as { status: unknown }).status === "failed";
      return { ...(failed ? { isError: true as const } : {}), structuredContent: data as Record<string, unknown>,
        content: [{ type: "text" as const, text: JSON.stringify(data) }] };
    } catch (error) {
      if (error instanceof RelaySpawnAdmissionError) {
        return { isError: true as const, structuredContent: { error: error.details },
          content: [{ type: "text" as const, text: JSON.stringify({ error: error.details }) }] };
      }
      if (error instanceof RelayToolError || error instanceof RelaycastCallError) return relayFailure(error);
      console.error("[selfhost-mcp] launch tool failed", { error: error instanceof Error ? error.name : "unknown" });
      return { isError: true as const, content: [{ type: "text" as const, text: RELEASE_HINT }] };
    }
  };
  server.registerTool("list_relay_spawn_targets", {
    description: "List the live machines in the current workspace's fleet that can launch agents, ranked best first. Each target reports target_node (its id; pass it to spawn_relay_agent, which also accepts a node name that only one node has, live), name, kind, machine, owner, allowed status, repositories, harnesses and versions, available slots, load, memory and ranking reason. Pass harness (the one you intend to launch) so memory is judged for it. A target with allowed false cannot accept this connection's launch; one with admissible false would refuse that launch now. Requires current workspace owner or admin access. Does not provision machines.",
    inputSchema: targetsInput.shape, annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, input => run(service => service.targets(input)));
  server.registerTool("spawn_relay_agent", {
    description: "Start an agent on one exact allowed target_node (a node id from list_relay_spawn_targets, or a name that only one node has, live) with a harness that target advertises. Among nodes sharing a name case-insensitively, the exact (case-sensitive) stored name wins when that node is live; otherwise the name is refused, and a value matching nothing is refused with the valid ids and names. The receipt always records the node id. worker_cwd (strongly recommended) is the absolute working directory on that machine. Nothing is selected, queued, retried or rerouted automatically. Permission, capacity, availability and (when the memory policy enforces) free memory are rechecked; a rejection returns a structured failure and allowed alternatives that would take the launch now. spawn_memory_low is retryable. An accepted result includes spawn_id and is not yet a readiness confirmation; poll get_relay_spawn_status.",
    inputSchema: spawnInput.shape, annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, (input, extra) => run(service => service.spawn(input, extra.requestId)));
  server.registerTool("get_relay_spawn_status", {
    description: "Refresh and return a launch you started, including readiness, structured terminal errors and any unconfirmed initial-task warning. A launch stays reachable from a later session of the same person in the same workspace; on an OAuth connection it must be the same approved connection. Unknown outcomes remain attached to the original spawn_id.",
    inputSchema: { spawn_id: z.string().uuid() }, annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, input => run(service => service.status(input.spawn_id)));
  server.registerTool("release_relay_agent", {
    description: "Stop and remove only a verified agent you launched. A launch stays reachable from a later session of the same person in the same workspace; on an OAuth connection it must be the same approved connection. Release uses the immutable worker identity and is repeat-safe. It does not delete or provision machines.",
    inputSchema: { spawn_id: z.string().uuid() }, annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, input => run(service => service.release(input.spawn_id)));
}
