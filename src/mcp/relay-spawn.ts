import { randomUUID } from "node:crypto";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SqlExecutor } from "../database.js";
import {
  RELAY_HARNESS_ID_PATTERN, RelaycastCallError, type RelaycastClient, type RelaySpawnInvocation, type RelaySpawnTarget,
} from "../messaging/relaycast.js";
import { LAUNCH_ROLE_REFUSAL } from "./catalog.js";
import type { McpContext } from "./context.js";
import { ownerHash, relayFailure, relayService, RelayToolError, type SpawnActor } from "./relay-participants.js";
import {
  alternativesFor, notAllowedMessage, rankTargets, type PlacedTarget, type SpawnNodeOwner,
} from "./relay-spawn-placement.js";

/**
 * Agent launches (SELFHOST_FEATURES launch; docs/agent-launch.md), ported
 * from Cloud's `lib/mcp/relay-spawn-service.ts` and `relay-spawn-tools.ts`.
 *
 * Launches reach only existing nodes enrolled in this workspace's own
 * Relaycast workspace: targets are read with this workspace's key and owners
 * from fleet_node_owners rows for this workspace and Relaycast workspace, so
 * a node from another workspace or another installation is never listed or
 * reachable. Every call rechecks the owner/admin role read at admission and
 * refuses OAuth connections. A launch is journaled (relay_spawns) before it
 * is sent and is sent at most once per journal row; status and release only
 * reach rows owned by the same workspace, user, MCP authority, Relaycast
 * workspace and launcher actor.
 */

export const spawnInput = z.object({
  name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/),
  cli: z.string().regex(RELAY_HARNESS_ID_PATTERN).describe("Harness advertised by the selected target_node, for example codex, claude, opencode or grok. Lowercase letters, digits and hyphens, at most 32 characters."),
  target_node: z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/).describe("Required identifier of an allowed live launch target in the current workspace fleet (target_node from list_relay_spawn_targets)."),
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

export function spawnStore(database: { query: SqlExecutor["query"]; transaction<T>(run: (tx: SqlExecutor) => Promise<T>): Promise<T> }) {
  async function find(owner: SpawnOwner, id: string): Promise<SpawnRow | null> {
    const result = await database.query(`SELECT ${COLUMNS} FROM relay_spawns WHERE ${OWNED} AND id = $6`, [...ownedParams(owner), id]);
    return result.rows[0] ? rowFrom(result.rows[0]) : null;
  }
  return {
    find,
    async findKey(owner: SpawnOwner, hash: string): Promise<SpawnRow | null> {
      const result = await database.query(`SELECT ${COLUMNS} FROM relay_spawns WHERE ${OWNED} AND idempotency_hash = $6`,
        [...ownedParams(owner), hash]);
      return result.rows[0] ? rowFrom(result.rows[0]) : null;
    },
    /** One transaction per reservation, never held over a network call. */
    reserve(row: Omit<SpawnRow, "updatedAt">): Promise<{ row: SpawnRow; created: boolean }> {
      return database.transaction(async (tx) => {
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

function failureMessage(code: string, node: string, harness: string, advertised?: string[]): string {
  return code === "spawn_capacity_exceeded" ? `Node "${node}" is at capacity`
    : code === "spawn_target_offline" ? `Node "${node}" is offline`
    : code === "spawn_harness_unavailable" ? `Node "${node}" does not provide spawn:${harness}` +
      (advertised?.length ? `; it advertises ${advertised.join(", ")}` : "")
    : code === "spawn_target_unavailable" ? `Node "${node}" is unavailable for spawn`
    : `Agent launch on "${node}" failed`;
}
const SPAWN_CODES = new Set(["spawn_failed", "spawn_capacity_exceeded", "spawn_target_unavailable", "spawn_target_offline",
  "spawn_harness_unavailable", "capacity_changed"]);
function failure(code: string | null, node: string, harness: string): SpawnFailure {
  const known = code && SPAWN_CODES.has(code) ? code : "spawn_failed";
  return { code: known, message: failureMessage(known, node, harness), node, harness, observed_at: new Date().toISOString(),
    retryable: ["spawn_capacity_exceeded", "spawn_target_offline", "spawn_target_unavailable", "capacity_changed"].includes(known) };
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
};

export function relaySpawnService(context: Pick<McpContext, "authMode" | "role" | "principal" | "workspace" | "relay" | "oauth">,
  deps: RelaySpawnDeps) {
  const userId = context.principal.userId;
  const sessionId = context.relay.sessionId;

  function authorize(): void {
    if (context.oauth || context.authMode === "oauth") {
      throw new RelayToolError("Agent launches are not available through an OAuth MCP connection on this self-hosted site. Connect with an Agent Relay CLI login or Agent Relay Desktop.");
    }
    if (context.role !== "owner" && context.role !== "admin") throw new RelayToolError(LAUNCH_ROLE_REFUSAL);
  }
  function owner(actor: SpawnActor): SpawnOwner {
    if (!sessionId) throw new RelayToolError("Initialize MCP and retain Mcp-Session-Id before starting agents.");
    return { workspaceId: context.workspace.id, userId, relaycastWorkspaceId: actor.relaycastWorkspaceId, actorId: actor.id,
      authorityHash: ownerHash(JSON.stringify([context.authMode, sessionId])) };
  }
  const run = <T>(fn: (actor: SpawnActor, owned: SpawnOwner) => Promise<T>): Promise<T> => {
    authorize();
    return deps.withActor(actor => fn(actor, owner(actor)));
  };
  async function lookup(owned: SpawnOwner, id: string): Promise<SpawnRow> {
    if (!z.string().uuid().safeParse(id).success) throw new RelayToolError("Use a spawn_id returned by this connection.");
    const row = await deps.store.find(owned, id);
    if (!row) throw new RelayToolError("This launch is not owned by this connection in the current workspace.");
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

  return {
    async targets() {
      authorize();
      const targets = (await deps.client.listSpawnTargets(deps.workspaceKey)).filter(eligible);
      return {
        targets: rankTargets(targets, await deps.owners(targets.map(target => target.id)), userId),
        note: "Ranked best first. Choose an allowed target, preferring an allowed desktop with the task's repository and free slots, " +
          "and pass its target_node to spawn_relay_agent. Existing machines only; permission and capacity are rechecked at launch.",
      };
    },

    async spawn(raw: unknown, requestId: string | number) {
      const parsed = spawnInput.safeParse(raw);
      if (!parsed.success) {
        throw new RelayToolError("Invalid launch input. Use a harness id the target advertises, an explicit target, a literal absolute directory and a task of at most 8192 UTF-8 bytes.");
      }
      const input: SpawnInput = parsed.data;
      return run(async (actor, owned) => {
        const key = input.idempotency_key ?? ownerHash(JSON.stringify([sessionId ?? null, requestId]));
        const launch = { name: input.name, cli: input.cli, task: input.task, target_node: input.target_node,
          ...(input.worker_cwd ? { worker_cwd: input.worker_cwd } : {}) };
        const idempotencyHash = ownerHash(JSON.stringify(["selfhost-spawn:v1", owned, key]));
        const requestHash = ownerHash(JSON.stringify(launch));
        const previous = await deps.store.findKey(owned, idempotencyHash);
        if (previous) {
          if (previous.requestHash !== requestHash) throw new RelayToolError("This idempotency key already describes a different launch.");
          return result(previous);
        }
        const online = await deps.client.listSpawnTargets(deps.workspaceKey);
        let target = online.find(item => item.id === input.target_node);
        const offline = target ? null
          : (await deps.client.listSpawnTargets(deps.workspaceKey, { includeOffline: true })).find(item => item.id === input.target_node);
        const owners = await deps.owners([...online.filter(eligible), ...(target ? [target] : []), ...(offline ? [offline] : [])]
          .map(item => item.id));
        const ranked = rankTargets(online.filter(eligible), owners, userId);
        const refuse = (code: string, refused: RelaySpawnTarget | undefined, placed?: PlacedTarget) => {
          const name = refused?.name ?? input.target_node;
          const advertised = code === "spawn_harness_unavailable" && refused
            ? refused.capabilities.map(capability => capability.slice("spawn:".length)) : undefined;
          return new RelaySpawnAdmissionError({
            code, message: code === "spawn_target_not_allowed" && placed ? notAllowedMessage(placed) : failureMessage(code, name, input.cli, advertised),
            node: name, harness: input.cli, ...(advertised ? { advertised } : {}),
            ...(code === "spawn_target_not_allowed" ? { owner: placed?.owner ?? null } : {}),
            active: refused?.activeAgents ?? null, reserved: refused?.reservedAgents ?? null, max: refused?.maxAgents ?? null,
            observed_at: new Date().toISOString(),
            retryable: !["spawn_harness_unavailable", "spawn_target_not_allowed"].includes(code),
            alternatives: alternativesFor(ranked, input.cli, { id: input.target_node,
              repositories: placed?.repositories }),
          });
        };
        // Permission first, even for an offline node: a node you may not use is never retryable.
        const known = target ?? offline ?? undefined;
        if (!known) throw refuse("spawn_target_unavailable", undefined);
        const placed = rankTargets([known], owners, userId)[0]!;
        if (!placed.allowed) throw refuse("spawn_target_not_allowed", known, placed);
        if (!target || !target.live) throw refuse("spawn_target_offline", known, placed);
        if (!target.handlersLive || target.stale || target.name === "self") throw refuse("spawn_target_unavailable", target, placed);
        if (!target.capabilities.includes(`spawn:${input.cli}`)) throw refuse("spawn_harness_unavailable", target, placed);
        if (!eligible(target)) throw refuse("spawn_capacity_exceeded", target, placed);

        const now = new Date().toISOString();
        const reserved = await deps.store.reserve({ ...owned, id: randomUUID(), idempotencyHash, requestHash,
          agentName: input.name, cli: input.cli, nodeId: target.id, state: "reserved", invocationId: null, workerId: null,
          workerAddress: null, releaseInvocationId: null, taskUnconfirmed: false, revision: 0,
          audit: [{ event: "reserved", at: now }] });
        if (!reserved.created) return result(reserved.row);
        let row = reserved.row;
        try {
          const invocation = await deps.client.spawnRelayAgent(actor.token, { ...launch, target_node: target.name }, `selfhost-spawn:${row.id}`);
          row = await deps.store.update(row, { state: "accepted", invocationId: invocation.id });
        } catch (error) {
          // Never send a second launch, even when the response is lost.
          const rejected = error instanceof RelaycastCallError && !error.outcomeUnknown;
          row = await deps.store.update(row, rejected
            ? { state: "failed", failure: failure(upstreamSpawnCode(error), target.name, input.cli) }
            : { state: "unknown" });
        }
        return row.state === "failed"
          ? { ...result(row), alternatives: alternativesFor(ranked, input.cli, { id: target.id, repositories: placed.repositories }) }
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
    store: spawnStore(database),
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
    description: "List the live machines in the current workspace's fleet that can launch agents, ranked best first. Each target reports target_node, kind, machine, owner, allowed status, repositories, harnesses and versions, available slots, load and ranking reason. A target with allowed false cannot accept this connection's launch. Requires current workspace owner or admin access. Does not provision machines.",
    inputSchema: {}, annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, () => run(service => service.targets()));
  server.registerTool("spawn_relay_agent", {
    description: "Start an agent on one exact allowed target_node with a harness that target advertises. worker_cwd (strongly recommended) is the absolute working directory on that machine. Nothing is selected, queued, retried or rerouted automatically. Permission, capacity and availability are rechecked; a rejection returns a structured failure and allowed alternatives. An accepted result includes spawn_id and is not yet a readiness confirmation; poll get_relay_spawn_status.",
    inputSchema: spawnInput.shape, annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, (input, extra) => run(service => service.spawn(input, extra.requestId)));
  server.registerTool("get_relay_spawn_status", {
    description: "Refresh and return a launch owned by this connection, including readiness, structured terminal errors and any unconfirmed initial-task warning. Unknown outcomes remain attached to the original spawn_id.",
    inputSchema: { spawn_id: z.string().uuid() }, annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, input => run(service => service.status(input.spawn_id)));
  server.registerTool("release_relay_agent", {
    description: "Stop and remove only a verified agent launched by this connection. Release uses the immutable worker identity and is repeat-safe. It does not delete or provision machines.",
    inputSchema: { spawn_id: z.string().uuid() }, annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, input => run(service => service.release(input.spawn_id)));
}
