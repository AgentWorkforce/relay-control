import { z } from "zod";
import type { SqlExecutor } from "../database.js";
import { assertEnvironmentRowAccessInTx, IdentityRefusal } from "./environments.js";
import {
  accessRevoked,
  byId,
  connectionKey,
  ENVIRONMENT_IDENTITY,
  ensureRelaySubscriptions,
  patch,
  relayFor,
  ReplicasError,
  scopeOf,
  underKey,
  withReplicasLock,
  type ReplicasDeps,
  type SpawnRow,
} from "./service.js";

/**
 * Push delivery for environment-identity bindings. Delivery is not
 * pull-only: once a replica enrols through the environment-level MCP, Relay
 * messages to its agent are pushed into one of its chats by the binding's
 * webhook (relayEvent in ./service.ts), and check_relay_inbox stays the
 * polling fallback.
 *
 * The chat: a replica with exactly one chat has it selected automatically;
 * with several, the workspace owner/admin who is the binding's person picks
 * one through bind_replica, and the selection is immutable afterwards. A
 * push is sent only while the provider reports the replica active: sleeping
 * compute is never woken, the delivery claim waits in `retrying` and Relay
 * retries it later. A pushed message stays readable through
 * check_relay_inbox until it is acknowledged there, so a replica that also
 * polls may see it twice.
 *
 * Each reconcile is triggered after a successful admission and coalesced per
 * replica in this process; every Control pod keeps its own coalescing map,
 * and the workspace lock serializes them.
 */

export type ReplicaInboundCode = "replica_chat_not_found" | "replica_chat_selection_required" | "replica_chat_inactive";

/** A chat that cannot receive a push. Its message is the code. */
export class ReplicaInboundError extends ReplicasError {
  constructor(readonly code: ReplicaInboundCode) {
    super(code, code === "replica_chat_not_found" ? 404 : 409);
    this.name = "ReplicaInboundError";
  }
}

const chatList = z.array(z.object({ id: z.string().uuid(), provider: z.string().min(1) })).max(100);

/**
 * Proves the binding's chat can receive a push now: the replica is active
 * and still lists the selected chat, or lists exactly one chat when none is
 * selected yet (that one is saved as the selection). Never wakes sleeping
 * compute. A provider 401/403 is marked with the key it was made with
 * (underKey) so the caller's lock or recordRefusedKey latches it.
 */
export async function proveReplicaChatInTx(deps: ReplicasDeps, tx: SqlExecutor, row: SpawnRow): Promise<SpawnRow> {
  if (!row.replica_id) throw new ReplicaInboundError("replica_chat_not_found");
  const { key, ciphertext } = await connectionKey(deps, tx, row.workspace_id);
  const replicaId = row.replica_id;
  const { replica } = await underKey(ciphertext, () => deps.replicas.get(key, replicaId));
  if (replica.status !== "active") throw new ReplicaInboundError("replica_chat_inactive");
  const parsed = chatList.safeParse(replica.chats ?? []);
  if (!parsed.success) throw new ReplicaInboundError("replica_chat_not_found");
  const chats = parsed.data;
  if (row.chat_id) {
    const selected = row.chat_id.toLowerCase();
    if (!chats.some((chat) => chat.id.toLowerCase() === selected)) throw new ReplicaInboundError("replica_chat_not_found");
    return row;
  }
  if (chats.length !== 1) throw new ReplicaInboundError("replica_chat_selection_required");
  return patch(tx, row.id, { chat_id: chats[0]!.id });
}

/** The safe code stored in `relay_inbound_error` and on a refused claim: never provider or Relay text. */
export function inboundErrorCode(error: unknown): string {
  if (error instanceof IdentityRefusal || error instanceof ReplicaInboundError) return error.code;
  if (accessRevoked(error)) return "replica_provider_access_revoked";
  return "replica_inbound_unavailable";
}

const ready = (row: SpawnRow | null): row is SpawnRow =>
  row !== null && row.state === "bound" && Boolean(row.token_ciphertext) && Boolean(row.agent_name);

/**
 * Brings one binding's push delivery up to date under the workspace lock:
 * the persisted enrolment checks (environment-identity rows), the chat
 * proof, the workspace Relay and both subscriptions. Success stamps
 * `relay_inbound_checked_at` and clears `relay_inbound_error`; a failure
 * stamps the time and the safe code in a separate transaction, best effort.
 * Rows that are not bound yet are left alone.
 *
 * Inbox catch-up (replaying messages that arrived while no push was
 * possible, from `relay_inbound_cursor`) and a periodic sweep over bound rows
 * are not part of this pass yet; they extend it after the subscriptions.
 */
export async function reconcileReplicaInbound(deps: ReplicasDeps, spawnId: string): Promise<void> {
  const candidate = await byId(deps.database, spawnId);
  if (!ready(candidate)) return;
  try {
    await withReplicasLock(deps, scopeOf(candidate), async (tx) => {
      let row = await byId(tx, spawnId, true);
      if (!ready(row)) return;
      if (row.source === ENVIRONMENT_IDENTITY) await assertEnvironmentRowAccessInTx(tx, row);
      row = await proveReplicaChatInTx(deps, tx, row);
      const relay = await relayFor(deps, tx, { workspaceId: row.workspace_id, userId: row.user_id }, row.relay_workspace_id);
      row = await ensureRelaySubscriptions(deps, tx, row, relay);
      await patch(tx, row.id, { input: { ...row.input, relay_inbound_checked_at: deps.now().toISOString(), relay_inbound_error: null } });
    });
  } catch (error) {
    const code = inboundErrorCode(error);
    await withReplicasLock(deps, scopeOf(candidate), async (tx) => {
      const row = await byId(tx, spawnId, true);
      if (!ready(row)) return;
      await patch(tx, row.id, { input: { ...row.input, relay_inbound_checked_at: deps.now().toISOString(), relay_inbound_error: code } });
    }).catch(() => undefined);
  }
}

/** One reconcile per replica per window in this process. */
export const INBOUND_COALESCE_MS = 30_000;
export const INBOUND_COALESCE_MAX = 2_000;
const recent = new WeakMap<ReplicasDeps, Map<string, number>>();

/**
 * Starts a reconcile for an environment-identity binding without waiting
 * for it, unless the same replica started one within INBOUND_COALESCE_MS.
 * The map is bounded: expired entries go first, then the oldest. Returns the
 * running reconcile (it never rejects), or null when none was started.
 */
export function scheduleReplicaInbound(deps: ReplicasDeps, row: SpawnRow): Promise<void> | null {
  if (row.source !== ENVIRONMENT_IDENTITY || !row.replica_id) return null;
  let seen = recent.get(deps);
  if (!seen) {
    seen = new Map();
    recent.set(deps, seen);
  }
  const now = deps.now().getTime();
  const replica = row.replica_id.toLowerCase();
  const last = seen.get(replica);
  if (last !== undefined && now - last < INBOUND_COALESCE_MS) return null;
  seen.delete(replica);
  if (seen.size >= INBOUND_COALESCE_MAX) {
    for (const [key, at] of seen) if (now - at >= INBOUND_COALESCE_MS) seen.delete(key);
    while (seen.size >= INBOUND_COALESCE_MAX) {
      const oldest = seen.keys().next().value;
      if (oldest === undefined) break;
      seen.delete(oldest);
    }
  }
  seen.set(replica, now);
  const running = reconcileReplicaInbound(deps, row.id).catch(() => undefined);
  void running;
  return running;
}
