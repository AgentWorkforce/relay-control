import { randomBytes, randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";
import { decryptSecret, encryptSecret, hashSecret, type EncryptionKeyring } from "../crypto.js";
import type { RelaycastClient, RemoteAgent } from "../messaging/relaycast.js";
import { HOSTED_SOURCE, ownerHash } from "../mcp/relay-participants.js";
import { historyState, HISTORY_PUSH_UNAVAILABLE, type HistoryRowState, type HistoryUploader, type PushSessionFactory } from "./history.js";
import { ampExport, ampThreadId } from "./provider.js";
import { AMP_KEY, AmpRuntimeError, type AmpOperation, type AmpRuntime } from "./runtime.js";

export type AmpDeps = {
  database: Database;
  keyring: EncryptionKeyring;
  relaycast: RelaycastClient;
  run: AmpRuntime;
  /** Public origin of this API; the reply helper and relay-events URLs are built from it. */
  publicBaseUrl: string;
  now: () => Date;
  leaseMs: number;
  /**
   * Workspace-scoped, push-only RelayHistory session for history upload
   * (history.ts). null in production: see module.ts and the header of
   * history.ts for the missing capability. While null, history never exports
   * or polls Amp.
   */
  pushSession: PushSessionFactory | null;
  /** Upload transport for prepared ingest pages; defaults to POST {baseUrl}/v1/ingest. */
  historyUpload?: HistoryUploader;
};

/** A person acting through REST or MCP. Authority is re-read from Postgres; nothing here is trusted. */
export type AmpActor = { userId: string; workspaceId: string; organizationId: string };

export class AmpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "AmpError";
  }
}

export type BindingRow = {
  id: string;
  workspace_id: string;
  organization_id: string;
  user_id: string;
  thread_id: string;
  state: "preparing" | "bound" | "retired";
  generation: number;
  relaycast_workspace_id: string | null;
  agent_name: string;
  agent_remote_id: string | null;
  token_ciphertext: string | null;
  hook_ciphertext: string | null;
  subscription_id: string | null;
  mention_subscription_id: string | null;
  last_synced_at: Date | string | null;
  last_error: string | null;
};

const BINDING_COLUMNS = `id, workspace_id, organization_id, user_id, thread_id, state, generation,
  relaycast_workspace_id, agent_name, agent_remote_id, token_ciphertext, hook_ciphertext,
  subscription_id, mention_subscription_id, last_synced_at, last_error`;

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const MESSAGE_ID = /^[A-Za-z0-9_-]{1,128}$/;
export const SEND_UNKNOWN = "amp_send_unknown: inspect the thread before retrying";
const CHANGED = "Amp settings changed while this request ran. Try again.";

export const encrypt = (deps: AmpDeps, value: string) => encryptSecret(value, deps.keyring.active);
export const decrypt = (deps: AmpDeps, value: string) => decryptSecret(value, deps.keyring);
export const agentNameFor = (threadId: string) => `amp-${hashSecret(threadId).slice(0, 16)}`;
/** A fresh Standard Webhooks secret for one binding's relay-events hook (as hosted Cloud mints it). */
const mintHookSecret = () => `whsec_${randomBytes(32).toString("base64")}`;

/**
 * The two Relaycast subscriptions every bound thread needs, in hosted Cloud's
 * order: its DMs and thread replies, then channel messages that mention it.
 */
const SUBSCRIPTIONS = [
  { column: "subscription_id", events: ["dm.received", "thread.reply"], mention: false },
  { column: "mention_subscription_id", events: ["message.created"], mention: true },
] as const;

const iso = (value: Date | string | null) => (value === null ? null : new Date(value).toISOString());

export function parseThreadId(raw: unknown): string {
  try {
    return ampThreadId(typeof raw === "string" ? raw : "");
  } catch {
    throw new AmpError(400, "invalid_thread", "Supply an Amp thread ID (T-...) or its ampcode.com URL.");
  }
}

/** Amp process failures; the provider's own detail is never surfaced. */
function ampFailure(error: unknown): AmpError {
  if (error instanceof AmpRuntimeError && error.code === "amp_transport_not_configured") {
    return new AmpError(503, "amp_transport_not_configured", "The Amp transport is not configured on this control plane.");
  }
  return new AmpError(502, "amp_unavailable", "Amp could not complete this operation. Check its connection in Settings.");
}

export async function runAmp(deps: AmpDeps, key: string, operation: AmpOperation): Promise<unknown> {
  try {
    return await deps.run(key, operation);
  } catch (error) {
    throw ampFailure(error);
  }
}

/**
 * Serializes Amp state per workspace. The organization row is share-locked
 * first, the same row store.deleteMembership locks for update, so a member
 * removal and an Amp change never interleave.
 */
export function withAmpLock<T>(
  deps: AmpDeps,
  scope: { workspaceId: string; organizationId: string },
  run: (tx: SqlExecutor) => Promise<T>,
): Promise<T> {
  return deps.database.transaction(async (tx) => {
    await tx.query("SELECT id FROM selfhost_organizations WHERE id = $1 FOR SHARE", [scope.organizationId]);
    await tx.query("SELECT pg_advisory_xact_lock(hashtext('selfhost-amp'), hashtext($1))", [scope.workspaceId]);
    return run(tx);
  });
}

export type WorkspaceRelay = { relaycastWorkspaceId: string; key: string };

/** Current owner/admin of this workspace's organization, read under the caller's lock. */
export async function requireAdmin(deps: AmpDeps, tx: SqlExecutor, actor: AmpActor): Promise<WorkspaceRelay> {
  const result = await tx.query<{ role: string; relaycast_workspace_id: string; relaycast_api_key_ciphertext: string }>(
    `SELECT m.role, w.relaycast_workspace_id, w.relaycast_api_key_ciphertext
       FROM selfhost_workspaces w
       JOIN selfhost_organization_memberships m
         ON m.organization_id = w.organization_id AND m.user_id = $3
      WHERE w.id = $1 AND w.organization_id = $2
      FOR SHARE OF m`,
    [actor.workspaceId, actor.organizationId, actor.userId],
  );
  const row = result.rows[0];
  if (!row || (row.role !== "owner" && row.role !== "admin")) {
    throw new AmpError(403, "forbidden", "Only current owners and admins can manage Amp.");
  }
  return { relaycastWorkspaceId: row.relaycast_workspace_id, key: decrypt(deps, row.relaycast_api_key_ciphertext) };
}

export async function workspaceRelay(deps: AmpDeps, executor: SqlExecutor, workspaceId: string): Promise<WorkspaceRelay | null> {
  const result = await executor.query<{ relaycast_workspace_id: string; relaycast_api_key_ciphertext: string }>(
    "SELECT relaycast_workspace_id, relaycast_api_key_ciphertext FROM selfhost_workspaces WHERE id = $1",
    [workspaceId],
  );
  const row = result.rows[0];
  return row ? { relaycastWorkspaceId: row.relaycast_workspace_id, key: decrypt(deps, row.relaycast_api_key_ciphertext) } : null;
}

type ConnectionRow = { user_id: string; key_ciphertext: string; key_hint: string; validated_at: Date | string };

async function connectionFor(tx: SqlExecutor, workspaceId: string): Promise<ConnectionRow | null> {
  const result = await tx.query<ConnectionRow>(
    "SELECT user_id, key_ciphertext, key_hint, validated_at FROM selfhost_amp_connections WHERE workspace_id = $1",
    [workspaceId],
  );
  return result.rows[0] ?? null;
}

export async function bindingById(executor: SqlExecutor, id: string, lock = false): Promise<BindingRow | null> {
  if (!UUID.test(id)) return null;
  const result = await executor.query<BindingRow>(
    `SELECT ${BINDING_COLUMNS} FROM selfhost_amp_bindings WHERE id = $1${lock ? " FOR UPDATE" : ""}`,
    [id],
  );
  return result.rows[0] ?? null;
}

function ownsBinding(agent: RemoteAgent, row: BindingRow): boolean {
  return agent.metadata.source === HOSTED_SOURCE
    && agent.metadata.amp_binding_id === row.id
    && agent.metadata.cloud_workspace_id === row.workspace_id
    && agent.metadata.owner_hash === ownerHash(row.user_id);
}

/** A Relay name may be recycled; delivery authority follows the immutable agent id. */
export async function requireBoundAgent(deps: AmpDeps, relay: WorkspaceRelay, row: BindingRow): Promise<void> {
  if (row.relaycast_workspace_id !== relay.relaycastWorkspaceId) {
    throw new AmpError(409, "relay_changed", "The bound relay is unavailable.");
  }
  const agent = await deps.relaycast.getAgent(relay.key, row.agent_name);
  if (!agent || agent.id !== row.agent_remote_id || !ownsBinding(agent, row)) {
    throw new AmpError(409, "relay_identity_changed",
      "The bound Relay identity changed. Disconnect and inspect it before reconnecting.");
  }
}

export function ownedThreads(data: unknown): Array<{ id: string; title: string }> {
  const rows = Array.isArray(data) ? data : (data as { threads?: unknown[] } | null)?.threads;
  const unsupported = () => new AmpError(502, "amp_unsupported_response", "Amp returned an unsupported thread list.");
  if (!Array.isArray(rows)) throw unsupported();
  return rows.slice(0, 100).map((value: unknown) => {
    if (!value || typeof value !== "object") throw unsupported();
    const row = value as { id?: unknown; title?: unknown };
    let id: string;
    try {
      id = ampThreadId(String(row.id));
    } catch {
      throw unsupported();
    }
    return { id, title: typeof row.title === "string" ? row.title.slice(0, 200) : id };
  });
}

/** Proves the key reads this thread, through the RelayHistory-owned parser only. */
async function exportProof(deps: AmpDeps, key: string, threadId: string): Promise<void> {
  let raw: unknown;
  try {
    raw = await deps.run(key, { kind: "export", threadId });
  } catch (error) {
    // A definite refusal of this one thread means the key cannot read it.
    if (error instanceof AmpRuntimeError && error.outcome === "rejected" && error.code === "amp_command_failed") {
      throw new AmpError(409, "amp_thread_unreadable", "This Amp key cannot read that thread.");
    }
    throw ampFailure(error);
  }
  try {
    ampExport(threadId, raw);
  } catch {
    throw new AmpError(409, "amp_thread_unreadable", "This Amp key cannot read that thread.");
  }
}

export async function summary(deps: AmpDeps, executor: SqlExecutor, workspaceId: string) {
  const connection = await connectionFor(executor, workspaceId);
  const bindings = await executor.query<BindingRow & HistoryRowState>(
    `SELECT ${BINDING_COLUMNS}, history_queued_at, history_lease_owner, history_lease_until, history_error
       FROM selfhost_amp_bindings WHERE workspace_id = $1 ORDER BY created_at, id`,
    [workspaceId],
  );
  const deliveries = await executor.query<{ binding_id: string; message_id: string; state: string }>(
    `SELECT d.binding_id, d.message_id, d.state
       FROM selfhost_amp_deliveries d JOIN selfhost_amp_bindings b ON b.id = d.binding_id
      WHERE b.workspace_id = $1 AND d.state <> 'delivered'
      ORDER BY d.created_at`,
    [workspaceId],
  );
  return {
    connection: connection
      ? { keyHint: connection.key_hint, validatedAt: iso(connection.validated_at), userId: connection.user_id }
      : null,
    bindings: bindings.rows.map((row) => ({
      id: row.id,
      threadId: row.thread_id,
      agentName: row.agent_name,
      state: row.state,
      lastError: row.last_error,
      lastSyncedAt: iso(row.last_synced_at),
      relaySubscription: row.subscription_id && row.mention_subscription_id ? "configured" : "not_configured",
      deliveries: deliveries.rows
        .filter((delivery) => delivery.binding_id === row.id)
        .map((delivery) => ({ messageId: delivery.message_id, state: delivery.state })),
      history: historyState(deps, row),
    })),
    history: deps.pushSession
      ? { available: true as const }
      : { available: false as const, reason: HISTORY_PUSH_UNAVAILABLE },
  };
}

export async function getSummary(deps: AmpDeps, actor: AmpActor) {
  return withAmpLock(deps, actor, async (tx) => {
    await requireAdmin(deps, tx, actor);
    return summary(deps, tx, actor.workspaceId);
  });
}

export async function connect(deps: AmpDeps, actor: AmpActor, raw: unknown) {
  const key = typeof raw === "string" ? raw.trim() : "";
  if (!AMP_KEY.test(key)) {
    throw new AmpError(400, "invalid_key", "Paste your Amp API key from Amp Security Settings (sgamp_…).");
  }
  // Authorize before any Amp call: a refused caller never reaches the provider.
  const before = await withAmpLock(deps, actor, async (tx) => {
    await requireAdmin(deps, tx, actor);
    const prior = await connectionFor(tx, actor.workspaceId);
    const bound = await tx.query<{ thread_id: string }>(
      "SELECT thread_id FROM selfhost_amp_bindings WHERE workspace_id = $1 AND state = 'bound'",
      [actor.workspaceId],
    );
    return { prior, bound: bound.rows.map((row) => row.thread_id) };
  });
  if (before.prior && before.bound.length && before.prior.user_id !== actor.userId) {
    throw new AmpError(409, "connection_owner_locked",
      "Disconnect existing Amp threads before changing the connection owner.");
  }
  // A read-only operation proves the key before it is stored. Never run a prompt to validate it.
  const threads = ownedThreads(await runAmp(deps, key, { kind: "discover" }));
  const priorKey = before.prior ? decrypt(deps, before.prior.key_ciphertext) : null;
  if (before.bound.length && priorKey !== key) {
    // A valid key may belong to another Amp account; keep the original key
    // until the replacement proves access to every thread that depends on it.
    try {
      for (const threadId of before.bound) ampExport(threadId, await deps.run(key, { kind: "export", threadId }));
    } catch {
      throw new AmpError(409, "key_cannot_read_threads",
        "This key cannot access every connected Amp thread. Your current key is unchanged.");
    }
  }
  return withAmpLock(deps, actor, async (tx) => {
    await requireAdmin(deps, tx, actor);
    const prior = await connectionFor(tx, actor.workspaceId);
    const bound = await tx.query<{ thread_id: string }>(
      "SELECT thread_id FROM selfhost_amp_bindings WHERE workspace_id = $1 AND state = 'bound'",
      [actor.workspaceId],
    );
    if (
      (prior?.key_ciphertext ?? null) !== (before.prior?.key_ciphertext ?? null)
      || bound.rows.some((row) => !before.bound.includes(row.thread_id))
    ) {
      throw new AmpError(409, "amp_changed", CHANGED);
    }
    await tx.query(
      `INSERT INTO selfhost_amp_connections
         (workspace_id, organization_id, user_id, key_ciphertext, key_hint, validated_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $6)
       ON CONFLICT (workspace_id) DO UPDATE
         SET user_id = EXCLUDED.user_id, key_ciphertext = EXCLUDED.key_ciphertext,
             key_hint = EXCLUDED.key_hint, validated_at = EXCLUDED.validated_at, updated_at = EXCLUDED.updated_at`,
      [actor.workspaceId, actor.organizationId, actor.userId, encrypt(deps, key), `sgamp_…${key.slice(-4)}`, deps.now()],
    );
    return { ...(await summary(deps, tx, actor.workspaceId)), threads };
  });
}

/** The connected key, only for the person who connected it (the API-key-owner fence). */
async function ownerKey(deps: AmpDeps, actor: AmpActor, message: string) {
  return withAmpLock(deps, actor, async (tx) => {
    await requireAdmin(deps, tx, actor);
    const connection = await connectionFor(tx, actor.workspaceId);
    if (!connection) throw new AmpError(409, "amp_not_connected", "Connect Amp in Settings first.");
    if (connection.user_id !== actor.userId) throw new AmpError(403, "not_connection_owner", message);
    return { key: decrypt(deps, connection.key_ciphertext), ciphertext: connection.key_ciphertext };
  });
}

export async function discover(deps: AmpDeps, actor: AmpActor) {
  // Use the same row whose ownership was authorized; a replacement committed
  // since then must never supply another person's key.
  const { key } = await ownerKey(deps, actor, "Only the person who connected Amp can browse its threads.");
  return ownedThreads(await runAmp(deps, key, { kind: "discover" }));
}

async function saveParticipant(deps: AmpDeps, tx: SqlExecutor, row: BindingRow, tokenCiphertext: string) {
  await tx.query(
    `INSERT INTO selfhost_hosted_relay_participants
       (id, workspace_id, user_id, relaycast_workspace_id, session_hash, agent_name, agent_remote_id, token_ciphertext)
     VALUES ($1, $2, $3, $4, NULL, $5, $6, $7)
     ON CONFLICT (workspace_id, user_id, agent_name) DO UPDATE
       SET relaycast_workspace_id = EXCLUDED.relaycast_workspace_id, agent_remote_id = EXCLUDED.agent_remote_id,
           token_ciphertext = EXCLUDED.token_ciphertext, updated_at = now()`,
    [randomUUID(), row.workspace_id, row.user_id, row.relaycast_workspace_id, row.agent_name, row.agent_remote_id, tokenCiphertext],
  );
}

/**
 * Binds one explicitly chosen thread. Only the connection owner may do it,
 * and only after the stored key exports that exact thread.
 */
export async function bind(deps: AmpDeps, actor: AmpActor, rawThread: unknown) {
  const threadId = parseThreadId(rawThread);
  const { key, ciphertext } = await ownerKey(deps, actor, "Only the person who connected Amp can select its threads.");
  await exportProof(deps, key, threadId);
  // Phase 1: a committed preparing row, so a crash after Relaycast registration is recoverable.
  const prepared = await withAmpLock(deps, actor, async (tx) => {
    const relay = await requireAdmin(deps, tx, actor);
    const connection = await connectionFor(tx, actor.workspaceId);
    if (!connection || connection.key_ciphertext !== ciphertext || connection.user_id !== actor.userId) {
      throw new AmpError(409, "amp_changed", CHANGED);
    }
    const existing = await tx.query<BindingRow>(
      `SELECT ${BINDING_COLUMNS} FROM selfhost_amp_bindings WHERE thread_id = $1 FOR UPDATE`,
      [threadId],
    );
    let row = existing.rows[0];
    if (row && (row.workspace_id !== actor.workspaceId || row.user_id !== actor.userId)) {
      throw new AmpError(409, "thread_owned", "This thread already has an owner on Relay.");
    }
    if (row?.state === "retired") {
      throw new AmpError(409, "thread_retired", "This thread was disconnected. Reconnect support requires a new binding.");
    }
    if (!row) {
      // The relay-events secret is minted once, with the row; a retry of this
      // preparing row reuses it (as hosted Cloud does).
      const inserted = await tx.query<BindingRow>(
        `INSERT INTO selfhost_amp_bindings
           (id, workspace_id, organization_id, user_id, thread_id, relaycast_workspace_id, agent_name, hook_ciphertext)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING ${BINDING_COLUMNS}`,
        [randomUUID(), actor.workspaceId, actor.organizationId, actor.userId, threadId,
          relay.relaycastWorkspaceId, agentNameFor(threadId), encrypt(deps, mintHookSecret())],
      );
      row = inserted.rows[0]!;
    } else if (!row.hook_ciphertext) {
      const updated = await tx.query<BindingRow>(
        `UPDATE selfhost_amp_bindings SET hook_ciphertext = $2, updated_at = now()
          WHERE id = $1 RETURNING ${BINDING_COLUMNS}`,
        [row.id, encrypt(deps, mintHookSecret())],
      );
      row = updated.rows[0]!;
    }
    return row;
  });
  // Phase 2: the Relaycast identity, owned by this binding id and person.
  // Committed while still preparing, so a later subscription failure keeps it.
  await withAmpLock(deps, actor, async (tx) => {
    const relay = await requireAdmin(deps, tx, actor);
    let row = await bindingById(tx, prepared.id, true);
    if (!row || row.state === "retired" || row.user_id !== actor.userId) throw new AmpError(409, "amp_changed", CHANGED);
    if (row.relaycast_workspace_id !== relay.relaycastWorkspaceId) {
      throw new AmpError(409, "relay_changed", "The bound relay is unavailable.");
    }
    if (!row.token_ciphertext) {
      const existing = await deps.relaycast.getAgent(relay.key, row.agent_name);
      if (existing && !ownsBinding(existing, row)) {
        throw new AmpError(409, "relay_name_taken", "This Relay name belongs to another agent.");
      }
      const agent = existing
        ? await deps.relaycast.recoverHosted(relay.key, row.agent_name, existing.id, `amp-binding:${row.id}`)
        : await deps.relaycast.registerHosted(relay.key, row.agent_name, {
          source: HOSTED_SOURCE,
          created_by: "amp-binding",
          amp_binding_id: row.id,
          cloud_workspace_id: row.workspace_id,
          owner_hash: ownerHash(row.user_id),
          session_kind: "amp",
          session_id: threadId,
          host: "Amp",
        });
      const updated = await tx.query<BindingRow>(
        `UPDATE selfhost_amp_bindings SET agent_remote_id = $2, token_ciphertext = $3, updated_at = now()
          WHERE id = $1 RETURNING ${BINDING_COLUMNS}`,
        [row.id, agent.id, encrypt(deps, agent.token)],
      );
      row = updated.rows[0]!;
    }
    await requireBoundAgent(deps, relay, row);
    await saveParticipant(deps, tx, row, row.token_ciphertext!);
  });
  // Phase 3: the two Relaycast event subscriptions, then bound. Ids this
  // attempt created are deleted again if anything after them fails (a later
  // create, the update storing them, or the commit), so the preparing row
  // stays retryable without leaking a subscription upstream.
  const created: string[] = [];
  const remote: { key: string | null } = { key: null };
  try {
    return await withAmpLock(deps, actor, async (tx) => {
      const relay = await requireAdmin(deps, tx, actor);
      remote.key = relay.key;
      const current = await bindingById(tx, prepared.id, true);
      if (!current || current.state === "retired" || current.user_id !== actor.userId
        || !current.token_ciphertext || !current.hook_ciphertext) {
        throw new AmpError(409, "amp_changed", CHANGED);
      }
      let row: BindingRow = current;
      if (row.relaycast_workspace_id !== relay.relaycastWorkspaceId) {
        throw new AmpError(409, "relay_changed", "The bound relay is unavailable.");
      }
      const secret = decrypt(deps, current.hook_ciphertext);
      for (const subscription of SUBSCRIPTIONS) {
        if (row[subscription.column]) continue;
        let id: string;
        try {
          id = await deps.relaycast.createSubscription(relay.key, {
            events: [...subscription.events],
            url: relayEventsUrl(deps, row.id),
            secret,
            ...(subscription.mention ? { filter: { mentions: row.agent_name } } : {}),
          });
        } catch {
          throw new AmpError(502, "relay_subscription_failed",
            "Relaycast could not create the event subscription for this thread. Try binding it again.");
        }
        created.push(id);
        const updated = await tx.query<BindingRow>(
          `UPDATE selfhost_amp_bindings SET ${subscription.column} = $2, updated_at = now()
            WHERE id = $1 RETURNING ${BINDING_COLUMNS}`,
          [row.id, id],
        );
        row = updated.rows[0]!;
      }
      await tx.query(
        "UPDATE selfhost_amp_bindings SET state = 'bound', last_error = NULL, updated_at = now() WHERE id = $1",
        [row.id],
      );
      return { binding_id: row.id, thread_id: threadId, agent: row.agent_name };
    });
  } catch (error) {
    const key = remote.key;
    if (key) for (const id of created) await deps.relaycast.deleteSubscription(key, id).catch(() => undefined);
    throw error;
  }
}

/**
 * Local revocation inside the caller's transaction: no Relaycast or Amp call.
 * Bumps the generation (fencing in-flight outbox claims), clears the agent
 * token, the relay-events secret, every reply capability and queued payload,
 * and drops any queued or leased history run with its pending page.
 * The subscription ids and agent id stay: releaseRetired needs them.
 */
export async function retireLocally(tx: SqlExecutor, where: string, params: unknown[]): Promise<string[]> {
  const retired = await tx.query<{ id: string; workspace_id: string; thread_id: string }>(
    `UPDATE selfhost_amp_bindings
        SET state = 'retired', generation = generation + 1, token_ciphertext = NULL,
            hook_ciphertext = NULL, history_queued_at = NULL, history_lease_owner = NULL,
            history_lease_until = NULL, updated_at = now()
      WHERE ${where} RETURNING id, workspace_id, thread_id`,
    params,
  );
  const ids = retired.rows.map((row) => row.id);
  if (!ids.length) return ids;
  await tx.query(
    `UPDATE selfhost_amp_deliveries
        SET state = CASE state WHEN 'pending' THEN 'rejected' WHEN 'sending' THEN 'unknown' ELSE state END,
            code = CASE WHEN state IN ('pending', 'sending') THEN 'binding_retired' ELSE code END,
            payload_ciphertext = NULL, reply_hash = NULL, reply_expires_at = NULL,
            lease_owner = NULL, lease_until = NULL, updated_at = now()
      WHERE binding_id = ANY($1::uuid[])`,
    [ids],
  );
  for (const row of retired.rows) {
    await tx.query(
      `UPDATE selfhost_amp_history_syncs SET pending_ciphertext = NULL, redactions_ciphertext = NULL
        WHERE workspace_id = $1 AND thread_id = $2`,
      [row.workspace_id, row.thread_id],
    );
  }
  return ids;
}

/**
 * Remote cleanup of one retired binding, after the revoking transaction
 * committed: delete its Relaycast subscriptions, release exactly the agent
 * this binding registered, then drop its participant and binding rows. A
 * subscription id is cleared only once deleted; any failure leaves the retired
 * row and its remaining locators for the worker's retry.
 */
export async function releaseRetired(deps: AmpDeps, bindingId: string): Promise<boolean> {
  const row = await bindingById(deps.database, bindingId);
  if (!row) return true;
  if (row.state !== "retired") return false;
  try {
    const relay = await workspaceRelay(deps, deps.database, row.workspace_id);
    if (!relay) return false;
    if (row.relaycast_workspace_id && row.relaycast_workspace_id === relay.relaycastWorkspaceId) {
      // Stop event delivery before the identity goes (hosted Cloud's order).
      for (const { column } of SUBSCRIPTIONS) {
        const id = row[column];
        if (!id) continue;
        await deps.relaycast.deleteSubscription(relay.key, id);
        await deps.database.query(
          `UPDATE selfhost_amp_bindings SET ${column} = NULL, updated_at = now() WHERE id = $1 AND ${column} = $2`,
          [row.id, id],
        );
      }
      const agent = await deps.relaycast.getAgent(relay.key, row.agent_name);
      if (agent && ((row.agent_remote_id && agent.id !== row.agent_remote_id) || !ownsBinding(agent, row))) {
        // A rejected name collision never established remote ownership: drop
        // only the preparatory row. Anything else needs a person to inspect it.
        if (row.agent_remote_id) {
          await deps.database.query(
            "UPDATE selfhost_amp_bindings SET last_error = $2, updated_at = now() WHERE id = $1",
            [row.id, "relay_identity_changed: inspect it before cleanup"],
          );
          return false;
        }
      } else if (agent) {
        await deps.relaycast.releaseHosted(relay.key, row.agent_name, agent.id);
      }
    }
    await deps.database.transaction(async (tx) => {
      await tx.query(
        `DELETE FROM selfhost_hosted_relay_participants
          WHERE workspace_id = $1 AND user_id = $2 AND agent_name = $3`,
        [row.workspace_id, row.user_id, row.agent_name],
      );
      await tx.query("DELETE FROM selfhost_amp_bindings WHERE id = $1 AND state = 'retired'", [row.id]);
    });
    return true;
  } catch {
    await deps.database.query(
      "UPDATE selfhost_amp_bindings SET last_error = $2, updated_at = now() WHERE id = $1",
      [row.id, "release_pending: Relaycast cleanup will retry"],
    ).catch(() => undefined);
    return false;
  }
}

export async function unbind(deps: AmpDeps, actor: AmpActor, id: string) {
  const retired = await withAmpLock(deps, actor, async (tx) => {
    await requireAdmin(deps, tx, actor);
    if (!UUID.test(id)) return [];
    return retireLocally(tx, "id = $1 AND workspace_id = $2", [id, actor.workspaceId]);
  });
  let released = true;
  for (const bindingId of retired) released = (await releaseRetired(deps, bindingId)) && released;
  return { disconnected: true, ...(released ? {} : { cleanup: "pending" }) };
}

export async function disconnect(deps: AmpDeps, actor: AmpActor) {
  const retired = await withAmpLock(deps, actor, async (tx) => {
    await requireAdmin(deps, tx, actor);
    const ids = await retireLocally(tx, "workspace_id = $1 AND state <> 'retired'", [actor.workspaceId]);
    await tx.query("DELETE FROM selfhost_amp_connections WHERE workspace_id = $1", [actor.workspaceId]);
    return ids;
  });
  let released = true;
  for (const bindingId of retired) released = (await releaseRetired(deps, bindingId)) && released;
  return { disconnected: true, ...(released ? {} : { cleanup: "pending" }) };
}

/**
 * store.deleteMembership beforeCommit hook: revokes everything the removed
 * person holds in Amp inside the membership transaction. Remote release runs
 * after commit (releaseMemberAmp).
 */
export async function purgeMemberAmp(tx: SqlExecutor, member: { organizationId: string; userId: string }): Promise<void> {
  await retireLocally(tx, "organization_id = $1 AND user_id = $2 AND state <> 'retired'", [member.organizationId, member.userId]);
  await tx.query(
    "DELETE FROM selfhost_amp_connections WHERE organization_id = $1 AND user_id = $2",
    [member.organizationId, member.userId],
  );
}

export async function releaseMemberAmp(deps: AmpDeps, member: { organizationId: string; userId: string }) {
  const rows = await deps.database.query<{ id: string }>(
    "SELECT id FROM selfhost_amp_bindings WHERE organization_id = $1 AND user_id = $2 AND state = 'retired'",
    [member.organizationId, member.userId],
  );
  for (const row of rows.rows) await releaseRetired(deps, row.id);
}

/**
 * Workspace deletion hook (no route calls it yet: self-host has no workspace
 * deletion). Releases identities even after the original owner has left.
 */
export async function cleanupWorkspaceAmp(deps: AmpDeps, workspaceId: string) {
  const workspace = await deps.database.query<{ organization_id: string }>(
    "SELECT organization_id FROM selfhost_workspaces WHERE id = $1",
    [workspaceId],
  );
  const organizationId = workspace.rows[0]?.organization_id;
  if (!organizationId) return { released: 0, pending: 0 };
  const retired = await withAmpLock(deps, { workspaceId, organizationId }, async (tx) => {
    const ids = await retireLocally(tx, "workspace_id = $1 AND state <> 'retired'", [workspaceId]);
    const already = await tx.query<{ id: string }>(
      "SELECT id FROM selfhost_amp_bindings WHERE workspace_id = $1 AND state = 'retired'",
      [workspaceId],
    );
    await tx.query("DELETE FROM selfhost_amp_connections WHERE workspace_id = $1", [workspaceId]);
    return [...new Set([...ids, ...already.rows.map((row) => row.id)])];
  });
  let pending = 0;
  for (const id of retired) if (!(await releaseRetired(deps, id))) pending += 1;
  return { released: retired.length - pending, pending };
}

export const relayEventsUrl = (deps: AmpDeps, id: string) =>
  `${deps.publicBaseUrl.replace(/\/+$/, "")}/api/v1/amp/relay-events/${id}`;
export const replyUrl = (deps: AmpDeps, id: string) =>
  `${deps.publicBaseUrl.replace(/\/+$/, "")}/api/v1/amp/agents/${id}/messages`;
