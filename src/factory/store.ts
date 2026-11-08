/**
 * Factory control-plane persistence. Every function takes the executor it
 * runs on so callers decide the transaction. Secrets are `encryptSecret`
 * envelopes; reply bearers exist here only as `hashSecret` digests.
 */
import type { SqlExecutor } from "../database.js";

export type FactoryConnectionRow = {
  workspace_id: string;
  organization_id: string;
  user_id: string;
  key_envelope: string;
  key_hint: string;
  validated_at: string | Date;
};

export type FactoryBindingState = "preparing" | "bound" | "retired";

export type FactoryBindingRow = {
  id: string;
  workspace_id: string;
  organization_id: string;
  user_id: string;
  session_id: string;
  computer_id: string;
  state: FactoryBindingState;
  generation: string | number;
  relay_agent_name: string;
  relay_agent_id: string | null;
  hosted_token_envelope: string | null;
  hook_secret_envelope: string | null;
  helper_secret_envelope: string | null;
  history_queued_at: string | Date | null;
  retired_at: string | Date | null;
  remote_cleanup_code: string | null;
  created_at: string | Date;
  updated_at: string | Date;
};

export type FactoryDeliveryState = "pending" | "sending" | "delivered" | "unknown" | "rejected";

export type FactoryDeliveryRow = {
  binding_id: string;
  message_id: string;
  workspace_id: string;
  organization_id: string;
  relay_delivery_id: string;
  sender_agent_name: string;
  sender_agent_id: string | null;
  payload_envelope: string | null;
  state: FactoryDeliveryState;
  attempts: number;
  lease_owner: string | null;
  claim_generation: string | number | null;
  factory_message_id: string | null;
  code: string | null;
  reply_expires_at: string | Date | null;
  reply_result: unknown;
  reply_body_hash: string | null;
};

/** A retired binding whose hosted agent still has to be released remotely. */
export type FactoryRelease = {
  id: string;
  workspace_id: string;
  relay_agent_name: string;
  relay_agent_id: string | null;
};

const BINDING_COLUMNS = `id, workspace_id, organization_id, user_id, session_id, computer_id, state,
  generation, relay_agent_name, relay_agent_id, hosted_token_envelope, hook_secret_envelope,
  helper_secret_envelope, history_queued_at, retired_at, remote_cleanup_code, created_at, updated_at`;

// ---------------------------------------------------------------- connections

export async function findConnection(
  executor: SqlExecutor,
  workspaceId: string,
  lock = false,
): Promise<FactoryConnectionRow | null> {
  const result = await executor.query<FactoryConnectionRow>(
    `SELECT workspace_id, organization_id, user_id, key_envelope, key_hint, validated_at
       FROM selfhost_factory_connections WHERE workspace_id = $1${lock ? " FOR UPDATE" : ""}`,
    [workspaceId],
  );
  return result.rows[0] ?? null;
}

/**
 * Serializes every connect of one workspace, including a first connect where
 * no connection row exists yet to lock (Cloud 9f813ff `locked`,
 * `factory-workspace:<id>`, service.ts:61-65). Taken after the organization
 * lock and before any connection or binding lock (§6.0 lock order).
 */
export async function lockWorkspaceFactory(executor: SqlExecutor, workspaceId: string): Promise<void> {
  await executor.query("SELECT pg_advisory_xact_lock(hashtext('factory-workspace'), hashtext($1))", [workspaceId]);
}

/**
 * Writes the connection only over the expected predecessor: an absent row
 * when `expected` is null, else the same owner and key envelope. Returns false
 * (nothing written) when the predecessor changed.
 */
export async function writeConnection(
  executor: SqlExecutor,
  input: { workspaceId: string; organizationId: string; userId: string; keyEnvelope: string; keyHint: string },
  expected: FactoryConnectionRow | null,
): Promise<boolean> {
  const result = expected
    ? await executor.query(
      `UPDATE selfhost_factory_connections
          SET user_id = $3, key_envelope = $4, key_hint = $5, validated_at = now(), updated_at = now()
        WHERE workspace_id = $1 AND organization_id = $2 AND user_id = $6 AND key_envelope = $7
        RETURNING workspace_id`,
      [input.workspaceId, input.organizationId, input.userId, input.keyEnvelope, input.keyHint, expected.user_id, expected.key_envelope],
    )
    : await executor.query(
      `INSERT INTO selfhost_factory_connections
         (workspace_id, organization_id, user_id, key_envelope, key_hint, validated_at)
       VALUES ($1, $2, $3, $4, $5, now())
       ON CONFLICT (workspace_id) DO NOTHING
       RETURNING workspace_id`,
      [input.workspaceId, input.organizationId, input.userId, input.keyEnvelope, input.keyHint],
    );
  return result.rows.length === 1;
}

/**
 * The setup snapshot (Cloud 9f813ff `readSetupSnapshot`, service.ts:182-199):
 * the workspace connection and every binding row of the workspace, retired
 * ones included. Unlocked: the caller's transaction already holds the
 * organization and workspace locks (§6.0 lock order).
 */
export type FactorySetupSnapshot = { connection: FactoryConnectionRow | null; bindings: FactoryBindingRow[] };

export async function setupSnapshot(executor: SqlExecutor, workspaceId: string): Promise<FactorySetupSnapshot> {
  const connection = await findConnection(executor, workspaceId);
  const bindings = await executor.query<FactoryBindingRow>(
    `SELECT ${BINDING_COLUMNS} FROM selfhost_factory_bindings WHERE workspace_id = $1 ORDER BY id`,
    [workspaceId],
  );
  return { connection, bindings: bindings.rows };
}

const isoOrNull = (value: string | Date | null) => (value === null ? null : new Date(value).toISOString());

/** The connection part of `setupIdentity` (Cloud service.ts:274-281). */
export function connectionIdentity(connection: FactoryConnectionRow | null): string {
  return JSON.stringify(connection
    ? { user_id: connection.user_id, key_envelope: connection.key_envelope, validated_at: isoOrNull(connection.validated_at) }
    : null);
}

/**
 * Cloud 9f813ff `setupIdentity` (service.ts:273-302): a stable rendering of
 * the connection owner/key/validation time and every binding's identity,
 * state, remote ids and secret envelopes. Any difference refuses the write.
 */
export function setupIdentity(snapshot: FactorySetupSnapshot): string {
  return JSON.stringify({
    connection: JSON.parse(connectionIdentity(snapshot.connection)) as unknown,
    bindings: snapshot.bindings
      .map((row) => [
        row.id, row.user_id, row.organization_id, row.session_id, row.computer_id, row.state,
        row.relay_agent_name, row.relay_agent_id, row.hosted_token_envelope, row.hook_secret_envelope,
        row.helper_secret_envelope,
      ])
      .sort((a, b) => String(a[0]).localeCompare(String(b[0]))),
  });
}

export async function deleteConnection(executor: SqlExecutor, workspaceId: string): Promise<void> {
  await executor.query("DELETE FROM selfhost_factory_connections WHERE workspace_id = $1", [workspaceId]);
}

/** True while the user is still a member of the organization (read inside the caller's transaction). */
export async function isMember(executor: SqlExecutor, organizationId: string, userId: string): Promise<boolean> {
  return (await memberRole(executor, organizationId, userId)) !== null;
}

/** The user's current role, or null after removal (read inside the caller's transaction). */
export async function memberRole(
  executor: SqlExecutor,
  organizationId: string,
  userId: string,
): Promise<"owner" | "admin" | "member" | null> {
  const result = await executor.query<{ role: "owner" | "admin" | "member" }>(
    `SELECT role FROM selfhost_organization_memberships WHERE organization_id = $1 AND user_id = $2`,
    [organizationId, userId],
  );
  return result.rows[0]?.role ?? null;
}

/**
 * Serializes a final connect/bind/delivery write against `deleteMembership`
 * and `putMembership`, which hold the organization row FOR UPDATE: whichever
 * commits first wins, and the late writer then re-reads the membership.
 */
export async function lockOrganizationShared(executor: SqlExecutor, organizationId: string): Promise<void> {
  await executor.query("SELECT id FROM selfhost_organizations WHERE id = $1 FOR SHARE", [organizationId]);
}

/**
 * The management fence (Cloud a749e46c `requireFactoryMembership`), run as
 * the first statement of a commit transaction rather than as a pre-check:
 * locks the organization shared, then requires a live owner/admin
 * membership. Removal and demotion both take the organization row FOR
 * UPDATE, so neither can commit between this check and the caller's write.
 */
export async function managerInTx(tx: SqlExecutor, organizationId: string, userId: string): Promise<boolean> {
  await lockOrganizationShared(tx, organizationId);
  const role = await memberRole(tx, organizationId, userId);
  return role === "owner" || role === "admin";
}

/**
 * The delivery fence (Cloud a749e46c `withLiveFactoryBinding(..., "delivery")`):
 * inside the insert transaction, the binding is still bound with a hosted
 * token, its owner is still a member, and the workspace connection still
 * belongs to that owner. Locks organization, connection, then binding
 * (§6.0 lock order).
 */
export async function liveDeliveryTargetInTx(
  tx: SqlExecutor,
  binding: { id: string; organization_id: string; workspace_id: string; user_id: string; generation: string | number },
): Promise<boolean> {
  await lockOrganizationShared(tx, binding.organization_id);
  if (!await isMember(tx, binding.organization_id, binding.user_id)) return false;
  const connection = await tx.query<{ user_id: string }>(
    "SELECT user_id FROM selfhost_factory_connections WHERE workspace_id = $1 FOR SHARE",
    [binding.workspace_id],
  );
  if (connection.rows[0]?.user_id !== binding.user_id) return false;
  const row = await tx.query<{ ok: boolean }>(
    `SELECT (state = 'bound' AND hosted_token_envelope IS NOT NULL AND user_id = $2
             AND generation = $3::bigint) AS ok
       FROM selfhost_factory_bindings WHERE id = $1 FOR SHARE`,
    [binding.id, binding.user_id, String(binding.generation)],
  );
  return row.rows[0]?.ok === true;
}

// ------------------------------------------------------------------- bindings

export async function liveBindings(
  executor: SqlExecutor,
  workspaceId: string,
  filter: { userId?: string; excludeUserId?: string; state?: "bound" } = {},
): Promise<FactoryBindingRow[]> {
  const result = await executor.query<FactoryBindingRow>(
    `SELECT ${BINDING_COLUMNS} FROM selfhost_factory_bindings
      WHERE workspace_id = $1 AND state <> 'retired'
        AND ($2::uuid IS NULL OR user_id = $2)
        AND ($3::uuid IS NULL OR user_id <> $3)
        AND ($4::text IS NULL OR state = $4)
      ORDER BY created_at, id`,
    [workspaceId, filter.userId ?? null, filter.excludeUserId ?? null, filter.state ?? null],
  );
  return result.rows;
}

/**
 * Setup-blocking bindings (Cloud 9f813ff `setupBlockingBindings`): only live
 * (preparing/bound) rows. A retired row reserves just its old session id
 * (409 `factory_cleanup_pending` on bind until verified cleanup) and its
 * cleanup metadata; it never blocks a personal connection, whatever its former
 * owner's membership. A current connection protects its owner on its own (the
 * callers check `connection.user_id`), even with zero binding rows.
 */
export async function setupBlockingBindings(
  executor: SqlExecutor,
  workspaceId: string,
): Promise<Array<{ id: string; user_id: string; state: string }>> {
  const result = await executor.query<{ id: string; user_id: string; state: string }>(
    `SELECT id, user_id, state FROM selfhost_factory_bindings
      WHERE workspace_id = $1 AND state <> 'retired'
      ORDER BY created_at, id`,
    [workspaceId],
  );
  return result.rows;
}

export async function liveBindingForSession(
  executor: SqlExecutor,
  sessionId: string,
  lock = false,
): Promise<FactoryBindingRow | null> {
  const result = await executor.query<FactoryBindingRow>(
    `SELECT ${BINDING_COLUMNS} FROM selfhost_factory_bindings
      WHERE session_id = $1 AND state <> 'retired'${lock ? " FOR UPDATE" : ""}`,
    [sessionId],
  );
  return result.rows[0] ?? null;
}

/** Live session ids across the installation, for marking discover rows. */
export async function liveSessionOwners(
  executor: SqlExecutor,
  sessionIds: string[],
): Promise<Array<{ session_id: string; workspace_id: string; user_id: string }>> {
  if (sessionIds.length === 0) return [];
  const result = await executor.query<{ session_id: string; workspace_id: string; user_id: string }>(
    `SELECT session_id, workspace_id, user_id FROM selfhost_factory_bindings
      WHERE state <> 'retired' AND session_id = ANY($1::text[])`,
    [sessionIds],
  );
  return result.rows;
}

export async function findBinding(
  executor: SqlExecutor,
  bindingId: string,
  lock = false,
): Promise<FactoryBindingRow | null> {
  const result = await executor.query<FactoryBindingRow>(
    `SELECT ${BINDING_COLUMNS} FROM selfhost_factory_bindings WHERE id = $1${lock ? " FOR UPDATE" : ""}`,
    [bindingId],
  );
  return result.rows[0] ?? null;
}

export async function bindingsForUser(
  executor: SqlExecutor,
  workspaceId: string,
  userId: string,
): Promise<FactoryBindingRow[]> {
  const result = await executor.query<FactoryBindingRow>(
    `SELECT ${BINDING_COLUMNS} FROM selfhost_factory_bindings
      WHERE workspace_id = $1 AND user_id = $2 ORDER BY created_at, id`,
    [workspaceId, userId],
  );
  return result.rows;
}

export async function insertPreparingBinding(
  executor: SqlExecutor,
  input: {
    id: string;
    workspaceId: string;
    organizationId: string;
    userId: string;
    sessionId: string;
    computerId: string;
    agentName: string;
    hookSecretEnvelope: string;
    helperSecretEnvelope: string;
  },
): Promise<FactoryBindingRow> {
  const result = await executor.query<FactoryBindingRow>(
    `INSERT INTO selfhost_factory_bindings
       (id, workspace_id, organization_id, user_id, session_id, computer_id, state,
        relay_agent_name, hook_secret_envelope, helper_secret_envelope)
     VALUES ($1, $2, $3, $4, $5, $6, 'preparing', $7, $8, $9)
     RETURNING ${BINDING_COLUMNS}`,
    [
      input.id, input.workspaceId, input.organizationId, input.userId, input.sessionId,
      input.computerId, input.agentName, input.hookSecretEnvelope, input.helperSecretEnvelope,
    ],
  );
  return result.rows[0]!;
}

/** preparing -> bound. Returns null when the row was retired or purged meanwhile. */
export async function markBound(
  executor: SqlExecutor,
  bindingId: string,
  agentId: string,
  hostedTokenEnvelope: string,
): Promise<FactoryBindingRow | null> {
  const result = await executor.query<FactoryBindingRow>(
    `UPDATE selfhost_factory_bindings
        SET state = 'bound', generation = generation + 1, relay_agent_id = $2,
            hosted_token_envelope = $3, updated_at = now()
      WHERE id = $1 AND state = 'preparing'
      RETURNING ${BINDING_COLUMNS}`,
    [bindingId, agentId, hostedTokenEnvelope],
  );
  return result.rows[0] ?? null;
}

export async function deleteBinding(executor: SqlExecutor, bindingId: string): Promise<void> {
  await executor.query("DELETE FROM selfhost_factory_bindings WHERE id = $1", [bindingId]);
}

/**
 * Local retirement, shared by unbind, disconnect, member purge and workspace
 * cleanup. Runs in the caller's transaction and never waits on remote I/O:
 * the binding is fenced (state, generation), every secret envelope is
 * cleared, the outbox is settled (pending -> rejected, sending -> unknown,
 * both `binding_retired`), and delivery payload ciphertext plus reply-bearer
 * hashes are cleared for every delivery of the binding. Returns the rows
 * whose hosted agent must be released after commit.
 */
export async function retireBindingsInTx(
  tx: SqlExecutor,
  filter:
    | { bindingIds: string[] }
    | { workspaceId: string; userId?: string }
    | { organizationId: string; userId: string },
): Promise<FactoryRelease[]> {
  const where = "bindingIds" in filter
    ? { sql: "id = ANY($1::uuid[])", params: [filter.bindingIds] }
    : "workspaceId" in filter
      ? { sql: "workspace_id = $1 AND ($2::uuid IS NULL OR user_id = $2)", params: [filter.workspaceId, filter.userId ?? null] }
      : { sql: "organization_id = $1 AND user_id = $2", params: [filter.organizationId, filter.userId] };
  const locked = await tx.query<{ id: string }>(
    `SELECT id FROM selfhost_factory_bindings WHERE ${where.sql} AND state <> 'retired' ORDER BY id FOR UPDATE`,
    where.params,
  );
  const ids = locked.rows.map((row) => row.id);
  if (ids.length === 0) return [];
  const retired = await tx.query<FactoryRelease>(
    `UPDATE selfhost_factory_bindings
        SET state = 'retired', retired_at = now(), generation = generation + 1,
            hosted_token_envelope = NULL, hook_secret_envelope = NULL,
            helper_secret_envelope = NULL, history_queued_at = NULL, updated_at = now()
      WHERE id = ANY($1::uuid[])
      RETURNING id, workspace_id, relay_agent_name, relay_agent_id`,
    [ids],
  );
  await tx.query(
    `UPDATE selfhost_factory_deliveries
        SET state = CASE state WHEN 'pending' THEN 'rejected' WHEN 'sending' THEN 'unknown' ELSE state END,
            code = CASE WHEN state IN ('pending', 'sending') THEN 'binding_retired' ELSE code END,
            lease_until = NULL, payload_envelope = NULL, reply_hash = NULL, reply_expires_at = NULL,
            updated_at = now()
      WHERE binding_id = ANY($1::uuid[])`,
    [ids],
  );
  await tx.query(
    `UPDATE selfhost_factory_history_syncs
        SET active_job_id = NULL, active_job_lease_until = NULL, pending_envelope = NULL, updated_at = now()
      WHERE binding_id = ANY($1::uuid[])`,
    [ids],
  );
  return retired.rows;
}

/**
 * Membership-removal purge, run by `deleteMembership`'s beforeCommit hook in
 * the removal transaction: retires every binding of the user in the
 * organization, deletes their connections (purging the key) and their
 * history sync rows. Remote release happens after commit.
 */
export async function purgeMemberInTx(
  tx: SqlExecutor,
  organizationId: string,
  userId: string,
): Promise<{ releases: FactoryRelease[]; connections: string[] }> {
  // §6.0 lock order: the caller holds the organization FOR UPDATE; the
  // member's connections are locked before any of their bindings.
  await tx.query(
    "SELECT workspace_id FROM selfhost_factory_connections WHERE organization_id = $1 AND user_id = $2 ORDER BY workspace_id FOR UPDATE",
    [organizationId, userId],
  );
  const releases = await retireBindingsInTx(tx, { organizationId, userId });
  // Removal deletes the member's outbox rows outright (Cloud a749e46c): no
  // queued body, reply bearer or receipt of a departed member survives.
  await tx.query(
    `DELETE FROM selfhost_factory_deliveries
      WHERE binding_id IN (SELECT id FROM selfhost_factory_bindings WHERE organization_id = $1 AND user_id = $2)`,
    [organizationId, userId],
  );
  const connections = await tx.query<{ workspace_id: string }>(
    `DELETE FROM selfhost_factory_connections WHERE organization_id = $1 AND user_id = $2 RETURNING workspace_id`,
    [organizationId, userId],
  );
  await tx.query(
    "DELETE FROM selfhost_factory_history_syncs WHERE organization_id = $1 AND user_id = $2",
    [organizationId, userId],
  );
  return { releases, connections: connections.rows.map((row) => row.workspace_id) };
}

/**
 * Local Factory teardown for a workspace that is about to be deleted, in the
 * caller's transaction. Every Factory row of the workspace is removed (the
 * RESTRICT foreign keys otherwise block the delete). The returned releases
 * must be passed to `afterWorkspaceDeleted` with the workspace key captured
 * before the delete, because the rows no longer exist for the cleanup loop.
 */
export async function cleanupWorkspaceFactory(
  tx: SqlExecutor,
  workspaceId: string,
): Promise<{ releases: FactoryRelease[] }> {
  // §6.0 lock order: connection before bindings.
  await tx.query("SELECT workspace_id FROM selfhost_factory_connections WHERE workspace_id = $1 FOR UPDATE", [workspaceId]);
  await retireBindingsInTx(tx, { workspaceId });
  const releases = await tx.query<FactoryRelease>(
    `SELECT id, workspace_id, relay_agent_name, relay_agent_id FROM selfhost_factory_bindings
      WHERE workspace_id = $1 AND relay_agent_id IS NOT NULL`,
    [workspaceId],
  );
  await tx.query("DELETE FROM selfhost_factory_history_syncs WHERE workspace_id = $1", [workspaceId]);
  await tx.query("DELETE FROM selfhost_factory_deliveries WHERE workspace_id = $1", [workspaceId]);
  await tx.query("DELETE FROM selfhost_factory_bindings WHERE workspace_id = $1", [workspaceId]);
  await tx.query("DELETE FROM selfhost_factory_connections WHERE workspace_id = $1", [workspaceId]);
  return { releases: releases.rows };
}

/** Retired rows still holding a remote agent, with the workspace key ciphertext. */
export async function pendingReleases(
  executor: SqlExecutor,
  limit: number,
  filter: { userId?: string; sessionId?: string; bindingIds?: string[] } = {},
): Promise<Array<FactoryRelease & { relaycast_api_key_ciphertext: string }>> {
  const result = await executor.query<FactoryRelease & { relaycast_api_key_ciphertext: string }>(
    `SELECT b.id, b.workspace_id, b.relay_agent_name, b.relay_agent_id, w.relaycast_api_key_ciphertext
       FROM selfhost_factory_bindings b
       JOIN selfhost_workspaces w ON w.id = b.workspace_id
      WHERE b.state = 'retired' AND b.relay_agent_id IS NOT NULL
        AND ($2::uuid IS NULL OR b.user_id = $2)
        AND ($3::text IS NULL OR b.session_id = $3)
        AND ($4::uuid[] IS NULL OR b.id = ANY($4::uuid[]))
      ORDER BY b.updated_at, b.id LIMIT $1`,
    [limit, filter.userId ?? null, filter.sessionId ?? null, filter.bindingIds ?? null],
  );
  return result.rows;
}

/** The remote agent is gone: keep the retired row as a secret-free tombstone. */
export async function markReleased(executor: SqlExecutor, bindingId: string): Promise<void> {
  await executor.query(
    `UPDATE selfhost_factory_bindings SET relay_agent_id = NULL, remote_cleanup_code = NULL, updated_at = now()
      WHERE id = $1 AND state = 'retired'`,
    [bindingId],
  );
}

export async function markReleaseFailed(executor: SqlExecutor, bindingId: string, code: string): Promise<void> {
  await executor.query(
    `UPDATE selfhost_factory_bindings SET remote_cleanup_code = $2, updated_at = now()
      WHERE id = $1 AND state = 'retired'`,
    [bindingId, code],
  );
}

// ----------------------------------------------------------------- deliveries

const DELIVERY_COLUMNS = `binding_id, message_id, workspace_id, organization_id, relay_delivery_id,
  sender_agent_name, sender_agent_id, payload_envelope, state, attempts, lease_owner, claim_generation,
  factory_message_id, code, reply_expires_at, reply_result, reply_body_hash`;

/** Records one inbox delivery. A re-polled delivery is a no-op whatever state the row is in. */
export async function insertDelivery(
  executor: SqlExecutor,
  input: {
    bindingId: string;
    messageId: string;
    workspaceId: string;
    organizationId: string;
    relayDeliveryId: string;
    senderName: string;
    senderId: string | null;
    payloadEnvelope: string | null;
    state: "pending" | "rejected";
    code: string | null;
  },
): Promise<boolean> {
  const result = await executor.query(
    `INSERT INTO selfhost_factory_deliveries
       (binding_id, message_id, workspace_id, organization_id, relay_delivery_id,
        sender_agent_name, sender_agent_id, payload_envelope, state, code)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
     ON CONFLICT (binding_id, message_id) DO NOTHING
     RETURNING message_id`,
    [
      input.bindingId, input.messageId, input.workspaceId, input.organizationId, input.relayDeliveryId,
      input.senderName, input.senderId, input.payloadEnvelope, input.state, input.code,
    ],
  );
  return result.rows.length === 1;
}

export async function findDelivery(
  executor: SqlExecutor,
  bindingId: string,
  messageId: string,
): Promise<FactoryDeliveryRow | null> {
  const result = await executor.query<FactoryDeliveryRow>(
    `SELECT ${DELIVERY_COLUMNS} FROM selfhost_factory_deliveries WHERE binding_id = $1 AND message_id = $2`,
    [bindingId, messageId],
  );
  return result.rows[0] ?? null;
}

/** Bound bindings for the inbox poll, oldest-polled first (soft cap per tick). */
export async function boundBindings(executor: SqlExecutor, limit: number): Promise<FactoryBindingRow[]> {
  const result = await executor.query<FactoryBindingRow>(
    `SELECT ${BINDING_COLUMNS} FROM selfhost_factory_bindings
      WHERE state = 'bound' AND hosted_token_envelope IS NOT NULL
      ORDER BY id LIMIT $1`,
    [limit],
  );
  return result.rows;
}
