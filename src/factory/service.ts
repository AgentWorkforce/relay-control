/**
 * Factory control operations (design §6): connect, discover, bind, unbind,
 * disconnect, member purge and workspace cleanup. Provider and Relaycast I/O
 * never runs inside a database transaction; the final local write re-checks
 * membership under the organization row lock so a racing member removal wins.
 */
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";
import { decryptSecret, encryptSecret, hashSecret, opaqueToken, type EncryptionKeyring } from "../crypto.js";
import { recordAudit, type AuditActor } from "../admin/audit.js";
import { ACQUISITION_OPERATOR_PURPOSE, type ApiTokenStore } from "../admin/api-tokens.js";
import { ownerHash } from "../mcp/relay-participants.js";
import { RelaycastCallError, type RelaycastClient } from "../messaging/relaycast.js";
import { replyBodyHash, replyIdempotencyKey } from "./reply-capability.js";
import {
  FACTORY_ID,
  FactoryRuntimeError,
  validFactoryKey,
  type FactoryRuntime,
} from "./runtime.js";
import {
  bindingsForUser,
  currentAcquisitionOperator,
  deleteBinding,
  drainAcquisitionOperatorsInTx,
  enrolledAcquisitionOperator,
  insertAcquisitionOperator,
  markAcquisitionOperatorRevoked,
  deleteConnection,
  findBinding,
  findConnection,
  findDelivery,
  insertPreparingBinding,
  isMember,
  liveBindingForSession,
  liveBindings,
  liveSessionOwners,
  managerInTx,
  memberRole,
  setupBlockingBindings,
  setupIdentity,
  setupSnapshot,
  markBound,
  markReleased,
  markReleaseFailed,
  pendingReleases,
  purgeMemberInTx,
  retireBindingsInTx,
  writeConnection,
  lockWorkspaceFactory,
  type AcquisitionOperatorRow,
  type FactoryBindingRow,
  type FactoryRelease,
} from "./store.js";

/** Error bodies are `{ error: code, message }` with fixed strings (design §3.1). */
export class FactoryHttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "FactoryHttpError";
  }
}

export const FACTORY_ERRORS = {
  workspaceToken: () => new FactoryHttpError(403, "factory_workspace_token", "Workspace tokens cannot use Factory"),
  scope: () => new FactoryHttpError(403, "insufficient_scope", "Insufficient scope"),
  csrf: () => new FactoryHttpError(403, "csrf_rejected", "Cross-site request refused"),
  notOwnerManage: () => new FactoryHttpError(403, "factory_not_owner", "Only the person who connected Factory can manage this connection."),
  notOwnerBrowse: () => new FactoryHttpError(403, "factory_not_owner", "Only the person who connected Factory can browse its sessions."),
  notOwnerDisconnect: () => new FactoryHttpError(403, "factory_not_owner", "Only the person who connected Factory can disconnect this session."),
  accessRevoked: () => new FactoryHttpError(403, "factory_access_revoked", "Factory access was revoked"),
  notManager: () => new FactoryHttpError(403, "forbidden", "Only current owners and admins can manage Factory."),
  notConnected: () => new FactoryHttpError(404, "factory_not_connected", "Factory is not connected"),
  bindingNotFound: () => new FactoryHttpError(404, "binding_not_found", "Binding not found"),
  deliveryNotFound: () => new FactoryHttpError(404, "delivery_not_found", "Delivery not found"),
  otherWorkspace: () => new FactoryHttpError(409, "factory_session_other_workspace", "Factory session is bound in another workspace"),
  otherMember: () => new FactoryHttpError(409, "factory_session_other_member", "Factory session is bound by another member"),
  moved: () => new FactoryHttpError(409, "factory_session_moved", "Factory session moved to another computer"),
  retired: () => new FactoryHttpError(409, "binding_retired", "Binding is retired"),
  otherMemberBindings: () => new FactoryHttpError(409, "factory_other_member_bindings", "Disconnect existing Factory sessions before changing the connection owner."),
  replaceLimit: () => new FactoryHttpError(409, "factory_replace_limit", "Too many bound Factory sessions to replace the key"),
  /** Cloud 9f813ff `requireSetupIdentity` (service.ts:303-309); the code is kept from the earlier bound-set check. */
  setupChanged: () => new FactoryHttpError(409, "factory_bindings_changed", "Factory changed while verification was running. Retry from current Settings."),
  cleanupPending: () => new FactoryHttpError(409, "factory_cleanup_pending", "Factory session cleanup is still pending"),
  acquisitionUnconfigured: () => new FactoryHttpError(409, "acquisition_unconfigured", "Acquisition enrollment is not configured"),
  replyUnauthorized: () => new FactoryHttpError(401, "unauthorized", "Unauthorized"),
  replyRecorded: () => new FactoryHttpError(409, "reply_already_recorded", "Reply already recorded"),
  replyFailed: () => new FactoryHttpError(503, "factory_reply_failed", "Factory reply failed."),
  agentConflict: () => new FactoryHttpError(409, "factory_agent_conflict", "Relay agent name is taken"),
  invalidKey: () => new FactoryHttpError(422, "invalid_factory_key", "Invalid Factory key"),
  invalidRequest: () => new FactoryHttpError(422, "invalid_request", "Invalid request"),
  keyRejected: () => new FactoryHttpError(502, "factory_key_rejected", "Factory rejected the key"),
  unavailable: () => new FactoryHttpError(503, "factory_unavailable", "Factory unavailable"),
  relayUnavailable: () => new FactoryHttpError(503, "relay_unavailable", "Relay unavailable"),
} as const;

/** Re-verification bound when the connection owner replaces the key (Cloud). */
export const MAX_REVERIFY_BINDINGS = 8;
/**
 * A draining acquisition-operator token is revoked once its obligations
 * settle, and at the latest this long after draining started, even with
 * obligations outstanding (recorded as `stranded_count`). No env knob.
 */
export const ACQUISITION_DRAIN_MAX_MS = 24 * 60 * 60 * 1_000;
export const ACQUISITION_OPERATOR_LABEL = "Factory acquisition operator";
const RECONCILER_ACTOR: AuditActor = { kind: "service", subject: "factory-acquisition-reconciler" };

/**
 * Acquisition obligations still owed through this workspace's draining
 * acquisition-operator token. Always 0 today: Control carries no acquisition
 * transport or revoke intents yet, so nothing can be outstanding. The
 * acquisition owner wires the real count here; the reconciler already honors
 * it (revoke at 0, or strand after ACQUISITION_DRAIN_MAX_MS).
 */
export async function outstandingObligations(_tx: SqlExecutor, _workspaceId: string): Promise<number> {
  return 0;
}

/** History is dormant in this release; every surface says so (design §9). */
export const HISTORY_DEFERRED = { queued: 0, deferred: true } as const;

export type FactoryAccess = {
  principal: { userId: string };
  workspace: { id: string; organizationId: string; relaycastApiKey: string };
};

export type FactoryLog = (fields: {
  event: string;
  kind?: string;
  bindingHash?: string;
  code?: string;
  outcome?: string;
}) => void;

export type FactoryServiceDeps = {
  database: Database;
  keyring: EncryptionKeyring;
  runtime: FactoryRuntime;
  relaycast: RelaycastClient;
  log: FactoryLog;
  /** Test hook: runs after remote I/O, before the final connect/bind transaction. */
  beforeFinalWrite?: (operation: "connect" | "bind") => Promise<void>;
  /**
   * Test hook, inert when unset: runs inside the final connect/disconnect
   * transaction after its locks and checks, before its write (real-Postgres
   * concurrency tests hold a transaction open here).
   */
  afterLock?: (operation: "connect" | "disconnect") => Promise<void>;
  /**
   * Acquisition enrollment, inert when unset or when `origin` is unset. The
   * token store must accept `origin` as an introspection audience.
   */
  acquisition?: {
    apiTokens: ApiTokenStore;
    /** Normalized SELFHOST_ACQUISITION_ORIGIN. */
    origin?: string;
    /** Origin of SELFHOST_PUBLIC_URL, recorded on each enrollment. */
    controlOrigin: string;
  };
};

export function bindingHash(bindingId: string): string {
  return createHash("sha256").update(bindingId).digest("hex").slice(0, 16);
}

export function agentNameFor(sessionId: string): string {
  return `factory-${createHash("sha256").update(sessionId).digest("hex").slice(0, 16)}`;
}

function iso(value: string | Date | null): string | null {
  return value === null ? null : new Date(value).toISOString();
}

export function bindingView(row: FactoryBindingRow) {
  return {
    id: row.id,
    session_id: row.session_id,
    computer_id: row.computer_id,
    state: row.state,
    agent: { name: row.relay_agent_name, id: row.relay_agent_id },
    history: "deferred" as const,
    created_at: iso(row.created_at),
    updated_at: iso(row.updated_at),
    retired_at: iso(row.retired_at),
  };
}

/** Maps transport failures to the fixed §3.1 errors; never echoes provider bodies. */
function failure(error: unknown): never {
  if (error instanceof FactoryHttpError) throw error;
  if (error instanceof FactoryRuntimeError) {
    if (error.code === "factory_invalid_key") throw FACTORY_ERRORS.invalidKey();
    if (error.code === "factory_http_401" || error.code === "factory_http_403") throw FACTORY_ERRORS.keyRejected();
    if (error.code === "factory_computer_changed") throw FACTORY_ERRORS.moved();
    if (["factory_http_404", "factory_session_mismatch", "factory_invalid_session"].includes(error.code)) {
      throw FACTORY_ERRORS.invalidRequest();
    }
    throw FACTORY_ERRORS.unavailable();
  }
  if (error instanceof RelaycastCallError) throw FACTORY_ERRORS.relayUnavailable();
  throw error;
}

export function createFactoryService(deps: FactoryServiceDeps) {
  const { database, keyring, runtime, relaycast, log } = deps;

  async function audit(
    executor: SqlExecutor,
    access: FactoryAccess,
    action: string,
    target: string | null,
  ): Promise<void> {
    await recordAudit(executor, {
      organizationId: access.workspace.organizationId,
      workspaceId: access.workspace.id,
      actor: { kind: "user", userId: access.principal.userId },
      action,
      target,
    });
  }

  const acquisitionOrigin = deps.acquisition?.origin;

  function operatorTarget(row: Pick<AcquisitionOperatorRow, "token_id">, detail?: string): string {
    return detail ? `${row.token_id} (acquisition-operator; ${detail})` : `${row.token_id} (acquisition-operator)`;
  }

  /**
   * Mints one acquisition-operator token on `tx` and records the enrolled
   * row. The plaintext exists only in this scope and in the encrypted
   * envelope; it is never logged, audited or returned.
   */
  async function enrolInTx(tx: SqlExecutor, access: FactoryAccess, action: string): Promise<void> {
    const acquisition = deps.acquisition!;
    const origin = acquisitionOrigin!;
    const created = await acquisition.apiTokens.createIn(tx, {
      workspaceId: access.workspace.id,
      organizationId: access.workspace.organizationId,
      label: ACQUISITION_OPERATOR_LABEL,
      purpose: ACQUISITION_OPERATOR_PURPOSE,
      expiryDays: undefined,
      neverExpires: true,
      aud: origin,
      actor: { kind: "user", userId: access.principal.userId },
    });
    await insertAcquisitionOperator(tx, {
      id: randomUUID(),
      workspaceId: access.workspace.id,
      organizationId: access.workspace.organizationId,
      origin,
      tokenId: created.id,
      tokenEnvelope: encryptSecret(created.accessToken, keyring.active),
      tokenPrefix: created.tokenPrefix,
      controlOrigin: acquisition.controlOrigin,
      userId: access.principal.userId,
    });
    await audit(tx, access, action, operatorTarget({ token_id: created.id }));
  }

  /** Revokes the row's token (if still active) and marks the row revoked, both on `tx`. */
  async function revokeOperatorInTx(
    tx: SqlExecutor,
    row: AcquisitionOperatorRow,
    actor: AuditActor,
    reason: string,
    stranded: number,
  ): Promise<void> {
    await deps.acquisition!.apiTokens.revokeIn(tx, {
      workspaceId: row.workspace_id,
      organizationId: row.organization_id,
      tokenId: row.token_id,
      actor,
    });
    await markAcquisitionOperatorRevoked(tx, row.id, reason, stranded);
    await recordAudit(tx, {
      organizationId: row.organization_id,
      workspaceId: row.workspace_id,
      actor,
      action: "factory.acquisition.revoke",
      target: operatorTarget(row, `reason=${reason}; stranded=${stranded}`),
    });
  }

  /** Honest enrollment status for the summary; never claims more than the rows show. */
  async function acquisitionSummary(workspaceId: string) {
    if (!acquisitionOrigin) return { state: "unconfigured" as const };
    const row = await currentAcquisitionOperator(database, workspaceId, acquisitionOrigin);
    if (!row) return { state: "unconfigured" as const };
    return {
      // A token revoked outside this flow (the API tokens routes) is reported as revoked.
      state: row.state === "enrolled" && row.token_revoked ? "revoked" as const : row.state,
      token_prefix: row.token_prefix,
      created_at: iso(row.created_at),
    };
  }

  /** The caller's connection key, or the §3.1 refusal. */
  async function ownedKey(access: FactoryAccess, refusal: () => FactoryHttpError): Promise<string> {
    const connection = await findConnection(database, access.workspace.id);
    if (!connection) throw FACTORY_ERRORS.notConnected();
    if (connection.user_id !== access.principal.userId) throw refusal();
    return decryptSecret(connection.key_envelope, keyring);
  }

  /**
   * Cloud 9f813ff connect guard: a current connection owned by someone else
   * refuses the change of owner even with zero binding rows, and so does any
   * foreign live (preparing/bound) row. Retired rows never block connect.
   */
  async function requireConnectAllowed(executor: SqlExecutor, access: FactoryAccess, connectionUserId: string | null) {
    const userId = access.principal.userId;
    if (connectionUserId !== null && connectionUserId !== userId) throw FACTORY_ERRORS.otherMemberBindings();
    const blocking = await setupBlockingBindings(executor, access.workspace.id);
    if (blocking.some((row) => row.user_id !== userId)) throw FACTORY_ERRORS.otherMemberBindings();
  }

  /** Cloud `requireSetupOwner`: the actor owns the connection and no foreign live row blocks it. */
  async function requireSetupOwner(tx: SqlExecutor, access: FactoryAccess, connectionUserId: string | null) {
    const userId = access.principal.userId;
    if (connectionUserId !== null && connectionUserId !== userId) throw FACTORY_ERRORS.notOwnerManage();
    const blocking = await setupBlockingBindings(tx, access.workspace.id);
    if (blocking.some((row) => row.user_id !== userId)) throw FACTORY_ERRORS.notOwnerManage();
  }

  /** The caller's own binding in this workspace; foreign rows are indistinguishable from missing. */
  async function ownBinding(access: FactoryAccess, bindingId: string): Promise<FactoryBindingRow> {
    if (!/^[0-9a-f-]{36}$/i.test(bindingId)) throw FACTORY_ERRORS.bindingNotFound();
    const row = await findBinding(database, bindingId);
    if (!row || row.workspace_id !== access.workspace.id || row.user_id !== access.principal.userId) {
      throw FACTORY_ERRORS.bindingNotFound();
    }
    return row;
  }

  /**
   * Releases hosted agents of retired rows after commit. Success keeps a
   * secret-free tombstone; failure keeps the remote id and a cleanup code
   * for the cleanup loop. Never throws.
   */
  async function release(rows: Array<FactoryRelease & { relaycast_api_key_ciphertext?: string }>, workspaceKey?: string) {
    let pending = 0;
    for (const row of rows) {
      if (!row.relay_agent_id) continue;
      try {
        const key = workspaceKey ?? decryptSecret(row.relaycast_api_key_ciphertext!, keyring);
        try {
          // Exact release of this row's own agent id, never by name alone: a
          // successor registered under the same name is never targeted.
          await relaycast.releaseHosted(key, row.relay_agent_name, row.relay_agent_id);
        } catch (error) {
          // 404: this row's agent is already gone. Only a read confirms it;
          // a successor now holding the name is never released here.
          if (!(error instanceof RelaycastCallError) || error.status !== 404) throw error;
          const current = await relaycast.getAgent(key, row.relay_agent_name);
          if (current?.id === row.relay_agent_id) throw error;
        }
        await markReleased(database, row.id);
        log({ event: "factory.release", bindingHash: bindingHash(row.id), outcome: "released" });
      } catch {
        pending++;
        await markReleaseFailed(database, row.id, "release_failed").catch(() => undefined);
        log({ event: "factory.release", bindingHash: bindingHash(row.id), code: "release_failed", outcome: "pending" });
      }
    }
    return pending;
  }

  async function releasePending(filter: Parameters<typeof pendingReleases>[2], limit = 50): Promise<number> {
    return release(await pendingReleases(database, limit, filter));
  }

  async function summary(access: FactoryAccess) {
    const connection = await findConnection(database, access.workspace.id);
    const live = await liveBindings(database, access.workspace.id);
    return {
      connected: Boolean(connection),
      key_hint: connection?.key_hint ?? null,
      validated_at: connection ? iso(connection.validated_at) : null,
      user_is_owner: connection?.user_id === access.principal.userId,
      bindings_count: live.length,
      history: "deferred" as const,
      acquisition: await acquisitionSummary(access.workspace.id),
    };
  }

  return {
    summary,

    async connect(access: FactoryAccess, key: unknown) {
      if (typeof key !== "string" || !validFactoryKey(key)) throw FACTORY_ERRORS.invalidKey();
      const userId = access.principal.userId;
      const workspaceId = access.workspace.id;
      // The full setup snapshot taken before any provider call (Cloud 9f813ff connect, service.ts:336-349).
      const before = await setupSnapshot(database, workspaceId);
      const existing = before.connection;
      // A successor may connect only when no one else holds the connection or a live row (Cloud 9f813ff).
      await requireConnectAllowed(database, access, existing?.user_id ?? null);
      let computers;
      try {
        computers = await runtime.listComputers(key);
      } catch (error) {
        failure(error);
      }
      const replacing = existing?.user_id === userId && decryptSecret(existing.key_envelope, keyring) !== key;
      if (replacing) {
        const bound = before.bindings.filter((row) => row.user_id === userId && row.state === "bound");
        if (bound.length > MAX_REVERIFY_BINDINGS) throw FACTORY_ERRORS.replaceLimit();
        const ids = new Set(computers.map((computer) => computer.id));
        for (const row of bound) {
          if (!ids.has(row.computer_id)) throw FACTORY_ERRORS.moved();
          try {
            await runtime.getSession(key, row.session_id, row.computer_id);
          } catch (error) {
            failure(error);
          }
        }
      }
      await deps.beforeFinalWrite?.("connect");
      await database.transaction(async (tx) => {
        if (!await managerInTx(tx, access.workspace.organizationId, userId)) throw FACTORY_ERRORS.accessRevoked();
        // Admission is serialized per workspace even when no connection row
        // exists yet to lock (Cloud 9f813ff `locked`).
        await lockWorkspaceFactory(tx, workspaceId);
        const current = await findConnection(tx, workspaceId, true);
        // Any change of the setup since `before` (a disconnect, a same-user key
        // replacement, a binding change) refuses this stale write (Cloud
        // `requireSetupIdentity(before, readSetupSnapshot(tx))`, service.ts:395-399).
        if (setupIdentity(before) !== setupIdentity(await setupSnapshot(tx, workspaceId))) throw FACTORY_ERRORS.setupChanged();
        await requireConnectAllowed(tx, access, current?.user_id ?? null);
        await tx.query(
          "DELETE FROM factory_history_syncs WHERE workspace_id = $1 AND user_id <> $2",
          [workspaceId, userId],
        );
        await deps.afterLock?.("connect");
        const written = await writeConnection(tx, {
          workspaceId,
          organizationId: access.workspace.organizationId,
          userId,
          keyEnvelope: encryptSecret(key, keyring.active),
          keyHint: `…${key.slice(-4)}`,
        }, before.connection);
        if (!written) throw FACTORY_ERRORS.setupChanged();
        await audit(tx, access, "factory.connection.put", null);
        if (acquisitionOrigin) {
          // One enrollment per workspace and origin: a key replacement keeps it.
          const enrolled = await enrolledAcquisitionOperator(tx, workspaceId, acquisitionOrigin, true);
          if (enrolled?.token_revoked) {
            // Its token was revoked elsewhere; record that and enrol afresh.
            await revokeOperatorInTx(tx, enrolled, { kind: "user", userId }, "token_revoked", 0);
          }
          if (!enrolled || enrolled.token_revoked) await enrolInTx(tx, access, "factory.acquisition.enrol");
        }
      });
      log({ event: "factory.connect", outcome: "connected" });
      return summary(access);
    },

    async disconnect(access: FactoryAccess): Promise<void> {
      const releases = await database.transaction(async (tx) => {
        // §6.0 lock order: organization, then connection, then bindings (the
        // same order as removal, which holds the organization FOR UPDATE).
        const member = await managerInTx(tx, access.workspace.organizationId, access.principal.userId);
        const connection = await findConnection(tx, access.workspace.id, true);
        if (!connection) return [];
        if (!member) throw FACTORY_ERRORS.accessRevoked();
        await requireSetupOwner(tx, access, connection.user_id);
        await deps.afterLock?.("disconnect");
        // Only the connection owner's own bindings: a removed member's retired
        // rows keep their cleanup locators for the cleanup loop (Cloud a749e46c).
        const retired = await retireBindingsInTx(tx, { workspaceId: access.workspace.id, userId: connection.user_id });
        await tx.query(
          "DELETE FROM factory_history_syncs WHERE workspace_id = $1 AND user_id = $2",
          [access.workspace.id, connection.user_id],
        );
        await deleteConnection(tx, access.workspace.id);
        await audit(tx, access, "factory.connection.delete", null);
        // Same transaction: the enrollment drains; the reconciler revokes its token later.
        await drainAcquisitionOperatorsInTx(tx, [access.workspace.id], "disconnect");
        return retired;
      });
      await release(releases, access.workspace.relaycastApiKey);
      log({ event: "factory.disconnect", outcome: "disconnected" });
    },

    async computers(access: FactoryAccess) {
      const key = await ownedKey(access, FACTORY_ERRORS.notOwnerBrowse);
      try {
        return { computers: await runtime.listComputers(key) };
      } catch (error) {
        failure(error);
      }
    },

    async sessions(access: FactoryAccess, computerId: string) {
      if (!FACTORY_ID.test(computerId)) throw FACTORY_ERRORS.invalidRequest();
      const key = await ownedKey(access, FACTORY_ERRORS.notOwnerBrowse);
      let listed;
      try {
        listed = await runtime.listSessions(key, computerId);
      } catch (error) {
        failure(error);
      }
      const owners = await liveSessionOwners(database, listed.sessions.map((row) => row.id));
      const byId = new Map(owners.map((row) => [row.session_id, row]));
      return {
        sessions: listed.sessions.map((row) => {
          const owner = byId.get(row.id);
          const here = owner?.workspace_id === access.workspace.id && owner.user_id === access.principal.userId;
          return {
            id: row.id,
            title: row.title,
            computer_id: row.computerId,
            bound: owner ? (here ? "here" : "elsewhere") : null,
          };
        }),
        ...(listed.warning ? { warning: listed.warning } : {}),
      };
    },

    async bind(access: FactoryAccess, input: { sessionId: unknown; computerId: unknown }) {
      const { sessionId, computerId } = input;
      if (typeof sessionId !== "string" || !FACTORY_ID.test(sessionId) ||
          typeof computerId !== "string" || !FACTORY_ID.test(computerId)) {
        throw FACTORY_ERRORS.invalidRequest();
      }
      const userId = access.principal.userId;
      const workspaceId = access.workspace.id;
      const workspaceKey = access.workspace.relaycastApiKey;
      await ownedKey(access, FACTORY_ERRORS.notOwnerManage);
      // A retired row of this session whose agent was not released yet still
      // holds the agent name; try its cleanup first (before the snapshot, as
      // a release clears that row's agent id).
      await releasePending({ sessionId });
      // The full setup snapshot taken before any provider call (Cloud 9f813ff
      // bind, service.ts:633-636).
      const before = await setupSnapshot(database, workspaceId);
      if (!before.connection) throw FACTORY_ERRORS.notConnected();
      if (before.connection.user_id !== userId) throw FACTORY_ERRORS.notOwnerManage();
      const key = decryptSecret(before.connection.key_envelope, keyring);
      try {
        const computers = await runtime.listComputers(key);
        if (!computers.some((computer) => computer.id === computerId)) throw FACTORY_ERRORS.invalidRequest();
        await runtime.getSession(key, sessionId, computerId);
      } catch (error) {
        failure(error);
      }

      const agentName = agentNameFor(sessionId);
      let preparedSnapshot = "";
      const prepared = await database.transaction(async (tx) => {
        if (!await managerInTx(tx, access.workspace.organizationId, userId)) throw FACTORY_ERRORS.accessRevoked();
        const connection = await findConnection(tx, workspaceId, true);
        if (!connection) throw FACTORY_ERRORS.notOwnerManage();
        await requireSetupOwner(tx, access, connection.user_id);
        // A key rotation, disconnect or binding change during the provider
        // calls refuses (Cloud `requireSetupIdentity`, service.ts:651-655, 686).
        if (setupIdentity(before) !== setupIdentity(await setupSnapshot(tx, workspaceId))) throw FACTORY_ERRORS.setupChanged();
        const live = await liveBindingForSession(tx, sessionId, true);
        if (live) {
          if (live.workspace_id !== workspaceId) throw FACTORY_ERRORS.otherWorkspace();
          if (live.user_id !== userId) throw FACTORY_ERRORS.otherMember();
          if (live.computer_id !== computerId) throw FACTORY_ERRORS.moved();
          return { row: live, snapshot: setupIdentity(await setupSnapshot(tx, workspaceId)) };
        }
        if ((await pendingReleases(tx, 1, { sessionId })).length > 0) throw FACTORY_ERRORS.cleanupPending();
        const row = await insertPreparingBinding(tx, {
          id: randomUUID(),
          workspaceId,
          organizationId: access.workspace.organizationId,
          userId,
          sessionId,
          computerId,
          agentName,
          hookSecretEnvelope: encryptSecret(`whsec_${randomBytes(32).toString("base64")}`, keyring.active),
          helperSecretEnvelope: encryptSecret(opaqueToken("factory_helper_"), keyring.active),
        });
        return { row, snapshot: setupIdentity(await setupSnapshot(tx, workspaceId)) };
      }).catch((error: unknown) => {
        // A concurrent insert of the same session lost the partial unique index.
        if ((error as { code?: string }).code === "23505") throw FACTORY_ERRORS.otherMember();
        throw error;
      }).then(({ row, snapshot }) => {
        preparedSnapshot = snapshot;
        return row;
      });
      if (prepared.state === "bound") {
        return { binding_id: prepared.id, session_id: sessionId, agent: { name: prepared.relay_agent_name, id: prepared.relay_agent_id } };
      }

      const metadata = {
        source: "cloud-hosted-mcp",
        created_by: "factory-binding",
        factory_binding_id: prepared.id,
        cloud_workspace_id: workspaceId,
        owner_hash: ownerHash(userId),
        session_kind: "droid",
        session_id: sessionId,
        host: "Factory Droid",
      };
      let agent: { id: string; name: string; token: string };
      try {
        const existing = await relaycast.getAgent(workspaceKey, agentName);
        if (existing) {
          const priorId = existing.metadata.factory_binding_id;
          if (priorId === prepared.id && existing.metadata.owner_hash === ownerHash(userId)) {
            // Our own earlier attempt registered but never committed: recover it.
            agent = await relaycast.recoverHosted(workspaceKey, agentName, existing.id, userId);
          } else {
            const prior = typeof priorId === "string" && /^[0-9a-f-]{36}$/i.test(priorId)
              ? await findBinding(database, priorId)
              : null;
            // An orphan of a retired binding of this same session is ours to release.
            if (!prior || prior.state !== "retired" || prior.session_id !== sessionId) throw FACTORY_ERRORS.agentConflict();
            await relaycast.releaseHosted(workspaceKey, agentName, existing.id);
            agent = await relaycast.registerHosted(workspaceKey, agentName, metadata);
          }
        } else {
          agent = await relaycast.registerHosted(workspaceKey, agentName, metadata);
        }
      } catch (error) {
        log({ event: "factory.bind", bindingHash: bindingHash(prepared.id), code: "relay_register", outcome: "failed" });
        failure(error);
      }

      await deps.beforeFinalWrite?.("bind");
      const outcome = await database.transaction(async (tx) => {
        // Removal, demotion and unbind all serialize against this transaction.
        const member = await managerInTx(tx, access.workspace.organizationId, userId);
        await findConnection(tx, workspaceId, true);
        const row = await findBinding(tx, prepared.id, true);
        // A concurrent attempt sharing this preparing row recovered the same
        // agent and won: that agent is the row's current one, never release it.
        if (row?.state === "bound" && row.relay_agent_id === agent.id) return { bound: null, member, exists: true, current: row };
        // The setup as this attempt left it in the preparing transaction must
        // be unchanged (Cloud `requireSetupIdentity`): a key rotation or
        // disconnect during the provider calls refuses the bind.
        const changed = setupIdentity(await setupSnapshot(tx, workspaceId)) !== preparedSnapshot;
        if (member && !changed && row?.state === "preparing") {
          const bound = await markBound(tx, prepared.id, agent.id, encryptSecret(agent.token, keyring.active));
          await audit(tx, access, "factory.binding.create", prepared.id);
          return { bound };
        }
        // Removal, an unbind or a setup change won the race: never leave a live binding.
        if (row?.state === "preparing") await retireBindingsInTx(tx, { bindingIds: [row.id] });
        return { bound: null, member, changed, exists: Boolean(row) };
      });
      if (!outcome.bound && "current" in outcome && outcome.current) {
        log({ event: "factory.bind", bindingHash: bindingHash(prepared.id), code: "concurrent_winner", outcome: "bound" });
        if (!outcome.member) throw FACTORY_ERRORS.accessRevoked();
        return { binding_id: prepared.id, session_id: sessionId, agent: { name: agentName, id: agent.id } };
      }
      if (!outcome.bound) {
        try {
          await relaycast.releaseHosted(workspaceKey, agentName, agent.id);
          if (outcome.exists) await markReleased(database, prepared.id);
        } catch {
          if (outcome.exists) {
            await database.query(
              "UPDATE factory_bindings SET relay_agent_id = $2, remote_cleanup_code = 'release_failed' WHERE id = $1 AND state = 'retired'",
              [prepared.id, agent.id],
            );
          }
        }
        log({ event: "factory.bind", bindingHash: bindingHash(prepared.id), code: "late_write", outcome: "refused" });
        if (!outcome.member) throw FACTORY_ERRORS.accessRevoked();
        throw "changed" in outcome && outcome.changed ? FACTORY_ERRORS.setupChanged() : FACTORY_ERRORS.retired();
      }
      log({ event: "factory.bind", bindingHash: bindingHash(prepared.id), outcome: "bound" });
      return { binding_id: prepared.id, session_id: sessionId, agent: { name: agentName, id: agent.id } };
    },

    async listBindings(access: FactoryAccess) {
      const rows = await bindingsForUser(database, access.workspace.id, access.principal.userId);
      return { bindings: rows.map(bindingView), history: "deferred" as const };
    },

    async getBinding(access: FactoryAccess, bindingId: string) {
      return bindingView(await ownBinding(access, bindingId));
    },

    async unbind(access: FactoryAccess, bindingId: string): Promise<void> {
      if (!/^[0-9a-f-]{36}$/i.test(bindingId)) return;
      const row = await findBinding(database, bindingId);
      if (!row || row.workspace_id !== access.workspace.id) return;
      if (row.user_id !== access.principal.userId) throw FACTORY_ERRORS.notOwnerDisconnect();
      const releases = await database.transaction(async (tx) => {
        if (!await managerInTx(tx, access.workspace.organizationId, access.principal.userId)) throw FACTORY_ERRORS.accessRevoked();
        // A rejoined former owner manages nothing of the current connection, not even its own old rows.
        const connection = await findConnection(tx, access.workspace.id, true);
        await requireSetupOwner(tx, access, connection?.user_id ?? null);
        const retired = await retireBindingsInTx(tx, { bindingIds: [bindingId] });
        if (retired.length > 0) await audit(tx, access, "factory.binding.delete", bindingId);
        return retired;
      });
      await release(releases, access.workspace.relaycastApiKey);
      log({ event: "factory.unbind", bindingHash: bindingHash(bindingId), outcome: "retired" });
    },

    async delivery(access: FactoryAccess, bindingId: string, messageId: string) {
      const row = await ownBinding(access, bindingId);
      if (!/^[A-Za-z0-9_-]{1,128}$/.test(messageId)) throw FACTORY_ERRORS.deliveryNotFound();
      const delivery = await findDelivery(database, row.id, messageId);
      if (!delivery) throw FACTORY_ERRORS.deliveryNotFound();
      // Read-only: an unknown send stays unknown (no provider reconciliation in v1).
      return { state: delivery.state, ...(delivery.code ? { code: delivery.code } : {}) };
    },

    /** Records a dormant history intent. 202 means accepted, never completed. */
    async scheduleHistory(access: FactoryAccess, bindingId: string) {
      const row = await ownBinding(access, bindingId);
      if (row.state !== "bound") throw FACTORY_ERRORS.retired();
      await database.transaction(async (tx) => {
        if (!await managerInTx(tx, access.workspace.organizationId, access.principal.userId)) {
          throw FACTORY_ERRORS.accessRevoked();
        }
        const current = await findBinding(tx, row.id, true);
        if (current?.state !== "bound" || current.user_id !== access.principal.userId) throw FACTORY_ERRORS.retired();
        await tx.query(
          `INSERT INTO factory_history_syncs
             (workspace_id, session_id, organization_id, binding_id, user_id, next_due_at)
           VALUES ($1, $2, $3, $4, $5, now())
           ON CONFLICT (workspace_id, session_id) DO UPDATE
             SET binding_id = EXCLUDED.binding_id, user_id = EXCLUDED.user_id,
                 next_due_at = now(), updated_at = now()`,
          [row.workspace_id, row.session_id, row.organization_id, row.id, row.user_id],
        );
        await tx.query(
          "UPDATE factory_bindings SET history_queued_at = now() WHERE id = $1 AND state = 'bound'",
          [row.id],
        );
      });
      log({ event: "factory.history", bindingHash: bindingHash(row.id), outcome: "deferred" });
      return HISTORY_DEFERRED;
    },

    /** Membership-removal purge, inside the removal transaction (deleteMembership beforeCommit). */
    async purgeMemberInTx(tx: SqlExecutor, organizationId: string, userId: string): Promise<void> {
      const purged = await purgeMemberInTx(tx, organizationId, userId);
      if (purged.releases.length > 0 || purged.connections.length > 0) {
        await recordAudit(tx, {
          organizationId,
          actor: { kind: "user", userId },
          action: "factory.member.purge",
          target: `bindings:${purged.releases.length};connections:${purged.connections.length}`,
        });
      }
    },

    /** Remote cleanup only, after the removal committed. Never throws. */
    async afterMemberRemoved(_organizationId: string, userId: string): Promise<void> {
      await releasePending({ userId }).catch(() => undefined);
    },

    /** Remote release for rows removed by `cleanupWorkspaceFactory`, with the key captured before deletion. */
    async afterWorkspaceDeleted(workspaceKey: string, releases: FactoryRelease[]): Promise<number> {
      let failed = 0;
      for (const row of releases) {
        if (!row.relay_agent_id) continue;
        try {
          await relaycast.releaseHosted(workspaceKey, row.relay_agent_name, row.relay_agent_id);
        } catch {
          failed++;
          log({ event: "factory.release", bindingHash: bindingHash(row.id), code: "release_failed", outcome: "abandoned" });
        }
      }
      return failed;
    },

    /**
     * Public reply route body (design §7.3). The bearer is a hash-only,
     * single-delivery capability; the reply always goes to the pinned Relay
     * sender as a thread reply to the injected message, sent as the bound
     * hosted agent. One recorded reply per delivery.
     */
    async reply(bindingId: string, bearer: string, text: string) {
      const now = Date.now();
      const found = await database.query<{
        binding_id: string; message_id: string; organization_id: string; user_id: string;
        binding_state: string; delivery_state: string; reply_expires_at: string | Date | null;
        reply_result: unknown; reply_body_hash: string | null; hosted_token_envelope: string | null;
      }>(
        `SELECT d.binding_id, d.message_id, b.organization_id, b.user_id, b.state AS binding_state,
                d.state AS delivery_state, d.reply_expires_at, d.reply_result, d.reply_body_hash,
                b.hosted_token_envelope
           FROM factory_deliveries d
           JOIN factory_bindings b ON b.id = d.binding_id
          WHERE d.reply_hash = $1`,
        [hashSecret(bearer)],
      );
      const row = found.rows[0];
      if (!row || row.binding_id !== bindingId) {
        // Retirement clears reply hashes; a well-formed bearer for a retired binding says so.
        const binding = /^[0-9a-f-]{36}$/i.test(bindingId) ? await findBinding(database, bindingId) : null;
        if (!row && binding?.state === "retired") throw FACTORY_ERRORS.retired();
        throw FACTORY_ERRORS.replyUnauthorized();
      }
      if (row.binding_state !== "bound" || !row.hosted_token_envelope ||
          !["sending", "delivered", "unknown"].includes(row.delivery_state) ||
          !row.reply_expires_at || new Date(row.reply_expires_at).getTime() <= now ||
          !await isMember(database, row.organization_id, row.user_id)) {
        throw FACTORY_ERRORS.replyUnauthorized();
      }
      const bodyHash = replyBodyHash(text);
      if (row.reply_result) {
        if (row.reply_body_hash === bodyHash) return row.reply_result;
        throw FACTORY_ERRORS.replyRecorded();
      }
      let sent;
      try {
        sent = await relaycast.replyToMessage({
          token: decryptSecret(row.hosted_token_envelope, keyring),
          parentId: row.message_id,
          text,
          idempotencyKey: replyIdempotencyKey(bindingId, row.message_id),
        });
      } catch {
        log({ event: "factory.reply", bindingHash: bindingHash(bindingId), code: "relay_reply", outcome: "failed" });
        throw FACTORY_ERRORS.replyFailed();
      }
      const result = { ok: true, message_id: sent.message.id, conversation_id: sent.conversationId };
      const stored = await database.query<{ reply_result: unknown; reply_body_hash: string | null }>(
        `UPDATE factory_deliveries SET reply_result = COALESCE(reply_result, $3::jsonb),
                reply_body_hash = COALESCE(reply_body_hash, $4), updated_at = now()
          WHERE binding_id = $1 AND message_id = $2
          RETURNING reply_result, reply_body_hash`,
        [bindingId, row.message_id, JSON.stringify(result), bodyHash],
      );
      log({ event: "factory.reply", bindingHash: bindingHash(bindingId), outcome: "sent" });
      const winner = stored.rows[0];
      if (winner && winner.reply_body_hash !== bodyHash) throw FACTORY_ERRORS.replyRecorded();
      return winner?.reply_result ?? result;
    },

    /**
     * Owner/admin: a new enrolled token for the configured origin; the
     * previous enrolled row drains (reason `rotate`) and the reconciler
     * revokes it. Needs a current connection.
     */
    async rotateAcquisition(access: FactoryAccess) {
      if (!acquisitionOrigin) throw FACTORY_ERRORS.acquisitionUnconfigured();
      await database.transaction(async (tx) => {
        if (!await managerInTx(tx, access.workspace.organizationId, access.principal.userId)) {
          throw FACTORY_ERRORS.accessRevoked();
        }
        await lockWorkspaceFactory(tx, access.workspace.id);
        if (!await findConnection(tx, access.workspace.id, true)) throw FACTORY_ERRORS.notConnected();
        await enrolledAcquisitionOperator(tx, access.workspace.id, acquisitionOrigin, true);
        await drainAcquisitionOperatorsInTx(tx, [access.workspace.id], "rotate");
        await enrolInTx(tx, access, "factory.acquisition.rotate");
      });
      log({ event: "factory.acquisition", kind: "rotate", outcome: "rotated" });
      return summary(access);
    },

    /**
     * Owner/admin: revokes every enrolled or draining acquisition-operator
     * token of the workspace now (reason `admin`). Works after a disconnect
     * too, so draining tokens can be cut without waiting for the reconciler.
     */
    async revokeAcquisition(access: FactoryAccess) {
      if (!acquisitionOrigin) throw FACTORY_ERRORS.acquisitionUnconfigured();
      const actor: AuditActor = { kind: "user", userId: access.principal.userId };
      await database.transaction(async (tx) => {
        if (!await managerInTx(tx, access.workspace.organizationId, access.principal.userId)) {
          throw FACTORY_ERRORS.accessRevoked();
        }
        await lockWorkspaceFactory(tx, access.workspace.id);
        const connection = await findConnection(tx, access.workspace.id, true);
        const rows = await tx.query<AcquisitionOperatorRow>(
          `SELECT o.*, (t.revoked_at IS NOT NULL) AS token_revoked
             FROM factory_acquisition_operators o
             JOIN workspace_api_tokens t ON t.id = o.token_id
            WHERE o.workspace_id = $1 AND o.state IN ('enrolled', 'draining')
            ORDER BY o.created_at, o.id
            FOR UPDATE OF o`,
          [access.workspace.id],
        );
        if (!connection && rows.rows.length === 0) throw FACTORY_ERRORS.notConnected();
        for (const row of rows.rows) await revokeOperatorInTx(tx, row, actor, "admin", 0);
      });
      log({ event: "factory.acquisition", kind: "revoke", outcome: "revoked" });
      return summary(access);
    },

    /**
     * Acquisition loop body: revokes draining tokens whose obligations are
     * settled, or that drained longer than ACQUISITION_DRAIN_MAX_MS (the
     * outstanding count is kept as `stranded_count`). Returns rows revoked.
     */
    async reconcileAcquisition(limit = 50): Promise<number> {
      if (!deps.acquisition) return 0;
      return database.transaction(async (tx) => {
        const rows = await tx.query<AcquisitionOperatorRow & { expired: boolean }>(
          `SELECT o.*, (t.revoked_at IS NOT NULL) AS token_revoked,
                  (o.drain_started_at <= now() - ($2::bigint * interval '1 millisecond')) AS expired
             FROM factory_acquisition_operators o
             JOIN workspace_api_tokens t ON t.id = o.token_id
            WHERE o.state = 'draining'
            ORDER BY o.drain_started_at, o.id
            LIMIT $1
            FOR UPDATE OF o SKIP LOCKED`,
          [limit, ACQUISITION_DRAIN_MAX_MS],
        );
        let revoked = 0;
        for (const row of rows.rows) {
          const obligations = await outstandingObligations(tx, row.workspace_id);
          if (obligations !== 0 && !row.expired) continue;
          await revokeOperatorInTx(tx, row, RECONCILER_ACTOR, row.reason ?? "drained", obligations);
          revoked++;
        }
        if (revoked > 0) log({ event: "factory.acquisition", kind: "reconcile", outcome: "revoked" });
        return revoked;
      });
    },

    /** Cleanup loop body: retries remote release of retired rows. Returns rows still pending. */
    releasePending,

    /** MCP tools: the caller's current role, re-read from Postgres (the MCP context's role is not trusted). */
    async assertManager(access: FactoryAccess): Promise<void> {
      const role = await memberRole(database, access.workspace.organizationId, access.principal.userId);
      if (role !== "owner" && role !== "admin") throw FACTORY_ERRORS.notManager();
    },

    /**
     * MCP resolver hook: the hosted identity of `userId`'s own bound Factory
     * session whose Relay agent is `name` in this workspace, while `userId`
     * is still a member. Null for anything else (preparing, retired, foreign,
     * removed member), so callers fall back to their own error.
     */
    async agentFor(workspaceId: string, userId: string, name: string): Promise<{ name: string; token: string } | null> {
      if (!name.startsWith("factory-")) return null;
      const row = (await bindingsForUser(database, workspaceId, userId)).find((candidate) =>
        candidate.state === "bound" && candidate.hosted_token_envelope !== null &&
        candidate.relay_agent_name === name && agentNameFor(candidate.session_id) === name);
      if (!row?.hosted_token_envelope || !await isMember(database, row.organization_id, userId)) return null;
      return { name: row.relay_agent_name, token: decryptSecret(row.hosted_token_envelope, keyring) };
    },
  };
}

export type FactoryService = ReturnType<typeof createFactoryService>;
export { deleteBinding };
