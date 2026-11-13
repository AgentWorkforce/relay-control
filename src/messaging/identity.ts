import { createHash, randomBytes, randomUUID } from "node:crypto";
import { decryptSecret, encryptSecret, type EncryptionKeyring } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";
import type { Principal } from "../store.js";
import { MessagingHttpError } from "./http.js";
import {
  admissionRejected,
  createRelaycastClient,
  isOwnedBy,
  RelaycastCallError,
  type PersonOwner,
  type RemoteAgent,
} from "./relaycast.js";

type PersonUser = Pick<Principal, "userId" | "name" | "email">;

const MAX_NAME = 48;
const STALE_CLAIM_MS = 15_000;

export type PersonIdentity = {
  name: string;
  agentId: string;
  token: string;
  relaycastWorkspaceId: string;
};

type IdentityRow = {
  agent_name: string;
  agent_remote_id: string;
  token_ciphertext: string;
  relaycast_workspace_id: string;
};

export type MessagingDeps = {
  database: Database;
  keyring: EncryptionKeyring;
  relaycastUrl: string;
  fetchImpl?: typeof fetch;
  now?: () => Date;
  /** Tests set this to 0 so a crashed pending claim can be reconciled immediately. */
  claimLeaseMs?: number;
  /** Throws after Relaycast accepts registration and before the local row is staged. */
  afterRemoteRegister?: () => Promise<void> | void;
  /** Throws after the local row is staged and before the identity transaction commits. */
  afterIdentityStaged?: () => Promise<void> | void;
  /** Runs inside the identity lock, after registration, before the membership re-check. */
  beforeMembershipRecheck?: (tx: SqlExecutor) => Promise<void> | void;
  beforeDispatch?: () => Promise<void> | void;
  afterUpstream?: () => Promise<void> | void;
};

type Relaycast = ReturnType<typeof createRelaycastClient>;

function slug(value: string): string {
  return value
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
}

export function candidateNames(user: { userId: string; email: string; name: string }, randomSuffix = () => randomBytes(2).toString("hex")): string[] {
  const bases = [slug(user.name), slug(user.email.split("@", 1)[0] ?? "")]
    .map((base) => base.slice(0, 32).replace(/-+$/, ""))
    .filter((base) => base.length >= 2);
  if (bases.length === 0) bases.push("person");
  const stable = createHash("sha256").update(user.userId).digest("hex").slice(0, 4);
  const names = [
    ...bases,
    ...bases.map((base) => `${base}-${stable}`),
    `${bases[0]}-${randomSuffix()}`,
    `${bases[0]}-${randomSuffix()}`,
  ];
  return [...new Set(names.map((name) => name.slice(0, MAX_NAME)))];
}

function ownerOf(workspaceId: string, user: PersonUser): PersonOwner {
  return {
    cloudWorkspaceId: workspaceId,
    cloudUserId: user.userId,
    displayName: user.name || user.email || null,
  };
}

async function withLock<T>(database: Database, key: string, run: (tx: SqlExecutor) => Promise<T>): Promise<T> {
  return database.transaction(async (tx) => {
    await tx.query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))", ["selfhost-person", key]);
    return run(tx);
  });
}

async function readRow(executor: SqlExecutor, workspaceId: string, userId: string): Promise<IdentityRow | null> {
  const result = await executor.query<IdentityRow>(
    `SELECT agent_name, agent_remote_id, token_ciphertext, relaycast_workspace_id
       FROM person_identities
      WHERE workspace_id = $1 AND user_id = $2`,
    [workspaceId, userId],
  );
  return result.rows[0] ?? null;
}

function usable(row: IdentityRow | null, relaycastWorkspaceId: string, keyring: EncryptionKeyring): PersonIdentity | null {
  if (!row || row.relaycast_workspace_id !== relaycastWorkspaceId) return null;
  return {
    name: row.agent_name,
    agentId: row.agent_remote_id,
    token: decryptSecret(row.token_ciphertext, keyring),
    relaycastWorkspaceId,
  };
}

async function isMember(executor: SqlExecutor, organizationId: string, userId: string): Promise<boolean> {
  const result = await executor.query<{ present: boolean }>(
    `SELECT true AS present
       FROM organization_memberships
      WHERE organization_id = $1 AND user_id = $2`,
    [organizationId, userId],
  );
  return result.rows.length === 1;
}

async function saveIdentity(
  executor: SqlExecutor,
  input: { workspaceId: string; userId: string; relaycastWorkspaceId: string; identity: PersonIdentity; keyring: EncryptionKeyring },
): Promise<void> {
  await executor.query(
    `INSERT INTO person_identities
       (id, workspace_id, user_id, agent_name, agent_remote_id, token_ciphertext, relaycast_workspace_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (workspace_id, user_id) DO UPDATE
       SET agent_name = EXCLUDED.agent_name,
           agent_remote_id = EXCLUDED.agent_remote_id,
           token_ciphertext = EXCLUDED.token_ciphertext,
           relaycast_workspace_id = EXCLUDED.relaycast_workspace_id`,
    [
      randomUUID(),
      input.workspaceId,
      input.userId,
      input.identity.name,
      input.identity.agentId,
      encryptSecret(input.identity.token, input.keyring.active),
      input.relaycastWorkspaceId,
    ],
  );
}

function client(deps: MessagingDeps): Relaycast {
  return createRelaycastClient({ internalOrigin: deps.relaycastUrl, fetchImpl: deps.fetchImpl });
}

export async function findPersonIdentity(
  deps: MessagingDeps,
  access: { workspaceId: string; user: { userId: string }; relaycastWorkspaceId: string },
): Promise<PersonIdentity | null> {
  const row = await readRow(deps.database, access.workspaceId, access.user.userId);
  return usable(row, access.relaycastWorkspaceId, deps.keyring);
}

async function createIdentity(
  deps: MessagingDeps,
  relaycast: Relaycast,
  access: { workspaceId: string; organizationId: string; relaycastWorkspaceId: string; relaycastApiKey: string; user: PersonUser },
  executor: SqlExecutor,
): Promise<PersonIdentity> {
  const owner = ownerOf(access.workspaceId, access.user);
  for (const name of candidateNames(access.user)) {
    try {
      const registered = await relaycast.registerHuman(access.relaycastApiKey, name, owner);
      const identity = {
        name: registered.name,
        agentId: registered.id,
        token: registered.token,
        relaycastWorkspaceId: access.relaycastWorkspaceId,
      };
      if (deps.afterRemoteRegister) await deps.afterRemoteRegister();
      await saveIdentity(executor, {
        workspaceId: access.workspaceId,
        userId: access.user.userId,
        relaycastWorkspaceId: access.relaycastWorkspaceId,
        identity,
        keyring: deps.keyring,
      });
      if (deps.afterIdentityStaged) await deps.afterIdentityStaged();
      return identity;
    } catch (error) {
      if (error instanceof RelaycastCallError && admissionRejected(error)) {
        throw new MessagingHttpError(409, "register_human_admission", "Relaycast register_human admission is full for this workspace");
      }
      const taken = error instanceof RelaycastCallError
        && (error.status === 409 || error.code === "agent_already_exists");
      if (!taken) throw new MessagingHttpError(502, "upstream_unavailable", "Relaycast could not register the member");
    }
    const remote = await relaycast.getAgent(access.relaycastApiKey, name);
    if (remote && isOwnedBy(remote, owner)) {
      return persistRecovery(deps, relaycast, access, remote, executor);
    }
  }
  throw new MessagingHttpError(409, "identity_unavailable", "Could not find a free name for your relay identity.");
}

async function persistRecovery(
  deps: MessagingDeps,
  relaycast: Relaycast,
  access: { workspaceId: string; relaycastWorkspaceId: string; relaycastApiKey: string; user: PersonUser },
  remote: RemoteAgent,
  executor: SqlExecutor,
): Promise<PersonIdentity> {
  const token = await relaycast.takeOver(
    access.relaycastApiKey,
    remote.name,
    remote.id,
    `selfhost-user:${access.user.userId}`,
  );
  const identity = {
    name: remote.name,
    agentId: remote.id,
    token,
    relaycastWorkspaceId: access.relaycastWorkspaceId,
  };
  await saveIdentity(executor, {
    workspaceId: access.workspaceId,
    userId: access.user.userId,
    relaycastWorkspaceId: access.relaycastWorkspaceId,
    identity,
    keyring: deps.keyring,
  });
  return identity;
}

export async function ensurePersonIdentity(
  deps: MessagingDeps,
  access: { workspaceId: string; organizationId: string; relaycastWorkspaceId: string; relaycastApiKey: string; user: PersonUser },
): Promise<PersonIdentity> {
  const relaycast = client(deps);
  const outcome = await withLock(deps.database, `${access.workspaceId}:${access.user.userId}`, async (tx) => {
    if (!(await isMember(tx, access.organizationId, access.user.userId))) {
      throw new MessagingHttpError(403, "forbidden", "Organization membership is required");
    }
    const current = usable(await readRow(tx, access.workspaceId, access.user.userId), access.relaycastWorkspaceId, deps.keyring);
    if (current) return { identity: current, revoke: null as PersonIdentity | null };
    const created = await createIdentity(deps, relaycast, access, tx);
    if (deps.beforeMembershipRecheck) await deps.beforeMembershipRecheck(tx);
    if (!(await isMember(tx, access.organizationId, access.user.userId))) {
      await queueRevocation(tx, {
        workspaceId: access.workspaceId,
        userId: access.user.userId,
        relaycastWorkspaceId: access.relaycastWorkspaceId,
        agentName: created.name,
        agentRemoteId: created.agentId,
        relaycastApiKey: access.relaycastApiKey,
      });
      return { identity: null as PersonIdentity | null, revoke: created };
    }
    return { identity: created, revoke: null as PersonIdentity | null };
  });
  if (outcome.revoke) {
    await relaycast.revokeHuman(
      access.relaycastApiKey,
      outcome.revoke.name,
      outcome.revoke.agentId,
      `selfhost-user:${access.user.userId}`,
    ).catch(() => undefined);
    throw new MessagingHttpError(403, "forbidden", "Organization membership ended before the credential was issued");
  }
  return outcome.identity!;
}

export function isRefusedToken(error: unknown): boolean {
  return error instanceof RelaycastCallError && (error.status === 401 || error.status === 403);
}

export async function recoverPersonIdentity(
  deps: MessagingDeps,
  access: { workspaceId: string; organizationId: string; relaycastWorkspaceId: string; relaycastApiKey: string; user: PersonUser },
  refused: PersonIdentity,
): Promise<PersonIdentity> {
  const relaycast = client(deps);
  return withLock(deps.database, `${access.workspaceId}:${access.user.userId}`, async (tx) => {
    const current = usable(await readRow(tx, access.workspaceId, access.user.userId), access.relaycastWorkspaceId, deps.keyring);
    if (current && current.token !== refused.token) return current;
    const remote = await relaycast.getAgent(access.relaycastApiKey, refused.name);
    if (!remote) return createIdentity(deps, relaycast, access, tx);
    const owner = ownerOf(access.workspaceId, access.user);
    if (!isOwnedBy(remote, owner) || remote.id !== refused.agentId) {
      throw new MessagingHttpError(409, "foreign_identity", "Your relay identity's name now belongs to someone else.");
    }
    return persistRecovery(deps, relaycast, access, remote, tx);
  });
}

export async function withPersonToken<T>(
  deps: MessagingDeps,
  access: { workspaceId: string; organizationId: string; relaycastWorkspaceId: string; relaycastApiKey: string; user: PersonUser },
  fn: (identity: PersonIdentity) => Promise<T>,
): Promise<T> {
  const identity = await ensurePersonIdentity(deps, access);
  try {
    return await fn(identity);
  } catch (error) {
    if (!isRefusedToken(error)) throw error;
    return fn(await recoverPersonIdentity(deps, access, identity));
  }
}

type RevocationTarget = {
  workspaceId: string;
  userId: string;
  relaycastWorkspaceId: string;
  agentName: string;
  agentRemoteId: string;
  relaycastApiKey: string;
};

async function queueRevocation(executor: SqlExecutor, target: RevocationTarget): Promise<void> {
  await executor.query(
    `INSERT INTO person_revocations
       (id, workspace_id, user_id, relaycast_workspace_id, agent_name, agent_remote_id)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (workspace_id, user_id, agent_remote_id) DO NOTHING`,
    [randomUUID(), target.workspaceId, target.userId, target.relaycastWorkspaceId, target.agentName, target.agentRemoteId],
  );
  await executor.query(
    `DELETE FROM person_identities
      WHERE workspace_id = $1 AND user_id = $2 AND agent_remote_id = $3`,
    [target.workspaceId, target.userId, target.agentRemoteId],
  );
}

/** Membership removal retires the human credential. Session sign-out does not. */
export async function revokeRemovedMember(deps: MessagingDeps, organizationId: string, userId: string): Promise<void> {
  const rows = await deps.database.query<{
    workspace_id: string;
    relaycast_workspace_id: string;
    agent_name: string;
    agent_remote_id: string;
    relaycast_api_key_ciphertext: string;
  }>(
    `SELECT identity.workspace_id, identity.relaycast_workspace_id, identity.agent_name,
            identity.agent_remote_id, workspace.relaycast_api_key_ciphertext
       FROM person_identities identity
       JOIN workspaces workspace ON workspace.id = identity.workspace_id
      WHERE workspace.organization_id = $1 AND identity.user_id = $2`,
    [organizationId, userId],
  );
  for (const row of rows.rows) {
    const relaycastApiKey = decryptSecret(row.relaycast_api_key_ciphertext, deps.keyring);
    await deps.database.transaction(async (tx) => {
      await queueRevocation(tx, {
        workspaceId: row.workspace_id,
        userId,
        relaycastWorkspaceId: row.relaycast_workspace_id,
        agentName: row.agent_name,
        agentRemoteId: row.agent_remote_id,
        relaycastApiKey,
      });
    });
  }
  await sweepRevocations(deps, organizationId, userId);
}

export async function sweepRevocations(deps: MessagingDeps, organizationId?: string, userId?: string): Promise<void> {
  const rows = await deps.database.query<{
    id: string;
    agent_name: string;
    agent_remote_id: string;
    relaycast_api_key_ciphertext: string;
    user_id: string;
  }>(
    `SELECT revocation.id, revocation.agent_name, revocation.agent_remote_id,
            revocation.user_id, workspace.relaycast_api_key_ciphertext
       FROM person_revocations revocation
       JOIN workspaces workspace ON workspace.id = revocation.workspace_id
      WHERE ($1::uuid IS NULL OR workspace.organization_id = $1)
        AND ($2::uuid IS NULL OR revocation.user_id = $2)`,
    [organizationId ?? null, userId ?? null],
  );
  const relaycast = client(deps);
  for (const row of rows.rows) {
    try {
      await relaycast.revokeHuman(
        decryptSecret(row.relaycast_api_key_ciphertext, deps.keyring),
        row.agent_name,
        row.agent_remote_id,
        `selfhost-user:${row.user_id}`,
      );
      await deps.database.query("DELETE FROM person_revocations WHERE id = $1", [row.id]);
    } catch {
      // The queue row remains for the next request.
    }
  }
}

export type SendClaim = {
  relay_message_id: string | null;
  conversation_id: string | null;
  body: string;
  peer_name: string;
  status: string;
  terminal_code: string | null;
  fingerprint: string;
  age_ms: number;
};

export function messageFingerprint(relaycastWorkspaceId: string, peer: string, text: string): string {
  return createHash("sha256").update(`${relaycastWorkspaceId}\n${peer}\n${text}`).digest("hex");
}

function isUniqueViolation(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const code = (error as { code?: unknown }).code;
  if (code === "23505") return true;
  return error instanceof Error && error.message.includes("duplicate key");
}

export async function claimSend(
  deps: MessagingDeps,
  input: {
    workspaceId: string;
    userId: string;
    relaycastWorkspaceId: string;
    peer: string;
    clientMessageId: string;
    text: string;
  },
): Promise<{ kind: "duplicate" | "dispatch" | "uncertain" | "rejected" | "wait"; claim: SendClaim }> {
  try {
    return await claimSendOnce(deps, input);
  } catch (error) {
    if (!isUniqueViolation(error)) throw error;
    return claimSendOnce(deps, input);
  }
}

async function claimSendOnce(
  deps: MessagingDeps,
  input: {
    workspaceId: string;
    userId: string;
    relaycastWorkspaceId: string;
    peer: string;
    clientMessageId: string;
    text: string;
  },
): Promise<{ kind: "duplicate" | "dispatch" | "uncertain" | "rejected" | "wait"; claim: SendClaim }> {
  const fingerprint = messageFingerprint(input.relaycastWorkspaceId, input.peer, input.text);
  const leaseMs = deps.claimLeaseMs ?? STALE_CLAIM_MS;
  return withLock(
    deps.database,
    `send:${input.workspaceId}:${input.userId}:${input.relaycastWorkspaceId}:${input.clientMessageId}`,
    async (tx) => {
      const existing = await tx.query<SendClaim & { created_at: Date | string }>(
        `SELECT relay_message_id, conversation_id, body, peer_name, status, terminal_code, fingerprint,
                EXTRACT(EPOCH FROM (clock_timestamp() - created_at)) * 1000 AS age_ms, created_at
           FROM person_messages
          WHERE workspace_id = $1 AND user_id = $2 AND relaycast_workspace_id = $3 AND client_message_id = $4
          FOR UPDATE`,
        [input.workspaceId, input.userId, input.relaycastWorkspaceId, input.clientMessageId],
      );
      const row = existing.rows[0];
      if (!row) {
        await tx.query(
          `INSERT INTO person_messages
             (id, workspace_id, user_id, relaycast_workspace_id, peer_name, client_message_id, body, fingerprint, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')`,
          [randomUUID(), input.workspaceId, input.userId, input.relaycastWorkspaceId, input.peer, input.clientMessageId, input.text, fingerprint],
        );
        return { kind: "dispatch" as const, claim: freshClaim(input, fingerprint) };
      }
      if (row.fingerprint !== fingerprint) {
        throw new MessagingHttpError(409, "idempotency_conflict", "clientMessageId was already used for a different message");
      }
      const claim = { ...row, age_ms: Number(row.age_ms) };
      if (row.status === "accepted") return { kind: "duplicate" as const, claim };
      if (row.status === "rejected") return { kind: "rejected" as const, claim };
      // A known failure never reached Relaycast, so a later try may dispatch.
      // uncertain and an expired pending claim may already be in flight or
      // stored. This engine has no verified idempotency receipt, so those
      // claims are not sent again.
      if (row.status === "retryable") {
        await tx.query(
          `UPDATE person_messages
              SET status = 'pending', created_at = clock_timestamp()
            WHERE workspace_id = $1 AND user_id = $2 AND relaycast_workspace_id = $3 AND client_message_id = $4`,
          [input.workspaceId, input.userId, input.relaycastWorkspaceId, input.clientMessageId],
        );
        return { kind: "dispatch" as const, claim: { ...claim, status: "pending", age_ms: 0 } };
      }
      if (row.status === "uncertain" || claim.age_ms >= leaseMs) {
        return { kind: "uncertain" as const, claim };
      }
      return { kind: "wait" as const, claim };
    },
  );
}

function freshClaim(input: { peer: string; text: string }, fingerprint: string): SendClaim {
  return {
    relay_message_id: null,
    conversation_id: null,
    body: input.text,
    peer_name: input.peer,
    status: "pending",
    terminal_code: null,
    fingerprint,
    age_ms: 0,
  };
}

export async function finishSend(
  deps: MessagingDeps,
  input: {
    workspaceId: string;
    userId: string;
    relaycastWorkspaceId: string;
    clientMessageId: string;
    status: "accepted" | "uncertain" | "retryable" | "rejected";
    relayMessageId?: string | null;
    conversationId?: string | null;
    terminalCode?: string | null;
  },
): Promise<void> {
  await deps.database.query(
    `UPDATE person_messages
        SET status = $5,
            relay_message_id = COALESCE($6, relay_message_id),
            conversation_id = COALESCE($7, conversation_id),
            terminal_code = $8
      WHERE workspace_id = $1 AND user_id = $2 AND relaycast_workspace_id = $3 AND client_message_id = $4`,
    [
      input.workspaceId,
      input.userId,
      input.relaycastWorkspaceId,
      input.clientMessageId,
      input.status,
      input.relayMessageId ?? null,
      input.conversationId ?? null,
      input.terminalCode ?? null,
    ],
  );
}

export async function waitForSend(
  deps: MessagingDeps,
  input: { workspaceId: string; userId: string; relaycastWorkspaceId: string; clientMessageId: string },
): Promise<SendClaim | null> {
  const started = Date.now();
  while (Date.now() - started < 5_000) {
    const result = await deps.database.query<SendClaim>(
      `SELECT relay_message_id, conversation_id, body, peer_name, status, terminal_code, fingerprint,
              EXTRACT(EPOCH FROM (clock_timestamp() - created_at)) * 1000 AS age_ms
         FROM person_messages
        WHERE workspace_id = $1 AND user_id = $2 AND relaycast_workspace_id = $3 AND client_message_id = $4`,
      [input.workspaceId, input.userId, input.relaycastWorkspaceId, input.clientMessageId],
    );
    const row = result.rows[0];
    if (row && row.status !== "pending") return { ...row, age_ms: Number(row.age_ms) };
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return null;
}
