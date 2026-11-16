import { randomUUID } from "node:crypto";
import { z } from "zod";
import { recordAudit } from "../admin/audit.js";
import type { SqlExecutor } from "../database.js";
import { HOSTED_SOURCE, ownerHash } from "../mcp/relay-participants.js";
import { emailHint, type ReplicaIdentityClaims } from "./identity.js";
import { ReplicasRuntimeError, type EnvironmentMcp } from "./runtime.js";
import {
  auditActor,
  COLUMNS,
  decrypt,
  encrypt,
  ENVIRONMENT_IDENTITY,
  isUuid,
  keyFor,
  patch,
  accessRevoked,
  recordProviderAccess,
  rejectedByProvider,
  relayFor,
  ReplicasError,
  requireAdmin,
  retireIdentityBindings,
  retireRemote,
  withReplicasLock,
  type ReplicasActor,
  type ReplicasDeps,
  type ResolvedBinding,
  type SpawnInput,
  type SpawnRow,
} from "./service.js";

/**
 * Environment-level Replicas MCP: one MCP entry per provider environment,
 * authenticated by the Replicas workspace's own `workspace_identity` token
 * (./identity.ts). A token is admitted only through an explicitly enabled
 * environment policy and either a creator mapping to a current member or the
 * workspace's explicit VM principal (a current member chosen by an admin,
 * never derived from an email or the owner); the first admitted call enrols
 * a Relay identity for that Replicas workspace. No
 * helper, credentials file or exec is written into the replica, and nothing
 * is pushed into its chats: it reads its inbox through the MCP tools.
 *
 * Connecting Replicas (an owner/admin action) discovers every environment of
 * the connected organization, enables it and registers the MCP entry; ones
 * discovered later on sync are enabled too. Admins opt out per environment,
 * or turn the default off for the whole workspace.
 */
export const IDENTITY_SERVER_NAME = "agent-relay-replica";

export type IdentityRefusalCode =
  | "replica_identity_invalid"
  | "replica_released"
  | "replica_owned_elsewhere"
  | "replica_environment_not_enabled"
  | "organization_shared"
  | "replica_creator_not_allowed"
  | "replica_already_bound";

/**
 * A refused workspace_identity call. Its message is the code, never claim
 * text. policyId is set only for an unmapped creator on an enabled policy,
 * so the request can be shown to an admin.
 */
export class IdentityRefusal extends ReplicasError {
  constructor(readonly code: IdentityRefusalCode, status: number, readonly scope: { workspaceId: string; organizationId: string } | null = null,
    readonly policyId: string | null = null) {
    super(code, status);
    this.name = "IdentityRefusal";
  }
}

type PolicyRow = {
  id: string;
  workspace_id: string;
  issuer: string;
  provider_organization_id: string;
  environment_id: string;
  environment_name: string;
  enabled: boolean;
  registered_mcp_id: string | null;
  opted_out: boolean;
  /** A create was (or was about to be) sent with an unknown outcome: every run only relists until it clears (retry_registration excepted). */
  create_unconfirmed: boolean;
  /** Set when a complete discovery listing no longer showed this enabled environment; fences admission. */
  discovery_missing_since: Date | string | null;
};
const POLICY = "id, workspace_id, issuer, provider_organization_id, environment_id, environment_name, enabled, registered_mcp_id, opted_out, create_unconfirmed, discovery_missing_since";

/**
 * actsAs: "creator" for a mapped creator, "principal" for the workspace VM
 * principal, "none" when neither applies (userId null): only an owned launch
 * or bind of the same replica can then admit it (liveBinding).
 */
type Admission = { policy: PolicyRow; organizationId: string; userId: string | null; actsAs: "creator" | "principal" | "none" };
const scopeOf = (admission: Admission) => ({ workspaceId: admission.policy.workspace_id, organizationId: admission.organizationId });

function identityConfig(deps: ReplicasDeps) {
  if (!deps.identity) throw new ReplicasError("The environment-level Replicas MCP is not configured.", 404);
  return deps.identity;
}

/** The environment-level MCP URL; it is also the token audience. */
export const environmentMcpUrl = (publicBaseUrl: string) => `${publicBaseUrl.replace(/\/+$/, "")}/api/v1/replicas/mcp`;
/** The Relay name of an environment-identity binding: derived from the provider workspace id. */
export const identityAgentName = (workspaceId: string) => `replicas-${workspaceId.replaceAll("-", "").toLowerCase().slice(0, 16)}`;

/** Whether one provider organization is connected in more than one workspace (then it is never admitted or enabled). */
async function organizationShared(tx: SqlExecutor, organization: string | null): Promise<boolean> {
  if (!organization) return false;
  const result = await tx.query<{ count: number }>(
    "SELECT count(DISTINCT workspace_id)::int AS count FROM remote_agent_connections WHERE provider = 'replicas' AND lower(provider_account) = $1",
    [organization.toLowerCase()],
  );
  return (result.rows[0]?.count ?? 0) > 1;
}

/**
 * Checks 2-4 of the admission order (1 = token verification, done by the
 * caller). Reads only; every refusal is a typed IdentityRefusal. A mapped
 * creator acts as its member; otherwise (no creator, or an unmapped one) the
 * workspace's VM principal is used when it is set and still a member.
 */
async function admissionChecks(tx: SqlExecutor, claims: ReplicaIdentityClaims): Promise<Admission> {
  // Any matching tombstone refuses, also one whose workspace was deleted (workspace_id NULL).
  const tombstone = await tx.query<{ workspace_id: string | null; organization_id: string | null }>(
    `SELECT t.workspace_id, w.organization_id FROM replica_identity_tombstones t LEFT JOIN workspaces w ON w.id = t.workspace_id
      WHERE t.issuer = $1 AND t.provider_organization_id = $2 AND t.provider_workspace_id = $3`,
    [claims.issuer, claims.organizationId, claims.workspaceId],
  );
  const released = tombstone.rows[0];
  if (released) {
    throw new IdentityRefusal("replica_released", 403, released.workspace_id && released.organization_id
      ? { workspaceId: released.workspace_id, organizationId: released.organization_id } : null);
  }
  const policies = await tx.query<PolicyRow & { organization_id: string; provider_account: string | null;
    access_revoked_at: Date | string | null; principal_member: string | null }>(
    `SELECT ${POLICY.split(", ").map((column) => `p.${column}`).join(", ")}, w.organization_id, c.provider_account,
            c.access_revoked_at, pm.user_id AS principal_member
       FROM replica_environment_policies p
       JOIN workspaces w ON w.id = p.workspace_id
       LEFT JOIN remote_agent_connections c ON c.workspace_id = p.workspace_id AND c.provider = 'replicas'
       LEFT JOIN replica_environment_settings s ON s.workspace_id = p.workspace_id
       LEFT JOIN organization_memberships pm ON pm.user_id = s.principal_user_id AND pm.organization_id = w.organization_id
      WHERE p.enabled AND p.discovery_missing_since IS NULL AND p.issuer = $1 AND p.provider_organization_id = $2 AND p.environment_id = $3`,
    [claims.issuer, claims.organizationId, claims.environmentId],
  );
  const candidate = policies.rows.length === 1 ? policies.rows[0]! : null;
  // No reassignment across workspaces: the first workspace that enrolled this replica owns it
  // for good, whatever state its row is in (live, retired or gone).
  if (candidate) {
    // An API launch or bind pinned by its first environment admission (identity_admitted) counts the same.
    const elsewhere = await tx.query(
      `SELECT 1 FROM replica_spawns
        WHERE lower(replica_id) = $4 AND workspace_id <> $5
          AND ((source = $1 AND issuer = $2 AND lower(provider_organization_id) = $3)
            OR (input->'identity_admitted'->>'issuer' = $2 AND lower(input->'identity_admitted'->>'organization_id') = $3))
        LIMIT 1`,
      [ENVIRONMENT_IDENTITY, claims.issuer, claims.organizationId, claims.workspaceId, candidate.workspace_id],
    );
    if (elsewhere.rows.length) {
      throw new IdentityRefusal("replica_owned_elsewhere", 403, { workspaceId: candidate.workspace_id, organizationId: candidate.organization_id });
    }
  }
  // An organization connected in several workspaces has no single tenant: refuse before any creator check.
  if (await organizationShared(tx, claims.organizationId)) {
    throw new IdentityRefusal("organization_shared", 403,
      candidate ? { workspaceId: candidate.workspace_id, organizationId: candidate.organization_id } : null);
  }
  // The workspace must still hold a connection to the same provider
  // organization, one the provider has not refused (the access-revoked latch).
  if (!candidate || candidate.provider_account?.toLowerCase() !== claims.organizationId || candidate.access_revoked_at) {
    throw new IdentityRefusal("replica_environment_not_enabled", 403);
  }
  const { organization_id: organizationId, provider_account: _account, access_revoked_at: _revoked,
    principal_member: principal, ...policy } = candidate;
  const scope = { workspaceId: policy.workspace_id, organizationId };
  if (claims.creatorId !== null) {
    const mapping = await tx.query<{ user_id: string; member: string | null }>(
      `SELECT c.user_id, m.user_id AS member FROM replica_environment_creators c
         LEFT JOIN organization_memberships m ON m.user_id = c.user_id AND m.organization_id = $3
        WHERE c.policy_id = $1 AND c.creator_id = $2`,
      [policy.id, claims.creatorId, organizationId],
    );
    const mapped = mapping.rows[0];
    if (mapped) {
      // A mapping to a former member is the admin's own choice: refused, never moved to the principal.
      if (!mapped.member) throw new IdentityRefusal("replica_creator_not_allowed", 403, scope);
      return { policy, organizationId, userId: mapped.user_id, actsAs: "creator" };
    }
  }
  if (principal) return { policy, organizationId, userId: principal, actsAs: "principal" };
  // No creator mapping and no principal: liveBinding refuses unless an owned launch or bind exists.
  return { policy, organizationId, userId: null, actsAs: "none" };
}

/** No mapped creator and no principal; only an unmapped creator becomes a pending request. */
const unadmitted = (claims: ReplicaIdentityClaims, admission: Admission) =>
  new IdentityRefusal("replica_creator_not_allowed", 403, scopeOf(admission), claims.creatorId === null ? null : admission.policy.id);

async function liveBinding(tx: SqlExecutor, claims: ReplicaIdentityClaims, admission: Admission): Promise<SpawnRow | null> {
  const live = await tx.query<SpawnRow>(
    `SELECT ${COLUMNS} FROM replica_spawns WHERE lower(replica_id) = $1 AND state <> 'gone' ORDER BY created_at, id FOR UPDATE`,
    [claims.workspaceId],
  );
  const row = live.rows[0];
  if (!row) {
    if (admission.actsAs === "none") throw unadmitted(claims, admission);
    return null;
  }
  // A launch or bind of the same replica in this workspace is reused as is: the identity acts as
  // that binding and its owner (never the principal or a creator mapping) while the owner is a member.
  // A rejected launch binds nothing by itself, so it stays a conflict until recovered or released.
  if (row.source !== ENVIRONMENT_IDENTITY && row.workspace_id === admission.policy.workspace_id && row.state !== "rejected") {
    const owner = await tx.query("SELECT 1 FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
      [admission.organizationId, row.user_id]);
    if (!owner.rows.length) throw new IdentityRefusal("replica_creator_not_allowed", 403, scopeOf(admission));
    // The first verified admission pins the reused row to this tenant. Written under the admission
    // lock (withReplicasLock), before the call is served, and only while unset: the first verified
    // issuer and organization stay immutable, and release or revive never clear them.
    if (!row.input.identity_admitted) {
      const stamped = await tx.query<SpawnRow>(
        `UPDATE replica_spawns SET input = input || jsonb_build_object('identity_admitted',
           jsonb_build_object('issuer', $2::text, 'organization_id', $3::text, 'at', now()))
          WHERE id = $1 AND input->>'identity_admitted' IS NULL RETURNING ${COLUMNS}`,
        [row.id, claims.issuer, claims.organizationId],
      );
      return stamped.rows[0] ?? row;
    }
    return row;
  }
  // Without an owned launch or bind, a creator mapping or the principal is required.
  if (admission.actsAs === "none") throw unadmitted(claims, admission);
  // A live binding in another workspace (for example under an earlier policy) is a bound replica, not a creator problem.
  if (row.source !== ENVIRONMENT_IDENTITY || row.workspace_id !== admission.policy.workspace_id) {
    throw new IdentityRefusal("replica_already_bound", 409, scopeOf(admission));
  }
  // The binding acts for exactly one person; a changed policy or mapping never silently moves it.
  if (row.issuer !== claims.issuer || row.provider_organization_id !== claims.organizationId || row.user_id !== admission.userId) {
    throw new IdentityRefusal("replica_creator_not_allowed", 403, scopeOf(admission));
  }
  return row;
}

/** This replica's own released environment-identity binding in the admitted workspace, locked. */
async function retiredPredecessor(tx: SqlExecutor, claims: ReplicaIdentityClaims, admission: Admission, spawnId: unknown): Promise<SpawnRow | null> {
  if (!isUuid(spawnId)) return null;
  const result = await tx.query<SpawnRow>(
    `SELECT ${COLUMNS} FROM replica_spawns WHERE id = $1 AND workspace_id = $2 AND lower(replica_id) = $3
        AND source = '${ENVIRONMENT_IDENTITY}' AND state = 'gone' FOR UPDATE`,
    [spawnId, admission.policy.workspace_id, claims.workspaceId],
  );
  return result.rows[0] ?? null;
}

/**
 * Refusals are audited with their reason code only (no subject, jti or
 * email), and only when the tenant is known: a token of a foreign
 * organization must not be able to fill the audit log.
 */
async function auditRefusal(deps: ReplicasDeps, refusal: IdentityRefusal): Promise<void> {
  const scope = refusal.scope;
  if (!scope) return;
  await deps.database.transaction((tx) => recordAudit(tx, {
    organizationId: scope.organizationId,
    workspaceId: scope.workspaceId,
    actor: { kind: "service", subject: "replicas-identity" },
    action: "replicas.identity.refused",
    target: refusal.code,
  })).catch(() => undefined);
}

const MAX_CREATOR_REQUESTS = 50;

/**
 * Records an unmapped creator on an enabled policy so an admin can learn which
 * creator_id to map. Masked email hint only; bounded per policy. Best effort.
 */
async function recordCreatorRequest(deps: ReplicasDeps, policyId: string, claims: ReplicaIdentityClaims): Promise<void> {
  if (claims.creatorId === null) return;
  await deps.database.transaction(async (tx) => {
    await tx.query(
      `INSERT INTO replica_environment_creator_requests (policy_id, creator_id, creator_email_hint) VALUES ($1, $2, $3)
       ON CONFLICT (policy_id, creator_id) DO UPDATE
         SET creator_email_hint = COALESCE(EXCLUDED.creator_email_hint, replica_environment_creator_requests.creator_email_hint),
             count = LEAST(replica_environment_creator_requests.count, 2147483646) + 1, last_seen_at = now()`,
      [policyId, claims.creatorId, emailHint(claims.creatorEmail)],
    );
    await tx.query(
      `DELETE FROM replica_environment_creator_requests WHERE policy_id = $1 AND creator_id NOT IN (
         SELECT creator_id FROM replica_environment_creator_requests WHERE policy_id = $1
          ORDER BY last_seen_at DESC, creator_id LIMIT ${MAX_CREATOR_REQUESTS})`,
      [policyId],
    );
  }).catch(() => undefined);
}

async function audited<T>(deps: ReplicasDeps, claims: ReplicaIdentityClaims, work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    if (error instanceof IdentityRefusal) {
      await auditRefusal(deps, error);
      if (error.policyId) await recordCreatorRequest(deps, error.policyId, claims);
    }
    throw error;
  }
}

/** Runs the read-only checks to find the tenant workspace, then re-runs them under its lock. */
async function underAdmission<T>(deps: ReplicasDeps, claims: ReplicaIdentityClaims,
  work: (tx: SqlExecutor, admission: Admission) => Promise<T>): Promise<T> {
  return audited(deps, claims, async () => {
    const first = await deps.database.transaction((tx) => admissionChecks(tx, claims));
    // An unmapped creator admitted as the principal still shows up for mapping.
    if (first.actsAs === "principal" && claims.creatorId !== null) await recordCreatorRequest(deps, first.policy.id, claims);
    return withReplicasLock(deps, scopeOf(first), async (tx) => {
      const admission = await admissionChecks(tx, claims);
      if (admission.policy.workspace_id !== first.policy.workspace_id) throw new IdentityRefusal("replica_environment_not_enabled", 403);
      return work(tx, admission);
    });
  });
}

/**
 * Admits a verified identity and returns its bound binding, enrolling it on
 * first use. Nothing is written until every check passed. Enrolment commits
 * the binding row (with its deterministic agent name) before the Relay
 * registration, so a lost registration is recovered, never duplicated.
 * A live launch or bind of the same replica in the admitted workspace is
 * returned as is, acting as its owner.
 */
export async function admitIdentity(deps: ReplicasDeps, claims: ReplicaIdentityClaims): Promise<SpawnRow> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const result = await underAdmission(deps, claims, (tx, admission) => enrolStep(deps, tx, claims, admission));
    if (result.state === "bound") return result;
  }
  throw new ReplicasError("Replicas enrolment could not finish. Retry the call.", 503);
}

async function enrolStep(deps: ReplicasDeps, tx: SqlExecutor, claims: ReplicaIdentityClaims, admission: Admission): Promise<SpawnRow> {
  let row = await liveBinding(tx, claims, admission);
  // A reused launch or bind is never enrolled: its own lifecycle binds it (admitIdentity 503s until then).
  if (row && row.source !== ENVIRONMENT_IDENTITY) return row;
  // An environment-identity binding always acts for a mapped creator or the principal.
  const userId = admission.userId;
  const actsAs = admission.actsAs;
  if (userId === null || actsAs === "none") throw unadmitted(claims, admission);
  const hint = emailHint(claims.creatorEmail);
  if (hint) {
    await tx.query("UPDATE replica_environment_creators SET creator_email_hint = $3 WHERE policy_id = $1 AND creator_id = $2 AND creator_email_hint IS DISTINCT FROM $3",
      [admission.policy.id, claims.creatorId, hint]);
  }
  if (row?.state === "bound" && row.token_ciphertext) return row;
  const relay = await relayFor(deps, tx, { workspaceId: admission.policy.workspace_id, userId }, row?.relay_workspace_id);
  const name = identityAgentName(claims.workspaceId);
  const ownId = row?.id;
  // A replica already bridged by another binding (a PR A spawn or bind) is never enrolled twice.
  const bridged = (await deps.relaycast.listAgents(relay.key, "all")).filter((agent) =>
    String(agent.metadata.replica_id ?? "").toLowerCase() === claims.workspaceId && agent.metadata.replicas_spawn_id !== ownId);
  const predecessors: SpawnRow[] = [];
  for (const agent of bridged) {
    const predecessor = await retiredPredecessor(tx, claims, admission, agent.metadata.replicas_spawn_id);
    if (!predecessor) throw new IdentityRefusal("replica_already_bound", 409, scopeOf(admission));
    predecessors.push(predecessor);
  }
  // This replica's own released binding whose Relay cleanup failed after commit
  // (disable, principal or mapping change): nothing else retries it, so it is retried here.
  for (const predecessor of predecessors) {
    try {
      await retireRemote(deps, tx, predecessor, null);
    } catch {
      throw new ReplicasError("Replicas enrolment could not finish. Retry the call.", 503);
    }
  }
  if (!row) {
    const id = randomUUID();
    const input: SpawnInput = { environment_id: claims.environmentId, name, task: "", coding_agent: "replicas",
      origin: ENVIRONMENT_IDENTITY, acts_as: actsAs, creator_id: claims.creatorId };
    const inserted = await tx.query<SpawnRow>(
      `INSERT INTO replica_spawns (id, workspace_id, organization_id, user_id, client_request_id, source, input, replica_id, state,
         relay_workspace_id, agent_name, environment_id, provider_organization_id, issuer)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, 'binding', $9, $10, $11, $12, $13) RETURNING ${COLUMNS}`,
      [id, admission.policy.workspace_id, admission.organizationId, userId, `environment-identity:${id}`, ENVIRONMENT_IDENTITY,
        JSON.stringify(input), claims.workspaceId, relay.relaycastWorkspaceId, name, claims.environmentId, claims.organizationId, claims.issuer],
    );
    // Committed before registration: the name is the cleanup locator.
    return inserted.rows[0]!;
  }
  const remote = await deps.relaycast.getAgent(relay.key, name);
  if (remote && (remote.metadata.source !== HOSTED_SOURCE || remote.metadata.replicas_spawn_id !== row.id
    || remote.metadata.cloud_workspace_id !== row.workspace_id || remote.metadata.owner_hash !== ownerHash(row.user_id))) {
    throw new IdentityRefusal("replica_already_bound", 409, scopeOf(admission));
  }
  let registered;
  try {
    registered = remote
      ? await deps.relaycast.recoverHosted(relay.key, name, remote.id, `replicas-binding:${row.id}`)
      : await deps.relaycast.registerHosted(relay.key, name, {
        source: HOSTED_SOURCE, created_by: "replicas-binding", session_kind: "replicas", host: "Replicas",
        cloud_workspace_id: row.workspace_id, owner_hash: ownerHash(row.user_id), replicas_spawn_id: row.id,
        replica_id: claims.workspaceId, replicas_environment_id: claims.environmentId,
        objective: `Replicas workspace ${claims.workspaceId}`,
      });
  } catch {
    // Rolls back nothing that matters: the committed row keeps the name, so the next call recovers it.
    throw new ReplicasError("Replicas enrolment could not finish. Retry the call.", 503);
  }
  row = await patch(tx, row.id, { agent_name: registered.name, agent_remote_id: registered.id, relay_workspace_id: relay.relaycastWorkspaceId,
    token_ciphertext: encrypt(deps, registered.token), state: "bound", last_error: null,
    input: { ...row.input, relay_mcp_version: 1 } });
  await tx.query(
    `INSERT INTO hosted_relay_participants
       (id, workspace_id, user_id, relaycast_workspace_id, session_hash, agent_name, agent_remote_id, token_ciphertext)
     VALUES ($1, $2, $3, $4, NULL, $5, $6, $7)
     ON CONFLICT (workspace_id, user_id, agent_name) DO UPDATE
       SET relaycast_workspace_id = EXCLUDED.relaycast_workspace_id, agent_remote_id = EXCLUDED.agent_remote_id,
           token_ciphertext = EXCLUDED.token_ciphertext, updated_at = now()`,
    [randomUUID(), row.workspace_id, row.user_id, row.relay_workspace_id, row.agent_name, row.agent_remote_id, row.token_ciphertext],
  );
  await recordAudit(tx, { organizationId: row.organization_id, workspaceId: row.workspace_id,
    actor: { kind: "service", subject: "replicas-identity" }, action: "replicas.identity.enrolled", target: row.id });
  return row;
}

/**
 * Runs one tool call for an admitted identity: every check (policy, creator
 * mapping, membership, release) is re-read under the revocation lock first.
 */
export async function withIdentityBinding<T>(deps: ReplicasDeps, claims: ReplicaIdentityClaims,
  work: (binding: ResolvedBinding) => Promise<T>): Promise<T> {
  return underAdmission(deps, claims, async (tx, admission) => {
    const row = await liveBinding(tx, claims, admission);
    if (!row || row.state !== "bound" || !row.token_ciphertext) throw new ReplicasError("Replicas enrolment could not finish. Retry the call.", 503);
    const relay = await relayFor(deps, tx, { workspaceId: row.workspace_id, userId: row.user_id }, row.relay_workspace_id);
    return work({ row, relay, token: decrypt(deps, row.token_ciphertext) });
  });
}

/* ------------------------------------------------------------------ */
/* Admin: discovery, policies and the provider MCP entry               */
/* ------------------------------------------------------------------ */

async function connectedOrganization(tx: SqlExecutor, workspaceId: string): Promise<string> {
  const result = await tx.query<{ provider_account: string | null }>(
    "SELECT provider_account FROM remote_agent_connections WHERE workspace_id = $1 AND provider = 'replicas'",
    [workspaceId],
  );
  const account = result.rows[0]?.provider_account;
  if (!account) {
    throw new ReplicasError("Replicas is not connected. An owner or admin connects it in Settings → Connections → Replicas.", 409);
  }
  return account.toLowerCase();
}

async function allEnvironmentsFlag(tx: SqlExecutor, workspaceId: string): Promise<boolean> {
  const result = await tx.query<{ all_environments: boolean }>(
    "SELECT all_environments FROM replica_environment_settings WHERE workspace_id = $1", [workspaceId]);
  // No row = the default: every environment of the connected organization.
  return result.rows[0]?.all_environments ?? true;
}

async function setAllEnvironments(tx: SqlExecutor, workspaceId: string, value: boolean): Promise<void> {
  await tx.query(
    `INSERT INTO replica_environment_settings (workspace_id, all_environments) VALUES ($1, $2)
     ON CONFLICT (workspace_id) DO UPDATE SET all_environments = EXCLUDED.all_environments, updated_at = now()`,
    [workspaceId, value],
  );
}

/**
 * Sets (or clears) the workspace VM principal: the current member a replica
 * acts as when its creator is missing or unmapped. A change releases every
 * live binding acting as the principal (state gone, no tombstone): they enrol
 * again under the new principal, or are refused when it is cleared. The
 * released ids are pushed to `released` for retirement after commit.
 */
async function setPrincipal(tx: SqlExecutor, actor: ReplicasActor, userId: string | null, released: string[]): Promise<void> {
  const next = userId?.toLowerCase() ?? null;
  if (next) {
    const member = await tx.query("SELECT 1 FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
      [actor.organizationId, next]);
    if (!member.rows.length) throw new ReplicasError("The principal must be a current member of this organization.");
  }
  const before = (await tx.query<{ principal_user_id: string | null }>(
    "SELECT principal_user_id FROM replica_environment_settings WHERE workspace_id = $1 FOR UPDATE", [actor.workspaceId])).rows[0];
  await tx.query(
    `INSERT INTO replica_environment_settings (workspace_id, principal_user_id) VALUES ($1, $2)
     ON CONFLICT (workspace_id) DO UPDATE SET principal_user_id = EXCLUDED.principal_user_id, updated_at = now()`,
    [actor.workspaceId, next],
  );
  if ((before?.principal_user_id ?? null) !== next || next === null) {
    const revoked = await tx.query<{ id: string }>(
      `UPDATE replica_spawns SET state = 'gone', helper_hash = NULL, updated_at = now()
        WHERE source = '${ENVIRONMENT_IDENTITY}' AND workspace_id = $1 AND state <> 'gone' AND input->>'acts_as' = 'principal'
        RETURNING id`,
      [actor.workspaceId],
    );
    released.push(...revoked.rows.map((row) => row.id));
  }
  await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
    actor: auditActor(actor), action: "replicas.environment.principal_updated", target: actor.workspaceId });
}

const principalInput = z.object({ userId: z.string().uuid().nullable() }).strict();

/** PUT …/replicas/environment-principal {userId: uuid | null}: owner/admin only; returns the policy view. */
export async function setEnvironmentPrincipal(deps: ReplicasDeps, actor: ReplicasActor, raw: unknown) {
  identityConfig(deps);
  const parsed = principalInput.safeParse(raw);
  if (!parsed.success) throw new ReplicasError("Send {userId: <member user id> | null}.");
  const released: string[] = [];
  await withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    await setPrincipal(tx, actor, parsed.data.userId, released);
  });
  await retireIdentityBindings(deps, actor, released);
  return listEnvironmentPolicies(deps, actor);
}

/** An enabled policy without an entry whose last create has an unknown outcome is registration_unconfirmed. */
const policyStatus = (policy: PolicyRow) => !policy.enabled ? "disabled"
  : policy.discovery_missing_since ? "discovery_missing" : policy.registered_mcp_id ? "registered"
  : policy.create_unconfirmed ? "registration_unconfirmed" : "enabled";

export type DiscoveryResult = {
  status: "ok" | "partial" | "failed";
  environments: Array<{ environmentId: string; name: string; status: "discovered" | "known" }>;
};

/**
 * Discovers the connected organization's environments and records each as a
 * policy (new ones disabled). Discovery never enables anything.
 */
export async function discoverEnvironments(deps: ReplicasDeps, actor: ReplicasActor): Promise<DiscoveryResult> {
  const { issuer } = identityConfig(deps);
  const key = await withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    await connectedOrganization(tx, actor.workspaceId);
    return keyFor(deps, tx, actor.workspaceId);
  });
  let listed: Awaited<ReturnType<ReplicasDeps["replicas"]["allEnvironments"]>>;
  try {
    listed = await deps.replicas.allEnvironments(key);
  } catch (error) {
    await recordProviderAccess(deps.database, actor.workspaceId, error);
    return { status: "failed", environments: [] };
  }
  await recordProviderAccess(deps.database, actor.workspaceId, "granted");
  return withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    const organization = await connectedOrganization(tx, actor.workspaceId);
    const environments: DiscoveryResult["environments"] = [];
    for (const environment of listed.environments) {
      const environmentId = environment.id.toLowerCase();
      const name = environment.name.slice(0, 256);
      const existing = await tx.query<{ id: string }>(
        "SELECT id FROM replica_environment_policies WHERE workspace_id = $1 AND environment_id = $2 FOR UPDATE",
        [actor.workspaceId, environmentId],
      );
      if (existing.rows[0]) {
        // Listed again: the discovery fence (if any) is lifted.
        await tx.query(
          "UPDATE replica_environment_policies SET environment_name = $2, discovery_missing_since = NULL, updated_at = now() WHERE id = $1",
          [existing.rows[0].id, name]);
        environments.push({ environmentId, name, status: "known" });
        continue;
      }
      await tx.query(
        `INSERT INTO replica_environment_policies (id, workspace_id, issuer, provider_organization_id, environment_id, environment_name)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [randomUUID(), actor.workspaceId, issuer, organization, environmentId, name],
      );
      environments.push({ environmentId, name, status: "discovered" });
    }
    // Only a complete listing proves absence: fence each enabled policy it
    // no longer shows (first timestamp kept). opted_out is never touched.
    if (listed.complete) {
      await tx.query(
        `UPDATE replica_environment_policies SET discovery_missing_since = now(), updated_at = now()
          WHERE workspace_id = $1 AND enabled AND discovery_missing_since IS NULL AND NOT (environment_id = ANY($2::text[]))`,
        [actor.workspaceId, environments.map((item) => item.environmentId)]);
    }
    return { status: listed.complete ? "ok" : "partial", environments };
  });
}

/** Dashboard view: every policy with its status, creator mappings and pending creators (masked email hints only). */
export async function listEnvironmentPolicies(deps: ReplicasDeps, actor: ReplicasActor) {
  const { mcpUrl } = identityConfig(deps);
  return withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    const connection = (await tx.query<{ provider_account: string | null; access_revoked_at: Date | string | null; access_error: string | null }>(
      "SELECT provider_account, access_revoked_at, access_error FROM remote_agent_connections WHERE workspace_id = $1 AND provider = 'replicas'",
      [actor.workspaceId])).rows[0];
    const policies = (await tx.query<PolicyRow>(
      `SELECT ${POLICY} FROM replica_environment_policies WHERE workspace_id = $1 ORDER BY environment_name, environment_id`,
      [actor.workspaceId])).rows;
    const creators = (await tx.query<{ policy_id: string; creator_id: string; user_id: string; creator_email_hint: string | null }>(
      `SELECT c.policy_id, c.creator_id, c.user_id, c.creator_email_hint FROM replica_environment_creators c
         JOIN replica_environment_policies p ON p.id = c.policy_id
        WHERE p.workspace_id = $1 ORDER BY c.created_at, c.creator_id`,
      [actor.workspaceId])).rows;
    const requests = (await tx.query<{ policy_id: string; creator_id: string; creator_email_hint: string | null; last_seen_at: Date | string; count: number }>(
      `SELECT r.policy_id, r.creator_id, r.creator_email_hint, r.last_seen_at, r.count FROM replica_environment_creator_requests r
         JOIN replica_environment_policies p ON p.id = r.policy_id
        WHERE p.workspace_id = $1 ORDER BY r.last_seen_at DESC, r.creator_id`,
      [actor.workspaceId])).rows;
    const principal = (await tx.query<{ principal_user_id: string | null; member: string | null }>(
      `SELECT s.principal_user_id, m.user_id AS member FROM replica_environment_settings s
         LEFT JOIN organization_memberships m ON m.user_id = s.principal_user_id AND m.organization_id = $2
        WHERE s.workspace_id = $1`,
      [actor.workspaceId, actor.organizationId])).rows[0];
    const bindings = (await tx.query<{ environment_id: string; count: number }>(
      `SELECT environment_id, count(*)::int AS count FROM replica_spawns
        WHERE workspace_id = $1 AND source = '${ENVIRONMENT_IDENTITY}' AND state <> 'gone' GROUP BY environment_id`,
      [actor.workspaceId])).rows;
    return {
      mcpUrl,
      organizationId: connection?.provider_account ?? null,
      // The provider refused the stored key (401/403): nothing is admitted until a 2xx environments list or a re-connect.
      accessRevoked: connection?.access_revoked_at
        ? { since: new Date(connection.access_revoked_at).toISOString(), error: connection.access_error } : null,
      allEnvironments: await allEnvironmentsFlag(tx, actor.workspaceId),
      // The VM principal; member false means it left the organization and admits nobody.
      principal: principal?.principal_user_id ? { userId: principal.principal_user_id, member: Boolean(principal.member) } : null,
      // True when this provider organization is connected in another workspace too: nothing is admitted or enabled.
      organizationShared: await organizationShared(tx, connection?.provider_account ?? null),
      environments: policies.map((policy) => ({
        environmentId: policy.environment_id,
        name: policy.environment_name,
        enabled: policy.enabled,
        status: policy.enabled && connection?.access_revoked_at ? "access_revoked" : policyStatus(policy),
        // When a complete discovery listing stopped showing this enabled environment (admission refused until listed again).
        discoveryMissingSince: policy.discovery_missing_since ? new Date(policy.discovery_missing_since).toISOString() : null,
        // An admin opt-out: sync and re-connect leave it disabled; a disabled policy without it is retried.
        optedOut: policy.opted_out,
        // A policy recorded for an earlier connection never admits a token.
        stale: Boolean(connection?.provider_account) && policy.provider_organization_id !== connection!.provider_account!.toLowerCase(),
        registeredMcpId: policy.registered_mcp_id,
        bindings: bindings.find((item) => item.environment_id === policy.environment_id)?.count ?? 0,
        creators: creators.filter((item) => item.policy_id === policy.id)
          .map((item) => ({ creatorId: item.creator_id, userId: item.user_id, emailHint: item.creator_email_hint })),
        // Creators seen without a mapping (admitted as the principal when one is set, refused otherwise), most recent first.
        pendingCreators: requests.filter((item) => item.policy_id === policy.id).map((item) => ({
          creatorId: item.creator_id, emailHint: item.creator_email_hint,
          lastSeenAt: new Date(item.last_seen_at).toISOString(), count: item.count,
        })),
      })),
    };
  });
}

async function policyFor(tx: SqlExecutor, workspaceId: string, environmentId: string): Promise<PolicyRow | null> {
  const result = await tx.query<PolicyRow>(
    `SELECT ${POLICY} FROM replica_environment_policies WHERE workspace_id = $1 AND environment_id = $2 FOR UPDATE`,
    [workspaceId, environmentId.toLowerCase()],
  );
  return result.rows[0] ?? null;
}

class OrganizationShared extends ReplicasError {
  constructor() {
    super("This Replicas organization is connected in another workspace.", 409);
  }
}

class EnabledElsewhere extends ReplicasError {
  constructor() {
    super("This Replicas environment is enabled in another workspace.", 409);
  }
}

/** An admin enable withdraws the opt-out, whether or not the enable itself succeeds. */
async function clearOptOut(tx: SqlExecutor, workspaceId: string, policies: PolicyRow[] | "all"): Promise<void> {
  if (policies === "all") {
    await tx.query("UPDATE replica_environment_policies SET opted_out = false, updated_at = now() WHERE workspace_id = $1 AND opted_out", [workspaceId]);
  } else if (policies.length) {
    await tx.query("UPDATE replica_environment_policies SET opted_out = false, updated_at = now() WHERE id = ANY($1::uuid[]) AND opted_out",
      [policies.map((policy) => policy.id)]);
  }
}

/** Enables admission for one policy. One workspace per provider environment. */
async function enablePolicy(tx: SqlExecutor, actor: ReplicasActor, policy: PolicyRow, organization: string): Promise<PolicyRow> {
  if (await organizationShared(tx, organization)) throw new OrganizationShared();
  if (policy.enabled) return policy;
  if (policy.provider_organization_id !== organization) {
    throw new ReplicasError("This environment belongs to an earlier Replicas connection. Sync environments first.", 409);
  }
  const elsewhere = await tx.query(
    `SELECT 1 FROM replica_environment_policies
      WHERE enabled AND issuer = $1 AND provider_organization_id = $2 AND environment_id = $3 AND workspace_id <> $4`,
    [policy.issuer, policy.provider_organization_id, policy.environment_id, actor.workspaceId],
  );
  if (elsewhere.rows.length) throw new EnabledElsewhere();
  // Another workspace can enable the same environment after the check above
  // (the locks are per workspace). The partial unique index decides; the
  // savepoint keeps the surrounding transaction usable for the other policies.
  let result;
  await tx.query("SAVEPOINT replicas_enable_policy");
  try {
    result = await tx.query<PolicyRow>(
      `UPDATE replica_environment_policies SET enabled = true, updated_at = now() WHERE id = $1 RETURNING ${POLICY}`, [policy.id]);
    await tx.query("RELEASE SAVEPOINT replicas_enable_policy");
  } catch (error) {
    await tx.query("ROLLBACK TO SAVEPOINT replicas_enable_policy");
    if ((error as { code?: string }).code === "23505") throw new EnabledElsewhere();
    throw error;
  }
  await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
    actor: auditActor(actor), action: "replicas.environment.enabled", target: policy.id });
  return result.rows[0]!;
}

/**
 * Disables admission for one policy and revokes (state gone) this
 * environment's environment-identity bindings in the workspace, without a
 * tombstone: they enrol again once the environment is enabled. The revoked
 * ids are pushed to `released`; the caller retires their Relay identities
 * after this transaction commits. optOut records an admin opt-out, which
 * sync and re-connect respect; turning the default off or disconnecting is not one.
 */
async function disablePolicy(tx: SqlExecutor, actor: ReplicasActor, policy: PolicyRow, released: string[],
  optOut = false): Promise<PolicyRow> {
  if (optOut && !policy.opted_out) {
    policy = (await tx.query<PolicyRow>(
      `UPDATE replica_environment_policies SET opted_out = true, updated_at = now() WHERE id = $1 RETURNING ${POLICY}`, [policy.id])).rows[0]!;
  }
  const revoked = await tx.query<{ id: string }>(
    `UPDATE replica_spawns SET state = 'gone', helper_hash = NULL, updated_at = now()
      WHERE source = '${ENVIRONMENT_IDENTITY}' AND environment_id = $1 AND workspace_id = $2 AND state <> 'gone' RETURNING id`,
    [policy.environment_id, actor.workspaceId],
  );
  released.push(...revoked.rows.map((row) => row.id));
  if (!policy.enabled) return policy;
  const result = await tx.query<PolicyRow>(
    `UPDATE replica_environment_policies SET enabled = false, updated_at = now() WHERE id = $1 RETURNING ${POLICY}`, [policy.id]);
  await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
    actor: auditActor(actor), action: "replicas.environment.disabled", target: policy.id });
  return result.rows[0]!;
}

const putInput = z.object({
  enabled: z.boolean().optional(),
  creators: z.array(z.object({ creatorId: z.string().min(1).max(256), userId: z.string().uuid() }).strict()).max(100).optional(),
  retry_registration: z.literal(true).optional(),
}).strict();

/**
 * Sets an environment's admission switch and/or replaces its creator
 * mappings. retry_registration (owner/admin, enabled environment only)
 * retries an unresolved write: after the enable it registers the
 * environment's provider MCP entry with recover set, so a create whose
 * outcome is unknown is sent again. A complete listing with no entry is the
 * precondition for re-sending, not proof that the earlier create failed: the
 * flag is an operator decision that accepts a possible duplicate entry the
 * provider may surface later. No sync does that.
 */
export async function updateEnvironmentPolicy(deps: ReplicasDeps, actor: ReplicasActor, environmentId: string, raw: unknown) {
  const parsed = putInput.safeParse(raw);
  if (!parsed.success) throw new ReplicasError("Send enabled and/or creators [{creatorId, userId}], optionally retry_registration: true.");
  const { enabled, creators, retry_registration: retry } = parsed.data;
  if (creators && new Set(creators.map((item) => item.creatorId)).size !== creators.length) {
    throw new ReplicasError("Each creator is mapped once.");
  }
  const released: string[] = [];
  await withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    let policy = await policyFor(tx, actor.workspaceId, environmentId);
    if (!policy) throw new ReplicasError("Unknown environment. Sync environments first.", 404);
    if (retry && (enabled === false || (enabled !== true && !policy.enabled))) {
      throw new ReplicasError("retry_registration needs an enabled environment.");
    }
    if (creators) {
      for (const { userId } of creators) {
        const member = await tx.query("SELECT 1 FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
          [actor.organizationId, userId.toLowerCase()]);
        if (!member.rows.length) throw new ReplicasError("Every creator must map to a current member of this workspace.");
      }
      await tx.query("DELETE FROM replica_environment_creators WHERE policy_id = $1 AND NOT (creator_id = ANY($2::text[]))",
        [policy.id, creators.map((item) => item.creatorId)]);
      for (const { creatorId, userId } of creators) {
        await tx.query(
          `INSERT INTO replica_environment_creators (policy_id, creator_id, user_id) VALUES ($1, $2, $3)
           ON CONFLICT (policy_id, creator_id) DO UPDATE SET user_id = EXCLUDED.user_id`,
          [policy.id, creatorId, userId.toLowerCase()],
        );
      }
      // A binding acting as a creator whose mapping was removed is released
      // (no tombstone): it enrols again as the principal when one is set and
      // is refused otherwise; its Relay agent is retired after commit.
      const unmapped = await tx.query<{ id: string }>(
        `UPDATE replica_spawns SET state = 'gone', helper_hash = NULL, updated_at = now()
          WHERE source = '${ENVIRONMENT_IDENTITY}' AND workspace_id = $1 AND environment_id = $2 AND state <> 'gone'
            AND input->>'acts_as' = 'creator' AND NOT (COALESCE(input->>'creator_id', '') = ANY($3::text[]))
          RETURNING id`,
        [actor.workspaceId, policy.environment_id, creators.map((item) => item.creatorId)],
      );
      released.push(...unmapped.rows.map((row) => row.id));
      // A binding of a newly mapped creator that acts as the principal or as
      // another member is released (no tombstone) and enrols again as the
      // mapped member.
      for (const { creatorId, userId } of creators) {
        const revoked = await tx.query<{ id: string }>(
          `UPDATE replica_spawns SET state = 'gone', helper_hash = NULL, updated_at = now()
            WHERE source = '${ENVIRONMENT_IDENTITY}' AND workspace_id = $1 AND environment_id = $2 AND state <> 'gone'
              AND input->>'creator_id' = $3 AND (input->>'acts_as' = 'principal' OR user_id <> $4)
            RETURNING id`,
          [actor.workspaceId, policy.environment_id, creatorId, userId.toLowerCase()],
        );
        released.push(...revoked.rows.map((row) => row.id));
      }
      // A mapped creator is no longer pending.
      await tx.query("DELETE FROM replica_environment_creator_requests WHERE policy_id = $1 AND creator_id = ANY($2::text[])",
        [policy.id, creators.map((item) => item.creatorId)]);
      await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
        actor: auditActor(actor), action: "replicas.environment.creators_updated", target: policy.id });
    }
    if (enabled === true) {
      await clearOptOut(tx, actor.workspaceId, [policy]);
      policy = await enablePolicy(tx, actor, policy, await connectedOrganization(tx, actor.workspaceId));
    }
    if (enabled === false) policy = await disablePolicy(tx, actor, policy, released, true);
  });
  await retireIdentityBindings(deps, actor, released);
  if (retry) {
    const { mcpUrl } = identityConfig(deps);
    await registerPolicy(deps, actor, environmentId.toLowerCase(),
      { url: mcpUrl, headers: {}, auth: { type: "workspace_identity", audience: mcpUrl } }, true);
  }
  const view = await listEnvironmentPolicies(deps, actor);
  return { environment: view.environments.find((item) => item.environmentId === environmentId.toLowerCase()) ?? null };
}

const selectionInput = z.union([
  z.object({ all: z.literal(true) }).strict(),
  z.object({ environmentIds: z.array(z.string().uuid()).min(1).max(100) }).strict(),
]);
type Selection = z.infer<typeof selectionInput>;
/** The enable body: a selection plus an optional VM principal, set in the same transaction before enabling. */
const enableInput = z.union([
  z.object({ all: z.literal(true), principalUserId: z.string().uuid().optional() }).strict(),
  z.object({ environmentIds: z.array(z.string().uuid()).min(1).max(100), principalUserId: z.string().uuid().optional() }).strict(),
]);
type EnableSelection = z.infer<typeof enableInput>;

export type EnvironmentMcpResult = {
  environmentId: string;
  status: "registered" | "registration_failed" | "registration_unconfirmed" | "not_found" | "enabled_elsewhere"
    | "organization_shared" | "stale_connection" | "access_revoked" | "disabled" | "removal_failed";
  retryable?: boolean;
};

function parseSelection(raw: unknown): Selection {
  const parsed = selectionInput.safeParse(raw);
  if (!parsed.success) throw new ReplicasError("Send {environmentIds: [...]} or {all: true}.");
  return parsed.data;
}

/**
 * Enables the selected environments and registers the environment-level MCP
 * in each one's provider configuration; an explicit enable clears the
 * opt-out. `{all: true}` turns the all-environments default back on, clears
 * every opt-out and re-enables every environment; environments discovered
 * later are enabled on sync. Registration reads the environment's entries
 * first and reuses a matching one; a second entry with the same name, or one
 * with another transport or config, is never overwritten (registration_failed,
 * not retryable). After a create (or a conflict or lost answer) the entry is
 * read back; an entry that cannot be confirmed is registration_unconfirmed
 * and a retry reconciles it.
 */
export async function enableEnvironmentMcp(deps: ReplicasDeps, actor: ReplicasActor, raw: unknown) {
  const parsed = enableInput.safeParse(raw);
  if (!parsed.success) throw new ReplicasError("Send {environmentIds: [...]} or {all: true}, optionally with principalUserId.");
  const selection = parsed.data;
  let discovery: DiscoveryResult | undefined;
  if ("all" in selection) discovery = await discoverEnvironments(deps, actor);
  const results = await enableSelected(deps, actor, selection);
  return { ...(discovery ? { discovery } : {}), environments: results };
}

type EntryMatch = { kind: "none" } | { kind: "conflict" } | { kind: "match"; id: string };

function sameValue(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length && left.every((item, index) => sameValue(item, right[index]));
  }
  if (!left || !right || typeof left !== "object" || typeof right !== "object") return false;
  const leftKeys = Object.keys(left);
  const rightRecord = right as Record<string, unknown>;
  return leftKeys.length === Object.keys(right).length
    && leftKeys.every((key) => Object.hasOwn(rightRecord, key) && sameValue((left as Record<string, unknown>)[key], rightRecord[key]));
}

/** Finds this edition's entry among an environment's MCP entries; anything ambiguous or different is a conflict. */
function matchEntry(entries: EnvironmentMcp[], policy: PolicyRow, config: unknown): EntryMatch {
  const named = entries.filter((entry) => entry.name === IDENTITY_SERVER_NAME);
  if (!named.length) return { kind: "none" };
  const entry = named[0]!;
  if (named.length > 1 || entry.transport !== "http" || !sameValue(entry.config, config)
    || (entry.environment_id !== undefined && entry.environment_id.toLowerCase() !== policy.environment_id)
    || (entry.organization_id !== undefined && entry.organization_id.toLowerCase() !== policy.provider_organization_id)) {
    return { kind: "conflict" };
  }
  return { kind: "match", id: entry.id };
}

/**
 * The default selections of the connected organization's policies. setup
 * (connect): every one that is not enabled and registered. sync (under the
 * all-environments flag only): every disabled one that is not opted out (new,
 * or a default enable that failed or was refused earlier) plus enabled ones
 * whose registration is missing; an opted-out policy is never re-enabled here,
 * and a policy fenced by discovery (discovery_missing_since) is skipped.
 */
type DefaultSelection = { defaults: "setup" | "sync" };
const DEFAULTS = {
  setup: "NOT (enabled AND registered_mcp_id IS NOT NULL)",
  sync: "discovery_missing_since IS NULL AND ((NOT enabled AND NOT opted_out) OR (enabled AND registered_mcp_id IS NULL))",
};

async function defaultPolicies(tx: SqlExecutor, workspaceId: string, organization: string, defaults: DefaultSelection["defaults"]) {
  return (await tx.query<PolicyRow>(
    `SELECT ${POLICY} FROM replica_environment_policies WHERE workspace_id = $1 AND provider_organization_id = $2 AND (${DEFAULTS[defaults]})
      ORDER BY environment_id FOR UPDATE`, [workspaceId, organization])).rows;
}

/** Enables a selection and registers each enabled policy; never replays an unconfirmed create (registerPolicy). */
async function enableSelected(deps: ReplicasDeps, actor: ReplicasActor,
  selection: Selection | EnableSelection | DefaultSelection): Promise<EnvironmentMcpResult[]> {
  const { mcpUrl } = identityConfig(deps);
  const results: EnvironmentMcpResult[] = [];
  const released: string[] = [];
  const toRegister = await withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    const organization = await connectedOrganization(tx, actor.workspaceId);
    await keyFor(deps, tx, actor.workspaceId);
    if ("principalUserId" in selection && selection.principalUserId !== undefined) {
      await setPrincipal(tx, actor, selection.principalUserId, released);
    }
    let policies: PolicyRow[];
    if ("defaults" in selection) {
      policies = selection.defaults === "sync" && !await allEnvironmentsFlag(tx, actor.workspaceId)
        ? [] : await defaultPolicies(tx, actor.workspaceId, organization, selection.defaults);
    } else if ("all" in selection) {
      await setAllEnvironments(tx, actor.workspaceId, true);
      await clearOptOut(tx, actor.workspaceId, "all");
      await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
        actor: auditActor(actor), action: "replicas.environment.all_enabled", target: actor.workspaceId });
      policies = (await tx.query<PolicyRow>(
        `SELECT ${POLICY} FROM replica_environment_policies WHERE workspace_id = $1 AND provider_organization_id = $2
          ORDER BY environment_id FOR UPDATE`, [actor.workspaceId, organization])).rows;
    } else {
      policies = [];
      for (const environmentId of new Set(selection.environmentIds.map((id) => id.toLowerCase()))) {
        const policy = await policyFor(tx, actor.workspaceId, environmentId);
        if (policy) policies.push(policy);
        else results.push({ environmentId, status: "not_found" });
      }
      await clearOptOut(tx, actor.workspaceId, policies);
    }
    const enabled: PolicyRow[] = [];
    for (const policy of policies) {
      try {
        enabled.push(await enablePolicy(tx, actor, policy, organization));
      } catch (error) {
        if (error instanceof OrganizationShared) results.push({ environmentId: policy.environment_id, status: "organization_shared", retryable: false });
        else if (error instanceof EnabledElsewhere) results.push({ environmentId: policy.environment_id, status: "enabled_elsewhere" });
        else if (error instanceof ReplicasError) results.push({ environmentId: policy.environment_id, status: "stale_connection" });
        else throw error;
      }
    }
    return enabled;
  });
  await retireIdentityBindings(deps, actor, released);
  const config = { url: mcpUrl, headers: {}, auth: { type: "workspace_identity" as const, audience: mcpUrl } };
  for (const policy of toRegister) {
    results.push(await registerPolicy(deps, actor, policy.environment_id, config));
  }
  return results;
}

type IdentityMcpConfig = { url: string; headers: Record<string, never>; auth: { type: "workspace_identity"; audience: string } };
type RegistrationTarget = { current: PolicyRow; key: string };

/** Re-reads one policy under the lock: still enabled, not yet registered, and the key is readable. */
async function registrationTarget(deps: ReplicasDeps, tx: SqlExecutor, actor: ReplicasActor,
  environmentId: string): Promise<EnvironmentMcpResult | RegistrationTarget> {
  await requireAdmin(tx, actor);
  const current = await policyFor(tx, actor.workspaceId, environmentId);
  if (!current || !current.enabled) return { environmentId, status: "disabled" };
  if (current.registered_mcp_id) return { environmentId: current.environment_id, status: "registered" };
  try {
    return { current, key: await keyFor(deps, tx, actor.workspaceId) };
  } catch {
    return { environmentId: current.environment_id, status: "registration_failed", retryable: true };
  }
}

async function setCreateIntent(tx: SqlExecutor, policyId: string, value: boolean): Promise<void> {
  await tx.query("UPDATE replica_environment_policies SET create_unconfirmed = $2, updated_at = now() WHERE id = $1", [policyId, value]);
}

async function markRegistered(tx: SqlExecutor, actor: ReplicasActor, policy: PolicyRow, mcpId: string): Promise<EnvironmentMcpResult> {
  await tx.query(
    "UPDATE replica_environment_policies SET registered_mcp_id = $2, create_unconfirmed = false, updated_at = now() WHERE id = $1",
    [policy.id, mcpId]);
  await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
    actor: auditActor(actor), action: "replicas.environment.mcp_registered", target: policy.id });
  return { environmentId: policy.environment_id, status: "registered" };
}

/**
 * Registers one enabled policy's provider MCP entry in two locked steps.
 * Step 1 lists the environment's entries: a matching entry is recorded as
 * registered (and the create intent cleared); otherwise the create intent
 * (create_unconfirmed) is committed before any create is sent. While the
 * intent is set from an earlier attempt, every run (startup, sweep, the sync
 * and enable routes, a plain enable) is read-only: it only relists and
 * reports registration_unconfirmed. The intent clears only when a complete
 * listing finds the entry or a create sent by this run is definitely
 * rejected. recover (the admin-only retry_registration flag) is the one
 * exception: an operator decision to retry the unresolved write. It creates
 * again only after a complete listing in step 1 and the relisting in step 2
 * both showed no entry; that is the precondition for re-sending, not proof
 * of the earlier outcome, so a duplicate entry may still surface later. Step 2 relists (another
 * run may have created it meanwhile), then creates and reads the entry back.
 * A timeout, 5xx, unreadable answer or a failed listing leaves the intent set.
 */
async function registerPolicy(deps: ReplicasDeps, actor: ReplicasActor, environmentId: string,
  config: IdentityMcpConfig, recover = false): Promise<EnvironmentMcpResult> {
  const failed = (retryable: boolean): EnvironmentMcpResult => ({ environmentId, status: "registration_failed", retryable });
  const unconfirmed: EnvironmentMcpResult = { environmentId, status: "registration_unconfirmed", retryable: true };
  // The provider refused the key itself: retrying with it cannot succeed, a re-connect can.
  const revoked: EnvironmentMcpResult = { environmentId, status: "access_revoked", retryable: false };
  const list = (target: RegistrationTarget) => deps.replicas.listEnvironmentMcps(target.key, target.current.environment_id)
    .then((entries) => matchEntry(entries, target.current, config));
  const intent = await withReplicasLock(deps, actor, async (tx): Promise<EnvironmentMcpResult | { previous: boolean }> => {
    const target = await registrationTarget(deps, tx, actor, environmentId);
    if (!("current" in target)) return target;
    let found: EntryMatch;
    try {
      found = await list(target);
    } catch (error) {
      await recordProviderAccess(tx, actor.workspaceId, error);
      return target.current.create_unconfirmed ? unconfirmed : accessRevoked(error) ? revoked : failed(true);
    }
    if (found.kind === "conflict") return failed(false);
    if (found.kind === "match") return markRegistered(tx, actor, target.current, found.id);
    if (target.current.create_unconfirmed && !recover) return unconfirmed;
    await setCreateIntent(tx, target.current.id, true);
    return { previous: target.current.create_unconfirmed };
  });
  if ("status" in intent) return intent;
  // Once a create was sent, only a definite rejection proves no entry was
  // created; anything else (timeout, 5xx, unreadable answer, our own
  // UPDATE or commit failing) leaves the outcome unknown.
  let asked = false;
  try {
    return await withReplicasLock(deps, actor, async (tx): Promise<EnvironmentMcpResult> => {
      const target = await registrationTarget(deps, tx, actor, environmentId);
      if (!("current" in target)) return target;
      let found: EntryMatch;
      try {
        found = await list(target);
      } catch (error) {
        await recordProviderAccess(tx, actor.workspaceId, error);
        // Nothing was sent in this attempt: restore the intent it found.
        if (!intent.previous) await setCreateIntent(tx, target.current.id, false);
        return intent.previous ? unconfirmed : accessRevoked(error) ? revoked : failed(true);
      }
      if (found.kind === "conflict") return failed(false);
      if (found.kind === "match") return markRegistered(tx, actor, target.current, found.id);
      asked = true;
      if (recover) {
        await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
          actor: auditActor(actor), action: "replicas.environment.registration_retried", target: target.current.id });
      }
      let createdId: string | null = null;
      try {
        createdId = (await deps.replicas.registerEnvironmentMcp(target.key, target.current.environment_id,
          { name: IDENTITY_SERVER_NAME, transport: "http", config })).id;
      } catch (error) {
        // A 409 or a lost answer may still have created the entry: read it back below.
        await recordProviderAccess(tx, actor.workspaceId, error);
        if (rejectedByProvider(error)) {
          asked = false;
          await setCreateIntent(tx, target.current.id, false);
          return accessRevoked(error) ? revoked : failed(true);
        }
      }
      try {
        found = await list(target);
      } catch (error) {
        await recordProviderAccess(tx, actor.workspaceId, error);
        return unconfirmed;
      }
      if (found.kind === "conflict") return failed(false);
      if (found.kind !== "match" || (createdId !== null && found.id !== createdId)) return unconfirmed;
      return markRegistered(tx, actor, target.current, found.id);
    });
  } catch (error) {
    if (!asked) throw error;
    return unconfirmed;
  }
}

/**
 * Disables the selected environments first (admission stops and their
 * bindings are revoked at commit), then removes their provider MCP entries
 * best effort and retires the released Relay identities. A failed removal keeps the
 * entry id so a later disable or disconnect retries it.
 */
export async function disableEnvironmentMcp(deps: ReplicasDeps, actor: ReplicasActor, raw: unknown) {
  const selection = parseSelection(raw);
  const results: EnvironmentMcpResult[] = [];
  const released: string[] = [];
  const targets = await withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    let policies: PolicyRow[];
    if ("all" in selection) {
      await setAllEnvironments(tx, actor.workspaceId, false);
      await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
        actor: auditActor(actor), action: "replicas.environment.all_disabled", target: actor.workspaceId });
      policies = (await tx.query<PolicyRow>(
        `SELECT ${POLICY} FROM replica_environment_policies WHERE workspace_id = $1 AND (enabled OR registered_mcp_id IS NOT NULL)
          ORDER BY environment_id FOR UPDATE`, [actor.workspaceId])).rows;
    } else {
      policies = [];
      for (const environmentId of new Set(selection.environmentIds.map((id) => id.toLowerCase()))) {
        const policy = await policyFor(tx, actor.workspaceId, environmentId);
        if (policy) policies.push(policy);
        else results.push({ environmentId, status: "not_found" });
      }
    }
    const disabled: PolicyRow[] = [];
    // {all: true} turns the workspace default off; it is not a per-environment opt-out.
    for (const policy of policies) disabled.push(await disablePolicy(tx, actor, policy, released, !("all" in selection)));
    return disabled;
  });
  for (const policy of targets) results.push(await removeEntry(deps, actor, policy, true));
  await retireIdentityBindings(deps, actor, released);
  return { environments: results };
}

async function removeEntry(deps: ReplicasDeps, actor: ReplicasActor, policy: PolicyRow, admin: boolean): Promise<EnvironmentMcpResult> {
  if (!policy.registered_mcp_id) return { environmentId: policy.environment_id, status: "disabled" };
  return withReplicasLock(deps, actor, async (tx): Promise<EnvironmentMcpResult> => {
    if (admin) await requireAdmin(tx, actor);
    const current = await policyFor(tx, actor.workspaceId, policy.environment_id);
    if (!current?.registered_mcp_id) return { environmentId: policy.environment_id, status: "disabled" };
    try {
      const key = await keyFor(deps, tx, actor.workspaceId);
      try {
        await deps.replicas.removeEnvironmentMcp(key, current.environment_id, current.registered_mcp_id);
      } catch (error) {
        // Already gone provider-side is a completed removal.
        if (!(error instanceof ReplicasRuntimeError) || ![404, 410].includes(error.status)) throw error;
      }
      await tx.query("UPDATE replica_environment_policies SET registered_mcp_id = NULL, updated_at = now() WHERE id = $1", [current.id]);
      await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
        actor: auditActor(actor), action: "replicas.environment.mcp_removed", target: current.id });
      return { environmentId: current.environment_id, status: "disabled" };
    } catch (error) {
      await recordProviderAccess(tx, actor.workspaceId, error);
      return { environmentId: current.environment_id, status: "removal_failed", retryable: true };
    }
  });
}

export type EnvironmentSetup = { discovery: DiscoveryResult; allEnvironments: boolean; environments: EnvironmentMcpResult[] };

/**
 * Runs the default enable step. A failure that is not already a
 * per-environment status (a database or lock error) is reported as a
 * retryable registration_failed for each target instead of a throw.
 */
async function enableDefaults(deps: ReplicasDeps, actor: ReplicasActor, selection: DefaultSelection,
  targets: string[]): Promise<EnvironmentMcpResult[]> {
  try {
    return await enableSelected(deps, actor, selection);
  } catch {
    return targets.map((environmentId) => ({ environmentId, status: "registration_failed", retryable: true }));
  }
}

/**
 * Connect-time setup. A fresh connect (no Replicas connection before it,
 * including a connect after a disconnect) turns the all-environments default
 * on and clears every opt-out (neither survives a disconnect), discovers the
 * organization's environments, then enables and registers every one that is
 * not already enabled and registered. A re-connect (a key rotation over an
 * existing connection) changes no flag and no opt-out: it runs the sync
 * semantics under the current flag. Under an organization connected in
 * another workspace nothing is enabled and each result is organization_shared.
 * Provider and registration failures are per-environment statuses or a
 * discovery status "failed", never a throw.
 */
export async function setupEnvironments(deps: ReplicasDeps, actor: ReplicasActor,
  options: { reconnect: boolean }): Promise<EnvironmentSetup> {
  identityConfig(deps);
  if (options.reconnect) {
    let discovery: DiscoveryResult;
    try {
      discovery = await discoverEnvironments(deps, actor);
    } catch {
      discovery = { status: "failed", environments: [] };
    }
    const { all, targets } = await withReplicasLock(deps, actor, async (tx) => {
      await requireAdmin(tx, actor);
      const all = await allEnvironmentsFlag(tx, actor.workspaceId);
      const targets = all ? await defaultPolicies(tx, actor.workspaceId, await connectedOrganization(tx, actor.workspaceId), "sync") : [];
      return { all, targets: targets.map((policy) => policy.environment_id) };
    });
    const environments = all ? await enableDefaults(deps, actor, { defaults: "sync" }, targets) : [];
    return { discovery, allEnvironments: all, environments };
  }
  await withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    await connectedOrganization(tx, actor.workspaceId);
    await setAllEnvironments(tx, actor.workspaceId, true);
    // A fresh connect starts clean: earlier opt-outs do not survive a disconnect.
    await clearOptOut(tx, actor.workspaceId, "all");
    await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
      actor: auditActor(actor), action: "replicas.environment.all_enabled", target: actor.workspaceId });
  });
  let discovery: DiscoveryResult;
  try {
    discovery = await discoverEnvironments(deps, actor);
  } catch {
    discovery = { status: "failed", environments: [] };
  }
  const environments = await enableDefaults(deps, actor, { defaults: "setup" },
    discovery.environments.map((item) => item.environmentId));
  return { discovery, allEnvironments: true, environments };
}

/**
 * Rediscovers environments. Under the all-environments flag, every disabled
 * environment that is not opted out (newly discovered, or a default enable
 * that failed or was refused earlier) is enabled and registered and enabled
 * ones without a registration are retried; opted-out environments stay disabled.
 */
export async function syncEnvironments(deps: ReplicasDeps, actor: ReplicasActor) {
  const discovery = await discoverEnvironments(deps, actor);
  const all = await withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    return allEnvironmentsFlag(tx, actor.workspaceId);
  });
  const environments = all ? await enableSelected(deps, actor, { defaults: "sync" }) : [];
  return { discovery, allEnvironments: all, environments };
}

/**
 * Disconnect: stop admission for every environment and revoke its bindings
 * (committed), then remove the registered provider entries best effort while
 * the key still exists, then retire the released Relay identities.
 * Called before the provider connection is deleted.
 */
export async function disconnectEnvironments(deps: ReplicasDeps, actor: ReplicasActor): Promise<void> {
  const released: string[] = [];
  const registered = await withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    await setAllEnvironments(tx, actor.workspaceId, false);
    const policies = (await tx.query<PolicyRow>(
      `SELECT ${POLICY} FROM replica_environment_policies WHERE workspace_id = $1 ORDER BY environment_id FOR UPDATE`,
      [actor.workspaceId])).rows;
    const disabled: PolicyRow[] = [];
    for (const policy of policies) disabled.push(await disablePolicy(tx, actor, policy, released));
    return disabled.filter((policy) => policy.registered_mcp_id);
  });
  for (const policy of registered) await removeEntry(deps, actor, policy, true).catch(() => undefined);
  await retireIdentityBindings(deps, actor, released);
}
