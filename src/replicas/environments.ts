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
  | "replica_environment_not_enabled"
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
};
const POLICY = "id, workspace_id, issuer, provider_organization_id, environment_id, environment_name, enabled, registered_mcp_id, opted_out";

/** actsAs: "creator" for a mapped creator, "principal" for the workspace VM principal. */
type Admission = { policy: PolicyRow; organizationId: string; userId: string; actsAs: "creator" | "principal" };
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
  const policies = await tx.query<PolicyRow & { organization_id: string; provider_account: string | null; principal_member: string | null }>(
    `SELECT ${POLICY.split(", ").map((column) => `p.${column}`).join(", ")}, w.organization_id, c.provider_account,
            pm.user_id AS principal_member
       FROM replica_environment_policies p
       JOIN workspaces w ON w.id = p.workspace_id
       LEFT JOIN remote_agent_connections c ON c.workspace_id = p.workspace_id AND c.provider = 'replicas'
       LEFT JOIN replica_environment_settings s ON s.workspace_id = p.workspace_id
       LEFT JOIN organization_memberships pm ON pm.user_id = s.principal_user_id AND pm.organization_id = w.organization_id
      WHERE p.enabled AND p.issuer = $1 AND p.provider_organization_id = $2 AND p.environment_id = $3`,
    [claims.issuer, claims.organizationId, claims.environmentId],
  );
  const candidate = policies.rows.length === 1 ? policies.rows[0]! : null;
  // An organization connected in several workspaces has no single tenant: refuse before any creator check.
  if (await organizationShared(tx, claims.organizationId)) {
    throw new IdentityRefusal("replica_environment_not_enabled", 403,
      candidate ? { workspaceId: candidate.workspace_id, organizationId: candidate.organization_id } : null);
  }
  // The workspace must still hold a connection to the same provider organization.
  if (!candidate || candidate.provider_account?.toLowerCase() !== claims.organizationId) {
    throw new IdentityRefusal("replica_environment_not_enabled", 403);
  }
  const { organization_id: organizationId, provider_account: _account, principal_member: principal, ...policy } = candidate;
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
  // Only an unmapped creator becomes a pending request.
  throw new IdentityRefusal("replica_creator_not_allowed", 403, scope, claims.creatorId === null ? null : policy.id);
}

async function liveBinding(tx: SqlExecutor, claims: ReplicaIdentityClaims, admission: Admission): Promise<SpawnRow | null> {
  const live = await tx.query<SpawnRow>(
    `SELECT ${COLUMNS} FROM replica_spawns WHERE lower(replica_id) = $1 AND state <> 'gone' ORDER BY created_at, id FOR UPDATE`,
    [claims.workspaceId],
  );
  const row = live.rows[0];
  if (!row) return null;
  // A launch or bind of the same replica in this workspace is reused as is: the identity acts as
  // that binding and its owner (never the principal or a creator mapping) while the owner is a member.
  // A rejected launch binds nothing by itself, so it stays a conflict until recovered or released.
  if (row.source !== ENVIRONMENT_IDENTITY && row.workspace_id === admission.policy.workspace_id && row.state !== "rejected") {
    const owner = await tx.query("SELECT 1 FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
      [admission.organizationId, row.user_id]);
    if (!owner.rows.length) throw new IdentityRefusal("replica_creator_not_allowed", 403, scopeOf(admission));
    return row;
  }
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
  const hint = emailHint(claims.creatorEmail);
  if (hint) {
    await tx.query("UPDATE replica_environment_creators SET creator_email_hint = $3 WHERE policy_id = $1 AND creator_id = $2 AND creator_email_hint IS DISTINCT FROM $3",
      [admission.policy.id, claims.creatorId, hint]);
  }
  if (row?.state === "bound" && row.token_ciphertext) return row;
  const relay = await relayFor(deps, tx, { workspaceId: admission.policy.workspace_id, userId: admission.userId }, row?.relay_workspace_id);
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
      origin: ENVIRONMENT_IDENTITY, acts_as: admission.actsAs, creator_id: claims.creatorId };
    const inserted = await tx.query<SpawnRow>(
      `INSERT INTO replica_spawns (id, workspace_id, organization_id, user_id, client_request_id, source, input, replica_id, state,
         relay_workspace_id, agent_name, environment_id, provider_organization_id, issuer)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, 'binding', $9, $10, $11, $12, $13) RETURNING ${COLUMNS}`,
      [id, admission.policy.workspace_id, admission.organizationId, admission.userId, `environment-identity:${id}`, ENVIRONMENT_IDENTITY,
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

const policyStatus = (policy: PolicyRow) => !policy.enabled ? "disabled" : policy.registered_mcp_id ? "registered" : "enabled";

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
  } catch {
    return { status: "failed", environments: [] };
  }
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
        await tx.query("UPDATE replica_environment_policies SET environment_name = $2, updated_at = now() WHERE id = $1",
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
    return { status: listed.complete ? "ok" : "partial", environments };
  });
}

/** Dashboard view: every policy with its status, creator mappings and pending creators (masked email hints only). */
export async function listEnvironmentPolicies(deps: ReplicasDeps, actor: ReplicasActor) {
  const { mcpUrl } = identityConfig(deps);
  return withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    const connection = (await tx.query<{ provider_account: string | null }>(
      "SELECT provider_account FROM remote_agent_connections WHERE workspace_id = $1 AND provider = 'replicas'",
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
      allEnvironments: await allEnvironmentsFlag(tx, actor.workspaceId),
      // The VM principal; member false means it left the organization and admits nobody.
      principal: principal?.principal_user_id ? { userId: principal.principal_user_id, member: Boolean(principal.member) } : null,
      // True when this provider organization is connected in another workspace too: nothing is admitted or enabled.
      organizationShared: await organizationShared(tx, connection?.provider_account ?? null),
      environments: policies.map((policy) => ({
        environmentId: policy.environment_id,
        name: policy.environment_name,
        enabled: policy.enabled,
        status: policyStatus(policy),
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
}).strict();

/** Sets an environment's admission switch and/or replaces its creator mappings. */
export async function updateEnvironmentPolicy(deps: ReplicasDeps, actor: ReplicasActor, environmentId: string, raw: unknown) {
  const parsed = putInput.safeParse(raw);
  if (!parsed.success) throw new ReplicasError("Send enabled and/or creators [{creatorId, userId}].");
  const { enabled, creators } = parsed.data;
  if (creators && new Set(creators.map((item) => item.creatorId)).size !== creators.length) {
    throw new ReplicasError("Each creator is mapped once.");
  }
  const released: string[] = [];
  await withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    let policy = await policyFor(tx, actor.workspaceId, environmentId);
    if (!policy) throw new ReplicasError("Unknown environment. Sync environments first.", 404);
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
      // A binding of a newly mapped creator that acts as the principal or as
      // another member is released (no tombstone) and enrols again as the
      // mapped member. Removing a mapping releases nothing: admission refuses.
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
    | "organization_shared" | "stale_connection" | "disabled" | "removal_failed";
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
 * whose registration is missing; an opted-out policy is never re-enabled here.
 */
type DefaultSelection = { defaults: "setup" | "sync" };
const DEFAULTS = {
  setup: "NOT (enabled AND registered_mcp_id IS NOT NULL)",
  sync: "(NOT enabled AND NOT opted_out) OR (enabled AND registered_mcp_id IS NULL)",
};

async function defaultPolicies(tx: SqlExecutor, workspaceId: string, organization: string, defaults: DefaultSelection["defaults"]) {
  return (await tx.query<PolicyRow>(
    `SELECT ${POLICY} FROM replica_environment_policies WHERE workspace_id = $1 AND provider_organization_id = $2 AND (${DEFAULTS[defaults]})
      ORDER BY environment_id FOR UPDATE`, [workspaceId, organization])).rows;
}

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
    // Once a create was sent, only a definite rejection proves no entry was
    // created; anything else (timeout, 5xx, unreadable answer, our own
    // UPDATE or commit failing) leaves the outcome unknown.
    let asked = false;
    try {
      results.push(await withReplicasLock(deps, actor, async (tx): Promise<EnvironmentMcpResult> => {
        await requireAdmin(tx, actor);
        const current = await policyFor(tx, actor.workspaceId, policy.environment_id);
        if (!current || !current.enabled) return { environmentId: policy.environment_id, status: "disabled" };
        if (current.registered_mcp_id) return { environmentId: current.environment_id, status: "registered" };
        let key: string;
        try {
          key = await keyFor(deps, tx, actor.workspaceId);
        } catch {
          return { environmentId: current.environment_id, status: "registration_failed", retryable: true };
        }
        const failed = (retryable: boolean): EnvironmentMcpResult => ({ environmentId: current.environment_id, status: "registration_failed", retryable });
        const unconfirmed: EnvironmentMcpResult = { environmentId: current.environment_id, status: "registration_unconfirmed", retryable: true };
        // Read first: reuse a matching entry, never overwrite a foreign or duplicated one.
        let found: EntryMatch;
        try {
          found = matchEntry(await deps.replicas.listEnvironmentMcps(key, current.environment_id), current, config);
        } catch {
          return failed(true);
        }
        if (found.kind === "conflict") return failed(false);
        if (found.kind === "none") {
          asked = true;
          let createdId: string | null = null;
          try {
            createdId = (await deps.replicas.registerEnvironmentMcp(key, current.environment_id,
              { name: IDENTITY_SERVER_NAME, transport: "http", config })).id;
          } catch (error) {
            // A 409 or a lost answer may still have created the entry: read it back below.
            if (rejectedByProvider(error)) {
              asked = false;
              return failed(true);
            }
          }
          try {
            found = matchEntry(await deps.replicas.listEnvironmentMcps(key, current.environment_id), current, config);
          } catch {
            return unconfirmed;
          }
          if (found.kind === "conflict") return failed(false);
          if (found.kind !== "match" || (createdId !== null && found.id !== createdId)) return unconfirmed;
        }
        const entry = { id: found.id };
        await tx.query("UPDATE replica_environment_policies SET registered_mcp_id = $2, updated_at = now() WHERE id = $1", [current.id, entry.id]);
        await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
          actor: auditActor(actor), action: "replicas.environment.mcp_registered", target: current.id });
        return { environmentId: current.environment_id, status: "registered" };
      }));
    } catch (error) {
      if (!asked) throw error;
      results.push({ environmentId: policy.environment_id, status: "registration_unconfirmed", retryable: true });
    }
  }
  return results;
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
    } catch {
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
 * Revives a tombstone whose workspace was deleted (workspace_id NULL). Only an
 * owner/admin of a workspace that currently holds the tombstone's provider
 * organization connection may remove it: 404 when the connected organization
 * has no such orphaned tombstone. The revival is audited in the caller's workspace.
 */
export async function reviveOrphanedTombstone(deps: ReplicasDeps, actor: ReplicasActor, providerWorkspaceId: string) {
  const { issuer } = identityConfig(deps);
  const notFound = () => new ReplicasError("No released replica with this provider workspace id was found for the connected organization.", 404);
  return withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    if (!isUuid(providerWorkspaceId)) throw notFound();
    const connection = await tx.query<{ provider_account: string | null }>(
      "SELECT provider_account FROM remote_agent_connections WHERE workspace_id = $1 AND provider = 'replicas'",
      [actor.workspaceId],
    );
    const organization = connection.rows[0]?.provider_account?.toLowerCase();
    if (!organization) throw notFound();
    const removed = await tx.query<{ provider_workspace_id: string }>(
      `DELETE FROM replica_identity_tombstones
        WHERE issuer = $1 AND provider_organization_id = $2 AND provider_workspace_id = $3 AND workspace_id IS NULL
        RETURNING provider_workspace_id`,
      [issuer, organization, providerWorkspaceId.toLowerCase()],
    );
    const revived = removed.rows[0];
    if (!revived) throw notFound();
    await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
      actor: auditActor(actor), action: "replicas.identity.revived", target: revived.provider_workspace_id });
    return { providerWorkspaceId: revived.provider_workspace_id, revived: true };
  });
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
