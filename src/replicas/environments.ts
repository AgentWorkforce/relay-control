import { randomUUID } from "node:crypto";
import { z } from "zod";
import { recordAudit } from "../admin/audit.js";
import type { SqlExecutor } from "../database.js";
import { HOSTED_SOURCE, ownerHash } from "../mcp/relay-participants.js";
import { emailHint, type ReplicaIdentityClaims } from "./identity.js";
import { ReplicasRuntimeError } from "./runtime.js";
import {
  COLUMNS,
  decrypt,
  encrypt,
  ENVIRONMENT_IDENTITY,
  keyFor,
  patch,
  relayFor,
  ReplicasError,
  requireAdmin,
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
 * environment policy and a creator mapping to a current member; the first
 * admitted call enrols a Relay identity for that Replicas workspace. No
 * helper, credentials file or exec is written into the replica, and nothing
 * is pushed into its chats: it reads its inbox through the MCP tools.
 *
 * Connecting Replicas only discovers environments (disabled). An owner/admin
 * enables them and registers the MCP entry.
 */
export const IDENTITY_SERVER_NAME = "agent-relay-replica";

export type IdentityRefusalCode =
  | "replica_identity_invalid"
  | "replica_released"
  | "replica_environment_not_enabled"
  | "replica_creator_not_allowed"
  | "replica_already_bound";

/** A refused workspace_identity call. Its message is the code, never claim text. */
export class IdentityRefusal extends ReplicasError {
  constructor(readonly code: IdentityRefusalCode, status: number, readonly scope: { workspaceId: string; organizationId: string } | null = null) {
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
};
const POLICY = "id, workspace_id, issuer, provider_organization_id, environment_id, environment_name, enabled, registered_mcp_id";

type Admission = { policy: PolicyRow; organizationId: string; userId: string };
const scopeOf = (admission: Admission) => ({ workspaceId: admission.policy.workspace_id, organizationId: admission.organizationId });

function identityConfig(deps: ReplicasDeps) {
  if (!deps.identity) throw new ReplicasError("The environment-level Replicas MCP is not configured.", 404);
  return deps.identity;
}

/** The environment-level MCP URL; it is also the token audience. */
export const environmentMcpUrl = (publicBaseUrl: string) => `${publicBaseUrl.replace(/\/+$/, "")}/api/v1/replicas/mcp`;
/** The Relay name of an environment-identity binding: derived from the provider workspace id. */
export const identityAgentName = (workspaceId: string) => `replicas-${workspaceId.replaceAll("-", "").toLowerCase().slice(0, 16)}`;

/**
 * Checks 2-4 of the admission order (1 = token verification, done by the
 * caller). Reads only; every refusal is a typed IdentityRefusal.
 */
async function admissionChecks(tx: SqlExecutor, claims: ReplicaIdentityClaims): Promise<Admission> {
  const tombstone = await tx.query<{ workspace_id: string; organization_id: string }>(
    `SELECT t.workspace_id, w.organization_id FROM replica_identity_tombstones t JOIN workspaces w ON w.id = t.workspace_id
      WHERE t.issuer = $1 AND t.provider_organization_id = $2 AND t.provider_workspace_id = $3`,
    [claims.issuer, claims.organizationId, claims.workspaceId],
  );
  const released = tombstone.rows[0];
  if (released) {
    throw new IdentityRefusal("replica_released", 403, { workspaceId: released.workspace_id, organizationId: released.organization_id });
  }
  const policies = await tx.query<PolicyRow & { organization_id: string; provider_account: string | null }>(
    `SELECT ${POLICY.split(", ").map((column) => `p.${column}`).join(", ")}, w.organization_id, c.provider_account
       FROM replica_environment_policies p
       JOIN workspaces w ON w.id = p.workspace_id
       LEFT JOIN remote_agent_connections c ON c.workspace_id = p.workspace_id AND c.provider = 'replicas'
      WHERE p.enabled AND p.issuer = $1 AND p.provider_organization_id = $2 AND p.environment_id = $3`,
    [claims.issuer, claims.organizationId, claims.environmentId],
  );
  const candidate = policies.rows.length === 1 ? policies.rows[0]! : null;
  // The workspace must still hold a connection to the same provider organization.
  if (!candidate || candidate.provider_account?.toLowerCase() !== claims.organizationId) {
    throw new IdentityRefusal("replica_environment_not_enabled", 403);
  }
  const { organization_id: organizationId, provider_account: _account, ...policy } = candidate;
  const scope = { workspaceId: policy.workspace_id, organizationId };
  if (claims.creatorId === null) throw new IdentityRefusal("replica_creator_not_allowed", 403, scope);
  const mapping = await tx.query<{ user_id: string }>(
    `SELECT c.user_id FROM replica_environment_creators c
       JOIN organization_memberships m ON m.user_id = c.user_id AND m.organization_id = $3
      WHERE c.policy_id = $1 AND c.creator_id = $2`,
    [policy.id, claims.creatorId, organizationId],
  );
  const userId = mapping.rows[0]?.user_id;
  if (!userId) throw new IdentityRefusal("replica_creator_not_allowed", 403, scope);
  return { policy, organizationId, userId };
}

async function liveBinding(tx: SqlExecutor, claims: ReplicaIdentityClaims, admission: Admission): Promise<SpawnRow | null> {
  const live = await tx.query<SpawnRow>(
    `SELECT ${COLUMNS} FROM replica_spawns WHERE lower(replica_id) = $1 AND state <> 'gone' ORDER BY created_at, id FOR UPDATE`,
    [claims.workspaceId],
  );
  const row = live.rows[0];
  if (!row) return null;
  if (row.source !== ENVIRONMENT_IDENTITY) throw new IdentityRefusal("replica_already_bound", 409, scopeOf(admission));
  // The binding acts for exactly one workspace and person; a changed policy
  // or mapping never silently moves it.
  if (row.issuer !== claims.issuer || row.provider_organization_id !== claims.organizationId
    || row.workspace_id !== admission.policy.workspace_id || row.user_id !== admission.userId) {
    throw new IdentityRefusal("replica_creator_not_allowed", 403, scopeOf(admission));
  }
  return row;
}

/** Refusals are audited with their reason code only (no subject, jti or email). */
async function auditRefusal(deps: ReplicasDeps, refusal: IdentityRefusal): Promise<void> {
  await deps.database.transaction((tx) => recordAudit(tx, {
    organizationId: refusal.scope?.organizationId ?? null,
    workspaceId: refusal.scope?.workspaceId ?? null,
    actor: { kind: "service", subject: "replicas-identity" },
    action: "replicas.identity.refused",
    target: refusal.code,
  })).catch(() => undefined);
}

async function audited<T>(deps: ReplicasDeps, work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    if (error instanceof IdentityRefusal) await auditRefusal(deps, error);
    throw error;
  }
}

/** Runs the read-only checks to find the tenant workspace, then re-runs them under its lock. */
async function underAdmission<T>(deps: ReplicasDeps, claims: ReplicaIdentityClaims,
  work: (tx: SqlExecutor, admission: Admission) => Promise<T>): Promise<T> {
  return audited(deps, async () => {
    const first = await deps.database.transaction((tx) => admissionChecks(tx, claims));
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
  const bridged = (await deps.relaycast.listAgents(relay.key, "all")).find((agent) =>
    String(agent.metadata.replica_id ?? "").toLowerCase() === claims.workspaceId && agent.metadata.replicas_spawn_id !== ownId);
  if (bridged) throw new IdentityRefusal("replica_already_bound", 409, scopeOf(admission));
  if (!row) {
    const id = randomUUID();
    const input: SpawnInput = { environment_id: claims.environmentId, name, task: "", coding_agent: "replicas",
      origin: ENVIRONMENT_IDENTITY };
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
  return Boolean(result.rows[0]?.all_environments);
}

async function setAllEnvironments(tx: SqlExecutor, workspaceId: string, value: boolean): Promise<void> {
  await tx.query(
    `INSERT INTO replica_environment_settings (workspace_id, all_environments) VALUES ($1, $2)
     ON CONFLICT (workspace_id) DO UPDATE SET all_environments = EXCLUDED.all_environments, updated_at = now()`,
    [workspaceId, value],
  );
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

/** Dashboard view: every policy with its status and creator mappings (masked email hints only). */
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
    const bindings = (await tx.query<{ environment_id: string; count: number }>(
      `SELECT environment_id, count(*)::int AS count FROM replica_spawns
        WHERE workspace_id = $1 AND source = '${ENVIRONMENT_IDENTITY}' AND state <> 'gone' GROUP BY environment_id`,
      [actor.workspaceId])).rows;
    return {
      mcpUrl,
      organizationId: connection?.provider_account ?? null,
      allEnvironments: await allEnvironmentsFlag(tx, actor.workspaceId),
      environments: policies.map((policy) => ({
        environmentId: policy.environment_id,
        name: policy.environment_name,
        enabled: policy.enabled,
        status: policyStatus(policy),
        // A policy recorded for an earlier connection never admits a token.
        stale: Boolean(connection?.provider_account) && policy.provider_organization_id !== connection!.provider_account!.toLowerCase(),
        registeredMcpId: policy.registered_mcp_id,
        bindings: bindings.find((item) => item.environment_id === policy.environment_id)?.count ?? 0,
        creators: creators.filter((item) => item.policy_id === policy.id)
          .map((item) => ({ creatorId: item.creator_id, userId: item.user_id, emailHint: item.creator_email_hint })),
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

class EnabledElsewhere extends ReplicasError {
  constructor() {
    super("This Replicas environment is enabled in another workspace.", 409);
  }
}

/** Enables admission for one policy. One workspace per provider environment. */
async function enablePolicy(tx: SqlExecutor, actor: ReplicasActor, policy: PolicyRow, organization: string): Promise<PolicyRow> {
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
  const result = await tx.query<PolicyRow>(
    `UPDATE replica_environment_policies SET enabled = true, updated_at = now() WHERE id = $1 RETURNING ${POLICY}`, [policy.id]);
  await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
    actor: { kind: "user", userId: actor.userId }, action: "replicas.environment.enabled", target: policy.id });
  return result.rows[0]!;
}

async function disablePolicy(tx: SqlExecutor, actor: ReplicasActor, policy: PolicyRow): Promise<PolicyRow> {
  if (!policy.enabled) return policy;
  const result = await tx.query<PolicyRow>(
    `UPDATE replica_environment_policies SET enabled = false, updated_at = now() WHERE id = $1 RETURNING ${POLICY}`, [policy.id]);
  await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
    actor: { kind: "user", userId: actor.userId }, action: "replicas.environment.disabled", target: policy.id });
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
      await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
        actor: { kind: "user", userId: actor.userId }, action: "replicas.environment.creators_updated", target: policy.id });
    }
    if (enabled === true) policy = await enablePolicy(tx, actor, policy, await connectedOrganization(tx, actor.workspaceId));
    if (enabled === false) policy = await disablePolicy(tx, actor, policy);
  });
  const view = await listEnvironmentPolicies(deps, actor);
  return { environment: view.environments.find((item) => item.environmentId === environmentId.toLowerCase()) ?? null };
}

const selectionInput = z.union([
  z.object({ all: z.literal(true) }).strict(),
  z.object({ environmentIds: z.array(z.string().uuid()).min(1).max(100) }).strict(),
]);
type Selection = z.infer<typeof selectionInput>;

export type EnvironmentMcpResult = {
  environmentId: string;
  status: "registered" | "registration_failed" | "not_found" | "enabled_elsewhere" | "stale_connection"
    | "disabled" | "removal_failed";
  retryable?: boolean;
};

function parseSelection(raw: unknown): Selection {
  const parsed = selectionInput.safeParse(raw);
  if (!parsed.success) throw new ReplicasError("Send {environmentIds: [...]} or {all: true}.");
  return parsed.data;
}

/**
 * Enables the selected environments and registers the environment-level MCP
 * in each one's provider configuration. `{all: true}` also enables every
 * environment discovered later (sync). A failed registration is retryable;
 * an unconfirmed one may have left a provider entry behind.
 */
export async function enableEnvironmentMcp(deps: ReplicasDeps, actor: ReplicasActor, raw: unknown) {
  const selection = parseSelection(raw);
  let discovery: DiscoveryResult | undefined;
  if ("all" in selection) discovery = await discoverEnvironments(deps, actor);
  const results = await enableSelected(deps, actor, selection);
  return { ...(discovery ? { discovery } : {}), environments: results };
}

async function enableSelected(deps: ReplicasDeps, actor: ReplicasActor, selection: Selection): Promise<EnvironmentMcpResult[]> {
  const { mcpUrl } = identityConfig(deps);
  const results: EnvironmentMcpResult[] = [];
  const toRegister = await withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    const organization = await connectedOrganization(tx, actor.workspaceId);
    await keyFor(deps, tx, actor.workspaceId);
    let policies: PolicyRow[];
    if ("all" in selection) {
      await setAllEnvironments(tx, actor.workspaceId, true);
      await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
        actor: { kind: "user", userId: actor.userId }, action: "replicas.environment.all_enabled", target: actor.workspaceId });
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
    }
    const enabled: PolicyRow[] = [];
    for (const policy of policies) {
      try {
        enabled.push(await enablePolicy(tx, actor, policy, organization));
      } catch (error) {
        if (error instanceof EnabledElsewhere) results.push({ environmentId: policy.environment_id, status: "enabled_elsewhere" });
        else if (error instanceof ReplicasError) results.push({ environmentId: policy.environment_id, status: "stale_connection" });
        else throw error;
      }
    }
    return enabled;
  });
  for (const policy of toRegister) {
    results.push(await withReplicasLock(deps, actor, async (tx): Promise<EnvironmentMcpResult> => {
      await requireAdmin(tx, actor);
      const current = await policyFor(tx, actor.workspaceId, policy.environment_id);
      if (!current || !current.enabled) return { environmentId: policy.environment_id, status: "disabled" };
      if (current.registered_mcp_id) return { environmentId: current.environment_id, status: "registered" };
      try {
        const key = await keyFor(deps, tx, actor.workspaceId);
        const entry = await deps.replicas.registerEnvironmentMcp(key, current.environment_id, {
          name: IDENTITY_SERVER_NAME, transport: "http",
          config: { url: mcpUrl, headers: {}, auth: { type: "workspace_identity", audience: mcpUrl } },
        });
        await tx.query("UPDATE replica_environment_policies SET registered_mcp_id = $2, updated_at = now() WHERE id = $1", [current.id, entry.id]);
        await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
          actor: { kind: "user", userId: actor.userId }, action: "replicas.environment.mcp_registered", target: current.id });
        return { environmentId: current.environment_id, status: "registered" };
      } catch {
        return { environmentId: current.environment_id, status: "registration_failed", retryable: true };
      }
    }));
  }
  return results;
}

/**
 * Disables the selected environments first (admission stops at commit), then
 * removes their provider MCP entries best effort. A failed removal keeps the
 * entry id so a later disable or disconnect retries it.
 */
export async function disableEnvironmentMcp(deps: ReplicasDeps, actor: ReplicasActor, raw: unknown) {
  const selection = parseSelection(raw);
  const results: EnvironmentMcpResult[] = [];
  const targets = await withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    let policies: PolicyRow[];
    if ("all" in selection) {
      await setAllEnvironments(tx, actor.workspaceId, false);
      await recordAudit(tx, { organizationId: actor.organizationId, workspaceId: actor.workspaceId,
        actor: { kind: "user", userId: actor.userId }, action: "replicas.environment.all_disabled", target: actor.workspaceId });
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
    for (const policy of policies) disabled.push(await disablePolicy(tx, actor, policy));
    return disabled;
  });
  for (const policy of targets) results.push(await removeEntry(deps, actor, policy, true));
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
        actor: { kind: "user", userId: actor.userId }, action: "replicas.environment.mcp_removed", target: current.id });
      return { environmentId: current.environment_id, status: "disabled" };
    } catch {
      return { environmentId: current.environment_id, status: "removal_failed", retryable: true };
    }
  });
}

/** Rediscovers environments; under the all-environments grant, newly discovered ones are enabled and registered. */
export async function syncEnvironments(deps: ReplicasDeps, actor: ReplicasActor) {
  const discovery = await discoverEnvironments(deps, actor);
  const all = await withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    return allEnvironmentsFlag(tx, actor.workspaceId);
  });
  const fresh = discovery.environments.filter((item) => item.status === "discovered").map((item) => item.environmentId);
  const environments = all && fresh.length ? await enableSelected(deps, actor, { environmentIds: fresh }) : [];
  return { discovery, allEnvironments: all, environments };
}

/**
 * Disconnect: stop admission for every environment (committed), then remove
 * the registered provider entries best effort while the key still exists.
 * Called before the provider connection is deleted.
 */
export async function disconnectEnvironments(deps: ReplicasDeps, actor: ReplicasActor): Promise<void> {
  const registered = await withReplicasLock(deps, actor, async (tx) => {
    await requireAdmin(tx, actor);
    await setAllEnvironments(tx, actor.workspaceId, false);
    await tx.query("UPDATE replica_environment_policies SET enabled = false, updated_at = now() WHERE workspace_id = $1 AND enabled",
      [actor.workspaceId]);
    return (await tx.query<PolicyRow>(
      `SELECT ${POLICY} FROM replica_environment_policies WHERE workspace_id = $1 AND registered_mcp_id IS NOT NULL ORDER BY environment_id`,
      [actor.workspaceId])).rows;
  });
  for (const policy of registered) await removeEntry(deps, actor, policy, true).catch(() => undefined);
}
