import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import { cookieRequestAllowed } from "../auth/device-approval.js";
import { bearer } from "../auth/bearer.js";
import { controlSessionToken } from "../auth/session-cookie.js";
import { hashSecret } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";
import { RelaycastCallError, type RelaycastClient } from "../messaging/relaycast.js";
import { ACCOUNT_SCOPE, type Principal } from "../store.js";
import { DELEGATION_JWKS_PATH, type DelegationSigner } from "./jws.js";
import {
  ACTION_CLASSES,
  actionClass,
  APPROVAL_DEFAULT_MS,
  APPROVAL_MAX_MS,
  canonicalAction,
  classTargetCovered,
  configTarget,
  NEVER_DELEGABLE_SETTINGS,
  GRANT_DEFAULT_DAYS,
  GRANT_MAX_DAYS,
  highRisk,
  mintActionsSchema,
  sha256Hex,
  validConfigPattern,
  validPromptPattern,
  validRfc3339,
  validTargetPattern,
  type ActionClass,
  type Scope,
} from "./scope.js";
import {
  anyBinding,
  attestDelegation,
  auditView,
  CLAIM_TTL_MS,
  expireLapsed,
  grantView,
  listAuditPage,
  loadOrgPolicy,
  loadPolicy,
  loadTargetOwners,
  memberRole,
  mintId,
  newClaimCode,
  promptDelegates,
  QUOTE_RETENTION_DAYS,
  QUOTE_RETENTION_MAX_DAYS,
  recordDelegationAudit,
  redactExpiredQuotes,
  redeemApproval,
  resolveBinding,
  revokeAllGrants,
  revokeGrants,
  time,
  type DelegationDeps,
  type DelegationPolicy,
  type DelegationWorkspace,
  type GrantRow,
} from "./service.js";

/**
 * HTTP surface for owner-named trusted delegates (relay
 * docs/design/owner-trusted-delegates.md §16.3), the self-hosted twin of
 * Cloud's (cloud#6501): the same paths, bodies, status codes and response
 * shapes, and Cloud's error body `{error: <message>, code}`. See
 * docs/owner-delegates.md.
 *
 * Human-only routes take the browser account session (the /cloud cookie) or
 * a Desktop-verified bearer (a redeemed browser-consent Desktop sign-in). A
 * device-flow CLI login, an enrollment-key session, a workspace API token
 * and any agent token are refused. Either a browser session or a verified
 * Desktop sign-in is enough for every owner action (§4.1, no step-up).
 * Cookie writes need JSON from an allowed Origin (CSRF).
 *
 * Agent routes prove the agent with its own Relaycast token. Attest, redeem
 * and prompt-delegates also take the recipient owner's Desktop-verified
 * bearer, exactly as Cloud's native-authority route does.
 */

const CLAIM_COMPLETE_RATE = { limit: 20, windowMs: 60_000 };
const AGENT_ROUTE_RATE = { limit: 120, windowMs: 60_000 };
const MAX_AUDIT_EVENTS = 1000;
const GRANT_ID = /^grt_[A-Za-z0-9]{8,64}$/u;

type JsonWriter = (response: ServerResponse, status: number, body: unknown, noStore?: boolean) => void;

export type DelegationRoutesInput = {
  database: Database;
  /** Server-held key for keyed quote digests (§8). */
  quoteKey: Buffer;
  relaycast: RelaycastClient;
  signer: DelegationSigner | null;
  gateOnly: boolean;
  browserOrigins: readonly string[];
  authenticateAccessToken: (token: string) => Promise<Principal | null>;
  workspaceForUser: (workspaceId: string, userId: string) => Promise<{
    id: string; organizationId: string; relaycastWorkspaceId: string; relaycastApiKey: string; role: Principal["role"];
  } | null>;
  json: JsonWriter;
  /** A workspace's Relaycast binding, without a person (claims/complete, withdraw). */
  relaycastBinding: (workspaceId: string) => Promise<{ relaycastWorkspaceId: string; relaycastApiKey: string } | null>;
  rateLimit: (response: ServerResponse, key: string, rule: { limit: number; windowMs: number }) => void;
  clientKey: (request: IncomingMessage) => string;
  now?: () => Date;
};

type AuthMethod = "session" | "desktop_bearer";

type Human = {
  principal: Principal;
  workspace: DelegationWorkspace & { role: Principal["role"] };
  authMethod: AuthMethod;
  admin: boolean;
};

type SessionFacts = {
  created_at: Date | string;
  desktop_host_name: string | null;
  desktop_verified_at: Date | string | null;
  desktop_exchange_challenge: string | null;
  provisioned_by_token_id: string | null;
  scopes: string[];
};

/** A refusal rendered as Cloud's delegation error body `{error: <message>, code}`. */
export class DelegationHttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "DelegationHttpError";
  }
}

const fail = (code: string, error: string, status: number): never => {
  throw new DelegationHttpError(status, code, error);
};
const UNAVAILABLE = () => fail("unavailable", "Delegation is unavailable", 503);
const NOT_ENABLED = () => fail("not_enabled", "Delegation is off for this workspace", 403);

// Request bodies, strict as Cloud's lib/delegation/requests.ts.
const rfc3339 = z.string().max(64).refine(validRfc3339, "must be RFC 3339 with a real date");
const classList = z.array(actionClass).max(ACTION_CLASSES.length);
const scopeSchema = z.object({
  class: actionClass,
  targets: z.array(z.string().max(256)).min(1).max(50),
}).strict().refine(scope => scope.targets.every(target =>
  scope.class === "prompt_approval" ? validPromptPattern(target)
    : scope.class === "config_change" ? validConfigPattern(target) : validTargetPattern(target)),
"`*` may only stand for a whole segment; prompt_approval and config_change targets are `<agent id>:*` or `*`");
const scopesSchema = z.array(scopeSchema).min(1).max(ACTION_CLASSES.length)
  .refine(scopes => new Set(scopes.map(scope => scope.class)).size === scopes.length, "one scope per class");

const createGrantBody = z.object({
  delegate_agent_id: z.string().min(1).max(200),
  scopes: scopesSchema,
  expires_at: rfc3339.optional(),
  require_tier_o: classList.optional(),
}).strict();
const patchGrantBody = z.object({
  scopes: scopesSchema.optional(),
  expires_at: rfc3339.optional(),
  require_tier_o: classList.optional(),
}).strict().refine(body => Object.keys(body).length > 0, "nothing to change");
const revokeAllBody = z.object({ all: z.boolean().optional() }).strict();
const mintBody = z.object({
  actions: mintActionsSchema,
  expires_at: rfc3339.optional(),
  single_use: z.boolean().optional(),
}).strict();
const policyBody = z.object({
  delegation_enabled: z.boolean(),
  max_expiry_days: z.number().int().min(1).max(GRANT_MAX_DAYS).optional(),
  allowed_classes: classList.nullable().optional(),
  require_tier_o: classList.optional(),
  code_owner_match: z.enum(["any_path", "all_paths"]).optional(),
}).strict();
/** `PUT /orgs/{org}/delegation-policy` (§16.3): org-wide settings no workspace policy overrides. */
const orgPolicyBody = z.object({
  quote_retention_days: z.number().int().min(1).max(QUOTE_RETENTION_MAX_DAYS),
}).strict();
const ORG_POLICY_PATH = /^\/api\/v1\/orgs\/([^/]+)\/delegation-policy$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const targetOwnerSchema = z.object({
  pattern: z.string().min(1).max(256).refine(validTargetPattern, "`*` may only stand for a whole segment"),
  repo: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\/[A-Za-z0-9_.-]{1,100}$/u).optional(),
  owner_ids: z.array(z.string().uuid()).min(1).max(50).optional(),
}).strict().refine(entry => Boolean(entry.repo || entry.owner_ids), "an entry names a repo or people");
/** The bare array of §16.3; `{target_owners: [...]}` is also accepted, as in Cloud. */
const targetOwnersBody = z.union([
  z.array(targetOwnerSchema).max(200),
  z.object({ target_owners: z.array(targetOwnerSchema).max(200) }).strict().transform(body => body.target_owners),
]);
const claimCompleteBody = z.object({
  code: z.string().min(16).max(128),
  agent_id: z.string().min(1).max(200),
  agent_token: z.string().min(12).max(512),
}).strict();
const recipientFields = {
  recipient_agent_id: z.string().min(1).max(200),
  recipient_token: z.string().min(12).max(512),
};
const attestBody = z.object({
  ...recipientFields,
  message_id: z.string().min(1).max(200),
  accept: z.enum(["code_owners", "own_owner"]).optional(),
}).strict();
const redeemBody = z.object({
  ...recipientFields,
  approval_id: z.string().regex(/^apv_[A-Za-z0-9]{8,64}$/u),
  action: z.object({ class: actionClass, target: z.string().min(1).max(256) }).strict(),
}).strict();
const withdrawBody = z.object({
  delegate_agent_id: z.string().min(1).max(200),
  delegate_token: z.string().min(12).max(512),
  approval_id: z.string().regex(/^apv_[A-Za-z0-9]{8,64}$/u),
}).strict();
const APPROVAL_ID = /^apv_[A-Za-z0-9]{8,64}$/u;
const promptDelegatesBody = z.object({
  session_agent_id: z.string().min(1).max(200),
  session_token: z.string().min(12).max(512),
}).strict();

/** The body as JSON, or null when it is empty or not JSON (Cloud's readJson). */
async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  // Past the limit, keep draining without buffering so the stream (and the
  // socket) stays open for the 413 answer.
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size <= 256 * 1024) chunks.push(buffer);
  }
  if (size > 256 * 1024) fail("payload_too_large", "Body exceeds 256 KiB", 413);
  const raw = Buffer.concat(chunks).toString("utf8");
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return raw.trim() ? null : undefined;
  }
}

function uniqueClasses(values: readonly ActionClass[] | undefined): ActionClass[] {
  return [...new Set(values ?? [])];
}

/** Cloud's policyRefusal: classes the policy does not allow. */
function policyRefusal(classes: readonly ActionClass[], policy: DelegationPolicy): void {
  const refused = policy.allowed_classes ? classes.filter(item => !policy.allowed_classes!.includes(item)) : [];
  if (refused.length) fail("out_of_scope", `Policy does not allow delegating: ${uniqueClasses(refused).join(", ")}`, 403);
}

export function isDelegationPath(path: string): boolean {
  return path === DELEGATION_JWKS_PATH || path === `/cloud${DELEGATION_JWKS_PATH}` || ORG_POLICY_PATH.test(path)
    || /^\/api\/v1\/workspaces\/[^/]+\/(delegates(\/.*)?|messaging\/delegation(\/redeem|\/prompt-delegates|\/withdraw)?)$/.test(path);
}

export function createDelegationHandler(input: DelegationRoutesInput) {
  const now = input.now ?? (() => new Date());
  const deps: DelegationDeps = {
    database: input.database, relaycast: input.relaycast, signer: input.signer, gateOnly: input.gateOnly, now,
    quoteKey: input.quoteKey,
  };

  /**
   * The live session row behind a token. Inside a transaction, `lock` takes a
   * share lock on it, so a concurrent revocation (an UPDATE of that row)
   * serializes with whatever the transaction commits.
   */
  async function sessionFacts(token: string, executor: SqlExecutor = input.database, lock = false): Promise<SessionFacts | null> {
    return (await executor.query<SessionFacts>(
      `SELECT created_at, desktop_host_name, desktop_verified_at, desktop_exchange_challenge,
              provisioned_by_token_id, scopes
         FROM token_sessions WHERE access_token_hash = $1 AND revoked_at IS NULL AND access_token_expires_at > now()
         ${lock ? "FOR SHARE" : ""}`,
      [hashSecret(token)],
    )).rows[0] ?? null;
  }

  /** A redeemed browser-consent Desktop sign-in (Cloud's isVerifiedDesktopSignInBearer). */
  function desktopVerified(facts: SessionFacts | null, allowProvisioned: boolean): boolean {
    return Boolean(facts && facts.desktop_host_name && facts.desktop_verified_at && !facts.desktop_exchange_challenge
      && facts.scopes.includes("cli:auth") && !facts.scopes.includes("mcp:desktop")
      && (allowProvisioned || !facts.provisioned_by_token_id));
  }

  /**
   * A current member of `workspaceId`, which must be the workspace the
   * credential was issued for (as every other relay-control workspace route
   * requires), or 403 forbidden.
   */
  async function memberWorkspace(principal: Principal, workspaceId: string) {
    if (principal.workspaceId !== workspaceId) return fail("forbidden", "Forbidden", 403);
    const workspace = await input.workspaceForUser(workspaceId, principal.userId).catch(() => null);
    if (!workspace || workspace.organizationId !== principal.organizationId) return fail("forbidden", "Forbidden", 403);
    return workspace;
  }

  /** Human-only routes: browser account session or Desktop-verified bearer, never an agent or plain CLI token. */
  async function human(request: IncomingMessage, publicPath: string, workspaceId: string,
    options: { write: boolean }): Promise<Human> {
    const headerToken = bearer(request);
    let principal: Principal | null;
    let authMethod: AuthMethod;
    if (headerToken) {
      principal = await input.authenticateAccessToken(headerToken);
      if (!principal) return fail("unauthorized", "Unauthorized", 401);
      if (!desktopVerified(await sessionFacts(headerToken), false)) fail("forbidden", "Forbidden", 403);
      authMethod = "desktop_bearer";
    } else {
      const cookie = publicPath.startsWith("/cloud/") ? controlSessionToken(request.headers.cookie) : null;
      principal = cookie ? await input.authenticateAccessToken(cookie) : null;
      if (!principal) return fail("unauthorized", "Unauthorized", 401);
      if (!principal.scopes.includes(ACCOUNT_SCOPE) || principal.pendingHandoff || principal.handoff) {
        fail("forbidden", "Forbidden", 403);
      }
      if (options.write && !cookieRequestAllowed(request, input.browserOrigins)) {
        fail("csrf_rejected", "Cross-origin request refused", 403);
      }
      authMethod = "session";
    }
    const workspace = await memberWorkspace(principal, workspaceId);
    return { principal, workspace, authMethod, admin: workspace.role === "owner" || workspace.role === "admin" };
  }

  /** Attest, redeem, prompt-delegates: the recipient owner's Desktop-verified bearer (Cloud's desktopBearer). */
  async function desktopCaller(request: IncomingMessage, workspaceId: string) {
    const token = bearer(request);
    if (!token) return fail("unauthorized", "Unauthorized", 401);
    const principal = await input.authenticateAccessToken(token);
    if (!principal) return fail("unauthorized", "Unauthorized", 401);
    if (!desktopVerified(await sessionFacts(token), true)) fail("forbidden", "Forbidden", 403);
    const workspace = await memberWorkspace(principal, workspaceId);
    return { principal, workspace,
      stillAuthorized: async (executor?: SqlExecutor) => desktopVerified(await sessionFacts(token, executor, Boolean(executor)), true) };
  }

  /**
   * `/orgs/{org}/delegation-policy` (Cloud's orgAdminCaller): a browser
   * session or a Desktop-verified bearer of an active owner or admin of that
   * org, read now. A token acts only in the organization it was issued for.
   */
  async function orgAdmin(request: IncomingMessage, publicPath: string, organizationId: string,
    write: boolean): Promise<{ userId: string; authMethod: AuthMethod }> {
    const headerToken = bearer(request);
    let principal: Principal | null;
    let authMethod: AuthMethod;
    if (headerToken) {
      principal = await input.authenticateAccessToken(headerToken);
      if (!principal) return fail("unauthorized", "Unauthorized", 401);
      if (!desktopVerified(await sessionFacts(headerToken), false)) fail("forbidden", "Forbidden", 403);
      authMethod = "desktop_bearer";
    } else {
      const cookie = publicPath.startsWith("/cloud/") ? controlSessionToken(request.headers.cookie) : null;
      principal = cookie ? await input.authenticateAccessToken(cookie) : null;
      if (!principal) return fail("unauthorized", "Unauthorized", 401);
      if (!principal.scopes.includes(ACCOUNT_SCOPE) || principal.pendingHandoff || principal.handoff) {
        fail("forbidden", "Forbidden", 403);
      }
      if (write && !cookieRequestAllowed(request, input.browserOrigins)) {
        fail("csrf_rejected", "Cross-origin request refused", 403);
      }
      authMethod = "session";
    }
    const role = (await input.database.query<{ role: string }>(
      `SELECT m.role FROM organization_memberships m JOIN organizations o ON o.id = m.organization_id
        WHERE m.organization_id = $1 AND m.user_id = $2`,
      [organizationId, principal.userId],
    )).rows[0]?.role;
    if (principal.organizationId !== organizationId || (role !== "owner" && role !== "admin")) {
      fail("forbidden", "Only org owners and admins can set org delegation policy", 403);
    }
    return { userId: principal.userId, authMethod };
  }

  async function requireEnabled(workspaceId: string): Promise<DelegationPolicy> {
    const policy = await loadPolicy(input.database, workspaceId);
    if (!policy.delegation_enabled) NOT_ENABLED();
    return policy;
  }

  function parse<T>(schema: z.ZodType<T>, body: unknown, error: string): T {
    const parsed = schema.safeParse(body);
    return parsed.success ? parsed.data : fail("invalid_request", error, 400);
  }

  function grantExpiry(value: string | undefined, policy: DelegationPolicy, from: Date): Date {
    const maxDays = Math.min(GRANT_MAX_DAYS, policy.max_expiry_days);
    const max = from.getTime() + maxDays * 86_400_000;
    const at = value ? Date.parse(value) : from.getTime() + Math.min(GRANT_DEFAULT_DAYS, maxDays) * 86_400_000;
    if (at <= from.getTime()) fail("invalid_expiry", "expires_at must be in the future", 400);
    if (at > max) fail("invalid_expiry", `expires_at may be at most ${maxDays} days away`, 400);
    return new Date(at);
  }

  async function route(request: IncomingMessage, response: ServerResponse, path: string, publicPath: string,
    method: string): Promise<boolean> {
    if (path === DELEGATION_JWKS_PATH || path === `/cloud${DELEGATION_JWKS_PATH}`) {
      if (method !== "GET") fail("method_not_allowed", "Method not allowed", 405);
      response.setHeader("cache-control", "public, max-age=300");
      input.json(response, 200, input.signer ? input.signer.jwks() : { keys: [] });
      return true;
    }
    const orgMatch = ORG_POLICY_PATH.exec(path);
    if (orgMatch) {
      if (method !== "GET" && method !== "PUT") fail("method_not_allowed", "Method not allowed", 405);
      let organizationId: string;
      try {
        organizationId = decodeURIComponent(orgMatch[1]!);
      } catch {
        return fail("not_found", "Organization not found", 404);
      }
      if (!UUID.test(organizationId)) fail("not_found", "Organization not found", 404);
      const caller = await orgAdmin(request, publicPath, organizationId, method === "PUT");
      if (method === "GET") {
        input.json(response, 200, await loadOrgPolicy(input.database, organizationId), true);
        return true;
      }
      const body = parse(orgPolicyBody, await readJson(request), "quote_retention_days must be an integer from 1 to 3650");
      const policy = { quote_retention_days: body.quote_retention_days };
      await input.database.transaction(async (tx) => {
        const before = await loadOrgPolicy(tx, organizationId);
        await tx.query(
          `INSERT INTO delegation_org_policies (organization_id, quote_retention_days, updated_by, updated_at)
           VALUES ($1, $2, $3, now())
           ON CONFLICT (organization_id) DO UPDATE SET quote_retention_days = EXCLUDED.quote_retention_days,
             updated_by = EXCLUDED.updated_by, updated_at = now()`,
          [organizationId, policy.quote_retention_days, caller.userId],
        );
        // Logged as org_policy.updated in each of the org's workspaces, as Cloud.
        const workspaces = (await tx.query<{ id: string }>(
          "SELECT id FROM workspaces WHERE organization_id = $1", [organizationId],
        )).rows;
        for (const workspace of workspaces) {
          await recordDelegationAudit(tx, { workspaceId: workspace.id, event: "org_policy.updated",
            actorUserId: caller.userId, authMethod: caller.authMethod,
            data: { organization_id: organizationId, before, after: policy } });
        }
      });
      input.json(response, 200, policy, true);
      return true;
    }
    const match = /^\/api\/v1\/workspaces\/([^/]+)\/(delegates(?:\/(.*))?|messaging\/delegation(\/redeem|\/prompt-delegates|\/withdraw)?)$/.exec(path);
    if (!match) return false;
    let workspaceId: string;
    try {
      workspaceId = decodeURIComponent(match[1]!);
    } catch {
      return fail("invalid_request", "Malformed path", 400);
    }
    const sub = match[3];
    const json = (status: number, body: unknown) => input.json(response, status, body, true);

    // Agent routes ------------------------------------------------------
    if (match[4] === "/withdraw") {
      if (method !== "POST") fail("method_not_allowed", "Method not allowed", 405);
      input.rateLimit(response, `delegation-withdraw:${input.clientKey(request)}`, CLAIM_COMPLETE_RATE);
      const body = parse(withdrawBody, await readJson(request), "Invalid request");
      json(200, await withdrawApproval(body.approval_id, body.delegate_agent_id, body.delegate_token, workspaceId));
      return true;
    }
    if (match[2]!.startsWith("messaging/delegation")) {
      if (method !== "POST") fail("method_not_allowed", "Method not allowed", 405);
      const caller = await desktopCaller(request, workspaceId);
      input.rateLimit(response, `delegation-attest:${caller.principal.userId}`, AGENT_ROUTE_RATE);
      const common = { workspace: caller.workspace, callerUserId: caller.principal.userId };
      if (match[4] === "/prompt-delegates") {
        const body = parse(promptDelegatesBody, await readJson(request), "Invalid request");
        let result;
        try {
          result = await promptDelegates(deps, { ...common, recipientAgentId: body.session_agent_id,
            recipientToken: body.session_token });
        } catch {
          return UNAVAILABLE();
        }
        if (!result) fail("forbidden", "The session is not yours", 403);
        json(200, result);
        return true;
      }
      if (match[4] === "/redeem") {
        const body = parse(redeemBody, await readJson(request), "Invalid request");
        json(200, await redeemApproval(deps, { ...common, recipientAgentId: body.recipient_agent_id,
          recipientToken: body.recipient_token, approvalId: body.approval_id, action: body.action,
          authMethod: "desktop_bearer", stillAuthorized: caller.stillAuthorized }));
        return true;
      }
      const body = parse(attestBody, await readJson(request), "Invalid request");
      json(200, await attestDelegation(deps, { ...common, recipientAgentId: body.recipient_agent_id,
        recipientToken: body.recipient_token, messageId: body.message_id, accept: body.accept ?? "code_owners",
        authMethod: "desktop_bearer", stillAuthorized: caller.stillAuthorized }));
      return true;
    }

    if (sub === "claims/complete") {
      if (method !== "POST") fail("method_not_allowed", "Method not allowed", 405);
      input.rateLimit(response, `delegation-claim:${input.clientKey(request)}`, CLAIM_COMPLETE_RATE);
      const body = parse(claimCompleteBody, await readJson(request), "Invalid claim");
      const workspace = (await input.database.query<{ id: string; relaycast_workspace_id: string | null }>(
        "SELECT id, relaycast_workspace_id FROM workspaces WHERE id::text = $1", [workspaceId],
      )).rows[0];
      if (!workspace) return NOT_ENABLED();
      await requireEnabled(workspace.id);
      // Unknown, used and expired codes look the same.
      const claim = (await input.database.query<{ id: string; user_id: string }>(
        `SELECT id, user_id FROM delegation_claims
          WHERE workspace_id = $1 AND code_hash = $2 AND consumed_at IS NULL AND expires_at > now()`,
        [workspace.id, sha256Hex(body.code)],
      )).rows[0];
      if (!claim) return fail("invalid_code", "Claim code is invalid or expired", 404);
      if (input.gateOnly || !workspace.relaycast_workspace_id) {
        return fail("unavailable", "Messaging is not provisioned for this workspace", 503);
      }
      const relaycastWorkspaceId = workspace.relaycast_workspace_id;
      let agent;
      try {
        agent = await input.relaycast.authenticatedAgent(body.agent_token);
      } catch (error) {
        if (!(error instanceof RelaycastCallError) || ![401, 403, 404].includes(error.status)) return UNAVAILABLE();
        agent = null;
      }
      if (!agent || agent.id !== body.agent_id || (agent.workspaceId && agent.workspaceId !== relaycastWorkspaceId)) {
        return fail("invalid_agent", "The agent token does not prove this agent id", 403);
      }
      const proven = agent;
      // A token proves its own agent, not which relay workspace it lives in:
      // the agent must also exist, with the same id, in this workspace's relay.
      const binding = await input.relaycastBinding(workspace.id);
      const local = binding ? await input.relaycast.getRosterAgent(binding.relaycastApiKey, proven.name).catch(() => null) : null;
      if (!local || local.id !== proven.id || local.status === "released") {
        fail("invalid_agent", "The agent is not part of this workspace's relay", 403);
      }
      if (!await memberRole(input.database, workspace.id, claim.user_id)) {
        fail("invalid_code", "Claim code is invalid or expired", 404);
      }
      if (await anyBinding(input.database, workspace.id, relaycastWorkspaceId, proven.id)) {
        fail("already_bound", "This agent already has a Control binding", 409);
      }
      const bound = await input.database.transaction(async (tx) => {
        if (await anyBinding(tx, workspace.id, relaycastWorkspaceId, proven.id)) return false;
        const consumed = (await tx.query(
          `UPDATE delegation_claims SET consumed_at = now(), agent_id = $2
            WHERE id = $1 AND consumed_at IS NULL AND expires_at > now() RETURNING id`,
          [claim.id, proven.id],
        )).rows[0];
        if (!consumed) return false;
        await tx.query(
          `INSERT INTO delegation_agent_bindings (workspace_id, relaycast_workspace_id, agent_id, agent_name, user_id, claim_id)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [workspace.id, relaycastWorkspaceId, proven.id, proven.name, claim.user_id, claim.id],
        );
        await recordDelegationAudit(tx, {
          workspaceId: workspace.id, event: "delegate.claimed", ownerUserId: claim.user_id, actorAgentId: proven.id,
          authMethod: "agent_token", data: { agent_id: proven.id, claim_method: "code", claim_id: claim.id },
        });
        return true;
      });
      if (!bound) fail("already_bound", "The claim was used, or this agent is already claimed", 409);
      json(200, { claim_id: claim.id, agent_id: proven.id, owner_id: claim.user_id });
      return true;
    }

    // Human-only routes ------------------------------------------------
    const caller = await human(request, publicPath, workspaceId, { write: method !== "GET" });
    const { principal, workspace } = caller;
    const actor = { actorUserId: principal.userId, authMethod: caller.authMethod };

    if (sub === undefined) {
      if (method === "GET") {
        const all = new URL(request.url ?? "/", "http://localhost").searchParams.get("all") === "1";
        if (all && !caller.admin) fail("forbidden", "Only org owners and admins can list every grant", 403);
        const rows = (await input.database.query<GrantRow>(
          `SELECT * FROM delegation_grants WHERE workspace_id = $1 AND ($2::boolean OR owner_user_id = $3)
            ORDER BY created_at DESC`,
          [workspace.id, all, principal.userId],
        )).rows;
        const at = now();
        json(200, { grants: rows.map(row => grantView(row, at)) });
        return true;
      }
      if (method !== "POST") fail("method_not_allowed", "Method not allowed", 405);
      const body = parse(createGrantBody, await readJson(request), "Invalid grant");
      const policy = await requireEnabled(workspace.id);
      const scopes: Scope[] = body.scopes.map(scope => ({ class: scope.class, targets: [...new Set(scope.targets)] }));
      policyRefusal(scopes.map(scope => scope.class), policy);
      const expiresAt = grantExpiry(body.expires_at, policy, now());
      // The delegate must have exactly one Control binding, owned by this
      // person. A name is never accepted, only the immutable agent id.
      const binding = await resolveBinding(input.database, workspace.id, workspace.relaycastWorkspaceId,
        body.delegate_agent_id, true);
      if (!binding || binding.userId !== principal.userId) {
        fail("not_delegate", "The agent must be bound to you; claim it first", 403);
      }
      const requireTierO = uniqueClasses(body.require_tier_o);
      let row: GrantRow;
      try {
        row = await input.database.transaction(async (tx) => {
          // Serialize with policy writers: lock the policy row and check the
          // committed policy, so a concurrent policy change cannot miss this grant.
          const locked = (await tx.query("SELECT 1 FROM delegation_policies WHERE workspace_id = $1 FOR UPDATE",
            [workspace.id])).rows.length > 0;
          const current = await loadPolicy(tx, workspace.id);
          if (!locked || !current.delegation_enabled) NOT_ENABLED();
          policyRefusal(scopes.map(scope => scope.class), current);
          if (expiresAt.getTime() > now().getTime() + Math.min(GRANT_MAX_DAYS, current.max_expiry_days) * 86_400_000) {
            fail("invalid_expiry", `expires_at may be at most ${Math.min(GRANT_MAX_DAYS, current.max_expiry_days)} days away`, 400);
          }
          await expireLapsed(tx, workspace.id, principal.userId, binding!.agentId);
          const existing = await tx.query(
            `SELECT 1 FROM delegation_grants
              WHERE workspace_id = $1 AND owner_user_id = $2 AND delegate_agent_id = $3 AND status = 'active'`,
            [workspace.id, principal.userId, binding!.agentId],
          );
          if (existing.rows.length) throw new GrantConflict();
          const created = (await tx.query<GrantRow>(
            `INSERT INTO delegation_grants
               (id, workspace_id, organization_id, owner_user_id, delegate_agent_id, delegate_agent_name,
                scopes, require_tier_o, expires_at, created_auth_method)
             VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10) RETURNING *`,
            [mintId("grt"), workspace.id, workspace.organizationId, principal.userId, binding!.agentId, binding!.name,
              JSON.stringify(scopes), requireTierO, expiresAt, caller.authMethod],
          )).rows[0]!;
          await recordDelegationAudit(tx, {
            workspaceId: workspace.id, event: "grant.created", ...actor, ownerUserId: principal.userId, grantId: created.id,
            data: { delegate_agent_id: binding!.agentId, scope_diff: { added: scopes, removed: [] },
              require_tier_o: requireTierO, expires_at: expiresAt.toISOString() },
          });
          return created;
        });
      } catch (error) {
        if (error instanceof DelegationHttpError) throw error;
        if (error instanceof GrantConflict || (error as { code?: string })?.code === "23505") {
          return fail("grant_exists", "This agent already has an active grant; narrow it or revoke it first", 409);
        }
        throw error;
      }
      json(201, grantView(row, now()));
      return true;
    }

    if (sub === "revoke-all") {
      if (method !== "POST") fail("method_not_allowed", "Method not allowed", 405);
      const raw = await readJson(request);
      const body = parse(revokeAllBody, raw === undefined ? {} : raw, "Invalid request");
      if (body.all && !caller.admin) fail("forbidden", "Only org owners and admins can revoke every grant", 403);
      const revoked = await input.database.transaction(tx => revokeAllGrants(tx, {
        workspaceId: workspace.id, ownerUserId: body.all ? null : principal.userId, actorUserId: principal.userId,
        reason: body.all ? "admin_revoke_all" : "owner_revoke_all", authMethod: caller.authMethod,
      }));
      json(200, { revoked });
      return true;
    }

    if (sub === "claims") {
      if (method !== "POST") fail("method_not_allowed", "Method not allowed", 405);
      await requireEnabled(workspace.id);
      const id = mintId("clm");
      const code = newClaimCode();
      const expiresAt = new Date(now().getTime() + CLAIM_TTL_MS);
      await input.database.query(
        `INSERT INTO delegation_claims (id, workspace_id, user_id, code_hash, expires_at) VALUES ($1, $2, $3, $4, $5)`,
        [id, workspace.id, principal.userId, sha256Hex(code), expiresAt],
      );
      json(201, { claim_id: id, code, expires_at: expiresAt.toISOString() });
      return true;
    }

    if (sub?.startsWith("approvals/") && !sub.slice(10).includes("/")) {
      if (method !== "DELETE") fail("method_not_allowed", "Method not allowed", 405);
      const approvalId = sub.slice(10);
      if (!APPROVAL_ID.test(approvalId)) fail("not_found", "Approval not found", 404);
      // Revoking one approval (tier D or tier O): its owner, or an org owner or
      // admin. Allowed while delegation is off; revoking only narrows.
      const approval = (await input.database.query<{ id: string; owner_user_id: string; invalidated_at: Date | null }>(
        "SELECT id, owner_user_id, invalidated_at FROM delegation_approvals WHERE id = $1 AND workspace_id = $2",
        [approvalId, workspace.id],
      )).rows[0];
      if (!approval || (approval.owner_user_id !== principal.userId && !caller.admin)) fail("not_found", "Approval not found", 404);
      await input.database.transaction(async (tx) => {
        const updated = (await tx.query(
          "UPDATE delegation_approvals SET invalidated_at = now() WHERE id = $1 AND invalidated_at IS NULL RETURNING id",
          [approvalId],
        )).rows.length > 0;
        if (updated) {
          await recordDelegationAudit(tx, { workspaceId: workspace.id, event: "approval.revoked", ...actor,
            ownerUserId: approval!.owner_user_id, approvalId,
            reason: approval!.owner_user_id === principal.userId ? "owner_revoked" : "admin_revoked" });
        }
      });
      json(200, { approval_id: approvalId, revoked: true });
      return true;
    }

    if (sub === "approvals") {
      if (method !== "POST") fail("method_not_allowed", "Method not allowed", 405);
      const body = parse(mintBody, await readJson(request), "Invalid approval");
      const policy = await requireEnabled(workspace.id);
      const actions = body.actions.map(canonicalAction);
      // The recipient's own delegation settings are never delegable (§5.3); checked first, as Cloud.
      if (actions.some(action => action.class === "config_change" &&
          NEVER_DELEGABLE_SETTINGS.includes(configTarget(action.target)?.setting ?? ""))) {
        fail("out_of_scope", "Delegation settings themselves are never delegable", 403);
      }
      policyRefusal(actions.map(action => action.class), policy);
      const from = now().getTime();
      const expiresAt = body.expires_at ? Date.parse(body.expires_at) : from + APPROVAL_DEFAULT_MS;
      if (expiresAt <= from) fail("invalid_expiry", "expires_at must be in the future", 400);
      if (expiresAt > from + APPROVAL_MAX_MS) fail("invalid_expiry", "expires_at may be at most 24 hours away", 400);
      const singleUse = body.single_use === true || actions.some(highRisk);
      const id = mintId("apv");
      await input.database.transaction(async (tx) => {
        await tx.query(
          `INSERT INTO delegation_approvals (id, workspace_id, owner_user_id, tier, actions, single_use, expires_at)
           VALUES ($1, $2, $3, 'O', $4::jsonb, $5, $6)`,
          [id, workspace.id, principal.userId, JSON.stringify(actions), singleUse, new Date(expiresAt)],
        );
        await recordDelegationAudit(tx, {
          workspaceId: workspace.id, event: "approval.minted", ...actor, ownerUserId: principal.userId, approvalId: id,
          data: { actions, single_use: singleUse, expires_at: new Date(expiresAt).toISOString() },
        });
      });
      json(201, { approval_id: id });
      return true;
    }

    if (sub === "audit") {
      if (method !== "GET") fail("method_not_allowed", "Method not allowed", 405);
      const params = new URL(request.url ?? "/", "http://localhost").searchParams;
      const since = params.get("since");
      if (since && !Number.isFinite(Date.parse(since))) fail("invalid_request", "since must be a timestamp", 400);
      const grantId = params.get("grant_id");
      if (grantId && !GRANT_ID.test(grantId)) fail("invalid_request", "Invalid grant_id", 400);
      // Resume after an event id, as Cloud: `?after_id=<last event id>`.
      // Events are returned in id order and a page never runs past an event
      // that could still be committing (listAuditPage's watermark), so
      // resuming after the last id never skips an event committed out of
      // id order.
      const after = params.get("after_id");
      if (after !== null && !/^(0|[1-9][0-9]{0,15})$/.test(after)) fail("invalid_request", "after_id must be an event id", 400);
      const format = params.get("format") ?? "json";
      if (format !== "json" && format !== "jsonl") fail("invalid_request", "format is json or jsonl", 400);
      const limit = Math.min(MAX_AUDIT_EVENTS,
        Math.max(1, Number.parseInt(params.get("limit") ?? `${MAX_AUDIT_EVENTS}`, 10) || MAX_AUDIT_EVENTS));
      await redactExpiredQuotes(input.database);
      const events = (await listAuditPage(input.database, {
        workspaceId: workspace.id, all: caller.admin, viewerUserId: principal.userId, since: since || null,
        grantId: grantId || null, limit, afterId: after,
      })).map(auditView);
      if (format === "jsonl") {
        response.writeHead(200, { "content-type": "application/x-ndjson; charset=utf-8", "cache-control": "no-store" });
        response.end(events.map(event => JSON.stringify(event)).join("\n") + (events.length ? "\n" : ""));
        return true;
      }
      json(200, { events });
      return true;
    }

    if (sub === "policy") {
      if (method !== "PUT") fail("method_not_allowed", "Method not allowed", 405);
      if (!caller.admin) fail("forbidden", "Only org owners and admins can set delegation policy", 403);
      const body = parse(policyBody, await readJson(request), "Invalid policy");
      // Cloud's PUT replaces the policy: omitted optional fields take their defaults.
      const next: DelegationPolicy = {
        delegation_enabled: body.delegation_enabled,
        max_expiry_days: body.max_expiry_days ?? GRANT_MAX_DAYS,
        allowed_classes: body.allowed_classes ? uniqueClasses(body.allowed_classes) : null,
        require_tier_o: uniqueClasses(body.require_tier_o),
        code_owner_match: body.code_owner_match ?? "any_path",
      };
      const revoked = await input.database.transaction(async (tx) => {
        // Serialize policy writers and grant creation on the workspace row
        // (this also covers the first insert of the policy row).
        // FOR NO KEY UPDATE: serializes policy writers without blocking the
        // key-share lock a grant insert takes on the workspace for its foreign
        // key (FOR UPDATE would conflict with it and could deadlock).
        await tx.query("SELECT 1 FROM workspaces WHERE id = $1 FOR NO KEY UPDATE", [workspace.id]);
        await tx.query("SELECT 1 FROM delegation_policies WHERE workspace_id = $1 FOR UPDATE", [workspace.id]);
        const before = await loadPolicy(tx, workspace.id);
        await tx.query(
          `INSERT INTO delegation_policies
             (workspace_id, delegation_enabled, max_expiry_days, allowed_classes, require_tier_o, code_owner_match,
              updated_by, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, now())
           ON CONFLICT (workspace_id) DO UPDATE SET delegation_enabled = EXCLUDED.delegation_enabled,
             max_expiry_days = EXCLUDED.max_expiry_days, allowed_classes = EXCLUDED.allowed_classes,
             require_tier_o = EXCLUDED.require_tier_o, code_owner_match = EXCLUDED.code_owner_match,
             updated_by = EXCLUDED.updated_by, updated_at = now()`,
          [workspace.id, next.delegation_enabled, next.max_expiry_days, next.allowed_classes, next.require_tier_o,
            next.code_owner_match, principal.userId],
        );
        await recordDelegationAudit(tx, { workspaceId: workspace.id, event: "policy.updated", ...actor,
          data: { before, after: next } });
        // §7: an active grant the new policy no longer admits is revoked.
        const active = (await tx.query<GrantRow>(
          "SELECT * FROM delegation_grants WHERE workspace_id = $1 AND status = 'active' FOR UPDATE", [workspace.id],
        )).rows;
        const misfits = active.filter(grant =>
          (next.allowed_classes && grant.scopes.some(scope => !next.allowed_classes!.includes(scope.class))) ||
          time(grant.expires_at) - time(grant.created_at) > next.max_expiry_days * 86_400_000 + 60_000);
        return revokeGrants(tx, { workspaceId: workspace.id, grantIds: misfits.map(grant => grant.id),
          actorUserId: principal.userId, reason: "policy_changed", authMethod: caller.authMethod });
      });
      json(200, { ...next, revoked_grants: revoked.map(row => row.id) });
      return true;
    }

    if (sub === "target-owners") {
      if (method !== "GET" && method !== "PUT") fail("method_not_allowed", "Method not allowed", 405);
      if (!caller.admin) {
        fail("forbidden", `Only org owners and admins can ${method === "GET" ? "read" : "set"} target owners`, 403);
      }
      if (method === "GET") {
        json(200, await loadTargetOwners(input.database, workspace.id));
        return true;
      }
      const entries = parse(targetOwnersBody, await readJson(request), "Invalid target owners")
        .map(entry => ({ pattern: entry.pattern, ...(entry.repo ? { repo: entry.repo } : {}),
          ...(entry.owner_ids ? { owner_ids: [...new Set(entry.owner_ids)] } : {}) }));
      await requireEnabled(workspace.id);
      await input.database.transaction(async (tx) => {
        await tx.query("DELETE FROM delegation_target_owners WHERE workspace_id = $1", [workspace.id]);
        for (const [position, entry] of entries.entries()) {
          await tx.query(
            `INSERT INTO delegation_target_owners (workspace_id, position, pattern, repo, owner_ids, updated_by)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [workspace.id, position, entry.pattern, entry.repo ?? null, entry.owner_ids ?? null, principal.userId],
          );
        }
        await recordDelegationAudit(tx, { workspaceId: workspace.id, event: "target_owners.updated", ...actor,
          data: { entries } });
      });
      json(200, entries);
      return true;
    }

    // /delegates/{grant_id}: PATCH and DELETE, as Cloud.
    if (sub !== undefined && !sub.includes("/")) {
      if (method === "DELETE") {
        if (!GRANT_ID.test(sub)) fail("not_found", "Grant not found", 404);
        const grant = await grantFor(workspace.id, sub);
        if (!grant || (grant.owner_user_id !== principal.userId && !caller.admin)) fail("not_found", "Grant not found", 404);
        const own = grant!.owner_user_id === principal.userId;
        await input.database.transaction(tx => revokeGrants(tx, {
          workspaceId: workspace.id, grantIds: [grant!.id], actorUserId: principal.userId,
          reason: own ? "owner_revoked" : "admin_revoked", authMethod: caller.authMethod,
        }));
        json(200, grantView((await grantFor(workspace.id, grant!.id)) ?? grant!, now()));
        return true;
      }
      if (method !== "PATCH") fail("method_not_allowed", "Method not allowed", 405);
      const body = patchGrantBody.safeParse(await readJson(request));
      if (!body.success || !GRANT_ID.test(sub)) fail("invalid_request", "Invalid grant change", 400);
      const patch = body.data!;
      await requireEnabled(workspace.id);
      const row = await input.database.transaction(async (tx) => {
        // Lock and reread the grant, so concurrent changes apply to the
        // current row and can never restore a narrowed scope or expiry.
        const grant = (await tx.query<GrantRow>(
          "SELECT * FROM delegation_grants WHERE id = $1 AND workspace_id = $2 FOR UPDATE", [sub, workspace.id],
        )).rows[0];
        if (!grant || grant.owner_user_id !== principal.userId) return fail("not_found", "Grant not found", 404);
        const at = now();
        if (grant.status !== "active" || time(grant.expires_at) <= at.getTime()) {
          fail("not_active", "Only an active grant can be changed", 409);
        }
        const scopes: Scope[] | undefined = patch.scopes?.map(scope => ({ class: scope.class, targets: [...new Set(scope.targets)] }));
        const expiresAt = patch.expires_at ? new Date(patch.expires_at) : undefined;
        if (expiresAt && expiresAt.getTime() <= at.getTime()) fail("invalid_expiry", "expires_at must be in the future", 400);
        const requireTierO = patch.require_tier_o ? uniqueClasses(patch.require_tier_o) : undefined;
        narrowingRefusal(grant, { scopes, expiresAt, requireTierO });
        const nextScopes = scopes ?? grant.scopes;
        const nextTierO = requireTierO ?? grant.require_tier_o;
        const nextExpiry = expiresAt ?? new Date(grant.expires_at);
        const updated = (await tx.query<GrantRow>(
          `UPDATE delegation_grants SET scopes = $3::jsonb, expires_at = $4, require_tier_o = $5, updated_at = now()
            WHERE id = $1 AND workspace_id = $2 AND status = 'active' AND expires_at > now() RETURNING *`,
          [grant.id, workspace.id, JSON.stringify(nextScopes), nextExpiry, nextTierO],
        )).rows[0];
        if (!updated) return null;
        const key = (scope: Scope) => scope.targets.map(target => `${scope.class} ${target}`);
        const before = new Set(grant.scopes.flatMap(key));
        const after = new Set(nextScopes.flatMap(key));
        await recordDelegationAudit(tx, {
          workspaceId: workspace.id, event: "grant.updated", ...actor, ownerUserId: grant.owner_user_id, grantId: grant.id,
          data: {
            scope_diff: { removed: [...before].filter(item => !after.has(item)), added: [...after].filter(item => !before.has(item)) },
            require_tier_o: { before: grant.require_tier_o, after: nextTierO },
            expires_at: { before: new Date(grant.expires_at).toISOString(), after: nextExpiry.toISOString() },
          },
        });
        return updated;
      });
      if (!row) fail("not_active", "Only an active grant can be changed", 409);
      json(200, grantView(row!, now()));
      return true;
    }
    return fail("not_found", "Route not found", 404);
  }

  /**
   * POST .../messaging/delegation/withdraw (§7): the delegate that sent an
   * approval withdraws it, proven by its own Relaycast token (and its presence
   * in this workspace's relay), so the next attest or redeem is `revoked`.
   * Withdrawing only ever narrows, so no person's credential is needed, as for
   * claims/complete.
   */
  async function withdrawApproval(approvalId: string, delegateAgentId: string, delegateToken: string, workspaceId: string) {
    const workspace = (await input.database.query<{ id: string }>(
      "SELECT id FROM workspaces WHERE id::text = $1", [workspaceId],
    )).rows[0];
    if (!workspace) return fail("not_found", "Approval not found", 404);
    const binding = await input.relaycastBinding(workspace.id);
    if (input.gateOnly || !binding) return UNAVAILABLE();
    let agent;
    try {
      agent = await input.relaycast.authenticatedAgent(delegateToken);
    } catch (error) {
      if (!(error instanceof RelaycastCallError) || ![401, 403, 404].includes(error.status)) return UNAVAILABLE();
      agent = null;
    }
    if (!agent || agent.id !== delegateAgentId) return fail("invalid_agent", "The agent token does not prove this agent id", 403);
    const local = await input.relaycast.getRosterAgent(binding.relaycastApiKey, agent.name).catch(() => null);
    if (!local || local.id !== agent.id) return fail("invalid_agent", "The agent is not part of this workspace's relay", 403);
    // Only an approval this delegate sent: one attested from it.
    const sent = (await input.database.query<{ owner_user_id: string }>(
      `SELECT a.owner_user_id FROM delegation_approvals a
        WHERE a.id = $1 AND a.workspace_id = $2
          AND EXISTS (SELECT 1 FROM delegation_attestations t WHERE t.approval_id = a.id AND t.delegate_agent_id = $3)`,
      [approvalId, workspace.id, agent.id],
    )).rows[0];
    if (!sent) return fail("not_found", "Approval not found", 404);
    await input.database.transaction(async (tx) => {
      const updated = (await tx.query(
        "UPDATE delegation_approvals SET invalidated_at = now() WHERE id = $1 AND invalidated_at IS NULL RETURNING id",
        [approvalId],
      )).rows.length > 0;
      if (updated) {
        await recordDelegationAudit(tx, { workspaceId: workspace.id, event: "approval.withdrawn", actorAgentId: agent!.id,
          authMethod: "agent_token", ownerUserId: sent.owner_user_id, approvalId, reason: "delegate_withdrew" });
      }
    });
    return { ok: true };
  }

  async function grantFor(workspaceId: string, grantId: string): Promise<GrantRow | null> {
    return (await input.database.query<GrantRow>(
      "SELECT * FROM delegation_grants WHERE id = $1 AND workspace_id = $2", [grantId, workspaceId],
    )).rows[0] ?? null;
  }

  /**
   * Every route answers a refusal as Cloud does: `{error: <message>, code}`
   * with no-store, and an unexpected failure as 503 `unavailable`.
   */
  return async function handleDelegation(request: IncomingMessage, response: ServerResponse,
    path: string, publicPath: string, method: string): Promise<boolean> {
    if (!isDelegationPath(path)) return false;
    try {
      return await route(request, response, path, publicPath, method);
    } catch (error) {
      if (response.headersSent) throw error;
      // DelegationHttpError, and the app's rate limiter (429 rate_limited).
      const known = error as { status?: unknown; code?: unknown; message?: unknown };
      if (error instanceof DelegationHttpError || (typeof known?.status === "number" && typeof known.code === "string")) {
        input.json(response, known.status as number, { error: String(known.message), code: known.code }, true);
        return true;
      }
      input.json(response, 503, { error: "Delegation is unavailable", code: "unavailable" }, true);
      return true;
    }
  };
}

class GrantConflict extends Error {}

/**
 * PATCH may only narrow (Cloud's narrowingRefusal): every new pattern sits
 * inside an old pattern of the same class, expiry does not move later, and
 * Tier O requirements are only added.
 */
function narrowingRefusal(grant: GrantRow, patch: { scopes?: Scope[]; expiresAt?: Date; requireTierO?: ActionClass[] }): void {
  const widen = (error: string) => fail("widening_not_allowed", error, 400);
  for (const scope of patch.scopes ?? []) {
    const old = grant.scopes.find(item => item.class === scope.class);
    if (!old) widen(`Grant does not cover class ${scope.class}; create a new grant to widen`);
    for (const target of scope.targets) {
      if (!old!.targets.some(pattern => classTargetCovered(scope.class, pattern, target, true))) {
        widen(`Target ${target} is not inside the grant; create a new grant to widen`);
      }
    }
  }
  if (patch.expiresAt && patch.expiresAt.getTime() > time(grant.expires_at)) widen("expires_at may only move earlier");
  if (patch.requireTierO && grant.require_tier_o.some(item => !patch.requireTierO!.includes(item))) {
    widen("require_tier_o may only gain classes");
  }
}
