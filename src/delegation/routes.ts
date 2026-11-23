import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import { cookieRequestAllowed } from "../auth/device-approval.js";
import { bearer } from "../auth/bearer.js";
import { controlSessionToken } from "../auth/session-cookie.js";
import { hashSecret } from "../crypto.js";
import type { Database } from "../database.js";
import { MessagingHttpError } from "../messaging/http.js";
import { RelaycastCallError, type RelaycastClient } from "../messaging/relaycast.js";
import { ACCOUNT_SCOPE, type Principal } from "../store.js";
import { DELEGATION_JWKS_PATH, type DelegationSigner } from "./jws.js";
import {
  ACTION_CLASSES,
  actionClass,
  actionSchema,
  APPROVAL_DEFAULT_MS,
  APPROVAL_MAX_MS,
  CLAIM_TTL_MS,
  GRANT_DEFAULT_DAYS,
  GRANT_MAX_DAYS,
  classTargetCovered,
  highRisk,
  MAX_ACTIONS,
  canonicalAction,
  validPromptPattern,
  validTargetPattern,
  type ActionClass,
  type Scope,
} from "./scope.js";
import {
  anyBinding,
  attestDelegation,
  claimCodeHash,
  grantView,
  loadPolicy,
  loadTargetOwners,
  memberRole,
  newApprovalId,
  newClaimCode,
  newClaimId,
  newGrantId,
  recordDelegationAudit,
  redactExpiredQuotes,
  promptDelegates,
  redeemApproval,
  resolveBinding,
  revokeGrants,
  type DelegationDeps,
  type DelegationWorkspace,
  type GrantRow,
} from "./service.js";

/**
 * HTTP surface for owner-named trusted delegates (relay
 * docs/design/owner-trusted-delegates.md §16.3), the self-hosted twin of
 * Cloud's. See docs/owner-delegates.md.
 *
 * Human-only routes take the browser account session (the /cloud cookie,
 * signed in within 15 minutes for writes other than revocation) or a
 * Desktop-verified bearer (a redeemed browser-consent Desktop sign-in). A
 * device-flow CLI login, an enrollment-key session, a workspace API token
 * and any agent token are refused.
 *
 * Agent routes prove the agent with its own Relaycast token. Attest and
 * redeem also take the recipient owner's Desktop-verified bearer, exactly
 * as Cloud's native-authority route does.
 */

const STEP_UP_MS = 15 * 60 * 1000;
const CLAIM_COMPLETE_RATE = { limit: 20, windowMs: 60_000 };
const AGENT_ROUTE_RATE = { limit: 120, windowMs: 60_000 };
const AUDIT_LIMIT = 1000;

type JsonWriter = (response: ServerResponse, status: number, body: unknown, noStore?: boolean) => void;

export type DelegationRoutesInput = {
  database: Database;
  relaycast: RelaycastClient;
  signer: DelegationSigner | null;
  gateOnly: boolean;
  browserOrigins: readonly string[];
  authenticateAccessToken: (token: string) => Promise<Principal | null>;
  workspaceForUser: (workspaceId: string, userId: string) => Promise<{
    id: string; organizationId: string; relaycastWorkspaceId: string; relaycastApiKey: string; role: Principal["role"];
  } | null>;
  requestObject: (request: IncomingMessage) => Promise<Record<string, unknown>>;
  json: JsonWriter;
  rateLimit: (response: ServerResponse, key: string, rule: { limit: number; windowMs: number }) => void;
  clientKey: (request: IncomingMessage) => string;
  now?: () => Date;
};

type Human = {
  principal: Principal;
  workspace: DelegationWorkspace & { role: Principal["role"] };
  authMethod: "browser" | "desktop";
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

const fail = (status: number, code: string, message: string): never => {
  throw new MessagingHttpError(status, code, message);
};

const rfc3339 = z.string().max(64).refine(value => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/i.test(value)
  && Number.isFinite(Date.parse(value)));
const classList = z.array(actionClass).max(ACTION_CLASSES.length);
const scopeSchema = z.object({
  class: actionClass,
  targets: z.array(z.string().refine(validTargetPattern, { message: "invalid target pattern" })).min(1).max(32),
}).strict().refine(scope => scope.class !== "prompt_approval" || scope.targets.every(validPromptPattern),
  { message: "prompt_approval targets are * or <agent id>:*" });
const scopesSchema = z.array(scopeSchema).min(1).max(ACTION_CLASSES.length)
  .refine(scopes => new Set(scopes.map(scope => scope.class)).size === scopes.length, { message: "one scope per class" });

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
}).strict().refine(body => Object.keys(body).length > 0, { message: "nothing to change" });
const revokeAllBody = z.object({ all: z.boolean().optional() }).strict();
const mintBody = z.object({
  actions: z.array(actionSchema).min(1).max(MAX_ACTIONS),
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
const targetOwnersBody = z.array(z.object({
  pattern: z.string().refine(validTargetPattern, { message: "invalid target pattern" }),
  repo: z.string().regex(/^[^/:#\s*]+\/[^/:#\s*]+$/).optional(),
  owner_ids: z.array(z.string().uuid()).min(1).max(50).optional(),
}).strict().refine(entry => (entry.repo === undefined) !== (entry.owner_ids === undefined),
  { message: "exactly one of repo or owner_ids" })).max(200);
const claimCompleteBody = z.object({
  code: z.string().min(8).max(64),
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
  accept: z.enum(["code_owners", "own_owner"]),
}).strict();
const promptDelegatesBody = z.object({
  session_agent_id: z.string().min(1).max(200),
  session_token: z.string().min(12).max(512),
}).strict();
const redeemBody = z.object({
  ...recipientFields,
  approval_id: z.string().regex(/^apv_[A-Za-z0-9]{8,64}$/),
  action: z.object({ class: actionClass, target: z.string().min(1).max(256) }).strict(),
}).strict();

function parse<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    return fail(400, "invalid_request", issue ? `${issue.path.join(".") || "body"}: ${issue.message}` : "Invalid request");
  }
  return parsed.data;
}

/** A JSON body that may be an array (PUT target-owners takes a bare list). */
async function jsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > 256 * 1024) fail(413, "payload_too_large", "Body exceeds 256 KiB");
    chunks.push(buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "null") as unknown;
  } catch {
    return fail(400, "invalid_request", "Body must be valid JSON");
  }
}

function uniqueClasses(values: readonly ActionClass[] | undefined): ActionClass[] {
  return [...new Set(values ?? [])];
}

export function isDelegationPath(path: string): boolean {
  return path === DELEGATION_JWKS_PATH || path === `/cloud${DELEGATION_JWKS_PATH}`
    || /^\/api\/v1\/workspaces\/[^/]+\/(delegates(\/.*)?|messaging\/delegation(\/redeem|\/prompt-delegates)?)$/.test(path);
}

export function createDelegationHandler(input: DelegationRoutesInput) {
  const now = input.now ?? (() => new Date());
  const deps: DelegationDeps = {
    database: input.database, relaycast: input.relaycast, signer: input.signer, gateOnly: input.gateOnly, now,
  };

  async function sessionFacts(token: string): Promise<SessionFacts | null> {
    return (await input.database.query<SessionFacts>(
      `SELECT created_at, desktop_host_name, desktop_verified_at, desktop_exchange_challenge,
              provisioned_by_token_id, scopes
         FROM token_sessions WHERE access_token_hash = $1 AND revoked_at IS NULL AND access_token_expires_at > now()`,
      [hashSecret(token)],
    )).rows[0] ?? null;
  }

  /** A redeemed browser-consent Desktop sign-in (Cloud's isVerifiedDesktopSignInBearer). */
  function desktopVerified(facts: SessionFacts | null, allowProvisioned: boolean): boolean {
    return Boolean(facts && facts.desktop_host_name && facts.desktop_verified_at && !facts.desktop_exchange_challenge
      && facts.scopes.includes("cli:auth") && !facts.scopes.includes("mcp:desktop")
      && (allowProvisioned || !facts.provisioned_by_token_id));
  }

  async function workspaceFor(principal: Principal, workspaceId: string) {
    if (principal.organizationId === undefined) return null;
    const workspace = await input.workspaceForUser(workspaceId, principal.userId);
    if (!workspace || workspace.organizationId !== principal.organizationId) return null;
    return workspace;
  }

  /** Human-only routes: browser account session or Desktop-verified bearer, never an agent or plain CLI token. */
  async function human(request: IncomingMessage, publicPath: string, workspaceId: string,
    options: { write: boolean; stepUp: boolean }): Promise<Human> {
    const headerToken = bearer(request);
    let principal: Principal | null = null;
    let authMethod: Human["authMethod"];
    if (headerToken) {
      principal = await input.authenticateAccessToken(headerToken);
      if (!principal) fail(401, "unauthorized", "Invalid or expired token");
      if (!desktopVerified(await sessionFacts(headerToken), false)) {
        fail(403, "human_session_required", "Delegation is managed only from a browser session or a verified Agent Relay Desktop sign-in");
      }
      authMethod = "desktop";
    } else {
      const cookie = publicPath.startsWith("/cloud/") ? controlSessionToken(request.headers.cookie) : null;
      if (!cookie) return fail(401, "unauthorized", "Authentication required");
      principal = await input.authenticateAccessToken(cookie);
      if (!principal) fail(401, "unauthorized", "Invalid or expired token");
      if (!principal!.scopes.includes(ACCOUNT_SCOPE) || principal!.pendingHandoff || principal!.handoff) {
        fail(403, "human_session_required", "Delegation is managed only from a browser session or a verified Agent Relay Desktop sign-in");
      }
      if (options.write && !cookieRequestAllowed(request, input.browserOrigins)) {
        fail(403, "csrf_rejected", "Cross-origin request refused");
      }
      if (options.stepUp) {
        const facts = await sessionFacts(cookie);
        if (!facts || now().getTime() - new Date(facts.created_at).getTime() > STEP_UP_MS) {
          fail(403, "reauthentication_required", "Sign in again (within the last 15 minutes) to change delegates");
        }
      }
      authMethod = "browser";
    }
    const workspace = await workspaceFor(principal!, workspaceId);
    if (!workspace || principal!.workspaceId !== workspaceId) fail(404, "workspace_not_found", "Workspace not found");
    return {
      principal: principal!,
      workspace: workspace!,
      authMethod: authMethod!,
      admin: workspace!.role === "owner" || workspace!.role === "admin",
    };
  }

  /** Attest and redeem: the recipient owner's Desktop-verified bearer, read live, for a current member. */
  async function desktopCaller(request: IncomingMessage, workspaceId: string) {
    const token = bearer(request);
    if (!token) return fail(401, "unauthorized", "Authentication required");
    const principal = await input.authenticateAccessToken(token);
    if (!principal) return fail(401, "unauthorized", "Invalid or expired token");
    if (!desktopVerified(await sessionFacts(token), true)) fail(403, "forbidden", "A verified Agent Relay Desktop sign-in is required");
    const workspace = await workspaceFor(principal, workspaceId);
    if (!workspace) fail(403, "forbidden", "Not a member of this workspace");
    return { principal, workspace: workspace!, token };
  }

  async function requireEnabled(workspaceId: string) {
    const policy = await loadPolicy(input.database, workspaceId);
    if (!policy.delegation_enabled) fail(403, "not_enabled", "Delegation is turned off for this workspace");
    return policy;
  }

  async function grantFor(workspaceId: string, grantId: string): Promise<GrantRow> {
    const row = (await input.database.query<GrantRow>(
      "SELECT * FROM delegation_grants WHERE id = $1 AND workspace_id = $2", [grantId, workspaceId],
    )).rows[0];
    return row ?? fail(404, "grant_not_found", "Grant not found");
  }

  function expiryWithin(value: string | undefined, maxDays: number, defaultDays: number, from = now()): Date {
    const max = from.getTime() + maxDays * 86_400_000;
    if (value === undefined) return new Date(Math.min(from.getTime() + defaultDays * 86_400_000, max));
    const at = Date.parse(value);
    if (at <= from.getTime()) fail(400, "invalid_request", "expires_at must be in the future");
    if (at > max) fail(400, "invalid_request", `expires_at may be at most ${maxDays} days away`);
    return new Date(at);
  }

  return async function handleDelegation(request: IncomingMessage, response: ServerResponse,
    path: string, publicPath: string, method: string): Promise<boolean> {
    if (path === DELEGATION_JWKS_PATH || path === `/cloud${DELEGATION_JWKS_PATH}`) {
      if (method !== "GET") fail(405, "method_not_allowed", "Method not allowed");
      response.setHeader("cache-control", "public, max-age=300");
      input.json(response, 200, input.signer ? input.signer.jwks() : { keys: [] });
      return true;
    }
    const match = /^\/api\/v1\/workspaces\/([^/]+)\/(delegates(?:\/(.*))?|messaging\/delegation(\/redeem|\/prompt-delegates)?)$/.exec(path);
    if (!match) return false;
    let workspaceId: string;
    try {
      workspaceId = decodeURIComponent(match[1]!);
    } catch {
      return fail(400, "invalid_request", "Malformed path");
    }
    const sub = match[3];
    const json = (status: number, body: unknown) => input.json(response, status, body, true);

    // Agent routes ------------------------------------------------------
    if (match[2]!.startsWith("messaging/delegation")) {
      if (method !== "POST") fail(405, "method_not_allowed", "Method not allowed");
      const caller = await desktopCaller(request, workspaceId);
      input.rateLimit(response, `delegation-attest:${caller.principal.userId}`, AGENT_ROUTE_RATE);
      const workspace = caller.workspace;
      const recheckBearer = async () => desktopVerified(await sessionFacts(caller.token), true);
      if (match[4] === "/prompt-delegates") {
        const body = parse(promptDelegatesBody, await input.requestObject(request));
        json(200, await promptDelegates(deps, {
          workspace, callerUserId: caller.principal.userId, recipientAgentId: body.session_agent_id,
          recipientToken: body.session_token,
        }));
        return true;
      }
      if (match[4]) {
        const body = parse(redeemBody, await input.requestObject(request));
        const result = await redeemApproval(deps, {
          workspace, callerUserId: caller.principal.userId, recipientAgentId: body.recipient_agent_id,
          recipientToken: body.recipient_token, approvalId: body.approval_id, action: body.action,
        });
        json(200, result);
        return true;
      }
      const body = parse(attestBody, await input.requestObject(request));
      const result = await attestDelegation(deps, {
        workspace, callerUserId: caller.principal.userId, recipientAgentId: body.recipient_agent_id,
        recipientToken: body.recipient_token, messageId: body.message_id, accept: body.accept,
      });
      // Token revocation during the Relaycast calls decides the verdict.
      if (result.verdict === "delegate" && !await recheckBearer()) {
        json(200, { verdict: "none", reason: "unavailable" });
        return true;
      }
      json(200, result);
      return true;
    }

    if (sub === "claims/complete") {
      if (method !== "POST") fail(405, "method_not_allowed", "Method not allowed");
      input.rateLimit(response, `delegation-claim:${input.clientKey(request)}`, CLAIM_COMPLETE_RATE);
      const body = parse(claimCompleteBody, await input.requestObject(request));
      if (input.gateOnly) fail(503, "unavailable", "Delegation is not available on a gate-only install");
      const workspace = (await input.database.query<{ id: string; relaycast_workspace_id: string | null }>(
        "SELECT id, relaycast_workspace_id FROM workspaces WHERE id::text = $1", [workspaceId],
      )).rows[0];
      if (!workspace?.relaycast_workspace_id) return fail(404, "claim_not_found", "No pending claim matches that code");
      await requireEnabled(workspace.id);
      const claim = (await input.database.query<{ id: string; user_id: string }>(
        `SELECT id, user_id FROM delegation_claims
          WHERE workspace_id = $1 AND code_hash = $2 AND consumed_at IS NULL AND expires_at > now()`,
        [workspace.id, claimCodeHash(body.code)],
      )).rows[0];
      if (!claim) return fail(404, "claim_not_found", "No pending claim matches that code");
      let agent;
      try {
        agent = await input.relaycast.authenticatedAgent(body.agent_token);
      } catch (error) {
        if (error instanceof RelaycastCallError && [401, 403, 404].includes(error.status)) {
          return fail(403, "agent_not_proven", "The agent token does not prove that agent id");
        }
        return fail(502, "unavailable", "The relay is not reachable right now");
      }
      if (agent.id !== body.agent_id || (agent.workspaceId && agent.workspaceId !== workspace.relaycast_workspace_id)) {
        fail(403, "agent_not_proven", "The agent token does not prove that agent id");
      }
      if (!await memberRole(input.database, workspace.id, claim.user_id)) {
        fail(404, "claim_not_found", "No pending claim matches that code");
      }
      const relaycastWorkspaceId = workspace.relaycast_workspace_id;
      const bound = await input.database.transaction(async (tx) => {
        if (await anyBinding(tx, workspace.id, relaycastWorkspaceId, agent.id)) return "already_bound" as const;
        const consumed = (await tx.query(
          `UPDATE delegation_claims SET consumed_at = now(), agent_id = $2
            WHERE id = $1 AND consumed_at IS NULL AND expires_at > now() RETURNING id`,
          [claim.id, agent.id],
        )).rows[0];
        if (!consumed) return "claim_not_found" as const;
        await tx.query(
          `INSERT INTO delegation_agent_bindings (workspace_id, relaycast_workspace_id, agent_id, agent_name, user_id, claim_id)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [workspace.id, relaycastWorkspaceId, agent.id, agent.name, claim.user_id, claim.id],
        );
        await recordDelegationAudit(tx, {
          workspaceId: workspace.id, event: "delegate.claimed", actorAgentId: agent.id, ownerUserId: claim.user_id,
          details: { agent_id: agent.id, agent_name: agent.name, claim_id: claim.id, method: "claim_code" },
        });
        return "bound" as const;
      });
      if (bound === "already_bound") fail(409, "already_bound", "That agent already has an owner in this workspace");
      if (bound === "claim_not_found") fail(404, "claim_not_found", "No pending claim matches that code");
      json(200, { claim_id: claim.id, owner_id: claim.user_id, agent_id: agent.id, agent_name: agent.name });
      return true;
    }

    // Human-only routes ------------------------------------------------
    const read = method === "GET";
    const revoking = method === "DELETE" || (method === "POST" && sub === "revoke-all");
    const caller = await human(request, publicPath, workspaceId, { write: !read, stepUp: !read && !revoking });
    const { principal, workspace } = caller;
    const actor = { actorUserId: principal.userId, authMethod: caller.authMethod };

    if (sub === undefined) {
      if (method === "GET") {
        const all = new URL(request.url ?? "/", "http://localhost").searchParams.get("all") === "1";
        if (all && !caller.admin) fail(403, "forbidden", "Workspace admin role required");
        const rows = (await input.database.query<GrantRow>(
          `SELECT * FROM delegation_grants WHERE workspace_id = $1 AND ($2::boolean OR owner_user_id = $3)
            ORDER BY created_at DESC LIMIT 500`,
          [workspace.id, all, principal.userId],
        )).rows;
        json(200, { grants: rows.map(row => grantView(row, now())), policy: await loadPolicy(input.database, workspace.id) });
        return true;
      }
      if (method !== "POST") fail(405, "method_not_allowed", "Method not allowed");
      const policy = await requireEnabled(workspace.id);
      const body = parse(createGrantBody, await input.requestObject(request));
      const classes = body.scopes.map(scope => scope.class);
      if (policy.allowed_classes && classes.some(item => !policy.allowed_classes!.includes(item))) {
        fail(403, "class_not_allowed", "The workspace policy does not allow delegating one of these classes");
      }
      const expiresAt = expiryWithin(body.expires_at, Math.min(GRANT_MAX_DAYS, policy.max_expiry_days),
        Math.min(GRANT_DEFAULT_DAYS, policy.max_expiry_days));
      const binding = await resolveBinding(input.database, workspace.id, workspace.relaycastWorkspaceId,
        body.delegate_agent_id, true);
      if (!binding || binding.userId !== principal.userId) {
        fail(409, "delegate_not_bound", "That agent is not bound to you. Bind it first (Desktop, a spawn, or a claim).");
      }
      const scopes: Scope[] = body.scopes.map(scope => ({ class: scope.class, targets: [...new Set(scope.targets)] }));
      const id = newGrantId();
      const row = await input.database.transaction(async (tx) => {
        const created = (await tx.query<GrantRow>(
          `INSERT INTO delegation_grants
             (id, workspace_id, organization_id, owner_user_id, delegate_agent_id, delegate_agent_name,
              scopes, require_tier_o, expires_at, created_auth_method)
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10) RETURNING *`,
          [id, workspace.id, workspace.organizationId, principal.userId, binding!.agentId, binding!.name,
            JSON.stringify(scopes), uniqueClasses(body.require_tier_o), expiresAt, caller.authMethod],
        )).rows[0]!;
        await recordDelegationAudit(tx, {
          workspaceId: workspace.id, event: "grant.created", ...actor, ownerUserId: principal.userId, grantId: id,
          details: { delegate_agent_id: binding!.agentId, scopes, require_tier_o: created.require_tier_o,
            expires_at: expiresAt.toISOString() },
        });
        return created;
      });
      json(201, grantView(row, now()));
      return true;
    }

    if (sub === "revoke-all") {
      if (method !== "POST") fail(405, "method_not_allowed", "Method not allowed");
      const body = parse(revokeAllBody, await input.requestObject(request));
      if (body.all && !caller.admin) fail(403, "forbidden", "Workspace admin role required");
      const revoked = await input.database.transaction(async (tx) => {
        const ids = (await tx.query<{ id: string }>(
          `SELECT id FROM delegation_grants
            WHERE workspace_id = $1 AND revoked_at IS NULL AND ($2::boolean OR owner_user_id = $3) FOR UPDATE`,
          [workspace.id, Boolean(body.all), principal.userId],
        )).rows.map(row => row.id);
        return revokeGrants(tx, { workspaceId: workspace.id, grantIds: ids, actorUserId: principal.userId,
          reason: body.all ? "admin_revoke_all" : "owner_revoke_all", authMethod: caller.authMethod });
      });
      json(200, { revoked: revoked.length, grant_ids: revoked.map(row => row.id) });
      return true;
    }

    if (sub === "claims") {
      if (method !== "POST") fail(405, "method_not_allowed", "Method not allowed");
      await requireEnabled(workspace.id);
      parse(z.object({}).strict(), await input.requestObject(request));
      const id = newClaimId();
      const code = newClaimCode();
      const expiresAt = new Date(now().getTime() + CLAIM_TTL_MS);
      await input.database.query(
        `INSERT INTO delegation_claims (id, workspace_id, user_id, code_hash, expires_at) VALUES ($1, $2, $3, $4, $5)`,
        [id, workspace.id, principal.userId, claimCodeHash(code), expiresAt],
      );
      json(201, { claim_id: id, code, expires_at: expiresAt.toISOString() });
      return true;
    }

    if (sub === "approvals") {
      if (method !== "POST") fail(405, "method_not_allowed", "Method not allowed");
      const policy = await requireEnabled(workspace.id);
      const body = parse(mintBody, await input.requestObject(request));
      if (policy.allowed_classes && body.actions.some(action => !policy.allowed_classes!.includes(action.class))) {
        fail(403, "class_not_allowed", "The workspace policy does not allow delegating one of these classes");
      }
      const from = now();
      const requested = body.expires_at ? Date.parse(body.expires_at) : from.getTime() + APPROVAL_DEFAULT_MS;
      if (requested <= from.getTime()) fail(400, "invalid_request", "expires_at must be in the future");
      if (requested > from.getTime() + APPROVAL_MAX_MS) fail(400, "invalid_request", "expires_at may be at most 24 hours away");
      const actions = body.actions.map(canonicalAction);
      const singleUse = body.single_use === true || actions.some(highRisk);
      const id = newApprovalId();
      await input.database.transaction(async (tx) => {
        await tx.query(
          `INSERT INTO delegation_approvals (id, workspace_id, owner_user_id, tier, actions, single_use, expires_at)
           VALUES ($1, $2, $3, 'O', $4::jsonb, $5, $6)`,
          [id, workspace.id, principal.userId, JSON.stringify(actions), singleUse, new Date(requested)],
        );
        await recordDelegationAudit(tx, {
          workspaceId: workspace.id, event: "approval.minted", ...actor, ownerUserId: principal.userId, approvalId: id,
          details: { actions, single_use: singleUse, expires_at: new Date(requested).toISOString() },
        });
      });
      json(201, { approval_id: id, actions, single_use: singleUse, expires_at: new Date(requested).toISOString() });
      return true;
    }

    if (sub === "audit") {
      if (method !== "GET") fail(405, "method_not_allowed", "Method not allowed");
      const params = new URL(request.url ?? "/", "http://localhost").searchParams;
      const since = params.get("since");
      if (since !== null && !Number.isFinite(Date.parse(since))) fail(400, "invalid_request", "since must be a timestamp");
      const grantId = params.get("grant_id");
      const format = params.get("format");
      if (format !== null && format !== "json" && format !== "jsonl") fail(400, "invalid_request", "format must be json or jsonl");
      await redactExpiredQuotes(input.database);
      const rows = (await input.database.query<Record<string, unknown>>(
        `SELECT id, occurred_at, event, actor_user_id, actor_agent_id, auth_method, owner_user_id, grant_id,
                approval_id, message_id, recipient_agent_id, reason, jti, details, quote, quote_sha256
           FROM delegation_audit_events
          WHERE workspace_id = $1
            AND ($2::boolean OR owner_user_id = $3 OR actor_user_id = $3)
            AND ($4::timestamptz IS NULL OR occurred_at > $4::timestamptz)
            AND ($5::text IS NULL OR grant_id = $5)
          ORDER BY occurred_at, id LIMIT ${AUDIT_LIMIT}`,
        [workspace.id, caller.admin, principal.userId, since, grantId],
      )).rows.map(row => ({ ...row, occurred_at: new Date(row.occurred_at as string).toISOString() }));
      if (format === "jsonl") {
        response.writeHead(200, { "content-type": "application/x-ndjson; charset=utf-8", "cache-control": "no-store" });
        response.end(rows.map(row => JSON.stringify(row)).join("\n") + (rows.length ? "\n" : ""));
        return true;
      }
      json(200, { events: rows });
      return true;
    }

    if (sub === "target-owners") {
      if (method !== "GET" && method !== "PUT") fail(405, "method_not_allowed", "Method not allowed");
      if (!caller.admin) fail(403, "forbidden", "Workspace admin role required");
      const view = (entries: Awaited<ReturnType<typeof loadTargetOwners>>) => entries.map(entry => ({
        pattern: entry.pattern, ...(entry.repo ? { repo: entry.repo } : {}), ...(entry.owner_ids ? { owner_ids: entry.owner_ids } : {}),
      }));
      if (method === "GET") {
        json(200, { target_owners: view(await loadTargetOwners(input.database, workspace.id)) });
        return true;
      }
      await requireEnabled(workspace.id);
      const raw = await jsonBody(request);
      const entries = parse(targetOwnersBody, Array.isArray(raw) ? raw
        : raw && typeof raw === "object" ? (raw as Record<string, unknown>).target_owners : undefined);
      for (const entry of entries) {
        for (const ownerId of entry.owner_ids ?? []) {
          if (!await memberRole(input.database, workspace.id, ownerId)) {
            fail(400, "invalid_request", "owner_ids must name members of this workspace's organization");
          }
        }
      }
      await input.database.transaction(async (tx) => {
        await tx.query("DELETE FROM delegation_target_owners WHERE workspace_id = $1", [workspace.id]);
        for (const [position, entry] of entries.entries()) {
          await tx.query(
            `INSERT INTO delegation_target_owners (workspace_id, position, pattern, repo, owner_ids, updated_by)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [workspace.id, position, entry.pattern, entry.repo ?? null, entry.owner_ids ? [...new Set(entry.owner_ids)] : null,
              principal.userId],
          );
        }
        await recordDelegationAudit(tx, {
          workspaceId: workspace.id, event: "target_owners.updated", ...actor, details: { target_owners: entries },
        });
      });
      json(200, { target_owners: view(await loadTargetOwners(input.database, workspace.id)) });
      return true;
    }

    if (sub === "policy") {
      if (method !== "PUT") fail(405, "method_not_allowed", "Method not allowed");
      if (!caller.admin) fail(403, "forbidden", "Workspace admin role required");
      const body = parse(policyBody, await input.requestObject(request));
      const current = await loadPolicy(input.database, workspace.id);
      const next = {
        delegation_enabled: body.delegation_enabled,
        max_expiry_days: body.max_expiry_days ?? current.max_expiry_days,
        allowed_classes: body.allowed_classes === undefined ? current.allowed_classes
          : body.allowed_classes === null ? null : uniqueClasses(body.allowed_classes),
        require_tier_o: body.require_tier_o === undefined ? current.require_tier_o : uniqueClasses(body.require_tier_o),
        code_owner_match: body.code_owner_match ?? current.code_owner_match,
      };
      const revoked = await input.database.transaction(async (tx) => {
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
        await recordDelegationAudit(tx, {
          workspaceId: workspace.id, event: "policy.updated", ...actor, details: { before: current, after: next },
        });
        // §7: a grant that no longer fits the policy is revoked.
        const live = (await tx.query<GrantRow>(
          "SELECT * FROM delegation_grants WHERE workspace_id = $1 AND revoked_at IS NULL FOR UPDATE", [workspace.id],
        )).rows;
        const misfit = live.filter(grant =>
          (next.allowed_classes && grant.scopes.some(scope => !next.allowed_classes!.includes(scope.class))) ||
          new Date(grant.expires_at).getTime() - new Date(grant.created_at).getTime() > next.max_expiry_days * 86_400_000);
        return revokeGrants(tx, { workspaceId: workspace.id, grantIds: misfit.map(grant => grant.id),
          actorUserId: principal.userId, reason: "policy_changed", authMethod: caller.authMethod });
      });
      json(200, { ...await loadPolicy(input.database, workspace.id), revoked_grant_ids: revoked.map(row => row.id) });
      return true;
    }

    // /delegates/{grant_id}
    if (sub && /^grt_[A-Za-z0-9]{8,64}$/.test(sub)) {
      const grant = await grantFor(workspace.id, sub);
      const own = grant.owner_user_id === principal.userId;
      if (method === "DELETE") {
        if (!own && !caller.admin) fail(404, "grant_not_found", "Grant not found");
        await input.database.transaction(tx => revokeGrants(tx, {
          workspaceId: workspace.id, grantIds: [grant.id], actorUserId: principal.userId,
          reason: own ? "owner_revoked" : "admin_revoked", authMethod: caller.authMethod,
        }));
        json(200, grantView(await grantFor(workspace.id, grant.id), now()));
        return true;
      }
      if (method === "GET") {
        if (!own && !caller.admin) fail(404, "grant_not_found", "Grant not found");
        json(200, grantView(grant, now()));
        return true;
      }
      if (method !== "PATCH") fail(405, "method_not_allowed", "Method not allowed");
      if (!own) fail(404, "grant_not_found", "Grant not found");
      await requireEnabled(workspace.id);
      const body = parse(patchGrantBody, await input.requestObject(request));
      if (grant.revoked_at || new Date(grant.expires_at).getTime() <= now().getTime()) {
        fail(409, "grant_not_active", "Only an active grant can be changed");
      }
      // Narrowing only: every new pattern is covered by an existing one of its class.
      const scopes: Scope[] = body.scopes
        ? body.scopes.map(scope => ({ class: scope.class, targets: [...new Set(scope.targets)] }))
        : grant.scopes;
      const widened = scopes.some(scope => scope.targets.some(target => !grant.scopes.some(old =>
        old.class === scope.class && old.targets.some(pattern => classTargetCovered(scope.class, pattern, target, true)))));
      const expiresAt = body.expires_at ? new Date(body.expires_at) : new Date(grant.expires_at);
      if (expiresAt.getTime() <= now().getTime()) fail(400, "invalid_request", "expires_at must be in the future");
      const requireTierO = body.require_tier_o ? uniqueClasses(body.require_tier_o) : grant.require_tier_o;
      if (widened || expiresAt.getTime() > new Date(grant.expires_at).getTime() ||
          grant.require_tier_o.some(item => !requireTierO.includes(item))) {
        fail(400, "widening_refused", "A grant can only be narrowed; widening needs a new grant");
      }
      const row = await input.database.transaction(async (tx) => {
        const updated = (await tx.query<GrantRow>(
          `UPDATE delegation_grants SET scopes = $3::jsonb, expires_at = $4, require_tier_o = $5, updated_at = now()
            WHERE id = $1 AND workspace_id = $2 AND revoked_at IS NULL RETURNING *`,
          [grant.id, workspace.id, JSON.stringify(scopes), expiresAt, requireTierO],
        )).rows[0];
        if (!updated) return fail(409, "grant_not_active", "Only an active grant can be changed");
        await recordDelegationAudit(tx, {
          workspaceId: workspace.id, event: "grant.updated", ...actor, ownerUserId: grant.owner_user_id, grantId: grant.id,
          details: {
            before: { scopes: grant.scopes, expires_at: new Date(grant.expires_at).toISOString(), require_tier_o: grant.require_tier_o },
            after: { scopes, expires_at: expiresAt.toISOString(), require_tier_o: requireTierO },
          },
        });
        return updated;
      });
      json(200, grantView(row, now()));
      return true;
    }
    return fail(404, "not_found", "Route not found");
  };
}
