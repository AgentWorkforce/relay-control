import type { IncomingMessage, ServerResponse } from "node:http";
import type { SelfhostConfig } from "../config.js";
import { readerKindOf } from "../session-read.js";
import type { ControlPlaneStore, Principal } from "../store.js";
import {
  accessHistory,
  getAccess,
  resetAccess,
  sessionAccessConfigured,
  setAccess,
  type AccessDeps,
  type AccessFailure,
  type AccessResult,
} from "./access.js";
import { accessViaDashboardReader, type HistoryIdentity } from "./history.js";

/**
 * Dashboard session access routes (docs/sessions-read-api.md, "Session
 * access"):
 *
 *   GET   /api/v1/workspaces/:ws/sessions/:id/access
 *   PATCH /api/v1/workspaces/:ws/sessions/:id/access
 *   POST  /api/v1/workspaces/:ws/sessions/:id/access/reset
 *   GET   /api/v1/workspaces/:ws/sessions/:id/access/history
 *
 * Same authentication as the dashboard session reads (workspace member, user
 * token or the dashboard cookie), plus the same-origin check on a cookie
 * PATCH or POST. relaygate decides who administers access; Control resolves
 * emails to members and forwards with the caller's own read token (reader
 * kind `browser` for the cookie, `device` for a bearer). Nothing is stored.
 */

const ACCESS_PATH = /^\/api\/v1\/workspaces\/([^/]+)\/sessions\/([^/]+)\/access(?:\/(reset|history))?$/;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const COUNTER = /^\d{1,10}$/;

type WorkspaceAccess = (
  request: IncomingMessage,
  workspaceId: string,
) => Promise<{
  principal: Principal;
  workspace: { id: string; organizationId: string; role: Principal["role"] };
  token: string;
}>;

export type AccessRouteContext = {
  method: string;
  path: string;
  url: URL;
  request: IncomingMessage;
  response: ServerResponse;
  config: SelfhostConfig;
  store: ControlPlaneStore;
  workspaceAccess: WorkspaceAccess;
  httpError: (status: number, code: string, message: string) => Error;
  json: (response: ServerResponse, status: number, body: unknown, noStore?: boolean) => void;
  /** The JSON body, with the same size limit as the neighbouring routes. */
  readBody?: () => Promise<Record<string, unknown>>;
  /** The same-origin check for a cookie-carried write. */
  originAllowed?: () => boolean;
  /** True when the request carries a bearer token rather than the cookie. */
  hasBearer?: () => boolean;
};

/** HTTP status and error code for every failure outcome. */
export const ACCESS_HTTP: Record<AccessFailure["outcome"], { status: number; error: string }> = {
  not_found: { status: 404, error: "not_found" },
  not_access_admin: { status: 403, error: "not_access_admin" },
  conflict: { status: 409, error: "conflict" },
  unknown_members: { status: 400, error: "unknown_members" },
  invalid_request: { status: 400, error: "invalid_request" },
  unavailable: { status: 503, error: "session_access_unavailable" },
  // Distinct from 503: the change may have applied. Read the access again.
  outcome_unknown: { status: 504, error: "session_access_outcome_unknown" },
  not_configured: { status: 404, error: "session_access_not_configured" },
};

function failureBody(result: AccessFailure): Record<string, unknown> {
  const body: Record<string, unknown> = { error: ACCESS_HTTP[result.outcome].error, message: result.message };
  if (result.outcome === "conflict") body.currentVersion = result.currentVersion;
  if (result.outcome === "unknown_members") body.emails = result.emails;
  return body;
}

function reply<T>(ctx: AccessRouteContext, result: AccessResult<T>, render: (value: T) => unknown): void {
  if (result.outcome === "ok") {
    ctx.json(ctx.response, 200, render(result.value), true);
    return;
  }
  ctx.json(ctx.response, ACCESS_HTTP[result.outcome].status, failureBody(result), true);
}

function decoded(ctx: AccessRouteContext, raw: string): string {
  let value: string;
  try {
    value = decodeURIComponent(raw);
  } catch {
    throw ctx.httpError(400, "invalid_request", "Invalid session identity");
  }
  if (!value || value.length > 512 || CONTROL.test(value)) {
    throw ctx.httpError(400, "invalid_request", "Invalid session identity");
  }
  return value;
}

/** `after` and `limit` only, each at most once, as non-negative integers. */
function historyQuery(ctx: AccessRouteContext): { after?: number; limit?: number } {
  const params = ctx.url.searchParams;
  const result: { after?: number; limit?: number } = {};
  for (const name of new Set(params.keys())) {
    const value = params.get(name) ?? "";
    if ((name !== "after" && name !== "limit") || params.getAll(name).length !== 1 || !COUNTER.test(value)) {
      throw ctx.httpError(400, "invalid_request", `Invalid session parameter: ${name}`);
    }
    result[name as "after" | "limit"] = Number(value);
  }
  return result;
}

/** Returns false when the path is not a session access route. */
export async function handleSessionAccessRoutes(ctx: AccessRouteContext): Promise<boolean> {
  const match = ACCESS_PATH.exec(ctx.path);
  if (!match) return false;
  const action = match[3] as "reset" | "history" | undefined;
  const allowed = action === "reset" ? ["POST"] : action === "history" ? ["GET"] : ["GET", "PATCH"];
  if (!allowed.includes(ctx.method)) return false;
  let workspaceId: string;
  try {
    workspaceId = decodeURIComponent(match[1]!);
  } catch {
    return false;
  }
  const write = ctx.method !== "GET";
  const access = await ctx.workspaceAccess(ctx.request, workspaceId);
  // A cookie-carried write must come from an allowed origin. Fail closed when
  // the app did not supply the check.
  const bearerCall = ctx.hasBearer?.() ?? false;
  if (write && !bearerCall && !(ctx.originAllowed?.() ?? false)) {
    throw ctx.httpError(403, "csrf_rejected", "Cross-origin request refused");
  }
  if (access.principal.pendingHandoff) {
    throw ctx.httpError(403, "handoff_not_exchanged", "Exchange the sign-in handoff first");
  }
  if (!access.principal.scopes.includes("rth:read")) {
    throw ctx.httpError(403, "forbidden", "Session access requires rth:read");
  }
  if (!sessionAccessConfigured(ctx.config) || !ctx.config.relayhistoryUrl) {
    throw ctx.httpError(404, ACCESS_HTTP.not_configured.error, "Session access management is not configured");
  }
  const sessionId = decoded(ctx, match[2]!);
  const identity: HistoryIdentity = {
    userId: access.principal.userId,
    organizationId: access.workspace.organizationId,
    workspaceId: access.workspace.id,
    role: access.workspace.role,
    callerToken: access.token,
    readerKind: readerKindOf(ctx.request),
  };
  const config = ctx.config;
  const store = ctx.store;
  const deps: AccessDeps = {
    send: (request) => accessViaDashboardReader(config, identity, request),
    members: async () => (await store.listMemberships(access.workspace.organizationId)).flatMap((row) =>
      typeof row.userId === "string" && typeof row.email === "string"
        ? [{
          userId: row.userId,
          email: row.email,
          name: typeof row.name === "string" && row.name.trim() ? row.name : null,
        }]
        : []),
  };

  if (action === "history") {
    const input = historyQuery(ctx);
    reply(ctx, await accessHistory(deps, sessionId, input), (value) => value);
    return true;
  }
  if (action === "reset") {
    if (!ctx.readBody) throw ctx.httpError(400, "invalid_request", "Body required");
    const body = await ctx.readBody();
    reply(ctx, await resetAccess(deps, sessionId, {
      reason: body.reason,
      ...("expectedVersion" in body ? { expectedVersion: body.expectedVersion } : {}),
    }), (policy) => ({ access: policy }));
    return true;
  }
  if (ctx.method === "PATCH") {
    if (!ctx.readBody) throw ctx.httpError(400, "invalid_request", "Body required");
    const body = await ctx.readBody();
    const known = new Set(["mode", "members", "groups", "label", "reason", "expectedVersion"]);
    const unknown = Object.keys(body).find((key) => !known.has(key));
    if (unknown !== undefined) throw ctx.httpError(400, "invalid_request", `Unknown field: ${unknown.slice(0, 64)}`);
    reply(ctx, await setAccess(deps, sessionId, body), (policy) => ({ access: policy }));
    return true;
  }
  reply(ctx, await getAccess(deps, sessionId), (policy) => ({ access: policy }));
  return true;
}
