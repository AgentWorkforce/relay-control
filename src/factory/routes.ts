/**
 * Factory HTTP surface (design §3) and module wiring. Mounted once from
 * app.ts; when SELFHOST_FACTORY_ENABLED is false every factory path answers
 * the generic 404 before any authentication runs, and the worker never starts.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { ApiTokenStore } from "../admin/api-tokens.js";
import { cookieRequestAllowed } from "../auth/device-approval.js";
import type { SelfhostConfig } from "../config.js";
import { secureEqual } from "../crypto.js";
import type { Database } from "../database.js";
import { sweepRevocations, type MessagingDeps } from "../messaging/identity.js";
import { createRelaycastClient } from "../messaging/relaycast.js";
import type { Principal } from "../store.js";
import { MAX_REPLY_BODY_BYTES, parseReplyBody, replyBearer } from "./reply-capability.js";
import { createFactoryRuntime, type FactoryRuntime } from "./runtime.js";
import { createFactoryWorker } from "./worker.js";
import {
  createFactoryService,
  bindingHash,
  FACTORY_ERRORS,
  FactoryHttpError,
  type FactoryAccess,
  type FactoryLog,
  type FactoryServiceDeps,
} from "./service.js";

export { cleanupWorkspaceFactory } from "./store.js";
export { FactoryHttpError } from "./service.js";

type JsonWriter = (response: ServerResponse, status: number, body: unknown, noStore?: boolean) => void;

export type FactoryRouteHelpers = {
  workspaceAccess: (request: IncomingMessage, workspaceId: string, admin?: boolean) => Promise<{
    principal: Principal;
    workspace: FactoryAccess["workspace"];
  }>;
  requestObject: (request: IncomingMessage) => Promise<Record<string, unknown>>;
  bearer: (request: IncomingMessage) => string | null;
  json: JsonWriter;
};

/** The app's own unknown-route body: a disabled feature is indistinguishable from an absent one. */
const NOT_FOUND = { error: "not_found", message: "Route not found" } as const;

const defaultLog: FactoryLog = (fields) => console.log("[selfhost-api] factory", fields);

export function createFactoryModule(input: {
  config: SelfhostConfig;
  database: Database;
  messaging: MessagingDeps;
  browserOrigins: readonly string[];
  /** Relaycast transport; tests pass a fake. */
  relayFetch?: typeof fetch;
  /** Factory transport; tests pass a fake. */
  factoryFetch?: typeof fetch;
  runtime?: FactoryRuntime;
  log?: FactoryLog;
  hooks?: Pick<FactoryServiceDeps, "beforeFinalWrite"> & { beforeInboxInsert?: () => Promise<void> };
}) {
  const factoryConfig = input.config.factory ?? { enabled: false, apiUrl: "https://api.factory.ai", historyIntervalMs: 300_000 };
  const enabled = factoryConfig.enabled;
  const log = input.log ?? defaultLog;
  const relaycast = createRelaycastClient({ internalOrigin: input.config.relaycastUrl, fetchImpl: input.relayFetch });
  const runtime = input.runtime ?? createFactoryRuntime({ apiUrl: factoryConfig.apiUrl, fetchImpl: input.factoryFetch });
  const service = createFactoryService({
    database: input.database,
    keyring: input.config.encryptionKeyring,
    runtime,
    relaycast,
    log,
    beforeFinalWrite: input.hooks?.beforeFinalWrite,
  });
  const apiTokens = new ApiTokenStore(input.database);
  const worker = createFactoryWorker({
    database: input.database,
    keyring: input.config.encryptionKeyring,
    runtime,
    relaycast,
    log,
    publicBaseUrl: input.config.publicBaseUrl,
    historyIntervalMs: factoryConfig.historyIntervalMs,
    releasePending: (limit) => service.releasePending({}, limit),
    beforeInboxInsert: input.hooks?.beforeInboxInsert,
  });

  async function rejectServiceCredential(token: string | null): Promise<void> {
    if (!token) return;
    const internal = input.config.internalServiceToken;
    if ((internal && secureEqual(token, internal)) ||
        (token.startsWith("sh_wk_") && await apiTokens.authenticate(token))) {
      throw FACTORY_ERRORS.workspaceToken();
    }
  }

  async function userAccess(
    request: IncomingMessage,
    method: string,
    workspaceId: string,
    helpers: FactoryRouteHelpers,
  ): Promise<FactoryAccess> {
    const token = helpers.bearer(request);
    await rejectServiceCredential(token);
    const access = await helpers.workspaceAccess(request, workspaceId, true);
    if (!access.principal.scopes.includes("cli:auth")) throw FACTORY_ERRORS.scope();
    if (method !== "GET" && !token && !cookieRequestAllowed(request, input.browserOrigins)) {
      throw FACTORY_ERRORS.csrf();
    }
    await sweepRevocations(input.messaging, access.workspace.organizationId);
    return { principal: access.principal, workspace: access.workspace };
  }

  return {
    enabled,
    service,
    runtime,
    relaycast,
    userAccess,
    /** In-transaction member purge for `deleteMembership`'s beforeCommit hook. */
    purgeMemberInTx: service.purgeMemberInTx,
    afterMemberRemoved: service.afterMemberRemoved,
    afterWorkspaceDeleted: service.afterWorkspaceDeleted,
    worker,
    log,
    internalServiceToken: input.config.internalServiceToken,
    /** The worker runs only when the flag is on. */
    start(): void {
      if (enabled) worker.start();
    },
    async stop(): Promise<void> {
      await worker.stop();
    },
  };
}

export type FactoryModule = ReturnType<typeof createFactoryModule>;

function segment(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw FACTORY_ERRORS.invalidRequest();
  }
}

async function boundedBody(request: IncomingMessage, limit: number): Promise<string | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > limit) return null;
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const USER_ROUTE = /^\/api\/v1\/workspaces\/([^/]+)\/factory(\/.*)?$/;
const REPLY_ROUTE = /^\/api\/v1\/factory-sessions\/agents\/([^/]+)\/messages$/;
const PUBLIC_PREFIX = /^\/api\/v1\/factory-sessions(\/|$)/;
/** Internal only: matched on the raw path, so never reachable through the /cloud alias. */
const JOB_PATH = "/internal/v1/factory/job";
const MAX_JOB_BODY_BYTES = 4096;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const JOB_MESSAGE_ID = /^[A-Za-z0-9_-]{1,128}$/;

export type FactoryJob =
  | { v: 1; kind: "sweep"; after?: string }
  | { v: 1; kind: "history"; bindingId: string; scheduledAt?: string }
  | { v: 1; kind: "inject"; bindingId: string; messageId: string };

/** Strict job envelope (Cloud's zod shape): unknown keys or kinds are refused. */
export function parseFactoryJob(value: unknown): FactoryJob | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const body = value as Record<string, unknown>;
  const keys = Object.keys(body);
  const only = (allowed: string[]) => keys.every((key) => allowed.includes(key));
  if (body.v !== 1) return null;
  if (body.kind === "sweep") {
    if (!only(["v", "kind", "after"])) return null;
    if (body.after !== undefined && (typeof body.after !== "string" || !UUID.test(body.after))) return null;
    return { v: 1, kind: "sweep", ...(body.after ? { after: body.after as string } : {}) };
  }
  if (body.kind === "history") {
    if (!only(["v", "kind", "bindingId", "scheduledAt"])) return null;
    if (typeof body.bindingId !== "string" || !UUID.test(body.bindingId)) return null;
    if (body.scheduledAt !== undefined &&
        (typeof body.scheduledAt !== "string" || !/^\d{4}-\d{2}-\d{2}T/.test(body.scheduledAt) ||
         Number.isNaN(Date.parse(body.scheduledAt)))) return null;
    return { v: 1, kind: "history", bindingId: body.bindingId };
  }
  if (body.kind === "inject") {
    if (!only(["v", "kind", "bindingId", "messageId"])) return null;
    if (typeof body.bindingId !== "string" || !UUID.test(body.bindingId)) return null;
    if (typeof body.messageId !== "string" || !JOB_MESSAGE_ID.test(body.messageId)) return null;
    return { v: 1, kind: "inject", bindingId: body.bindingId, messageId: body.messageId };
  }
  return null;
}

/**
 * Returns a request handler that answers factory paths and returns false for
 * everything else. Errors become `{ error, message }` with `no-store`.
 */
export function mountFactoryRoutes(module: FactoryModule, helpers: FactoryRouteHelpers) {
  const { service } = module;
  const { json } = helpers;

  async function userRoute(
    request: IncomingMessage,
    response: ServerResponse,
    method: string,
    workspaceId: string,
    rest: string,
  ): Promise<void> {
    const parts = rest.split("/").filter(Boolean);
    const route = (pattern: string[]) => parts.length === pattern.length &&
      pattern.every((part, index) => part === "*" || part === parts[index]);
    const methods = (allowed: string[]) => {
      if (!allowed.includes(method)) throw new FactoryHttpError(405, "method_not_allowed", "Method not allowed");
    };
    // Route shape and method are decided before auth so unknown paths never authenticate.
    let run: (access: FactoryAccess) => Promise<void>;
    if (route(["connection"])) {
      methods(["GET", "PUT", "DELETE"]);
      run = async (access) => {
        if (method === "GET") return json(response, 200, await service.summary(access), true);
        if (method === "PUT") {
          const body = await helpers.requestObject(request);
          return json(response, 200, await service.connect(access, body.key), true);
        }
        await service.disconnect(access);
        response.writeHead(204, { "cache-control": "no-store" }).end();
      };
    } else if (route(["computers"])) {
      methods(["GET"]);
      run = async (access) => json(response, 200, await service.computers(access), true);
    } else if (route(["computers", "*", "sessions"])) {
      methods(["GET"]);
      const computerId = segment(parts[1]!);
      run = async (access) => json(response, 200, await service.sessions(access, computerId), true);
    } else if (route(["bindings"])) {
      methods(["GET", "POST"]);
      run = async (access) => {
        if (method === "GET") return json(response, 200, await service.listBindings(access), true);
        const body = await helpers.requestObject(request);
        json(response, 201, await service.bind(access, { sessionId: body.session_id, computerId: body.computer_id }), true);
      };
    } else if (route(["bindings", "*"])) {
      methods(["GET", "DELETE"]);
      const bindingId = segment(parts[1]!);
      run = async (access) => {
        if (method === "GET") return json(response, 200, await service.getBinding(access, bindingId), true);
        await service.unbind(access, bindingId);
        response.writeHead(204, { "cache-control": "no-store" }).end();
      };
    } else if (route(["bindings", "*", "deliveries", "*"])) {
      methods(["GET"]);
      const bindingId = segment(parts[1]!);
      const messageId = segment(parts[3]!);
      run = async (access) => json(response, 200, await service.delivery(access, bindingId, messageId), true);
    } else if (route(["bindings", "*", "history", "schedule"])) {
      methods(["POST"]);
      const bindingId = segment(parts[1]!);
      run = async (access) => json(response, 202, await service.scheduleHistory(access, bindingId), true);
    } else {
      json(response, 404, NOT_FOUND, true);
      return;
    }
    await run(await module.userAccess(request, method, workspaceId, helpers));
  }

  async function replyRoute(request: IncomingMessage, response: ServerResponse, method: string, bindingId: string) {
    if (method !== "POST") throw new FactoryHttpError(405, "method_not_allowed", "Method not allowed");
    const bearer = replyBearer(request.headers.authorization);
    if (!bearer) throw FACTORY_ERRORS.replyUnauthorized();
    const raw = await boundedBody(request, MAX_REPLY_BODY_BYTES);
    if (raw === null) throw new FactoryHttpError(413, "payload_too_large", "Too large");
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = null;
    }
    const text = parseReplyBody(parsed);
    if (text === null) throw new FactoryHttpError(400, "invalid_request", "Invalid request");
    json(response, 200, await service.reply(bindingId, bearer, text), true);
  }

  async function jobRoute(request: IncomingMessage, response: ServerResponse, method: string) {
    if (method !== "POST") throw new FactoryHttpError(405, "method_not_allowed", "Method not allowed");
    const token = helpers.bearer(request);
    if (!token) throw new FactoryHttpError(401, "unauthorized", "Internal service token required");
    if (!secureEqual(token, module.internalServiceToken!)) throw new FactoryHttpError(403, "forbidden", "Forbidden");
    const raw = await boundedBody(request, MAX_JOB_BODY_BYTES);
    let parsed: unknown = null;
    try {
      parsed = raw === null ? null : JSON.parse(raw);
    } catch {
      parsed = null;
    }
    const job = parseFactoryJob(parsed);
    if (!job) throw new FactoryHttpError(400, "invalid_request", "Invalid request");
    const bindingHashValue = "bindingId" in job ? bindingHash(job.bindingId) : undefined;
    try {
      let body: Record<string, unknown>;
      if (job.kind === "sweep") {
        const expired = await module.worker.sweepLeases();
        const history = await module.worker.historyTick(job.after);
        body = { ok: true, expired, scheduled: history.scheduled };
      } else if (job.kind === "history") {
        body = { ok: true, deferred: true };
      } else {
        const result = await module.worker.kickDelivery(job.bindingId, job.messageId);
        // Cloud's job contract: an absent delivery is acknowledged as skipped.
        body = result.state === null ? { ok: true, skipped: true } : { ok: true, state: result.state };
      }
      module.log({ event: "factory.job", kind: job.kind, bindingHash: bindingHashValue, outcome: "ok" });
      json(response, 200, body, true);
    } catch {
      module.log({ event: "factory.job", kind: job.kind, bindingHash: bindingHashValue, outcome: "failed" });
      throw new FactoryHttpError(503, "factory_job_failed", "Factory job failed");
    }
  }

  return async function handleFactory(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    publicPath: string,
    method: string,
  ): Promise<boolean> {
    const isJob = publicPath === JOB_PATH;
    const user = USER_ROUTE.exec(path);
    const isPublic = PUBLIC_PREFIX.test(path);
    if (!user && !isPublic && !isJob) return false;
    try {
      if (!module.enabled || (isJob && !module.internalServiceToken)) {
        json(response, 404, NOT_FOUND, true);
        return true;
      }
      if (isJob) {
        await jobRoute(request, response, method);
        return true;
      }
      if (user) {
        await userRoute(request, response, method, segment(user[1]!), user[2] ?? "");
        return true;
      }
      const reply = REPLY_ROUTE.exec(path);
      if (reply) {
        await replyRoute(request, response, method, segment(reply[1]!));
        return true;
      }
      // relay-events/{id} and anything else under factory-sessions: subscriptions are deferred.
      json(response, 404, NOT_FOUND, true);
      return true;
    } catch (error) {
      if (error instanceof FactoryHttpError) {
        json(response, error.status, { error: error.code, message: error.message }, true);
        return true;
      }
      throw error;
    }
  };
}

