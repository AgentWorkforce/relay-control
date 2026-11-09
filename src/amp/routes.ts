import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import { ApiTokenStore } from "../admin/api-tokens.js";
import { cookieRequestAllowed } from "../auth/device-approval.js";
import type { Database } from "../database.js";
import { secureEqual } from "../crypto.js";
import type { Principal } from "../store.js";
import type { AmpConfig } from "./config.js";
import { queueHistory } from "./history.js";
import { reconcileDelivery, injectJob, RELAY_EVENT_MAX_BYTES, relayEvent, replySend, sweep } from "./delivery.js";
import {
  AmpError,
  bind,
  connect,
  disconnect,
  discover,
  getSummary,
  MESSAGE_ID,
  unbind,
  type AmpActor,
  type AmpDeps,
} from "./service.js";

type Json = (response: ServerResponse, status: number, body: unknown, noStore?: boolean) => void;
export type AmpHelpers = {
  workspaceAccess(request: IncomingMessage, workspaceId: string, admin?: boolean): Promise<{
    principal: Principal;
    workspace: { id: string; organizationId: string };
  }>;
  bearer(request: IncomingMessage): string | null;
  json: Json;
};

export const AMP_INTERNAL_JOB_PATH = "/api/v1/internal/amp/job";
const REPLY_MAX_BYTES = 64 * 1024;
const WORKSPACE = /^\/api\/v1\/workspaces\/([^/]+)\/amp(\/.*)?$/;
const REPLY = /^\/api\/v1\/amp\/agents\/([^/]+)\/messages$/;
const RELAY_EVENTS = /^\/api\/v1\/amp\/relay-events\/([^/]+)$/;

/** Every route this module owns, on the normalized (/cloud-stripped) path. */
export function isAmpPath(path: string): boolean {
  return WORKSPACE.test(path) || REPLY.test(path) || RELAY_EVENTS.test(path) || path === AMP_INTERNAL_JOB_PATH;
}

const job = z.discriminatedUnion("kind", [
  z.object({ v: z.literal(1), kind: z.literal("sweep"), after: z.string().uuid().optional() }).strict(),
  z.object({
    v: z.literal(1),
    kind: z.literal("history"),
    bindingId: z.string().uuid(),
    scheduledAt: z.string().datetime().optional(),
  }).strict(),
  z.object({
    v: z.literal(1),
    kind: z.literal("inject"),
    bindingId: z.string().uuid(),
    messageId: z.string().regex(MESSAGE_ID),
  }).strict(),
]);

class BodyTooLarge extends Error {}

async function readBody(request: IncomingMessage, limit: number): Promise<string> {
  const declared = Number(request.headers["content-length"]);
  if (Number.isFinite(declared) && declared > limit) throw new BodyTooLarge();
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > limit) throw new BodyTooLarge();
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function readJson(request: IncomingMessage, limit: number): Promise<Record<string, unknown>> {
  const raw = await readBody(request, limit);
  if (!raw.trim()) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AmpError(400, "invalid_request", "Body must be valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new AmpError(400, "invalid_request", "Body must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

const decode = (value: string) => {
  try {
    return decodeURIComponent(value);
  } catch {
    return "";
  }
};

/** Maps a delivery result's failure statuses onto the { error, message } shape. */
function eventFailure(status: number): { error: string; message: string } {
  if (status === 410) return { error: "binding_gone", message: "This Amp binding is not bound." };
  if (status === 401) return { error: "unauthorized", message: "Webhook signature, timestamp or secret is invalid." };
  if (status === 400) return { error: "invalid_request", message: "Body must be valid JSON" };
  return { error: "amp_unavailable", message: "Amp could not complete this operation." };
}

export function createAmpHandler(input: {
  config: AmpConfig;
  deps: AmpDeps;
  database: Database;
  internalServiceToken: string | null;
  browserOrigins: string[];
  wake?: () => void;
}) {
  const apiTokens = new ApiTokenStore(input.database);
  const { config, deps } = input;

  async function personActor(
    request: IncomingMessage,
    workspaceId: string,
    method: string,
    helpers: AmpHelpers,
  ): Promise<AmpActor> {
    // Agent, CI and service credentials never act as a person here.
    const token = helpers.bearer(request);
    if (token && input.internalServiceToken && secureEqual(token, input.internalServiceToken)) {
      throw new AmpError(403, "forbidden", "Service credentials cannot manage Amp.");
    }
    if (token?.startsWith("sh_wk_") && await apiTokens.authenticate(token)) {
      throw new AmpError(403, "forbidden", "Agent, CI, and service tokens cannot manage Amp.");
    }
    const access = await helpers.workspaceAccess(request, workspaceId, true);
    if (!access.principal.scopes.includes("cli:auth")) {
      throw new AmpError(403, "forbidden", "Managing Amp requires a person credential with cli:auth.");
    }
    if (method !== "GET" && !token && !cookieRequestAllowed(request, input.browserOrigins)) {
      throw new AmpError(403, "csrf_rejected", "Cross-origin Amp write refused");
    }
    return {
      userId: access.principal.userId,
      workspaceId: access.workspace.id,
      organizationId: access.workspace.organizationId,
    };
  }

  async function workspaceRoute(
    request: IncomingMessage,
    response: ServerResponse,
    method: string,
    workspaceId: string,
    rest: string,
    helpers: AmpHelpers,
  ): Promise<boolean> {
    const send = (body: unknown, status = 200) => helpers.json(response, status, body, true);
    const binding = /^\/bindings\/([^/]+)$/.exec(rest);
    const check = /^\/bindings\/([^/]+)\/deliveries\/([^/]+)\/check$/.exec(rest);
    const known = (rest === "" && method === "GET")
      || (rest === "/connection" && (method === "POST" || method === "DELETE"))
      || (rest === "/threads" && method === "GET")
      || (rest === "/bindings" && method === "POST")
      || (binding && method === "DELETE")
      || (check && method === "POST");
    if (!known) throw new AmpError(404, "not_found", "Route not found");
    const actor = await personActor(request, workspaceId, method, helpers);
    if (rest === "") return send(await getSummary(deps, actor)), true;
    if (rest === "/connection" && method === "POST") {
      const body = await readJson(request, REPLY_MAX_BYTES);
      return send(await connect(deps, actor, body.key)), true;
    }
    if (rest === "/connection") return send(await disconnect(deps, actor)), true;
    if (rest === "/threads") return send({ threads: await discover(deps, actor) }), true;
    if (rest === "/bindings") {
      const body = await readJson(request, REPLY_MAX_BYTES);
      return send(await bind(deps, actor, body.threadId ?? body.thread_id), 201), true;
    }
    if (binding) return send(await unbind(deps, actor, decode(binding[1]!))), true;
    return send(await reconcileDelivery(deps, actor, decode(check![1]!), decode(check![2]!))), true;
  }

  async function internalJob(request: IncomingMessage, response: ServerResponse, helpers: AmpHelpers) {
    const send = (status: number, body: unknown) => helpers.json(response, status, body, true);
    // Unset secret: the job surface does not exist. Never BrokerHmacSecret.
    if (!config.internalSecret) return send(404, { error: "Not found" });
    const token = helpers.bearer(request);
    if (!token) return send(401, { error: "unauthorized", message: "Bearer token required" });
    if (!secureEqual(token, config.internalSecret)) return send(403, { error: "forbidden", message: "Invalid internal credential" });
    let raw: unknown = null;
    try {
      raw = JSON.parse(await readBody(request, REPLY_MAX_BYTES));
    } catch (error) {
      if (error instanceof BodyTooLarge) return send(413, { error: "payload_too_large", message: "Body exceeds 64 KiB" });
    }
    const parsed = job.safeParse(raw);
    if (!parsed.success) return send(400, { error: "invalid_request", message: "Unsupported Amp job." });
    try {
      if (parsed.data.kind === "sweep") {
        const result = await sweep(deps);
        input.wake?.();
        return send(200, result);
      }
      if (parsed.data.kind === "history") {
        // Without a push session nothing is queued or exported (history.ts header).
        if (!deps.pushSession) {
          return send(501, {
            error: "history_push_unavailable",
            message: "Amp history upload is inactive: this control plane cannot issue a workspace-scoped push-only RelayHistory session without a caller token.",
          });
        }
        // Coalesced with any queued run; the worker claims it under a lease.
        const queued = await queueHistory(deps, parsed.data.bindingId, parsed.data.scheduledAt);
        if (queued) input.wake?.();
        return send(queued ? 202 : 200, queued ? { ok: true, queued: true } : { ok: true, queued: false, skipped: true });
      }
      const result = await injectJob(deps, parsed.data.bindingId, parsed.data.messageId);
      return send(result.status, result.status >= 400
        ? { error: "amp_job_failed", message: "The delivery was not completed.", ...result.body }
        : result.body);
    } catch {
      return send(503, { error: "amp_job_failed", message: "The Amp job failed." });
    }
  }

  return async function handle(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    publicPath: string,
    method: string,
    helpers: AmpHelpers,
  ): Promise<boolean> {
    if (!isAmpPath(path)) return false;
    // Off: the surface does not exist, answered before any authentication.
    if (!config.enabled) {
      helpers.json(response, 404, { error: "Not found" }, true);
      return true;
    }
    try {
      // Internal: never reachable through the /cloud alias.
      if (path === AMP_INTERNAL_JOB_PATH) {
        if (publicPath !== AMP_INTERNAL_JOB_PATH || method !== "POST") return false;
        await internalJob(request, response, helpers);
        return true;
      }
      const reply = REPLY.exec(path);
      if (reply) {
        if (method !== "POST") throw new AmpError(405, "method_not_allowed", "Use POST");
        const header = request.headers.authorization ?? "";
        const match = /^Bearer (amp_reply_[A-Za-z0-9_-]{43})$/.exec(header);
        if (!match) throw new AmpError(401, "unauthorized", "Invalid or revoked reply capability.");
        const body = await readJson(request, REPLY_MAX_BYTES);
        helpers.json(response, 200, await replySend(deps, decode(reply[1]!), match[1]!, body), true);
        return true;
      }
      const events = RELAY_EVENTS.exec(path);
      if (events) {
        if (method !== "POST") throw new AmpError(405, "method_not_allowed", "Use POST");
        const body = await readBody(request, RELAY_EVENT_MAX_BYTES);
        const header = (name: string) => {
          const value = request.headers[name];
          return typeof value === "string" ? value : null;
        };
        const result = await relayEvent(deps, decode(events[1]!), {
          id: header("webhook-id"),
          timestamp: header("webhook-timestamp"),
          signature: header("webhook-signature"),
        }, body, input.wake);
        helpers.json(response, result.status, result.status >= 400 ? eventFailure(result.status) : result.body, true);
        return true;
      }
      const workspace = WORKSPACE.exec(path)!;
      return await workspaceRoute(request, response, method, decode(workspace[1]!), workspace[2] ?? "", helpers);
    } catch (error) {
      if (error instanceof BodyTooLarge) {
        response.setHeader("connection", "close");
        helpers.json(response, 413, { error: "payload_too_large", message: "Request body is too large." }, true);
        return true;
      }
      if (error instanceof AmpError) {
        helpers.json(response, error.status, { error: error.code, message: error.message }, true);
        return true;
      }
      throw error;
    }
  };
}
