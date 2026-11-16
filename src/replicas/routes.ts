import type { IncomingMessage, ServerResponse } from "node:http";
import { ApiTokenStore } from "../admin/api-tokens.js";
import { cookieRequestAllowed } from "../auth/device-approval.js";
import type { Database } from "../database.js";
import { secureEqual } from "../crypto.js";
import type { Principal } from "../store.js";
import { ReplicasRuntimeError } from "./runtime.js";
import {
  GENERIC_FAILURE,
  getSpawn,
  listEnvironments,
  OWNER_ADMIN_REFUSAL,
  relayEvent,
  releaseReplica,
  ReplicasError,
  spawnReplica,
  withCapability,
  workspaceReplicas,
  type ReplicasActor,
  type ReplicasDeps,
} from "./service.js";
import { capabilityCall } from "./tools.js";

type Json = (response: ServerResponse, status: number, body: unknown, noStore?: boolean) => void;
export type ReplicasHelpers = {
  workspaceAccess(request: IncomingMessage, workspaceId: string, admin?: boolean): Promise<{
    principal: Principal;
    workspace: { id: string; organizationId: string };
  }>;
  bearer(request: IncomingMessage): string | null;
  json: Json;
};

const BODY_MAX_BYTES = 64 * 1024;
const RELAY_EVENT_MAX_BYTES = 256 * 1024;
const WORKSPACE = /^\/api\/v1\/workspaces\/([^/]+)\/replicas(\/.*)?$/;
const CAPABILITY = /^\/api\/v1\/replicas\/agents\/([^/]+)\/messages$/;
const RELAY_EVENTS = /^\/api\/v1\/replicas\/relay-events\/([^/]+)$/;

/** Every route this module owns, on the normalized (/cloud-stripped) path. */
export function isReplicasPath(path: string): boolean {
  return WORKSPACE.test(path) || CAPABILITY.test(path) || RELAY_EVENTS.test(path);
}

class BodyTooLarge extends Error {}
class InvalidJson extends Error {}

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

async function readJson(request: IncomingMessage): Promise<unknown> {
  const raw = await readBody(request, BODY_MAX_BYTES);
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new InvalidJson();
  }
}

const decode = (value: string) => {
  try {
    return decodeURIComponent(value);
  } catch {
    return "";
  }
};

/** Control-authored failure text only; provider and Relay bodies never reach a caller. */
function failure(error: unknown): { status: number; error: string } {
  if (error instanceof ReplicasError) return { status: error.status, error: error.message };
  if (error instanceof ReplicasRuntimeError && error.status === 429) return { status: 429, error: "Replicas rate limit reached. Retry later." };
  return { status: 502, error: GENERIC_FAILURE };
}

export function createReplicasHandler(input: {
  enabled: boolean;
  deps: ReplicasDeps;
  database: Database;
  internalServiceToken: string | null;
  browserOrigins: string[];
}) {
  const apiTokens = new ApiTokenStore(input.database);
  const { deps } = input;

  async function personActor(request: IncomingMessage, workspaceId: string, method: string, helpers: ReplicasHelpers): Promise<ReplicasActor> {
    // Agent, CI and service credentials never act as a person here.
    const token = helpers.bearer(request);
    if (token && input.internalServiceToken && secureEqual(token, input.internalServiceToken)) {
      throw new ReplicasError(OWNER_ADMIN_REFUSAL, 403);
    }
    if (token?.startsWith("sh_wk_") && await apiTokens.authenticate(token)) throw new ReplicasError(OWNER_ADMIN_REFUSAL, 403);
    let access: Awaited<ReturnType<ReplicasHelpers["workspaceAccess"]>>;
    try {
      access = await helpers.workspaceAccess(request, workspaceId, true);
    } catch (error) {
      const status = (error as { status?: unknown }).status;
      if (status === 401) throw new ReplicasError("Unauthorized", 401);
      if (status === 404) throw new ReplicasError("Workspace not found.", 404);
      if (status !== 403) throw error;
      throw new ReplicasError(OWNER_ADMIN_REFUSAL, 403);
    }
    if (!access.principal.scopes.includes("cli:auth")) throw new ReplicasError(OWNER_ADMIN_REFUSAL, 403);
    if (method !== "GET" && !token && !cookieRequestAllowed(request, input.browserOrigins)) {
      throw new ReplicasError("Cross-origin Replicas write refused.", 403);
    }
    return { userId: access.principal.userId, workspaceId: access.workspace.id, organizationId: access.workspace.organizationId };
  }

  async function workspaceRoute(request: IncomingMessage, method: string, workspaceId: string, rest: string, helpers: ReplicasHelpers) {
    const spawn = /^\/spawns\/([^/]+)$/.exec(rest);
    const known = (rest === "" && method === "GET")
      || (rest === "/environments" && method === "GET")
      || (rest === "/spawns" && method === "POST")
      || (spawn && (method === "GET" || method === "DELETE"));
    if (!known) throw new ReplicasError("Not found", 404);
    const actor = await personActor(request, workspaceId, method, helpers);
    if (rest === "") return { status: 200, body: await workspaceReplicas(deps, actor) };
    if (rest === "/environments") return { status: 200, body: await listEnvironments(deps, actor) };
    if (rest === "/spawns") return { status: 201, body: await spawnReplica(deps, actor, await readJson(request)) };
    const id = decode(spawn![1]!);
    if (method === "GET") return { status: 200, body: await getSpawn(deps, actor, id) };
    return { status: 200, body: await releaseReplica(deps, actor, id) };
  }

  return async function handle(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    method: string,
    helpers: ReplicasHelpers,
  ): Promise<boolean> {
    if (!isReplicasPath(path)) return false;
    const send = (status: number, body: unknown) => helpers.json(response, status, body, true);
    // Off: the surface does not exist, answered before any authentication.
    if (!input.enabled) return send(404, { error: "Not found" }), true;
    const events = RELAY_EVENTS.exec(path);
    if (events) {
      if (method !== "POST") return send(405, { ok: false }), true;
      const header = (name: string) => {
        const value = request.headers[name];
        return typeof value === "string" ? value : null;
      };
      if (!header("webhook-signature")) return send(401, { ok: false }), true;
      try {
        const body = await readBody(request, RELAY_EVENT_MAX_BYTES);
        const result = await relayEvent(deps, decode(events[1]!), {
          id: header("webhook-id"), timestamp: header("webhook-timestamp"), signature: header("webhook-signature"),
        }, body);
        return send(result.status, result.body), true;
      } catch (error) {
        if (error instanceof BodyTooLarge) {
          response.setHeader("connection", "close");
          return send(413, { ok: false }), true;
        }
        return send(error instanceof ReplicasError ? error.status : 503, { ok: false }), true;
      }
    }
    try {
      const capability = CAPABILITY.exec(path);
      if (capability) {
        if (method !== "POST") throw new ReplicasError("Use POST.", 405);
        const match = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(request.headers.authorization ?? "");
        if (!match) return send(401, { error: "Unauthorized" }), true;
        const body = await readJson(request);
        const result = await withCapability(deps, decode(capability[1]!), match[1]!, (binding) => capabilityCall(deps, binding, body));
        return send(200, result), true;
      }
      const workspace = WORKSPACE.exec(path)!;
      const result = await workspaceRoute(request, method, decode(workspace[1]!), workspace[2] ?? "", helpers);
      return send(result.status, result.body), true;
    } catch (error) {
      if (error instanceof BodyTooLarge) {
        response.setHeader("connection", "close");
        return send(413, { error: "Request is too large." }), true;
      }
      if (error instanceof InvalidJson) return send(400, { error: "Invalid JSON." }), true;
      const { status, error: message } = failure(error);
      return send(status, { error: message }), true;
    }
  };
}
