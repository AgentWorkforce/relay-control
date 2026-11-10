import type { IncomingMessage, ServerResponse } from "node:http";
import type { Principal } from "../store.js";
import { RemoteAgentConnections, RemoteAgentError, isRemoteAgentId, type RemoteAgentId, type RemoteConnection } from "./connections.js";

/** Shared-cookie dashboard endpoints; never a general-purpose upstream proxy.
 * The Capy/Replicas aliases preserve the existing webapp #117 contracts.
 */
export function remoteAgentRoutes(connections: RemoteAgentConnections) {
  return async (request: IncomingMessage, response: ServerResponse, path: string, method: string, helpers: {
    workspaceAccess(request: IncomingMessage, workspaceId: string, admin?: boolean): Promise<{
      principal: Principal; workspace: { id: string; organizationId: string };
    }>;
    requestObject(request: IncomingMessage): Promise<Record<string, unknown>>;
    csrfAllowed(request: IncomingMessage): boolean;
    json(response: ServerResponse, status: number, body: unknown, noStore: boolean): void;
  }): Promise<boolean> => {
    const generic = /^\/api\/v1\/workspaces\/([^/]+)\/remote-agent-connections(?:\/([^/]+))?$/.exec(path);
    const capy = /^\/api\/v1\/workspaces\/([^/]+)\/capy\/connection$/.exec(path);
    const replicas = /^\/api\/v1\/workspaces\/([^/]+)\/replicas$/.exec(path);
    const match = generic ?? capy ?? replicas;
    if (!match) return false;
    const send = (status: number, body: unknown) => helpers.json(response, status, body, true);
    let workspaceId: string;
    try { workspaceId = decodeURIComponent(match[1]!); }
    catch { send(400, { error: "invalid_request", message: "Malformed workspace ID." }); return true; }
    const id = capy ? "capy" : replicas ? "replicas" : generic?.[2];
    const alias = Boolean(capy || replicas);
    const aliasView = (connection: RemoteConnection | null) => capy ? {
      connected: Boolean(connection), key_hint: connection?.keyHint ?? null,
      validated_at: connection?.validatedAt ?? null, last_error: null,
      capabilities: { relayBinding: false, historySync: false },
    } : connection ? {
      keyHint: connection.keyHint, organizationId: connection.providerAccount,
      validatedAt: connection.validatedAt, capabilities: { relayBinding: false, historySync: false },
    } : null;
    try {
      if (id && !isRemoteAgentId(id)) throw new RemoteAgentError(404, "not_found", "Unknown remote agent provider.");
      const write = capy ? "PUT" : "POST";
      const allowed = id ? (alias ? ["GET", write, "DELETE"] : ["POST", "DELETE"]) : ["GET"];
      if (!allowed.includes(method)) {
        response.setHeader("allow", allowed.join(", "));
        throw new RemoteAgentError(405, "method_not_allowed", "Method not allowed.");
      }
      const access = await helpers.workspaceAccess(request, workspaceId, method !== "GET");
      if (method === "GET") {
        const providers = await connections.list(access.workspace.id);
        send(200, alias ? aliasView(providers.find(provider => provider.id === id)?.connection ?? null) : { providers });
        return true;
      }
      // Same person-only boundary as Amp; CI/workspace/agent tokens cannot
      // manage keys even if they have permission to read session evidence.
      if (!access.principal.scopes.includes("cli:auth")) {
        throw new RemoteAgentError(403, "forbidden", "Provider settings require a person credential.");
      }
      if (!helpers.csrfAllowed(request)) throw new RemoteAgentError(403, "csrf_rejected", "Cross-origin provider write refused.");
      const actor = { userId: access.principal.userId, workspaceId: access.workspace.id, organizationId: access.workspace.organizationId };
      const provider = id as RemoteAgentId;
      if (method === "DELETE") {
        await connections.disconnect(actor, provider);
        send(200, alias ? replicas ? { disconnected: true } : aliasView(null) : { connection: null });
      } else {
        if (request.headers["content-type"]?.split(";")[0]?.trim().toLowerCase() !== "application/json") {
          throw new RemoteAgentError(415, "unsupported_media_type", "Use application/json.");
        }
        const body = await helpers.requestObject(request);
        const keyField = replicas ? "api_key" : "key";
        if (Object.keys(body).some(key => key !== keyField && !(provider === "devin" && key === "orgId"))) {
          throw new RemoteAgentError(400, "invalid_request", "Unsupported connection field.");
        }
        const connection = await connections.connect(actor, provider, { key: body[keyField], ...(provider === "devin" ? { orgId: body.orgId } : {}) });
        send(200, alias ? aliasView(connection) : { connection });
      }
    } catch (error) {
      if (!(error instanceof RemoteAgentError)) throw error;
      send(error.status, { error: error.code, message: error.message });
    }
    return true;
  };
}
