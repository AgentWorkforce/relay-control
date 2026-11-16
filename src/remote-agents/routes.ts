import type { IncomingMessage, ServerResponse } from "node:http";
import type { Principal } from "../store.js";
import { RemoteAgentConnections, RemoteAgentError, isRemoteAgentId, type RemoteAgentId } from "./connections.js";

/** Shared-cookie dashboard endpoints; never a general-purpose upstream proxy. */
export function remoteAgentRoutes(connections: RemoteAgentConnections) {
  return async (request: IncomingMessage, response: ServerResponse, path: string, method: string, helpers: {
    workspaceAccess(request: IncomingMessage, workspaceId: string, admin?: boolean): Promise<{
      principal: Principal; workspace: { id: string; organizationId: string };
    }>;
    requestObject(request: IncomingMessage): Promise<Record<string, unknown>>;
    csrfAllowed(request: IncomingMessage): boolean;
    json(response: ServerResponse, status: number, body: unknown, noStore: boolean): void;
  }): Promise<boolean> => {
    const match = /^\/api\/v1\/workspaces\/([^/]+)\/remote-agent-connections(?:\/([^/]+))?$/.exec(path);
    if (!match) return false;
    const send = (status: number, body: unknown) => helpers.json(response, status, body, true);
    let workspaceId: string;
    try { workspaceId = decodeURIComponent(match[1]!); }
    catch { send(400, { error: "invalid_request", message: "Malformed workspace ID." }); return true; }
    const id = match[2];
    try {
      if (id && !isRemoteAgentId(id)) throw new RemoteAgentError(404, "not_found", "Unknown remote agent provider.");
      const allowed = id ? ["POST", "DELETE"] : ["GET"];
      if (!allowed.includes(method)) {
        response.setHeader("allow", allowed.join(", "));
        throw new RemoteAgentError(405, "method_not_allowed", "Method not allowed.");
      }
      const access = await helpers.workspaceAccess(request, workspaceId, method !== "GET");
      if (method === "GET") {
        const providers = await connections.list(access.workspace.id);
        send(200, { providers });
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
        // The body is optional: an empty one is no options, and only then is no content type needed.
        const body = await helpers.requestObject(request);
        if (Object.keys(body).length
          && request.headers["content-type"]?.split(";")[0]?.trim().toLowerCase() !== "application/json") {
          throw new RemoteAgentError(415, "unsupported_media_type", "Use application/json.");
        }
        // Replicas only: owners and admins may abandon the provider environment cleanup.
        if (Object.keys(body).some(key => key !== "abandon_environment_cleanup" || provider !== "replicas")
          || (body.abandon_environment_cleanup !== undefined && typeof body.abandon_environment_cleanup !== "boolean")) {
          throw new RemoteAgentError(400, "invalid_request", "Unsupported disconnect field.");
        }
        const { environmentCleanupAbandoned } = await connections.disconnect(actor, provider,
          { abandonEnvironmentCleanup: body.abandon_environment_cleanup === true });
        send(200, { connection: null, ...(environmentCleanupAbandoned ? { environment_cleanup_abandoned: true } : {}) });
      } else {
        if (request.headers["content-type"]?.split(";")[0]?.trim().toLowerCase() !== "application/json") {
          throw new RemoteAgentError(415, "unsupported_media_type", "Use application/json.");
        }
        const body = await helpers.requestObject(request);
        if (Object.keys(body).some(key => key !== "key" && !(provider === "devin" && key === "orgId"))) {
          throw new RemoteAgentError(400, "invalid_request", "Unsupported connection field.");
        }
        const { connection, replaced } = await connections.connectReporting(actor, provider,
          { key: body.key, ...(provider === "devin" ? { orgId: body.orgId } : {}) });
        // Replicas: environment discovery and the default enable (sync semantics on a re-connect);
        // partial failures are statuses, never a failed connect.
        const environments = provider === "replicas" ? await connections.replicasSetup(actor, { reconnect: replaced }) : undefined;
        send(200, { connection, ...(environments ?? {}) });
      }
    } catch (error) {
      if (!(error instanceof RemoteAgentError)) throw error;
      send(error.status, { error: error.code, message: error.message });
    }
    return true;
  };
}
