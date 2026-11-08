// Workspace-scoped HTTP routes for coding agents. Paths mirror hosted:
//   GET    /api/v1/workspaces/{id}/cloud-agents              (hosted GET /api/v1/cloud-agents?scope=workspace)
//   POST   /api/v1/workspaces/{id}/provider-credentials/byok
//   POST   /api/v1/workspaces/{id}/provider-credentials/setup-token
//   POST   /api/v1/workspaces/{id}/cloud-agents/{agentId}/activate
//   POST   /api/v1/workspaces/{id}/cloud-agents/{agentId}/check
//   DELETE /api/v1/workspaces/{id}/cloud-agents/{agentId}
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  CODING_AGENT_PROVIDERS,
  CodingAgentError,
  type CodingAgentStore,
} from "./coding-agents.js";
import type { AdminRouteHelpers, WorkspaceAccess } from "./routes.js";
import {
  DEVICE_BINDING_COOKIES,
  type SubscriptionLoginStore,
  type SubscriptionProvider,
} from "./subscription-logins.js";

function readCookie(request: IncomingMessage, name: string): string | null {
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      return null;
    }
  }
  return null;
}

type Json = (response: ServerResponse, status: number, body: unknown) => void;

function userActor(access: WorkspaceAccess) {
  return { kind: "user" as const, userId: access.principal.userId };
}

/** Public provider catalog for the connect dialog (no secrets). */
export function codingAgentCatalog() {
  return CODING_AGENT_PROVIDERS.map((provider) => ({
    id: provider.id,
    displayName: provider.displayName,
    harness: provider.harness,
    envName: provider.apiKeyEnv,
    authTypes: [
      ...(provider.setupToken ? ["oauth_token"] : []),
      ...(provider.deviceLogin ? ["provider_oauth"] : []),
      "byo_api_key",
    ],
    keyPlaceholder: provider.keyPlaceholder,
    docsUrl: provider.docsUrl,
  }));
}

export async function handleCodingAgentRoute(input: {
  request: IncomingMessage;
  response: ServerResponse;
  workspaceId: string;
  rest: string;
  helpers: AdminRouteHelpers;
  store: CodingAgentStore;
  logins: SubscriptionLoginStore;
  json: Json;
  requireJsonWrite: (request: IncomingMessage) => void;
}): Promise<boolean> {
  const { request, response, workspaceId, rest, helpers, store, json } = input;
  const method = request.method ?? "GET";

  if (rest === "cloud-agents" && method === "GET") {
    const access = await helpers.workspaceAccess(request, workspaceId, false);
    const canManage = access.workspace.role === "owner" || access.workspace.role === "admin";
    json(response, 200, {
      agents: await store.list(access.workspace.id),
      providers: codingAgentCatalog(),
      canManage,
    });
    return true;
  }

  if (rest === "provider-credentials/byok" && method === "POST") {
    input.requireJsonWrite(request);
    const access = await helpers.workspaceAccess(request, workspaceId, true);
    const body = await helpers.requestObject(request);
    const { record, created } = await store.putApiKey({
      workspaceId: access.workspace.id,
      organizationId: access.workspace.organizationId,
      modelProvider: body.modelProvider,
      key: body.key,
      label: body.label,
      actor: userActor(access),
    });
    json(response, created ? 201 : 200, { providerCredentialId: record.id, id: record.id, agent: record });
    return true;
  }

  if (rest === "provider-credentials/setup-token" && method === "POST") {
    input.requireJsonWrite(request);
    const access = await helpers.workspaceAccess(request, workspaceId, true);
    const body = await helpers.requestObject(request);
    const { record, created } = await store.putSetupToken({
      workspaceId: access.workspace.id,
      organizationId: access.workspace.organizationId,
      token: body.token,
      accountEmail: body.accountEmail,
      label: body.label,
      actor: userActor(access),
    });
    json(response, created ? 201 : 200, { providerCredentialId: record.id, id: record.id, agent: record });
    return true;
  }

  const action = /^cloud-agents\/([^/]+)\/(activate|check)$/.exec(rest);
  if (action && method === "POST") {
    const [, agentId, verb] = action as unknown as [string, string, "activate" | "check"];
    input.requireJsonWrite(request);
    const access = await helpers.workspaceAccess(request, workspaceId, true);
    if (verb === "activate") {
      const body = await helpers.requestObject(request);
      const agent = await store.activate({
        workspaceId: access.workspace.id,
        organizationId: access.workspace.organizationId,
        id: agentId,
        selection: body.selection,
        actor: userActor(access),
      });
      json(response, 200, { agent });
      return true;
    }
    json(response, 200, await store.check({ workspaceId: access.workspace.id, id: agentId }));
    return true;
  }

  // Hosted provider-credentials/{openai,xai}-device/{start,status}: browser
  // device logins with no hosted callback. Owner/admin only (credential write).
  const device = /^provider-credentials\/(openai|xai)-device\/(start|status)$/.exec(rest);
  if (device && method === "POST") {
    const provider = device[1] as SubscriptionProvider;
    input.requireJsonWrite(request);
    const access = await helpers.workspaceAccess(request, workspaceId, true);
    const cookieName = DEVICE_BINDING_COOKIES[provider];
    if (device[2] === "start") {
      const started = await input.logins.startDevice({
        provider,
        workspaceId: access.workspace.id,
        organizationId: access.workspace.organizationId,
        userId: access.principal.userId,
      });
      const maxAge = Math.max(60, Math.ceil((Date.parse(started.expiresAt) - Date.now()) / 1000) + 60);
      response.setHeader(
        "set-cookie",
        `${cookieName}=${encodeURIComponent(started.browserBinding)}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Strict`,
      );
      const { browserBinding: _binding, ...body } = started;
      json(response, 201, body);
      return true;
    }
    const body = await helpers.requestObject(request);
    const status = await input.logins.pollDevice({
      provider,
      transactionId: body.transactionId,
      workspaceId: access.workspace.id,
      organizationId: access.workspace.organizationId,
      userId: access.principal.userId,
      browserBinding: readCookie(request, cookieName),
    });
    if (status.status !== "pending") {
      response.setHeader("set-cookie", `${cookieName}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`);
    }
    json(response, 200, status);
    return true;
  }

  const item = /^cloud-agents\/([^/]+)$/.exec(rest);
  if (item && method === "DELETE") {
    const access = await helpers.workspaceAccess(request, workspaceId, true);
    const deleted = await store.delete({
      workspaceId: access.workspace.id,
      organizationId: access.workspace.organizationId,
      id: item[1]!,
      actor: userActor(access),
    });
    if (!deleted) throw new CodingAgentError(404, "credential_not_found", "Credential not found");
    json(response, 200, { deleted: true, id: deleted.id });
    return true;
  }

  return false;
}
