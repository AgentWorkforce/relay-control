// admin lane HTTP routes: workspace environment variables, provider
// connections (BYO OAuth), workspace API tokens, org settings, audit, and the
// /internal/v1 runtime read contract. Mounted from src/app.ts.
import type { IncomingMessage, ServerResponse } from "node:http";
import type { SelfhostConfig } from "../config.js";
import type { EncryptionKeyring } from "../crypto.js";
import { secureEqual } from "../crypto.js";
import type { Database } from "../database.js";
import type { Principal } from "../store.js";
import { ApiTokenError, ApiTokenStore } from "./api-tokens.js";
import { acceptedAudiences } from "../auth/introspect.js";
import { listAudit, recordAudit, type AuditActor } from "./audit.js";
import { ConnectionError, ConnectionStore, type FetchLike } from "./connections.js";
import { EnvVarStore } from "./env-vars.js";
import { CodingAgentError, CodingAgentStore } from "./coding-agents.js";
import { handleCodingAgentRoute } from "./coding-agent-routes.js";
import { CredentialBlobStore, credentialBackendFromEnv, type CredentialObjectBackend } from "./credential-blobs.js";
import { SubscriptionLoginStore } from "./subscription-logins.js";
import { EnvVarValidationError } from "./env-policy.js";
import {
  catalogEntry,
  DEFAULT_PROVIDERS,
  ProviderRegistry,
  ProviderTokenError,
  type ProviderDefinition,
} from "./providers.js";

type JsonObject = Record<string, unknown>;

export class AdminHttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "AdminHttpError";
  }
}

export type WorkspaceAccess = {
  principal: Principal;
  workspace: { id: string; organizationId: string; name: string; role: Principal["role"] };
};

/** Helpers app.ts already has; passed in so auth stays in one place. */
export type AdminRouteHelpers = {
  workspaceAccess(request: IncomingMessage, workspaceId: string, admin: boolean): Promise<WorkspaceAccess>;
  organizationAccess(request: IncomingMessage, organizationId: string, admin: boolean): Promise<unknown>;
  requestObject(request: IncomingMessage): Promise<JsonObject>;
  bearer(request: IncomingMessage): string | null;
};

/**
 * Optional hook for the flows lane: map a worker credential to the workspace
 * it may read. Return null when the token is not a worker credential.
 */
export type RuntimeCredentialVerifier = (token: string) => Promise<
  { subject: string; workspaceId: string; scopes?: string[] } | null
>;

export type AdminModule = {
  handle(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    url: URL,
    helpers: AdminRouteHelpers,
  ): Promise<boolean>;
  envVars: EnvVarStore;
  connections: ConnectionStore;
  apiTokens: ApiTokenStore;
  providers: ProviderRegistry;
  codingAgents: CodingAgentStore;
  logins: SubscriptionLoginStore;
  runtimeEnvironment(
    workspaceId: string,
    actor: Parameters<EnvVarStore["readRuntimeEnvironment"]>[1],
    includeIntegrations: boolean,
  ): Promise<{
    workspaceId: string;
    env: Record<string, string>;
    secretEnvNames: string[];
    skipped: unknown[];
    integrationErrors: Array<{ provider: string; error: string }>;
  }>;
};

const RUNTIME_ENV_SCOPE = "runtime:env:read";
const RUNTIME_INTEGRATIONS_SCOPE = "runtime:integrations:read";

function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(JSON.stringify(body));
}

function match(path: string, pattern: RegExp): string[] | null {
  const found = pattern.exec(path);
  if (!found) return null;
  try {
    return found.slice(1).map(decodeURIComponent);
  } catch {
    throw new AdminHttpError(400, "invalid_request", "Malformed path segment");
  }
}

function html(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function userActor(access: WorkspaceAccess): AuditActor & { kind: "user" } {
  return { kind: "user", userId: access.principal.userId };
}

/** Refuse simple cross-site form posts for cookie-authenticated writes. */
function requireJsonWrite(request: IncomingMessage, helpers: AdminRouteHelpers): void {
  const method = request.method ?? "GET";
  if (method === "GET" || method === "HEAD" || method === "DELETE") return;
  if (helpers.bearer(request)) return;
  const type = request.headers["content-type"]?.split(";")[0]?.trim().toLowerCase();
  if (type !== "application/json") {
    throw new AdminHttpError(415, "unsupported_media_type", "Use application/json");
  }
}

function listEntry(
  provider: ProviderDefinition | null,
  connection: Awaited<ReturnType<ConnectionStore["list"]>>[number],
): JsonObject {
  return {
    ...connection,
    provider: connection.provider,
    providerConfigKey: provider?.configKey ?? connection.provider,
    status: connection.status,
    upstreamConnected: connection.status === "ready",
    deprecated: false,
    backend: "selfhost",
  };
}

export function createAdminModule(input: {
  config: SelfhostConfig;
  database: Database;
  keyring: EncryptionKeyring;
  providers?: readonly ProviderDefinition[];
  fetchImpl?: FetchLike;
  runtimeCredentialVerifier?: RuntimeCredentialVerifier;
  /** Where subscription-login auth files are stored. Default: from env (Postgres fallback). */
  credentialBackend?: CredentialObjectBackend;
}): AdminModule {
  const { config, database } = input;
  const providers = new ProviderRegistry(input.providers ?? DEFAULT_PROVIDERS);
  const envVars = new EnvVarStore(database, input.keyring);
  const connections = new ConnectionStore(
    database,
    input.keyring,
    providers,
    config.oauthRedirectUrl,
    input.fetchImpl,
    config.operatorOAuthApps ?? {},
  );

  /** A same-origin dashboard URL to return to after the provider callback, or null. */
  function safeReturnTo(value: unknown): string | null {
    if (typeof value !== "string" || !value || value.length > 2_048) return null;
    try {
      const target = new URL(value, config.dashboardUrl);
      return target.origin === new URL(config.dashboardUrl).origin ? target.toString() : null;
    } catch {
      return null;
    }
  }
  const apiTokens = new ApiTokenStore(database, () => acceptedAudiences(config));
  const blobs = new CredentialBlobStore(
    input.credentialBackend ?? credentialBackendFromEnv(process.env, database),
    input.keyring,
  );
  const codingAgents = new CodingAgentStore(database, input.keyring, input.fetchImpl, blobs);
  const logins = new SubscriptionLoginStore(database, input.keyring, blobs, input.fetchImpl);

  async function workspaceOrganization(workspaceId: string): Promise<string | null> {
    if (!/^[0-9a-f-]{36}$/i.test(workspaceId)) return null;
    const result = await database.query<{ organization_id: string }>(
      "SELECT organization_id FROM workspaces WHERE id = $1",
      [workspaceId],
    );
    return result.rows[0]?.organization_id ?? null;
  }

  /** Runtime consumers: service token, workspace API token, or worker hook. */
  async function runtimeAccess(
    request: IncomingMessage,
    helpers: AdminRouteHelpers,
    workspaceId: string,
    scope: string,
  ): Promise<AuditActor> {
    const token = helpers.bearer(request);
    if (!token) throw new AdminHttpError(401, "unauthorized", "Service credential required");
    let actor: AuditActor | null = null;
    if (config.internalServiceToken && secureEqual(token, config.internalServiceToken)) {
      actor = { kind: "service", subject: "internal-service-token" };
    } else if (token.startsWith("sh_wk_")) {
      const principal = await apiTokens.authenticate(token);
      if (!principal) throw new AdminHttpError(401, "unauthorized", "Invalid or expired token");
      if (principal.workspaceId !== workspaceId) {
        throw new AdminHttpError(404, "workspace_not_found", "Workspace not found");
      }
      if (!principal.scopes.includes(scope)) {
        throw new AdminHttpError(403, "insufficient_scope", `Token lacks ${scope}`);
      }
      actor = { kind: "service", subject: `api-token:${principal.tokenId}` };
    } else if (input.runtimeCredentialVerifier) {
      const worker = await input.runtimeCredentialVerifier(token);
      if (worker) {
        if (worker.workspaceId !== workspaceId) {
          throw new AdminHttpError(404, "workspace_not_found", "Workspace not found");
        }
        if (worker.scopes && !worker.scopes.includes(scope)) {
          throw new AdminHttpError(403, "insufficient_scope", `Credential lacks ${scope}`);
        }
        actor = { kind: "service", subject: worker.subject.slice(0, 200) };
      }
    }
    if (!actor) throw new AdminHttpError(401, "unauthorized", "Service credential required");
    if (!await workspaceOrganization(workspaceId)) {
      throw new AdminHttpError(404, "workspace_not_found", "Workspace not found");
    }
    return actor;
  }

  async function runtimeEnvironment(
    workspaceId: string,
    actor: Parameters<EnvVarStore["readRuntimeEnvironment"]>[1],
    includeIntegrations: boolean,
  ) {
    const environment = await envVars.readRuntimeEnvironment(workspaceId, actor);
    const agentEnvironment = await codingAgents.readRuntimeEnvironment(workspaceId, actor);
    const { env: integrationEnv, failed } = includeIntegrations
      ? await connections.runtimeIntegrationEnv(workspaceId, actor)
      : { env: {} as Record<string, string>, failed: [] as Array<{ provider: string; error: string }> };
    // Run-managed values win over workspace variables in the launcher.
    // Here a selected coding-agent credential (Settings > Connections)
    // wins over a same-named workspace variable, and integration env wins
    // over both.
    const env = { ...environment.env, ...agentEnvironment.env, ...integrationEnv };
    return {
      workspaceId,
      env,
      secretEnvNames: Object.keys(env).sort(),
      skipped: [...environment.skipped, ...agentEnvironment.skipped],
      integrationErrors: failed,
    };
  }

  function oauthCallbackPage(
    response: ServerResponse,
    status: number,
    outcome: { ok: boolean; title: string; detail: string; returnTo?: string | null },
  ): void {
    const dashboard = outcome.returnTo ?? config.dashboardUrl;
    response.writeHead(status, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "content-security-policy":
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    });
    response.end(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>${html(outcome.title)}</title>
<style>body{font:16px system-ui;max-width:34rem;margin:10vh auto;padding:1.5rem;color:#171717}</style>
</head><body><main><h1>${html(outcome.title)}</h1><p>${html(outcome.detail)}</p>
<p><a href="${html(dashboard)}">${outcome.returnTo ? "Return to where you were" : "Return to the dashboard"}</a></p></main>
<script>${outcome.ok ? "if(window.opener){setTimeout(function(){window.close()},1200)}" : ""}</script>
</body></html>`);
  }

  async function handle(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    url: URL,
    helpers: AdminRouteHelpers,
  ): Promise<boolean> {
    const method = request.method ?? "GET";

    // ---------------------------------------------------------- public
    if (path === "/api/v1/integrations/catalog" && method === "GET") {
      const entries = providers.list().map(catalogEntry);
      json(response, 200, { providers: entries, version: "selfhost-1" });
      return true;
    }

    if (path === "/api/v1/integrations/oauth/callback" && method === "GET") {
      const state = url.searchParams.get("state");
      if (!state || state.length > 512) {
        oauthCallbackPage(response, 400, {
          ok: false,
          title: "Connection failed",
          detail: "This connection link is invalid or has expired. Start again from the dashboard.",
        });
        return true;
      }
      try {
        const { connection, returnTo } = await connections.completeOAuth({
          state,
          code: url.searchParams.get("code"),
          error: url.searchParams.get("error"),
        });
        oauthCallbackPage(response, 200, {
          ok: true,
          returnTo,
          title: `${connection.displayName} connected`,
          detail: connection.accountLabel
            ? `Connected to ${connection.accountLabel}. You can close this window.`
            : "You can close this window.",
        });
      } catch (error) {
        if (error instanceof ConnectionError || error instanceof ProviderTokenError) {
          oauthCallbackPage(response, error instanceof ConnectionError ? error.status : 502, {
            ok: false,
            title: "Connection failed",
            detail: error.message,
          });
          return true;
        }
        throw error;
      }
      return true;
    }

    // -------------------------------------------------------- internal
    const internalEnv = match(path, /^\/internal\/v1\/workspaces\/([^/]+)\/environment$/);
    if (internalEnv && method === "GET") {
      const workspaceId = internalEnv[0]!;
      const actor = await runtimeAccess(request, helpers, workspaceId, RUNTIME_ENV_SCOPE);
      const includeIntegrations = url.searchParams.get("includeIntegrations");
      const integrations = includeIntegrations === "1" || includeIntegrations === "true";
      if (integrations) await runtimeAccess(request, helpers, workspaceId, RUNTIME_INTEGRATIONS_SCOPE);
      json(response, 200, await runtimeEnvironment(workspaceId, actor, integrations));
      return true;
    }

    const internalIntegrations = match(path, /^\/internal\/v1\/workspaces\/([^/]+)\/integrations$/);
    if (internalIntegrations && method === "GET") {
      const workspaceId = internalIntegrations[0]!;
      await runtimeAccess(request, helpers, workspaceId, RUNTIME_INTEGRATIONS_SCOPE);
      json(response, 200, {
        workspaceId,
        integrations: (await connections.list(workspaceId)).map((connection) =>
          listEntry(providers.get(connection.provider), connection)
        ),
      });
      return true;
    }

    const internalToken = match(
      path,
      /^\/internal\/v1\/workspaces\/([^/]+)\/integrations\/([^/]+)\/token$/,
    );
    if (internalToken && method === "POST") {
      const [workspaceId, provider] = internalToken as [string, string];
      const actor = await runtimeAccess(request, helpers, workspaceId, RUNTIME_INTEGRATIONS_SCOPE);
      const body = await helpers.requestObject(request);
      const token = await connections.runtimeToken({
        workspaceId,
        provider,
        forceRefresh: body.forceRefresh === true,
        actor,
      });
      json(response, 200, token);
      return true;
    }

    // ---------------------------------------------- organization settings
    const organization = match(path, /^\/api\/v1\/organizations\/([^/]+)$/);
    if (organization && method === "PATCH") {
      requireJsonWrite(request, helpers);
      const organizationId = organization[0]!;
      const auth = await helpers.organizationAccess(request, organizationId, true);
      const body = await helpers.requestObject(request);
      if (typeof body.name !== "string") {
        throw new AdminHttpError(400, "invalid_request", "name must be a string");
      }
      const name = body.name.replace(/[\p{C}]/gu, " ").replace(/\s+/g, " ").trim();
      if (!name || name.length > 80) {
        throw new AdminHttpError(400, "invalid_request", "name must be 1-80 characters");
      }
      const updated = await database.transaction(async (tx) => {
        const result = await tx.query<{ id: string; name: string }>(
          `UPDATE organizations SET name = $2, updated_at = now()
            WHERE id = $1 RETURNING id, name`,
          [organizationId, name],
        );
        const row = result.rows[0];
        if (row) {
          const principal = (auth as { kind: string; principal?: Principal }).principal;
          await recordAudit(tx, {
            organizationId,
            actor: principal ? { kind: "user", userId: principal.userId } : { kind: "bootstrap" },
            action: "organization.rename",
            target: organizationId,
          });
        }
        return row;
      });
      if (!updated) throw new AdminHttpError(404, "organization_not_found", "Organization not found");
      json(response, 200, { organization: updated });
      return true;
    }

    // --------------------------------------------- workspace-scoped routes
    const workspaceRoute = match(path, /^\/api\/v1\/workspaces\/([^/]+)\/(.+)$/);
    if (!workspaceRoute) return false;
    const [workspaceId, rest] = workspaceRoute as [string, string];

    // Coding agents (hosted: Settings > Connections > Coding agents).
    if (await handleCodingAgentRoute({
      request,
      response,
      workspaceId,
      rest,
      helpers,
      store: codingAgents,
      logins,
      json,
      requireJsonWrite: (req) => requireJsonWrite(req, helpers),
    })) {
      return true;
    }

    // Environment variables (hosted: /secrets).
    if (rest === "secrets") {
      if (method === "GET") {
        const access = await helpers.workspaceAccess(request, workspaceId, false);
        json(response, 200, { ok: true, data: { items: await envVars.list(access.workspace.id) } });
        return true;
      }
      if (method === "POST") {
        requireJsonWrite(request, helpers);
        const access = await helpers.workspaceAccess(request, workspaceId, true);
        const body = await helpers.requestObject(request);
        if (body.kind !== undefined && body.kind !== "environment") {
          throw new AdminHttpError(400, "invalid_request", "kind must be environment when provided");
        }
        if (body.envVar !== undefined && body.envVar !== body.name) {
          throw new AdminHttpError(400, "invalid_request", "envVar must equal name");
        }
        const { record, created } = await envVars.put({
          workspaceId: access.workspace.id,
          organizationId: access.workspace.organizationId,
          name: body.name,
          value: body.value,
          actor: userActor(access),
        });
        json(response, created ? 201 : 200, record);
        return true;
      }
    }

    const secretItem = match(rest, /^secrets\/([^/]+)$/);
    if (secretItem) {
      const name = secretItem[0]!;
      if (method === "GET") {
        const access = await helpers.workspaceAccess(request, workspaceId, false);
        const record = await envVars.get(access.workspace.id, name);
        if (!record) throw new AdminHttpError(404, "secret_not_found", "Secret not found");
        json(response, 200, record);
        return true;
      }
      if (method === "DELETE") {
        const access = await helpers.workspaceAccess(request, workspaceId, true);
        const record = await envVars.delete({
          workspaceId: access.workspace.id,
          organizationId: access.workspace.organizationId,
          name,
          actor: userActor(access),
        });
        if (!record) throw new AdminHttpError(404, "secret_not_found", "Secret not found");
        json(response, 200, record);
        return true;
      }
    }

    // Provider connections.
    if (rest === "integrations" && method === "GET") {
      const access = await helpers.workspaceAccess(request, workspaceId, false);
      const list = await connections.list(access.workspace.id);
      // Bare array, as hosted (relayfile CLI `integration list` parses this).
      json(response, 200, list.map((connection) =>
        listEntry(providers.get(connection.provider), connection)
      ));
      return true;
    }

    if (rest === "integrations/providers" && method === "GET") {
      const access = await helpers.workspaceAccess(request, workspaceId, false);
      const [apps, list] = await Promise.all([
        connections.listOAuthApps(access.workspace.id),
        connections.list(access.workspace.id),
      ]);
      json(response, 200, {
        redirectUri: config.oauthRedirectUrl,
        canManage: access.workspace.role === "owner" || access.workspace.role === "admin",
        providers: providers.list().map((provider) => {
          const app = apps.find((item) => item.provider === provider.id) ?? null;
          const operator = connections.operatorConfigured(provider.id);
          const configured = provider.authMode === "api_key" || operator || app !== null;
          return {
            ...catalogEntry(provider),
            configured,
            configuredBy: provider.authMode === "api_key" ? null : operator ? "operator" : app ? "workspace" : null,
            ...(configured
              ? {}
              : { adminMessage: `Your administrator needs to configure the ${provider.displayName} app before it can be connected.` }),
            oauthApp: operator ? null : app,
            connection: list.find((item) => item.provider === provider.id) ?? null,
          };
        }),
      });
      return true;
    }

    if (rest === "integrations/connect-session" && method === "POST") {
      requireJsonWrite(request, helpers);
      // Any member may connect just in time (hosted parity): the CLI, flow
      // onboarding and flow creation start here. The OAuth app itself is
      // operator configuration.
      const access = await helpers.workspaceAccess(request, workspaceId, false);
      const body = await helpers.requestObject(request);
      const allowed = body.allowedIntegrations;
      if (!Array.isArray(allowed) || allowed.length !== 1 || typeof allowed[0] !== "string") {
        throw new AdminHttpError(
          400,
          "invalid_request",
          "allowedIntegrations must name exactly one provider",
        );
      }
      if (body.requestedBackend !== undefined && body.requestedBackend !== "selfhost") {
        throw new AdminHttpError(501, "backend_not_supported", "Self-hosted connections use the selfhost backend");
      }
      const provider = providers.get(allowed[0]);
      if (!provider) {
        json(response, 409, {
          error: "unknown_provider",
          providers: providers.list().map((item) => ({
            id: item.id,
            displayName: item.displayName,
            configKey: item.configKey,
            vfsRoot: item.vfsRoot,
          })),
        });
        return true;
      }
      const session = await connections.startOAuth({
        workspaceId: access.workspace.id,
        provider: provider.id,
        userId: access.principal.userId,
        returnTo: safeReturnTo(body.returnTo),
      });
      const relayWorkspace = await database.query<{ relaycast_workspace_id: string }>(
        "SELECT relaycast_workspace_id FROM workspaces WHERE id = $1",
        [access.workspace.id],
      );
      json(response, 200, {
        connectLink: session.connectLink,
        expiresAt: session.expiresAt,
        workspaceId: access.workspace.id,
        // agent-relay cloud integration connect requires it (hosted shape).
        relayWorkspaceId: relayWorkspace.rows[0]?.relaycast_workspace_id ?? access.workspace.id,
        backend: "selfhost",
        backendIntegrationId: provider.id,
        providers: [{
          id: provider.id,
          displayName: provider.displayName,
          backend: "selfhost",
          configKey: provider.configKey,
          providerConfigKey: provider.configKey,
          vfsRoot: provider.vfsRoot,
        }],
      });
      return true;
    }

    const oauthApp = match(rest, /^integrations\/([^/]+)\/oauth-app$/);
    if (oauthApp) {
      const provider = oauthApp[0]!;
      if (method === "PUT") {
        requireJsonWrite(request, helpers);
        const access = await helpers.workspaceAccess(request, workspaceId, true);
        const body = await helpers.requestObject(request);
        const app = await connections.putOAuthApp({
          workspaceId: access.workspace.id,
          organizationId: access.workspace.organizationId,
          provider,
          clientId: body.clientId,
          clientSecret: body.clientSecret,
          scopes: body.scopes,
          actor: userActor(access),
        });
        json(response, 200, app);
        return true;
      }
      if (method === "DELETE") {
        const access = await helpers.workspaceAccess(request, workspaceId, true);
        const deleted = await connections.deleteOAuthApp({
          workspaceId: access.workspace.id,
          organizationId: access.workspace.organizationId,
          provider,
          actor: userActor(access),
        });
        if (!deleted) throw new AdminHttpError(404, "oauth_app_not_found", "OAuth app not configured");
        json(response, 200, { deleted: true });
        return true;
      }
    }

    const integrationStatus = match(rest, /^integrations\/([^/]+)\/status$/);
    const integrationItem = match(rest, /^integrations\/([^/]+)$/);
    const providerId = integrationStatus?.[0] ?? integrationItem?.[0];
    if (providerId && (integrationStatus || integrationItem)) {
      if (method === "GET") {
        const access = await helpers.workspaceAccess(request, workspaceId, false);
        const provider = connections.provider(providerId);
        const connection = await connections.get(access.workspace.id, provider.id);
        if (integrationItem) {
          if (!connection) throw new AdminHttpError(404, "integration_not_found", "Integration not connected");
          json(response, 200, listEntry(provider, connection));
          return true;
        }
        const requested = url.searchParams.get("connectionId");
        json(response, 200, {
          ready: connection?.status === "ready",
          provider: provider.id,
          displayName: provider.displayName,
          backend: "selfhost",
          configKey: provider.configKey,
          vfsRoot: provider.vfsRoot,
          state: connection ? connection.status : "pending",
          connectionId: connection?.connectionId ?? null,
          requestedConnectionId: requested,
          currentConnectionId: connection?.connectionId ?? null,
          connectionMatched: requested ? requested === connection?.connectionId : null,
          oauth: {
            connected: Boolean(connection),
            connectedAt: connection?.connectedAt ?? null,
            lastAuthAt: connection?.lastRefreshedAt ?? connection?.updatedAt ?? null,
          },
        });
        return true;
      }
      if (method === "DELETE") {
        const access = await helpers.workspaceAccess(request, workspaceId, true);
        const deleted = await connections.disconnect({
          workspaceId: access.workspace.id,
          organizationId: access.workspace.organizationId,
          provider: providerId,
          actor: userActor(access),
        });
        json(response, 200, {
          success: true,
          localDeleted: deleted,
          // Self-host keeps no upstream connection object; revoke the grant
          // in the provider's settings if required.
          upstreamDelete: { success: true, backend: "selfhost", skipped: true },
        });
        return true;
      }
      if (method === "POST" && integrationItem) {
        requireJsonWrite(request, helpers);
        const access = await helpers.workspaceAccess(request, workspaceId, true);
        const body = await helpers.requestObject(request);
        if (body.connectionId !== undefined) {
          throw new AdminHttpError(
            400,
            "invalid_request",
            "Self-hosted connections are created by OAuth or credentials, not by connectionId",
          );
        }
        const connection = await connections.putApiKeyConnection({
          workspaceId: access.workspace.id,
          organizationId: access.workspace.organizationId,
          provider: providerId,
          credentials: body.credentials,
          actor: userActor(access),
        });
        json(response, 201, connection);
        return true;
      }
    }

    // Workspace API tokens (hosted: deployment-api-tokens). Owner/admin only.
    if (rest === "deployment-api-tokens") {
      if (method === "GET") {
        const access = await helpers.workspaceAccess(request, workspaceId, true);
        json(response, 200, { tokens: await apiTokens.list(access.workspace.id) });
        return true;
      }
      if (method === "POST") {
        requireJsonWrite(request, helpers);
        const access = await helpers.workspaceAccess(request, workspaceId, true);
        const body = await helpers.requestObject(request);
        const token = await apiTokens.create({
          workspaceId: access.workspace.id,
          organizationId: access.workspace.organizationId,
          label: body.label,
          purpose: body.purpose,
          expiryDays: body.expiryDays,
          neverExpires: body.neverExpires,
          agentName: body.agent_name,
          aud: body.aud,
          scope: body.scope,
          scopes: body.scopes,
          actor: userActor(access),
        });
        json(response, 201, token);
        return true;
      }
    }
    const tokenItem = match(rest, /^deployment-api-tokens\/([^/]+)$/);
    if (tokenItem && method === "DELETE") {
      const access = await helpers.workspaceAccess(request, workspaceId, true);
      const revoked = await apiTokens.revoke({
        workspaceId: access.workspace.id,
        organizationId: access.workspace.organizationId,
        tokenId: tokenItem[0]!,
        actor: userActor(access),
      });
      if (!revoked) throw new AdminHttpError(404, "token_not_found", "Token not found");
      response.writeHead(204, { "cache-control": "no-store" });
      response.end();
      return true;
    }

    if (rest === "admin/audit" && method === "GET") {
      const access = await helpers.workspaceAccess(request, workspaceId, true);
      json(response, 200, { events: await listAudit(database, access.workspace.id) });
      return true;
    }

    return false;
  }

  return { handle, envVars, connections, apiTokens, providers, codingAgents, logins, runtimeEnvironment };
}

/** Maps admin-module errors to HTTP. Returns null for foreign errors. */
export function adminErrorResponse(
  error: unknown,
): { status: number; body: { error: string; message: string } } | null {
  if (
    error instanceof AdminHttpError ||
    error instanceof ConnectionError ||
    error instanceof CodingAgentError ||
    error instanceof ApiTokenError
  ) {
    return { status: error.status, body: { error: error.code, message: error.message } };
  }
  if (error instanceof EnvVarValidationError) {
    return { status: 400, body: { error: "invalid_workspace_secret", message: error.message } };
  }
  if (error instanceof ProviderTokenError) {
    return { status: 502, body: { error: "provider_token_error", message: error.message } };
  }
  return null;
}
