import { revokeOrganizationMcpOAuthGrants } from "./mcp/oauth/revocations.js";
import { createMcpOAuthHttpModule } from "./mcp/oauth/routes.js";
import { McpOAuthStore } from "./mcp/oauth/store.js";
import { connectorKind } from "./mcp/oauth/connector-kind.js";
import { ownerHash, HOSTED_SOURCE } from "./mcp/relay-participants.js";
import { McpOAuthTeardown,mcpOAuthTeardownFetch } from "./mcp/oauth/teardown.js";
import { mcpOAuthActive } from "./mcp/oauth/config.js";
import { retiringIdentity } from "./mcp/oauth/retirement.js";
import { isDeviceReservedClientName } from "./reserved-client-names.js";
import type { IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { SELFHOST_API_VERSION, type SelfhostConfig } from "./config.js";
import { secureEqual } from "./crypto.js";
import { adminErrorResponse, type AdminModule } from "./admin/routes.js";
import { ApiTokenStore } from "./admin/api-tokens.js";
import { recordAudit } from "./admin/audit.js";
import { ReadCursorExpiredError, UpstreamError } from "./relayhistory.js";
import { handleChiefRelay } from "./chief-relay.js";
import { handleRelayNode } from "./relay-node/broker.js";
import { handleFlowsBroker } from "./flows-broker.js";
import { FlowRunRelayfileCredentials } from "./flows/relayfile-credentials.js";
import { handleSessionRoutes } from "./sessions/routes.js";
import { UsageRangeError, usageDays, usageReport } from "./usage/routes.js";
import { UsageStore } from "./usage/store.js";
import { readSessionRequest, readRefreshRequest, requestReadSession, SessionReadError } from "./session-read.js";
import { z } from "zod";
import { acceptedAudiences, handleIntrospection, introspect, INTROSPECT_PATH } from "./auth/introspect.js";
import { IntrospectionHold } from "./auth/introspection-hold.js";
import { handleAcquisitionRoutes } from "./acquisition/routes.js";
import { createDesktopFeedHandler, type DesktopFeedLimits } from "./desktop-feed/routes.js";
import { AwsKmsDesktopFeedSigner, MemoryDesktopFeedSigner, type DesktopFeedSigner } from "./desktop-feed/signer.js";
import { MemoryDesktopFeedStorage, S3DesktopFeedStorage, type DesktopFeedStorage } from "./desktop-feed/storage.js";
import { DesktopFeedStore } from "./desktop-feed/store.js";
import { DefaultAwsCredentialProvider, type AwsCredentialProvider } from "./aws/sigv4.js";
import { AwsStsClient, type StsClient } from "./aws/sts.js";
import {
  HistoryUploadCredentials,
  parseUploadCredentialsRequest,
  S3PrivacyJournalReader,
  UploadCredentialsError,
  type PrivacyJournalReader,
} from "./history-upload/credentials.js";
import {
  ACCOUNT_SCOPE,
  DASHBOARD_DEVICE_CLIENT,
  DESKTOP_WORKSPACES_SCOPE,
  InvitationRequiredError,
  MembershipConflictError,
  NODE_ID_PATTERN,
  NodeClaimError,
  OrganizationBoundaryError,
  OrganizationConflictError,
  ReservedClientNameError,
  type ControlPlaneStore,
  type Principal,
} from "./store.js";
import { createFlowsHandler } from "./flows/routes.js";
import { isUuid, type FlowsStore } from "./flows/store.js";
import type { TelemetryModule } from "./telemetry/module.js";
import { identityErrorResponse, type IdentityModule } from "./identity/routes.js";
import { revokeRemovedMember, type MessagingDeps } from "./messaging/identity.js";
import { createMessagingHandler, MessagingHttpError } from "./messaging/routes.js";
import { createFactoryModule, mountFactoryRoutes, type FactoryModule } from "./factory/routes.js";
import { createMcpHandler } from "./mcp/routes.js";
import type { AmpModule } from "./amp/module.js";
import { isAmpPath } from "./amp/routes.js";
import { purgeMemberAmp, releaseMemberAmp } from "./amp/service.js";
import {
  DESKTOP_MCP_TOKEN,
  DesktopMcpCredentialError,
  DesktopMcpCredentials,
  PROVIDER,
  UUID,
} from "./auth/desktop-mcp-credentials.js";
import { handleDesktopIdentityRoutes } from "./messaging/desktop-identities.js";
import { handleChiefRoutes, type ChiefBackend } from "./chief/routes.js";
import { handleProviderRoutes } from "./providers/routes.js";
import { RemoteAgentConnections } from "./remote-agents/connections.js";
import { remoteAgentRoutes } from "./remote-agents/routes.js";
import type { ProviderProbes } from "./providers/registry.js";
import {
  CapturePolicyError,
  parseCaptureSettings,
  parseIfMatch,
  readCapturePolicy,
  writeCapturePolicy,
} from "./capture-policy.js";
import { operatorControlsEntitled } from "./admin/operator-controls.js";
import { createRelaycastClient, type RosterAgent } from "./messaging/relaycast.js";
import { isListedRelayAgent } from "./mcp/team-activity.js";
import {
  erasureTarget,
  eraseSession,
  readSessionErasure,
  requireErasureApi,
  SessionErasureError,
} from "./session-erasure.js";
import {
  FeatureRefusedError,
  NO_FEATURES,
  requireSelected,
  type Feature,
  type SelectedFeatures,
} from "./features.js";
import type { AnalyticsConfig } from "./analytics/config.js";
import {
  clientAttribution,
  GATEWAY_RATE_LIMITS,
  GATEWAY_REQUIRED_SCOPE,
  GatewayRequestError,
  parseClientBatch,
} from "./analytics/gateway.js";
import { droppedTotal } from "./analytics/queue.js";
import type { AnalyticsGatewayCounter, AnalyticsGatewayRejection, AnalyticsPort } from "./analytics/types.js";
import {
  clientIp,
  cookieRequestAllowed,
  DEVICE_RATE_LIMITS,
  deviceApprovalPageUrl,
  limiterKey,
  RateLimiter,
  safeNextPath,
  sanitizeDesktopHostName,
} from "./auth/device-approval.js";
import {
  challengeMatches,
  cloudPathForNext,
  DESKTOP_CONSENT_FIELDS,
  DESKTOP_LOGIN_RATE_LIMITS,
  desktopConsentDeniedPage,
  desktopConsentPage,
  desktopWorkspacePickerPage,
  handoffCallbackUrl,
  validateDesktopLogin,
} from "./auth/desktop-login.js";

type JsonObject = Record<string, unknown>;
const WorkspaceChoice = z.object({ workspaceId: z.string().trim().min(1).max(200) }).strict();
/** Multi mode: listing and minting across workspaces (DG-001 capability routes). */
const CAPABILITY_RATE_LIMIT = { limit: 30, windowMs: 60 * 1_000 };
/** `token` is the caller's raw access token; it is a credential, never log it. */
type Auth = { kind: "bootstrap" } | { kind: "user"; principal: Principal; token: string };
const ACCESS_TOKEN_PREFIX = "sh_at_";
/** Upper bound on the advisory expiry of a native upload session (ingest re-introspects every call). */
const NATIVE_UPLOAD_SESSION_MAX_MS = 15 * 60_000;
/** Not a credential: the native ingest edge never reads it and refuses every refresh with 401. */
const NATIVE_UPLOAD_NO_REFRESH = "native_ingest_no_refresh";
const SESSION_COOKIE = "agent_relay_session";
const DEVICE_COOKIE = "agent_relay_device";

class HttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly extra?: Record<string, string>) {
    super(message);
  }
}

function json(response: ServerResponse, status: number, body: unknown, noStore = false): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    ...(noStore ? { "cache-control": "no-store" } : {}),
  });
  response.end(JSON.stringify(body));
}

function text(response: ServerResponse, status: number, body: string, type = "text/plain"): void {
  response.writeHead(status, { "content-type": `${type}; charset=utf-8` });
  response.end(body);
}

function bearer(request: IncomingMessage): string | null {
  const header = request.headers.authorization;
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match?.[1]?.trim() || null;
}

function cookie(request: IncomingMessage, name: string): string | null {
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

function secureCookie(name: string, value: string, path: string, maxAge: number): string {
  return `${name}=${encodeURIComponent(value)}; Path=${path}; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;
}

function clearCookie(name: string, path: string): string {
  return `${name}=; Path=${path}; Max-Age=0; Secure; HttpOnly; SameSite=Lax`;
}

function html(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function normalizeRoutePath(path: string): string {
  if (path === "/cloud/api/v1") return "/api/v1";
  return path.startsWith("/cloud/api/v1/")
    ? path.slice("/cloud".length)
    : path;
}

const DEFAULT_BODY_LIMIT_BYTES = 1024 * 1024;

/** Reads the body, refusing it (413) as soon as the streamed bytes pass `maxBytes`. */
async function bodyText(request: IncomingMessage, maxBytes = DEFAULT_BODY_LIMIT_BYTES): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > maxBytes) {
      throw new HttpError(
        413,
        "payload_too_large",
        maxBytes === DEFAULT_BODY_LIMIT_BYTES ? "Body exceeds 1 MiB" : `Body exceeds ${maxBytes} bytes`,
      );
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function requestObject(request: IncomingMessage): Promise<JsonObject> {
  const raw = await bodyText(request);
  if (!raw.trim()) return {};
  const contentType = request.headers["content-type"]?.split(";")[0]?.trim();
  if (contentType === "application/x-www-form-urlencoded") {
    return Object.fromEntries(new URLSearchParams(raw));
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new HttpError(400, "invalid_request", "Body must be valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new HttpError(400, "invalid_request", "Body must be a JSON object");
  }
  return parsed as JsonObject;
}

function stringField(body: JsonObject, name: string, required = true): string | undefined {
  const value = body[name];
  if (value === undefined && !required) return undefined;
  if (typeof value !== "string" || !value.trim()) {
    throw new HttpError(400, "invalid_request", `${name} must be a non-empty string`);
  }
  return value.trim();
}

/** RFC 8628 §3.5 descriptions, as hosted Cloud sends them. */
const DEVICE_TOKEN_ERROR_DESCRIPTIONS: Record<string, string> = {
  authorization_pending: "The user has not approved this device yet; keep polling at the interval",
  slow_down: "Polling too fast; wait the returned interval before polling again",
  access_denied: "The user denied this device authorization",
  expired_token: "The device code has expired; start a new device authorization",
  invalid_grant: "The device code is unknown or was already used; start a new device authorization",
};

const RELAYCAST_TIMEOUT_MS = 10_000;

async function relaycastJson(
  url: string,
  bearerToken: string,
): Promise<{ status: number; data: Record<string, unknown> | null }> {
  let response: Response;
  try {
    response = await globalThis.fetch(url, {
      headers: { authorization: `Bearer ${bearerToken}` },
      signal: AbortSignal.timeout(RELAYCAST_TIMEOUT_MS),
    });
  } catch {
    // A stalled or unreachable Relaycast is a 502, never a hung request.
    throw new NodeClaimError(502, "Relaycast could not confirm the node.");
  }
  const body = await response.json().catch(() => null) as { data?: unknown } | null;
  const data = body?.data;
  return {
    status: response.status,
    data: data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : null,
  };
}

/**
 * Which node a node token belongs to, and that it is in this workspace's
 * relay (hosted Cloud's verifyNodeToken): the token's own `/v1/node/me`, then
 * the workspace key's read of that node by name, whose id must match.
 */
async function verifyNodeToken(
  relaycastUrl: string,
  workspaceKey: string,
  nodeToken: string,
): Promise<{ id: string; name: string }> {
  const base = relaycastUrl.replace(/\/+$/, "");
  const me = await relaycastJson(`${base}/v1/node/me`, nodeToken);
  if (me.status === 401 || me.status === 403) {
    throw new NodeClaimError(403, "That is not a valid node token for this workspace.");
  }
  const id = me.data?.id;
  const name = me.data?.name;
  if (
    me.status !== 200 || typeof id !== "string" || !/^[A-Za-z0-9._:-]{1,200}$/.test(id) ||
    typeof name !== "string" || !name
  ) {
    throw new NodeClaimError(502, "Relaycast could not confirm the node.");
  }
  const inWorkspace = await relaycastJson(`${base}/v1/nodes/${encodeURIComponent(name)}`, workspaceKey);
  if (inWorkspace.status === 404 || (inWorkspace.status === 200 && inWorkspace.data?.id !== id)) {
    throw new NodeClaimError(403, "That node token belongs to another workspace.");
  }
  if (inWorkspace.status !== 200) throw new NodeClaimError(502, "Relaycast could not confirm the node.");
  return { id, name };
}

function routeMatch(pathname: string, pattern: RegExp): string[] | null {
  const match = pattern.exec(pathname);
  return match ? match.slice(1).map(decodeURIComponent) : null;
}

/** Origins allowed to send cookie-authenticated writes. */
export function browserOriginsFor(config: SelfhostConfig): string[] {
  return [...new Set([
    new URL(config.publicBaseUrl).origin,
    new URL(config.dashboardUrl).origin,
  ])];
}

/** A bodiless cookie DELETE needs an allowed Origin, or same-origin fetch metadata. */
function cookieDeleteAllowed(request: IncomingMessage, browserOrigins: string[]): boolean {
  const origin = request.headers.origin;
  return typeof origin === "string" && origin && origin !== "null"
    ? browserOrigins.includes(origin)
    : request.headers["sec-fetch-site"] === "same-origin";
}

export function createApp(input: {
  config: SelfhostConfig;
  store: ControlPlaneStore;
  flows?: FlowsStore | (() => FlowsStore);
  /**
   * Per-run Relayfile credentials (docs/flows-relayfile-credential.md). Unset:
   * built from the Flows settings, read only when a credential is issued.
   */
  flowRelayfileCredentials?: FlowRunRelayfileCredentials;
  admin?: AdminModule;
  telemetry?: TelemetryModule;
  /** bootstrap-signup lane: OIDC / email sign-in, invites (src/identity). */
  identity?: IdentityModule;
  chief?: ChiefBackend;
  /** SELFHOST_FEATURES selection (src/features.ts). Unset = core only. */
  features?: SelectedFeatures;
  /** Amp control (src/amp). Absent or disabled: every Amp route answers 404 before auth. */
  amp?: AmpModule;
  /** Server-owned worker; absent tests use the same on-demand cleanup without a timer. */
  mcpOAuthTeardown?: McpOAuthTeardown;
  /**
   * Runtime probes for the provider modules this build contains. Unset (the
   * default) means no provider module: each reports implemented, configured
   * and enabled as false.
   */
  providerProbes?: ProviderProbes;
  /** Fixed-origin provider credential checks; injectable for offline tests. */
  remoteAgentFetch?: typeof fetch;
  /**
   * analytics lane: the product-analytics port and its configuration. The
   * client gateway (POST /api/v1/analytics/events) is mounted only when the
   * destination is not `none`.
   */
  analytics?: {
    port: AnalyticsPort;
    config: Pick<AnalyticsConfig, "destination" | "gateway">;
    /** Test hook: gateway rate limits. Production leaves this unset (GATEWAY_RATE_LIMITS). */
    rateLimits?: Partial<Record<keyof typeof GATEWAY_RATE_LIMITS, { limit: number; windowMs: number }>>;
  };
  /** Person messaging. Tests pass fetchImpl; the server uses global fetch. */
  messagingFetch?: typeof fetch;
  /** Factory sessions (dormant unless SELFHOST_FACTORY_ENABLED). The server passes its module so it can run the worker. */
  factory?: FactoryModule;
  /** Desktop feed overrides for tests; the feed itself is on only when config.desktopFeed is set. */
  desktopFeed?: {
    signer?: DesktopFeedSigner;
    storage?: DesktopFeedStorage;
    limits?: Partial<DesktopFeedLimits>;
    log?: (message: string, fields: Record<string, unknown>) => void;
  };
  /** Direct-to-S3 upload credential overrides for tests; the route is on only when config.historyUpload is set. */
  historyUpload?: {
    sts?: StsClient;
    journal?: PrivacyJournalReader;
    credentials?: AwsCredentialProvider;
    endpoints?: { sts?: string; s3?: string };
    fetchImpl?: typeof fetch;
  };
  now?: () => Date;
  /** Test hooks for claim leases and crash injection. Production leaves this unset. */
  messaging?: Pick<MessagingDeps,
    "claimLeaseMs" | "beforeDispatch" | "afterUpstream" | "afterRemoteRegister" | "afterIdentityStaged" | "beforeMembershipRecheck">;
}): (request: IncomingMessage, response: ServerResponse) => void {
  const { config, store, admin, telemetry, identity } = input;
  const features = input.features ?? NO_FEATURES;
  // Usage page counters: written only while the `usage` feature is selected.
  const usage = new UsageStore(store.database, () => input.now?.() ?? new Date());
  const recordUsage = (write: () => Promise<void>): void => {
    if (!features.usage) return;
    // Counters never fail or slow a request.
    void write().catch(() => {});
  };
  // Every route that authenticates an access token (API, dashboard account
  // pages, Desktop, MCP) counts its user as active today.
  if (features.usage) {
    store.onAuthenticated = (principal) =>
      recordUsage(() => usage.recordActiveUser(principal.organizationId, principal.userId));
  }
  /** Throws the 403 refusal unless `feature` is selected. Call after membership, before backends. */
  function requireFeature(feature: Feature): void {
    requireSelected(features, feature);
  }
  // Database outage hold for POST /internal/v1/auth/introspect (opt-in, per process).
  const introspectionHold = (config.introspectOutageHoldMs ?? 0) > 0
    ? new IntrospectionHold(config.introspectOutageHoldMs!)
    : undefined;
  const browserOrigins = browserOriginsFor(config);
  // The desktop sign-in pages post to a path-only action, so the form always
  // resolves to the page's own origin; both browser origins (API and
  // dashboard) are still named in form-action so the policy holds however
  // the page was reached, and the Origin check on the post accepts the same set.
  const formActionSources = ["'self'", ...browserOrigins];
  const messagingDeps: MessagingDeps = {
    database: store.database,
    keyring: config.encryptionKeyring,
    relaycastUrl: config.relaycastUrl,
    fetchImpl: input.messagingFetch,
    now: input.now,
    ...input.messaging,
  };
  const messaging = createMessagingHandler({
    ...messagingDeps,
    relaycastPublicUrl: config.relaycastPublicUrl,
    internalServiceToken: config.internalServiceToken,
    browserOrigins,
  });
  const factory = input.factory ?? createFactoryModule({
    config,
    database: store.database,
    messaging: messagingDeps,
    browserOrigins,
    relayFetch: input.messagingFetch,
  });
  // desktop-auth lane: hosted Cloud's device-route limits and CSRF origins.
  const limiter = new RateLimiter(() => (input.now?.() ?? new Date()).getTime());
  const NODE_TOKEN = /^nt_live_[A-Za-z0-9_-]{8,256}$/;
  const NODE_ID = NODE_ID_PATTERN;
  // The site a client signed in through: the public API origin or the
  // dashboard origin (both serve /cloud/api). Agent Relay Desktop requires
  // api_url == <its site>/cloud, so sign-in answers name the origin the
  // request arrived on. Only these configured origins are ever echoed, so a
  // forged Host header cannot point a client elsewhere.
  const siteBases = new Map<string, string>([
    [new URL(config.dashboardUrl).host.toLowerCase(), new URL(config.dashboardUrl).origin],
    [new URL(config.publicBaseUrl).host.toLowerCase(), config.publicBaseUrl.replace(/\/+$/, "")],
  ]);
  function siteBaseUrl(request: IncomingMessage): string {
    const host = typeof request.headers.host === "string" ? request.headers.host.trim().toLowerCase() : "";
    return siteBases.get(host) ?? config.publicBaseUrl.replace(/\/+$/, "");
  }
  // Hosted MCP (shared-sessions facade): reads, team activity, capabilities.
  const amp = input.amp?.config.enabled ? input.amp : null;
  const providerProbes: ProviderProbes = input.providerProbes ?? {};
  const remoteAgents = remoteAgentRoutes(new RemoteAgentConnections(store.database, config.encryptionKeyring, input.remoteAgentFetch));
  const oauthRelay = createRelaycastClient({internalOrigin:config.relaycastUrl,fetchImpl:input.messagingFetch});
  const oauthTeardown=mcpOAuthActive(config) ? input.mcpOAuthTeardown??new McpOAuthTeardown({
    database:store.database,keyring:config.encryptionKeyring,
    client:createRelaycastClient({internalOrigin:config.relaycastUrl,fetchImpl:mcpOAuthTeardownFetch(input.messagingFetch)}),now:input.now,
  }) : null;
  const mcpOAuth = createMcpOAuthHttpModule({
    config,mountedResources:["/mcp","/api/v1/mcp/shared-sessions"],
    clientAddress:request=>limiterKey(clientIp(request)),
    createStore:({protocol,issuer})=>new McpOAuthStore(store.database,{
      protocol,tenancyMode:store.tenancy,now:input.now,issueIdToken:issuer?.issueMcpOidcIdToken,
      isGrokRoutine:(request,client)=>request.resourcePath==="/api/v1/mcp/relay-events" &&
        request.scopes.includes("relay:events") && connectorKind({
          clientName:client.clientName,redirectUris:[request.redirectUri],
        })==="grok-bot",
    }),
    resolveSession:async request=>{
      if(request.headers.has("authorization")) return null;
      const raw=(request.headers.get("cookie")??"").split(";").map(part=>part.trim())
        .find(part=>part.startsWith(SESSION_COOKIE+"="))?.slice(SESSION_COOKIE.length+1);
      if(!raw) return null;
      let token:string;try {token=decodeURIComponent(raw);} catch {return null;}
      const principal=await store.authenticateAccessToken(token);
      return principal?{transport:"cookie" as const,principal}:null;
    },
    workspaceAccess:async principal=>{
      if(!(await store.readiness()).ready) return false;
      const workspace=await store.workspaceForUser(principal.workspaceId,principal.userId);
      return workspace?.organizationId===principal.organizationId;
    },
    workspaceLabel:async principal=>(await store.workspaceForUser(principal.workspaceId,principal.userId))?.name??principal.workspaceId,
    checkAgentNameAvailability:async(principal,name)=>{
      const workspace=await store.workspaceForUser(principal.workspaceId,principal.userId);
      if(!workspace || workspace.organizationId!==principal.organizationId) return "unknown";
      const remote=await oauthRelay.getAgent(workspace.relaycastApiKey,name);
      if(!remote) return "available";
      if(remote.metadata.source!==HOSTED_SOURCE || remote.metadata.cloud_workspace_id!==principal.workspaceId ||
        remote.metadata.owner_hash!==ownerHash(principal.userId)) return "taken";
      // An agent whose release may be in flight cannot be attached to.
      return await retiringIdentity(store.database,{organizationId:principal.organizationId,workspaceId:principal.workspaceId,
        userId:principal.userId,agentRemoteId:remote.id,agentName:remote.name})?"taken":"yours";
    },
    now:input.now,afterMutation:()=>oauthTeardown?.kick(),
  });
  const mcp = createMcpHandler({
    config, store, browserOrigins, siteBaseUrl, fetchImpl: input.messagingFetch, providerProbes,
    ...(amp ? { amp: amp.deps } : {}),
    ...(factory.enabled ? { factory: factory.mcp } : {}),
    ...(mcpOAuth.store ? {oauthSessions:mcpOAuth.store.sessions} : {}),
  });
  const desktopMcpCredentials = new DesktopMcpCredentials(store.database);
  const DESKTOP_MCP_RATE = { limit: 30, windowMs: 60_000 };
  const AGENT_NAMES_RATE = { limit: 60, windowMs: 60_000 };
  function rateLimit(
    response: ServerResponse,
    key: string,
    rule: { limit: number; windowMs: number },
    code: string,
    message: string,
  ): void {
    const result = limiter.consume(key, rule.limit, rule.windowMs);
    if (result.allowed) return;
    response.setHeader("retry-after", String(result.retryAfterSeconds));
    throw new HttpError(429, code, message);
  }

  async function authenticate(request: IncomingMessage, bootstrap = false): Promise<Auth> {
    const headerToken = bearer(request);
    const requestPath = new URL(request.url ?? "/", config.publicBaseUrl).pathname;
    const cookieToken = requestPath === "/cloud" || requestPath.startsWith("/cloud/")
      ? cookie(request, SESSION_COOKIE)
      : null;
    const token = headerToken ?? cookieToken;
    if (!token) throw new HttpError(401, "unauthorized", "Authentication required");
    if (bootstrap && headerToken && secureEqual(token, config.bootstrapToken)) {
      return { kind: "bootstrap" };
    }
    const principal = await store.authenticateAccessToken(token);
    if (!principal) throw new HttpError(401, "unauthorized", "Invalid or expired token");
    return { kind: "user", principal, token };
  }

  // analytics lane: the client gateway. Authority comes only from the
  // credential's principal; the body names events and properties, nothing else.
  const analyticsGateway = input.analytics && input.analytics.config.destination !== "none"
    ? input.analytics
    : null;

  async function analyticsEvents(
    request: IncomingMessage,
    response: ServerResponse,
    gateway: NonNullable<typeof analyticsGateway>,
  ): Promise<void> {
    const { port } = gateway;
    const count = (counter: AnalyticsGatewayCounter, amount = 1) => {
      try {
        port.recordGateway?.(counter, amount);
      } catch {
        // Counters never fail a request.
      }
    };
    count("requests");
    // Which gateway.rejected counter an HttpError at the current step maps to.
    let step: AnalyticsGatewayRejection = "auth";
    try {
      // Bootstrap, internal and workspace API tokens resolve to no session: 401.
      const auth = await authenticate(request);
      if (auth.kind !== "user") throw new HttpError(401, "unauthorized", "User token required");
      const { principal } = auth;
      // authenticate() takes the bearer first and the cookie only under /cloud/.
      const client = bearer(request) ? "desktop" : "dashboard";
      if (client === "dashboard" && !cookieRequestAllowed(request, browserOrigins)) {
        step = "csrf";
        throw new HttpError(403, "forbidden", "Cross-origin analytics request refused");
      }
      if (!principal.scopes.includes(GATEWAY_REQUIRED_SCOPE)) {
        throw new HttpError(403, "forbidden", `Scope ${GATEWAY_REQUIRED_SCOPE} required`);
      }
      step = "rate_limited";
      const limited = "Too many analytics requests. Try again shortly.";
      const limits = { ...GATEWAY_RATE_LIMITS, ...gateway.rateLimits };
      rateLimit(response, `analytics:session:${principal.sessionId}`, limits.session, "rate_limited", limited);
      // Keyed by limiterKey(clientIp()), as the auth limiters are: the socket address, or
      // with SELFHOST_TRUSTED_PROXIES=N the address the Nth trusted proxy saw;
      // see docs/analytics.md "Rate limits and the forwarded-header boundary".
      rateLimit(response, `analytics:ip:${limiterKey(clientIp(request))}`, limits.ip, "rate_limited", limited);
      // A membership revoked after the token was checked attributes nothing.
      step = "auth";
      const workspace = await store.workspaceForUser(principal.workspaceId, principal.userId);
      if (!workspace) throw new HttpError(404, "workspace_not_found", "Workspace not found");
      step = "body";
      const raw = await bodyText(request, gateway.config.gateway.maxBodyBytes);
      const now = (input.now?.() ?? new Date()).getTime();
      const events = parseClientBatch(raw, { client, maxEvents: gateway.config.gateway.maxEvents, now });

      const authority = { organizationId: principal.organizationId, workspaceId: principal.workspaceId };
      const traceId = randomUUID();
      const droppedBefore = droppedTotal(port.stats());
      for (const event of events) {
        port.capture({
          event: event.event,
          properties: event.properties,
          traceId,
          occurredAt: event.occurredAt,
          ...clientAttribution(event.scope, authority),
        });
      }
      const queued = droppedTotal(port.stats()) === droppedBefore;
      count("accepted", events.length);
      const adjusted = events.filter((event) => event.clockAdjusted).length;
      if (adjusted > 0) count("clock_adjusted", adjusted);
      json(response, 202, { accepted: events.length, queued }, true);
    } catch (error) {
      if (error instanceof GatewayRequestError) {
        count(`rejected.${error.counter}`);
        throw new HttpError(error.status, error.code, error.message);
      }
      if (error instanceof HttpError) count(`rejected.${step}`);
      throw error;
    }
  }

  async function organizationAccess(
    request: IncomingMessage,
    organizationId: string,
    admin = false,
  ): Promise<Auth> {
    const auth = await authenticate(request, true);
    if (!await store.organizationExists(organizationId)) {
      throw new HttpError(404, "organization_not_found", "Organization not found");
    }
    if (auth.kind === "bootstrap") {
      // Multi mode: the installation-wide operator bearer leaves a trail in
      // the organization it acted on.
      if (store.tenancy === "multi") {
        await recordAudit(store.database, {
          organizationId,
          actor: { kind: "bootstrap" },
          action: "bootstrap.access",
          target: `${request.method ?? "GET"} ${new URL(request.url ?? "/", config.publicBaseUrl).pathname}`,
        });
      }
      return auth;
    }
    // DG-001: a token acts only in the organization it was issued for, as a
    // bearer or as the cookie alike; the role is the live one there.
    if (auth.principal.organizationId !== organizationId) {
      throw new HttpError(404, "organization_not_found", "Organization not found");
    }
    const role = await store.memberRole(organizationId, auth.principal.userId);
    if (!role) throw new HttpError(404, "organization_not_found", "Organization not found");
    if (admin && role !== "owner" && role !== "admin") {
      throw new HttpError(403, "forbidden", "Organization admin role required");
    }
    return auth;
  }

  const apiTokens = new ApiTokenStore(store.database);
  const flowRelayfileCredentials = input.flowRelayfileCredentials ?? new FlowRunRelayfileCredentials(
    store.database,
    () => input.now?.() ?? new Date(),
    () => {
      const flowsStore = typeof input.flows === "function" ? input.flows() : input.flows;
      return flowsStore
        ? {
            ttlMs: flowsStore.config.relayfileCredentialTtlMs,
            workerRelayfileUrl: flowsStore.config.workerRelayfileUrl,
            audiences: () => acceptedAudiences(config),
          }
        : null;
    },
  );

  /** Workspace agent tokens and the service token are not a person. */
  async function rejectServiceCredential(request: IncomingMessage): Promise<void> {
    const token = bearer(request);
    if (!token) return;
    if (config.internalServiceToken && secureEqual(token, config.internalServiceToken)) {
      throw new HttpError(403, "forbidden", "Service credentials cannot resolve the Relaycast key");
    }
    if (token.startsWith("sh_wk_") && await apiTokens.authenticate(token)) {
      throw new HttpError(403, "forbidden", "Agent, CI, and service tokens cannot resolve the Relaycast key");
    }
  }

  async function workspaceAccess(
    request: IncomingMessage,
    workspaceId: string,
    admin = false,
  ) {
    const auth = await authenticate(request);
    if (auth.kind !== "user") throw new HttpError(401, "unauthorized", "User token required");
    if (workspaceId !== auth.principal.workspaceId) {
      throw new HttpError(404, "workspace_not_found", "Workspace not found");
    }
    const workspace = await store.workspaceForUser(workspaceId, auth.principal.userId);
    if (!workspace) throw new HttpError(404, "workspace_not_found", "Workspace not found");
    if (admin && workspace.role !== "owner" && workspace.role !== "admin") {
      throw new HttpError(403, "forbidden", "Workspace admin role required");
    }
    return { principal: auth.principal, workspace, token: auth.token };
  }

  // Desktop feed (docs/desktop-feed.md): off, so every route 404s, unless
  // both SELFHOST_DESKTOP_FEED_SIGNER and _STORAGE are configured.
  const feedConfig = config.desktopFeed ?? null;
  const desktopFeed = feedConfig
    ? createDesktopFeedHandler({
      config,
      controlStore: store,
      store: new DesktopFeedStore(store.database),
      signer: input.desktopFeed?.signer ?? (feedConfig.signer.kind === "awskms"
        ? new AwsKmsDesktopFeedSigner({
          region: feedConfig.signer.region, label: feedConfig.signer.label, keyAliases: feedConfig.signer.keyAliases,
        })
        : new MemoryDesktopFeedSigner({ label: feedConfig.signer.label })),
      storage: input.desktopFeed?.storage ?? (feedConfig.storage.kind === "s3"
        ? new S3DesktopFeedStorage({
          bucket: feedConfig.storage.bucket, region: feedConfig.storage.region, prefix: feedConfig.storage.prefix,
        })
        : new MemoryDesktopFeedStorage()),
      browserOrigins,
      publisherTokenHashes: feedConfig.publisherTokenHashes,
      now: input.now,
      limits: input.desktopFeed?.limits,
      log: input.desktopFeed?.log,
      organizationAccess,
      requestObject,
      json,
      httpError: (status, code, message) => new HttpError(status, code, message),
    })
    : null;

  // Direct-to-S3 session uploads (docs/sessions-read-api.md): off, so the
  // upload-credentials route 404s, unless SELFHOST_HISTORY_UPLOAD_DIRECT is
  // allowlist or on. One AWS credential provider serves STS and the journal.
  const uploadConfig = config.historyUpload ?? null;
  const historyUpload = uploadConfig
    ? (() => {
      const hooks = input.historyUpload;
      const credentials = hooks?.credentials ?? new DefaultAwsCredentialProvider();
      return new HistoryUploadCredentials({
        config: uploadConfig,
        sts: hooks?.sts ?? new AwsStsClient({
          region: uploadConfig.region, credentials, endpoint: hooks?.endpoints?.sts, fetchImpl: hooks?.fetchImpl, now: input.now,
        }),
        journal: hooks?.journal ?? new S3PrivacyJournalReader({
          bucket: uploadConfig.bucket,
          region: uploadConfig.region,
          credentials,
          endpoint: hooks?.endpoints?.s3,
          fetchImpl: hooks?.fetchImpl,
          now: input.now,
        }),
        now: input.now,
      });
    })()
    : null;

  /**
   * The bearer-client checks shared by sync mode of .../relayhistory/session
   * and .../relayhistory/upload-credentials: a browser session, an
   * unexchanged handoff, a non-user token or a token not live for rth:sync
   * is refused. Returns the introspection result.
   */
  async function assertNativeUploadCaller(
    request: IncomingMessage,
    access: Awaited<ReturnType<typeof workspaceAccess>>,
  ) {
    const { principal, workspace, token } = access;
    if (!bearer(request)) throw new HttpError(403, "forbidden", "Browser clients cannot obtain upload credentials");
    if (principal.pendingHandoff) {
      throw new HttpError(403, "handoff_not_exchanged", "Exchange the sign-in handoff first");
    }
    if (!token.startsWith(ACCESS_TOKEN_PREFIX)) throw new HttpError(401, "unauthorized", "User token required");
    const active = await introspect(config, store, { token, aud: config.sessionReadApi.publicUrl, workspace: workspace.id });
    if (!active.active || !active.scopes.includes("rth:sync")) {
      throw new HttpError(401, "unauthorized", "Token is not valid for uploads");
    }
    return active;
  }

  /**
   * POST .../relayhistory/session, served by the sessions pipeline (the only
   * History backend). `read` is the read API handoff. `sync` hands a bearer
   * client's own relaycontrol token back as the upload credential for the
   * ingest edge, which re-introspects it on every request; nothing is minted.
   * refreshToken is a fixed placeholder: the edge answers every refresh with
   * 401 refresh_not_supported, and Desktop then renews here with its own
   * sign-in.
   */
  async function nativeHistorySession(
    request: IncomingMessage,
    response: ServerResponse,
    access: Awaited<ReturnType<typeof workspaceAccess>>,
    mode: "read" | "sync",
    label: string | undefined,
  ): Promise<Record<string, unknown>> {
    const { principal, workspace, token } = access;
    const browser = !bearer(request);
    if (browser && !cookieRequestAllowed(request, browserOrigins)) {
      throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
    }
    if (principal.pendingHandoff) {
      throw new HttpError(403, "handoff_not_exchanged", "Exchange the sign-in handoff first");
    }
    const api = config.sessionReadApi;
    if (mode === "read") {
      if (!principal.scopes.includes("rth:read")) {
        throw new HttpError(403, "mode_not_authorized", "Read mode is not authorized");
      }
      const parsed = readSessionRequest.safeParse(label === undefined ? {} : { label });
      if (!parsed.success) throw new HttpError(400, "invalid_request", "Invalid session read request");
      rateLimit(response, `session-read:${principal.userId}:${workspace.id}`,
        { limit: 30, windowMs: 60_000 }, "rate_limited", "Too many session read credential requests");
      const session = await requestReadSession(api, {
        userId: principal.userId, orgId: workspace.organizationId, workspaceId: workspace.id,
      }, parsed.data);
      const { refreshToken: _refresh, refreshTokenExpiresAt: _expiry, ...accessOnly } = session;
      return browser ? accessOnly : session;
    }
    const active = await assertNativeUploadCaller(request, access);
    const expiresAt = new Date(Math.min(active.exp * 1_000, Date.now() + NATIVE_UPLOAD_SESSION_MAX_MS)).toISOString();
    return {
      baseUrl: api.publicUrl,
      accessToken: token,
      accessTokenExpiresAt: expiresAt,
      refreshToken: NATIVE_UPLOAD_NO_REFRESH,
      refreshTokenExpiresAt: expiresAt,
      tokenType: "Bearer",
      scopes: ["rth:sync"],
      orgId: workspace.organizationId,
      workspaceId: workspace.id,
    };
  }

  const factoryRoutes = mountFactoryRoutes(factory, { workspaceAccess, requestObject, bearer, json });

  /**
   * DG-001 capability routes. The browser account session is the
   * agent_relay_session cookie under /cloud carrying scope "account"; a bearer
   * is refused. A credential issued before the capability existed gets 403
   * reauthentication_required (it keeps working on resource routes).
   */
  async function accountSession(request: IncomingMessage, publicPath: string): Promise<Principal | null> {
    if (bearer(request)) {
      throw new HttpError(401, "unauthorized", "This route takes the browser session cookie, not a bearer token");
    }
    const token = publicPath === "/cloud" || publicPath.startsWith("/cloud/") ? cookie(request, SESSION_COOKIE) : null;
    const principal = token ? await store.authenticateAccessToken(token) : null;
    if (!principal) return null;
    if (!principal.scopes.includes(ACCOUNT_SCOPE) || principal.pendingHandoff || principal.handoff) {
      throw new HttpError(403, "reauthentication_required", "Sign in again to use this session for workspace selection");
    }
    return principal;
  }

  async function desktopSession(request: IncomingMessage): Promise<Principal> {
    const token = bearer(request);
    const principal = token ? await store.authenticateAccessToken(token) : null;
    if (!principal) throw new HttpError(401, "unauthorized", "Invalid or expired token");
    if (!principal.scopes.includes(DESKTOP_WORKSPACES_SCOPE)) {
      throw new HttpError(403, "reauthentication_required", "Sign in to Agent Relay Desktop again to switch workspaces");
    }
    // An unexchanged browser handoff carries desktop:workspaces but has not
    // proved the PKCE verifier yet; only the exchange may redeem it.
    if (principal.pendingHandoff) {
      throw new HttpError(403, "handoff_not_exchanged", "Exchange the sign-in handoff (POST /api/v1/auth/desktop/session) first");
    }
    // An exchanged handoff stays a browser-redirect artifact: redeeming it
    // issued a separate PKCE-proven pair, and only that pair may switch.
    if (principal.handoff) {
      throw new HttpError(403, "handoff_not_capable", "This sign-in handoff cannot switch workspaces; use the session issued by POST /api/v1/auth/desktop/session");
    }
    return principal;
  }

  async function parseChoice(request: IncomingMessage): Promise<string> {
    const parsed = WorkspaceChoice.safeParse(await requestObject(request));
    if (!parsed.success) throw new HttpError(400, "invalid_request", "Send {\"workspaceId\": \"<id>\"}");
    return parsed.data.workspaceId;
  }

  async function accountView(principal: Principal): Promise<JsonObject> {
    const workspaces = await store.memberWorkspaces(principal.userId);
    const organizations = new Map<string, { id: string; name: string; role: Principal["role"] }>();
    for (const workspace of workspaces) {
      organizations.set(workspace.organizationId, {
        id: workspace.organizationId,
        name: workspace.organizationName,
        role: workspace.role,
      });
    }
    return {
      authenticated: true,
      user: { id: principal.userId, name: principal.name, email: principal.email },
      currentOrganization: {
        id: principal.organizationId,
        name: principal.organizationName,
        role: principal.role,
      },
      currentWorkspace: { id: principal.workspaceId, name: principal.workspaceName },
      organizations: [...organizations.values()],
      workspaces: workspaces.map((workspace) => ({
        id: workspace.id,
        name: workspace.name,
        organizationId: workspace.organizationId,
        organizationName: workspace.organizationName,
      })),
    };
  }

  // Relayflows: worker protocol, flows, runs (src/flows). Dashboard calls are
  // scoped to the caller's current workspace, matching the hosted contract.
  const flows = input.flows
    ? createFlowsHandler({
      store: input.flows,
      publicBaseUrl: config.publicBaseUrl,
      requireFeature: () => requireFeature("flows"),
      userAccess: async (request, admin = false) => {
        const auth = await authenticate(request);
        if (auth.kind !== "user") throw new HttpError(401, "unauthorized", "User token required");
        const workspace = await store.workspaceForUser(
          auth.principal.workspaceId,
          auth.principal.userId,
        );
        if (!workspace) throw new HttpError(404, "workspace_not_found", "Workspace not found");
        if (admin && workspace.role !== "owner" && workspace.role !== "admin") {
          throw new HttpError(403, "forbidden", "Workspace admin role required");
        }
        return { principal: auth.principal, workspace };
      },
    })
    : null;

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const method = request.method ?? "GET";
    const url = new URL(request.url ?? "/", config.publicBaseUrl);
    const publicPath = url.pathname.replace(/\/+$/, "") || "/";
    const path = normalizeRoutePath(publicPath);

    if (method === "GET" && path === "/healthz") {
      json(response, 200, { status: "ok" });
      return;
    }
    if (method === "GET" && publicPath === "/cloud/api/health") {
      json(response, 200, {
        status: "ok",
        timestamp: new Date().toISOString(),
        version: SELFHOST_API_VERSION,
      }, true);
      return;
    }
    if (method === "GET" && path === "/readyz") {
      const readiness = await store.readiness();
      const introspection = {
        enabled: Boolean(config.introspectSecret),
        audiences: acceptedAudiences(config),
        outageHoldMs: config.introspectOutageHoldMs ?? 0,
      };
      json(response, readiness.ready ? 200 : 503, readiness.ready
        ? { status: "ready", introspection, capabilities: features }
        : { status: "not_ready", reason: readiness.reason, message: readiness.message, introspection, capabilities: features });
      return;
    }
    if (method === "GET" && path === "/openapi.yaml") {
      const location = resolve(dirname(fileURLToPath(import.meta.url)), "../openapi.yaml");
      text(response, 200, await readFile(location, "utf8"), "application/yaml");
      return;
    }

    // The sessions pipeline and relayfile verify relaycontrol access tokens here.
    // Internal only: never reachable through the /cloud alias.
    if (method === "POST" && publicPath === INTROSPECT_PATH) {
      const outcome = await handleIntrospection(
        config, store, request, undefined, admin?.apiTokens, flowRelayfileCredentials, introspectionHold,
      );
      if (outcome.status === 200) json(response, 200, outcome.body, true);
      else json(response, outcome.status, { error: outcome.error, message: outcome.message }, true);
      return;
    }

    // Internal only, like introspection: never reachable through the /cloud alias.
    if (await handleFlowsBroker(request, response, method, publicPath, {
      secret: config.relayfileControlBrokerSecret,
      admin,
      relayfileCredentials: () => flowRelayfileCredentials,
      relaycastBinding: (id) => store.relaycastBinding(id),
      requireFlows: () => requireFeature("flows"),
      bearer,
      requestObject,
      json,
    })) {
      return;
    }

    if (await handleChiefRelay(request, response, method, publicPath, {
      secret: config.chiefRelaySecret,
      relaycast: oauthRelay,
      relaycastBinding: (id) => store.relaycastBinding(id),
      requireChief: () => requireFeature("chief"),
      bearer,
      requestObject,
      json,
    })) {
      return;
    }

    // Relay node broker (docs/relay-node-credential.md): a relay-node token
    // runs allowlisted Relaycast workspace-key routes with the stored key.
    // Never reachable through the /cloud alias.
    if (await handleRelayNode(request, response, method, publicPath, {
      apiTokens,
      relaycastUrl: config.relaycastUrl,
      relaycastBinding: (id) => store.relaycastBinding(id),
      bearer,
      rateLimit: (res, key, rule) =>
        rateLimit(res, key, rule, "rate_limited", "Too many relay-node requests; retry later"),
      bodyText: (incoming) => bodyText(incoming),
      json,
    })) {
      return;
    }

    // Dormant acquisition assertion issuer (docs/acquisition-issuer.md): every
    // /api/v1/acquisition path is 404 until SELFHOST_ACQUISITION_ISSUER_ENABLED.
    if (await handleAcquisitionRoutes({
      config, store, apiTokens: admin?.apiTokens, request, response, method, path, now: input.now,
    })) {
      return;
    }
    // Amp control: gated before any authentication (off answers 404).
    if (isAmpPath(path)) {
      if (!amp) {
        json(response, 404, { error: "Not found" }, true);
        return;
      }
      if (await amp.handle(request, response, path, publicPath, method, { workspaceAccess, bearer, json })) return;
    }
    // Factory sessions: 404 before auth when the flag is off.
    if (await factoryRoutes(request, response, path, publicPath, method)) return;

    // bootstrap-signup lane: the sign-in page with SSO / email links, OIDC
    // callbacks and the invitation API. The device-code page below remains
    // the fallback when no identity module is wired.
    if (identity && await identity.handle(request, response, path, publicPath, url, {
      organizationAccess,
      authenticate: (incoming) => authenticate(incoming),
      authenticateWithBootstrap: (incoming) => authenticate(incoming, true),
      requestObject,
      bearer,
      siteBaseUrl,
      browserOrigins,
    })) {
      return;
    }

    if (method === "GET" && publicPath === "/login") {
      // Back to where sign-in was asked for (e.g. the device approval page).
      const next = safeNextPath(url.searchParams.get("next"));
      const started = await store.startDeviceAuthorization(DASHBOARD_DEVICE_CLIENT, null, { reserved: true });
      response.setHeader("set-cookie", secureCookie(
        DEVICE_COOKIE,
        started.deviceCode,
        "/login",
        Math.max(1, Math.floor((Date.parse(started.expiresAt) - Date.now()) / 1_000)),
      ));
      response.setHeader("cache-control", "no-store");
      response.setHeader(
        "content-security-policy",
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
      );
      response.setHeader("referrer-policy", "no-referrer");
      text(response, 200, `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Sign in to Agent Relay</title>
<style>body{font:16px system-ui;max-width:34rem;margin:10vh auto;padding:1.5rem;color:#171717}code{font-size:2rem;letter-spacing:.12em}#status{color:#555}</style>
</head><body><main><h1>Sign in to Agent Relay</h1>
<p>Approve this device code from an authenticated Agent Relay client or administrator:</p>
<p><code>${html(started.userCode)}</code></p>
<p id="status">Waiting for approval…</p></main>
<script>
const status=document.getElementById("status");
const next=${JSON.stringify(next).replaceAll("<", "\\u003c")};
async function poll(){try{const r=await fetch("/login/poll",{method:"POST",credentials:"same-origin",headers:{accept:"application/json"}});
if(r.status===202){const p=await r.json();setTimeout(poll,Math.max(1,Number(p.interval)||5)*1000);return}
if(r.ok){location.replace(next);return}status.textContent="Sign-in failed. Reload to start again."}catch{setTimeout(poll,5000)}}
setTimeout(poll,${Math.max(1, started.intervalSeconds) * 1_000});
</script></body></html>`, "text/html");
      return;
    }

    if (method === "POST" && publicPath === "/login/poll") {
      const deviceCode = cookie(request, DEVICE_COOKIE);
      if (!deviceCode) {
        throw new HttpError(401, "login_expired", "Login attempt is missing or expired");
      }
      // A dashboard browser session, not a device client: no rth:acquire.
      const result = await store.pollDeviceAuthorization(deviceCode, "browser");
      if (result.kind === "error") {
        if (result.error === "authorization_pending" || result.error === "slow_down") {
          json(response, 202, {
            status: "pending",
            interval: result.intervalSeconds,
          }, true);
          return;
        }
        response.setHeader("set-cookie", clearCookie(DEVICE_COOKIE, "/login"));
        throw new HttpError(401, result.error, "Device authorization did not complete");
      }
      const maxAge = Math.max(
        1,
        Math.floor((Date.parse(result.tokens.accessTokenExpiresAt) - Date.now()) / 1_000),
      );
      response.setHeader("set-cookie", [
        secureCookie(SESSION_COOKIE, result.tokens.accessToken, "/cloud", maxAge),
        clearCookie(DEVICE_COOKIE, "/login"),
      ]);
      json(response, 200, { status: "authenticated", redirect: "/" }, true);
      return;
    }

    // desktop-auth lane, browser flow. Hosted Cloud's provider sign-in starts
    // (Google, Microsoft): the Desktop opens one with next=/api/v1/cli/login?...
    // Self-host sends Microsoft to its own Microsoft sign-in when configured
    // (SELFHOST_MICROSOFT_*). Everything else, including Google, lands on the
    // /login chooser, which lists every provider; a bounce never forces one
    // provider. The `next` stays on the /cloud mount, where the session
    // cookie is scoped.
    if (
      method === "GET" &&
      (publicPath === "/cloud/api/auth/google/start" || publicPath === "/cloud/api/auth/microsoft/start")
    ) {
      const next = cloudPathForNext(url.searchParams.get("next"));
      const signIn = publicPath === "/cloud/api/auth/microsoft/start" && identity?.config.microsoft
        ? "/login/microsoft/start"
        : "/login";
      response.writeHead(302, {
        location: `${signIn}?next=${encodeURIComponent(next)}`,
        "cache-control": "no-store",
        "referrer-policy": "no-referrer",
      });
      response.end();
      return;
    }

    // Agent Relay Desktop's browser sign-in (desktop-core browser_login.rs):
    // with a session cookie it hands the loopback listener a 15-minute token
    // bound to the app's S256 challenge. A sign-in that names its host first
    // asks the person to approve "Agent Relay Desktop on <host>".
    if (path === "/api/v1/cli/login" && (method === "GET" || method === "POST")) {
      rateLimit(
        response,
        `cli-login:${limiterKey(clientIp(request))}`,
        DESKTOP_LOGIN_RATE_LIMITS.login,
        "rate_limited",
        "Too many sign-in attempts. Try again shortly.",
      );
      let params = url.searchParams;
      if (method === "POST") {
        const body = await requestObject(request);
        params = new URLSearchParams();
        for (const field of [...DESKTOP_CONSENT_FIELDS, "consent_token", "decision"]) {
          const value = body[field];
          if (typeof value === "string") params.set(field, value);
        }
      }
      const login = validateDesktopLogin(params);
      if ("error" in login) throw new HttpError(400, "invalid_request", login.error);

      const sessionToken = publicPath.startsWith("/cloud/") ? cookie(request, SESSION_COOKIE) : null;
      const principal = sessionToken ? await store.authenticateAccessToken(sessionToken) : null;
      if (!principal) {
        if (method === "POST") throw new HttpError(401, "unauthorized", "Sign in first");
        response.writeHead(302, {
          location: `/login?next=${encodeURIComponent(`${publicPath}${url.search}`)}`,
          "cache-control": "no-store",
          "referrer-policy": "no-referrer",
        });
        response.end();
        return;
      }
      if (!login.codeChallenge) {
        // Only desktop sign-ins exist here: nothing issues an unbound token.
        throw new HttpError(400, "invalid_request", "client=desktop with an S256 code_challenge is required");
      }
      // DG-001: an account session (scope "account") may hand the Desktop any
      // workspace the person is a member of; any other session stays bound to
      // its own workspace, as the device flow does.
      let target = {
        organizationId: principal.organizationId,
        workspaceId: principal.workspaceId,
        workspaceName: principal.workspaceName,
      };
      if (principal.scopes.includes(ACCOUNT_SCOPE)) {
        const workspaces = await store.memberWorkspaces(principal.userId);
        if (workspaces.length === 0) {
          throw new HttpError(403, "forbidden", "This workspace is not available to your account.");
        }
        let chosen = login.workspace === null
          ? (workspaces.length === 1 ? workspaces[0] : undefined)
          : workspaces.find((workspace) => workspace.id === login.workspace);
        if (login.workspace !== null && !chosen) {
          throw new HttpError(403, "forbidden", "This workspace is not available to your account.");
        }
        if (!chosen) {
          if (method === "POST") throw new HttpError(400, "invalid_request", "Choose a workspace first");
          const pickerParams = new URLSearchParams();
          for (const field of DESKTOP_CONSENT_FIELDS) {
            const value = params.get(field);
            if (value !== null && field !== "workspace") pickerParams.set(field, value);
          }
          response.writeHead(200, {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
            "referrer-policy": "no-referrer",
            "content-security-policy":
              `default-src 'none'; style-src 'unsafe-inline'; form-action ${formActionSources.join(" ")}; base-uri 'none'; frame-ancestors 'none'`,
          });
          response.end(desktopWorkspacePickerPage({
            action: publicPath,
            params: pickerParams,
            workspaces: workspaces.map((workspace) => ({
              id: workspace.id,
              name: workspace.name,
              organizationName: workspace.organizationName,
            })),
          }));
          return;
        }
        target = { organizationId: chosen.organizationId, workspaceId: chosen.id, workspaceName: chosen.name };
      } else if (login.workspace !== null && login.workspace !== principal.workspaceId) {
        throw new HttpError(403, "forbidden", "This workspace is not available to your account.");
      }
      const codeChallenge = login.codeChallenge;
      const attempt = {
        userId: principal.userId,
        codeChallenge,
        hostName: login.desktopHostName ?? "",
        workspaceId: target.workspaceId,
        redirectUri: login.redirectUri,
      };
      const issueHandoff = async (status: 303 | 307, consentedHostName?: string) => {
        const issued = await store.issueDesktopHandoff({
          userId: principal.userId,
          organizationId: target.organizationId,
          workspaceId: target.workspaceId,
          codeChallenge,
          ...(consentedHostName ? { consentedHostName } : {}),
        });
        response.writeHead(status, {
          location: handoffCallbackUrl(login, issued, `${siteBaseUrl(request)}/cloud`),
          "cache-control": "no-store",
          "referrer-policy": "no-referrer",
        });
        response.end();
      };
      if (method === "GET") {
        if (!login.desktopHostName) {
          await issueHandoff(307);
          return;
        }
        const consentParams = new URLSearchParams();
        for (const field of DESKTOP_CONSENT_FIELDS) {
          const value = params.get(field);
          if (value !== null) consentParams.set(field, value);
        }
        consentParams.set("workspace", target.workspaceId);
        // The consent form posts back to this origin, and the browser derives
        // the POST's Origin header from the page's referrer policy: with
        // no-referrer it would send "Origin: null", which the same-origin
        // check below refuses. same-origin keeps the real origin on the
        // form post and still withholds the URL from any other destination.
        // The approve post is answered with a 303 to this computer's loopback
        // listener, and Chromium applies form-action to that redirect too, so
        // the validated loopback origin (isLoopbackRedirectUri) is allowed
        // beside 'self'; with 'self' alone the page just stayed put.
        const loopbackOrigin = new URL(login.redirectUri).origin;
        response.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
          "referrer-policy": "same-origin",
          "content-security-policy":
            `default-src 'none'; style-src 'unsafe-inline'; form-action ${[...formActionSources, loopbackOrigin].join(" ")}; base-uri 'none'; frame-ancestors 'none'`,
        });
        response.end(desktopConsentPage({
          action: publicPath,
          params: consentParams,
          hostName: login.desktopHostName,
          workspaceName: target.workspaceName,
          consentToken: await store.issueDesktopConsentToken(attempt),
        }));
        return;
      }
      // The person's decision: a same-origin form post carrying the token the
      // consent screen embedded for this person and this attempt.
      const origin = request.headers.origin;
      const fetchSite = request.headers["sec-fetch-site"];
      if (
        typeof origin !== "string" || !browserOrigins.includes(origin) ||
        (fetchSite !== undefined && fetchSite !== "same-origin")
      ) {
        throw new HttpError(403, "forbidden", "Cross-origin consent refused");
      }
      if (!login.desktopHostName) {
        throw new HttpError(400, "invalid_request", "Desktop consent needs client=desktop, an S256 code_challenge and desktop_host_name");
      }
      if (!(await store.consumeDesktopConsentToken(params.get("consent_token"), attempt))) {
        throw new HttpError(403, "forbidden", "Consent token is missing, used, or for another sign-in");
      }
      if (params.get("decision") !== "approve") {
        response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        response.end(desktopConsentDeniedPage());
        return;
      }
      // Only an approved consent records the host: that is the provenance a
      // verified Desktop sign-in (desktop MCP credentials) requires.
      await issueHandoff(303, login.desktopHostName);
      return;
    }

    // Redeems the handoff for a renewable session by proving the verifier of
    // the S256 challenge the sign-in carried (hosted: auth/desktop/session).
    if (method === "POST" && path === "/api/v1/auth/desktop/session") {
      rateLimit(
        response,
        `desktop-session:${limiterKey(clientIp(request))}`,
        DESKTOP_LOGIN_RATE_LIMITS.exchange,
        "rate_limited",
        "Too many exchange attempts. Try again shortly.",
      );
      const handoff = bearer(request);
      if (!handoff) throw new HttpError(401, "unauthorized", "Invalid or expired desktop sign-in");
      const body = await requestObject(request);
      const codeVerifier = typeof body.codeVerifier === "string" ? body.codeVerifier : "";
      if (!codeVerifier) throw new HttpError(400, "invalid_request", "Missing codeVerifier");
      const issued = await store.exchangeDesktopHandoff(
        handoff,
        (challenge) => challengeMatches(challenge, codeVerifier),
      );
      if (!issued) throw new HttpError(401, "unauthorized", "Invalid or expired desktop sign-in");
      json(response, 200, {
        accessToken: issued.accessToken,
        accessTokenExpiresAt: issued.accessTokenExpiresAt,
        refreshToken: issued.refreshToken,
        refreshTokenExpiresAt: issued.refreshTokenExpiresAt,
        apiUrl: `${siteBaseUrl(request)}/cloud`,
        tokenType: "Bearer",
      }, true);
      return;
    }

    // Whose computer a Relaycast node is (hosted: fleet/nodes/claim). The
    // Desktop claims its own spawn node with its workspace-bound sign-in. The
    // node token is proven against Relaycast and never stored or logged.
    if (path === "/api/v1/fleet/nodes/claim" && (method === "POST" || method === "DELETE")) {
      const auth = await authenticate(request);
      if (auth.kind !== "user") throw new HttpError(401, "unauthorized", "User token required");
      const body = await requestObject(request);
      const workspaceId = stringField(body, "workspaceId")!;
      if (workspaceId !== auth.principal.workspaceId) {
        throw new HttpError(404, "workspace_not_found", "Workspace not found");
      }
      const workspace = await store.workspaceForUser(workspaceId, auth.principal.userId);
      if (!workspace) throw new HttpError(404, "workspace_not_found", "Workspace not found");
      if (method === "DELETE") {
        const nodeId = stringField(body, "nodeId")!;
        if (!NODE_ID.test(nodeId)) throw new HttpError(400, "invalid_request", "Send workspaceId and nodeId.");
        json(response, 200, await store.releaseNode({
          workspaceId,
          organizationId: workspace.organizationId,
          nodeId,
          actorUserId: auth.principal.userId,
        }), true);
        return;
      }
      rateLimit(
        response,
        `node-claim:${auth.principal.userId}`,
        DESKTOP_LOGIN_RATE_LIMITS.claim,
        "rate_limited",
        "Too many node claims. Try again later.",
      );
      const nodeToken = typeof body.nodeToken === "string" ? body.nodeToken.trim() : "";
      if (!NODE_TOKEN.test(nodeToken)) {
        throw new HttpError(400, "invalid_request", "Send workspaceId and the node's token (nt_live_...).");
      }
      const proven = await verifyNodeToken(config.relaycastUrl, workspace.relaycastApiKey, nodeToken);
      const result = await store.claimNode({
        workspaceId,
        organizationId: workspace.organizationId,
        relaycastWorkspaceId: workspace.relaycastWorkspaceId,
        nodeId: proven.id,
        nodeName: proven.name,
        userId: auth.principal.userId,
      });
      json(response, 200, { nodeId: result.nodeId, claimed: result.claimed, owner: "you" }, true);
      return;
    }

    if (method === "GET" && publicPath === "/cloud/api/auth/session") {
      if (url.searchParams.has("renew") && url.searchParams.get("renew") !== "0") {
        throw new HttpError(400, "invalid_request", "renew must be 0");
      }
      let principal: Principal | null;
      try {
        principal = await accountSession(request, publicPath);
      } catch (error) {
        // A pre-upgrade cookie on this route only: dashboards treat 401 as
        // signed out and send the person to /login, which issues a session
        // with the account scope. The other account routes keep the 403.
        if (error instanceof HttpError && error.code === "reauthentication_required") {
          json(response, 401, { authenticated: false, reason: "reauthentication_required" }, true);
          return;
        }
        throw error;
      }
      if (!principal) {
        json(response, 401, { authenticated: false }, true);
        return;
      }
      json(response, 200, await accountView(principal), true);
      return;
    }

    // DG-001: switching workspaces mints a new account session bound to the
    // chosen workspace and revokes the old access and refresh token.
    if (method === "POST" && publicPath === "/cloud/api/auth/workspace") {
      const principal = await accountSession(request, publicPath);
      if (!principal) throw new HttpError(401, "unauthorized", "Sign in first");
      if (!cookieRequestAllowed(request, browserOrigins)) {
        throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
      rateLimit(
        response,
        `account-switch:${principal.userId}`,
        CAPABILITY_RATE_LIMIT,
        "rate_limited",
        "Too many workspace switches. Try again shortly.",
      );
      const workspaceId = await parseChoice(request);
      const issued = await store.switchAccountSession({
        sessionId: principal.sessionId,
        userId: principal.userId,
        workspaceId,
      });
      if (!issued) throw new HttpError(404, "workspace_not_found", "Workspace not found");
      const next = await store.authenticateAccessToken(issued.accessToken);
      if (!next) throw new HttpError(404, "workspace_not_found", "Workspace not found");
      const maxAge = Math.max(1, Math.floor((Date.parse(issued.accessTokenExpiresAt) - Date.now()) / 1_000));
      response.setHeader("set-cookie", secureCookie(SESSION_COOKIE, issued.accessToken, "/cloud", maxAge));
      json(response, 200, await accountView(next), true);
      return;
    }

    // Desktop: the workspaces its sign-in may switch to, and a new session
    // bound to one of them (scope desktop:workspaces, bearer).
    if (path === "/api/v1/auth/desktop/workspaces" && (method === "GET" || method === "POST")) {
      const principal = await desktopSession(request);
      rateLimit(
        response,
        `desktop-workspaces:${principal.userId}`,
        CAPABILITY_RATE_LIMIT,
        "rate_limited",
        "Too many workspace requests. Try again shortly.",
      );
      if (method === "GET") {
        const workspaces = await store.memberWorkspaces(principal.userId);
        json(response, 200, {
          current_workspace_id: principal.workspaceId,
          workspaces: workspaces.map((workspace) => ({
            id: workspace.id,
            name: workspace.name,
            organization_id: workspace.organizationId,
            organization_name: workspace.organizationName,
            role: workspace.role,
          })),
        }, true);
        return;
      }
      const workspaceId = await parseChoice(request);
      const target = (await store.memberWorkspaces(principal.userId)).find((workspace) => workspace.id === workspaceId);
      if (!target) throw new HttpError(404, "workspace_not_found", "Workspace not found");
      let issued;
      try {
        issued = await store.issueDesktopSession({
          userId: principal.userId,
          organizationId: target.organizationId,
          workspaceId: target.id,
          tokenFamilyId: principal.tokenFamilyId,
        });
      } catch (error) {
        if (error instanceof OrganizationBoundaryError) {
          throw new HttpError(404, "workspace_not_found", "Workspace not found");
        }
        throw error;
      }
      json(response, 200, {
        accessToken: issued.accessToken,
        accessTokenExpiresAt: issued.accessTokenExpiresAt,
        refreshToken: issued.refreshToken,
        refreshTokenExpiresAt: issued.refreshTokenExpiresAt,
        apiUrl: `${siteBaseUrl(request)}/cloud`,
        tokenType: "Bearer",
        workspace: {
          id: target.id,
          name: target.name,
          organization_id: target.organizationId,
          organization_name: target.organizationName,
        },
      }, true);
      return;
    }

    if (method === "POST" && path === "/api/v1/auth/device/start") {
      rateLimit(
        response,
        `device-start:${limiterKey(clientIp(request))}`,
        DEVICE_RATE_LIMITS.start,
        "slow_down",
        "Too many device authorization requests",
      );
      const body = await requestObject(request);
      const clientName = stringField(body, "client_name", false);
      if (clientName && isDeviceReservedClientName(clientName.trim())) {
        throw new HttpError(400, "invalid_request", "client_name is reserved");
      }
      const started = await store.startDeviceAuthorization(
        clientName,
        sanitizeDesktopHostName(body.desktop_host_name),
      );
      // Under /cloud/api so it reaches this service on a shared dashboard
      // origin too (the ingress sends only /cloud/api and /login here). A GET
      // redirects to the dashboard's approval page.
      const verification = `${siteBaseUrl(request)}/cloud/api/v1/auth/device/approve`;
      json(response, 201, {
        device_code: started.deviceCode,
        user_code: started.userCode,
        verification_uri: verification,
        verification_uri_complete: `${verification}?user_code=${encodeURIComponent(started.userCode)}`,
        expires_in: Math.max(0, Math.floor((Date.parse(started.expiresAt) - Date.now()) / 1_000)),
        interval: started.intervalSeconds,
      }, true);
      return;
    }

    if (method === "GET" && path === "/api/v1/auth/device/approve") {
      // verification_uri(_complete): a person opened it; send them to the
      // dashboard's approval page, which signs them in first if needed.
      response.writeHead(303, {
        location: deviceApprovalPageUrl(config.dashboardUrl, url.searchParams.get("user_code")),
        "cache-control": "no-store",
        "referrer-policy": "no-referrer",
      });
      response.end();
      return;
    }

    if (method === "POST" && path === "/api/v1/auth/device/approve") {
      const auth = await authenticate(request, true);
      if (!bearer(request) && !cookieRequestAllowed(request, browserOrigins)) {
        throw new HttpError(403, "csrf_rejected", "Cross-origin approval refused");
      }
      // Bounds guessing of the low-entropy user code by a signed-in user. The
      // bootstrap bearer can already approve any code for anyone.
      if (auth.kind === "user") {
        rateLimit(
          response,
          `device-approve:${auth.principal.userId}`,
          DEVICE_RATE_LIMITS.approve,
          "device_approve_rate_limited",
          "Too many device approval attempts. Try again shortly.",
        );
      }
      const body = await requestObject(request);
      const action = stringField(body, "action");
      if (action !== "approve" && action !== "deny" && action !== "lookup") {
        throw new HttpError(400, "invalid_request", "action must be lookup, approve, or deny");
      }
      const userCode = stringField(body, "user_code")!;
      if (action === "lookup") {
        const found = await store.findDeviceAuthorization(userCode);
        if (!found) throw new HttpError(404, "not_found", "That code was not found");
        const workspaces = auth.kind !== "user"
          ? []
          : auth.principal.scopes.includes(ACCOUNT_SCOPE)
          ? (await store.memberWorkspaces(auth.principal.userId)).map((workspace) => ({
            id: workspace.id,
            name: workspace.name,
            organization_name: workspace.organizationName,
          }))
          : [{
            id: auth.principal.workspaceId,
            name: auth.principal.workspaceName,
            organization_name: auth.principal.organizationName,
          }];
        json(response, 200, {
          user_code: found.userCode,
          client_name: found.clientName,
          desktop_host_name: found.desktopHostName,
          status: found.status,
          expires_at: found.expiresAt,
          current_workspace_id: auth.kind === "user" ? auth.principal.workspaceId : null,
          workspaces,
        }, true);
        return;
      }
      // An absent workspace_id means the session's own workspace. An account
      // session (DG-001) may pick any workspace it is a member of; any other
      // session is bound to its own.
      const workspaceId = auth.kind === "user" && body.workspace_id === undefined
        ? auth.principal.workspaceId
        : stringField(body, "workspace_id")!;
      if (auth.kind === "user" && workspaceId !== auth.principal.workspaceId) {
        const member = auth.principal.scopes.includes(ACCOUNT_SCOPE) &&
          (await store.memberWorkspaces(auth.principal.userId)).some((workspace) => workspace.id === workspaceId);
        if (!member) throw new HttpError(404, "workspace_not_found", "Workspace not found");
      }
      const userId = auth.kind === "bootstrap"
        ? stringField(body, "user_id")!
        : auth.principal.userId;
      const result = await store.decideDeviceAuthorization({
        userCode,
        approve: action === "approve",
        userId,
        workspaceId,
      });
      const errors: Record<string, [number, string]> = {
        not_found: [404, "Device authorization not found"],
        expired: [410, "Device authorization expired"],
        already_decided: [409, "Device authorization already decided"],
        not_member: [403, "User is not a workspace member"],
      };
      if (errors[result]) {
        const [status, message] = errors[result];
        throw new HttpError(status, result, message);
      }
      json(response, 200, { status: result }, true);
      return;
    }

    if (method === "POST" && path === "/api/v1/auth/device/token") {
      rateLimit(
        response,
        `device-token:${limiterKey(clientIp(request))}`,
        DEVICE_RATE_LIMITS.token,
        "slow_down",
        "Too many token requests",
      );
      const body = await requestObject(request);
      const grantType = typeof body.grant_type === "string"
        ? body.grant_type
        : "urn:ietf:params:oauth:grant-type:device_code";
      if (grantType !== "urn:ietf:params:oauth:grant-type:device_code") {
        throw new HttpError(400, "unsupported_grant_type", "Unsupported grant_type");
      }
      const result = await store.pollDeviceAuthorization(stringField(body, "device_code")!);
      if (result.kind === "error") {
        json(response, 400, {
          error: result.error,
          error_description: DEVICE_TOKEN_ERROR_DESCRIPTIONS[result.error] ??
            "Device authorization did not complete",
          interval: result.intervalSeconds,
        }, true);
        return;
      }
      json(response, 200, {
        access_token: result.tokens.accessToken,
        refresh_token: result.tokens.refreshToken,
        token_type: "Bearer",
        access_token_expires_at: result.tokens.accessTokenExpiresAt,
        refresh_token_expires_at: result.tokens.refreshTokenExpiresAt,
        scope: result.tokens.scopes.join(" "),
        // Hosted Cloud's shape: the API base is the site's /cloud mount, and
        // Desktop refuses a sign-in whose api_url is anything else.
        api_url: `${siteBaseUrl(request)}/cloud`,
      }, true);
      return;
    }

    if (method === "POST" && path === "/api/v1/auth/token/refresh") {
      const body = await requestObject(request);
      const refreshToken = stringField(body, "refreshToken")!;
      if (!refreshToken.startsWith("sh_rt_")) {
        throw new HttpError(403, "invalid_grant", "Invalid or expired refresh token");
      }
      const issued = await store.refresh(refreshToken);
      if (!issued) throw new HttpError(403, "invalid_grant", "Invalid or expired refresh token");
      json(response, 200, {
        accessToken: issued.accessToken,
        accessTokenExpiresAt: issued.accessTokenExpiresAt,
        refreshToken: issued.refreshToken,
        refreshTokenExpiresAt: issued.refreshTokenExpiresAt,
        tokenType: "Bearer",
        apiUrl: `${siteBaseUrl(request)}/cloud`,
      }, true);
      return;
    }

    if (method === "POST" && path === "/api/v1/auth/token/revoke") {
      const body = await requestObject(request);
      const token = typeof body.token === "string" && body.token.trim()
        ? body.token.trim()
        : bearer(request);
      if (!token) throw new HttpError(400, "invalid_request", "token is required");
      if (!await store.revoke(token)) throw new HttpError(404, "token_not_found", "Token not found");
      json(response, 200, { revoked: true }, true);
      return;
    }

    if (method === "GET" && path === "/api/v1/auth/whoami") {
      const auth = await authenticate(request);
      if (auth.kind !== "user") throw new HttpError(401, "unauthorized", "User token required");
      const principal = auth.principal;
      json(response, 200, {
        authenticated: true,
        source: "token",
        subjectType: "cli",
        scopes: principal.scopes,
        user: { id: principal.userId, email: principal.email, name: principal.name },
        currentOrganization: {
          id: principal.organizationId,
          name: principal.organizationName,
          role: principal.role,
        },
        currentWorkspace: { id: principal.workspaceId, name: principal.workspaceName },
        // The workspaces this person belongs to (Desktop reads this when
        // present); the token itself stays bound to currentWorkspace.
        workspaceCount: await store.memberWorkspaceCount(principal.userId),
      }, true);
      return;
    }

    // Which optional features this installation serves, for any signed-in member.
    if (method === "GET" && path === "/api/v1/capabilities") {
      const auth = await authenticate(request);
      if (auth.kind !== "user") throw new HttpError(401, "unauthorized", "User token required");
      json(response, 200, { capabilities: features }, true);
      return;
    }

    // Usage page (docs/usage.md): owner-only daily counts for one organization.
    const usageRoute = routeMatch(path, /^\/api\/v1\/organizations\/([^/]+)\/usage$/);
    if (usageRoute && method === "GET") {
      const auth = await organizationAccess(request, usageRoute[0]!);
      if (auth.kind !== "user" || await store.memberRole(usageRoute[0]!, auth.principal.userId) !== "owner") {
        throw new HttpError(403, "forbidden", "Organization owner role required");
      }
      requireFeature("usage");
      let days: number;
      try {
        days = usageDays(url);
      } catch (error) {
        if (error instanceof UsageRangeError) throw new HttpError(400, "invalid_request", error.message);
        throw error;
      }
      json(response, 200, {
        usage: await usageReport({
          config,
          store,
          usage,
          organizationId: usageRoute[0]!,
          owner: { userId: auth.principal.userId, token: auth.token },
          days,
          now: input.now?.() ?? new Date(),
        }),
      }, true);
      return;
    }

    if (path === "/api/v1/organizations" && method === "GET") {
      const auth = await authenticate(request, true);
      json(response, 200, {
        organizations: await store.listOrganizations(
          auth.kind === "user" ? auth.principal.userId : undefined,
        ),
      });
      return;
    }
    if (path === "/api/v1/organizations" && method === "POST") {
      const auth = await authenticate(request, true);
      if (auth.kind !== "bootstrap") {
        throw new HttpError(403, "forbidden", "Bootstrap token required");
      }
      const body = await requestObject(request);
      const organization = await store.createOrganization({
        name: stringField(body, "name")!,
        ownerEmail: stringField(body, "ownerEmail")!,
        ownerName: stringField(body, "ownerName")!,
      });
      json(response, 201, organization);
      return;
    }

    const workspaceCollection = routeMatch(
      path,
      /^\/api\/v1\/organizations\/([^/]+)\/workspaces$/,
    );
    if (workspaceCollection) {
      const organizationId = workspaceCollection[0]!;
      const auth = await organizationAccess(request, organizationId, method === "POST");
      if (method === "GET") {
        json(response, 200, { workspaces: await store.listWorkspaces(organizationId) });
        return;
      }
      if (method === "POST") {
        const body = await requestObject(request);
        const workspace = await store.createWorkspace({
          organizationId,
          name: stringField(body, "name")!,
          relaycastWorkspaceId: stringField(body, "relaycastWorkspaceId", false),
          relaycastApiKey: stringField(body, "relaycastApiKey")!,
        });
        json(response, 201, workspace);
        return;
      }
      void auth;
    }

    const workspaceItem = routeMatch(
      path,
      /^\/api\/v1\/organizations\/([^/]+)\/workspaces\/([^/]+)$/,
    );
    if (workspaceItem && method === "PUT") {
      // Replaces the Relaycast key (and optionally the Relaycast workspace id
      // or name), e.g. after the Relaycast behind it was reset and a new key
      // minted there. Bootstrap bearer or organization owner/admin.
      const [organizationId, workspaceId] = workspaceItem as [string, string];
      await organizationAccess(request, organizationId, true);
      const body = await requestObject(request);
      if (body.name === undefined && body.relaycastWorkspaceId === undefined && body.relaycastApiKey === undefined) {
        throw new HttpError(400, "invalid_request", "Send name, relaycastWorkspaceId, or relaycastApiKey");
      }
      const updated = await store.updateWorkspace({
        organizationId,
        workspaceId,
        name: stringField(body, "name", false),
        relaycastWorkspaceId: stringField(body, "relaycastWorkspaceId", false),
        relaycastApiKey: stringField(body, "relaycastApiKey", false),
      });
      if (!updated) throw new HttpError(404, "workspace_not_found", "Workspace not found");
      json(response, 200, updated);
      return;
    }

    if (workspaceItem && method === "DELETE") {
      // Bootstrap bearer or organization owner/admin. An organization's last
      // workspace is kept for a person, who could not sign in without one;
      // only the operator's bootstrap bearer can empty an organization.
      const [organizationId, workspaceId] = workspaceItem as [string, string];
      const auth = await organizationAccess(request, organizationId, true);
      if (!bearer(request)) {
        const origin = request.headers.origin;
        const allowed = typeof origin === "string" && origin && origin !== "null"
          ? browserOrigins.includes(origin)
          : request.headers["sec-fetch-site"] === "same-origin";
        if (!allowed) throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
      const outcome = isUuid(workspaceId)
        ? await store.deleteWorkspace({
          organizationId,
          workspaceId,
          allowLast: auth.kind === "bootstrap",
          actor: auth.kind === "bootstrap" ? { kind: "bootstrap" } : { kind: "user", userId: auth.principal.userId },
        })
        : "not_found";
      if (outcome === "not_found") throw new HttpError(404, "workspace_not_found", "Workspace not found");
      if (outcome === "last_workspace") {
        throw new HttpError(409, "last_workspace", "An organization must keep at least one workspace");
      }
      if (outcome === "in_use") {
        throw new HttpError(409, "workspace_in_use", "Disconnect workspace integrations and finish their cleanup first");
      }
      response.writeHead(204);
      response.end();
      return;
    }

    const abandonCleanup = routeMatch(
      path,
      /^\/api\/v1\/organizations\/([^/]+)\/workspaces\/([^/]+)\/mcp-oauth\/abandon-cleanup$/,
    );
    if (abandonCleanup && method === "POST") {
      // Operator-only escape hatch for connector cleanup that cannot finish.
      // It skips the remote release, so organization admins cannot use it.
      const [organizationId, workspaceId] = abandonCleanup as [string, string];
      const auth = await organizationAccess(request, organizationId, true);
      if (auth.kind !== "bootstrap") {
        throw new HttpError(403, "operator_only", "Only the operator can abandon connector cleanup");
      }
      // revoke_live=true also revokes the workspace's live grants, for when the
      // module is off or unavailable and nobody can disconnect them.
      const revokeParam = new URL(request.url ?? "/", "http://local").searchParams.get("revoke_live");
      if (revokeParam !== null && revokeParam !== "true" && revokeParam !== "false") {
        throw new HttpError(400, "invalid_request", "revoke_live must be true or false");
      }
      const revokeLive = revokeParam === "true";
      const result = isUuid(workspaceId)
        ? await store.abandonMcpOAuthCleanup({ organizationId, workspaceId, actor: { kind: "bootstrap" }, revokeLive })
        : null;
      if (result === null) throw new HttpError(404, "workspace_not_found", "Workspace not found");
      json(response, 200, revokeLive ? result : { abandoned: result.abandoned });
      return;
    }

    const membershipCollection = routeMatch(
      path,
      /^\/api\/v1\/organizations\/([^/]+)\/memberships$/,
    );
    if (membershipCollection) {
      const organizationId = membershipCollection[0]!;
      const auth = await organizationAccess(request, organizationId, method === "POST");
      if (method === "GET") {
        json(response, 200, { memberships: await store.listMemberships(organizationId) });
        return;
      }
      if (method === "POST") {
        const body = await requestObject(request);
        const role = stringField(body, "role")!;
        if (role !== "owner" && role !== "admin" && role !== "member") {
          throw new HttpError(400, "invalid_request", "role must be owner, admin, or member");
        }
        const email = stringField(body, "email")!;
        // Owners are managed only by owners (admins manage admins and members).
        if (auth.kind === "user" && auth.principal.role !== "owner") {
          if (role === "owner") throw new HttpError(403, "forbidden", "Only an owner can make someone an owner.");
          if (await store.memberRoleByEmail(organizationId, email) === "owner") {
            throw new HttpError(403, "forbidden", "Only an owner can change an owner's role.");
          }
        }
        const membership = await store.putMembership({
          organizationId,
          email,
          name: stringField(body, "name")!,
          role,
          operator: auth.kind === "bootstrap",
        });
        await identity?.auditMembership({
          organizationId,
          auth,
          action: "membership.update",
          target: `${String(membership.userId)} ${String(membership.email)} role=${role}`,
        });
        json(response, 200, membership);
        return;
      }
    }

    const membershipItem = routeMatch(
      path,
      /^\/api\/v1\/organizations\/([^/]+)\/memberships\/([^/]+)$/,
    );
    if (membershipItem && method === "DELETE") {
      const [organizationId, userId] = membershipItem as [string, string];
      const auth = await organizationAccess(request, organizationId, true);
      if (auth.kind === "user" && auth.principal.role !== "owner" &&
        await store.memberRole(organizationId, userId) === "owner") {
        throw new HttpError(403, "forbidden", "Only an owner can remove an owner.");
      }
      // Local Amp, Factory and OAuth authority retires atomically, including
      // when a module is off. Remote release remains post-commit.
      const deleted = await store.deleteMembership(
        organizationId,
        userId,
        async (tx, member) => {
          await purgeMemberAmp(tx, member);
          await factory.purgeMemberInTx(tx, organizationId, userId);
          await revokeOrganizationMcpOAuthGrants(tx, member, input.now?.() ?? new Date());
        },
      );
      if (!deleted) {
        if (!(await store.memberRole(organizationId, userId))) {
          await revokeRemovedMember(messagingDeps, organizationId, userId);
        }
        throw new HttpError(409, "membership_not_removed", "Membership not found or is the last owner");
      }
      await identity?.auditMembership({ organizationId, auth, action: "membership.remove", target: userId });
      await revokeRemovedMember(messagingDeps, organizationId, userId);
      if (amp) await releaseMemberAmp(amp.deps, { organizationId, userId }).catch(() => undefined);
      await factory.afterMemberRemoved(organizationId, userId);
      oauthTeardown?.kick();
      response.writeHead(204);
      response.end();
      return;
    }

    // Names for the session search `@name` autocomplete: names only, for members.
    const agentNames = routeMatch(path, /^\/api\/v1\/workspaces\/([^/]+)\/session-agent-names$/);
    if (agentNames && method === "GET") {
      const { principal, workspace } = await workspaceAccess(request, agentNames[0]!);
      if (principal.pendingHandoff) {
        throw new HttpError(403, "handoff_not_exchanged", "Exchange the sign-in handoff first");
      }
      // Each call spends the workspace's server-side Relaycast key.
      rateLimit(response, `session-agent-names:${principal.userId}`, AGENT_NAMES_RATE, "rate_limited", "Too many requests. Try again shortly.");
      let roster: RosterAgent[];
      try {
        roster = await createRelaycastClient({ internalOrigin: config.relaycastUrl, fetchImpl: input.messagingFetch })
          .listAgents(workspace.relaycastApiKey, "all");
      } catch {
        throw new HttpError(502, "agent_roster_unavailable", "The agent roster is unavailable");
      }
      const names = roster.filter(isListedRelayAgent).map((agent) => agent.name).filter(Boolean);
      json(response, 200, { names: [...new Set(names)].sort() }, true);
      return;
    }

    // Capture policy (docs/capture-policy.md): any member reads it through
    // access/me; organization owner/admin writes it.
    const accessMe = routeMatch(path, /^\/api\/v1\/workspaces\/([^/]+)\/access\/me$/);
    if (accessMe && method === "GET") {
      const { workspace } = await workspaceAccess(request, accessMe[0]!);
      json(response, 200, {
        workspace: { id: workspace.id, name: workspace.name },
        role: workspace.role,
        policy: await readCapturePolicy(store.database, workspace.organizationId),
      }, true);
      return;
    }

    const capturePolicy = routeMatch(path, /^\/api\/v1\/organizations\/([^/]+)\/capture-policy$/);
    if (capturePolicy && (method === "GET" || method === "PUT" || method === "DELETE")) {
      const organizationId = capturePolicy[0]!;
      const auth = await organizationAccess(request, organizationId, true);
      if (method === "GET") {
        json(response, 200, await readCapturePolicy(store.database, organizationId), true);
        return;
      }
      if (!operatorControlsEntitled()) {
        throw new HttpError(403, "operator_controls_not_entitled", "Operator controls are not enabled for this installation");
      }
      // Cookie writes: JSON from an allowed origin; a bodiless DELETE needs
      // an allowed Origin (or same-origin fetch metadata).
      if (!bearer(request)) {
        const allowed = method === "DELETE"
          ? cookieDeleteAllowed(request, browserOrigins)
          : cookieRequestAllowed(request, browserOrigins);
        if (!allowed) throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
      const expectedRevision = parseIfMatch(request.headers["if-match"]);
      let settings = {};
      if (method === "PUT") {
        const body = await requestObject(request);
        const extra = Object.keys(body).filter((key) => key !== "settings");
        if (extra.length > 0) {
          throw new CapturePolicyError(400, "invalid_policy", `Unknown field: ${extra[0]!.slice(0, 64)}`);
        }
        settings = parseCaptureSettings(body.settings);
      }
      const policy = await writeCapturePolicy(store.database, {
        organizationId,
        settings,
        expectedRevision,
        actor: auth.kind === "user" ? { kind: "user", userId: auth.principal.userId } : { kind: "bootstrap" },
        action: method === "PUT" ? "capture_policy.set" : "capture_policy.cleared",
      });
      json(response, 200, policy, true);
      return;
    }

    // Operator session hard delete (docs/session-erasure.md). Erases session
    // data only: organization membership is never touched.
    const sessionErase = routeMatch(path, /^\/api\/v1\/organizations\/([^/]+)\/sessions\/([^/]+)$/);
    if (sessionErase && method === "DELETE") {
      const [organizationId, sessionId] = sessionErase as [string, string];
      const auth = await organizationAccess(request, organizationId, true);
      if (!operatorControlsEntitled()) {
        throw new HttpError(403, "operator_controls_not_entitled", "Operator controls are not enabled for this installation");
      }
      if (!bearer(request) && !cookieDeleteAllowed(request, browserOrigins)) {
        throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
      const api = requireErasureApi(config);
      const target = await erasureTarget(store.database, organizationId, sessionId, url.searchParams);
      const result = await eraseSession(
        store.database,
        api,
        target,
        auth.kind === "user" ? { kind: "user", userId: auth.principal.userId } : { kind: "bootstrap" },
      );
      json(response, result.status === "completed" ? 200 : 202, result, true);
      return;
    }

    const sessionErasure = routeMatch(path, /^\/api\/v1\/organizations\/([^/]+)\/sessions\/([^/]+)\/erasure$/);
    if (sessionErasure && method === "GET") {
      const [organizationId, sessionId] = sessionErasure as [string, string];
      await organizationAccess(request, organizationId, true);
      const api = requireErasureApi(config);
      const target = await erasureTarget(store.database, organizationId, sessionId, url.searchParams);
      json(response, 200, await readSessionErasure(store.database, api, target), true);
      return;
    }

    const resolveWorkspace = routeMatch(
      path,
      /^\/api\/v1\/workspaces\/([^/]+)\/resolve$/,
    );
    if (resolveWorkspace && method === "GET") {
      // Cloud parity: the workspace-wide key goes only to a person holding
      // cli:auth (every device and browser session carries it), bearer or cookie.
      await rejectServiceCredential(request);
      const { principal, workspace } = await workspaceAccess(request, resolveWorkspace[0]!);
      if (!principal.scopes.includes("cli:auth")) {
        throw new HttpError(403, "forbidden", "Relaycast key requires a browser session or cli:auth");
      }
      // Written before the key leaves; the target is the non-secret session id.
      await recordAudit(store.database, {
        organizationId: workspace.organizationId,
        workspaceId: workspace.id,
        actor: { kind: "user", userId: principal.userId },
        action: "workspace.relaycast_key.resolved",
        target: `session:${principal.sessionId}`,
      });
      json(response, 200, {
        workspaceId: workspace.id,
        cloudWorkspaceId: workspace.id,
        relaycastWorkspaceId: workspace.relaycastWorkspaceId,
        organizationId: workspace.organizationId,
        name: workspace.name,
        relaycastApiKey: workspace.relaycastApiKey,
        urls: { relaycastUrl: config.relaycastPublicUrl },
        provisioned: false,
      }, true);
      return;
    }

    const runtime = routeMatch(path, /^\/api\/v1\/workspaces\/([^/]+)\/runtime$/);
    if (runtime) {
      const access = await workspaceAccess(request, runtime[0]!, method === "PUT");
      if (method === "GET") {
        json(response, 200, { runtime: access.workspace.runtime });
        return;
      }
      if (method === "PUT") {
        const body = await requestObject(request);
        if (!("runtime" in body) || body.runtime === undefined) {
          throw new HttpError(400, "invalid_request", "runtime is required");
        }
        await store.setRuntime(access.workspace.id, body.runtime);
        json(response, 200, { runtime: body.runtime });
        return;
      }
    }

    if (await handleSessionRoutes({
      method,
      path,
      url,
      request,
      response,
      config,
      store,
      workspaceAccess,
      httpError: (status, code, message) => new HttpError(status, code, message),
      json,
      now: input.now,
      onSearch: (organizationId) => recordUsage(() => usage.increment(organizationId, "searches")),
    })) {
      return;
    }

    const readSession = routeMatch(path, /^\/api\/v1\/workspaces\/([^/]+)\/session-read\/(session|refresh)$/);
    if (readSession && method === "POST") {
      const browser = !bearer(request);
      const { principal, workspace } = await workspaceAccess(request, readSession[0]!);
      if (browser && !cookieRequestAllowed(request, browserOrigins)) {
        throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
      if (browser && readSession[1] === "refresh") {
        throw new HttpError(403, "forbidden", "Browser clients must request a new read session");
      }
      if (principal.pendingHandoff) {
        throw new HttpError(403, "handoff_not_exchanged", "Exchange the sign-in handoff first");
      }
      if (!principal.scopes.includes("rth:read")) {
        throw new HttpError(403, "forbidden", "Read credentials require rth:read");
      }
      const schema = readSession[1] === "refresh" ? readRefreshRequest : readSessionRequest;
      const parsed = schema.safeParse(await requestObject(request));
      if (!parsed.success) throw new HttpError(400, "invalid_request", "Invalid session read request");
      rateLimit(response, `session-read:${principal.userId}:${workspace.id}`,
        { limit: 30, windowMs: 60_000 }, "rate_limited", "Too many session read credential requests");
      const session = await requestReadSession(config.sessionReadApi, {
        userId: principal.userId, orgId: workspace.organizationId, workspaceId: workspace.id,
      }, parsed.data);
      // Page scripts get a short-lived access token only. Renew by requesting
      // a new session through the cookie path, which rechecks live membership.
      const { refreshToken: _refresh, refreshTokenExpiresAt: _expiry, ...accessOnly } = session;
      json(response, 200, browser ? accessOnly : session, true);
      return;
    }

    // Read-only: which History origin this workspace's sessions are bound
    // to. Nothing is issued and the sessions pipeline is not called, so Desktop can
    // answer site-push admission and cold-process delete/revoke lookups
    // without the session issue/renew path.
    const historyOrigin = routeMatch(
      path,
      /^\/api\/v1\/workspaces\/([^/]+)\/relayhistory\/origin$/,
    );
    if (historyOrigin && method === "GET") {
      const workspaceId = historyOrigin[0]!;
      // Callers: the user sessions the sibling POST .../relayhistory/session
      // accepts through workspaceAccess (device, exchanged Desktop handoff,
      // browser), minus an unexchanged handoff. Service, bootstrap and
      // workspace API tokens are 401. Order: authenticate, handoff refusal,
      // workspace binding, membership, configuration.
      const auth = await authenticate(request);
      if (auth.kind !== "user") throw new HttpError(401, "unauthorized", "User token required");
      const principal = auth.principal;
      if (principal.pendingHandoff) {
        throw new HttpError(403, "handoff_not_exchanged", "Exchange the sign-in handoff (POST /api/v1/auth/desktop/session) first");
      }
      const workspace = await store.workspaceForUser(workspaceId, principal.userId);
      if (workspaceId !== principal.workspaceId) {
        // 403 only for a workspace in the token's own organization that the
        // caller is a member of; anything else, including the same person's
        // workspaces in other organizations, is 404 (no existence oracle).
        if (workspace && workspace.organizationId === principal.organizationId) {
          throw new HttpError(403, "forbidden", "Token is not authorized for this workspace");
        }
        throw new HttpError(404, "workspace_not_found", "Workspace not found");
      }
      if (!workspace) throw new HttpError(404, "workspace_not_found", "Workspace not found");
      // Sessions are bound to relayhistoryPublicUrl, the read API's public
      // origin (default introspection audience, returned baseUrl, ingest edge
      // origin). One installation-wide value. loadConfig requires it to be a
      // bare origin, and introspection compares the audience by exact string.
      if (!config.relayhistoryUrl || !config.relayhistoryPublicUrl) {
        throw new HttpError(404, "relayhistory_not_configured", "RelayHistory is not configured");
      }
      json(response, 200, {
        workspace: workspace.id,
        origin: config.relayhistoryPublicUrl,
        audience: config.relayhistoryPublicUrl,
      }, true);
      return;
    }

    const historySession = routeMatch(
      path,
      /^\/api\/v1\/workspaces\/([^/]+)\/relayhistory\/session$/,
    );
    if (historySession && method === "POST") {
      const access = await workspaceAccess(request, historySession[0]!);
      const body = await requestObject(request);
      const mode = body.mode ?? "sync";
      if (mode !== "read" && mode !== "sync") {
        throw new HttpError(400, "invalid_mode", "mode must be read or sync");
      }
      if (mode === "sync" && !access.principal.scopes.includes("rth:sync")) {
        throw new HttpError(403, "mode_not_authorized", "Sync mode is not authorized");
      }
      const label = stringField(body, "label", false);
      json(response, 200, await nativeHistorySession(request, response, access, mode, label), true);
      return;
    }

    // Direct-to-S3 upload credentials (docs/sessions-read-api.md). Off and
    // not-allowlisted answer the same 404 so a client cannot tell them apart.
    const historyUploadCredentials = routeMatch(
      path,
      /^\/api\/v1\/workspaces\/([^/]+)\/relayhistory\/upload-credentials$/,
    );
    if (historyUploadCredentials) {
      if (!historyUpload || !uploadConfig) {
        throw new HttpError(404, "history_upload_direct_off", "Direct session uploads are not enabled");
      }
      if (method !== "POST") {
        response.setHeader("allow", "POST");
        throw new HttpError(405, "method_not_allowed", "Method not allowed");
      }
      const access = await workspaceAccess(request, historyUploadCredentials[0]!);
      await assertNativeUploadCaller(request, access);
      const { principal, workspace } = access;
      if (uploadConfig.mode === "allowlist" && !uploadConfig.allowlist.includes(principal.userId)) {
        throw new HttpError(404, "history_upload_direct_off", "Direct session uploads are not enabled");
      }
      rateLimit(response, `history-upload-credentials:${principal.userId}:${workspace.id}`,
        { limit: 12, windowMs: 60_000 }, "rate_limited", "Too many upload credential requests");
      try {
        const parsed = parseUploadCredentialsRequest(await requestObject(request));
        json(response, 200, await historyUpload.issue({
          orgId: workspace.organizationId, workspaceId: workspace.id, userId: principal.userId,
        }, parsed), true);
      } catch (error) {
        if (error instanceof UploadCredentialsError) throw new HttpError(error.status, error.code, error.message);
        throw error;
      }
      return;
    }

    // Desktop-provider MCP credentials (Copilot in VS Code): Agent Relay
    // Desktop registers the secret it saved, with its own verified sign-in.
    const credentialCollection = routeMatch(
      path,
      /^\/api\/v1\/workspaces\/([^/]+)\/mcp\/shared-sessions-tokens$/,
    );
    const credentialItem = routeMatch(
      path,
      /^\/api\/v1\/workspaces\/([^/]+)\/mcp\/shared-sessions-tokens\/([^/]+)$/,
    );
    if (credentialCollection || credentialItem) {
      const allowed = credentialCollection ? ["GET", "POST"] : ["PUT", "DELETE"];
      if (!allowed.includes(method)) {
        response.setHeader("allow", allowed.join(", "));
        throw new HttpError(405, "method_not_allowed", "Method not allowed");
      }
      const workspaceId = (credentialCollection ?? credentialItem)![0]!;
      // Only a header bearer can be a Desktop sign-in; cookies never are.
      if (!bearer(request)) throw new HttpError(401, "unauthorized", "Authentication required");
      const access = await workspaceAccess(request, workspaceId);
      rateLimit(
        response,
        `desktop-mcp:${access.workspace.id}:${access.principal.userId}`,
        DESKTOP_MCP_RATE,
        "rate_limited",
        "Too many provider credential requests. Try again shortly.",
      );
      try {
        if (credentialCollection && method === "GET") {
          json(response, 200, { tokens: await desktopMcpCredentials.list(access.token, access.workspace.id) }, true);
          return;
        }
        if (credentialCollection) {
          const body = await requestObject(request);
          const keys = Object.keys(body).sort();
          const { provider, installationId, accessToken } = body;
          if (
            keys.join(",") !== "accessToken,installationId,provider" ||
            typeof provider !== "string" || !PROVIDER.test(provider) ||
            typeof installationId !== "string" || !UUID.test(installationId) ||
            typeof accessToken !== "string" || !DESKTOP_MCP_TOKEN.test(accessToken)
          ) {
            throw new HttpError(400, "invalid_request", "Invalid provider credential request");
          }
          const issued = await desktopMcpCredentials.issue({
            parentToken: access.token,
            workspaceId: access.workspace.id,
            provider,
            installationId,
            accessToken,
          });
          // Metadata only: Desktop already holds the secret it sent.
          json(response, 201, issued, true);
          return;
        }
        const tokenId = credentialItem![1]!;
        if (method === "PUT") {
          json(response, 200, await desktopMcpCredentials.renew(access.token, access.workspace.id, tokenId), true);
          return;
        }
        await desktopMcpCredentials.revoke(access.token, access.workspace.id, tokenId);
        response.writeHead(204, { "cache-control": "no-store" });
        response.end();
        return;
      } catch (error) {
        if (error instanceof DesktopMcpCredentialError) throw new HttpError(error.status, error.code, error.message, error.extra);
        throw error;
      }
    }

    if (await handleDesktopIdentityRoutes(request, response, path, method, {
      workspaceAccess,
      requestObject,
      json,
      database: store.database,
      keyring: config.encryptionKeyring,
      fetchImpl: input.messagingFetch,
      relaycastUrl: config.relaycastUrl,
      csrfAllowed: (incoming) => Boolean(bearer(incoming)) || cookieRequestAllowed(incoming, browserOrigins),
    })) return;

    if (analyticsGateway && method === "POST" && path === "/api/v1/analytics/events") {
      await analyticsEvents(request, response, analyticsGateway);
      return;
    }

    if (await mcp(request, response, path, method)) return;
    if (await mcpOAuth.handleNode(request,response)) return;
    if (desktopFeed && await desktopFeed(request, response, path, method)) return;
    if (await handleProviderRoutes(request, response, path, method, {
      probes: providerProbes, workspaceAccess: (incoming, id) => workspaceAccess(incoming, id), json,
    })) return;
    if (await remoteAgents(request, response, path, method, {
      workspaceAccess, requestObject, json,
      csrfAllowed: incoming => Boolean(bearer(incoming)) || cookieRequestAllowed(incoming, browserOrigins),
    })) return;
    if (await handleChiefRoutes(request, response, path, {
      backend: input.chief, workspaceAccess, requestObject, json,
      requireFeature: () => requireFeature("chief"),
      csrfAllowed: incoming => Boolean(bearer(incoming)) || cookieRequestAllowed(incoming, browserOrigins),
    })) return;

    if (await messaging(request, response, path, method, { workspaceAccess, bearer, json })) return;

    if (flows && await flows(request, response, path, url)) return;

    if (admin && await admin.handle(request, response, path, url, {
      workspaceAccess,
      organizationAccess,
      requestObject,
      bearer,
    })) {
      return;
    }

    if (telemetry && await telemetry.handle(request, response, path, url, {
      organizationAccess,
      requestObject,
      bearer,
    })) {
      return;
    }

    throw new HttpError(404, "not_found", "Route not found");
  }

  return (request, response) => {
    // telemetry lane: aggregate usage per feature area (no bodies or queries).
    if (telemetry) {
      const routePath = new URL(request.url ?? "/", config.publicBaseUrl).pathname;
      response.once("finish", () => telemetry.observeRequest({
        method: request.method ?? "GET",
        path: routePath,
        status: response.statusCode,
      }));
    }
    void handle(request, response).catch((error: unknown) => {
      if (response.headersSent) {
        response.end();
        return;
      }
      if (error instanceof FeatureRefusedError) {
        json(response, error.status, { error: error.code, message: error.message, feature: error.feature }, true);
        return;
      }
      if (error instanceof HttpError || error instanceof MessagingHttpError) {
        const extra = error instanceof HttpError ? error.extra : undefined;
        json(response, error.status, { error: error.code, message: error.message, ...extra }, true);
        return;
      }
      if (error instanceof CapturePolicyError) {
        json(response, error.status, { error: error.code, message: error.message }, true);
        return;
      }
      if (error instanceof SessionErasureError) {
        json(response, error.status, {
          error: error.code,
          message: error.message,
          ...(error.erasure ? { erasure: error.erasure } : {}),
        }, true);
        return;
      }
      const identityError = identityErrorResponse(error);
      if (identityError) {
        json(response, identityError.status, identityError.body, true);
        return;
      }
      const adminError = adminErrorResponse(error);
      if (adminError) {
        json(response, adminError.status, adminError.body, true);
        return;
      }
      if (error instanceof ReadCursorExpiredError) {
        json(response, 410, { error: "cursor_expired", message: error.message }, true);
        return;
      }
      if (error instanceof SessionReadError) {
        json(response, error.status, { error: error.code, message: error.message }, true);
        return;
      }
      if (error instanceof UpstreamError) {
        telemetry?.observeError(error, {
          path: new URL(request.url ?? "/", config.publicBaseUrl).pathname,
          status: error.status ?? 502,
          component: "relayhistory",
        });
        json(response, error.retryable ? 503 : 502, {
          error: "relayhistory_session_failed",
          stage: error.stage,
          upstreamStatus: error.status ?? null,
        }, true);
        return;
      }
      if (error instanceof NodeClaimError) {
        json(response, error.status, { error: "node_claim_refused", message: error.message }, true);
        return;
      }
      if (error instanceof MembershipConflictError) {
        json(response, 409, {
          error: "last_owner_required",
          message: error.message,
        }, true);
        return;
      }
      if (error instanceof ReservedClientNameError) {
        json(response, 400, { error: "invalid_request", message: error.message }, true);
        return;
      }
      if (error instanceof InvitationRequiredError) {
        json(response, 409, { error: "invitation_required", message: error.message }, true);
        return;
      }
      if (error instanceof OrganizationConflictError) {
        json(response, 409, {
          error: "organization_already_configured",
          message: error.message,
        }, true);
        return;
      }
      if (error instanceof OrganizationBoundaryError) {
        json(response, 404, {
          error: "organization_not_found",
          message: "Organization not found",
        }, true);
        return;
      }
      telemetry?.observeError(error, {
        path: new URL(request.url ?? "/", config.publicBaseUrl).pathname,
        status: 500,
      });
      console.error("[selfhost-api] request failed", {
        method: request.method,
        path: request.url,
        error: error instanceof Error ? error.message : String(error),
      });
      json(response, 500, { error: "internal", message: "Internal server error" }, true);
    });
  };
}
