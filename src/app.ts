import { page } from "./identity/pages.js";
import { revokeOrganizationMcpOAuthGrants } from "./mcp/oauth/revocations.js";
import { createMcpOAuthHttpModule } from "./mcp/oauth/routes.js";
import { McpOAuthStore } from "./mcp/oauth/store.js";
import { connectorKind, isGrokRoutineKind } from "./mcp/oauth/connector-kind.js";
import { createCursorCloud } from "./mcp/cursor-cloud.js";
import type { CursorJwks } from "./mcp/cursor-oidc.js";
import { relayHostedCredentials } from "./mcp/relay-hosted-credentials.js";
import { agentIdentityHoldsName, ownerHash, HOSTED_SOURCE } from "./mcp/relay-participants.js";
import { McpOAuthTeardown,mcpOAuthTeardownFetch } from "./mcp/oauth/teardown.js";
import { mcpOAuthActive } from "./mcp/oauth/config.js";
import { GrokRoutines, grokRoutinesOptions } from "./mcp/grok-routines.js";
import { AgentRules, isAgentRulesAudience } from "./agent-rules/service.js";
import { AgentRulesInputError } from "./agent-rules/overlays.js";
import { retiringIdentity } from "./mcp/oauth/retirement.js";
import { isDeviceReservedClientName } from "./reserved-client-names.js";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { delegationQuoteSecret, SELFHOST_API_VERSION, type SelfhostConfig } from "./config.js";
import { browserOriginsFor } from "./site-origins.js";
import { secureEqual } from "./crypto.js";
import type { SqlExecutor } from "./database.js";
import { adminErrorResponse, type AdminModule } from "./admin/routes.js";
import { ApiTokenStore, ENROLLMENT_KEY_PREFIX, type AgentIdentityRosterCheck } from "./admin/api-tokens.js";
import { recordAudit } from "./admin/audit.js";
import { ReadCursorExpiredError, UpstreamError } from "./relayhistory.js";
import { handleChiefRelay } from "./chief-relay.js";
import { handleRelayNode, RELAY_NODE_RATE_LIMIT } from "./relay-node/broker.js";
import { relayNodeCredentials, type RelayNodeCredentials } from "./relay-node/credentials.js";
import { createRelayNodeSocketBridge, refuseUpgrade } from "./relay-node/socket.js";
import { handleFlowsBroker } from "./flows-broker.js";
import { FlowRunRelayfileCredentials } from "./flows/relayfile-credentials.js";
import { relayLaunchCredentials } from "./mcp/relay-launch-credentials.js";
import { handleSessionRoutes } from "./sessions/routes.js";
import { parseClientTelemetry, recordClientTelemetry, recordsClientTelemetry } from "./sessions/client-telemetry.js";
import { UsageRangeError, usageDates, usageDays, usageReport } from "./usage/routes.js";
import {
  decodeFleetCursor, FLEET_AUDIT_ACTION, FleetInputError, fleetView, type FleetCursor, type FleetUsageInput,
} from "./fleet/view.js";
import { UsageStore } from "./usage/store.js";
import { GitHubDesktopReleases } from "./desktop-releases.js";
import {
  listReadAudit, parseReadAuditQuery, readAuditCsv, ReadAuditQueryError, restrictReadAudit, type ReadAuditAccessProbe,
} from "./mcp/read-audit.js";
import { accessViaDashboardReader, readWorkspaceHistory, type HistoryIdentity } from "./sessions/history.js";
import { confirmsAccessAdministrator, sessionAccessConfigured } from "./sessions/access.js";
import {
  PeopleInputError, PersonNotFoundError, peopleAudit, peopleReport, personSessions, recordPeopleView, UsagePeopleStore,
} from "./usage/people.js";
import { mcpReaderMarker, readerKindOf, readSessionRequest, readRefreshRequest, requestReadSession, SessionReadError } from "./session-read.js";
import { bearer } from "./auth/bearer.js";
import { z } from "zod";
import {
  acceptedAudiences,
  handleIntrospection,
  introspect,
  INTROSPECT_PATH,
  matchingRelayhistoryAudience,
} from "./auth/introspect.js";
import { IntrospectionHold } from "./auth/introspection-hold.js";
import { controlSessionToken, SESSION_COOKIE } from "./auth/session-cookie.js";
import { handleAcquisitionRoutes } from "./acquisition/routes.js";
import { createDesktopFeedHandler, type DesktopFeedLimits } from "./desktop-feed/routes.js";
import { AwsKmsDesktopFeedSigner, FileDesktopFeedSigner, MemoryDesktopFeedSigner, type DesktopFeedSigner } from "./desktop-feed/signer.js";
import { GcsDesktopFeedStorage, MemoryDesktopFeedStorage, S3DesktopFeedStorage, type DesktopFeedStorage } from "./desktop-feed/storage.js";
import { DesktopFeedStore } from "./desktop-feed/store.js";
import { DefaultAwsCredentialProvider, StaticAwsCredentialProvider, type AwsCredentialProvider } from "./aws/sigv4.js";
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
  RelaycastBindingUnavailableError,
  type ControlPlaneStore,
  type Principal,
} from "./store.js";
import { createFlowsHandler } from "./flows/routes.js";
import { isUuid, type FlowsStore } from "./flows/store.js";
import { OrganizationTeams, TeamsError, teamName } from "./teams/store.js";
import {
  grantJson,
  parseMintRequest,
  StaffReadGrantError,
  StaffReadGrants,
  type StaffPerson,
} from "./admin/staff-read-grants.js";
import type { TelemetryModule } from "./telemetry/module.js";
import { identityErrorResponse, type IdentityModule } from "./identity/routes.js";
import { revokeRemovedMember, type MessagingDeps } from "./messaging/identity.js";
import { createMessagingHandler, MessagingHttpError } from "./messaging/routes.js";
import { createDelegationHandler } from "./delegation/routes.js";
import { ConnectionError } from "./admin/connections.js";
import { GithubUnavailable } from "./delegation/gates.js";
import { relaycastQuoteRedactor } from "./delegation/service.js";
import { DelegationSigner } from "./delegation/jws.js";
import { GITHUB_ACTIONS_OIDC_ISSUER, workflowOidcVerifier } from "./delegation/oidc.js";
import { isBindingOwnedIdentity } from "./messaging/binding-identities.js";
import type { McpContext } from "./mcp/context.js";
import { createFactoryModule, mountFactoryRoutes, type FactoryModule } from "./factory/routes.js";
import { createMcpHandler } from "./mcp/routes.js";
import { createCustomerSupportNoticeHandler } from "./mcp/customer-support-notice.js";
import type { AmpModule } from "./amp/module.js";
import type { ReplicasModule } from "./replicas/module.js";
import { isReplicasPath } from "./replicas/routes.js";
import { abandonEnvironmentCleanup, disconnectEnvironments, setupEnvironments } from "./replicas/environments.js";
import { disconnectReplicas, purgeMemberReplicas, releaseMemberReplicas, ReplicasError } from "./replicas/service.js";
import { isAmpPath } from "./amp/routes.js";
import { createEventsShimRoutes, isEventsShimPath } from "./events-shim/routes.js";
import type { AgentLinkDeps } from "./events-shim/agent-link.js";
import { PostgresEventsShimStore } from "./events-shim/store.js";
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
import { RemoteAgentConnections, RemoteAgentError } from "./remote-agents/connections.js";
import { remoteAgentRoutes } from "./remote-agents/routes.js";
import type { ProviderProbes } from "./providers/registry.js";
import {
  CapturePolicyError,
  capturePolicyForCaller,
  parseCaptureSettings,
  parseIfMatch,
  readCapturePolicy,
  CAPTURE_POLICY_REVISION_HEADER,
  sharingDeployment,
  uploadPolicyVerdict,
  writeCapturePolicy,
} from "./capture-policy.js";
import {
  parseWorkspacePolicyInput,
  readWorkspacePolicy,
  workspacePolicyForCaller,
  sessionManagedByEnrollmentKey,
  UNSET_WORKSPACE_POLICY,
  writeWorkspacePolicy,
} from "./workspace-policy.js";
import { operatorControlsEntitled } from "./admin/operator-controls.js";
import { createRelaycastClient, RelaycastCallError, type RosterAgent, type WorkspaceLeaders } from "./messaging/relaycast.js";
import { LeaderPatternsError, parseLeaderPatterns } from "./workspace-leaders.js";
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
import { canonicalRelayhistoryOrigin } from "./relayhistory-origin.js";
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
  ENROLLMENT_RATE_LIMITS,
  limiterKey,
  RateLimiter,
  safeNextPath,
  sanitizeDesktopHostName,
} from "./auth/device-approval.js";
import { dashboardLinkRedirect } from "./dashboard-links.js";
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

// Re-exported: src/server.ts and tests import it from here.
export { browserOriginsFor };

/** A bodiless cookie DELETE needs an allowed Origin, or same-origin fetch metadata. */
function cookieDeleteAllowed(request: IncomingMessage, browserOrigins: string[]): boolean {
  const origin = request.headers.origin;
  return typeof origin === "string" && origin && origin !== "null"
    ? browserOrigins.includes(origin)
    : request.headers["sec-fetch-site"] === "same-origin";
}

/**
 * The request handler, plus the HTTP upgrade handler for server "upgrade"
 * events: the relay-node socket bridge on gate-only installs, 404 otherwise.
 */
export type AppHandler = ((request: IncomingMessage, response: ServerResponse) => void) & {
  handleUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer): void;
  /** Ends every bridged socket (shutdown). */
  closeUpgrades(): void;
};

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
  /** Replicas agents (src/replicas). Absent or disabled: every Replicas bridge route answers 404 before auth. */
  replicas?: ReplicasModule;
  /** Server-owned worker; absent tests use the same on-demand cleanup without a timer. */
  mcpOAuthTeardown?: McpOAuthTeardown;
  grokRoutines?: GrokRoutines;
  /** The rules source (docs/agent-rules.md); tests may inject one with a fixture bundle. */
  agentRules?: AgentRules;
  /** Cursor's OIDC signing keys (tests inject a local issuer); default api.cursor.com's JWKS. */
  cursorJwks?: CursorJwks;
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
  /** Test hook: fetch for release-gate OIDC discovery and JWKS (docs/owner-delegates.md). */
  delegationOidcFetch?: typeof fetch;
  /** GitHub's REST API, for resolving a gate's repository ids at registration (tests inject it). */
  delegationGithubFetch?: typeof fetch;
  /** RELAYCAST_INTERNAL_SECRET: lets webhook inboxes issue temporary Agent Relay workspaces. */
  relaycastInternalSecret?: string | null;
  /** Factory sessions (dormant unless SELFHOST_FACTORY_ENABLED). The server passes its module so it can run the worker. */
  factory?: FactoryModule;
  /** Internal dormant Capy send resolver; server wiring requires a complete runtime. */
  capy?: McpContext["capy"];
  /** Test hook: the GitHub fetch behind GET /api/v1/desktop/releases. */
  desktopReleasesFetch?: typeof fetch;
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
}): AppHandler {
  const { config, store, admin, telemetry, identity } = input;
  const features = input.features ?? NO_FEATURES;
  const workspaceHistoryOrigin = (
    workspace: { relayhistoryOrigin: string | null },
    fallback: string,
  ): string => {
    const stored = workspace.relayhistoryOrigin;
    const imported = stored === null ? null : canonicalRelayhistoryOrigin(stored);
    if (stored !== null && (
      imported === null || matchingRelayhistoryAudience(config, imported) === undefined
    )) {
      // Do not hand a user bearer to an imported destination the operator did
      // not explicitly allow. Use the same 404 as an unconfigured backend so
      // callers cannot enumerate operator configuration.
      throw new HttpError(404, "relayhistory_not_configured", "RelayHistory is not configured");
    }
    return imported ?? canonicalRelayhistoryOrigin(fallback) ?? fallback;
  };
  // Installation wiring, not an opt-in SELFHOST_FEATURES name or a grant to
  // the caller. DELETE still checks organization role and the operator gate.
  const capabilities = () => ({
    ...features,
    session_delete: Boolean(config.sessionErasureApi) && operatorControlsEntitled(),
    // Session reads follow per-session access (docs/sessions-read-api.md#session-access).
    session_access: sessionAccessConfigured(config) && Boolean(config.relayhistoryUrl),
    // Desktop enrollment keys (docs/identity.md): always served.
    enrollment_keys: true,
    // Member self-mint at POST /api/v1/me/enrollment-keys (SELFHOST_ENROLLMENT_SELF_RENEWAL).
    enrollment_self_mint: config.enrollmentSelfRenewal !== false,
  });
  // Usage page counters: written only while the `usage` feature is selected.
  const usage = new UsageStore(store.database, () => input.now?.() ?? new Date());
  const desktopReleases = config.desktopReleasesRepo
    ? new GitHubDesktopReleases(config.desktopReleasesRepo, input.desktopReleasesFetch ?? globalThis.fetch)
    : null;
  const people = new UsagePeopleStore(store.database, () => input.now?.() ?? new Date());
  // Counters never fail or slow a request; each is written only while its feature is on.
  const recordUsage = (write: () => Promise<void>): void => {
    if (!features.usage) return;
    void write().catch(() => {});
  };
  const recordPeople = (write: () => Promise<void>): void => {
    if (!features.usage_people) return;
    void write().catch(() => {});
  };
  // Every route that authenticates an access token (API, dashboard account
  // pages, Desktop, MCP, and introspection by ingest and the read API)
  // counts its user as active today.
  if (features.usage || features.usage_people) {
    store.onAuthenticated = (user) => {
      recordUsage(() => usage.recordActiveUser(user.organizationId, user.userId));
      recordPeople(() => people.recordActive(user.organizationId, user.userId));
    };
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
    relaygatePublicUrl: config.relaygatePublicUrl,
    fetchImpl: input.messagingFetch,
    now: input.now,
    ...input.messaging,
  };
  const messaging = createMessagingHandler({
    ...messagingDeps,
    relaycastPublicUrl: config.relaycastPublicUrl,
    relaygatePublicUrl: config.relaygatePublicUrl,
    internalServiceToken: config.internalServiceToken,
    browserOrigins,
  });
  const customerSupportNotice = createCustomerSupportNoticeHandler(config, store, messagingDeps);
  // Owner-named trusted delegates (docs/owner-delegates.md). Off per
  // workspace until an admin turns delegation_enabled on.
  const delegation = createDelegationHandler({
    database: store.database,
    quoteKey: delegationQuoteSecret(config),
    relaycastRedact: relaycastQuoteRedactor({ relaycastUrl: config.relaycastUrl,
      internalSecret: input.relaycastInternalSecret ?? null, fetchImpl: input.messagingFetch }),
    relaycast: createRelaycastClient({ internalOrigin: config.relaycastUrl, fetchImpl: input.messagingFetch }),
    signer: config.delegationSigning ? new DelegationSigner(config.delegationSigning) : null,
    gateOnly: Boolean(config.relaygatePublicUrl),
    browserOrigins,
    authenticateAccessToken: (token) => store.authenticateAccessToken(token),
    workspaceForUser: (workspaceId, userId) => store.workspaceForUser(workspaceId, userId),
    json,
    workflowOidc: workflowOidcVerifier({
      issuers: [GITHUB_ACTIONS_OIDC_ISSUER, ...(config.delegationOidcIssuers ?? [])],
      audience: new URL(config.publicBaseUrl).origin,
      fetchImpl: input.delegationOidcFetch,
      now: input.now,
    }),
    oidcIssuers: [GITHUB_ACTIONS_OIDC_ISSUER, ...(config.delegationOidcIssuers ?? [])],
    githubFetch: input.delegationGithubFetch ?? globalThis.fetch,
    // The workspace's GitHub connection (App installation or OAuth), when it has one, as Cloud's installation reader.
    // No connection (404 connection_not_found) is "not installed": registration may fall back to the public API.
    // Any other failure is an outage: no fallback (registration answers 503).
    githubToken: async (workspaceId, userId) => {
      if (!admin) return null;
      try {
        return (await admin.connections.runtimeToken({ workspaceId, provider: "github",
          actor: userId ? { kind: "user", userId } : { kind: "service", subject: "delegation-gate-redeem" } })).accessToken;
      } catch (error) {
        if (error instanceof ConnectionError && error.status === 404) return null;
        throw new GithubUnavailable();
      }
    },
    // Never provisions: these lookups can run before any caller is proven.
    relaycastBinding: (workspaceId) => store.existingRelaycastBinding(workspaceId),
    rateLimit: (res, key, rule) => rateLimit(res, key, rule, "rate_limited", "Too many delegation requests; retry later"),
    clientKey: (request) => limiterKey(clientIp(request)),
    now: input.now,
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
  // Relaycast issues node tokens in two credential families and every deployment
  // accepts both (@relaycast/types credentials.ts): legacy `nt_live_…` and
  // `ar_nd_<workspace 11>_<tag 11>_<secret 43><crc 6>`, which self-hosted relays
  // issue. Shape only; Relaycast decides validity (verifyNodeToken).
  const NODE_TOKEN = /^(?:nt_live_[A-Za-z0-9_-]{8,256}|ar_nd_[0-9A-Za-z]{11}_[a-z][0-9A-Za-z]{10}_[0-9A-Za-z]{49})$/;
  const NODE_ID = NODE_ID_PATTERN;
  // The site a client signed in through: the public API origin or the
  // dashboard origin (both serve /cloud/api). Agent Relay Desktop requires
  // api_url == <its site>/cloud, so sign-in answers name the origin the
  // request arrived on. Only these configured origins are ever echoed, so a
  // forged Host header cannot point a client elsewhere.
  //
  // A third origin (SELFHOST_ROUTED_SITE_URL, docs/repository-guide.md): an edge
  // router on another site origin forwards <site>/cloud/... here, so those
  // requests arrive with this service's own Host, and the router sets
  // x-original-host to its site's host. That header only selects among
  // configured values; nothing from it is echoed. It is honoured without proof
  // from the router because the origin goes back only to the caller that sent
  // the header, is an operator-configured public value, scopes no cookie, is
  // never the target of a redirect sent here and is not stored. That is also
  // why only the Desktop/CLI API answers use apiSiteBaseUrl: emailed links,
  // OIDC redirect URIs and the MCP endpoint URL keep the Host-selected origin.
  //
  // Extra sites (SELFHOST_EXTRA_SITES) are more host sets in front of this same
  // deployment: each of their hosts maps to its own configured origin here, so
  // a request arriving on one is answered with that origin. Config validation
  // keeps every host in one site only.
  const siteBases = new Map<string, string>([
    [new URL(config.dashboardUrl).host.toLowerCase(), new URL(config.dashboardUrl).origin],
    [new URL(config.publicBaseUrl).host.toLowerCase(), config.publicBaseUrl.replace(/\/+$/, "")],
    ...(config.extraSites ?? []).flatMap((site): [string, string][] => [
      [new URL(site.dashboardOrigin).host.toLowerCase(), site.dashboardOrigin],
      [new URL(site.apiOrigin).host.toLowerCase(), site.apiOrigin],
    ]),
  ]);
  // Either host of an extra site -> that site's dashboard origin.
  const extraDashboards = new Map<string, string>((config.extraSites ?? []).flatMap((site): [string, string][] => [
    [new URL(site.dashboardOrigin).host.toLowerCase(), site.dashboardOrigin],
    [new URL(site.apiOrigin).host.toLowerCase(), site.dashboardOrigin],
  ]));
  function requestHost(request: IncomingMessage): string {
    return typeof request.headers.host === "string" ? request.headers.host.trim().toLowerCase() : "";
  }
  function siteBaseUrl(request: IncomingMessage): string {
    return siteBases.get(requestHost(request)) ?? config.publicBaseUrl.replace(/\/+$/, "");
  }
  /** The dashboard URL for the site the request arrived on: an extra site's origin with the configured path, else dashboardUrl. */
  function dashboardUrlFor(request: IncomingMessage): string {
    const origin = extraDashboards.get(requestHost(request));
    if (!origin) return config.dashboardUrl;
    const primary = new URL(config.dashboardUrl);
    return new URL(`${primary.pathname}${primary.search}`, origin).toString();
  }
  const routedSiteOrigin = config.routedSiteOrigin ?? null;
  const routedSiteHost = routedSiteOrigin ? new URL(routedSiteOrigin).host.toLowerCase() : null;
  function apiSiteBaseUrl(request: IncomingMessage): string {
    if (routedSiteOrigin && routedSiteHost) {
      // One header, one value: Node joins repeats with ", ", which never matches.
      const forwarded = request.headers["x-original-host"];
      if (typeof forwarded === "string" && forwarded.trim().toLowerCase() === routedSiteHost) return routedSiteOrigin;
    }
    return siteBaseUrl(request);
  }
  // Hosted MCP (shared-sessions facade): reads, team activity, capabilities.
  const amp = input.amp?.config.enabled ? input.amp : null;
  const providerProbes: ProviderProbes = input.providerProbes ?? {};
  const replicas = input.replicas?.config.enabled ? input.replicas : null;
  const remoteAgents = remoteAgentRoutes(new RemoteAgentConnections(store.database, config.encryptionKeyring, input.remoteAgentFetch, {
    replicasEnabled: Boolean(replicas),
    // Bindings are revoked and retired while the key still exists to sleep their compute.
    ...(replicas ? { replicasCleanup: async (actor: { userId: string; workspaceId: string; organizationId: string },
      options: { abandonEnvironmentCleanup?: boolean }) => {
      try {
        // Stop environment-level admission (the fence), then retire bindings (the compute check and
        // Relay retirement always run, also on an abandon request), and only then confirm and remove
        // provider MCP entries (skipped on an abandon request): an entry that cannot be removed never
        // keeps compute running.
        await disconnectEnvironments(replicas.deps, actor, { ...options, afterFence: () => disconnectReplicas(replicas.deps, actor) });
      } catch (error) {
        if (error instanceof ReplicasError) throw new RemoteAgentError(error.status, "replicas_cleanup_failed", error.message);
        throw new RemoteAgentError(502, "replicas_cleanup_failed", "Replicas cleanup could not finish. Retry the disconnect.");
      }
    },
    replicasAbandon: (tx: SqlExecutor, actor: { userId: string; workspaceId: string; organizationId: string }) =>
      abandonEnvironmentCleanup(tx, actor),
    replicasSetup: (actor: { userId: string; workspaceId: string; organizationId: string }, options: { reconnect: boolean }) =>
      setupEnvironments(replicas.deps, actor, options) } : {}),
  }));
  const oauthRelay = createRelaycastClient({internalOrigin:config.relaycastUrl,fetchImpl:input.messagingFetch});
  // Agent-identity mint: same "mine vs taken" rule as the hosted registration
  // path. The mint route's access check binds the workspace before this runs;
  // a still-unbound workspace (a direct store caller) is not provisioned here
  // and reads as free. Any roster agent other than the identity's own,
  // released or not, holds the name.
  const agentIdentityRoster: AgentIdentityRosterCheck = async (workspaceId, agentName, ownerRef) => {
    const apiKey = await store.existingRelaycastApiKey(workspaceId);
    if (apiKey === null) return "free";
    const remote = await oauthRelay.getAgent(apiKey, agentName);
    if (!remote) return "free";
    return ownerRef !== null && !isBindingOwnedIdentity(remote.metadata) && remote.metadata.source === HOSTED_SOURCE &&
      remote.metadata.cloud_workspace_id === workspaceId && remote.metadata.owner_hash === ownerHash(ownerRef) ? "free" : "held";
  };
  const oauthTeardown=mcpOAuthActive(config) ? input.mcpOAuthTeardown??new McpOAuthTeardown({
    database:store.database,keyring:config.encryptionKeyring,
    client:createRelaycastClient({internalOrigin:config.relaycastUrl,fetchImpl:mcpOAuthTeardownFetch(input.messagingFetch)}),now:input.now,
    ...(config.relaygatePublicUrl ? {gate:createRelaycastClient({internalOrigin:config.relaygatePublicUrl,
      fetchImpl:mcpOAuthTeardownFetch(input.messagingFetch)})} : {}),
  }) : null;
  // Loaded once: a malformed or unpinned bundle fails start-up.
  const agentRules = input.agentRules ?? new AgentRules({ database: store.database, now: input.now });
  const grokRoutines = mcpOAuthActive(config) ? input.grokRoutines ?? new GrokRoutines(grokRoutinesOptions(config,{
      database:store.database,tenancyMode:store.tenancy,client:oauthRelay,fetchImpl:input.messagingFetch,now:input.now,
    })) : undefined;
  // Cursor cloud agents: per-run identity on cursor-cloud OAuth grants (docs/cursor-cloud-agents.md).
  const cursorCloud = mcpOAuthActive(config) && config.cursorCloud ? createCursorCloud({
    config:config.cursorCloud,publicOrigin:config.publicBaseUrl,keyring:config.encryptionKeyring,database:store.database,
    ...(input.cursorJwks ? {jwks:input.cursorJwks} : {}),
  }) : undefined;
  const mcpOAuth = createMcpOAuthHttpModule({
    grokRoutines,
    ...(cursorCloud ? {cursorCloudLinks:cursorCloud.links} : {}),
    config,mountedResources:["/mcp","/api/v1/mcp/shared-sessions"],
    clientAddress:request=>limiterKey(clientIp(request)),
    createStore:({protocol,issuer})=>new McpOAuthStore(store.database,{
      protocol,tenancyMode:store.tenancy,now:input.now,issueIdToken:issuer?.issueMcpOidcIdToken,
      isGrokRoutine:(request,client)=>request.resourcePath==="/api/v1/mcp/relay-events" &&
        request.scopes.includes("relay:events") && isGrokRoutineKind(connectorKind({
          clientName:client.clientName,redirectUris:[request.redirectUri],
        })),
    }),
    resolveSession:async request=>{
      if(request.headers.has("authorization")) return null;
      const token=controlSessionToken(request.headers.get("cookie"));
      if(!token) return null;
      const principal=await store.authenticateAccessToken(token);
      return principal?{transport:"cookie" as const,principal}:null;
    },
    workspaceAccess:async principal=>{
      if(!(await store.readiness()).ready) return false;
      const workspace=await store.workspaceMembershipForUser(principal.workspaceId,principal.userId);
      return workspace?.organizationId===principal.organizationId;
    },
    workspaceLabel:async principal=>(await store.workspaceMembershipForUser(principal.workspaceId,principal.userId))?.name??principal.workspaceId,
    checkAgentNameAvailability:async(principal,name)=>{
      const workspace=await store.workspaceForUser(principal.workspaceId,principal.userId);
      if(!workspace || workspace.organizationId!==principal.organizationId) return "unknown";
      // A workspace agent identity's name (any letter case) is never approvable for a person.
      if(await agentIdentityHoldsName(store.database,principal.workspaceId,name)) return "taken";
      const remote=await oauthRelay.getAgent(workspace.relaycastApiKey,name);
      if(!remote) return "available";
      if(isBindingOwnedIdentity(remote.metadata) || remote.metadata.source!==HOSTED_SOURCE || remote.metadata.cloud_workspace_id!==principal.workspaceId ||
        remote.metadata.owner_hash!==ownerHash(principal.userId)) return "taken";
      // An agent whose release may be in flight cannot be attached to.
      return await retiringIdentity(store.database,{organizationId:principal.organizationId,workspaceId:principal.workspaceId,
        userId:principal.userId,agentRemoteId:remote.id,agentName:remote.name})?"taken":"yours";
    },
    now:input.now,afterMutation:()=>oauthTeardown?.kick(),
  });
  // Webhook inbox links to bound agents (docs/events-shim.md): with the events_shim feature only.
  const agentLinks: AgentLinkDeps | null = features.events_shim ? {
    database: store.database,
    keyring: config.encryptionKeyring,
    relaycast: createRelaycastClient({ internalOrigin: config.relaycastUrl, fetchImpl: input.messagingFetch }),
    store: new PostgresEventsShimStore(store.database, config.encryptionKeyring),
    ...(input.now ? { now: input.now } : {}),
  } : null;
  const mcp = createMcpHandler({
    config, store, browserOrigins, siteBaseUrl, fetchImpl: input.messagingFetch, providerProbes,
    onError: (error, context) => telemetry?.observeError(error, context),
    ...(agentLinks ? { webhookInbox: agentLinks } : {}),
    ...(amp ? { amp: amp.deps } : {}),
    ...(replicas ? { replicas: replicas.deps } : {}),
    ...(factory.enabled ? { factory: factory.mcp } : {}),
    ...(input.capy ? { capy: input.capy } : {}),
    ...(features.launch ? { launch: true } : {}),
    ...(mcpOAuth.store ? {oauthSessions:mcpOAuth.store.sessions} : {}),
    grokRoutines,
    agentRules,
    ...(cursorCloud ? { cursorCloud } : {}),
    ...(input.now ? { now: input.now } : {}),
  });
  const desktopMcpCredentials = new DesktopMcpCredentials(store.database);
  // Events shim (docs/events-shim.md): webhook inboxes that wake an agent.
  // Off unless the events_shim feature is selected; then every route but
  // create is capability-based (the token in the URL or the manage bearer).
  const EVENTS_SHIM_CREATE_RATE = { limit: 20, windowMs: 60 * 60_000 };
  const eventsShim = features.events_shim ? createEventsShimRoutes({
    database: store.database,
    keyring: config.encryptionKeyring,
    publicBaseUrl: config.publicBaseUrl,
    relayOrigins: config.eventsShimRelayOrigins ?? [new URL(config.relaycastPublicUrl).origin],
    relaycast: { url: config.relaycastUrl, internalSecret: input.relaycastInternalSecret ?? null },
    gateOnly: Boolean(config.relaygatePublicUrl),
    fetchImpl: input.messagingFetch,
    ...(agentLinks ? { agentLinks } : {}),
    now: input.now,
    authorizeCreate: async (request, response) => {
      const auth = await authenticate(request);
      if (auth.kind !== "user") throw new HttpError(401, "unauthorized", "User token required");
      const { principal } = auth;
      if (principal.pendingHandoff) {
        throw new HttpError(403, "handoff_not_exchanged", "Exchange the sign-in handoff first");
      }
      if (!bearer(request) && !cookieRequestAllowed(request, browserOrigins)) {
        throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
      const workspace = await store.workspaceForUser(principal.workspaceId, principal.userId);
      if (!workspace) throw new HttpError(404, "workspace_not_found", "Workspace not found");
      rateLimit(response, `events-shim-create:${principal.userId}`, EVENTS_SHIM_CREATE_RATE,
        "rate_limited", "Too many webhook inboxes created. Try again later.");
      return { workspaceId: workspace.id, userId: principal.userId };
    },
  }) : null;
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
      ? controlSessionToken(request.headers.cookie)
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

  /**
   * /api/v1/me/enrollment-keys: a person's own session with cli:auth or
   * account. A mutating request carried only by the /cloud session cookie
   * must pass the same-origin check, like every other cookie-capable write.
   */
  async function enrollmentKeyOwner(request: IncomingMessage): Promise<Principal> {
    const auth = await authenticate(request);
    if (auth.kind !== "user") throw new HttpError(401, "unauthorized", "User token required");
    const { principal } = auth;
    if (principal.pendingHandoff) {
      throw new HttpError(403, "handoff_not_exchanged", "Exchange the sign-in handoff first");
    }
    if (request.method !== "GET" && !bearer(request) && !cookieRequestAllowed(request, browserOrigins)) {
      throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
    }
    if (!principal.scopes.includes("cli:auth") && !principal.scopes.includes(ACCOUNT_SCOPE)) {
      throw new HttpError(403, "insufficient_scope", "Requires a cli:auth or account session");
    }
    return principal;
  }

  /** POST /api/v1/me/enrollment-keys: self-minted enrollment keys per person per hour. */
  const ENROLLMENT_SELF_MINT_RATE = { limit: 10, windowMs: 3_600_000 };

  const organizationTeams = new OrganizationTeams(store.database);
  const staffReadGrants = new StaffReadGrants(store.database, store.tenancy, () => input.now?.() ?? new Date());
  const STAFF_READ_GRANT_MINT_RATE = { limit: 10, windowMs: 3_600_000 };

  /**
   * /api/v1/workspaces/{id}/staff-read-grants (docs/staff-read-grants.md):
   * the staff rule, presented by a browser account session or an interactive
   * CLI login. Not a Desktop session (including a device code Desktop
   * started), an enrollment-key session, a handoff,
   * a Desktop provider credential or any other credential kind. Every
   * refusal after the CSRF check is the same 404, so the routes are no
   * oracle for staff status or for workspace existence.
   */
  async function staffReadGrantCaller(
    request: IncomingMessage,
    workspaceId: string,
  ): Promise<{ staff: StaffPerson; workspace: { id: string; organizationId: string } }> {
    const notFound = () => new HttpError(404, "not_found", "Route not found");
    if (request.method !== "GET" && !bearer(request) && !cookieRequestAllowed(request, browserOrigins)) {
      throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
    }
    let auth: Auth;
    try {
      auth = await authenticate(request);
    } catch (error) {
      if (error instanceof HttpError) throw notFound();
      throw error;
    }
    if (auth.kind !== "user") throw notFound();
    const { principal } = auth;
    const interactive = principal.scopes.includes(ACCOUNT_SCOPE) || principal.scopes.includes("cli:auth");
    if (
      !interactive || principal.scopes.includes(DESKTOP_WORKSPACES_SCOPE) || principal.scopes.includes("mcp:desktop") ||
      principal.provisionedByTokenId || principal.pendingHandoff || principal.handoff || principal.desktopHostName
    ) {
      throw notFound();
    }
    // Agent Relay Desktop also signs in by device code, naming its host; such
    // a session carries no Desktop marker, so look at the device code itself.
    const desktopDeviceCode = await store.database.query(
      "SELECT 1 FROM device_authorizations WHERE api_token_session_id = $1 AND desktop_host_name IS NOT NULL",
      [principal.sessionId],
    );
    if (desktopDeviceCode.rows.length > 0) throw notFound();
    const staff = await staffReadGrants.staff(principal.userId);
    if (!staff || !isUuid(workspaceId)) throw notFound();
    const workspace = (await store.database.query<{ id: string; organization_id: string }>(
      "SELECT id, organization_id FROM workspaces WHERE id = $1",
      [workspaceId],
    )).rows[0];
    if (!workspace) throw notFound();
    return { staff, workspace: { id: workspace.id, organizationId: workspace.organization_id } };
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

  // Standard installs: the node token proves the node against Relaycast; it
  // is never stored or logged.
  async function proveNodeToken(workspaceKey: string, body: Record<string, unknown>) {
    const nodeToken = typeof body.nodeToken === "string" ? body.nodeToken.trim() : "";
    if (!NODE_TOKEN.test(nodeToken)) {
      throw new HttpError(400, "invalid_request", "Send workspaceId and the node's token (nt_live_... or ar_nd_...).");
    }
    return verifyNodeToken(config.relaycastUrl, workspaceKey, nodeToken);
  }

  // Gate-only installs: the node host never holds its Relaycast node token,
  // so the proof is the node's enrolment through this Control's relay-node
  // broker with a relay-node token minted in this workspace and bound to that
  // name (docs/relay-node-credential.md, "Claiming the node"). Relaycast is
  // not asked. A row whose sealed token no longer opens still proves the
  // enrolment; the socket bridge refuses that node separately.
  async function proveEnrolledNode(
    credentials: RelayNodeCredentials,
    workspaceId: string,
    body: Record<string, unknown>,
  ) {
    if (body.nodeToken !== undefined) {
      throw new HttpError(
        400,
        "invalid_request",
        "This installation runs behind relaygate; send workspaceId and nodeName (the node's enrolled name).",
      );
    }
    const nodeName = body.nodeName;
    if (typeof nodeName !== "string" || !NODE_ID.test(nodeName)) {
      throw new HttpError(400, "invalid_request", "Send workspaceId and nodeName.");
    }
    const enrolled = await credentials.find({ workspaceId, nodeName });
    if (!enrolled) throw new NodeClaimError(403, "That node has not enrolled through this installation.");
    return { id: enrolled.relaycastNodeId, name: enrolled.nodeName };
  }

  const apiTokens = new ApiTokenStore(store.database);
  // Gate-only installs only: relaygate introspects one-time `sh_lt_` launch credentials.
  const relayLaunchCredentialStore = config.relaygatePublicUrl
    ? relayLaunchCredentials(store.database, config.encryptionKeyring) : undefined;
  // Gate-only installs only: relaygate introspects one-time `sh_ht_` hosted participant credentials.
  const relayHostedCredentialStore = config.relaygatePublicUrl ? relayHostedCredentials(store.database) : undefined;
  // Gate-only installs only: Control holds relay nodes' Relaycast node tokens and bridges their sockets.
  const relayNodeCredentialStore = config.relaygatePublicUrl
    ? relayNodeCredentials(store.database, config.encryptionKeyring) : undefined;
  const relayNodeSocket = relayNodeCredentialStore && relayLaunchCredentialStore
    ? createRelayNodeSocketBridge({
      apiTokens,
      nodeCredentials: relayNodeCredentialStore,
      launchCredentials: relayLaunchCredentialStore,
      relaycastUrl: config.relaycastUrl,
      database: store.database,
      rateLimit: (key) => limiter.consume(key, RELAY_NODE_RATE_LIMIT.limit, RELAY_NODE_RATE_LIMIT.windowMs).allowed,
      log: (message, fields) => console.warn(`[selfhost-api] ${message}`, fields),
    })
    : undefined;
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

  // The audit exporter's own session access, asked with its own read token.
  // A credential that cannot hold a person's read token reads nothing (null).
  function readAuditAccessProbe(
    access: Awaited<ReturnType<typeof workspaceAccess>>,
    request: IncomingMessage,
  ): ReadAuditAccessProbe | null {
    if (!access.principal.scopes.includes("rth:read") || access.principal.pendingHandoff || !config.relayhistoryUrl) return null;
    const identity: HistoryIdentity = {
      userId: access.principal.userId,
      organizationId: access.workspace.organizationId,
      workspaceId: access.workspace.id,
      role: access.workspace.role,
      callerToken: access.token,
      readerKind: readerKindOf(request),
    };
    return {
      // Fails closed (confirmsAccessAdministrator): a 200 naming the asked
      // session, or relaygate's session-not-found 404 (it checks administration
      // before existence). Any other answer, including another 404 body, is not
      // an administrator, so a backend without the access routes cannot make
      // every exporter one.
      administrator: async (sessionId) => {
        const reply = await accessViaDashboardReader(config, identity, {
          method: "GET", path: `/v1/sessions/${encodeURIComponent(sessionId)}/access`,
        });
        return reply.kind === "response" && confirmsAccessAdministrator(reply.status, reply.body, sessionId);
      },
      readable: async (sessionId) => {
        const read = await readWorkspaceHistory(config, identity, `/v1/sessions/${encodeURIComponent(sessionId)}/metadata`,
          new URLSearchParams(), { allowNotFound: true });
        return read.status === "ok" && read.body.sessionId === sessionId;
      },
    };
  }

  // Deployment sharing-mode values (docs/capture-policy.md), applied per caller.
  const sharing = sharingDeployment(config);
  const sharingConfigured = sharing.defaultSharingMode !== undefined || sharing.overrideRoles !== undefined;

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
        : feedConfig.signer.kind === "file"
        ? new FileDesktopFeedSigner({ label: feedConfig.signer.label, keyFiles: feedConfig.signer.keyFiles })
        : new MemoryDesktopFeedSigner({ label: feedConfig.signer.label })),
      storage: input.desktopFeed?.storage ?? (feedConfig.storage.kind === "s3"
        ? new S3DesktopFeedStorage({
          bucket: feedConfig.storage.bucket, region: feedConfig.storage.region, prefix: feedConfig.storage.prefix,
        })
        : feedConfig.storage.kind === "gcs"
        ? new GcsDesktopFeedStorage({ bucket: feedConfig.storage.bucket, prefix: feedConfig.storage.prefix })
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
  // allowlist or on. One AWS credential provider serves STS, the journal and
  // (S3-compatible stores) presigned URLs: the AWS chain on AWS, the dedicated
  // issuer user's static keys on an S3-compatible store.
  const uploadConfig = config.historyUpload ?? null;
  const historyUpload = uploadConfig
    ? (() => {
      const hooks = input.historyUpload;
      const credentials = hooks?.credentials
        ?? (uploadConfig.storeCredentials
          ? new StaticAwsCredentialProvider(uploadConfig.storeCredentials)
          : new DefaultAwsCredentialProvider());
      return new HistoryUploadCredentials({
        config: uploadConfig,
        sts: hooks?.sts ?? new AwsStsClient({
          region: uploadConfig.region, credentials, endpoint: hooks?.endpoints?.sts, fetchImpl: hooks?.fetchImpl, now: input.now,
        }),
        journal: hooks?.journal ?? new S3PrivacyJournalReader({
          bucket: uploadConfig.bucket,
          region: uploadConfig.region,
          credentials,
          // The internal endpoint (in-cluster service URL) avoids hairpinning
          // through the public ingress the upload clients use.
          endpoint: hooks?.endpoints?.s3 ?? uploadConfig.internalEndpoint ?? undefined,
          fetchImpl: hooks?.fetchImpl,
          now: input.now,
        }),
        credentials,
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
    const historyOrigin = workspaceHistoryOrigin(workspace, config.sessionReadApi.publicUrl);
    const active = await introspect(config, store, { token, aud: historyOrigin, workspace: workspace.id });
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
      // Same facts as `browser` above: cookie -> browser, bearer -> device
      // (or mcp with the MCP reader's marker; see readerKindOf).
      const session = await requestReadSession(api, {
        userId: principal.userId, orgId: workspace.organizationId, workspaceId: workspace.id, role: workspace.role,
        readerKind: readerKindOf(request, mcpReaderMarker(api.secret)),
      }, parsed.data, { includeRole: config.sessionReadMintIncludeRole });
      const { refreshToken: _refresh, refreshTokenExpiresAt: _expiry, ...accessOnly } = session;
      return browser ? accessOnly : session;
    }
    const active = await assertNativeUploadCaller(request, access);
    const expiresAt = new Date(Math.min(active.exp * 1_000, Date.now() + NATIVE_UPLOAD_SESSION_MAX_MS)).toISOString();
    return {
      baseUrl: workspaceHistoryOrigin(workspace, api.publicUrl),
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
    const token = publicPath === "/cloud" || publicPath.startsWith("/cloud/") ? controlSessionToken(request.headers.cookie) : null;
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
      csrfAllowed: incoming => Boolean(bearer(incoming)) || cookieRequestAllowed(incoming, browserOrigins),
      originAllowed: incoming => Boolean(bearer(incoming)) || cookieDeleteAllowed(incoming, browserOrigins),
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

  async function handle(request: IncomingMessage, response: ServerResponse, url: URL): Promise<void> {
    const method = request.method ?? "GET";
    const publicPath = url.pathname.replace(/\/+$/, "") || "/";
    const path = normalizeRoutePath(publicPath);

    if (method === "GET" && path === "/healthz") {
      json(response, 200, { status: "ok" });
      return;
    }
    // Agent Relay Desktop's Cloud-shaped browser links on a separate dashboard host.
    const dashboardLink = dashboardLinkRedirect({
      method, target: request.url ?? "/", host: request.headers.host,
      // An extra site's links open that site's dashboard, not the primary one.
      publicBaseUrl: config.publicBaseUrl, dashboardUrl: dashboardUrlFor(request),
    });
    if (dashboardLink) {
      response.writeHead(302, { location: dashboardLink, "cache-control": "no-store", "referrer-policy": "no-referrer" });
      response.end();
      return;
    }
    if (method === "GET" && publicPath === "/cloud/api/health") {
      json(response, 200, {
        status: "ok",
        timestamp: new Date().toISOString(),
        version: SELFHOST_API_VERSION,
        imageVersion: config.imageVersion ?? null,
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
        ? { status: "ready", introspection, capabilities: capabilities() }
        : { status: "not_ready", reason: readiness.reason, message: readiness.message, introspection, capabilities: capabilities() });
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
        config, store, request, undefined, admin?.apiTokens, flowRelayfileCredentials, relayLaunchCredentialStore, introspectionHold,
        relayHostedCredentialStore,
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
      ...(relayNodeCredentialStore ? { nodeCredentials: relayNodeCredentialStore } : {}),
    })) {
      return;
    }

    if (await customerSupportNotice(request, response, publicPath, method)) return;
    if (await delegation(request, response, path, publicPath, method)) return;
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
    // Replicas agents: gated before any authentication (off answers 404).
    if (isReplicasPath(path)) {
      if (!replicas) {
        json(response, 404, { error: "Not found" }, true);
        return;
      }
      if (await replicas.handle(request, response, path, method, { workspaceAccess, bearer, json })) return;
    }
    // Events shim: 404 before any authentication while the feature is off.
    if (isEventsShimPath(path)) {
      if (!eventsShim || !(await eventsShim(request, response, path, method))) {
        json(response, 404, { error: "Not found" }, true);
      }
      return;
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
      text(response, 200, page("Sign in to Agent Relay", `<h1>Sign in to Agent Relay</h1>
<p class="muted">Approve this device code from an authenticated Agent Relay client or administrator:</p>
<p><code>${html(started.userCode)}</code></p>
<p class="muted" id="status">Waiting for approval…</p>`, `const status=document.getElementById("status");
const next=${JSON.stringify(next).replaceAll("<", "\\u003c")};
async function poll(){try{const r=await fetch("/login/poll",{method:"POST",credentials:"same-origin",headers:{accept:"application/json"}});
if(r.status===202){const p=await r.json();setTimeout(poll,Math.max(1,Number(p.interval)||5)*1000);return}
if(r.ok){location.replace(next);return}status.textContent="Sign-in failed. Reload to start again."}catch{setTimeout(poll,5000)}}
setTimeout(poll,${Math.max(1, started.intervalSeconds) * 1_000});
`), "text/html");
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

      const sessionToken = publicPath.startsWith("/cloud/") ? controlSessionToken(request.headers.cookie) : null;
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
          // The picker is a GET form, and a sign-in without consent answers it
          // with a redirect to the validated loopback listener, which Chromium
          // checks against form-action too (see the consent page below).
          const pickerLoopback = new URL(login.redirectUri).origin;
          response.writeHead(200, {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
            "referrer-policy": "no-referrer",
            "content-security-policy":
              `default-src 'none'; style-src 'unsafe-inline'; form-action ${[...formActionSources, pickerLoopback].join(" ")}; base-uri 'none'; frame-ancestors 'none'`,
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
          location: handoffCallbackUrl(login, issued, `${apiSiteBaseUrl(request)}/cloud`),
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
        apiUrl: `${apiSiteBaseUrl(request)}/cloud`,
        tokenType: "Bearer",
      }, true);
      return;
    }

    // Whose computer a Relaycast node is (hosted: fleet/nodes/claim). The
    // Desktop claims its own spawn node with its workspace-bound sign-in:
    // with the node token on standard installs, by enrolled node name on
    // gate-only installs (proveNodeToken / proveEnrolledNode).
    if (path === "/api/v1/fleet/nodes/claim" && (method === "POST" || method === "DELETE")) {
      const auth = await authenticate(request);
      if (auth.kind !== "user") throw new HttpError(401, "unauthorized", "User token required");
      // Both methods carry a JSON body, so both get the JSON + origin check.
      if (!bearer(request) && !cookieRequestAllowed(request, browserOrigins)) {
        throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
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
      const proven = relayNodeCredentialStore
        ? await proveEnrolledNode(relayNodeCredentialStore, workspaceId, body)
        : await proveNodeToken(workspace.relaycastApiKey, body);
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
        apiUrl: `${apiSiteBaseUrl(request)}/cloud`,
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
      const verification = `${apiSiteBaseUrl(request)}/cloud/api/v1/auth/device/approve`;
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
        location: deviceApprovalPageUrl(dashboardUrlFor(request), url.searchParams.get("user_code")),
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
        api_url: `${apiSiteBaseUrl(request)}/cloud`,
      }, true);
      return;
    }

    // Desktop enrollment keys (docs/identity.md, "Desktop enrollment keys"):
    // an installer spends a single-use sh_ek_ key once for a device session.
    // Unauthenticated apart from the key; one generic refusal for any key
    // problem, so an anonymous caller learns nothing about a key's state.
    if (method === "POST" && path === "/api/v1/auth/enrollment/token") {
      const ip = clientIp(request);
      rateLimit(
        response,
        `enrollment-token:${limiterKey(ip)}`,
        ENROLLMENT_RATE_LIMITS.exchange,
        "slow_down",
        "Too many enrollment key exchanges",
      );
      const body = await requestObject(request);
      const key = body.enrollment_key;
      if (typeof key !== "string" || !key.startsWith(ENROLLMENT_KEY_PREFIX) || key.length > 256) {
        throw new HttpError(400, "invalid_request", "enrollment_key must be an sh_ek_ enrollment key");
      }
      const rawClientName = stringField(body, "client_name")!;
      const clientName = rawClientName.replace(/[\p{C}]/gu, " ").trim();
      if (!clientName || clientName.length > 120) {
        throw new HttpError(400, "invalid_request", "client_name must be 1-120 characters");
      }
      if (isDeviceReservedClientName(clientName)) {
        throw new HttpError(400, "invalid_request", "client_name is reserved");
      }
      const desktopHostName = sanitizeDesktopHostName(body.desktop_host_name);
      if (desktopHostName === null) {
        throw new HttpError(400, "invalid_request", "desktop_host_name must be 1-80 characters");
      }
      // The Desktop's version, for the audit row only (never trusted for anything else).
      const userAgent = request.headers["user-agent"];
      const clientVersion = typeof userAgent === "string"
        ? /^AgentRelayDesktop\/([0-9A-Za-z.+_-]{1,40})(?:[\s;(]|$)/.exec(userAgent)?.[1] ?? null
        : null;
      const result = await store.exchangeEnrollmentKey({ key, clientName, desktopHostName, clientIp: ip, clientVersion });
      // One line, key id only (never the key; null for an unknown key).
      console.info("[selfhost-api] enrollment key exchange", {
        keyId: result.keyId,
        outcome: result.ok ? "exchanged" : "refused",
      });
      if (!result.ok) {
        json(response, 400, {
          error: "invalid_grant",
          error_description: "Enrollment key is invalid, expired, revoked or already used",
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
        api_url: `${apiSiteBaseUrl(request)}/cloud`,
        // Workspace policy (docs/workspace-policy.md): whether this session is
        // managed (the key carries admin policy consent), the revision to
        // compare a cached policy against, and the document itself so the
        // first launch is right before the first access/me refresh.
        managed: result.managed,
        policy_revision: result.policyRevision,
        // Served to the bound user (SELFHOST_DEFAULT_SHARING_MODE and
        // SELFHOST_SHARING_MODE_OVERRIDE_ROLES); the role is read only when
        // one of them is configured.
        workspace_policy: workspacePolicyForCaller(
          await readWorkspacePolicy(store.database, result.organizationId, {
            workspaceId: result.workspaceId,
            managed: result.managed,
          }),
          sharingConfigured ? await store.memberRole(result.organizationId, result.userId) : null,
          sharing,
        ),
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
        apiUrl: `${apiSiteBaseUrl(request)}/cloud`,
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
        // An admin-provisioned sign-in (desktop enrollment key); else null.
        provisioning: principal.provisionedByTokenId
          ? await apiTokens.enrollmentProvisioning(principal.provisionedByTokenId)
          : null,
      }, true);
      return;
    }

    // The caller's own desktop enrollment keys (docs/identity.md, "Desktop
    // enrollment keys"): list, and revoke one with the sessions it provisioned.
    if (path === "/api/v1/me/enrollment-keys" && method === "GET") {
      const principal = await enrollmentKeyOwner(request);
      json(response, 200, {
        keys: await apiTokens.listForUser({ organizationId: principal.organizationId, userId: principal.userId }),
      }, true);
      return;
    }
    // Member self-mint (docs/identity.md, "Member self-mint"): a single-use
    // key for the caller's own next machine, consent inherited from the key
    // that provisioned this session and never raised.
    if (path === "/api/v1/me/enrollment-keys" && method === "POST") {
      const principal = await enrollmentKeyOwner(request);
      if (config.enrollmentSelfRenewal === false) {
        throw new HttpError(
          403,
          "self_mint_disabled",
          "Enrollment key self-renewal is turned off on this install; ask an admin for a key",
        );
      }
      const body = await requestObject(request);
      const unknown = Object.keys(body).filter((key) => key !== "label" && key !== "expiryDays");
      if (unknown.length > 0) {
        throw new HttpError(
          400,
          "invalid_request",
          `Only label and expiryDays are accepted; refused: ${unknown.sort().join(", ")}`,
        );
      }
      rateLimit(response, `enrollment-self-mint:${principal.userId}`, ENROLLMENT_SELF_MINT_RATE, "rate_limited",
        "Too many enrollment keys minted; try again later");
      const key = await apiTokens.selfMint({
        organizationId: principal.organizationId,
        workspaceId: principal.workspaceId,
        userId: principal.userId,
        email: principal.email,
        provisionedByTokenId: principal.provisionedByTokenId ?? null,
        label: body.label,
        expiryDays: body.expiryDays,
      });
      json(response, 201, key, true);
      return;
    }
    const ownEnrollmentKey = routeMatch(path, /^\/api\/v1\/me\/enrollment-keys\/([^/]+)$/);
    if (ownEnrollmentKey && method === "DELETE") {
      const principal = await enrollmentKeyOwner(request);
      const revoked = await apiTokens.revokeForUser({
        organizationId: principal.organizationId,
        userId: principal.userId,
        tokenId: ownEnrollmentKey[0]!,
      });
      if (!revoked) throw new HttpError(404, "token_not_found", "Enrollment key not found");
      response.writeHead(204, { "cache-control": "no-store" });
      response.end();
      return;
    }

    // Which features and configured operator capabilities this installation serves.
    if (method === "GET" && path === "/api/v1/capabilities") {
      const auth = await authenticate(request);
      if (auth.kind !== "user") throw new HttpError(401, "unauthorized", "User token required");
      json(response, 200, { capabilities: capabilities() }, true);
      return;
    }

    // Desktop downloads from a configured public GitHub releases repo
    // (docs/desktop-feed.md, "GitHub releases source"). Unset: 404 like any
    // unknown path. Any signed-in member, like the downloads card.
    if (path === "/api/v1/desktop/releases" && method === "GET" && desktopReleases) {
      const auth = await authenticate(request);
      if (auth.kind !== "user") throw new HttpError(401, "unauthorized", "User token required");
      json(response, 200, await desktopReleases.latest(), true);
      return;
    }

    // Usage page People drill-down (docs/usage.md, "People"): owner-only, per member.
    // routeMatch would turn an absent optional group into "undefined".
    const peopleRoute = /^\/api\/v1\/organizations\/([^/]+)\/usage\/people(?:\/(audit|[^/]+\/sessions))?$/.exec(path);
    if (peopleRoute && method === "GET") {
      let organizationId: string;
      try {
        organizationId = decodeURIComponent(peopleRoute[1]!);
      } catch {
        throw new HttpError(400, "invalid_request", "Invalid organization id");
      }
      const auth = await organizationAccess(request, organizationId);
      if (auth.kind !== "user" || await store.memberRole(organizationId, auth.principal.userId) !== "owner") {
        throw new HttpError(403, "forbidden", "Organization owner role required");
      }
      requireFeature("usage_people");
      const sub = peopleRoute[2];
      const owner = { userId: auth.principal.userId, token: auth.token, readerKind: readerKindOf(request) };
      const now = input.now?.() ?? new Date();
      if (sub === "audit") {
        if ([...url.searchParams.keys()].length > 0) throw new HttpError(400, "invalid_request", "No parameters are accepted");
        json(response, 200, { events: await peopleAudit(store.database, store, organizationId) }, true);
        return;
      }
      const cursor = url.searchParams.get("cursor") ?? undefined;
      const query = new URL(url);
      query.searchParams.delete("cursor");
      if (sub === undefined && cursor !== undefined) throw new HttpError(400, "invalid_request", "cursor is not accepted here");
      if (url.searchParams.getAll("cursor").length > 1) throw new HttpError(400, "invalid_request", "cursor must be given once");
      let days: number;
      try {
        days = usageDays(query);
      } catch (error) {
        if (error instanceof UsageRangeError) throw new HttpError(400, "invalid_request", error.message);
        throw error;
      }
      if (sub === undefined) {
        json(response, 200, {
          people: await peopleReport({ config, store, people, organizationId, owner, days, now }),
        }, true);
        return;
      }
      let subjectUserId: string;
      try {
        subjectUserId = decodeURIComponent(sub.slice(0, -"/sessions".length));
      } catch {
        throw new HttpError(400, "invalid_request", "Invalid user id");
      }
      try {
        const result = await personSessions({
          config, store, organizationId, owner, subjectUserId, days, cursor, now,
        });
        // Every page is audited, whatever the cursor says, before the member's
        // sessions leave Control.
        await recordPeopleView(store.database, {
          organizationId, viewerUserId: owner.userId, subjectUserId, days, page: cursor === undefined ? "first" : "next",
        });
        json(response, 200, result, true);
      } catch (error) {
        if (error instanceof PersonNotFoundError) throw new HttpError(404, "user_not_found", "Not a member of this organization");
        if (error instanceof PeopleInputError) throw new HttpError(400, "invalid_request", error.message);
        throw error;
      }
      return;
    }

    // Fleet view (docs/fleet.md): owners and admins, members with their
    // Desktop machines, policy state and (with usage_people) usage.
    const fleetRoute = /^\/api\/v1\/organizations\/([^/]+)\/fleet$/.exec(path);
    if (fleetRoute && method === "GET") {
      let organizationId: string;
      try {
        organizationId = decodeURIComponent(fleetRoute[1]!);
      } catch {
        throw new HttpError(400, "invalid_request", "Invalid organization id");
      }
      const auth = await organizationAccess(request, organizationId);
      const role = auth.kind === "user" ? await store.memberRole(organizationId, auth.principal.userId) : null;
      if (auth.kind !== "user" || (role !== "owner" && role !== "admin")) {
        throw new HttpError(403, "forbidden", "Organization owner or admin role required");
      }
      for (const name of new Set(url.searchParams.keys())) {
        if (name !== "days" && name !== "cursor") throw new HttpError(400, "invalid_request", `Unknown parameter ${name}`);
      }
      if (url.searchParams.getAll("cursor").length > 1) throw new HttpError(400, "invalid_request", "cursor must be given once");
      const rawCursor = url.searchParams.get("cursor");
      let after: FleetCursor | null = null;
      if (rawCursor !== null) {
        try {
          after = decodeFleetCursor(rawCursor);
        } catch (error) {
          if (error instanceof FleetInputError) throw new HttpError(400, "invalid_request", error.message);
          throw error;
        }
      }
      const query = new URL(url);
      query.searchParams.delete("cursor");
      let days: number;
      try {
        days = usageDays(query);
      } catch (error) {
        if (error instanceof UsageRangeError) throw new HttpError(400, "invalid_request", error.message);
        throw error;
      }
      const now = input.now?.() ?? new Date();
      const dates = usageDates(days, now);
      let usage: FleetUsageInput = null;
      if (features.usage_people) {
        // peopleReport reads with the caller's own authority: it resolves the
        // caller's membership per workspace and has no owner check of its own.
        const report = await peopleReport({
          config, store, people, organizationId, days, now,
          owner: { userId: auth.principal.userId, token: auth.token, readerKind: readerKindOf(request) },
        });
        usage = {
          byUser: new Map(report.members.map((member) => [member.userId, {
            sessionsUploaded: member.sessionsUploaded,
            lastSessionAt: member.lastSessionAt,
            topProjects: member.topProjects,
          }])),
          unavailable: report.unavailable,
          truncated: report.truncated,
        };
      }
      const view = await fleetView({
        executor: store.database,
        organizationId,
        policy: await readWorkspacePolicy(store.database, organizationId),
        days,
        range: { from: dates[0]!, to: dates[dates.length - 1]! },
        after,
        usage,
        now,
      });
      await recordAudit(store.database, {
        organizationId,
        actor: { kind: "user", userId: auth.principal.userId },
        action: FLEET_AUDIT_ACTION,
        target: organizationId,
      });
      json(response, 200, view, true);
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
          owner: { userId: auth.principal.userId, token: auth.token, readerKind: readerKindOf(request) },
          days,
          now: input.now?.() ?? new Date(),
        }),
      }, true);
      return;
    }

    // Staff read grants (docs/staff-read-grants.md): list, mint, revoke.
    const staffGrantsRoute = routeMatch(path, /^\/api\/v1\/workspaces\/([^/]+)\/staff-read-grants$/);
    if (staffGrantsRoute && (method === "GET" || method === "POST")) {
      const { staff, workspace } = await staffReadGrantCaller(request, staffGrantsRoute[0]!);
      if (method === "GET") {
        const grants = await staffReadGrants.list(workspace.id);
        json(response, 200, { workspace_id: workspace.id, grants: grants.map(grantJson) }, true);
        return;
      }
      let parsed;
      try {
        parsed = parseMintRequest(await requestObject(request));
      } catch (error) {
        if (error instanceof StaffReadGrantError) throw new HttpError(error.status, error.code, error.message);
        throw error;
      }
      rateLimit(response, `staff-read-grant-mint:${staff.userId}`, STAFF_READ_GRANT_MINT_RATE, "rate_limited",
        "Too many staff read grants minted; try again later");
      const minted = await staffReadGrants.mint({
        workspaceId: workspace.id,
        organizationId: workspace.organizationId,
        staff,
        reason: parsed.reason,
        expiresInDays: parsed.expiresInDays,
      });
      json(response, 201, {
        grant: grantJson(minted.grant),
        token: { accessToken: minted.accessToken, workspaceId: workspace.id, expiresAt: minted.grant.expiresAt },
      }, true);
      return;
    }
    const staffGrantRoute = routeMatch(path, /^\/api\/v1\/workspaces\/([^/]+)\/staff-read-grants\/([^/]+)$/);
    if (staffGrantRoute && method === "DELETE") {
      const { staff, workspace } = await staffReadGrantCaller(request, staffGrantRoute[0]!);
      const grantId = staffGrantRoute[1]!;
      const grant = isUuid(grantId) ? await staffReadGrants.revoke(workspace.id, grantId, staff.userId) : null;
      if (!grant) throw new HttpError(404, "not_found", "Route not found");
      json(response, 200, { grant: grantJson(grant) }, true);
      return;
    }

    // Shared-session read audit export (docs/shared-session-read-audit.md):
    // workspace owner/admin only, oldest first, keyset-paginated, JSON or CSV.
    const readAuditRoute = routeMatch(path, /^\/api\/v1\/workspaces\/([^/]+)\/shared-session-read-audit$/);
    if (readAuditRoute && method === "GET") {
      const access = await workspaceAccess(request, readAuditRoute[0]!, true);
      let query;
      try {
        query = parseReadAuditQuery(url);
      } catch (error) {
        if (error instanceof ReadAuditQueryError) throw new HttpError(400, "invalid_request", error.message);
        throw error;
      }
      const page = await listReadAudit(store.database, access.workspace.id, query);
      // With per-session access, a non-administrator exporter sees only the
      // session ids it may itself read (docs/shared-session-read-audit.md).
      const shown = config.sessionReadApi?.mintReaderKind
        ? await restrictReadAudit(page.records, readAuditAccessProbe(access, request))
        : { restricted: false as const, records: page.records };
      if (query.format === "csv") {
        response.writeHead(200, {
          "content-type": "text/csv; charset=utf-8",
          "cache-control": "no-store",
          "content-disposition": `attachment; filename="shared-session-read-audit-${access.workspace.id}.csv"`,
          ...(page.nextCursor ? { "x-next-cursor": page.nextCursor } : {}),
        });
        response.end(readAuditCsv(shown.records, { restricted: shown.restricted }));
        return;
      }
      json(response, 200, { workspace_id: access.workspace.id, records: shown.records, next_cursor: page.nextCursor }, true);
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
        if (!bearer(request) && !cookieRequestAllowed(request, browserOrigins)) {
          throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
        }
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
      if (!bearer(request) && !cookieRequestAllowed(request, browserOrigins)) {
        throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
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
          queueFlowsDelete: Boolean(config.flowsWorkspaceDelete),
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
        // teamId is shown only to the operator bearer and live owners and
        // admins, the callers the team routes admit (docs/teams.md).
        const teams = features.teams && (auth.kind === "bootstrap" ||
          ["owner", "admin"].includes(await store.memberRole(organizationId, auth.principal.userId) ?? ""));
        json(response, 200, { memberships: await store.listMemberships(organizationId, { teams }) });
        return;
      }
      if (method === "POST") {
        if (!bearer(request) && !cookieRequestAllowed(request, browserOrigins)) {
          throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
        }
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
      if (!bearer(request) && !cookieDeleteAllowed(request, browserOrigins)) {
        throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
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
          await purgeMemberReplicas(tx, { organizationId, userId });
          await factory.purgeMemberInTx(tx, organizationId, userId);
          await revokeOrganizationMcpOAuthGrants(tx, member, input.now?.() ?? new Date());
          // The member's desktop enrollment keys, exchanged ones included,
          // are revoked with the membership together with the sessions they
          // provisioned (one api_token.revoke audit row per key).
          await apiTokens.revokeEnrollmentKeysForMemberIn(tx, {
            organizationId,
            userId,
            actor: auth.kind === "user" ? { kind: "user", userId: auth.principal.userId } : { kind: "bootstrap" },
          });
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
      if (replicas) await releaseMemberReplicas(replicas.deps, { organizationId, userId }).catch(() => undefined);
      await factory.afterMemberRemoved(organizationId, userId);
      oauthTeardown?.kick();
      response.writeHead(204);
      response.end();
      return;
    }

    // Organization teams (docs/teams.md): owners and admins, behind the teams feature.
    const teamCollection = routeMatch(path, /^\/api\/v1\/organizations\/([^/]+)\/teams$/);
    const teamItem = routeMatch(path, /^\/api\/v1\/organizations\/([^/]+)\/teams\/([^/]+)$/);
    const teamMember = routeMatch(path, /^\/api\/v1\/organizations\/([^/]+)\/teams\/([^/]+)\/members\/([^/]+)$/);
    const teamRoute = teamCollection && (method === "GET" || method === "POST") ? teamCollection
      : teamItem && (method === "PATCH" || method === "DELETE") ? teamItem
      : teamMember && (method === "PUT" || method === "DELETE") ? teamMember
      : undefined;
    if (teamRoute) {
      const organizationId = teamRoute[0]!;
      const auth = await organizationAccess(request, organizationId, true);
      requireFeature("teams");
      // Cookie writes: JSON from an allowed origin; a bodiless PUT or DELETE
      // needs an allowed Origin (or same-origin fetch metadata).
      if (method !== "GET" && !bearer(request)) {
        const allowed = method === "POST" || method === "PATCH"
          ? cookieRequestAllowed(request, browserOrigins)
          : cookieDeleteAllowed(request, browserOrigins);
        if (!allowed) throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
      const actor = auth.kind === "user"
        ? { kind: "user" as const, userId: auth.principal.userId }
        : { kind: "bootstrap" as const };
      if (teamCollection && method === "GET") {
        const archived = url.searchParams.getAll("archived");
        if (archived.length > 1 || (archived.length === 1 && archived[0] !== "true")) {
          throw new HttpError(400, "invalid_request", "archived must be true when present");
        }
        json(response, 200, { teams: await organizationTeams.list(organizationId, archived.length === 1) }, true);
        return;
      }
      if (teamCollection) {
        const body = await requestObject(request);
        json(response, 201, await organizationTeams.create({ organizationId, name: teamName(body.name), actor }), true);
        return;
      }
      if (teamItem && method === "PATCH") {
        const body = await requestObject(request);
        json(response, 200, await organizationTeams.rename({
          organizationId, teamId: teamItem[1]!, name: teamName(body.name), actor,
        }), true);
        return;
      }
      if (teamItem) {
        json(response, 200, await organizationTeams.archive({ organizationId, teamId: teamItem[1]!, actor }), true);
        return;
      }
      const [, teamId, userId] = teamMember as [string, string, string];
      if (method === "PUT") {
        json(response, 200, await organizationTeams.assign({ organizationId, teamId, userId, actor }), true);
        return;
      }
      json(response, 200, { unassigned: await organizationTeams.unassign({ organizationId, teamId, userId, actor }) }, true);
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

    // Workspace leaders (docs/workspace-leaders.md): stored by the Relaycast
    // engine; Control proxies with the workspace key and stores nothing.
    // Any member reads, workspace owner/admin writes.
    const workspaceLeaders = routeMatch(path, /^\/api\/v1\/workspaces\/([^/]+)\/leaders$/);
    if (workspaceLeaders && (method === "GET" || method === "PUT")) {
      const { principal, workspace } = await workspaceAccess(request, workspaceLeaders[0]!, method === "PUT");
      if (principal.pendingHandoff) {
        throw new HttpError(403, "handoff_not_exchanged", "Exchange the sign-in handoff first");
      }
      if (method === "PUT" && !bearer(request) && !cookieRequestAllowed(request, browserOrigins)) {
        throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
      let patterns: string[] = [];
      if (method === "PUT") {
        try {
          patterns = parseLeaderPatterns(await requestObject(request));
        } catch (error) {
          if (error instanceof LeaderPatternsError) throw new HttpError(error.status, error.code, error.message);
          throw error;
        }
      }
      // Each call spends the workspace's server-side Relaycast key.
      rateLimit(response, `workspace-leaders:${principal.userId}`, AGENT_NAMES_RATE, "rate_limited", "Too many requests. Try again shortly.");
      const relaycast = createRelaycastClient({ internalOrigin: config.relaycastUrl, fetchImpl: input.messagingFetch });
      let leaders: WorkspaceLeaders;
      try {
        leaders = method === "PUT"
          ? await relaycast.setWorkspaceLeaders(workspace.relaycastApiKey, patterns)
          : await relaycast.getWorkspaceLeaders(workspace.relaycastApiKey);
      } catch (error) {
        if (error instanceof RelaycastCallError && error.status === 400) {
          throw new HttpError(400, "invalid_request", "The Relaycast engine refused the leader patterns");
        }
        throw new HttpError(502, "workspace_leaders_unavailable", "The workspace leaders setting is unavailable");
      }
      if (method === "PUT") {
        // Agent-name patterns are not secret; the engine's normalised list is recorded.
        await recordAudit(store.database, {
          organizationId: workspace.organizationId,
          workspaceId: workspace.id,
          actor: { kind: "user", userId: principal.userId },
          action: "workspace_leaders.set",
          target: `${workspace.id} patterns=${leaders.patterns.length} ${JSON.stringify(leaders.patterns)}`,
        });
      }
      json(response, 200, {
        leaders: leaders.leaders.map((leader) => ({ name: leader.name, agent_id: leader.agentId })),
        patterns: leaders.patterns,
      }, true);
      return;
    }

    // Capture policy (docs/capture-policy.md) and workspace policy
    // (docs/workspace-policy.md): any member reads both through access/me;
    // organization owner/admin writes them.
    const accessMe = routeMatch(path, /^\/api\/v1\/workspaces\/([^/]+)\/access\/me$/);
    if (accessMe && method === "GET") {
      const { principal, workspace } = await workspaceAccess(request, accessMe[0]!);
      // Fleet rollout C1: a device-client session records the Desktop version,
      // platform and applied policy revision it presents here. Never fails the read.
      if (recordsClientTelemetry(principal)) {
        try {
          await recordClientTelemetry(store.database, principal.sessionId, parseClientTelemetry(request.headers));
        } catch (error) {
          console.warn("[selfhost-api] client telemetry write failed", {
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }
      // Managed: the session was provisioned by an enrollment key carrying admin policy consent.
      const managed = principal.provisionedByTokenId
        ? await sessionManagedByEnrollmentKey(store.database, principal.provisionedByTokenId)
        : false;
      json(response, 200, {
        workspace: { id: workspace.id, name: workspace.name },
        role: workspace.role,
        // Served per caller (docs/capture-policy.md, "Deployment default and
        // override roles"); the organization routes below serve what is stored.
        policy: capturePolicyForCaller(
          await readCapturePolicy(store.database, workspace.organizationId),
          workspace.role,
          sharing,
        ),
        workspace_policy: workspacePolicyForCaller(
          await readWorkspacePolicy(store.database, workspace.organizationId, {
            workspaceId: workspace.id,
            managed,
          }),
          workspace.role,
          sharing,
        ),
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

    // Agent rules (docs/agent-rules.md). Any signed-in member reads the
    // composed rules for their organization; owners and admins write overlays.
    const rulesRead = routeMatch(path, /^\/api\/v1\/agent-rules\/([^/]+)$/);
    if (rulesRead && method === "GET") {
      const audience = rulesRead[0]!;
      if (!isAgentRulesAudience(audience)) throw new HttpError(404, "not_found", "Unknown audience");
      const auth = await authenticate(request);
      if (auth.kind !== "user") throw new HttpError(401, "unauthorized", "User token required");
      const { principal } = auth;
      if (principal.pendingHandoff) throw new HttpError(403, "handoff_not_exchanged", "Exchange the sign-in handoff first");
      if (!principal.scopes.includes("cli:auth") && !principal.scopes.includes(ACCOUNT_SCOPE)) {
        throw new HttpError(403, "insufficient_scope", "Requires a cli:auth or account session");
      }
      if (!await store.memberRole(principal.organizationId, principal.userId)) throw new HttpError(404, "not_found", "Organization not found");
      const composed = await agentRules.compose(principal.organizationId, audience);
      const etag = `"${composed.sha256}"`;
      response.setHeader("etag", etag);
      response.setHeader("cache-control", "private, no-cache");
      if (request.headers["if-none-match"] === etag) {
        response.statusCode = 304;
        response.end();
        return;
      }
      if (/\btext\/markdown\b/.test(String(request.headers.accept ?? ""))) {
        response.setHeader("content-type", "text/markdown; charset=utf-8");
        response.end(composed.text);
        return;
      }
      json(response, 200, { audience: composed.audience, version: composed.version, sha256: composed.sha256,
        bootstrap_version_current: composed.bootstrapVersion, sections: composed.sections, text: composed.text }, true);
      return;
    }
    const rulesOverlay = routeMatch(path, /^\/api\/v1\/organizations\/([^/]+)\/agent-rules\/([^/]+)$/);
    if (rulesOverlay && (method === "GET" || method === "PUT")) {
      const [organizationId, audience] = rulesOverlay as [string, string];
      if (!isAgentRulesAudience(audience)) throw new HttpError(404, "not_found", "Unknown audience");
      const auth = await organizationAccess(request, organizationId, true);
      if (method === "GET") {
        const overlay = await agentRules.overlays.read(organizationId, audience);
        json(response, 200, { audience, overlay, base_version: agentRules.bundle.version }, true);
        return;
      }
      if (!bearer(request) && !cookieRequestAllowed(request, browserOrigins)) {
        throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
      const body = await requestObject(request);
      if (typeof body.text !== "string") throw new HttpError(400, "invalid_request", "text must be a string; an empty string clears the overlay");
      try {
        const written = await agentRules.overlays.write({ organizationId, audience, text: body.text,
          actor: auth.kind === "user" ? { kind: "user", userId: auth.principal.userId } : { kind: "bootstrap" } });
        json(response, 200, { audience, ...written, version_string: written.cleared ? agentRules.bundle.version : `${agentRules.bundle.version}+org.${written.version}` }, true);
      } catch (error) {
        if (error instanceof AgentRulesInputError) throw new HttpError(400, "invalid_request", error.message);
        throw error;
      }
      return;
    }

    const workspacePolicy = routeMatch(path, /^\/api\/v1\/organizations\/([^/]+)\/workspace-policy$/);
    if (workspacePolicy && (method === "GET" || method === "PUT" || method === "DELETE")) {
      const organizationId = workspacePolicy[0]!;
      const auth = await organizationAccess(request, organizationId, true);
      if (method === "GET") {
        // No workspace here, so admin_senders is never resolved.
        json(response, 200, await readWorkspacePolicy(store.database, organizationId), true);
        return;
      }
      if (!operatorControlsEntitled()) {
        throw new HttpError(403, "operator_controls_not_entitled", "Operator controls are not enabled for this installation");
      }
      // Cookie writes: same rules as the capture policy route.
      if (!bearer(request)) {
        const allowed = method === "DELETE"
          ? cookieDeleteAllowed(request, browserOrigins)
          : cookieRequestAllowed(request, browserOrigins);
        if (!allowed) throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
      const expectedRevision = parseIfMatch(request.headers["if-match"]);
      const input = method === "PUT"
        ? parseWorkspacePolicyInput(await requestObject(request))
        : { sections: UNSET_WORKSPACE_POLICY.sections, consent: [] };
      const policy = await writeWorkspacePolicy(store.database, {
        organizationId,
        sections: input.sections,
        consent: input.consent,
        expectedRevision,
        actor: auth.kind === "user" ? { kind: "user", userId: auth.principal.userId } : { kind: "bootstrap" },
        action: method === "PUT" ? "workspace_policy.set" : "workspace_policy.cleared",
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
      const identity = {
        workspaceId: workspace.id,
        cloudWorkspaceId: workspace.id,
        cloudRelayWorkspaceId: workspace.cloudRelayWorkspaceId,
        relaycastWorkspaceId: workspace.relaycastWorkspaceId,
        organizationId: workspace.organizationId,
        name: workspace.name,
      };
      // Gate-only install (SELFHOST_RELAYGATE_PUBLIC_URL): relaygate is the
      // only public way into Relaycast, so the workspace-wide key, which
      // would bypass its policy, never leaves. The device enrols at the gate
      // with its Control token instead. Clients that require the key fail
      // closed on its absence. The resolve is still audited, as withheld.
      if (config.relaygatePublicUrl) {
        await recordAudit(store.database, {
          organizationId: workspace.organizationId,
          workspaceId: workspace.id,
          actor: { kind: "user", userId: principal.userId },
          action: "workspace.relaycast_key.withheld",
          target: `session:${principal.sessionId}`,
        });
        json(response, 200, {
          ...identity,
          urls: { relaycastUrl: config.relaycastPublicUrl, relaygateUrl: config.relaygatePublicUrl },
          provisioned: workspace.relaycastProvisioned,
        }, true);
        return;
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
        ...identity,
        relaycastApiKey: workspace.relaycastApiKey,
        urls: { relaycastUrl: config.relaycastPublicUrl },
        provisioned: workspace.relaycastProvisioned,
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
        if (!bearer(request) && !cookieRequestAllowed(request, browserOrigins)) {
          throw new HttpError(403, "csrf_rejected", "Cross-origin request refused");
        }
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
      onSearch: (organizationId, userId) => {
        recordUsage(() => usage.increment(organizationId, "searches"));
        recordPeople(() => people.recordSearch(organizationId, userId));
      },
      readBody: () => requestObject(request),
      originAllowed: () => cookieRequestAllowed(request, browserOrigins),
      hasBearer: () => Boolean(bearer(request)),
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
      // Cookie -> browser, bearer -> device, bearer plus the MCP reader's
      // marker (src/mcp/session-read-reader.ts) -> mcp. The marker is never
      // logged or echoed.
      const session = await requestReadSession(config.sessionReadApi, {
        userId: principal.userId, orgId: workspace.organizationId, workspaceId: workspace.id, role: workspace.role,
        readerKind: readerKindOf(request, mcpReaderMarker(config.sessionReadApi.secret)),
      }, parsed.data, { includeRole: config.sessionReadMintIncludeRole });
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
      // An allowlisted imported customer-hosted origin wins for this
      // workspace. NULL uses the installation default. Both are exact
      // introspection audiences.
      const importedOrigin = workspace.relayhistoryOrigin;
      if (!importedOrigin && (!config.relayhistoryUrl || !config.relayhistoryPublicUrl)) {
        throw new HttpError(404, "relayhistory_not_configured", "RelayHistory is not configured");
      }
      const origin = workspaceHistoryOrigin(workspace, config.relayhistoryPublicUrl);
      json(response, 200, {
        workspace: workspace.id,
        origin,
        audience: origin,
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
      // Capture policy revision (docs/capture-policy.md): Desktop names the policy it applies. Report mode logs a
      // missing or older one; enforce refuses it so Desktop reads the policy again (its POST fallback is checked
      // the same way by the sessions pipeline).
      // Checked against the policy as served to this caller (its access/me).
      const capturePolicy = capturePolicyForCaller(
        await readCapturePolicy(store.database, workspace.organizationId),
        workspace.role,
        sharing,
      );
      const verdict = uploadPolicyVerdict(capturePolicy, request.headers[CAPTURE_POLICY_REVISION_HEADER]);
      if (verdict === "missing" || verdict === "stale") {
        const mode = config.capturePolicyUploads ?? "report";
        console.warn("[selfhost-api] capture policy upload check", {
          metric: "capture_policy_upload_violation",
          outcome: verdict,
          mode,
          organization: workspace.organizationId,
          workspace: workspace.id,
          revision: capturePolicy.revision,
        });
        if (mode === "enforce") {
          throw new HttpError(409, "capture_policy_stale",
            `Uploads need capture policy revision ${capturePolicy.revision}; read the policy again and retry`);
        }
      }
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
      relaygatePublicUrl: config.relaygatePublicUrl,
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
      cookieOriginAllowed: incoming => cookieDeleteAllowed(incoming, browserOrigins),
      agentRoster: agentIdentityRoster,
      rateLimit: (res, key, rule) =>
        rateLimit(res, key, rule, "rate_limited", "Too many requests. Try again later."),
    })) {
      return;
    }

    if (telemetry && await telemetry.handle(request, response, path, url, {
      organizationAccess,
      requestObject,
      bearer,
      cookieOriginAllowed: incoming => cookieDeleteAllowed(incoming, browserOrigins),
    })) {
      return;
    }

    throw new HttpError(404, "not_found", "Route not found");
  }

  const handler = (request: IncomingMessage, response: ServerResponse): void => {
    const target = request.url ?? "/";
    const url = /^[\\/]{2}/.test(target) ? null : URL.parse(target, config.publicBaseUrl);
    if (!url) {
      json(response, 400, { error: "invalid_request", message: "Invalid request target" }, true);
      return;
    }
    // telemetry lane: aggregate usage per feature area (no bodies or queries).
    if (telemetry) {
      response.once("finish", () => telemetry.observeRequest({
        method: request.method ?? "GET",
        path: url.pathname,
        status: response.statusCode,
      }));
    }
    void handle(request, response, url).catch((error: unknown) => {
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
      if (error instanceof TeamsError) {
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
        if (adminError.retryAfterSeconds !== undefined) response.setHeader("retry-after", String(adminError.retryAfterSeconds));
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
          path: url.pathname,
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
      if (error instanceof RelaycastBindingUnavailableError) {
        response.setHeader("retry-after", String(error.retryAfterSeconds));
        json(response, error.status, { error: error.code, message: error.message }, true);
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
        path: url.pathname,
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
  return Object.assign(handler, {
    handleUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer): void {
      if (relayNodeSocket) relayNodeSocket.handleUpgrade(request, socket, head);
      else refuseUpgrade(socket, 404);
    },
    closeUpgrades(): void {
      relayNodeSocket?.close();
    },
  });
}
