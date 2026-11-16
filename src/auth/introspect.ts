import { createHash, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { ApiTokenStore } from "../admin/api-tokens.js";
import type { SelfhostConfig } from "../config.js";
import { canonicalRelayhistoryOrigin } from "../relayhistory-origin.js";
import type { CapturePolicy } from "../capture-policy.js";
import { hashSecret } from "../crypto.js";
import { databaseErrorCause, isDatabaseUnavailable } from "../database.js";
import type { FlowRunRelayfileCredentials } from "../flows/relayfile-credentials.js";
import {
  RELAY_LAUNCH_CREDENTIAL_PREFIX, RELAY_LAUNCH_SCOPE, type RelayLaunchCredentials,
} from "../mcp/relay-launch-credentials.js";
import { NODE_ID_PATTERN, type ControlPlaneStore, type IntrospectedToken, type Principal } from "../store.js";
import type { HeldAudienceVerdict, IntrospectionHold } from "./introspection-hold.js";

/**
 * POST /internal/v1/auth/introspect: the sessions pipeline (and relayfile)
 * verify a relaycontrol user access token (`sh_at_`) presented to them.
 * Contract: internal design note a-no-relayauth-contract (v1, the
 * v1.1 addendum: machine verification, 2026-11-07, v1.2: optional
 * workspace, 2026-11-07, and v1.4: Flows run credentials, 2026-11-09).
 *
 * - Request `{token, aud, workspace?, machine?}`. `workspace` may be absent
 *   or null (the Desktop-upload edge has only the bearer): a token session is
 *   bound to exactly one workspace, so the response `workspace` is then
 *   authoritative and no `workspace` reason can occur. When supplied it must
 *   be a non-empty string (trimmed) equal to the session's workspace, else
 *   inactive with `workspace`. `machine` is the caller's
 *   claimed machine id (a Relaycast node id, NODE_ID_PATTERN); it is only a
 *   claim. Once every token check passes it must be a node the token's user
 *   claimed in the token session's workspace (fleet_node_owners,
 *   whether or not `workspace` was supplied), else
 *   inactive with `machine_not_owned` (another user's claim in this
 *   workspace), `machine_workspace_mismatch` (no claim in this workspace,
 *   but one in another) or `machine_unclaimed` (no claim anywhere).
 * - `machine_id` is the verified machine, or null when `machine` was absent
 *   (a read-only principal). History takes the machine id only from this
 *   response, never from its own caller.
 * - Authenticated by RELAYCONTROL_INTROSPECT_SECRET only; unset = 404.
 * - 200 for every well-formed authenticated request; inactive answers carry
 *   only `{active:false, reason}`.
 * - Relayfile agent tokens (v1.3): a workspace API token (`sh_wk_`) is
 *   accepted only when its purpose is `relayfile-agent`; one with no such
 *   record is `unknown`, every other `sh_wk_` (other purpose, revoked or not)
 *   is `wrong-kind`. Then `revoked`,
 *   `expired`, `audience` (the request aud must normalize to the token's
 *   stored aud, which must still be an accepted audience) and `workspace` as
 *   for users. An agent has no machine: any `machine` is `machine_not_owned`.
 *   Active answers have principal_type `agent`, sub = token_id = the token id,
 *   email and machine_id null, iat = minted, exp = the token's expiry or,
 *   when it has none, now + AGENT_TOKEN_EXP_WINDOW_SECONDS recomputed on
 *   every call (callers must re-introspect at least that often).
 * - Acquisition operator tokens: a `sh_wk_` of purpose `acquisition-operator`
 *   passes the same checks (`revoked`, `expired`, `audience`, `workspace`;
 *   any `machine` is `machine_not_owned`) and answers like an agent token
 *   except principal_type `service`, agent_name null and scopes
 *   `["acquisition:operate"]`. Minted only by a workspace owner/admin through
 *   the deployment-api-tokens routes, or by a Factory connect when
 *   SELFHOST_ACQUISITION_ORIGIN is set (docs/factory-sessions.md).
 * - Flows run Relayfile credentials (v1.4, docs/flows-relayfile-credential.md):
 *   an `sh_fr_` token minted by the Flows credential broker for one run.
 *   Inactive reasons `unknown`, `revoked`, `expired`, `audience`, `workspace`
 *   and, for any `machine`, `machine_not_owned`, checked like an agent token.
 *   Active answers have principal_type `agent`, agent_name
 *   `flows-run-<runId>`, sub = token_id = the credential id, the stored
 *   path scopes, iat = minted and exp = the credential's expiry.
 * - Relay launch credentials (gate-only installs, SELFHOST_RELAYGATE_PUBLIC_URL;
 *   docs/identity.md): an `sh_lt_` token minted for one agent launch, which
 *   relaygate presents here with its own audience. Inactive reasons
 *   `unknown`, `expired`, `revoked` (already redeemed), `audience`,
 *   `workspace` and, for any `machine`, `machine_not_owned`. Only once every
 *   check passes is the credential burned; the first active answer is the
 *   only one, a lost race answers inactive. Active answers have
 *   principal_type `relay_launch`, sub = the launching user, agent_name and
 *   node_name of the launch, scopes `["relay:agent:enrol"]`, token_id = the
 *   credential id, iat = minted and exp = the credential's expiry. Unset gate
 *   URL: every `sh_lt_` is `unknown`.
 * - User tokens also carry `role`, the live organization role, so optional
 *   add-on services can make the same admin decisions as this service without
 *   reading its database. Each add-on is one more origin in
 *   SELFHOST_INTROSPECT_AUDIENCES; this service never depends on one existing.
 * - User tokens also carry `capture_policy` (v1.5), the organization's served
 *   capture policy `{version, revision, settings}` exactly as
 *   GET .../capture-policy returns it (docs/capture-policy.md), read in the
 *   same query as the token. The sessions pipeline enforces it from here
 *   (e.g. `user_retroactive_delete: false` refuses a member's own session
 *   delete) instead of keeping a copy. A held answer carries the policy as it
 *   was when the held verdict was checked. Agent and service tokens carry none.
 * - No caching here: the token session row is the truth on every call.
 *   The one exception is the opt-in database outage hold
 *   (SELFHOST_INTROSPECT_OUTAGE_HOLD_MS, docs/identity.md): only when the
 *   `sh_at_` lookup fails with a connection-class database error, the last
 *   ACTIVE verdict the database gave for that token and requested audience
 *   within the hold answers instead, marked `held: true` with `exp` clamped
 *   to that audience confirmation's end.
 *   Machine claims are never held.
 * - The token, its hash, the secret and the body are never logged.
 */
export const INTROSPECT_PATH = "/internal/v1/auth/introspect";
export const INTROSPECT_BODY_LIMIT = 16 * 1024;
const USER_ACCESS_TOKEN_PREFIX = "sh_at_";
export const WORKSPACE_API_TOKEN_PREFIX = "sh_wk_";
export const FLOW_RUN_CREDENTIAL_PREFIX = "sh_fr_";
/** `exp` horizon for an agent token without an expiry, from each call. */
export const AGENT_TOKEN_EXP_WINDOW_SECONDS = 3_600;

export type InactiveReason =
  | "expired"
  | "revoked"
  | "unknown"
  | "wrong-kind"
  | "audience"
  | "workspace"
  | "machine_not_owned"
  | "machine_unclaimed"
  | "machine_workspace_mismatch";

export type IntrospectionRequest = { token: string; aud: string; workspace?: string; machine?: string };

export type IntrospectionResult =
  | { active: false; reason: InactiveReason }
  | {
    active: true;
    sub: string;
    email: string;
    principal_type: "desktop-user";
    agent_name: null;
    machine_id: string | null;
    org: string;
    workspace: string;
    cloud_relay_workspace_id: string | null;
    role: Principal["role"];
    scopes: string[];
    aud: string;
    iat: number;
    exp: number;
    token_id: string;
    /** The organization's served capture policy (v1.5). */
    capture_policy: CapturePolicy;
    /** Present (true) only for a database-outage hold answer. */
    held?: true;
  }
  | {
    active: true;
    sub: string;
    email: null;
    principal_type: "agent";
    agent_name: string;
    machine_id: null;
    org: string;
    workspace: string;
    cloud_relay_workspace_id: string | null;
    scopes: string[];
    aud: string;
    iat: number;
    exp: number;
    token_id: string;
  }
  | {
    active: true;
    sub: string;
    email: null;
    principal_type: "service";
    agent_name: null;
    machine_id: null;
    org: string;
    workspace: string;
    cloud_relay_workspace_id: string | null;
    scopes: string[];
    aud: string;
    iat: number;
    exp: number;
    token_id: string;
  }
  | {
    active: true;
    /** The launching user. */
    sub: string;
    email: null;
    principal_type: "relay_launch";
    agent_name: string;
    node_name: string;
    machine_id: null;
    org: string;
    workspace: string;
    /** Always `["relay:agent:enrol"]` (RELAY_LAUNCH_SCOPE). */
    scopes: string[];
    aud: string;
    iat: number;
    exp: number;
    token_id: string;
  };

export type IntrospectionLog = (message: string, fields: Record<string, unknown>) => void;

/** Only the HTTP route passes a hold; every in-process caller stays strict. */
export type IntrospectionOptions = { hold?: IntrospectionHold; log?: IntrospectionLog };

export type IntrospectionOutcome =
  | { status: 200; body: IntrospectionResult }
  | { status: 400 | 401 | 404; error: string; message: string };

function digest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

/** Constant time regardless of the presented value's length. */
function secretMatches(presented: string, expected: string): boolean {
  return timingSafeEqual(digest(presented), digest(expected));
}

function presentedSecret(request: IncomingMessage): string | null {
  const header = request.headers.authorization;
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match?.[1]?.trim() || null;
}

/** scheme://host[:port], lowercase, default port dropped; null if not http(s). */
export function normalizedOrigin(value: string): string | null {
  try {
    const url = new URL(value.trim());
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.username || url.password) return null;
    return url.origin;
  } catch {
    return null;
  }
}

/** Stable for an access token's life; changes on every refresh/rotation. */
export function tokenIdFor(accessTokenHash: string): string {
  return createHash("sha256")
    .update(`selfhost-token-id:${accessTokenHash}`)
    .digest("hex")
    .slice(0, 32);
}

async function boundedBody(request: IncomingMessage): Promise<string | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    // Keep draining so the connection stays usable, but stop buffering.
    if (size > INTROSPECT_BODY_LIMIT) continue;
    chunks.push(buffer);
  }
  return size > INTROSPECT_BODY_LIMIT ? null : Buffer.concat(chunks).toString("utf8");
}

function parseBody(raw: string | null): IntrospectionRequest | null {
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const { token, aud, workspace, machine } = parsed as Record<string, unknown>;
  if (
    typeof token !== "string" || !token ||
    typeof aud !== "string" || !aud.trim()
  ) {
    return null;
  }
  // Absent, undefined or null means "not supplied" (v1.2); otherwise it must
  // be a non-empty string once trimmed.
  const supplied = workspace !== undefined && workspace !== null;
  if (supplied && (typeof workspace !== "string" || !workspace.trim())) return null;
  // Absent (or undefined) means "no machine claimed"; anything else must be a
  // well-formed node id. Not trimmed: the pattern admits no whitespace.
  if (machine !== undefined && (typeof machine !== "string" || !NODE_ID_PATTERN.test(machine))) {
    return null;
  }
  return {
    token,
    aud,
    ...(supplied ? { workspace: (workspace as string).trim() } : {}),
    ...(machine !== undefined ? { machine } : {}),
  };
}

function epochSeconds(value: Date): number {
  return Math.floor(value.getTime() / 1_000);
}

/**
 * The normalized origins introspection compares `aud` against, or [] while the
 * endpoint is disabled (no secret). Shown by GET /readyz.
 */
export function acceptedAudiences(config: SelfhostConfig): string[] {
  if (!config.introspectSecret) return [];
  return [...new Set([
    ...(config.introspectAudiences ?? []),
    ...(config.relayhistoryAudiences ?? [config.relayhistoryPublicUrl]),
  ])]
    .map(normalizedOrigin)
    .filter((origin): origin is string => origin !== null);
}

/** The configured audience value whose normalized origin matches `value`. */
export function matchingIntrospectionAudience(config: SelfhostConfig, value: string): string | undefined {
  const requested = normalizedOrigin(value);
  if (requested === null) return undefined;
  return [
    ...(config.introspectAudiences ?? []),
    ...(config.relayhistoryAudiences ?? [config.relayhistoryPublicUrl]),
  ]
    .find((configured) => normalizedOrigin(configured) === requested);
}

/** A dedicated History audience match, distinct from acquisition/Relayfile. */
export function matchingRelayhistoryAudience(config: SelfhostConfig, value: string): string | undefined {
  const requested = canonicalRelayhistoryOrigin(value);
  if (requested === null) return undefined;
  return (config.relayhistoryAudiences ?? [config.relayhistoryPublicUrl])
    .find((configured) => canonicalRelayhistoryOrigin(configured) === requested);
}

/** relayfile-agent (principal `agent`) and acquisition-operator (`service`) tokens. */
async function introspectWorkspaceApiToken(
  config: SelfhostConfig,
  apiTokens: ApiTokenStore | undefined,
  request: IntrospectionRequest,
): Promise<IntrospectionResult> {
  const token = apiTokens ? await apiTokens.introspect(request.token) : null;
  if (!token) return { active: false, reason: "unknown" };
  if (!token.aud) return { active: false, reason: "wrong-kind" };
  const kind = token.purpose === "relayfile-agent" && token.agentName
    ? "agent"
    : token.purpose === "acquisition-operator"
      ? "service"
      : null;
  if (kind === null) return { active: false, reason: "wrong-kind" };
  if (token.revoked) return { active: false, reason: "revoked" };
  if (token.expired) return { active: false, reason: "expired" };
  if (
    normalizedOrigin(request.aud) !== token.aud ||
    !acceptedAudiences(config).includes(token.aud)
  ) {
    return { active: false, reason: "audience" };
  }
  if (request.workspace !== undefined && token.workspaceId !== request.workspace) {
    return { active: false, reason: "workspace" };
  }
  if (request.machine !== undefined) return { active: false, reason: "machine_not_owned" };
  const principal = kind === "agent"
    ? { principal_type: "agent" as const, agent_name: token.agentName! }
    : { principal_type: "service" as const, agent_name: null };
  return {
    active: true,
    sub: token.tokenId,
    email: null,
    ...principal,
    machine_id: null,
    org: token.organizationId,
    workspace: token.workspaceId,
    cloud_relay_workspace_id: token.cloudRelayWorkspaceId,
    scopes: [...token.scopes],
    aud: token.aud,
    iat: epochSeconds(token.createdAt),
    exp: token.expiresAt
      ? epochSeconds(token.expiresAt)
      : epochSeconds(new Date()) + AGENT_TOKEN_EXP_WINDOW_SECONDS,
    token_id: token.tokenId,
  };
}

/** Flows run Relayfile credentials (`sh_fr_`, principal `agent`). */
async function introspectFlowRunCredential(
  config: SelfhostConfig,
  credentials: FlowRunRelayfileCredentials | undefined,
  request: IntrospectionRequest,
): Promise<IntrospectionResult> {
  const credential = credentials ? await credentials.introspect(request.token) : null;
  if (!credential) return { active: false, reason: "unknown" };
  if (credential.revoked) return { active: false, reason: "revoked" };
  if (credential.expired) return { active: false, reason: "expired" };
  if (
    normalizedOrigin(request.aud) !== credential.aud ||
    !acceptedAudiences(config).includes(credential.aud)
  ) {
    return { active: false, reason: "audience" };
  }
  if (request.workspace !== undefined && credential.workspaceId !== request.workspace) {
    return { active: false, reason: "workspace" };
  }
  if (request.machine !== undefined) return { active: false, reason: "machine_not_owned" };
  return {
    active: true,
    sub: credential.credentialId,
    email: null,
    principal_type: "agent",
    agent_name: `flows-run-${credential.runId}`,
    machine_id: null,
    org: credential.organizationId,
    workspace: credential.workspaceId,
    cloud_relay_workspace_id: credential.cloudRelayWorkspaceId,
    scopes: [...credential.scopes],
    aud: credential.aud,
    iat: epochSeconds(credential.createdAt),
    exp: epochSeconds(credential.expiresAt),
    token_id: credential.credentialId,
  };
}

/** One-time relay launch credentials (`sh_lt_`, principal `relay_launch`); burned on the active answer. */
async function introspectRelayLaunchCredential(
  config: SelfhostConfig,
  credentials: RelayLaunchCredentials | undefined,
  request: IntrospectionRequest,
): Promise<IntrospectionResult> {
  const found = credentials ? await credentials.peek(request.token) : { state: "unknown" as const };
  if (found.state === "unknown") return { active: false, reason: "unknown" };
  if (found.state === "redeemed") return { active: false, reason: "revoked" };
  if (found.state === "expired") return { active: false, reason: "expired" };
  const aud = normalizedOrigin(request.aud);
  if (aud === null || !acceptedAudiences(config).includes(aud)) return { active: false, reason: "audience" };
  if (request.workspace !== undefined && found.credential.workspaceId !== request.workspace) {
    return { active: false, reason: "workspace" };
  }
  if (request.machine !== undefined) return { active: false, reason: "machine_not_owned" };
  // Every check passed: burn it. Only the caller that wins the burn is answered active.
  const redeemed = await credentials!.redeem(request.token);
  if (redeemed.state !== "active") {
    return { active: false, reason: redeemed.state === "expired" ? "expired" : redeemed.state === "unknown" ? "unknown" : "revoked" };
  }
  const credential = redeemed.credential;
  return {
    active: true,
    sub: credential.userId,
    email: null,
    principal_type: "relay_launch",
    agent_name: credential.agentName,
    node_name: credential.nodeName,
    machine_id: null,
    org: credential.organizationId,
    workspace: credential.workspaceId,
    scopes: [RELAY_LAUNCH_SCOPE],
    aud,
    iat: epochSeconds(credential.createdAt),
    exp: epochSeconds(credential.expiresAt),
    token_id: credential.id,
  };
}

export async function introspect(
  config: SelfhostConfig,
  store: ControlPlaneStore,
  request: IntrospectionRequest,
  apiTokens?: ApiTokenStore,
  flowRunCredentials?: FlowRunRelayfileCredentials,
  launchCredentials?: RelayLaunchCredentials,
  options?: IntrospectionOptions,
): Promise<IntrospectionResult> {
  if (request.token.startsWith(WORKSPACE_API_TOKEN_PREFIX)) {
    return introspectWorkspaceApiToken(config, apiTokens, request);
  }
  if (request.token.startsWith(FLOW_RUN_CREDENTIAL_PREFIX)) {
    return introspectFlowRunCredential(config, flowRunCredentials, request);
  }
  if (request.token.startsWith(RELAY_LAUNCH_CREDENTIAL_PREFIX)) {
    return introspectRelayLaunchCredential(config, launchCredentials, request);
  }
  // Refresh, internal, bootstrap, worker, run and enrollment tokens are
  // never looked up as user tokens. That includes sh_ek_ desktop enrollment
  // keys: they are exchanged once at POST /api/v1/auth/enrollment/token and
  // are never a bearer for any other route.
  if (!request.token.startsWith(USER_ACCESS_TOKEN_PREFIX)) {
    return { active: false, reason: "wrong-kind" };
  }
  const accessTokenHash = hashSecret(request.token);
  const hold = options?.hold;
  let session: IntrospectedToken | null;
  let held: { audiences: ReadonlyMap<string, HeldAudienceVerdict>; cause: string } | null = null;
  let outage: unknown;
  try {
    session = await store.introspectAccessToken(request.token);
  } catch (error) {
    if (!hold || !isDatabaseUnavailable(error)) throw error;
    const entry = hold.lookup(accessTokenHash);
    if (!entry) throw error;
    session = entry.session;
    held = {
      audiences: entry.audiences,
      cause: databaseErrorCause(error),
    };
    outage = error;
  }
  if (!session) {
    if (!held) hold?.observe(null, { hash: accessTokenHash });
    return { active: false, reason: "unknown" };
  }
  if (session.revoked) {
    if (!held) hold?.observe(session);
    return { active: false, reason: "revoked" };
  }
  // A held verdict's flag was computed when it was checked: recompute it.
  if (held ? session.expiresAt.getTime() <= Date.now() : session.expired) {
    if (!held) hold?.observe(session);
    return { active: false, reason: "expired" };
  }
  let aud = matchingIntrospectionAudience(config, request.aud);
  const matchedAudience = aud;
  const historyAudience = matchingRelayhistoryAudience(config, request.aud);
  const requestedHistoryOrigin = canonicalRelayhistoryOrigin(request.aud);
  const expectedHistoryOrigin = canonicalRelayhistoryOrigin(
    session.relayhistoryOrigin ?? config.relayhistoryPublicUrl,
  );
  if (historyAudience !== undefined) {
    aud = expectedHistoryOrigin !== null && requestedHistoryOrigin === expectedHistoryOrigin
      ? historyAudience
      : undefined;
  } else if (!held && aud !== undefined && requestedHistoryOrigin !== null) {
    // Legacy configs may still name a customer History origin in the old
    // general list. The unique origin index makes this lookup unambiguous;
    // refuse the general-list match for every workspace, including tenants
    // other than the owner, until the operator moves it to the dedicated list.
    if (await store.workspaceIdForRelayhistoryOrigin(requestedHistoryOrigin) !== null) aud = undefined;
  }
  if (!aud) {
    // A live refusal is authoritative for this token+audience. Do not let an
    // earlier confirmation outlive a newly imported History-origin fence.
    if (!held && matchedAudience) hold?.forgetAudience(accessTokenHash, matchedAudience);
    return { active: false, reason: "audience" };
  }
  // The hold re-serves authoritative token+audience verdicts, not merely a
  // token session. This keeps the DB-backed legacy History-origin fence in
  // force without a second database query during the outage.
  const heldAudience = held?.audiences.get(aud) ?? null;
  if (held && !heldAudience) return { active: false, reason: "audience" };
  if (request.workspace !== undefined && session.workspaceId !== request.workspace) {
    return { active: false, reason: "workspace" };
  }
  // Only now, so an inactive token never reveals anything about a machine.
  let machineId: string | null = null;
  // Machine ownership needs the node-claims query: never answered from a hold.
  if (request.machine !== undefined && held) throw outage;
  if (request.machine !== undefined) {
    const claims = await store.nodeClaimsFor(request.machine);
    const here = claims.find((claim) => claim.workspaceId === session.workspaceId);
    if (!here) {
      return { active: false, reason: claims.length > 0 ? "machine_workspace_mismatch" : "machine_unclaimed" };
    }
    if (here.userId !== session.userId) return { active: false, reason: "machine_not_owned" };
    machineId = request.machine;
  }
  if (!held) hold?.observe(session, { audience: aud });
  const tokenId = tokenIdFor(session.accessTokenHash);
  if (held) {
    options?.log?.("[selfhost-api] token introspection held", {
      token_id: tokenId,
      aud,
      workspace: session.workspaceId,
      age_ms: Math.max(0, Date.now() - heldAudience!.checkedAt),
      cause: held.cause,
    });
  }
  return {
    active: true,
    sub: session.userId,
    email: session.email,
    principal_type: "desktop-user",
    agent_name: null,
    machine_id: machineId,
    org: session.organizationId,
    workspace: session.workspaceId,
    cloud_relay_workspace_id: session.cloudRelayWorkspaceId,
    role: session.role,
    scopes: [...session.scopes],
    aud,
    iat: epochSeconds(session.issuedAt),
    exp: epochSeconds(held ? new Date(heldAudience!.validUntil) : session.expiresAt),
    token_id: tokenId,
    capture_policy: session.capturePolicy,
    ...(held ? { held: true as const } : {}),
  };
}

export async function handleIntrospection(
  config: SelfhostConfig,
  store: ControlPlaneStore,
  request: IncomingMessage,
  log: IntrospectionLog = (message, fields) =>
    console.warn(message, fields),
  apiTokens?: ApiTokenStore,
  flowRunCredentials?: FlowRunRelayfileCredentials,
  launchCredentials?: RelayLaunchCredentials,
  hold?: IntrospectionHold,
): Promise<IntrospectionOutcome> {
  const secret = config.introspectSecret;
  if (!secret) {
    // Feature off: indistinguishable from an unknown route.
    request.resume();
    return { status: 404, error: "not_found", message: "Route not found" };
  }
  const presented = presentedSecret(request);
  if (!presented || !secretMatches(presented, secret)) {
    request.resume();
    log("[selfhost-api] token introspection rejected", {
      reason: presented ? "wrong_secret" : "missing_secret",
    });
    return { status: 401, error: "unauthorized", message: "Authentication required" };
  }
  const body = parseBody(await boundedBody(request));
  if (!body) {
    return {
      status: 400,
      error: "invalid_request",
      message: "Body must be a JSON object with string token and aud, optionally a non-empty string (or null) workspace, and optionally a node-id string machine (at most 16 KiB)",
    };
  }
  return { status: 200, body: await introspect(config, store, body, apiTokens, flowRunCredentials, launchCredentials, { hold, log }) };
}
