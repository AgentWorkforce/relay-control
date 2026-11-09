import { createHash } from "node:crypto";
import type { SelfhostConfig } from "../config.js";
import { issueRelayhistorySession, ReadCursorExpiredError, UpstreamError } from "../relayhistory.js";

/**
 * Workspace-scoped RelayHistory reads for the dashboard sessions views.
 *
 * Isolation rules (mirroring Cloud's `rejectHistoryResponse`):
 * - every read uses a `rth:read` session minted for exactly one
 *   {user, organization, workspace} triple, after the caller has passed the
 *   control plane's membership check;
 * - every upstream query carries `workspace=<authorized workspace>`, which
 *   RelayHistory requires to equal the token's workspace (403 otherwise);
 * - every accepted response must attest the same workspace through
 *   `X-Relayhistory-Workspace-Id`. A missing or different header is treated
 *   as an upstream failure, so an org-wide read can never reach the browser.
 */
export const WORKSPACE_ATTESTATION_HEADER = "x-relayhistory-workspace-id";

export type HistoryIdentity = {
  userId: string;
  organizationId: string;
  workspaceId: string;
  /**
   * The caller's raw relaycontrol access token. Without RelayAuth it is what
   * History exchanges (and introspects); it is a credential and is only ever
   * used as a cache key through its SHA-256.
   */
  callerToken: string;
};

type CachedToken = { accessToken: string; expiresAt: number };

const TOKEN_CACHE_LIMIT = 1_000;
const TOKEN_MAX_AGE_MS = 5 * 60_000;
const TOKEN_EXPIRY_MARGIN_MS = 60_000;
const tokenCaches = new WeakMap<SelfhostConfig, Map<string, CachedToken>>();

function cacheFor(config: SelfhostConfig): Map<string, CachedToken> {
  let cache = tokenCaches.get(config);
  if (!cache) {
    cache = new Map();
    tokenCaches.set(config, cache);
  }
  return cache;
}

function cacheKey(identity: HistoryIdentity): string {
  // Keyed per token session too, so a History token minted for one access
  // token is never reused for another (revoked, rotated, or other session).
  const tokenHash = createHash("sha256").update(identity.callerToken).digest("hex");
  return JSON.stringify([identity.userId, identity.organizationId, identity.workspaceId, tokenHash]);
}

/**
 * A short-lived read token per identity. Membership is re-checked by the
 * caller on every request before this is used, so caching only saves the
 * RelayAuth assertion (or History introspection) and History login round trips (and avoids creating a
 * History auth session per page view).
 */
async function readToken(
  config: SelfhostConfig,
  identity: HistoryIdentity,
  now = Date.now(),
): Promise<string> {
  const cache = cacheFor(config);
  const key = cacheKey(identity);
  const cached = cache.get(key);
  if (cached && cached.expiresAt > now) return cached.accessToken;
  cache.delete(key);
  const session = await issueRelayhistorySession(config, {
    ...identity,
    mode: "read",
    label: "relay-dashboard",
  });
  const accessToken = session.accessToken;
  if (typeof accessToken !== "string" || !accessToken) {
    throw new UpstreamError("exchange", undefined, "RelayHistory returned no access token");
  }
  const upstreamExpiry = Date.parse(String(session.accessTokenExpiresAt));
  const expiresAt = Math.min(
    now + TOKEN_MAX_AGE_MS,
    Number.isFinite(upstreamExpiry) ? upstreamExpiry - TOKEN_EXPIRY_MARGIN_MS : now,
  );
  if (expiresAt > now) {
    if (cache.size >= TOKEN_CACHE_LIMIT) {
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) cache.delete(oldest);
    }
    cache.set(key, { accessToken, expiresAt });
  }
  return accessToken;
}

export function forgetHistoryTokens(config: SelfhostConfig): void {
  tokenCaches.delete(config);
}

export type HistoryRead =
  | { status: "ok"; body: Record<string, unknown> }
  | { status: "not_found" }
  /**
   * The backend answered 501: it does not serve this view (or cannot answer
   * this first page exactly). No workspace data is returned, so no
   * attestation is required.
   */
  | { status: "unsupported"; reason: string };

export const UNSUPPORTED_BY_BACKEND = "unsupported_by_backend";

async function unsupportedReason(response: Response): Promise<string> {
  const body: unknown = await response.json().catch(() => null);
  if (isRecord(body)) {
    if (nonEmptyString(body.reason)) return body.reason;
    if (nonEmptyString(body.error)) return body.error;
  }
  return UNSUPPORTED_BY_BACKEND;
}

/**
 * GET a RelayHistory read path for one authorized workspace. The caller
 * supplies only the path and non-tenant parameters; `workspace` is always
 * set here and cannot be overridden.
 */
export async function readWorkspaceHistory(
  config: SelfhostConfig,
  identity: HistoryIdentity,
  path: string,
  params: URLSearchParams,
  options: { allowNotFound?: boolean } = {},
): Promise<HistoryRead> {
  const query = new URLSearchParams(params);
  query.delete("workspace");
  query.set("workspace", identity.workspaceId);
  // The base rollout serves unsearched lists, turns and recorded summaries. Session events have
  // their own opt-in so existing list/turn-only readers keep the History path.
  const rolloutPath = path === "/v1/sessions" || /^\/v1\/sessions\/[^/]+\/(?:turns|summary)$/.test(path);
  const eventPath = /^\/v1\/sessions\/[^/]+\/events$/.test(path);
  // Other admitted credential families retain their pre-existing History
  // transport; this connection never forwards them to a sh_at_-only Worker.
  const direct = Boolean(config.relayhistoryReadApiUrl && identity.callerToken.startsWith("sh_at_") &&
    (rolloutPath || (eventPath && config.relayhistoryReadApiEvents)) && !query.has("q") && !query.has("search"));
  // A read-API cursor cannot be interpreted by History after configuration
  // rollback. Refuse instead of silently restarting on its first page.
  if (!direct && (rolloutPath || eventPath) && /^b96[a-z][0-9]+:/.test(query.get("cursor") ?? "")) {
    throw new ReadCursorExpiredError();
  }
  if (direct && eventPath) {
    // Native events already carry their authoritative eventId. The legacy
    // message-ID expansion option is unsupported there; do not request it or
    // synthesize a messageId in Control. Legacy requests keep it unchanged.
    query.delete("includeMessageId");
  }
  const origin = direct ? config.relayhistoryReadApiUrl! : config.relayhistoryUrl;
  const url = new URL(`${path}?${query}`, `${origin}/`);
  if (url.origin !== new URL(origin).origin || !url.pathname.startsWith("/v1/")) {
    throw new UpstreamError("read", undefined, "RelayHistory read origin mismatch");
  }

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const accessToken = direct ? identity.callerToken : await readToken(config, identity);
    let response: Response;
    try {
      response = await globalThis.fetch(url, {
        method: "GET",
        redirect: "error",
        signal: AbortSignal.timeout(15_000),
        headers: {
          accept: "application/json",
          authorization: `Bearer ${accessToken}`,
        },
      });
    } catch (error) {
      throw new UpstreamError("read", undefined, error instanceof Error ? error.message : undefined);
    }
    if (!direct && response.status === 401 && attempt === 0) {
      // A revoked or rotated History session: mint a fresh one once.
      await response.body?.cancel().catch(() => {});
      cacheFor(config).delete(cacheKey(identity));
      continue;
    }
    if (response.status === 404 && options.allowNotFound) {
      await response.body?.cancel().catch(() => {});
      return { status: "not_found" };
    }
    if (response.status === 501) {
      // json() consumes the body (or fails, which releases it).
      return { status: "unsupported", reason: await unsupportedReason(response) };
    }
    if (!response.ok) {
      // Includes a dormant read-API container (503 not_configured). The
      // cached History token is kept: only a 401 evicts it.
      await response.body?.cancel().catch(() => {});
      throw new UpstreamError("read", response.status, undefined, direct && response.status === 503);
    }
    if (response.headers.get(WORKSPACE_ATTESTATION_HEADER) !== identity.workspaceId) {
      await response.body?.cancel().catch(() => {});
      throw new UpstreamError("read", response.status, "RelayHistory did not attest the workspace");
    }
    const body: unknown = await response.json().catch(() => null);
    if (!isRecord(body)) {
      throw new UpstreamError("read", response.status, "RelayHistory returned invalid JSON");
    }
    return { status: "ok", body };
  }
  throw new UpstreamError("read", 401);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}
