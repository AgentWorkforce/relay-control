import { createHash } from "node:crypto";
import type { SelfhostConfig } from "../config.js";
import { ReadCursorExpiredError, UpstreamError } from "../relayhistory.js";
import { requestReadSession, SessionReadError } from "../session-read.js";

/**
 * Workspace-scoped History reads for the dashboard sessions views, served by
 * the sessions pipeline read API.
 *
 * Isolation rules (mirroring Cloud's `rejectHistoryResponse`):
 * - every read uses a `rth:read` session minted for exactly one
 *   {user, organization, workspace} triple, after the caller has passed the
 *   control plane's membership check;
 * - every upstream query carries `workspace=<authorized workspace>`, which
 *   the read API requires to equal the token's workspace (403 otherwise);
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
   * The caller's raw relaycontrol access token. It is a credential and is only
   * ever used as a cache key through its SHA-256, so a read token is kept per
   * caller token session.
   */
  callerToken: string;
};

type CachedToken = { accessToken: string; expiresAt: number; refreshToken?: string; refreshExpiresAt?: number };

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
 * The read API issues the token through the Control handoff. Control has authorized this {user, org, workspace} on this
 * request; the pair is kept per token session so a reader's token is renewed
 * on its own refresh lineage instead of creating a new session per page view.
 */
async function nativeReadToken(
  config: SelfhostConfig,
  identity: HistoryIdentity,
  cache: Map<string, CachedToken>,
  key: string,
  now: number,
  previous: CachedToken | undefined,
): Promise<string> {
  const api = config.sessionReadApi;
  const readIdentity = { userId: identity.userId, orgId: identity.organizationId, workspaceId: identity.workspaceId };
  let session;
  try {
    session = previous?.refreshToken && (previous.refreshExpiresAt ?? 0) > now + TOKEN_EXPIRY_MARGIN_MS
      ? await requestReadSession(api, readIdentity, { refreshToken: previous.refreshToken })
        .catch((error: unknown) => {
          if (error instanceof SessionReadError && error.status === 401) return null;
          throw error;
        })
      : null;
    session ??= await requestReadSession(api, readIdentity, { label: "relay-dashboard" });
  } catch (error) {
    if (error instanceof SessionReadError) throw new UpstreamError("exchange", error.status, undefined, error.status === 503);
    throw error;
  }
  const expiresAt = Math.min(now + TOKEN_MAX_AGE_MS, Date.parse(session.accessTokenExpiresAt) - TOKEN_EXPIRY_MARGIN_MS);
  if (expiresAt > now) {
    if (cache.size >= TOKEN_CACHE_LIMIT) {
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) cache.delete(oldest);
    }
    cache.set(key, {
      accessToken: session.accessToken,
      expiresAt,
      refreshToken: session.refreshToken,
      refreshExpiresAt: Date.parse(session.refreshTokenExpiresAt),
    });
  }
  return session.accessToken;
}

/**
 * A short-lived read token per identity. Membership is re-checked by the
 * caller on every request before this is used, so caching only saves read API
 * handoff round trips (and avoids creating a read session per page view).
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
  // The expired pair is kept for its refresh token.
  return nativeReadToken(config, identity, cache, key, now, cached);
}

export function forgetHistoryTokens(config: SelfhostConfig): void {
  tokenCaches.delete(config);
}

/** Which agent matching the backend applied; absent on a backend without prefix support. */
export const AGENT_MATCH_HEADER = "x-sessions-read-agent-match";

export type HistoryRead =
  | { status: "ok"; body: Record<string, unknown>; agentMatch?: string | null }
  | { status: "not_found" }
  /** The backend refused this agent filter (400 with an `agent_*` code). */
  | { status: "agent_rejected"; code: string }
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
    // The native read API uses { error: { code, reason, message } }.
    if (isRecord(body.error)) {
      // Agent-filter 400s are classified by code, not by explanatory reason.
      if (response.status === 400 && nonEmptyString(body.error.code)) return body.error.code;
      if (nonEmptyString(body.error.reason)) return body.error.reason;
      if (nonEmptyString(body.error.code)) return body.error.code;
    }
    if (nonEmptyString(body.error)) return body.error;
  }
  return UNSUPPORTED_BY_BACKEND;
}

/**
 * GET a read API path for one authorized workspace. The caller
 * supplies only the path and non-tenant parameters; `workspace` is always
 * set here and cannot be overridden.
 */
export async function readWorkspaceHistory(
  config: SelfhostConfig,
  identity: HistoryIdentity,
  path: string,
  params: URLSearchParams,
  options: { allowNotFound?: boolean; agentFilter?: boolean } = {},
): Promise<HistoryRead> {
  const query = new URLSearchParams(params);
  query.delete("workspace");
  query.set("workspace", identity.workspaceId);
  const origin = config.relayhistoryUrl;
  const url = new URL(`${path}?${query}`, `${origin}/`);
  if (url.origin !== new URL(origin).origin || !url.pathname.startsWith("/v1/")) {
    throw new UpstreamError("read", undefined, "RelayHistory read origin mismatch");
  }

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const accessToken = await readToken(config, identity);
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
    if (response.status === 401 && attempt === 0) {
      // A revoked or rotated read session: mint a fresh one once.
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
    if (response.status === 400 && options.agentFilter) {
      const code = await unsupportedReason(response);
      if (code.startsWith("agent_")) return { status: "agent_rejected", code };
      throw new UpstreamError("read", response.status);
    }
    if (!response.ok) {
      // Includes a dormant read-API container (503 not_configured). The
      // cached read token is kept: only a 401 evicts it.
      await response.body?.cancel().catch(() => {});
      if (response.status === 410) throw new ReadCursorExpiredError();
      throw new UpstreamError("read", response.status, undefined, response.status === 503);
    }
    if (response.headers.get(WORKSPACE_ATTESTATION_HEADER) !== identity.workspaceId) {
      await response.body?.cancel().catch(() => {});
      throw new UpstreamError("read", response.status, "RelayHistory did not attest the workspace");
    }
    const body: unknown = await response.json().catch(() => null);
    if (!isRecord(body)) {
      throw new UpstreamError("read", response.status, "RelayHistory returned invalid JSON");
    }
    return { status: "ok", body, agentMatch: response.headers.get(AGENT_MATCH_HEADER) };
  }
  throw new UpstreamError("read", 401);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}
