import { createHash } from "node:crypto";
import type { SelfhostConfig } from "../config.js";
import { UpstreamError } from "../relayhistory.js";
import { requestReadSession } from "../session-read.js";
import {
  isRecord,
  WORKSPACE_ATTESTATION_HEADER,
  type HistoryIdentity,
  type HistoryRead,
} from "../sessions/history.js";

/**
 * The MCP's session reads through the session read API
 * (SESSION_READ_API_MCP_READS=true, default false). Every read uses an access
 * token the read API issued for exactly this {user, organization, workspace};
 * the service secret only ever reaches the issue and refresh calls. Refresh
 * tokens stay in this process's memory.
 *
 * Returns null when the existing History path should answer: the setting is
 * off, the route is outside the read contract, or a first page failed. A
 * read API cursor never falls back, because History would restart at page one.
 */
const READ_ROUTES = /^\/v1\/(?:events|sessions(?:\/activity|\/[^/]+\/(?:turns|metadata|events))?)$/;
const READ_API_CURSOR = /^b96[a-z][0-9]+:/;
const EXPIRY_MARGIN_MS = 30_000;
const CACHE_LIMIT = 1_000;

type Held = {
  accessToken: string;
  accessExpiresAt: number;
  refreshToken: string;
  refreshExpiresAt: number;
};

const caches = new WeakMap<SelfhostConfig, Map<string, Promise<Held>>>();

function cacheFor(config: SelfhostConfig): Map<string, Promise<Held>> {
  let cache = caches.get(config);
  if (!cache) {
    cache = new Map();
    caches.set(config, cache);
  }
  return cache;
}

function cacheKey(identity: HistoryIdentity): string {
  // Bound to the caller's token too: a rotated or revoked sign-in never reuses a held session.
  const tokenHash = createHash("sha256").update(identity.callerToken).digest("hex");
  return JSON.stringify([identity.userId, identity.organizationId, identity.workspaceId, tokenHash]);
}

export function forgetSessionReadTokens(config: SelfhostConfig): void {
  caches.delete(config);
}

async function issue(
  api: NonNullable<SelfhostConfig["sessionReadApi"]>,
  identity: HistoryIdentity,
  previous: Held | null,
): Promise<Held> {
  const ids = { userId: identity.userId, orgId: identity.organizationId, workspaceId: identity.workspaceId };
  const session = previous
    ? await requestReadSession(api, ids, { refreshToken: previous.refreshToken })
      .catch(() => requestReadSession(api, ids, { label: "mcp" }))
    : await requestReadSession(api, ids, { label: "mcp" });
  return {
    accessToken: session.accessToken,
    accessExpiresAt: Date.parse(session.accessTokenExpiresAt),
    refreshToken: session.refreshToken,
    refreshExpiresAt: Date.parse(session.refreshTokenExpiresAt),
  };
}

async function heldSession(
  config: SelfhostConfig,
  api: NonNullable<SelfhostConfig["sessionReadApi"]>,
  identity: HistoryIdentity,
): Promise<Held> {
  const cache = cacheFor(config);
  const key = cacheKey(identity);
  const existing = cache.get(key);
  const current = existing ? await existing.catch(() => null) : null;
  if (current && current.accessExpiresAt - EXPIRY_MARGIN_MS > Date.now()) return current;
  // Concurrent callers share one issue or refresh: refresh tokens rotate on use.
  const latest = cache.get(key);
  if (latest && latest !== existing) return latest;
  const usable = current && current.refreshExpiresAt - EXPIRY_MARGIN_MS > Date.now() ? current : null;
  const pending = issue(api, identity, usable);
  if (!cache.has(key) && cache.size >= CACHE_LIMIT) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(key, pending);
  pending.catch(() => {
    if (cache.get(key) === pending) cache.delete(key);
  });
  return pending;
}

export async function readViaSessionRead(
  config: SelfhostConfig,
  identity: HistoryIdentity,
  path: string,
  params: URLSearchParams,
): Promise<HistoryRead | null> {
  const api = config.sessionReadApi;
  if (!config.sessionReadMcpReads || !api || !READ_ROUTES.test(path)) return null;
  const cursor = params.get("cursor");
  // A History cursor can only continue at History.
  if (cursor && !READ_API_CURSOR.test(cursor)) return null;
  const orFallback = (stage: "exchange" | "read", status?: number): null => {
    if (cursor) throw new UpstreamError(stage, status);
    return null;
  };

  const query = new URLSearchParams(params);
  query.delete("workspace");
  query.set("workspace", identity.workspaceId);
  const url = new URL(`${path}?${query}`, `${api.url}/`);
  if (url.origin !== new URL(api.url).origin) throw new UpstreamError("read", undefined, "RelayHistory read origin mismatch");

  for (let attempt = 0; attempt < 2; attempt += 1) {
    let held: Held;
    try {
      held = await heldSession(config, api, identity);
    } catch {
      return orFallback("exchange");
    }
    let response: Response;
    try {
      response = await globalThis.fetch(url, {
        method: "GET",
        redirect: "error",
        signal: AbortSignal.timeout(15_000),
        headers: { accept: "application/json", authorization: `Bearer ${held.accessToken}` },
      });
    } catch {
      return orFallback("read");
    }
    if (response.status === 401 && attempt === 0) {
      await response.body?.cancel().catch(() => {});
      cacheFor(config).delete(cacheKey(identity));
      continue;
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      return orFallback("read", response.status);
    }
    // Never a fallback: a response naming another workspace is a tenancy failure.
    if (response.headers.get(WORKSPACE_ATTESTATION_HEADER) !== identity.workspaceId) {
      await response.body?.cancel().catch(() => {});
      throw new UpstreamError("read", response.status, "RelayHistory did not attest the workspace");
    }
    const body: unknown = await response.json().catch(() => null);
    if (!isRecord(body)) return orFallback("read", response.status);
    return { status: "ok", body };
  }
  return orFallback("read", 401);
}
