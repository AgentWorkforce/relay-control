import type { IncomingMessage } from "node:http";
import { createHmac } from "node:crypto";
import { z } from "zod";
import { bearer } from "./auth/bearer.js";
import type { SelfhostConfig } from "./config.js";
import { secureEqual } from "./crypto.js";
import type { Principal } from "./store.js";

const opaqueToken = (prefix: string) => z.string().max(4096).regex(new RegExp(`^${prefix}[A-Za-z0-9_-]{43,}$`));
export const readSessionRequest = z.object({
  label: z.string().min(1).max(128).regex(/^[^\u0000-\u001f\u007f]+$/u).optional(),
}).strict();
export const readRefreshRequest = z.object({ refreshToken: opaqueToken("rth_rt_read_") }).strict();

const sessionPair = z.object({
  sessionId: z.string().min(1).max(256),
  userId: z.string().min(1),
  orgId: z.string().min(1),
  workspaceId: z.string().min(1),
  audience: z.string(),
  scopes: z.tuple([z.literal("rth:read")]),
  accessToken: opaqueToken("rth_at_read_"),
  accessTokenExpiresAt: z.iso.datetime({ offset: true }),
  refreshToken: opaqueToken("rth_rt_read_"),
  refreshTokenExpiresAt: z.iso.datetime({ offset: true }),
  tokenType: z.literal("Bearer"),
});

/** Contains fixed metadata only: never retain upstream bodies, tokens or fetch errors. */
export class SessionReadError extends Error {
  constructor(readonly status: 401 | 502 | 503, readonly code: string) {
    super("Session read credential handoff failed");
  }
}

/**
 * How the person behind a read-token mint reached Control. It is derived from
 * the request's authentication, never from a request body:
 * - `browser`: cookie session (no Authorization bearer);
 * - `device`: `sh_at_` bearer (Desktop and device clients); a request with
 *   both a cookie and a bearer is a bearer request;
 * - `mcp`: an MCP read on the person's behalf.
 */
export type ReaderKind = "browser" | "device" | "mcp";

/** Header the MCP session reader sends on its hop to the public session-read route. */
export const MCP_READER_HEADER = "x-relaycontrol-session-reader";

/**
 * The marker the MCP session reader presents in MCP_READER_HEADER:
 * HMAC-SHA256(key = the read API issuer secret, data = a fixed string), hex.
 * Derived from the shared secret, so it is equal on every replica, and it is
 * not the secret. Never log or echo it.
 */
export function mcpReaderMarker(secret: string): string {
  return createHmac("sha256", secret).update("relay-control session-read mcp reader").digest("hex");
}

/**
 * The reader kind of a request. `marker` is given only on the public
 * session-read route, which the flagged MCP reader calls over HTTP with the
 * caller's bearer; a matching marker on a bearer request names that hop `mcp`.
 * A cookie request is always `browser`, whatever headers it carries. A device
 * that sent the header could only call itself `mcp`, which grants nothing:
 * `mcp` and `device` reads are treated alike downstream (neither is a browser
 * read). The marker is derived from the shared issuer secret, so it is equal
 * on every replica.
 */
export function readerKindOf(request: IncomingMessage, marker?: string): ReaderKind {
  if (!bearer(request)) return "browser";
  const presented = request.headers[MCP_READER_HEADER];
  if (marker && typeof presented === "string" && secureEqual(presented, marker)) return "mcp";
  return "device";
}


/**
 * `role` is the member's live organization role, the one Control authorized
 * this request with (the membership row `workspaceForUser` reads).
 */
export type ReadIdentity = {
  userId: string; orgId: string; workspaceId: string; role: Principal["role"]; readerKind: ReaderKind;
};

/**
 * The internal mint/refresh body. `role` is sent only when
 * SESSION_READ_MINT_INCLUDE_ROLE is on: read APIs that predate it refuse
 * unknown fields, so turn it on only after the read API accepts `role`.
 * `reader_kind` is sent only behind relaygate (config.mintReaderKind), which
 * records it and strips it before proxying; the read API's strict mint schema
 * rejects unknown fields.
 */
export function readSessionBody(
  config: NonNullable<SelfhostConfig["sessionReadApi"]>,
  identity: ReadIdentity,
  input: { label?: string } | { refreshToken: string },
  options: { includeRole?: boolean } = {},
): Record<string, unknown> {
  const { role, readerKind, ...ids } = identity;
  return {
    ...ids,
    ...(options.includeRole ? { role } : {}),
    ...(config.mintReaderKind ? { reader_kind: readerKind } : {}),
    audience: config.publicUrl, scopes: ["rth:read"], ...input,
  };
}

/** The read API is the issuer. Control authorizes a single identity and validates its reply. */
export async function requestReadSession(
  config: NonNullable<SelfhostConfig["sessionReadApi"]>,
  identity: ReadIdentity,
  input: { label?: string } | { refreshToken: string },
  options: { includeRole?: boolean } = {},
) {
  const refreshing = "refreshToken" in input;
  const path = refreshing ? "/internal/v1/session-read/sessions/refresh" : "/internal/v1/session-read/sessions";
  let response: Response;
  let value: unknown;
  try {
    response = await fetch(new URL(path, config.url), {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
      headers: { authorization: `Bearer ${config.secret}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(readSessionBody(config, identity, input, options)),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new SessionReadError(
        refreshing && response.status === 401 ? 401 : response.status === 503 ? 503 : 502,
        refreshing && response.status === 401 ? "invalid_refresh_token" : "session_read_unavailable",
      );
    }
    // Bound the response even when Content-Length is absent or untrustworthy.
    const reader = response.body?.getReader();
    if (!reader) throw new SessionReadError(502, "invalid_session_read_response");
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        size += chunk.value.byteLength;
        if (size > 16_384) throw new SessionReadError(502, "invalid_session_read_response");
        chunks.push(chunk.value);
      }
    } finally {
      await reader.cancel();
    }
    value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch (error) {
    if (error instanceof SessionReadError) throw error;
    throw new SessionReadError(502, "session_read_unavailable");
  }
  const parsed = sessionPair.safeParse(value);
  if (!parsed.success) throw new SessionReadError(502, "invalid_session_read_response");
  const pair = parsed.data;
  if (
    pair.userId !== identity.userId || pair.orgId !== identity.orgId || pair.workspaceId !== identity.workspaceId ||
    pair.audience !== config.publicUrl || Date.parse(pair.accessTokenExpiresAt) <= Date.now() ||
    Date.parse(pair.accessTokenExpiresAt) > Date.now() + 3_600_000 ||
    Date.parse(pair.refreshTokenExpiresAt) < Date.parse(pair.accessTokenExpiresAt) ||
    (refreshing && pair.refreshToken === input.refreshToken)
  ) throw new SessionReadError(502, "invalid_session_read_response");
  return { baseUrl: config.publicUrl, ...pair };
}
