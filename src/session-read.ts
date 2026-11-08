import { z } from "zod";
import type { SelfhostConfig } from "./config.js";

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

export type ReadIdentity = { userId: string; orgId: string; workspaceId: string };

/** The read API is the issuer. Control authorizes a single identity and validates its reply. */
export async function requestReadSession(
  config: NonNullable<SelfhostConfig["sessionReadApi"]>,
  identity: ReadIdentity,
  input: { label?: string } | { refreshToken: string },
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
      body: JSON.stringify({ ...identity, audience: config.publicUrl, scopes: ["rth:read"], ...input }),
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
