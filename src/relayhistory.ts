import type { SelfhostConfig } from "./config.js";

export type RelayhistoryMode = "read" | "sync";

export class UpstreamError extends Error {
  constructor(
    readonly stage: "assertion" | "exchange" | "read",
    readonly status?: number,
    message = `RelayHistory ${stage} failed`,
    readonly retryable = false,
  ) {
    super(message);
  }
}

/** A backend-specific cursor cannot continue after rollback or credential transport changes. */
export class ReadCursorExpiredError extends Error {
  constructor() {
    super("This session cursor has expired. Restart from the first page.");
    this.name = "ReadCursorExpiredError";
  }
}

/**
 * The configured History backend authenticated the caller but does not serve
 * the requested mode (the self-host read API container grants only
 * `rth:read`, so a sync session cannot be issued). Not an upstream failure:
 * the session route answers 501 `unsupported_by_backend`.
 */
export class UnsupportedModeError extends Error {
  readonly reason = "sync_not_served";
  constructor(readonly mode: RelayhistoryMode) {
    super("The configured session backend serves reads only; sync sessions are not available");
  }
}

export function scopesForMode(mode: RelayhistoryMode): string[] {
  return mode === "sync" ? ["rth:read", "rth:sync"] : ["rth:read"];
}

/**
 * Issues a RelayHistory session for an authorized {user, organization,
 * workspace}.
 *
 * - RelayAuth configured (transitional): mint a 60 s RelayAuth assertion for
 *   exactly the requested mode's scopes and exchange it at History.
 * - RelayAuth not configured: exchange the caller's own relaycontrol access
 *   token (`sh_at_`). History verifies it through relaycontrol's
 *   POST /internal/v1/auth/introspect and grants scopes from the token
 *   session's scopes; `mode` is then enforced here only (sync requires
 *   rth:sync on the caller), not narrowed at History.
 *
 * `callerToken` is a credential: it is sent only to RelayHistory and never
 * logged or put into an error message.
 */
export async function issueRelayhistorySession(
  config: SelfhostConfig,
  input: {
    userId: string;
    organizationId: string;
    workspaceId: string;
    mode: RelayhistoryMode;
    label?: string;
    /** The caller's raw relaycontrol access token (bearer or session cookie). */
    callerToken: string;
  },
): Promise<Record<string, unknown>> {
  const viaRelayauth = Boolean(config.relayauthUrl && config.relayauthApiKey);
  const agentRelayToken = viaRelayauth
    ? await relayauthAssertion(config, config.relayauthUrl!, config.relayauthApiKey!, input)
    : callerAccessToken(input.callerToken);

  const session = await postJson(
    `${config.relayhistoryUrl}/v1/cli/login`,
    {},
    {
      agentRelayToken,
      ...(input.label ? { label: input.label } : {}),
    },
    "exchange",
  );
  if (
    typeof session.accessToken !== "string" ||
    typeof session.accessTokenExpiresAt !== "string" ||
    typeof session.refreshToken !== "string" ||
    typeof session.refreshTokenExpiresAt !== "string" ||
    session.tokenType !== "Bearer"
  ) {
    throw new UpstreamError("exchange", undefined, "RelayHistory returned an invalid session");
  }
  const scopes = Array.isArray(session.scopes)
    ? session.scopes.filter((scope): scope is string => typeof scope === "string")
    : [];
  // A reply without a `scopes` array is trusted as before, for compatibility.
  if (!viaRelayauth && Array.isArray(session.scopes)) {
    // The caller's token is exchanged as-is, so History answers the scopes it
    // serves out of the token's scopes (the read API container: rth:read
    // only). The session must cover the requested mode; it is never returned
    // (or cached by callers) otherwise.
    if (!scopes.includes("rth:read")) {
      throw new UpstreamError("exchange", undefined, "RelayHistory returned an invalid session");
    }
    if (input.mode === "sync" && !scopes.includes("rth:sync")) {
      throw new UnsupportedModeError(input.mode);
    }
  }
  return {
    baseUrl: config.relayhistoryPublicUrl,
    ...(typeof session.sessionId === "string" ? { sessionId: session.sessionId } : {}),
    accessToken: session.accessToken,
    accessTokenExpiresAt: session.accessTokenExpiresAt,
    refreshToken: session.refreshToken,
    refreshTokenExpiresAt: session.refreshTokenExpiresAt,
    tokenType: "Bearer",
    scopes,
    orgId: input.organizationId,
    workspaceId: input.workspaceId,
  };
}

function callerAccessToken(token: string): string {
  if (typeof token !== "string" || !token.startsWith("sh_at_")) {
    throw new UpstreamError("exchange", undefined, "Caller is not authenticated with a user access token");
  }
  return token;
}

async function relayauthAssertion(
  config: SelfhostConfig,
  relayauthUrl: string,
  relayauthApiKey: string,
  input: {
    userId: string;
    organizationId: string;
    workspaceId: string;
    mode: RelayhistoryMode;
    label?: string;
  },
): Promise<string> {
  const scopes = scopesForMode(input.mode);
  const historyOrigin = config.relayhistoryPublicUrl;
  const assertionResponse = await postJson(
    `${relayauthUrl}/v1/tokens/relayhistory-assertion`,
    {
      "x-api-key": relayauthApiKey,
    },
    {
      orgId: input.organizationId,
      workspaceId: input.workspaceId,
      sponsorId: input.userId,
      scopes,
      expiresIn: 60,
      historyOrigin,
      metadata: {
        productId: "selfhost-control-plane",
        purpose: "relayhistory-login",
        requestedMode: input.mode,
        grantedMode: input.mode,
        ...(input.label ? { label: input.label } : {}),
      },
    },
    "assertion",
  );
  const assertion = assertionResponse.accessToken;
  if (typeof assertion !== "string" || !assertion.trim()) {
    throw new UpstreamError("assertion", undefined, "RelayAuth returned no assertion");
  }
  validateAssertion(assertion, {
    userId: input.userId,
    organizationId: input.organizationId,
    workspaceId: input.workspaceId,
    scopes,
    audience: historyOrigin,
  });
  return assertion;
}

async function postJson(
  url: string,
  headers: Record<string, string>,
  body: unknown,
  stage: "assertion" | "exchange",
): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await globalThis.fetch(url, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
    });
  } catch (error) {
    throw new UpstreamError(stage, undefined, error instanceof Error ? error.message : undefined);
  }
  if (!response.ok) throw new UpstreamError(stage, response.status);
  const result: unknown = await response.json().catch(() => null);
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new UpstreamError(stage, response.status, "Upstream returned invalid JSON");
  }
  return result as Record<string, unknown>;
}

function validateAssertion(
  token: string,
  expected: {
    userId: string;
    organizationId: string;
    workspaceId: string;
    scopes: string[];
    audience: string;
  },
): void {
  const claims = decodeJwtPayload(token);
  const scopes = Array.isArray(claims.scopes)
    ? claims.scopes.filter((scope): scope is string => typeof scope === "string")
    : [];
  const actualScopes = [...new Set(scopes)].sort();
  const expectedScopes = [...new Set(expected.scopes)].sort();
  const audience = claims.aud;
  const exactAudience = typeof audience === "string"
    ? audience === expected.audience
    : Array.isArray(audience) && audience.length === 1 && audience[0] === expected.audience;
  if (
    claims.org !== expected.organizationId ||
    claims.wks !== expected.workspaceId ||
    claims.sponsorId !== expected.userId ||
    !exactAudience ||
    actualScopes.length !== expectedScopes.length ||
    !actualScopes.every((scope, index) => scope === expectedScopes[index])
  ) {
    throw new UpstreamError("assertion", undefined, "RelayAuth assertion claims mismatch");
  }
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const raw = token.trim().replace(/^relay_(ag|pa|ws|id)_/, "");
  const parts = raw.split(".");
  if (parts.length !== 3 || !parts[1]) {
    throw new UpstreamError("assertion", undefined, "RelayAuth assertion is not a JWT");
  }
  try {
    const parsed: unknown = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    return parsed as Record<string, unknown>;
  } catch {
    throw new UpstreamError("assertion", undefined, "RelayAuth assertion payload is invalid");
  }
}
