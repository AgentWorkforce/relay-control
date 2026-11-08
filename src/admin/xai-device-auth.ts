// Ported verbatim from the hosted control plane.
// Server-side Grok device login (RFC 8628 + PKCE): no hosted callback.
import crypto from "node:crypto";

// Verified against https://auth.x.ai/.well-known/openid-configuration 2026-07-14.
const XAI_DEVICE_AUTHORIZATION_ENDPOINT = "https://auth.x.ai/oauth2/device/code";
const XAI_DEVICE_TOKEN_ENDPOINT = "https://auth.x.ai/oauth2/token";
const XAI_OIDC_ISSUER = "https://auth.x.ai";
export const XAI_DEVICE_VERIFICATION_URI = "https://accounts.x.ai/oauth2/device";
export const XAI_DEVICE_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828";
export const XAI_DEVICE_CREDENTIAL_SCOPE = `${XAI_OIDC_ISSUER}::${XAI_DEVICE_CLIENT_ID}`;

const XAI_DEVICE_SCOPES = "openid profile email offline_access grok-cli:access api:access";
const REQUEST_TIMEOUT_MS = 15_000;
const MAX_LIFETIME_SECONDS = 24 * 60 * 60;

type Fetch = typeof globalThis.fetch;

export type XaiDeviceAuthorization = {
  deviceCode: string;
  userCode: string;
  codeVerifier: string;
  verificationUri: typeof XAI_DEVICE_VERIFICATION_URI;
  intervalSeconds: number;
  expiresInSeconds: number;
};

export type GrokAuthJson = {
  [XAI_DEVICE_CREDENTIAL_SCOPE]: {
    key: string;
    auth_mode: "oidc";
    create_time: string;
    email?: string;
    refresh_token: string;
    expires_at: string;
    oidc_issuer: typeof XAI_OIDC_ISSUER;
    oidc_client_id: typeof XAI_DEVICE_CLIENT_ID;
  };
};

export type XaiDevicePollResult =
  | { status: "pending"; slowDown: boolean }
  | { status: "denied" }
  | { status: "expired" }
  | { status: "authorized"; credential: GrokAuthJson; refreshToken: string };

export class XaiDeviceAuthError extends Error {
  constructor(
    readonly code:
      | "start_unavailable"
      | "invalid_start_response"
      | "poll_unavailable"
      | "poll_rejected"
      | "invalid_poll_response"
      | "invalid_token_response"
      | "invalid_token_claims",
    readonly retryable: boolean,
  ) {
    super(code);
    this.name = "XaiDeviceAuthError";
  }
}

function requestSignal(): AbortSignal {
  return AbortSignal.timeout(REQUEST_TIMEOUT_MS);
}

function requiredString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number | null {
  const normalized = typeof value === "string" ? value.trim() : value;
  const parsed = typeof normalized === "number"
    ? normalized
    : typeof normalized === "string" && /^\d+$/.test(normalized)
      ? Number.parseInt(normalized, 10)
      : Number.NaN;
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : null;
}

async function readJsonObject(response: Response): Promise<Record<string, unknown> | null> {
  try {
    const value = await response.json();
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function readJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) return null;
  try {
    const value = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function verificationUriIsTrusted(value: string): boolean {
  try {
    return new URL(value).origin === new URL(XAI_DEVICE_VERIFICATION_URI).origin;
  } catch {
    return false;
  }
}

function generatePkce(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  return {
    codeVerifier,
    codeChallenge: crypto.createHash("sha256").update(codeVerifier).digest("base64url"),
  };
}

export async function startXaiDeviceAuthorization(
  fetchImpl: Fetch = globalThis.fetch,
): Promise<XaiDeviceAuthorization> {
  const pkce = generatePkce();
  const body = new URLSearchParams({
    client_id: XAI_DEVICE_CLIENT_ID,
    scope: XAI_DEVICE_SCOPES,
    code_challenge: pkce.codeChallenge,
    code_challenge_method: "S256",
  });

  let response: Response;
  try {
    response = await fetchImpl(XAI_DEVICE_AUTHORIZATION_ENDPOINT, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
      signal: requestSignal(),
    });
  } catch {
    throw new XaiDeviceAuthError("start_unavailable", true);
  }
  if (!response.ok) {
    throw new XaiDeviceAuthError("start_unavailable", response.status >= 500);
  }

  const payload = await readJsonObject(response);
  const deviceCode = requiredString(payload?.device_code);
  const userCode = requiredString(payload?.user_code);
  const verificationUri = requiredString(payload?.verification_uri);
  const expiresInSeconds = boundedInteger(payload?.expires_in, 1, MAX_LIFETIME_SECONDS);
  const intervalSeconds = payload && !Object.hasOwn(payload, "interval")
    ? 5
    : boundedInteger(payload?.interval, 1, 60);
  if (
    !deviceCode || !userCode || !verificationUri || !verificationUriIsTrusted(verificationUri) ||
    !expiresInSeconds || !intervalSeconds
  ) {
    throw new XaiDeviceAuthError("invalid_start_response", false);
  }

  return {
    deviceCode,
    userCode,
    codeVerifier: pkce.codeVerifier,
    verificationUri: XAI_DEVICE_VERIFICATION_URI,
    intervalSeconds,
    expiresInSeconds,
  };
}

export async function pollXaiDeviceAuthorization(
  input: { deviceCode: string; codeVerifier: string; now?: Date },
  fetchImpl: Fetch = globalThis.fetch,
): Promise<XaiDevicePollResult> {
  // Keep this insertion order stable. F11 requires a byte-for-byte guard on
  // this RFC 8628 + PKCE body and forbids redirect_uri/authorization_code.
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    device_code: input.deviceCode,
    client_id: XAI_DEVICE_CLIENT_ID,
    code_verifier: input.codeVerifier,
  });

  let response: Response;
  try {
    response = await fetchImpl(XAI_DEVICE_TOKEN_ENDPOINT, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
      signal: requestSignal(),
    });
  } catch {
    throw new XaiDeviceAuthError("poll_unavailable", true);
  }

  const payload = await readJsonObject(response);
  if (!response.ok) {
    const errorCode = requiredString(payload?.error);
    if (errorCode === "authorization_pending") return { status: "pending", slowDown: false };
    if (errorCode === "slow_down") return { status: "pending", slowDown: true };
    if (errorCode === "access_denied") return { status: "denied" };
    if (errorCode === "expired_token") return { status: "expired" };
    throw new XaiDeviceAuthError("poll_rejected", response.status >= 500);
  }
  if (!payload) throw new XaiDeviceAuthError("invalid_poll_response", false);

  const idToken = requiredString(payload.id_token);
  const accessToken = requiredString(payload.access_token);
  const refreshToken = requiredString(payload.refresh_token);
  const expiresInSeconds = boundedInteger(payload.expires_in, 1, MAX_LIFETIME_SECONDS);
  if (!idToken || !accessToken || !refreshToken || !expiresInSeconds) {
    throw new XaiDeviceAuthError("invalid_token_response", false);
  }
  const claims = readJwtPayload(idToken);
  if (!claims) throw new XaiDeviceAuthError("invalid_token_claims", false);

  const now = input.now ?? new Date();
  const email = requiredString(claims.email);
  const credential: GrokAuthJson = {
    [XAI_DEVICE_CREDENTIAL_SCOPE]: {
      key: accessToken,
      auth_mode: "oidc",
      create_time: now.toISOString(),
      ...(email ? { email } : {}),
      refresh_token: refreshToken,
      expires_at: new Date(now.getTime() + expiresInSeconds * 1000).toISOString(),
      oidc_issuer: XAI_OIDC_ISSUER,
      oidc_client_id: XAI_DEVICE_CLIENT_ID,
    },
  };
  return { status: "authorized", credential, refreshToken };
}
