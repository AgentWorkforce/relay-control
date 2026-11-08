// Ported verbatim from the hosted control plane.
// Server-side Codex device login: no hosted callback; the operator approves a
// one-time code at auth.openai.com and this control plane exchanges it.
import crypto from "node:crypto";

export const OPENAI_DEVICE_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
export const OPENAI_DEVICE_VERIFICATION_URI = "https://auth.openai.com/codex/device";
export const OPENAI_DEVICE_AUTH_LIFETIME_SECONDS = 15 * 60;

const OPENAI_DEVICE_USER_CODE_ENDPOINT =
  "https://auth.openai.com/api/accounts/deviceauth/usercode";
const OPENAI_DEVICE_TOKEN_ENDPOINT =
  "https://auth.openai.com/api/accounts/deviceauth/token";
const OPENAI_OAUTH_TOKEN_ENDPOINT = "https://auth.openai.com/oauth/token";
const OPENAI_DEVICE_REDIRECT_URI = "https://auth.openai.com/deviceauth/callback";
const OPENAI_AUTH_CLAIMS_KEY = "https://api.openai.com/auth";
const REQUEST_TIMEOUT_MS = 15_000;

type Fetch = typeof globalThis.fetch;

export type OpenAIDeviceAuthorization = {
  deviceAuthId: string;
  userCode: string;
  verificationUri: string;
  intervalSeconds: number;
  expiresInSeconds: number;
};

export type OpenAIDevicePollResult =
  | { status: "pending" }
  | {
      status: "authorized";
      authorizationCode: string;
      codeVerifier: string;
    };

export type CodexAuthJson = {
  auth_mode: "chatgpt";
  OPENAI_API_KEY: null;
  tokens: {
    id_token: string;
    access_token: string;
    refresh_token: string;
    account_id: string;
  };
  last_refresh: string;
};

export class OpenAIDeviceAuthError extends Error {
  constructor(
    readonly code:
      | "start_unavailable"
      | "invalid_start_response"
      | "poll_unavailable"
      | "poll_rejected"
      | "invalid_poll_response"
      | "pkce_mismatch"
      | "exchange_unavailable"
      | "exchange_rejected"
      | "invalid_token_response"
      | "invalid_token_claims",
    readonly retryable: boolean,
  ) {
    super(code);
    this.name = "OpenAIDeviceAuthError";
  }
}

function requestSignal(): AbortSignal {
  return AbortSignal.timeout(REQUEST_TIMEOUT_MS);
}

function requiredString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
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

function parsePollInterval(value: unknown): number | null {
  const normalized = typeof value === "string" ? value.trim() : value;
  const parsed = typeof normalized === "number"
    ? normalized
    : typeof normalized === "string" && /^\d+$/.test(normalized)
      ? Number.parseInt(normalized, 10)
      : Number.NaN;
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 60 ? parsed : null;
}

function expectedPkceChallenge(codeVerifier: string): string {
  return crypto.createHash("sha256").update(codeVerifier).digest("base64url");
}

function readJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function readOpenAIAuthClaims(payload: Record<string, unknown>): Record<string, unknown> | null {
  const claims = payload[OPENAI_AUTH_CLAIMS_KEY];
  return claims && typeof claims === "object" && !Array.isArray(claims)
    ? claims as Record<string, unknown>
    : null;
}

export async function startOpenAIDeviceAuthorization(
  fetchImpl: Fetch = globalThis.fetch,
): Promise<OpenAIDeviceAuthorization> {
  let response: Response;
  try {
    response = await fetchImpl(OPENAI_DEVICE_USER_CODE_ENDPOINT, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ client_id: OPENAI_DEVICE_CLIENT_ID }),
      signal: requestSignal(),
    });
  } catch {
    throw new OpenAIDeviceAuthError("start_unavailable", true);
  }
  if (!response.ok) {
    throw new OpenAIDeviceAuthError("start_unavailable", response.status >= 500);
  }

  const payload = await readJsonObject(response);
  const deviceAuthId = requiredString(payload?.device_auth_id);
  const userCode = requiredString(payload?.user_code ?? payload?.usercode);
  const intervalSeconds = parsePollInterval(payload?.interval);
  if (!deviceAuthId || !userCode || !intervalSeconds) {
    throw new OpenAIDeviceAuthError("invalid_start_response", false);
  }

  return {
    deviceAuthId,
    userCode,
    verificationUri: OPENAI_DEVICE_VERIFICATION_URI,
    intervalSeconds,
    expiresInSeconds: OPENAI_DEVICE_AUTH_LIFETIME_SECONDS,
  };
}

export async function pollOpenAIDeviceAuthorization(
  input: { deviceAuthId: string; userCode: string },
  fetchImpl: Fetch = globalThis.fetch,
): Promise<OpenAIDevicePollResult> {
  let response: Response;
  try {
    response = await fetchImpl(OPENAI_DEVICE_TOKEN_ENDPOINT, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        device_auth_id: input.deviceAuthId,
        user_code: input.userCode,
      }),
      signal: requestSignal(),
    });
  } catch {
    throw new OpenAIDeviceAuthError("poll_unavailable", true);
  }

  if (response.status === 403 || response.status === 404) {
    return { status: "pending" };
  }
  if (!response.ok) {
    throw new OpenAIDeviceAuthError("poll_rejected", response.status >= 500);
  }

  const payload = await readJsonObject(response);
  const authorizationCode = requiredString(payload?.authorization_code);
  const codeChallenge = requiredString(payload?.code_challenge);
  const codeVerifier = requiredString(payload?.code_verifier);
  if (!authorizationCode || !codeChallenge || !codeVerifier) {
    throw new OpenAIDeviceAuthError("invalid_poll_response", false);
  }
  if (expectedPkceChallenge(codeVerifier) !== codeChallenge) {
    throw new OpenAIDeviceAuthError("pkce_mismatch", false);
  }

  return { status: "authorized", authorizationCode, codeVerifier };
}

export async function exchangeOpenAIDeviceAuthorization(
  input: { authorizationCode: string; codeVerifier: string; now?: Date },
  fetchImpl: Fetch = globalThis.fetch,
): Promise<CodexAuthJson> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.authorizationCode,
    redirect_uri: OPENAI_DEVICE_REDIRECT_URI,
    client_id: OPENAI_DEVICE_CLIENT_ID,
    code_verifier: input.codeVerifier,
  });

  let response: Response;
  try {
    response = await fetchImpl(OPENAI_OAUTH_TOKEN_ENDPOINT, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
      signal: requestSignal(),
    });
  } catch {
    throw new OpenAIDeviceAuthError("exchange_unavailable", true);
  }
  if (!response.ok) {
    throw new OpenAIDeviceAuthError("exchange_rejected", response.status >= 500);
  }

  const payload = await readJsonObject(response);
  const idToken = requiredString(payload?.id_token);
  const accessToken = requiredString(payload?.access_token);
  const refreshToken = requiredString(payload?.refresh_token);
  if (!idToken || !accessToken || !refreshToken) {
    throw new OpenAIDeviceAuthError("invalid_token_response", false);
  }

  const idPayload = readJwtPayload(idToken);
  const accessPayload = readJwtPayload(accessToken);
  const idClaims = idPayload ? readOpenAIAuthClaims(idPayload) : null;
  const accessClaims = accessPayload ? readOpenAIAuthClaims(accessPayload) : null;
  const accountId = requiredString(idClaims?.chatgpt_account_id);
  const accessAccountId = requiredString(accessClaims?.chatgpt_account_id);
  if (!idClaims || !accessClaims || !accountId || (accessAccountId && accessAccountId !== accountId)) {
    throw new OpenAIDeviceAuthError("invalid_token_claims", false);
  }

  return {
    auth_mode: "chatgpt",
    OPENAI_API_KEY: null,
    tokens: {
      id_token: idToken,
      access_token: accessToken,
      refresh_token: refreshToken,
      account_id: accountId,
    },
    last_refresh: (input.now ?? new Date()).toISOString(),
  };
}
