import { createHash, createHmac, webcrypto } from "node:crypto";

/**
 * Cursor cloud agent identity (docs/cursor-cloud-agents.md).
 *
 * A Cursor cloud agent runs on a Cursor-managed VM that mints short-lived
 * OIDC JWTs from a local socket (`POST /v1/tokens/oidc` on
 * $CURSOR_AGENT_SOCKET; cursor.com/docs/cloud-agent/identity). The token is
 * RS256, issued by https://api.cursor.com, valid five minutes, bound to the
 * audience the caller asks for and, optionally, to a nonce, and it names the
 * cloud agent run (`cloud_agent_id`) and its owner. It is the cloud
 * counterpart of Agent Relay Desktop's per-chat attestation: one cloud agent
 * run is one chat. The VM's metadata API is unsigned and never trusted.
 *
 * The agent passes the token as a tool argument. That is safe because it is
 * unforgeable, audience-bound to this install, nonce-bound to the caller's
 * own connection, single use (its `jti` is spent once) and expires in
 * minutes; an agent can only ever present its own run's identity.
 */

export const CURSOR_OIDC_ISSUER = "https://api.cursor.com";
export const CURSOR_OIDC_JWKS_URL = "https://api.cursor.com/keys";
/** Clock skew accepted on nbf/exp. */
const SKEW_SECONDS = 60;
/** Cursor's own maximum lifetime; a longer-lived token is refused. */
const MAX_LIFETIME_SECONDS = 300 + SKEW_SECONDS;
const JWKS_TTL_MS = 10 * 60_000;
/** A kid miss refetches the key set at most this often. */
const JWKS_MISS_REFETCH_MS = 30_000;
const MAX_TOKEN_LENGTH = 16_384;

export class CursorIdentityError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "CursorIdentityError";
  }
}

export type CursorIdentity = {
  /** Cursor's Cloud Agent id (bcId): one cloud agent run. */
  cloudAgentId: string;
  /** `user:<id>` or `service_account:<id>`. */
  subject: string;
  ownerUserId: string | null;
  ownerServiceAccountId: string | null;
  /** Lowercased; can change, so never a link key on its own. */
  ownerEmail: string | null;
  teamId: string | null;
  runtime: "managed" | "self_hosted";
  repoUrl: string | null;
  jti: string;
  expiresAt: Date;
};

type Jwk = { kty?: string; kid?: string; alg?: string; use?: string; n?: string; e?: string };

/** Cursor's signing keys, cached; refetched on expiry or (rate-limited) on an unknown kid. */
export function cursorJwks(options: { fetchImpl?: typeof fetch; now?: () => number; url?: string } = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;
  let cached: { keys: Map<string, webcrypto.CryptoKey>; fetchedAt: number } | null = null;
  let inflight: Promise<Map<string, webcrypto.CryptoKey>> | null = null;

  async function load(): Promise<Map<string, webcrypto.CryptoKey>> {
    const response = await fetchImpl(options.url ?? CURSOR_OIDC_JWKS_URL, {
      redirect: "error", headers: { accept: "application/json" }, signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) throw new CursorIdentityError("jwks_unavailable");
    const body = await response.json() as { keys?: Jwk[] };
    const keys = new Map<string, webcrypto.CryptoKey>();
    for (const jwk of Array.isArray(body.keys) ? body.keys : []) {
      if (jwk.kty !== "RSA" || !jwk.kid || !jwk.n || !jwk.e || (jwk.alg && jwk.alg !== "RS256") || (jwk.use && jwk.use !== "sig")) continue;
      keys.set(jwk.kid, await webcrypto.subtle.importKey("jwk", { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]));
    }
    cached = { keys, fetchedAt: now() };
    return keys;
  }

  function refresh() {
    inflight ??= load().finally(() => { inflight = null; });
    return inflight;
  }

  return async function key(kid: string): Promise<webcrypto.CryptoKey | null> {
    if (!cached || now() - cached.fetchedAt > JWKS_TTL_MS) await refresh();
    const hit = cached!.keys.get(kid);
    if (hit) return hit;
    if (now() - cached!.fetchedAt > JWKS_MISS_REFETCH_MS) return (await refresh()).get(kid) ?? null;
    return null;
  };
}
export type CursorJwks = ReturnType<typeof cursorJwks>;

const b64json = (part: string): Record<string, unknown> => {
  if (!/^[A-Za-z0-9_-]+$/.test(part)) throw new CursorIdentityError("malformed");
  try {
    const value: unknown = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("not an object");
    return value as Record<string, unknown>;
  } catch {
    throw new CursorIdentityError("malformed");
  }
};
const str = (value: unknown): string | null => typeof value === "string" && value.length > 0 && value.length <= 512 ? value : null;
const num = (value: unknown): number | null => typeof value === "number" && Number.isFinite(value) ? value : null;

/**
 * Verifies a Cursor cloud agent OIDC token. Checks, in order: shape, RS256
 * with a key from Cursor's JWKS, issuer, the exact audience, nbf/exp (and a
 * lifetime no longer than Cursor's), the nonce, the claims this service
 * needs, the runtime, and finally spends the jti once. Throws
 * CursorIdentityError with a short reason; the token is never echoed.
 */
export async function verifyCursorIdentityToken(token: string, options: {
  audience: string;
  /** The nonces this connection accepts now (cursorIdentityNonces().accepted). */
  nonces: readonly string[];
  jwks: CursorJwks;
  /** Records the jti; false when it was already spent. */
  spend: (jti: string, expiresAt: Date) => Promise<boolean>;
  allowSelfHosted?: boolean;
  now?: () => number;
}): Promise<CursorIdentity> {
  if (typeof token !== "string" || token.length > MAX_TOKEN_LENGTH) throw new CursorIdentityError("malformed");
  const parts = token.split(".");
  if (parts.length !== 3) throw new CursorIdentityError("malformed");
  const [rawHeader, rawPayload, rawSignature] = parts as [string, string, string];
  const header = b64json(rawHeader);
  if (header.alg !== "RS256" || typeof header.kid !== "string" || !header.kid) throw new CursorIdentityError("unsupported_algorithm");
  const key = await options.jwks(header.kid);
  if (!key) throw new CursorIdentityError("unknown_key");
  if (!/^[A-Za-z0-9_-]+$/.test(rawSignature)) throw new CursorIdentityError("malformed");
  const valid = await webcrypto.subtle.verify("RSASSA-PKCS1-v1_5", key, Buffer.from(rawSignature, "base64url"),
    Buffer.from(`${rawHeader}.${rawPayload}`));
  if (!valid) throw new CursorIdentityError("bad_signature");
  const claims = b64json(rawPayload);
  if (claims.iss !== CURSOR_OIDC_ISSUER) throw new CursorIdentityError("issuer");
  // Cursor does not allowlist audiences: anything but this install's exact audience is refused.
  const aud = claims.aud;
  if (!(aud === options.audience || (Array.isArray(aud) && aud.length === 1 && aud[0] === options.audience))) {
    throw new CursorIdentityError("audience");
  }
  const now = Math.floor((options.now ?? Date.now)() / 1000);
  const exp = num(claims.exp), iat = num(claims.iat), nbf = num(claims.nbf) ?? iat;
  if (exp === null || iat === null || nbf === null) throw new CursorIdentityError("malformed");
  if (exp < now - SKEW_SECONDS) throw new CursorIdentityError("expired");
  if (nbf > now + SKEW_SECONDS) throw new CursorIdentityError("not_yet_valid");
  if (exp - iat > MAX_LIFETIME_SECONDS) throw new CursorIdentityError("lifetime");
  if (typeof claims.nonce !== "string" || !options.nonces.includes(claims.nonce)) throw new CursorIdentityError("nonce");
  const cloudAgentId = str(claims.cloud_agent_id), subject = str(claims.sub), jti = str(claims.jti);
  if (!cloudAgentId || !subject || !jti || !/^(user|service_account):[^\s:]+$/.test(subject)) throw new CursorIdentityError("claims");
  const runtime = claims.agent_runtime;
  if (runtime !== "managed" && runtime !== "self_hosted") throw new CursorIdentityError("claims");
  if (runtime === "self_hosted" && !options.allowSelfHosted) throw new CursorIdentityError("self_hosted_runtime");
  if (!await options.spend(jti, new Date((exp + SKEW_SECONDS) * 1000))) throw new CursorIdentityError("replayed");
  const email = str(claims.owner_email);
  return {
    cloudAgentId, subject, jti, runtime,
    ownerUserId: str(claims.owner_user_id),
    ownerServiceAccountId: str(claims.owner_service_account_id),
    ownerEmail: email ? email.toLowerCase() : null,
    teamId: str(claims.team_id),
    repoUrl: str(claims.repo_url),
    expiresAt: new Date(exp * 1000),
  };
}

/** The audience a Cursor cloud agent mints for: this install's MCP endpoint, so a token for anything else is refused. */
export const cursorIdentityAudience = (publicOrigin: string) => `${new URL(publicOrigin).origin}/mcp#cursor-cloud`;

/**
 * The nonce a connection mints its token with: an HMAC over the connection
 * (grant or MCP session) and a ten-minute window, so a token minted for one
 * connection is refused on any other and a stale one ages out. Stateless; the
 * current and previous windows are accepted.
 */
export function cursorIdentityNonces(secret: Uint8Array, connection: string, now = Date.now()): { current: string; accepted: string[] } {
  const window = Math.floor(now / 600_000);
  const at = (w: number) => createHmac("sha256", secret).update(`cursor-cloud-nonce:v1:${connection}:${w}`).digest("base64url").slice(0, 32);
  return { current: at(window), accepted: [at(window), at(window - 1)] };
}

/** The participant name of one cloud agent run: fixed by the server, never chosen by the agent. */
export const cursorCloudParticipantName = (cloudAgentId: string) =>
  `cursor-cloud-${createHash("sha256").update(cloudAgentId).digest("hex").slice(0, 10)}`;

/** The shell command an agent runs to mint its token, for tool guidance. */
export const cursorMintCommand = (audience: string, nonce: string) =>
  `curl -s --unix-socket "$CURSOR_AGENT_SOCKET" -H 'content-type: application/json' -d '{"aud":"${audience}","nonce":"${nonce}"}' http://cursor-agent/v1/tokens/oidc`;
