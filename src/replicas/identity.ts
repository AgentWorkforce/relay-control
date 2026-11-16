import { createPublicKey, verify as verifySignature, type KeyObject } from "node:crypto";

/**
 * Verifier for Replicas `workspace_identity` tokens: RS256 JWTs a Replicas
 * workspace presents to the environment-level MCP. Node crypto only.
 *
 * Discovery and keys come only from the configured issuer: its
 * `/.well-known/openid-configuration` must name the same issuer and a JWKS
 * URL on the issuer's origin. Keys are cached by kid for ten minutes; an
 * unknown kid triggers at most one refetch (and forced refetches are spaced,
 * so random kids cannot turn callers into a JWKS amplifier).
 *
 * Every token failure is the same ReplicaIdentityError with no token, claim
 * or email text in it; an issuer that cannot be read (discovery or JWKS) is
 * ReplicaIdentityUnavailable instead, so callers answer 503, not 401. Tokens
 * are never logged.
 */
export type ReplicaIdentityClaims = {
  issuer: string;
  organizationId: string;
  environmentId: string;
  /** The Replicas workspace (the replica) presenting the token. */
  workspaceId: string;
  creatorId: string | null;
  /** Only used for a masked creator hint; never logged, audited or returned in an error. */
  creatorEmail: string | null;
  jti: string;
};

export class ReplicaIdentityError extends Error {
  constructor() {
    super("replica_identity_invalid");
    this.name = "ReplicaIdentityError";
  }
}

/** Discovery or JWKS could not be fetched or read: the token was not judged. */
export class ReplicaIdentityUnavailable extends Error {
  constructor() {
    super("replica_identity_unavailable");
    this.name = "ReplicaIdentityUnavailable";
  }
}

export type ReplicaIdentityVerifier = { verify(token: string): Promise<ReplicaIdentityClaims> };

const KEY_TTL_MS = 10 * 60_000;
const FORCED_REFETCH_INTERVAL_MS = 30_000;
const SKEW_SECONDS = 30;
const MAX_LIFETIME_SECONDS = 60 * 60;
const FETCH_TIMEOUT_MS = 5_000;
const MAX_DOCUMENT_BYTES = 64 * 1024;
const MAX_TOKEN_BYTES = 8 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SEGMENT = /^[A-Za-z0-9_-]+$/;

const fail = (): never => {
  throw new ReplicaIdentityError();
};
const unavailable = (): never => {
  throw new ReplicaIdentityUnavailable();
};

function decodeJson(segment: string): Record<string, unknown> {
  if (!SEGMENT.test(segment)) fail();
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  } catch {
    return fail();
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  return value as Record<string, unknown>;
}

/** Reads at most MAX_DOCUMENT_BYTES; a larger body is refused without buffering it. */
async function boundedText(response: Response): Promise<string> {
  if (!response.body) return unavailable();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > MAX_DOCUMENT_BYTES) unavailable();
      chunks.push(chunk.value);
    }
    return Buffer.concat(chunks).toString("utf8");
  } finally {
    void reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

/** Every failure (network, timeout, redirect, non-2xx, oversize, not a JSON object) is ReplicaIdentityUnavailable. */
async function fetchJson(fetchImpl: typeof fetch, url: string): Promise<Record<string, unknown>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetchImpl(url, { method: "GET", redirect: "error", cache: "no-store", signal: controller.signal,
      headers: { accept: "application/json" } });
    if (!response.ok) {
      void response.body?.cancel().catch(() => undefined);
      return unavailable();
    }
    const value = JSON.parse(await boundedText(response)) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) unavailable();
    return value as Record<string, unknown>;
  } catch {
    return unavailable();
  } finally {
    clearTimeout(timer);
  }
}

function rsaKey(jwk: Record<string, unknown>): KeyObject | null {
  if (jwk.kty !== "RSA" || typeof jwk.n !== "string" || typeof jwk.e !== "string") return null;
  if (jwk.use !== undefined && jwk.use !== "sig") return null;
  if (jwk.alg !== undefined && jwk.alg !== "RS256") return null;
  try {
    const key = createPublicKey({ key: { kty: "RSA", n: jwk.n, e: jwk.e }, format: "jwk" });
    const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
    return bits >= 2048 ? key : null;
  } catch {
    return null;
  }
}

export function createReplicaIdentityVerifier(options: {
  issuer: string;
  audience: string;
  fetchImpl?: typeof fetch;
  now?: () => Date;
}): ReplicaIdentityVerifier {
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? (() => new Date());
  const issuerOrigin = new URL(options.issuer).origin;
  let keys = new Map<string, KeyObject>();
  let fetchedAt = -Infinity;
  let lastAttempt = -Infinity;
  let lastForced = -Infinity;
  let inflight: Promise<void> | null = null;
  // Whether the most recent discovery/JWKS load failed: then a missing key is an outage, not a bad token.
  let lastLoadFailed = false;

  async function load(): Promise<void> {
    const discovery = await fetchJson(fetchImpl, `${options.issuer}/.well-known/openid-configuration`);
    if (discovery.issuer !== options.issuer || typeof discovery.jwks_uri !== "string") unavailable();
    let jwksUrl: URL;
    try {
      jwksUrl = new URL(discovery.jwks_uri as string);
    } catch {
      return unavailable();
    }
    // Keys come from the configured issuer only, never from a URL it points elsewhere.
    if (jwksUrl.protocol !== "https:" || jwksUrl.origin !== issuerOrigin || jwksUrl.username || jwksUrl.password) unavailable();
    const jwks = await fetchJson(fetchImpl, jwksUrl.href);
    if (!Array.isArray(jwks.keys)) unavailable();
    const next = new Map<string, KeyObject>();
    for (const entry of jwks.keys as unknown[]) {
      if (!entry || typeof entry !== "object") continue;
      const jwk = entry as Record<string, unknown>;
      if (typeof jwk.kid !== "string" || !jwk.kid || next.has(jwk.kid)) continue;
      const key = rsaKey(jwk);
      if (key) next.set(jwk.kid, key);
    }
    keys = next;
    fetchedAt = now().getTime();
    lastLoadFailed = false;
  }

  /**
   * Shared by concurrent callers. Attempts are spaced, so an issuer outage or
   * a stream of unknown kids cannot turn callers into a fetch amplifier.
   */
  function refresh(forced = false): Promise<void> {
    if (inflight) return inflight;
    const last = forced ? lastForced : lastAttempt;
    if (now().getTime() - last < FORCED_REFETCH_INTERVAL_MS) return Promise.resolve();
    lastAttempt = now().getTime();
    if (forced) lastForced = lastAttempt;
    inflight = load().catch(() => {
      lastLoadFailed = true;
      // Fail closed: expired keys are not reused after a failed refresh.
      if (now().getTime() - fetchedAt >= KEY_TTL_MS) keys = new Map();
    }).finally(() => {
      inflight = null;
    });
    return inflight;
  }

  async function keyFor(kid: string): Promise<KeyObject> {
    if (now().getTime() - fetchedAt >= KEY_TTL_MS) {
      await refresh();
      // No current keys means the issuer could not be read.
      if (now().getTime() - fetchedAt >= KEY_TTL_MS) return unavailable();
    }
    const cached = keys.get(kid);
    if (cached) return cached;
    // One refetch for an unknown kid (key rotation). Still unknown after a
    // successful load is a bad token; after a failed one, an outage.
    await refresh(true);
    return keys.get(kid) ?? (lastLoadFailed ? unavailable() : fail());
  }

  return {
    async verify(token: string): Promise<ReplicaIdentityClaims> {
      if (typeof token !== "string" || !token || Buffer.byteLength(token) > MAX_TOKEN_BYTES) fail();
      const parts = token.split(".");
      if (parts.length !== 3 || !parts[2] || !SEGMENT.test(parts[2])) fail();
      const header = decodeJson(parts[0]!);
      if (header.alg !== "RS256" || typeof header.kid !== "string" || !header.kid || header.crit !== undefined) fail();
      const claims = decodeJson(parts[1]!);
      const key = await keyFor(header.kid as string);
      const valid = verifySignature("RSA-SHA256", Buffer.from(`${parts[0]}.${parts[1]}`), key, Buffer.from(parts[2]!, "base64url"));
      if (!valid) fail();

      if (claims.iss !== options.issuer) fail();
      const audience = claims.aud;
      const audienceOk = audience === options.audience
        || (Array.isArray(audience) && audience.length === 1 && audience[0] === options.audience);
      if (!audienceOk) fail();
      const seconds = now().getTime() / 1000;
      if (typeof claims.exp !== "number" || !Number.isFinite(claims.exp) || seconds >= claims.exp + SKEW_SECONDS) fail();
      if ((claims.exp as number) - seconds > MAX_LIFETIME_SECONDS + SKEW_SECONDS) fail();
      if (claims.nbf !== undefined && (typeof claims.nbf !== "number" || !Number.isFinite(claims.nbf) || seconds < claims.nbf - SKEW_SECONDS)) fail();
      for (const name of ["organization_id", "environment_id", "workspace_id"]) {
        if (typeof claims[name] !== "string" || !UUID.test(claims[name] as string)) fail();
      }
      if (!("creator_id" in claims) || (claims.creator_id !== null
        && (typeof claims.creator_id !== "string" || !claims.creator_id || claims.creator_id.length > 256))) fail();
      if (typeof claims.jti !== "string" || !claims.jti || claims.jti.length > 256) fail();
      const email = typeof claims.creator_email === "string" && claims.creator_email.length <= 320 ? claims.creator_email : null;
      return {
        issuer: options.issuer,
        organizationId: (claims.organization_id as string).toLowerCase(),
        environmentId: (claims.environment_id as string).toLowerCase(),
        workspaceId: (claims.workspace_id as string).toLowerCase(),
        creatorId: claims.creator_id as string | null,
        creatorEmail: email,
        jti: claims.jti as string,
      };
    },
  };
}

/** `a…@example.com`: enough for an admin to recognise a creator, never the full address. */
export function emailHint(email: string | null): string | null {
  if (!email) return null;
  const at = email.lastIndexOf("@");
  if (at < 1 || at === email.length - 1) return null;
  const domain = email.slice(at + 1).toLowerCase();
  if (!/^[a-z0-9.-]{1,253}$/.test(domain)) return null;
  return `${email[0]}…@${domain}`;
}
