import { createPublicKey, verify as verifySignature, type KeyObject } from "node:crypto";
import { logDependencyFailed } from "./observe.js";

/**
 * Workflow OIDC tokens for release-gate redeem (relay
 * docs/design/owner-trusted-delegates.md §11a.3). GitHub Actions is always
 * accepted; a self-host may add issuers (GitHub Enterprise Server and the
 * like) with SELFHOST_DELEGATION_OIDC_ISSUERS. A token is accepted only when
 * its signature verifies against its issuer's published JWKS, its issuer is
 * one of those, its audience is this deployment's origin, and it is within
 * its validity window. No stored secret is involved.
 */

export const GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const JWKS_TTL_MS = 10 * 60 * 1000;
/** An unknown `kid` refetches at most once a minute, so forged tokens cannot drive outbound calls (as Cloud). */
const REFRESH_COOLDOWN_MS = 60 * 1000;
/** After a failed fetch, no new fetch starts for this long: an outage does not add a fetch to every redeem (as Cloud). */
const FAILURE_BACKOFF_MS = 30 * 1000;
/** Each discovery or JWKS request, headers and body together (as Cloud). */
const FETCH_TIMEOUT_MS = 5_000;
const CLOCK_SKEW_SECONDS = 60;
const MAX_TOKEN_CHARS = 16_384;

/** The workflow claims a gate matches, all from a verified token. */
export type WorkflowClaims = {
  issuer: string;
  repository: string;
  /** The workflow the run started from (`<repo>/.github/workflows/<file>@<ref>`). */
  workflow_ref: string;
  /** The workflow file the job runs in: a reusable workflow's, or the same as workflow_ref. */
  job_workflow_ref: string;
  ref: string;
  event_name: string;
  run_id: string;
  run_attempt: number;
  /** GitHub's stable repository and owner ids, when the issuer sends them (a gate pins them on first match). */
  repository_id: string | null;
  repository_owner_id: string | null;
  /** The commit the run is on: lower-case hex, 40 (or 64 for a SHA-256 repository). Required. */
  sha: string;
  /**
   * The commit the issuer read the job's workflow file at: for a reusable
   * workflow, the commit its `@ref` resolved to when the run started. Null
   * when absent.
   */
  job_workflow_sha: string | null;
};

export class OidcInvalid extends Error {
  constructor(readonly detail: string) {
    super(`oidc_invalid: ${detail}`);
  }
}

/**
 * The issuer's keys could not be read (discovery or JWKS fetch failed, or is
 * backing off) and no good keys are cached: an outage, never a forged token.
 * Gate redeem answers `unavailable`.
 */
export class OidcKeysUnavailable extends Error {
  constructor(readonly status: number | null = null) {
    super("oidc_keys_unavailable");
  }
}

type Jwk = { kty?: string; kid?: string; alg?: string; use?: string; n?: string; e?: string; crv?: string; x?: string; y?: string };

/**
 * A verifier for the given issuers. JWKS are fetched through OpenID discovery
 * (`<issuer>/.well-known/openid-configuration` -> `jwks_uri`), cached for 10
 * minutes, and fetched again when a token names an unknown `kid`.
 */
export function workflowOidcVerifier(input: {
  issuers: readonly string[];
  audience: string;
  fetchImpl?: typeof fetch;
  now?: () => Date;
}) {
  const fetchImpl = input.fetchImpl ?? fetch;
  const now = input.now ?? (() => new Date());
  const issuers = new Set(input.issuers.map(issuer => issuer.replace(/\/+$/, "")));
  const cache = new Map<string, { at: number; keys: Jwk[] }>();
  const failedAt = new Map<string, number>();
  /** One refresh per issuer at a time (as Cloud): concurrent callers share it, so cache writes land in order. */
  const refreshing = new Map<string, Promise<Jwk[]>>();

  async function fetchJson(url: string): Promise<Record<string, unknown>> {
    // One deadline covers the headers and the body (as Cloud's 5 s): a stalled body aborts too.
    const response = await fetchImpl(url, { headers: { accept: "application/json" }, redirect: "error",
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (!response.ok) throw new OidcKeysUnavailable(response.status);
    const body = await response.json().catch(() => null) as unknown;
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new OidcKeysUnavailable(response.status);
    return body as Record<string, unknown>;
  }

  /**
   * The issuer's keys, as Cloud's githubJwks: cached for 10 minutes, an
   * unknown kid refetches at most once a minute, and after a failed fetch no
   * refetch starts for 30 seconds. A failure serves the last good keys, or
   * (with none) throws OidcKeysUnavailable; either way it is logged
   * (`delegation.dependency_failed`, op github_oidc_jwks).
   */
  /** `stale`: the issuer could not be reached and these are the last good keys (as Cloud). */
  async function keys(issuer: string, refresh: boolean): Promise<{ keys: Jwk[]; stale: boolean; notRefreshed?: boolean }> {
    const cached = cache.get(issuer);
    const at = now().getTime();
    const age = cached ? at - cached.at : Number.POSITIVE_INFINITY;
    if (cached && !refresh && age < JWKS_TTL_MS) return { keys: cached.keys, stale: false };
    // A refresh asked within the cooldown is not made: those keys may predate a rotation (as Cloud).
    if (cached && refresh && age < REFRESH_COOLDOWN_MS) return { keys: cached.keys, stale: false, notRefreshed: true };
    if (at - (failedAt.get(issuer) ?? Number.NEGATIVE_INFINITY) < FAILURE_BACKOFF_MS) {
      if (cached) return { keys: cached.keys, stale: true };
      throw new OidcKeysUnavailable();
    }
    try {
      return { keys: await refreshKeys(issuer), stale: false };
    } catch (error) {
      // The backoff starts when the fetch failed, not when it started (a slow failure backs off as long).
      failedAt.set(issuer, now().getTime());
      logDependencyFailed("github_oidc_jwks", error, { stale_cache_served: Boolean(cached), refresh,
        ...(error instanceof OidcKeysUnavailable && error.status !== null ? { status: error.status } : {}) });
      if (cached) return { keys: cached.keys, stale: true };
      throw error instanceof OidcKeysUnavailable ? error : new OidcKeysUnavailable();
    }
  }

  function refreshKeys(issuer: string): Promise<Jwk[]> {
    const pending = refreshing.get(issuer);
    if (pending) return pending;
    const started = fetchKeys(issuer).finally(() => refreshing.delete(issuer));
    refreshing.set(issuer, started);
    return started;
  }

  async function fetchKeys(issuer: string): Promise<Jwk[]> {
    const discovery = await fetchJson(`${issuer}/.well-known/openid-configuration`);
    const jwksUri = typeof discovery.jwks_uri === "string" ? discovery.jwks_uri : null;
    // The keys must be served from the issuer's own origin.
    // Compare issuers without a trailing slash, as the token's issuer is compared.
    const published = typeof discovery.issuer === "string" ? discovery.issuer.replace(/\/+$/, "") : null;
    if (!jwksUri || published !== issuer || new URL(jwksUri).origin !== new URL(issuer).origin) {
      throw new OidcKeysUnavailable();
    }
    const jwks = await fetchJson(jwksUri);
    // No keys array is a failed fetch (as Cloud): the last good keys keep serving.
    if (!Array.isArray(jwks.keys)) throw new OidcKeysUnavailable();
    const list = jwks.keys.filter((key): key is Jwk => Boolean(key) && typeof key === "object");
    cache.set(issuer, { at: now().getTime(), keys: list });
    return list;
  }

  /** Imported RSA keys by kid, modulus and exponent (at most 32), so a hot redeem path does not re-import (as Cloud). */
  const rsaKeys = new Map<string, KeyObject>();
  function publicKey(jwk: Jwk): KeyObject {
    if (jwk.kty === "RSA" && jwk.n && jwk.e) {
      const id = `${jwk.kid ?? ""}\u0000${jwk.n}\u0000${jwk.e}`;
      let key = rsaKeys.get(id);
      if (!key) {
        if (rsaKeys.size >= 32) rsaKeys.clear();
        key = createPublicKey({ key: { kty: "RSA", n: jwk.n, e: jwk.e }, format: "jwk" });
        rsaKeys.set(id, key);
      }
      return key;
    }
    if (jwk.kty === "EC" && jwk.crv === "P-256" && jwk.x && jwk.y) {
      return createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" });
    }
    throw new OidcInvalid("unsupported_key");
  }

  const decode = (part: string): Record<string, unknown> => {
    try {
      const value = JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as unknown;
      if (value && typeof value === "object" && !Array.isArray(value)) return value as Record<string, unknown>;
    } catch {
      // fall through
    }
    throw new OidcInvalid("malformed");
  };

  /** Verifies a compact JWS and returns its workflow claims, or throws OidcInvalid. */
  return async function verifyWorkflowToken(token: string): Promise<WorkflowClaims> {
    if (!token || token.length > MAX_TOKEN_CHARS) throw new OidcInvalid("malformed");
    const parts = token.split(".");
    if (parts.length !== 3 || parts.some(part => !/^[A-Za-z0-9_-]+$/.test(part))) throw new OidcInvalid("malformed");
    const header = decode(parts[0]!);
    const claims = decode(parts[1]!);
    const alg = header.alg;
    if (alg !== "RS256" && alg !== "ES256") throw new OidcInvalid("unsupported_alg");
    if (typeof header.kid !== "string" || !header.kid) throw new OidcInvalid("malformed");
    const issuer = typeof claims.iss === "string" ? claims.iss.replace(/\/+$/, "") : "";
    // The issuer is checked before any network call, so a token cannot point
    // the server at a URL of its choosing.
    if (!issuers.has(issuer)) throw new OidcInvalid("issuer");
    // Every other claim is judged before any key is looked up (as Cloud):
    // a token with the wrong audience, out of its window or
    // missing a claim is refused (OidcInvalid, 401) without reading the JWKS,
    // so an unknown kid on it never spends the refresh cooldown or answers
    // `unavailable`. The signature below still covers these very bytes.
    const audience = claims.aud;
    const audiences = Array.isArray(audience) ? audience : [audience];
    if (!audiences.includes(input.audience)) throw new OidcInvalid("audience");
    const seconds = Math.floor(now().getTime() / 1000);
    if (typeof claims.exp !== "number" || claims.exp + CLOCK_SKEW_SECONDS <= seconds) throw new OidcInvalid("expired");
    if (typeof claims.nbf === "number" && claims.nbf - CLOCK_SKEW_SECONDS > seconds) throw new OidcInvalid("not_yet_valid");
    if (typeof claims.iat === "number" && claims.iat - CLOCK_SKEW_SECONDS > seconds) throw new OidcInvalid("not_yet_valid");
    const text = (name: string) => {
      const value = claims[name];
      if (typeof value !== "string" || !value || value.length > 512) throw new OidcInvalid(`claim_${name}`);
      return value;
    };
    text("sub");
    const optionalId = (name: string) => {
      const value = claims[name];
      return typeof value === "string" && /^[0-9]{1,20}$/.test(value) ? value : null;
    };
    const runAttempt = Number(text("run_attempt"));
    const runId = text("run_id");
    if (!/^[1-9][0-9]{0,19}$/.test(runId) || !Number.isSafeInteger(runAttempt) || runAttempt < 1) {
      throw new OidcInvalid("claim_run");
    }
    // GitHub sets `sha` on every Actions token: the commit the run is on. As Cloud, it is required.
    const commit = (value: unknown) => typeof value === "string" && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/iu.test(value) ? value.toLowerCase() : null;
    const sha = commit(claims.sha);
    if (!sha) throw new OidcInvalid("claim_sha");
    // The commit the job's workflow file was read at (its reusable workflow's, for a reusable job), as Cloud.
    const jobWorkflowSha = commit(claims.job_workflow_sha);
    const result: WorkflowClaims = {
      issuer,
      repository: text("repository"),
      workflow_ref: text("workflow_ref"),
      job_workflow_ref: text("job_workflow_ref"),
      ref: text("ref"),
      event_name: text("event_name"),
      run_id: runId,
      run_attempt: runAttempt,
      sha,
      job_workflow_sha: jobWorkflowSha,
      repository_id: optionalId("repository_id"),
      repository_owner_id: optionalId("repository_owner_id"),
    };
    // Only signing keys (`use` is "sig" or absent) are candidates (as Cloud).
    const pick = (set: { keys: Jwk[] }) => set.keys.find(key => key.kid === header.kid && (key.use === undefined || key.use === "sig"));
    let jwk = pick(await keys(issuer, false));
    if (!jwk) {
      const refreshed = await keys(issuer, true);
      jwk = pick(refreshed);
      // An unknown kid while the issuer cannot be reached may be a key it just
      // rotated in: that is `unavailable` (retry), never a forged token (as Cloud).
      // The same within the refresh cooldown, when no refetch was made (as Cloud).
      if (!jwk && (refreshed.stale || refreshed.notRefreshed)) throw new OidcKeysUnavailable();
    }
    if (!jwk || (jwk.use && jwk.use !== "sig") || (jwk.alg && jwk.alg !== alg)) throw new OidcInvalid("unknown_key");
    const key = publicKey(jwk);
    if ((alg === "RS256") !== (jwk.kty === "RSA")) throw new OidcInvalid("unknown_key");
    const signed = Buffer.from(`${parts[0]}.${parts[1]}`);
    const signature = Buffer.from(parts[2]!, "base64url");
    const ok = alg === "RS256"
      ? verifySignature("RSA-SHA256", signed, key, signature)
      : verifySignature("SHA256", signed, { key, dsaEncoding: "ieee-p1363" }, signature);
    if (!ok) throw new OidcInvalid("signature");
    // The key lookup may have waited on the issuer: the token must still be in its window now.
    if ((claims.exp as number) + CLOCK_SKEW_SECONDS <= Math.floor(now().getTime() / 1000)) throw new OidcInvalid("expired");
    return result;
  };
}

export type WorkflowOidcVerifier = ReturnType<typeof workflowOidcVerifier>;
