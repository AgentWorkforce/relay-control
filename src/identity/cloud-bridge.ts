import { createPublicKey, verify, type KeyObject } from "node:crypto";

/**
 * Session bridge for organizations moved from Agent Relay Cloud
 * (docs/identity.md). Cloud signs a short-lived, single-use Ed25519 JWS for a
 * browser that holds a live Cloud session; this module checks that assertion.
 * Control never sees or validates a Cloud session or token: the signature by
 * a configured key is the only thing it trusts.
 */

export const CLOUD_BRIDGE_TYP = "cloud-bridge+jwt";
/** Clock difference tolerated between Cloud and this server, both ways. */
export const CLOUD_BRIDGE_SKEW_SECONDS = 30;
/** Longest exp - iat accepted: the assertion only has to survive one auto-posted form. */
export const CLOUD_BRIDGE_MAX_LIFETIME_SECONDS = 120;
/** A compact EdDSA JWS with these claims is well under 1 KiB; anything near this cap is not one. */
export const CLOUD_BRIDGE_MAX_ASSERTION_BYTES = 4_096;
export const CLOUD_BRIDGE_DEFAULT_MAX_AUTH_AGE_SECONDS = 30 * 24 * 60 * 60;
/** A Cloud sign-in older than this cannot vouch for anyone, whatever the operator sets. */
export const CLOUD_BRIDGE_MAX_AUTH_AGE_LIMIT_SECONDS = 90 * 24 * 60 * 60;
const MAX_KEYS = 4;
const MAX_KID_LENGTH = 200;
const MAX_ID_LENGTH = 200;
const MAX_JTI_LENGTH = 128;
const MAX_NONCE_LENGTH = 128;
const MAX_AUTH_METHOD_LENGTH = 64;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

export type CloudBridgeConfig = {
  /** SELFHOST_CLOUD_BRIDGE_ISSUER: the exact `iss` Cloud signs. */
  issuer: string;
  /** SELFHOST_CLOUD_BRIDGE_AUDIENCE: the exact `aud` Cloud signs for this deployment. */
  audience: string;
  /** SELFHOST_CLOUD_BRIDGE_HANDOFF_URL: Cloud's page that signs and auto-posts the assertion. */
  handoffUrl: string;
  /** The handoff URL's origin: the only Origin a consume POST may carry. */
  handoffOrigin: string;
  /** SELFHOST_CLOUD_BRIDGE_PUBLIC_KEYS: Cloud's Ed25519 verification keys by kid. */
  keys: ReadonlyMap<string, KeyObject>;
  /** SELFHOST_CLOUD_BRIDGE_MAX_AUTH_AGE_SECONDS: oldest Cloud sign-in (auth_time) accepted. */
  maxAuthAgeSeconds: number;
};

export type CloudBridgeRawConfig = {
  issuer: string | undefined;
  audience: string | undefined;
  handoffUrl: string | undefined;
  publicKeys: string | undefined;
  maxAuthAgeSeconds: string | undefined;
};

function requiredText(value: string | undefined, name: string): string {
  const text = value?.trim();
  if (!text) throw new Error(`${name} is required when SELFHOST_CLOUD_BRIDGE_ENABLED=true`);
  if (text.length > 512 || /\s/.test(text)) throw new Error(`${name} must be at most 512 characters without spaces`);
  return text;
}

function parseHandoffUrl(value: string | undefined): string {
  const raw = requiredText(value, "SELFHOST_CLOUD_BRIDGE_HANDOFF_URL");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("SELFHOST_CLOUD_BRIDGE_HANDOFF_URL must be an absolute URL");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK_HOSTS.includes(url.hostname))) {
    throw new Error("SELFHOST_CLOUD_BRIDGE_HANDOFF_URL must use HTTPS except on loopback");
  }
  // The start route appends ?nonce= itself; checking the raw text also
  // catches a bare "?" or "#", which URL drops.
  if (raw.includes("?") || raw.includes("#") || url.username || url.password) {
    throw new Error("SELFHOST_CLOUD_BRIDGE_HANDOFF_URL must not carry a query, fragment or credentials");
  }
  return url.href;
}

/** Cloud's public keys as a JWKS: 1-4 OKP Ed25519 keys with unique kids, no private members. */
export function parseCloudBridgeKeys(value: string | undefined): ReadonlyMap<string, KeyObject> {
  const name = "SELFHOST_CLOUD_BRIDGE_PUBLIC_KEYS";
  if (!value?.trim()) throw new Error(`${name} is required when SELFHOST_CLOUD_BRIDGE_ENABLED=true`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${name} must be a JWKS JSON document ({"keys":[...]})`);
  }
  const list = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as { keys?: unknown }).keys : undefined;
  if (!Array.isArray(list) || list.length < 1 || list.length > MAX_KEYS) {
    throw new Error(`${name} must hold 1 to ${MAX_KEYS} keys in "keys"`);
  }
  const keys = new Map<string, KeyObject>();
  for (const entry of list) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error(`${name}: every key must be a JSON object`);
    const jwk = entry as Record<string, unknown>;
    // A private member here means a signing key was pasted into a
    // verification setting; refuse it rather than quietly keep a secret.
    if ("d" in jwk) throw new Error(`${name} must hold public keys only (remove the private "d" member)`);
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") throw new Error(`${name}: every key must be kty OKP, crv Ed25519`);
    if (typeof jwk.kid !== "string" || !jwk.kid.trim() || jwk.kid.length > MAX_KID_LENGTH) {
      throw new Error(`${name}: every key needs a non-empty kid of at most ${MAX_KID_LENGTH} characters`);
    }
    if (keys.has(jwk.kid)) throw new Error(`${name}: kid ${JSON.stringify(jwk.kid)} appears more than once`);
    if (jwk.alg !== undefined && jwk.alg !== "EdDSA") throw new Error(`${name}: key alg must be EdDSA when set`);
    if (typeof jwk.x !== "string") throw new Error(`${name}: every key needs its public "x" member`);
    let key: KeyObject;
    try {
      key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
    } catch {
      throw new Error(`${name}: key ${JSON.stringify(jwk.kid)} is not a valid Ed25519 public key`);
    }
    if (key.asymmetricKeyType !== "ed25519") throw new Error(`${name}: key ${JSON.stringify(jwk.kid)} is not Ed25519`);
    keys.set(jwk.kid, key);
  }
  return keys;
}

function parseMaxAuthAge(value: string | undefined): number {
  const text = value?.trim();
  if (!text) return CLOUD_BRIDGE_DEFAULT_MAX_AUTH_AGE_SECONDS;
  const seconds = /^\d+$/.test(text) ? Number(text) : Number.NaN;
  if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > CLOUD_BRIDGE_MAX_AUTH_AGE_LIMIT_SECONDS) {
    throw new Error(`SELFHOST_CLOUD_BRIDGE_MAX_AUTH_AGE_SECONDS must be an integer from 1 to ${CLOUD_BRIDGE_MAX_AUTH_AGE_LIMIT_SECONDS}`);
  }
  return seconds;
}

export function parseCloudBridgeConfig(raw: CloudBridgeRawConfig): CloudBridgeConfig {
  const handoffUrl = parseHandoffUrl(raw.handoffUrl);
  return {
    issuer: requiredText(raw.issuer, "SELFHOST_CLOUD_BRIDGE_ISSUER"),
    audience: requiredText(raw.audience, "SELFHOST_CLOUD_BRIDGE_AUDIENCE"),
    handoffUrl,
    handoffOrigin: new URL(handoffUrl).origin,
    keys: parseCloudBridgeKeys(raw.publicKeys),
    maxAuthAgeSeconds: parseMaxAuthAge(raw.maxAuthAgeSeconds),
  };
}

export type CloudBridgeClaims = {
  kid: string;
  /** The Cloud user id: the only identity key (never the email). */
  sub: string;
  orgId: string;
  workspaceId: string | null;
  /** Epoch seconds of the Cloud sign-in that vouches for this browser. */
  authTime: number;
  /** Audit only. */
  authMethod: string | null;
  /** Always "browser"; a desktop_refresh assertion is refused. */
  use: "browser";
  nonce: string;
  jti: string;
  /** Epoch seconds. */
  iat: number;
  exp: number;
};

/**
 * Why a bridge consume was refused, for the log line and the audit row.
 * The request- and assertion-level reasons all answer the browser with the
 * same cloud_bridge_invalid, so a caller learns nothing about which check
 * failed; the account-level ones (last five) have their own browser codes.
 */
export type CloudBridgeRefusalReason =
  | "origin"
  | "attempt_missing"
  | "malformed"
  | "wrong_type"
  | "wrong_alg"
  | "unknown_kid"
  | "bad_signature"
  | "wrong_issuer"
  | "wrong_audience"
  | "expired"
  | "not_yet_valid"
  | "lifetime_too_long"
  | "wrong_use"
  | "nonce_mismatch"
  | "replayed"
  | "user_unknown"
  | "org_not_moved"
  | "not_member"
  | "auth_too_old"
  | "signed_out";

/** The verifier's refusals; the request- and account-level ones are raised by the route and store. */
export type CloudBridgeAssertionReason = Exclude<
  CloudBridgeRefusalReason,
  "origin" | "attempt_missing" | "nonce_mismatch" | "replayed" | "user_unknown" | "org_not_moved" | "not_member" | "auth_too_old" | "signed_out"
>;

/**
 * An assertion the verifier refused. `verified` (with `sub`, `orgId` and
 * `jti`, when present) is set only once the signature has verified, so a
 * forged token can never put its claims into a log line or cause an audit
 * row in somebody's organization.
 */
export class CloudBridgeAssertionError extends Error {
  constructor(
    readonly reason: CloudBridgeAssertionReason,
    readonly kid: string | null = null,
    readonly verified: { sub: string | null; orgId: string | null; jti: string | null } | null = null,
  ) {
    super(`cloud bridge assertion refused: ${reason}`);
  }
}

function decodePart(part: string): Buffer | null {
  if (!BASE64URL.test(part)) return null;
  const bytes = Buffer.from(part, "base64url");
  // Buffer decoding is lenient; a part that does not round-trip (stray
  // trailing bits) is not canonical base64url.
  return bytes.toString("base64url") === part ? bytes : null;
}

function jsonObject(bytes: Buffer): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(bytes.toString("utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function boundedText(value: unknown, max: number): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= max ? value : null;
}

function numericDate(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

/** Verifies a compact EdDSA JWS from Cloud and returns its claims, or throws CloudBridgeAssertionError. */
export function verifyCloudBridgeAssertion(token: string, config: CloudBridgeConfig, nowMs: number): CloudBridgeClaims {
  if (Buffer.byteLength(token) > CLOUD_BRIDGE_MAX_ASSERTION_BYTES) throw new CloudBridgeAssertionError("malformed");
  const parts = token.split(".");
  if (parts.length !== 3) throw new CloudBridgeAssertionError("malformed");
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  const headerBytes = decodePart(headerPart);
  const payloadBytes = decodePart(payloadPart);
  const signature = decodePart(signaturePart);
  if (!headerBytes || !payloadBytes || !signature) throw new CloudBridgeAssertionError("malformed");
  const header = jsonObject(headerBytes);
  if (!header) throw new CloudBridgeAssertionError("malformed");
  const kid = boundedText(header.kid, MAX_KID_LENGTH);
  // Only EdDSA under a configured kid: no "none", no algorithm the key was
  // not made for, and no critical extension this verifier cannot honour.
  if (header.alg !== "EdDSA") throw new CloudBridgeAssertionError("wrong_alg", kid);
  if (header.typ !== CLOUD_BRIDGE_TYP) throw new CloudBridgeAssertionError("wrong_type", kid);
  if ("crit" in header) throw new CloudBridgeAssertionError("malformed", kid);
  const key = kid ? config.keys.get(kid) : undefined;
  if (!kid || !key) throw new CloudBridgeAssertionError("unknown_kid", kid);
  let valid = false;
  try {
    valid = signature.length === 64 && verify(null, Buffer.from(`${headerPart}.${payloadPart}`, "ascii"), key, signature);
  } catch {
    valid = false;
  }
  if (!valid) throw new CloudBridgeAssertionError("bad_signature", kid);

  // From here on the payload is Cloud's own words, so its ids may be named
  // in the refusal (log line, audit row) even when a claim check fails.
  const claims = jsonObject(payloadBytes);
  if (!claims) throw new CloudBridgeAssertionError("malformed", kid, { sub: null, orgId: null, jti: null });
  const orgId = boundedText(claims.org_id, MAX_ID_LENGTH);
  const sub = boundedText(claims.sub, MAX_ID_LENGTH);
  const jti = boundedText(claims.jti, MAX_JTI_LENGTH);
  const refuse = (reason: CloudBridgeAssertionReason): never => {
    throw new CloudBridgeAssertionError(reason, kid, { sub, orgId, jti });
  };
  if (typeof claims.iss !== "string" || claims.iss !== config.issuer) refuse("wrong_issuer");
  // A string only: an audience array could name several deployments at once.
  if (typeof claims.aud !== "string" || claims.aud !== config.audience) refuse("wrong_audience");
  if (claims.use !== "browser") refuse("wrong_use");
  const nonce = boundedText(claims.nonce, MAX_NONCE_LENGTH);
  const authTime = numericDate(claims.auth_time);
  const iat = numericDate(claims.iat);
  const exp = numericDate(claims.exp);
  if (!sub || !orgId || !nonce || !jti || authTime === null || iat === null || exp === null) refuse("malformed");
  let workspaceId: string | null = null;
  if (claims.workspace_id !== undefined && claims.workspace_id !== null) {
    workspaceId = boundedText(claims.workspace_id, MAX_ID_LENGTH) ?? refuse("malformed");
  }
  let authMethod: string | null = null;
  if (claims.auth_method !== undefined && claims.auth_method !== null) {
    authMethod = boundedText(claims.auth_method, MAX_AUTH_METHOD_LENGTH) ?? refuse("malformed");
  }
  const now = nowMs / 1_000;
  if (exp! <= iat! || exp! - iat! > CLOUD_BRIDGE_MAX_LIFETIME_SECONDS) refuse("lifetime_too_long");
  if (iat! > now + CLOUD_BRIDGE_SKEW_SECONDS) refuse("not_yet_valid");
  if (claims.nbf !== undefined) {
    const nbf = numericDate(claims.nbf);
    if (nbf === null || nbf > now + CLOUD_BRIDGE_SKEW_SECONDS) refuse("not_yet_valid");
  }
  if (exp! <= now - CLOUD_BRIDGE_SKEW_SECONDS) refuse("expired");
  // `email` is deliberately never read: the account is found by sub alone.
  return {
    kid,
    sub: sub!,
    orgId: orgId!,
    workspaceId,
    authTime: authTime!,
    authMethod,
    use: "browser",
    nonce: nonce!,
    jti: jti!,
    iat: iat!,
    exp: exp!,
  };
}
