import {
  constants,
  createHash,
  createPublicKey,
  randomBytes,
  verify as verifySignature,
  type JsonWebKey,
  type KeyObject,
} from "node:crypto";
import type { OidcConfig } from "./config.js";

/**
 * Minimal OpenID Connect relying party: discovery, the authorization-code
 * flow with PKCE (S256), a confidential-client code exchange, and id_token
 * verification against the issuer's JWKS. Works with Google Workspace,
 * Okta, Microsoft Entra ID, Keycloak, Dex and other standard providers.
 */

const FETCH_TIMEOUT_MS = 10_000;
const DISCOVERY_TTL_MS = 60 * 60 * 1_000;
const JWKS_REFRESH_FLOOR_MS = 60 * 1_000;
const CLOCK_SKEW_S = 120;

export class OidcError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

type Discovery = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  token_endpoint_auth_methods_supported?: string[];
};

export type OidcIdentity = {
  subject: string;
  email: string;
  name: string | null;
  /**
   * The id_token said email_verified: true. An absent claim is not verified
   * unless the operator named this issuer as trusted for it.
   */
  emailVerified: boolean;
};

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

function base64url(buffer: Buffer): string {
  return buffer.toString("base64url");
}

export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = base64url(randomBytes(32));
  return { verifier, challenge: base64url(createHash("sha256").update(verifier).digest()) };
}

export function randomState(): string {
  return base64url(randomBytes(24));
}

function endpoint(value: unknown, name: string, allowHttp: boolean): string {
  if (typeof value !== "string") throw new OidcError("discovery_invalid", `Discovery document has no ${name}`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new OidcError("discovery_invalid", `Discovery ${name} is not a URL`);
  }
  if (url.protocol !== "https:" && !(allowHttp && url.protocol === "http:")) {
    throw new OidcError("discovery_invalid", `Discovery ${name} must use https`);
  }
  return value;
}

const ALGORITHMS: Record<string, { hash: string; kind: "rsa" | "pss" | "ec" }> = {
  RS256: { hash: "sha256", kind: "rsa" },
  RS384: { hash: "sha384", kind: "rsa" },
  RS512: { hash: "sha512", kind: "rsa" },
  PS256: { hash: "sha256", kind: "pss" },
  PS384: { hash: "sha384", kind: "pss" },
  PS512: { hash: "sha512", kind: "pss" },
  ES256: { hash: "sha256", kind: "ec" },
  ES384: { hash: "sha384", kind: "ec" },
  ES512: { hash: "sha512", kind: "ec" },
};

function decodeJson(part: string, what: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
  } catch {
    // fall through
  }
  throw new OidcError("id_token_invalid", `id_token ${what} is not valid JSON`);
}

export class OidcClient {
  #discovery: { value: Discovery; fetchedAt: number } | null = null;
  #jwks: { keys: JsonWebKey[]; fetchedAt: number } | null = null;

  constructor(
    readonly config: OidcConfig,
    private readonly fetchImpl: FetchLike = (input, init) => globalThis.fetch(input, init),
    private readonly now: () => number = () => Date.now(),
  ) {}

  private async getJson(url: string, init?: RequestInit): Promise<{ status: number; body: Record<string, unknown> | null }> {
    let response: Response;
    try {
      response = await this.fetchImpl(url, { ...init, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    } catch {
      throw new OidcError("idp_unreachable", "The identity provider could not be reached");
    }
    const body = await response.json().catch(() => null) as unknown;
    return {
      status: response.status,
      body: body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null,
    };
  }

  async discovery(): Promise<Discovery> {
    if (this.#discovery && this.now() - this.#discovery.fetchedAt < DISCOVERY_TTL_MS) return this.#discovery.value;
    const { status, body } = await this.getJson(`${this.config.issuer}/.well-known/openid-configuration`, {
      headers: { accept: "application/json" },
    });
    if (status !== 200 || !body) throw new OidcError("discovery_failed", `OIDC discovery answered ${status}`);
    const issuer = typeof body.issuer === "string" ? body.issuer : "";
    if (issuer.replace(/\/+$/, "") !== this.config.issuer) {
      throw new OidcError("discovery_invalid", "Discovery issuer does not match SELFHOST_OIDC_ISSUER");
    }
    const allowHttp = this.config.allowHttpIssuer;
    const value: Discovery = {
      issuer,
      authorization_endpoint: endpoint(body.authorization_endpoint, "authorization_endpoint", allowHttp),
      token_endpoint: endpoint(body.token_endpoint, "token_endpoint", allowHttp),
      jwks_uri: endpoint(body.jwks_uri, "jwks_uri", allowHttp),
      ...(Array.isArray(body.token_endpoint_auth_methods_supported)
        ? { token_endpoint_auth_methods_supported: body.token_endpoint_auth_methods_supported.filter((m): m is string => typeof m === "string") }
        : {}),
    };
    this.#discovery = { value, fetchedAt: this.now() };
    return value;
  }

  async authorizationUrl(input: { redirectUri: string; state: string; nonce: string; codeChallenge: string; loginHint?: string }): Promise<string> {
    const discovery = await this.discovery();
    const url = new URL(discovery.authorization_endpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.config.clientId);
    url.searchParams.set("redirect_uri", input.redirectUri);
    url.searchParams.set("scope", this.config.scopes.join(" "));
    url.searchParams.set("state", input.state);
    url.searchParams.set("nonce", input.nonce);
    url.searchParams.set("code_challenge", input.codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    if (input.loginHint) url.searchParams.set("login_hint", input.loginHint);
    // Google Workspace: preselect the hosted domain when exactly one is allowed.
    if (this.config.allowedDomains.length === 1) url.searchParams.set("hd", this.config.allowedDomains[0]!);
    return url.toString();
  }

  /** Exchanges the code and returns the verified identity from the id_token. */
  async complete(input: { code: string; redirectUri: string; codeVerifier: string; nonce: string }): Promise<OidcIdentity> {
    const discovery = await this.discovery();
    const form = new URLSearchParams({
      grant_type: "authorization_code",
      code: input.code,
      redirect_uri: input.redirectUri,
      code_verifier: input.codeVerifier,
    });
    const headers: Record<string, string> = {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    };
    const methods = discovery.token_endpoint_auth_methods_supported;
    if (methods && !methods.includes("client_secret_basic") && methods.includes("client_secret_post")) {
      form.set("client_id", this.config.clientId);
      form.set("client_secret", this.config.clientSecret);
    } else {
      // RFC 6749 §2.3.1: form-encode both parts before base64.
      const user = encodeURIComponent(this.config.clientId);
      const pass = encodeURIComponent(this.config.clientSecret);
      headers.authorization = `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}`;
    }
    const { status, body } = await this.getJson(discovery.token_endpoint, { method: "POST", headers, body: form.toString() });
    if (status !== 200 || !body) {
      const code = typeof body?.error === "string" ? body.error.slice(0, 64) : `status_${status}`;
      throw new OidcError("token_exchange_failed", `The identity provider refused the sign-in (${code})`);
    }
    const idToken = body.id_token;
    if (typeof idToken !== "string") throw new OidcError("id_token_missing", "The identity provider returned no id_token");
    return this.verifyIdToken(idToken, input.nonce, discovery);
  }

  private async keys(force: boolean, discovery: Discovery): Promise<JsonWebKey[]> {
    if (this.#jwks && (!force || this.now() - this.#jwks.fetchedAt < JWKS_REFRESH_FLOOR_MS)) {
      return this.#jwks.keys;
    }
    const { status, body } = await this.getJson(discovery.jwks_uri, { headers: { accept: "application/json" } });
    if (status !== 200 || !body || !Array.isArray(body.keys)) throw new OidcError("jwks_failed", `JWKS answered ${status}`);
    const keys = body.keys.filter((key): key is JsonWebKey => Boolean(key) && typeof key === "object");
    this.#jwks = { keys, fetchedAt: this.now() };
    return keys;
  }

  private async publicKey(kid: string | undefined, alg: string, discovery: Discovery): Promise<KeyObject> {
    const pick = (keys: JsonWebKey[]) => {
      const usable = keys.filter((key) =>
        (key.use === undefined || key.use === "sig") &&
        (key.alg === undefined || key.alg === alg));
      return kid === undefined
        ? (usable.length === 1 ? usable[0] : undefined)
        : usable.find((key) => (key as { kid?: string }).kid === kid);
    };
    let jwk = pick(await this.keys(false, discovery));
    // Key rotation: an unknown kid refetches the JWKS (at most once a minute).
    if (!jwk) jwk = pick(await this.keys(true, discovery));
    if (!jwk) throw new OidcError("id_token_invalid", "id_token is signed with an unknown key");
    try {
      return createPublicKey({ key: jwk, format: "jwk" });
    } catch {
      throw new OidcError("id_token_invalid", "The identity provider's signing key is unusable");
    }
  }

  async verifyIdToken(token: string, nonce: string, discovery?: Discovery): Promise<OidcIdentity> {
    const resolved = discovery ?? await this.discovery();
    const parts = token.split(".");
    if (parts.length !== 3) throw new OidcError("id_token_invalid", "id_token is not a JWS");
    const header = decodeJson(parts[0]!, "header");
    const claims = decodeJson(parts[1]!, "payload");
    const alg = typeof header.alg === "string" ? header.alg : "";
    const spec = ALGORITHMS[alg];
    // Never `none` or a shared-secret HS* algorithm.
    if (!spec) throw new OidcError("id_token_invalid", `id_token algorithm ${alg || "(none)"} is not accepted`);
    const key = await this.publicKey(typeof header.kid === "string" ? header.kid : undefined, alg, resolved);
    const data = Buffer.from(`${parts[0]}.${parts[1]}`);
    const signature = Buffer.from(parts[2]!, "base64url");
    let valid = false;
    try {
      valid = spec.kind === "ec"
        ? verifySignature(spec.hash, data, { key, dsaEncoding: "ieee-p1363" }, signature)
        : spec.kind === "pss"
          ? verifySignature(spec.hash, data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST }, signature)
          : verifySignature(spec.hash, data, key, signature);
    } catch {
      valid = false;
    }
    if (!valid) throw new OidcError("id_token_invalid", "id_token signature is invalid");

    const nowS = Math.floor(this.now() / 1_000);
    if (claims.iss !== resolved.issuer) throw new OidcError("id_token_invalid", "id_token issuer does not match");
    const aud = claims.aud;
    const audiences = Array.isArray(aud) ? aud : [aud];
    if (!audiences.includes(this.config.clientId)) throw new OidcError("id_token_invalid", "id_token audience does not match");
    if (audiences.length > 1 && claims.azp !== this.config.clientId) {
      throw new OidcError("id_token_invalid", "id_token authorized party does not match");
    }
    if (typeof claims.exp !== "number" || claims.exp + CLOCK_SKEW_S < nowS) throw new OidcError("id_token_expired", "id_token has expired");
    if (typeof claims.iat === "number" && claims.iat - CLOCK_SKEW_S > nowS) throw new OidcError("id_token_invalid", "id_token is issued in the future");
    if (claims.nonce !== nonce) throw new OidcError("id_token_invalid", "id_token nonce does not match this sign-in");
    if (typeof claims.sub !== "string" || !claims.sub) throw new OidcError("id_token_invalid", "id_token has no subject");

    const email = typeof claims.email === "string" ? claims.email.trim().toLowerCase() : "";
    if (!email) {
      throw new OidcError("email_missing", "Your identity provider did not share an email address. Ask your administrator to add the email claim.");
    }
    // Providers that send email_verified must mark it true. (Microsoft Entra
    // ID omits it; its email comes from the tenant directory.)
    if (claims.email_verified === false || claims.email_verified === "false") {
      throw new OidcError("email_unverified", "Your email address is not verified with your identity provider.");
    }
    const name = typeof claims.name === "string" && claims.name.trim()
      ? claims.name.trim()
      : [claims.given_name, claims.family_name].filter((part): part is string => typeof part === "string" && Boolean(part.trim())).join(" ") || null;
    // Only an explicit true counts as verified for operator-assigned domain
    // auto-join in multi mode (an absent claim is still allowed to sign in),
    // unless the operator trusts this issuer's directory. `iss` already
    // matched the configured issuer above.
    const emailVerified = claims.email_verified === true || claims.email_verified === "true"
      || (claims.email_verified === undefined && this.config.trustMissingEmailVerified);
    return { subject: claims.sub, email, name, emailVerified };
  }
}
