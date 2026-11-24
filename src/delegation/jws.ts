import { createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";

/**
 * Delegation attestation signing (relay docs/design/owner-trusted-delegates.md
 * §16.4): compact JWS, header {"alg":"EdDSA","typ":"relay-delegation+jws","kid"},
 * Ed25519. The public half is served as a JWKS of OKP keys at
 * /.well-known/relay-delegation-keys.json.
 */

export const DELEGATION_JWS_TYP = "relay-delegation+jws";
export const DELEGATION_JWKS_PATH = "/.well-known/relay-delegation-keys.json";

/** A published verification key: kid and the raw 32-byte public key, base64url. */
export type DelegationPublicKey = { kid: string; x: string };

export type DelegationSigningConfig = {
  kid: string;
  /** The 32-byte Ed25519 private seed. */
  seed: Buffer;
  /** Retired keys still published so attestations they signed keep verifying. */
  previous: DelegationPublicKey[];
};

export type Jwk = { kty: "OKP"; crv: "Ed25519"; x: string; kid: string; alg: "EdDSA"; use: "sig" };

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function privateKeyFromSeed(seed: Buffer): KeyObject {
  if (seed.byteLength !== 32) throw new Error("An Ed25519 seed is 32 bytes");
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
}

export function publicX(privateKey: KeyObject): string {
  const jwk = createPublicKey(privateKey).export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) throw new Error("Ed25519 public key export failed");
  return jwk.x;
}

export class DelegationSigner {
  readonly #key: KeyObject;
  readonly kid: string;
  readonly #jwks: Jwk[];

  constructor(config: DelegationSigningConfig) {
    this.#key = privateKeyFromSeed(config.seed);
    this.kid = config.kid;
    const keys = [{ kid: config.kid, x: publicX(this.#key) }, ...config.previous.filter(key => key.kid !== config.kid)];
    this.#jwks = keys.map(key => ({ kty: "OKP", crv: "Ed25519", x: key.x, kid: key.kid, alg: "EdDSA", use: "sig" }));
  }

  /** Signs `claims` as a compact JWS. */
  sign(claims: Record<string, unknown>): string {
    const header = { alg: "EdDSA", typ: DELEGATION_JWS_TYP, kid: this.kid };
    const input = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(claims))}`;
    const signature = sign(null, Buffer.from(input), this.#key);
    return `${input}.${signature.toString("base64url")}`;
  }

  jwks(): { keys: Jwk[] } {
    return { keys: this.#jwks.map(key => ({ ...key })) };
  }
}

function b64(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

/**
 * Verifies a compact JWS against a JWKS, as a relay-node does: the header
 * must be exactly EdDSA / relay-delegation+jws with a known kid. Returns the
 * claims, or null.
 */
export function verifyDelegationJws(jws: string, jwks: { keys: Array<Partial<Jwk>> }): Record<string, unknown> | null {
  const parts = jws.split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")) as Record<string, unknown>;
    if (header.alg !== "EdDSA" || header.typ !== DELEGATION_JWS_TYP || typeof header.kid !== "string") return null;
    const jwk = jwks.keys.find(key => key.kid === header.kid && key.kty === "OKP" && key.crv === "Ed25519");
    if (!jwk?.x) return null;
    const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
    const ok = verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), publicKey, Buffer.from(parts[2]!, "base64url"));
    if (!ok) return null;
    const claims = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as unknown;
    return claims && typeof claims === "object" && !Array.isArray(claims) ? claims as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
