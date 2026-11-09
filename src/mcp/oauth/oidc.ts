/**
 * Port of Cloud 1776499a packages/web/lib/auth/mcp-oidc.ts.
 * RS256, pairwise subject, at_hash and ID-token TTL retain the source logic.
 * The caller supplies operator key configuration instead of reading SST.
 * This module mounts no routes and reads no environment or database state.
 */
import {
  createHash, createHmac, createPrivateKey, createPublicKey, sign,
  type JsonWebKey, type KeyObject,
} from "node:crypto";

type OidcPublicJwk = JsonWebKey & { alg: "RS256"; kid: string; use: "sig" };
type OidcSigner = { privateKey: KeyObject; publicJwk: OidcPublicJwk };

export type McpOidcConfiguration = {
  keyId: string;
  privateKeyPem: string;
  subjectSalt: string;
  previousPublicKeys?: ReadonlyArray<{
    kid: string;
    publicJwk: JsonWebKey;
    expiresAt: string;
  }>;
};

function base64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

/** Cloud's JWK thumbprint; operators can retain it as the existing kid. */
export function mcpOidcKeyId(jwk: JsonWebKey): string {
  if (jwk.kty !== "RSA" || !jwk.e || !jwk.n) throw new Error("MCP OIDC signing key must be RSA");
  return createHash("sha256")
    .update(JSON.stringify({ e: jwk.e, kty: "RSA", n: jwk.n }))
    .digest("base64url");
}

function validateKeyId(kid: string): void {
  if (typeof kid !== "string" || !kid || kid.length > 128 || !/^[\x21-\x7e]+$/.test(kid)) {
    throw new Error("MCP OIDC key id must be bounded printable ASCII");
  }
}

export function createMcpOidcSigner(privateKeyPem: string, kid?: string): OidcSigner {
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "rsa" || (privateKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new Error("MCP OIDC signing key must be an RSA key of at least 2048 bits");
  }
  const exported = createPublicKey(privateKey).export({ format: "jwk" });
  const keyId = kid ?? mcpOidcKeyId(exported);
  validateKeyId(keyId);
  return {
    privateKey,
    publicJwk: { kty: "RSA", n: exported.n!, e: exported.e!, alg: "RS256", use: "sig", kid: keyId },
  };
}

function normalizePublicJwk(value: JsonWebKey, kid: string): OidcPublicJwk {
  validateKeyId(kid);
  if (!value || typeof value !== "object" || Array.isArray(value) || value.kty !== "RSA" || !value.e || !value.n ||
      ["d", "p", "q", "dp", "dq", "qi", "oth", "k"].some(key => Object.hasOwn(value, key))) {
    throw new Error("MCP OIDC previous key must be a public RSA JWK");
  }
  const publicKey = createPublicKey({ key: value, format: "jwk" });
  if (publicKey.asymmetricKeyType !== "rsa" || (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new Error("MCP OIDC previous key must be an RSA key of at least 2048 bits");
  }
  const exported = publicKey.export({ format: "jwk" });
  return { kty: "RSA", n: exported.n!, e: exported.e!, alg: "RS256", use: "sig", kid };
}

function pairwiseSubject(subjectSalt: string, issuer: string, sectorIdentifier: string, userId: string): string {
  return createHmac("sha256", subjectSalt)
    .update(`${issuer}\u0000${sectorIdentifier}\u0000${userId}`)
    .digest("base64url");
}

function accessTokenHash(accessToken: string): string {
  return createHash("sha256").update(accessToken).digest().subarray(0, 16).toString("base64url");
}

export type McpOidcIdTokenInput = {
  issuer: string;
  clientId: string;
  sectorIdentifier: string;
  userId: string;
  accessToken: string;
  nonce: string | null;
  now?: Date;
};

/** Per-instance keys avoid process-global key or salt selection across issuers. */
export function createMcpOidcIssuer(configuration: McpOidcConfiguration) {
  validateKeyId(configuration.keyId);
  if (!configuration.subjectSalt?.trim()) throw new Error("MCP OIDC subject salt is not configured");
  const signer = createMcpOidcSigner(configuration.privateKeyPem, configuration.keyId);
  const subjectSalt = configuration.subjectSalt;
  const previousInput = configuration.previousPublicKeys ?? [];
  // Retain the source's bounded key ring; expired keys still undergo validation.
  if (!Array.isArray(previousInput) || previousInput.length > 2) throw new Error("MCP OIDC allows at most two previous keys");
  const ids = new Set([configuration.keyId]);
  const materials = new Set([mcpOidcKeyId(signer.publicJwk)]);
  const previous = previousInput.map(entry => {
    if (!entry || typeof entry !== "object") throw new Error("MCP OIDC previous key is invalid");
    const key = normalizePublicJwk(entry.publicJwk, entry.kid);
    if (ids.has(key.kid)) throw new Error("MCP OIDC key ids must be unique");
    ids.add(key.kid);
    const material=mcpOidcKeyId(key);
    if(materials.has(material)) throw new Error("MCP OIDC key material must be unique across key ids");
    materials.add(material);
    const expiresAt = Date.parse(entry.expiresAt);
    if (!Number.isFinite(expiresAt)) throw new Error("MCP OIDC previous key expiry is invalid");
    return { key, expiresAt };
  });

  function mcpOidcJwks(now = new Date()) {
    return { keys: [signer.publicJwk, ...previous.filter(entry => entry.expiresAt > now.getTime()).map(entry => entry.key)]
      .map(key => ({ ...key })) };
  }

  function issueMcpOidcIdToken(input: McpOidcIdTokenInput): string {
    const issuedAt = Math.floor((input.now ?? new Date()).getTime() / 1000);
    const payload = {
      iss: input.issuer,
      sub: pairwiseSubject(subjectSalt, input.issuer, input.sectorIdentifier, input.userId),
      aud: input.clientId,
      exp: issuedAt + 5 * 60,
      iat: issuedAt,
      at_hash: accessTokenHash(input.accessToken),
      ...(input.nonce ? { nonce: input.nonce } : {}),
    };
    const header = { alg: "RS256", typ: "JWT", kid: signer.publicJwk.kid };
    const signingInput = `${base64urlJson(header)}.${base64urlJson(payload)}`;
    const signature = sign("RSA-SHA256", Buffer.from(signingInput, "ascii"), signer.privateKey).toString("base64url");
    return `${signingInput}.${signature}`;
  }

  return { mcpOidcJwks, issueMcpOidcIdToken };
}
