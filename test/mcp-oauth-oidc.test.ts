import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash, createHmac, createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { createMcpOidcIssuer, createMcpOidcSigner, mcpOidcKeyId, type McpOidcConfiguration } from "../src/mcp/oauth/oidc.js";

// Ephemeral fixtures, never operator keys or customer credentials.
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const previousPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const configuration: McpOidcConfiguration = { keyId: "fake-active", privateKeyPem: pem, subjectSalt: "fake-subject-salt" };
const now = new Date("2026-01-01T00:00:00Z");
const input = { issuer: "https://relay.example.test/cloud", clientId: "mcpc_fake", sectorIdentifier: "chat.example.test",
  userId: "fake-user", accessToken: "fake-access", nonce: "fake-nonce", now };

function decode(token: string, part: number): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[part]!, "base64url").toString("utf8"));
}

test("Cloud RS256 payload, pairwise subject, at_hash, nonce and five-minute TTL are retained", () => {
  const issuer = createMcpOidcIssuer(configuration);
  const token = issuer.issueMcpOidcIdToken(input);
  const [header, payload, signature] = token.split(".");
  assert.equal(verify("RSA-SHA256", Buffer.from(`${header}.${payload}`, "ascii"), pair.publicKey,
    Buffer.from(signature!, "base64url")), true);
  assert.deepEqual(decode(token, 0), { alg: "RS256", typ: "JWT", kid: "fake-active" });
  assert.deepEqual(decode(token, 1), {
    iss: input.issuer,
    sub: createHmac("sha256", configuration.subjectSalt).update(`${input.issuer}\u0000${input.sectorIdentifier}\u0000${input.userId}`).digest("base64url"),
    aud: input.clientId, exp: now.getTime() / 1000 + 300, iat: now.getTime() / 1000,
    at_hash: createHash("sha256").update(input.accessToken).digest().subarray(0, 16).toString("base64url"), nonce: input.nonce,
  });
  const jwk = issuer.mcpOidcJwks(now).keys[0]!;
  assert.equal(verify("RSA-SHA256", Buffer.from(`${header}.${payload}`, "ascii"),
    createPublicKey({ key: jwk, format: "jwk" }), Buffer.from(signature!, "base64url")), true);
});

test("pairwise subjects preserve same sector and isolate user, issuer, salt and sector", () => {
  const issuer = createMcpOidcIssuer(configuration);
  const subject = (changes = {}) => decode(issuer.issueMcpOidcIdToken({ ...input, ...changes }), 1).sub;
  assert.equal(subject(), subject({ clientId: "mcpc_another" }));
  for (const change of [{ userId: "fake-other" }, { issuer: "https://other.example.test/cloud" }, { sectorIdentifier: "other.example.test" }]) {
    assert.notEqual(subject(), subject(change));
  }
  assert.notEqual(subject(), decode(createMcpOidcIssuer({ ...configuration, subjectSalt: "fake-other-salt" }).issueMcpOidcIdToken(input), 1).sub);
  assert.equal(Object.hasOwn(decode(issuer.issueMcpOidcIdToken({ ...input, nonce: null }), 1), "nonce"), false);
});

test("Cloud thumbprint kid remains available for continuity; explicit operator kid is honored", () => {
  const jwk = pair.publicKey.export({ format: "jwk" });
  const expected = createHash("sha256").update(JSON.stringify({ e: jwk.e, kty: "RSA", n: jwk.n })).digest("base64url");
  assert.equal(mcpOidcKeyId(jwk), expected);
  assert.equal(createMcpOidcSigner(pem).publicJwk.kid, expected);
  assert.equal(createMcpOidcSigner(pem, "fake-operator").publicJwk.kid, "fake-operator");
});

test("JWKS retains unexpired previous public keys, validates and snapshots caller configuration", () => {
  const publicJwk = previousPair.publicKey.export({ format: "jwk" });
  const previous = [{ kid: "fake-previous", publicJwk, expiresAt: "2026-01-02T00:00:00Z" }];
  const issuer = createMcpOidcIssuer({ ...configuration, previousPublicKeys: previous });
  previous[0]!.kid = "fake-changed";
  publicJwk.n = "fake-changed";
  assert.deepEqual(issuer.mcpOidcJwks(now).keys.map(key => key.kid), ["fake-active", "fake-previous"]);
  assert.deepEqual(issuer.mcpOidcJwks(new Date("2026-01-02T00:00:00Z")).keys.map(key => key.kid), ["fake-active"]);
  const keys = issuer.mcpOidcJwks(now).keys;
  keys[0]!.kid = "fake-returned-mutation";
  assert.equal(decode(issuer.issueMcpOidcIdToken(input), 0).kid, "fake-active");
  for (const key of issuer.mcpOidcJwks(now).keys) {
    assert.deepEqual(Object.keys(key).sort(), ["alg", "e", "kid", "kty", "n", "use"]);
  }
});

test("invalid, weak, duplicate, private or unbounded key configurations fail closed", () => {
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  for (const key of [weak.privateKey, ec.privateKey]) {
    assert.throws(() => createMcpOidcSigner(key.export({ type: "pkcs8", format: "pem" }).toString()), /RSA/);
  }
  for (const keyId of ["", "bad\nkid", "é", "x".repeat(129)]) assert.throws(() => createMcpOidcIssuer({ ...configuration, keyId }));
  assert.throws(() => createMcpOidcIssuer({ ...configuration, subjectSalt: " " }), /salt/);
  const publicJwk = previousPair.publicKey.export({ format: "jwk" });
  const entry = { kid: "fake-previous", publicJwk, expiresAt: "2026-01-02T00:00:00Z" };
  for (const previousPublicKeys of [[{ ...entry, kid: configuration.keyId }], [entry, entry], [entry, entry, entry],
    [{ ...entry, expiresAt: "invalid" }], [{ ...entry, publicJwk: previousPair.privateKey.export({ format: "jwk" }) }],
    [{ ...entry, publicJwk: { ...publicJwk, p: "fake-private" } }]]) {
    assert.throws(() => createMcpOidcIssuer({ ...configuration, previousPublicKeys }));
  }
});
