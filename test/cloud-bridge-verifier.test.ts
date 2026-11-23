import assert from "node:assert/strict";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  CloudBridgeAssertionError,
  parseCloudBridgeConfig,
  verifyCloudBridgeAssertion,
  type CloudBridgeConfig,
  type CloudBridgeRawConfig,
} from "../src/identity/cloud-bridge.js";
import { loadIdentityConfig } from "../src/identity/config.js";

// Pure checks of the session bridge verifier and its settings
// (docs/identity.md). The routes and the store are covered, against a
// database, in cloud-bridge.test.ts.

const ISSUER = "https://cloud.example.test";
const AUDIENCE = "https://control.example.test/cloud";
const HANDOFF_URL = "https://cloud.example.test/bridge/handoff";
const KID = "test-key-1";

function keyPair() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey, jwk: publicKey.export({ format: "jwk" }) as Record<string, unknown> };
}

const PRIMARY = keyPair();
const OTHER = keyPair();

function raw(overrides: Partial<CloudBridgeRawConfig> = {}): CloudBridgeRawConfig {
  return {
    issuer: ISSUER,
    audience: AUDIENCE,
    handoffUrl: HANDOFF_URL,
    publicKeys: JSON.stringify({ keys: [{ ...PRIMARY.jwk, kid: KID }] }),
    maxAuthAgeSeconds: undefined,
    ...overrides,
  };
}

const CONFIG: CloudBridgeConfig = parseCloudBridgeConfig(raw());
const NOW_MS = 1_800_000_000_000;
const NOW = NOW_MS / 1_000;

function part(value: unknown): string {
  return Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");
}

function jws(header: Record<string, unknown>, payload: unknown, key: KeyObject = PRIMARY.privateKey): string {
  const signingInput = `${part(header)}.${part(payload)}`;
  return `${signingInput}.${sign(null, Buffer.from(signingInput), key).toString("base64url")}`;
}

const HEADER = { alg: "EdDSA", typ: "cloud-bridge+jwt", kid: KID };

function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const base: Record<string, unknown> = {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: "user-1",
    org_id: "org-1",
    workspace_id: "workspace-1",
    auth_time: NOW - 600,
    auth_method: "password",
    use: "browser",
    nonce: "nonce-value",
    jti: "jti-1",
    iat: NOW - 10,
    exp: NOW + 50,
    email: "person@example.test",
  };
  for (const [name, value] of Object.entries(overrides)) {
    if (value === undefined) delete base[name];
    else base[name] = value;
  }
  return base;
}

function refusal(token: string, config: CloudBridgeConfig = CONFIG, nowMs = NOW_MS): CloudBridgeAssertionError {
  try {
    verifyCloudBridgeAssertion(token, config, nowMs);
  } catch (error) {
    assert(error instanceof CloudBridgeAssertionError, `unexpected error ${String(error)}`);
    return error;
  }
  assert.fail("the assertion verified");
}

/** Changes one character in the middle of a base64url segment, which keeps it canonical. */
function flipMiddle(segment: string): string {
  const index = Math.floor(segment.length / 2);
  const replacement = segment[index] === "A" ? "B" : "A";
  return `${segment.slice(0, index)}${replacement}${segment.slice(index + 1)}`;
}

// ---- settings ---------------------------------------------------------------------

test("cloud bridge settings: off unless exactly true, and every required value is checked", () => {
  assert.equal(loadIdentityConfig({}).cloudBridge, null);
  assert.equal(loadIdentityConfig({ SELFHOST_CLOUD_BRIDGE_ENABLED: "false" }).cloudBridge, null);
  // When off, the other values are not read at all.
  assert.equal(loadIdentityConfig({ SELFHOST_CLOUD_BRIDGE_ENABLED: "false", SELFHOST_CLOUD_BRIDGE_PUBLIC_KEYS: "not json" }).cloudBridge, null);
  for (const value of ["TRUE", "1", "yes", "on", "False"]) {
    assert.throws(() => loadIdentityConfig({ SELFHOST_CLOUD_BRIDGE_ENABLED: value }), /SELFHOST_CLOUD_BRIDGE_ENABLED must be true or false/, value);
  }
  const env = {
    SELFHOST_CLOUD_BRIDGE_ENABLED: "true",
    SELFHOST_CLOUD_BRIDGE_ISSUER: ISSUER,
    SELFHOST_CLOUD_BRIDGE_AUDIENCE: AUDIENCE,
    SELFHOST_CLOUD_BRIDGE_HANDOFF_URL: HANDOFF_URL,
    SELFHOST_CLOUD_BRIDGE_PUBLIC_KEYS: JSON.stringify({ keys: [{ ...PRIMARY.jwk, kid: KID }] }),
  };
  const loaded = loadIdentityConfig(env).cloudBridge!;
  assert.equal(loaded.issuer, ISSUER);
  assert.equal(loaded.audience, AUDIENCE);
  assert.equal(loaded.handoffOrigin, "https://cloud.example.test");
  assert.equal(loaded.maxAuthAgeSeconds, 2_592_000);
  assert.deepEqual([...loaded.keys.keys()], [KID]);
  for (const name of ["SELFHOST_CLOUD_BRIDGE_ISSUER", "SELFHOST_CLOUD_BRIDGE_AUDIENCE", "SELFHOST_CLOUD_BRIDGE_HANDOFF_URL", "SELFHOST_CLOUD_BRIDGE_PUBLIC_KEYS"]) {
    assert.throws(() => loadIdentityConfig({ ...env, [name]: "" }), new RegExp(`${name} is required`), name);
  }
});

test("cloud bridge settings: handoff URL is https (http on loopback only) with no query, fragment or credentials", () => {
  assert.equal(parseCloudBridgeConfig(raw({ handoffUrl: "http://localhost:4000/handoff" })).handoffOrigin, "http://localhost:4000");
  assert.equal(parseCloudBridgeConfig(raw({ handoffUrl: "http://127.0.0.1/handoff" })).handoffOrigin, "http://127.0.0.1");
  for (const handoffUrl of [
    "http://cloud.example.test/handoff",
    "/bridge/handoff",
    "https://cloud.example.test/handoff?x=1",
    "https://cloud.example.test/handoff?",
    "https://cloud.example.test/handoff#top",
    "https://user:pass@cloud.example.test/handoff",
    "ftp://cloud.example.test/handoff",
  ]) {
    assert.throws(() => parseCloudBridgeConfig(raw({ handoffUrl })), /SELFHOST_CLOUD_BRIDGE_HANDOFF_URL/, handoffUrl);
  }
});

test("cloud bridge settings: the JWKS holds 1-4 public Ed25519 keys with unique kids", () => {
  const key = { ...PRIMARY.jwk, kid: KID };
  const keys = (list: unknown[]) => JSON.stringify({ keys: list });
  const refused: Array<[string, string, RegExp]> = [
    ["not JSON", "not json", /must be a JWKS/],
    ["a bare array", JSON.stringify([key]), /must hold 1 to 4 keys/],
    ["no keys", keys([]), /must hold 1 to 4 keys/],
    ["five keys", keys([1, 2, 3, 4, 5].map((n) => ({ ...keyPair().jwk, kid: `k${n}` }))), /must hold 1 to 4 keys/],
    ["a private key", keys([{ ...(PRIMARY.privateKey.export({ format: "jwk" }) as object), kid: KID }]), /public keys only/],
    ["an RSA key", keys([{ ...(generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "jwk" }) as object), kid: KID }]), /kty OKP, crv Ed25519/],
    ["an X25519 key", keys([{ ...(generateKeyPairSync("x25519").publicKey.export({ format: "jwk" }) as object), kid: KID }]), /kty OKP, crv Ed25519/],
    ["no kid", keys([PRIMARY.jwk]), /non-empty kid/],
    ["a blank kid", keys([{ ...PRIMARY.jwk, kid: " " }]), /non-empty kid/],
    ["a duplicate kid", keys([key, { ...OTHER.jwk, kid: KID }]), /appears more than once/],
    ["another alg", keys([{ ...key, alg: "RS256" }]), /alg must be EdDSA/],
    ["no x", keys([{ kty: "OKP", crv: "Ed25519", kid: KID }]), /public "x" member/],
    ["a bad x", keys([{ ...key, x: "AAAA" }]), /not a valid Ed25519 public key/],
  ];
  for (const [label, publicKeys, message] of refused) {
    assert.throws(() => parseCloudBridgeConfig(raw({ publicKeys })), message, label);
  }
  const four = parseCloudBridgeConfig(raw({ publicKeys: keys([key, { ...OTHER.jwk, kid: "k2" }, { ...keyPair().jwk, kid: "k3" }, { ...keyPair().jwk, kid: "k4", alg: "EdDSA" }]) }));
  assert.deepEqual([...four.keys.keys()], [KID, "k2", "k3", "k4"]);
});

test("cloud bridge settings: the maximum auth age defaults to 30 days and is capped at 90", () => {
  assert.equal(parseCloudBridgeConfig(raw()).maxAuthAgeSeconds, 2_592_000);
  assert.equal(parseCloudBridgeConfig(raw({ maxAuthAgeSeconds: "3600" })).maxAuthAgeSeconds, 3_600);
  assert.equal(parseCloudBridgeConfig(raw({ maxAuthAgeSeconds: "7776000" })).maxAuthAgeSeconds, 7_776_000);
  for (const value of ["0", "7776001", "1.5", "-1", "1e3", "ten"]) {
    assert.throws(() => parseCloudBridgeConfig(raw({ maxAuthAgeSeconds: value })), /MAX_AUTH_AGE_SECONDS must be an integer/, value);
  }
});

// ---- verifier -----------------------------------------------------------------------

test("cloud bridge verifier: a well-formed assertion verifies; email is never returned", () => {
  const verified = verifyCloudBridgeAssertion(jws(HEADER, claims()), CONFIG, NOW_MS);
  assert.deepEqual(verified, {
    kid: KID,
    sub: "user-1",
    orgId: "org-1",
    workspaceId: "workspace-1",
    authTime: NOW - 600,
    authMethod: "password",
    use: "browser",
    nonce: "nonce-value",
    jti: "jti-1",
    iat: NOW - 10,
    exp: NOW + 50,
  });
  // workspace_id, auth_method and email are optional; nbf within the skew is fine.
  const minimal = verifyCloudBridgeAssertion(
    jws(HEADER, claims({ workspace_id: undefined, auth_method: undefined, email: undefined, nbf: NOW + 25 })),
    CONFIG,
    NOW_MS,
  );
  assert.equal(minimal.workspaceId, null);
  assert.equal(minimal.authMethod, null);
  // A second configured key verifies under its own kid (rotation).
  const rotated = parseCloudBridgeConfig(raw({ publicKeys: JSON.stringify({ keys: [{ ...PRIMARY.jwk, kid: KID }, { ...OTHER.jwk, kid: "k2" }] }) }));
  assert.equal(verifyCloudBridgeAssertion(jws({ ...HEADER, kid: "k2" }, claims(), OTHER.privateKey), rotated, NOW_MS).kid, "k2");
});

test("cloud bridge verifier: header and signature refusals carry no claims", () => {
  const token = jws(HEADER, claims());
  const [header, payload, signature] = token.split(".") as [string, string, string];
  const cases: Array<[string, string, string]> = [
    ["two parts", `${header}.${payload}`, "malformed"],
    ["four parts", `${token}.x`, "malformed"],
    ["oversized", `${header}.${"A".repeat(4_100)}.${signature}`, "malformed"],
    ["non-base64url header", `${header}=.${payload}.${signature}`, "malformed"],
    ["header not JSON", `${part("not json")}.${payload}.${signature}`, "malformed"],
    ["header an array", `${part([1])}.${payload}.${signature}`, "malformed"],
    ["alg none", jws({ ...HEADER, alg: "none" }, claims()), "wrong_alg"],
    ["alg RS256", jws({ ...HEADER, alg: "RS256" }, claims()), "wrong_alg"],
    ["no alg", jws({ typ: HEADER.typ, kid: KID }, claims()), "wrong_alg"],
    ["typ JWT", jws({ ...HEADER, typ: "JWT" }, claims()), "wrong_type"],
    ["no typ", jws({ alg: "EdDSA", kid: KID }, claims()), "wrong_type"],
    ["crit", jws({ ...HEADER, crit: ["exp"] }, claims()), "malformed"],
    ["no kid", jws({ alg: "EdDSA", typ: HEADER.typ }, claims()), "unknown_kid"],
    ["unknown kid", jws({ ...HEADER, kid: "someone-else" }, claims()), "unknown_kid"],
    ["wrong key under a known kid", jws(HEADER, claims(), OTHER.privateKey), "bad_signature"],
    ["changed payload", `${header}.${flipMiddle(payload)}.${signature}`, "bad_signature"],
    ["changed signature", `${header}.${payload}.${flipMiddle(signature)}`, "bad_signature"],
    ["short signature", `${header}.${payload}.${signature.slice(0, 40)}`, "bad_signature"],
    ["no signature", `${header}.${payload}.`, "malformed"],
  ];
  for (const [label, candidate, reason] of cases) {
    const error = refusal(candidate);
    assert.equal(error.reason, reason, label);
    assert.equal(error.verified, null, `${label}: claims of an unverified assertion are never exposed`);
  }
  assert.equal(refusal(jws({ ...HEADER, kid: "someone-else" }, claims())).kid, "someone-else");
});

test("cloud bridge verifier: claim refusals after the signature verified name sub, org and jti", () => {
  const cases: Array<[string, Record<string, unknown>, string]> = [
    ["other issuer", { iss: "https://elsewhere.example.test" }, "wrong_issuer"],
    ["no issuer", { iss: undefined }, "wrong_issuer"],
    ["other audience", { aud: "https://elsewhere.example.test" }, "wrong_audience"],
    ["audience array", { aud: [AUDIENCE] }, "wrong_audience"],
    ["desktop use", { use: "desktop_refresh" }, "wrong_use"],
    ["no use", { use: undefined }, "wrong_use"],
    ["no sub", { sub: undefined }, "malformed"],
    ["empty sub", { sub: "" }, "malformed"],
    ["no org", { org_id: undefined }, "malformed"],
    ["no nonce", { nonce: undefined }, "malformed"],
    ["no jti", { jti: undefined }, "malformed"],
    ["jti too long", { jti: "j".repeat(129) }, "malformed"],
    ["no auth_time", { auth_time: undefined }, "malformed"],
    ["auth_time as text", { auth_time: "1790000000" }, "malformed"],
    ["no iat", { iat: undefined }, "malformed"],
    ["no exp", { exp: undefined }, "malformed"],
    ["numeric workspace", { workspace_id: 7 }, "malformed"],
    ["numeric auth_method", { auth_method: 7 }, "malformed"],
    ["lifetime 121 s", { iat: NOW - 10, exp: NOW + 111 }, "lifetime_too_long"],
    ["exp before iat", { iat: NOW, exp: NOW - 1 }, "lifetime_too_long"],
    ["iat in the future", { iat: NOW + 31, exp: NOW + 60 }, "not_yet_valid"],
    ["nbf in the future", { nbf: NOW + 31 }, "not_yet_valid"],
    ["nbf as text", { nbf: "soon" }, "not_yet_valid"],
    ["expired beyond the skew", { iat: NOW - 100, exp: NOW - 30 }, "expired"],
  ];
  for (const [label, overrides, reason] of cases) {
    const error = refusal(jws(HEADER, claims(overrides)));
    assert.equal(error.reason, reason, label);
    assert.equal(error.kid, KID, label);
    assert(error.verified, `${label}: verified`);
    assert.equal(error.verified.orgId, overrides.org_id === undefined && "org_id" in overrides ? null : "org-1", label);
  }
  // Boundaries that still verify: exactly 120 s of lifetime, exp inside the skew.
  assert.equal(verifyCloudBridgeAssertion(jws(HEADER, claims({ iat: NOW - 10, exp: NOW + 110 })), CONFIG, NOW_MS).exp, NOW + 110);
  assert.equal(verifyCloudBridgeAssertion(jws(HEADER, claims({ iat: NOW - 100, exp: NOW - 29 })), CONFIG, NOW_MS).exp, NOW - 29);
  // A payload that is not an object verified but names nobody.
  const notObject = refusal(jws(HEADER, [1, 2]));
  assert.equal(notObject.reason, "malformed");
  assert.deepEqual(notObject.verified, { sub: null, orgId: null, jti: null });
});

// ---- contract fixture ---------------------------------------------------------------
// test/fixtures/cloud-bridge-contract.json is byte-identical to the signer's
// copy in Cloud: an assertion made by Cloud's code with a throwaway key whose
// private half was discarded. These tests pin both sides to the same wire.

type ContractFixture = {
  jwks: { keys: unknown[] };
  claims: Record<string, string | number>;
  assertion: string;
};

const FIXTURE = JSON.parse(readFileSync(new URL("./fixtures/cloud-bridge-contract.json", import.meta.url), "utf8")) as ContractFixture;

function contractConfig(overrides: Partial<CloudBridgeRawConfig> = {}): CloudBridgeConfig {
  return parseCloudBridgeConfig({
    issuer: "agentrelay-cloud",
    audience: "https://agentrelay.com/cloud",
    handoffUrl: "https://cloud.example.test/bridge/handoff",
    publicKeys: JSON.stringify(FIXTURE.jwks),
    maxAuthAgeSeconds: undefined,
    ...overrides,
  });
}

test("cloud bridge contract: Cloud's fixture assertion verifies inside its lifetime", () => {
  const verified = verifyCloudBridgeAssertion(FIXTURE.assertion, contractConfig(), 1_790_000_120_000);
  assert.deepEqual(
    {
      sub: verified.sub,
      org_id: verified.orgId,
      workspace_id: verified.workspaceId,
      auth_time: verified.authTime,
      use: verified.use,
      nonce: verified.nonce,
      jti: verified.jti,
      iat: verified.iat,
      exp: verified.exp,
    },
    {
      sub: FIXTURE.claims.sub,
      org_id: FIXTURE.claims.org_id,
      workspace_id: FIXTURE.claims.workspace_id,
      auth_time: FIXTURE.claims.auth_time,
      use: FIXTURE.claims.use,
      nonce: FIXTURE.claims.nonce,
      jti: FIXTURE.claims.jti,
      iat: FIXTURE.claims.iat,
      exp: FIXTURE.claims.exp,
    },
  );
  assert.equal(verified.kid, "JUQ6GP3ifr-p-PgHPhLG7OswY1LR6xFboorZyd2Zfgc");
  assert.equal(verified.sub, "fixture-user-0001");
  assert.equal(verified.authMethod, null);
});

test("cloud bridge contract: the fixture assertion is expired at the real time", () => {
  assert.equal(refusal(FIXTURE.assertion, contractConfig(), Date.now()).reason, "expired");
});

test("cloud bridge contract: changing one character of the signature or payload refuses it", () => {
  const [header, payload, signature] = FIXTURE.assertion.split(".") as [string, string, string];
  const at = 1_790_000_120_000;
  assert.equal(refusal(`${header}.${payload}.${flipMiddle(signature)}`, contractConfig(), at).reason, "bad_signature");
  assert.equal(refusal(`${header}.${flipMiddle(payload)}.${signature}`, contractConfig(), at).reason, "bad_signature");
});

test("cloud bridge contract: a different audience or issuer refuses it", () => {
  const at = 1_790_000_120_000;
  assert.equal(refusal(FIXTURE.assertion, contractConfig({ audience: "https://elsewhere.example.test/cloud" }), at).reason, "wrong_audience");
  assert.equal(refusal(FIXTURE.assertion, contractConfig({ issuer: "another-issuer" }), at).reason, "wrong_issuer");
});
