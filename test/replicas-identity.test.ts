import assert from "node:assert/strict";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import test from "node:test";
import { createReplicaIdentityVerifier, emailHint, ReplicaIdentityError, ReplicaIdentityUnavailable } from "../src/replicas/identity.js";

const ISSUER = "https://api.replicas.dev";
const AUDIENCE = "https://control.selfhosted.company/api/v1/replicas/mcp";
const ORG = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ENV = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const WS = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

const pair = () => generateKeyPairSync("rsa", { modulusLength: 2048 });
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");

function jwt(privateKey: KeyObject, claims: Record<string, unknown>, header: Record<string, unknown> = { alg: "RS256", kid: "k1", typ: "JWT" }) {
  const signing = `${b64(header)}.${b64(claims)}`;
  return `${signing}.${sign("RSA-SHA256", Buffer.from(signing), privateKey).toString("base64url")}`;
}

function issuerFetch(keys: () => Array<{ kid: string; publicKey: KeyObject }>, options: { jwksUri?: string; issuer?: string } = {}) {
  const requests: string[] = [];
  const impl = (async (input: string | URL | Request) => {
    const url = String(input);
    requests.push(url);
    if (url === `${ISSUER}/.well-known/openid-configuration`) {
      return Response.json({ issuer: options.issuer ?? ISSUER, jwks_uri: options.jwksUri ?? `${ISSUER}/.well-known/jwks.json` });
    }
    if (url === `${ISSUER}/.well-known/jwks.json` || url === options.jwksUri) {
      return Response.json({ keys: keys().map(({ kid, publicKey }) => ({ ...publicKey.export({ format: "jwk" }), kid, use: "sig", alg: "RS256" })) });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  return { impl, requests };
}

function setup(overrides: { jwksUri?: string; issuer?: string } = {}) {
  const first = pair();
  let current = [{ kid: "k1", ...first }];
  let clock = Date.parse("2026-11-16T12:00:00Z");
  const fetched = issuerFetch(() => current, overrides);
  const verifier = createReplicaIdentityVerifier({ issuer: ISSUER, audience: AUDIENCE, fetchImpl: fetched.impl, now: () => new Date(clock) });
  const seconds = () => Math.floor(clock / 1000);
  const claims = (extra: Record<string, unknown> = {}) => ({
    iss: ISSUER, aud: AUDIENCE, exp: seconds() + 300, iat: seconds(), nbf: seconds(), jti: "jti-1",
    organization_id: ORG, environment_id: ENV, workspace_id: WS.toUpperCase(), creator_id: "creator-1",
    creator_email: "person@example.com", ...extra,
  });
  return {
    verifier, fetched, claims, first,
    advance: (ms: number) => { clock += ms; },
    rotate: (kid: string) => { const next = { kid, ...pair() }; current = [next]; return next; },
  };
}

const rejects = (promise: Promise<unknown>) => assert.rejects(promise, (error: unknown) =>
  error instanceof ReplicaIdentityError && error.message === "replica_identity_invalid");

test("a valid token yields normalized claims", async () => {
  const { verifier, claims, first } = setup();
  const result = await verifier.verify(jwt(first.privateKey, claims()));
  assert.deepEqual(result, {
    issuer: ISSUER, organizationId: ORG, environmentId: ENV, workspaceId: WS, creatorId: "creator-1",
    creatorEmail: "person@example.com", jti: "jti-1",
  });
  // A null creator is a valid token (admission refuses it later); a one-element aud array is accepted.
  assert.equal((await verifier.verify(jwt(first.privateKey, claims({ creator_id: null, aud: [AUDIENCE] })))).creatorId, null);
});

test("signature, algorithm, issuer, audience and claim checks fail closed", async () => {
  const { verifier, claims, first } = setup();
  const other = pair();
  await rejects(verifier.verify(jwt(other.privateKey, claims())));
  await rejects(verifier.verify(jwt(first.privateKey, claims(), { alg: "HS256", kid: "k1" })));
  await rejects(verifier.verify(jwt(first.privateKey, claims(), { alg: "none", kid: "k1" })));
  await rejects(verifier.verify(jwt(first.privateKey, claims(), { alg: "RS256" })));
  await rejects(verifier.verify(jwt(first.privateKey, claims({ iss: "https://api.replicas.dev/" }))));
  await rejects(verifier.verify(jwt(first.privateKey, claims({ aud: "https://control.selfhosted.company/api/v1/mcp" }))));
  await rejects(verifier.verify(jwt(first.privateKey, claims({ aud: [AUDIENCE, "other"] }))));
  for (const name of ["organization_id", "environment_id", "workspace_id"]) {
    await rejects(verifier.verify(jwt(first.privateKey, claims({ [name]: "not-a-uuid" }))));
    await rejects(verifier.verify(jwt(first.privateKey, { ...claims(), [name]: undefined })));
  }
  const { creator_id: _creator, ...withoutCreator } = claims();
  await rejects(verifier.verify(jwt(first.privateKey, withoutCreator)));
  await rejects(verifier.verify(jwt(first.privateKey, claims({ creator_id: 7 }))));
  await rejects(verifier.verify(jwt(first.privateKey, claims({ jti: "" }))));
  await rejects(verifier.verify(jwt(first.privateKey, claims({ exp: undefined }))));
  await rejects(verifier.verify("a.b"));
  await rejects(verifier.verify("x".repeat(9000)));
  const token = jwt(first.privateKey, claims());
  await rejects(verifier.verify(`${token.slice(0, -2)}AA`));
});

test("exp and nbf allow thirty seconds of skew", async () => {
  const { verifier, claims, first, advance } = setup();
  const base = claims();
  await verifier.verify(jwt(first.privateKey, { ...base, nbf: (base.nbf as number) + 25 }));
  await rejects(verifier.verify(jwt(first.privateKey, { ...base, nbf: (base.nbf as number) + 40 })));
  const expiring = jwt(first.privateKey, { ...base, exp: (base.iat as number) + 10 });
  advance(35_000);
  await verifier.verify(expiring);
  advance(10_000);
  await rejects(verifier.verify(expiring));
});

test("keys are cached by kid, an unknown kid refetches once, the TTL forces a refresh", async () => {
  const { verifier, claims, first, fetched, rotate, advance } = setup();
  await verifier.verify(jwt(first.privateKey, claims()));
  await verifier.verify(jwt(first.privateKey, claims()));
  assert.equal(fetched.requests.length, 2, "discovery + JWKS once");
  const next = rotate("k2");
  await verifier.verify(jwt(next.privateKey, claims(), { alg: "RS256", kid: "k2" }));
  assert.equal(fetched.requests.length, 4, "one refetch for the unknown kid");
  // A stream of unknown kids does not refetch again inside the spacing window.
  await rejects(verifier.verify(jwt(next.privateKey, claims(), { alg: "RS256", kid: "k3" })));
  assert.equal(fetched.requests.length, 4);
  // The old key is gone after rotation.
  await rejects(verifier.verify(jwt(first.privateKey, claims())));
  advance(10 * 60_000);
  await verifier.verify(jwt(next.privateKey, claims(), { alg: "RS256", kid: "k2" }));
  assert.equal(fetched.requests.length, 6, "TTL refresh");
});

const unavailable = (promise: Promise<unknown>) => assert.rejects(promise, (error: unknown) =>
  error instanceof ReplicaIdentityUnavailable && !(error instanceof ReplicaIdentityError) && error.message === "replica_identity_unavailable");

test("discovery must name the issuer and a same-origin JWKS, else the issuer is unavailable", async () => {
  const elsewhere = setup({ jwksUri: "https://keys.example.net/jwks.json" });
  await unavailable(elsewhere.verifier.verify(jwt(elsewhere.first.privateKey, elsewhere.claims())));
  const wrongIssuer = setup({ issuer: "https://evil.example.net" });
  await unavailable(wrongIssuer.verifier.verify(jwt(wrongIssuer.first.privateKey, wrongIssuer.claims())));
});

test("an unreadable issuer is unavailable, not an invalid token; a bad signature stays invalid", async () => {
  const keys = pair();
  const claims = {
    iss: ISSUER, aud: AUDIENCE, exp: Math.floor(Date.now() / 1000) + 300, jti: "jti-1",
    organization_id: ORG, environment_id: ENV, workspace_id: WS, creator_id: "creator-1",
  };
  const verifierFor = (impl: (url: string) => Response | Promise<Response>) =>
    createReplicaIdentityVerifier({ issuer: ISSUER, audience: AUDIENCE, fetchImpl: (async (input: string | URL | Request) => impl(String(input))) as typeof fetch });
  // Issuer 5xx.
  await unavailable(verifierFor(() => new Response("{}", { status: 500 })).verify(jwt(keys.privateKey, claims)));
  // Network failure.
  await unavailable(verifierFor(() => { throw new TypeError("fetch failed"); }).verify(jwt(keys.privateKey, claims)));
  // A document over the 64 KiB cap, streamed without a content-length.
  const oversize = () => new Response(new ReadableStream({
    start(controller) {
      for (let index = 0; index < 80; index++) controller.enqueue(new TextEncoder().encode(index === 0 ? "{\"pad\":\"" : "x".repeat(1024)));
      controller.close();
    },
  }), { status: 200, headers: { "content-type": "application/json" } });
  await unavailable(verifierFor(oversize).verify(jwt(keys.privateKey, claims)));
  // Not JSON.
  await unavailable(verifierFor(() => new Response("<html>", { status: 200 })).verify(jwt(keys.privateKey, claims)));
  // A readable issuer and a signature by another key: the token is at fault.
  const { verifier, claims: valid } = setup();
  await rejects(verifier.verify(jwt(pair().privateKey, valid())));
});

test("errors and hints never carry the token or the full email", async () => {
  const { verifier, claims } = setup();
  const other = pair();
  const token = jwt(other.privateKey, claims());
  await assert.rejects(verifier.verify(token), (error: Error) => !error.message.includes(token) && !error.message.includes("person@"));
  assert.equal(emailHint("person@Example.com"), "p…@example.com");
  assert.equal(emailHint("bad"), null);
  assert.equal(emailHint(null), null);
});
