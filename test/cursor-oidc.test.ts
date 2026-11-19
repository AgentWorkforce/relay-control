import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import test from "node:test";
import {
  CursorIdentityError, cursorCloudParticipantName, cursorIdentityAudience, cursorIdentityNonces, cursorJwks,
  verifyCursorIdentityToken,
} from "../src/mcp/cursor-oidc.js";

// A Cursor cloud agent's OIDC token (cursor.com/docs/cloud-agent/identity),
// signed by a local key standing in for api.cursor.com's.

const AUDIENCE = cursorIdentityAudience("https://relay.example.test");
const SECRET = new Uint8Array(32).fill(9);

function issuer() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const kid = `kid-${randomUUID()}`;
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" };
  let fetches = 0;
  const jwks = cursorJwks({ fetchImpl: (async () => { fetches++; return Response.json({ keys: [jwk] }); }) as typeof fetch });
  const mint = (claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const head = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid, ...header })).toString("base64url");
    const body = Buffer.from(JSON.stringify({
      iss: "https://api.cursor.com", aud: AUDIENCE, sub: "user:42", iat: now, nbf: now - 5, exp: now + 300, jti: randomUUID(),
      cloud_agent_id: "bc-0123", agent_runtime: "managed", owner_user_id: "42", owner_email: "Dev@Example.test", team_id: "7",
      repo_url: "github.com/example/widgets", nonce: cursorIdentityNonces(SECRET, "grant-1").current, ...claims,
    })).toString("base64url");
    const signature = sign("sha256", Buffer.from(`${head}.${body}`), privateKey).toString("base64url");
    return `${head}.${body}.${signature}`;
  };
  return { jwks, mint, fetches: () => fetches };
}

function verifier(jwks: ReturnType<typeof cursorJwks>, options: { allowSelfHosted?: boolean; connection?: string } = {}) {
  const spent = new Set<string>();
  return (token: string) => verifyCursorIdentityToken(token, {
    audience: AUDIENCE, nonces: cursorIdentityNonces(SECRET, options.connection ?? "grant-1").accepted, jwks,
    spend: async (jti) => !spent.has(jti) && Boolean(spent.add(jti)), allowSelfHosted: options.allowSelfHosted,
  });
}

const refused = async (work: Promise<unknown>, reason: string) => {
  await assert.rejects(work, (error: unknown) => error instanceof CursorIdentityError && error.reason === reason);
};

test("a Cursor cloud agent token verifies to its run and owner, once", async () => {
  const { jwks, mint } = issuer();
  const verify = verifier(jwks);
  const token = mint();
  const identity = await verify(token);
  assert.equal(identity.cloudAgentId, "bc-0123");
  assert.equal(identity.subject, "user:42");
  assert.equal(identity.ownerUserId, "42");
  assert.equal(identity.ownerEmail, "dev@example.test");
  assert.equal(identity.teamId, "7");
  assert.equal(identity.runtime, "managed");
  await refused(verify(token), "replayed");
});

test("tokens for another audience, issuer, connection or algorithm are refused", async () => {
  const { jwks, mint } = issuer();
  const verify = verifier(jwks);
  await refused(verify(mint({ aud: "sts.amazonaws.com" })), "audience");
  await refused(verify(mint({ aud: [AUDIENCE, "other"] })), "audience");
  await refused(verify(mint({ iss: "https://api2.cursor.sh/cloud-agent/identity" })), "issuer");
  await refused(verify(mint({ nonce: cursorIdentityNonces(SECRET, "another-grant").current })), "nonce");
  await refused(verify(mint({ nonce: undefined })), "nonce");
  await refused(verify(mint({}, { alg: "HS256" })), "unsupported_algorithm");
  await refused(verify(mint({}, { kid: "someone-elses-key" })), "unknown_key");
});

test("expired, future, over-long, self-hosted and incomplete tokens are refused", async () => {
  const { jwks, mint } = issuer();
  const verify = verifier(jwks);
  const now = Math.floor(Date.now() / 1000);
  await refused(verify(mint({ iat: now - 900, nbf: now - 900, exp: now - 600 })), "expired");
  await refused(verify(mint({ iat: now + 600, nbf: now + 600, exp: now + 900 })), "not_yet_valid");
  await refused(verify(mint({ exp: now + 3600 })), "lifetime");
  await refused(verify(mint({ agent_runtime: "self_hosted" })), "self_hosted_runtime");
  assert.equal((await verifier(jwks, { allowSelfHosted: true })(mint({ agent_runtime: "self_hosted" }))).runtime, "self_hosted");
  await refused(verify(mint({ cloud_agent_id: undefined })), "claims");
  await refused(verify(mint({ sub: "alice@example.test" })), "claims");
});

test("a tampered payload or signature is refused, and garbage never reaches the crypto", async () => {
  const { jwks, mint } = issuer();
  const verify = verifier(jwks);
  const [head, , sig] = mint().split(".");
  const forged = Buffer.from(JSON.stringify({ iss: "https://api.cursor.com", aud: AUDIENCE, cloud_agent_id: "bc-other" })).toString("base64url");
  await refused(verify(`${head}.${forged}.${sig}`), "bad_signature");
  await refused(verify("not-a-jwt"), "malformed");
  await refused(verify("a.b.c.d"), "malformed");
  await refused(verify("x".repeat(20_000)), "malformed");
});

test("the key set is cached; nonces rotate per window and per connection; names are fixed by the run", async () => {
  const { jwks, mint, fetches } = issuer();
  const verify = verifier(jwks);
  await verify(mint()); await verify(mint());
  assert.equal(fetches(), 1);
  const at = Date.UTC(2026, 10, 19, 12, 0, 0);
  const now = cursorIdentityNonces(SECRET, "grant-1", at), later = cursorIdentityNonces(SECRET, "grant-1", at + 600_000);
  assert.ok(later.accepted.includes(now.current), "the previous window is still accepted");
  assert.notEqual(cursorIdentityNonces(SECRET, "grant-2", at).current, now.current);
  assert.equal(cursorCloudParticipantName("bc-0123"), cursorCloudParticipantName("bc-0123"));
  assert.match(cursorCloudParticipantName("bc-0123"), /^cursor-cloud-[0-9a-f]{10}$/);
});
