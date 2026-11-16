import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import { createAdminModule } from "../src/admin/routes.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * Member self-mint of relay-node tokens on gate-only installs
 * (docs/relay-node-credential.md, "Member self-mint").
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const HISTORY = "https://history.selfhosted.test";
const NODE_SCOPES = ["relay:workspace:read", "relay:nodes:read", "relay:nodes:enroll", "relay:agents:read"];
const DAY_MS = 24 * 60 * 60 * 1000;

type Reply = { status: number; body?: unknown };

async function setup(t: TestContext, options: { gate?: boolean; selfMint?: boolean } = {}) {
  const gate = options.gate ?? true;
  // Fake Relaycast for the broker; `reply` picks the answer.
  let reply: (call: { method: string; url: string }) => Reply = () => ({ status: 200, body: { ok: true, data: {} } });
  const relaycast = createServer((incoming: IncomingMessage, response: ServerResponse) => {
    incoming.resume();
    incoming.on("end", () => {
      const answer = reply({ method: incoming.method ?? "GET", url: incoming.url ?? "/" });
      response.writeHead(answer.status, { "content-type": "application/json" });
      response.end(JSON.stringify(answer.body ?? {}));
    });
  });
  const relaycastOrigin = await listen(relaycast);

  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: relaycastOrigin,
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: HISTORY,
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: HISTORY, secret: "r".repeat(32) },
    introspectSecret: INTROSPECT_SECRET,
    introspectAudiences: [HISTORY],
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: SERVICE,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/dashboard/`,
    port: 0,
    host: "127.0.0.1",
    ...(gate ? { relaygatePublicUrl: "https://gate.selfhosted.test" } : {}),
    ...(options.selfMint === false ? { relayNodeSelfMint: false } : {}),
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  const admin = createAdminModule({ config, database, keyring: KEYRING });
  control.on("request", createApp({ config, store, admin }));
  t.after(async () => {
    await close(control);
    await close(relaycast);
    await database.close();
  });

  const org = await request(origin, "/api/v1/organizations", {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const organizationId = org.body.id as string;
  const ownerId = org.body.owner.id as string;
  const created = await request(origin, `/api/v1/organizations/${organizationId}/workspaces`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "primary", relaycastApiKey: "rk_primary" },
  });
  assert.equal(created.status, 201, created.raw);
  const workspaceId = created.body.id as string;
  const adminBase = `/api/v1/workspaces/${workspaceId}/deployment-api-tokens`;
  const selfBase = `/api/v1/workspaces/${workspaceId}/relay-node/self-tokens`;

  const deviceToken = async (userId: string) => {
    const started = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: {} });
    const approved = await request(origin, "/api/v1/auth/device/approve", {
      method: "POST",
      token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const issued = await request(origin, "/api/v1/auth/device/token", {
      method: "POST",
      body: { device_code: started.body.device_code },
    });
    assert.equal(issued.status, 200);
    return issued.body.access_token as string;
  };
  const owner = await deviceToken(ownerId);
  const adminMint = (body: Record<string, unknown>) =>
    request(origin, adminBase, { method: "POST", token: owner, body });
  const addMember = async (email: string) => {
    const added = await request(origin, `/api/v1/organizations/${organizationId}/memberships`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { email, name: email, role: "member" },
    });
    assert.equal(added.status, 200);
    return added.body.userId as string;
  };
  /** A member signed in through Agent Relay Desktop (desktop-enrollment key exchange). */
  const desktopMember = async (email: string, host = "build-01") => {
    const userId = await addMember(email);
    const key = await adminMint({ label: "laptop rollout", purpose: "desktop-enrollment", email });
    assert.equal(key.status, 201, key.raw);
    const exchanged = await request(origin, "/api/v1/auth/enrollment/token", {
      method: "POST",
      body: { enrollment_key: key.body.accessToken, client_name: "Agent Relay Desktop", desktop_host_name: host },
    });
    assert.equal(exchanged.status, 200, exchanged.raw);
    return { userId, token: exchanged.body.access_token as string };
  };
  const audit = async () => {
    const listed = await request(origin, `/api/v1/workspaces/${workspaceId}/admin/audit`, { token: owner });
    assert.equal(listed.status, 200);
    return listed.body.events as Array<{ actorKind: string; actorId: string | null; action: string; target: string | null }>;
  };
  const selfMint = (token: string, body: Record<string, unknown>) =>
    request(origin, selfBase, { method: "POST", token, body });
  const selfList = (token: string) => request(origin, selfBase, { token });
  const selfRevoke = (token: string, id: string) =>
    request(origin, `${selfBase}/${id}`, { method: "DELETE", token });
  const broker = async (path: string, token: string, init: { method?: string; body?: unknown } = {}) => {
    const response = await fetch(`${origin}${path}`, {
      method: init.method ?? "GET",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
    const raw = await response.text();
    let body: Record<string, any> = {};
    try { body = raw ? JSON.parse(raw) : {}; } catch { body = {}; }
    return { status: response.status, body, raw };
  };
  return {
    database, origin, organizationId, ownerId, workspaceId, adminBase, selfBase, owner,
    deviceToken, adminMint, addMember, desktopMember, audit, selfMint, selfList, selfRevoke, broker,
    setReply: (next: typeof reply) => { reply = next; },
  };
}

test("not gate-only: every self-token route is 404 not_found", async (t) => {
  const ctx = await setup(t, { gate: false });
  const member = await ctx.desktopMember("member@acme.test");
  for (const answer of [
    await ctx.selfMint(member.token, { nodeName: "node-a" }),
    await ctx.selfList(member.token),
    await ctx.selfRevoke(member.token, "00000000-0000-4000-8000-000000000000"),
  ]) {
    assert.equal(answer.status, 404, answer.raw);
    assert.equal(answer.body.error, "not_found");
  }
});

test("only a redeemed Desktop session may self-mint: API token 401, device-code session 403", async (t) => {
  const ctx = await setup(t);
  const deployment = await ctx.adminMint({ label: "ci", purpose: "deployment" });
  assert.equal(deployment.status, 201);
  const byApiToken = await ctx.selfMint(deployment.body.accessToken, { nodeName: "node-a" });
  assert.equal(byApiToken.status, 401, byApiToken.raw);

  const memberId = await ctx.addMember("member@acme.test");
  const device = await ctx.deviceToken(memberId);
  for (const answer of [
    await ctx.selfMint(device, { nodeName: "node-a" }),
    await ctx.selfList(device),
    await ctx.selfRevoke(device, "00000000-0000-4000-8000-000000000000"),
  ]) {
    assert.equal(answer.status, 403, answer.raw);
    assert.equal(answer.body.error, "desktop_session_required");
  }
  // The owner's device-code session is refused too: the role does not matter.
  const ownerAnswer = await ctx.selfMint(ctx.owner, { nodeName: "node-a" });
  assert.equal(ownerAnswer.status, 403);
  assert.equal(ownerAnswer.body.error, "desktop_session_required");
});

test("201 mints an sh_wk_ relay-node token, audited twice, listed without its value", async (t) => {
  const ctx = await setup(t);
  const member = await ctx.desktopMember("member@acme.test", "build-01");
  const before = Date.now();
  const minted = await ctx.selfMint(member.token, { nodeName: "node-a" });
  assert.equal(minted.status, 201, minted.raw);
  assert.match(minted.body.accessToken, /^sh_wk_/);
  assert.equal(minted.body.purpose, "relay-node");
  assert.equal(minted.body.nodeName, "node-a");
  assert.deepEqual(minted.body.scopes, NODE_SCOPES);
  assert.equal(minted.body.label, "desktop build-01");
  assert.equal(minted.body.createdBy.id, member.userId);
  const expires = Date.parse(minted.body.accessTokenExpiresAt);
  assert(Math.abs(expires - (before + 90 * DAY_MS)) < 60_000, minted.body.accessTokenExpiresAt);

  const labelled = await ctx.selfMint(member.token, { nodeName: "node-a", label: "spare", expiryDays: 1 });
  assert.equal(labelled.status, 201, labelled.raw);
  assert.equal(labelled.body.label, "spare");

  const listed = await ctx.selfList(member.token);
  assert.equal(listed.status, 200);
  assert.deepEqual(listed.body.tokens.map((token: { id: string }) => token.id).sort(),
    [minted.body.id, labelled.body.id].sort());
  assert(!listed.raw.includes(minted.body.accessToken));
  assert(!listed.raw.includes(labelled.body.accessToken));
  assert(!listed.raw.includes('"accessToken"'));

  // The /cloud alias answers the same.
  const cloud = await request(ctx.origin, `/cloud${ctx.selfBase}`, { token: member.token });
  assert.equal(cloud.status, 200, cloud.raw);
  assert.equal(cloud.body.tokens.length, 2);

  const events = await ctx.audit();
  const created = events.filter((event) => event.target?.startsWith(minted.body.id));
  assert.deepEqual(created.map((event) => event.action).sort(), ["api_token.create", "relay_node.token.self_minted"]);
  const selfMinted = created.find((event) => event.action === "relay_node.token.self_minted")!;
  assert.equal(selfMinted.target, `${minted.body.id} (relay-node: node-a) host=build-01`);
  assert.equal(selfMinted.actorKind, "user");
  assert.equal(selfMinted.actorId, member.userId);
});

test("GET lists only the caller's own live relay-node tokens", async (t) => {
  const ctx = await setup(t);
  const alice = await ctx.desktopMember("alice@acme.test", "alice-host");
  const bob = await ctx.desktopMember("bob@acme.test", "bob-host");
  const aliceToken = await ctx.selfMint(alice.token, { nodeName: "alice-node" });
  const bobToken = await ctx.selfMint(bob.token, { nodeName: "bob-node" });
  assert.equal(aliceToken.status, 201);
  assert.equal(bobToken.status, 201);
  const adminToken = await ctx.adminMint({ label: "relay node", purpose: "relay-node", nodeName: "shared" });
  assert.equal(adminToken.status, 201);
  const spent = await ctx.selfMint(alice.token, { nodeName: "alice-node" });
  assert.equal((await ctx.selfRevoke(alice.token, spent.body.id)).status, 204);
  const expired = await ctx.selfMint(alice.token, { nodeName: "alice-node", expiryDays: 1 });
  await ctx.database.query(
    `UPDATE workspace_api_tokens SET expires_at = now() - interval '1 minute' WHERE id = $1`,
    [expired.body.id],
  );

  const listed = await ctx.selfList(alice.token);
  assert.equal(listed.status, 200);
  assert.deepEqual(listed.body.tokens.map((token: { id: string }) => token.id), [aliceToken.body.id]);
  const bobListed = await ctx.selfList(bob.token);
  assert.deepEqual(bobListed.body.tokens.map((token: { id: string }) => token.id), [bobToken.body.id]);
});

test("409 node_name_taken for another person's live node; the same caller may rotate", async (t) => {
  const ctx = await setup(t);
  const alice = await ctx.desktopMember("alice@acme.test");
  const bob = await ctx.desktopMember("bob@acme.test");
  const first = await ctx.selfMint(alice.token, { nodeName: "node-a" });
  assert.equal(first.status, 201);
  const rotated = await ctx.selfMint(alice.token, { nodeName: "node-a" });
  assert.equal(rotated.status, 201, rotated.raw);

  const taken = await ctx.selfMint(bob.token, { nodeName: "node-a" });
  assert.equal(taken.status, 409);
  assert.equal(taken.body.error, "node_name_taken");

  // An admin-minted token for a node also holds the name.
  assert.equal((await ctx.adminMint({ label: "n", purpose: "relay-node", nodeName: "node-b" })).status, 201);
  const adminHeld = await ctx.selfMint(bob.token, { nodeName: "node-b" });
  assert.equal(adminHeld.status, 409);
  assert.equal(adminHeld.body.error, "node_name_taken");

  // Once Alice's tokens are revoked or expired the name is free.
  assert.equal((await ctx.selfRevoke(alice.token, first.body.id)).status, 204);
  await ctx.database.query(
    `UPDATE workspace_api_tokens SET expires_at = now() - interval '1 minute' WHERE id = $1`,
    [rotated.body.id],
  );
  const freed = await ctx.selfMint(bob.token, { nodeName: "node-a" });
  assert.equal(freed.status, 201, freed.raw);
});

test("409 too_many_tokens at the fourth live token; a revoke frees a slot", async (t) => {
  const ctx = await setup(t);
  const member = await ctx.desktopMember("member@acme.test");
  const minted: Array<Record<string, any>> = [];
  for (const nodeName of ["node-1", "node-2", "node-3"]) {
    const answer = await ctx.selfMint(member.token, { nodeName });
    assert.equal(answer.status, 201, answer.raw);
    minted.push(answer.body);
  }
  const fourth = await ctx.selfMint(member.token, { nodeName: "node-4" });
  assert.equal(fourth.status, 409);
  assert.equal(fourth.body.error, "too_many_tokens");
  assert.equal((await ctx.selfRevoke(member.token, minted[0]!.id)).status, 204);
  const again = await ctx.selfMint(member.token, { nodeName: "node-4" });
  assert.equal(again.status, 201, again.raw);
});

test("DELETE revokes only the caller's own relay-node tokens; the broker then refuses it", async (t) => {
  const ctx = await setup(t);
  const alice = await ctx.desktopMember("alice@acme.test", "alice-host");
  const bob = await ctx.desktopMember("bob@acme.test", "bob-host");
  const own = await ctx.selfMint(alice.token, { nodeName: "node-a" });
  const bobs = await ctx.selfMint(bob.token, { nodeName: "node-b" });
  const adminMinted = await ctx.adminMint({ label: "n", purpose: "relay-node", nodeName: "node-c" });
  const deployment = await ctx.adminMint({ label: "ci", purpose: "deployment" });
  for (const id of [bobs.body.id, adminMinted.body.id, deployment.body.id, "not-a-uuid"]) {
    const refused = await ctx.selfRevoke(alice.token, id);
    assert.equal(refused.status, 404, id);
    assert.equal(refused.body.error, "token_not_found");
  }

  ctx.setReply(() => ({ status: 200, body: { ok: true, data: { id: "rw-1", name: "Relay WS" } } }));
  assert.equal((await ctx.broker("/relay-node/v1/workspace", own.body.accessToken)).status, 200);
  const revoked = await ctx.selfRevoke(alice.token, own.body.id);
  assert.equal(revoked.status, 204);
  assert.equal((await ctx.broker("/relay-node/v1/workspace", own.body.accessToken)).status, 401);
  assert.equal((await ctx.selfRevoke(alice.token, own.body.id)).status, 404);
  // Bob's and the admin's tokens still work.
  assert.equal((await ctx.broker("/relay-node/v1/workspace", bobs.body.accessToken)).status, 200);
  assert.equal((await ctx.broker("/relay-node/v1/workspace", adminMinted.body.accessToken)).status, 200);

  const events = await ctx.audit();
  const selfRevoked = events.filter((event) => event.action === "relay_node.token.self_revoked");
  assert.deepEqual(selfRevoked.map((event) => event.target), [`${own.body.id} (relay-node: node-a) host=alice-host`]);
  assert(events.some((event) => event.action === "api_token.revoke" && event.target?.startsWith(own.body.id)));
});

test("400 for a bad body: expiryDays above 90, neverExpires, missing or bad nodeName", async (t) => {
  const ctx = await setup(t);
  const member = await ctx.desktopMember("member@acme.test");
  for (const body of [
    { nodeName: "node-a", expiryDays: 91 },
    { nodeName: "node-a", expiryDays: 0 },
    { nodeName: "node-a", expiryDays: "7" },
    { nodeName: "node-a", neverExpires: true },
    {},
    { nodeName: "" },
    { nodeName: "bad name" },
    { nodeName: "node-a", label: "" },
  ]) {
    const answer = await ctx.selfMint(member.token, body);
    assert.equal(answer.status, 400, JSON.stringify(body));
    assert.equal(answer.body.error, "invalid_request", JSON.stringify(body));
  }
  assert.equal((await ctx.selfMint(member.token, { nodeName: "node-a", expiryDays: 90 })).status, 201);
});

test("403 self_mint_disabled when SELFHOST_RELAY_NODE_SELF_MINT is off; the admin mint still works", async (t) => {
  const ctx = await setup(t, { selfMint: false });
  const member = await ctx.desktopMember("member@acme.test");
  for (const answer of [
    await ctx.selfMint(member.token, { nodeName: "node-a" }),
    await ctx.selfList(member.token),
  ]) {
    assert.equal(answer.status, 403, answer.raw);
    assert.equal(answer.body.error, "self_mint_disabled");
  }
  assert.equal((await ctx.adminMint({ label: "n", purpose: "relay-node", nodeName: "node-a" })).status, 201);
});

test("429 rate_limited after 10 mints per person per hour", async (t) => {
  const ctx = await setup(t);
  const member = await ctx.desktopMember("member@acme.test");
  for (let i = 0; i < 10; i += 1) {
    const minted = await ctx.selfMint(member.token, { nodeName: "node-a" });
    assert.equal(minted.status, 201, `mint ${i}: ${minted.raw}`);
    assert.equal((await ctx.selfRevoke(member.token, minted.body.id)).status, 204);
  }
  const limited = await ctx.selfMint(member.token, { nodeName: "node-a" });
  assert.equal(limited.status, 429, limited.raw);
  assert.equal(limited.body.error, "rate_limited");
  assert(limited.headers.get("retry-after"));
  // GET and DELETE are not counted; another person has their own budget.
  assert.equal((await ctx.selfList(member.token)).status, 200);
  const other = await ctx.desktopMember("other@acme.test");
  assert.equal((await ctx.selfMint(other.token, { nodeName: "node-b" })).status, 201);
});

test("end to end: the self-minted token enrols its own node and nothing else", async (t) => {
  const ctx = await setup(t);
  const member = await ctx.desktopMember("member@acme.test", "build-01");
  const minted = await ctx.selfMint(member.token, { nodeName: "build-01" });
  assert.equal(minted.status, 201);
  ctx.setReply(() => ({ status: 201, body: { ok: true, data: { id: "n-1", name: "build-01", token: "nt_live_first" } } }));

  const refused = await ctx.broker("/relay-node/v1/nodes", minted.body.accessToken, {
    method: "POST",
    body: { name: "someone-else" },
  });
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error.code, "node_mismatch");

  const enrolled = await ctx.broker("/relay-node/v1/nodes", minted.body.accessToken, {
    method: "POST",
    body: { name: "build-01" },
  });
  assert.equal(enrolled.status, 201, enrolled.raw);
  assert(!enrolled.raw.includes("nt_live_first"));
});
