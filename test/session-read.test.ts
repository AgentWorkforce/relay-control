import assert from "node:assert/strict";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { hashSecret } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

const secret = "fake-reader-control-secret-".repeat(2);
const publicUrl = "https://sessions.selfhosted.company";
const refreshToken = `rth_rt_read_${"r".repeat(43)}`;

async function setup(t: TestContext) {
  const calls: { path: string; body: Record<string, any>; bearer: string | undefined }[] = [];
  let status = 200;
  let change = (body: Record<string, any>) => body;
  const reader = createServer(async (incoming, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    calls.push({ path: incoming.url!, body, bearer: incoming.headers.authorization });
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify(change({
      sessionId: "reader-session",
      userId: body.userId, orgId: body.orgId, workspaceId: body.workspaceId,
      audience: body.audience, scopes: ["rth:read"], tokenType: "Bearer",
      accessToken: `rth_at_read_${"a".repeat(43)}`,
      accessTokenExpiresAt: new Date(Date.now() + 300_000).toISOString(),
      refreshToken: `rth_rt_read_${"n".repeat(43)}`,
      refreshTokenExpiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      // Control must never blindly forward upstream extras.
      secretDebug: secret,
    })));
  });
  const readerUrl = await listen(reader);
  t.after(() => close(reader));
  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused", publicBaseUrl: "https://control.selfhosted.company",
    relaycastUrl: "http://relaycast.internal", relaycastPublicUrl: "https://relay.selfhosted.company",
    relayhistoryUrl: "http://history.internal", relayhistoryPublicUrl: "https://history.selfhosted.company",
    bootstrapToken: "bootstrap-secret-".repeat(3),
    encryptionKeyring: { active: { id: "test", key: Buffer.alloc(32, 5) } },
    internalServiceToken: "service-secret-".repeat(3), port: 3000, host: "127.0.0.1",
    oauthRedirectUrl: "https://control.selfhosted.company/callback", dashboardUrl: "https://app.selfhosted.company",
    sessionReadApi: { url: readerUrl, publicUrl, secret },
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0, { tenancy: "multi" });
  const org = await store.createOrganization({ name: "Tenant", ownerEmail: "owner@example.test", ownerName: "Owner" });
  const alpha = await store.createWorkspace({ organizationId: org.id, name: "Alpha", relaycastApiKey: "fake-alpha-key" });
  const beta = await store.createWorkspace({ organizationId: org.id, name: "Beta", relaycastApiKey: "fake-beta-key" });
  const identity = { userId: org.owner.id, organizationId: org.id, workspaceId: alpha.id };
  const pair = await database.transaction((tx) => store.issueBrowserSession(tx, { ...identity, label: "test" }));
  const pending = await store.issueDesktopHandoff({ ...identity, codeChallenge: "a".repeat(43) });
  const server = createServer(createApp({ config, store }));
  const origin = await listen(server);
  t.after(async () => { await close(server); await database.close(); });
  const path = `/api/v1/workspaces/${alpha.id}/session-read`;
  const post = (action = "session", body: unknown = {}, token = pair.accessToken) =>
    request(origin, `${path}/${action}`, { method: "POST", token, body });
  return { calls, config, database, org, alpha, beta, pair, pending, origin, path, post,
    respond: (next: typeof change, nextStatus = 200) => { change = next; status = nextStatus; } };
}

test("Control hands off reader-issued credentials with the verified identity and configured audience", async (t) => {
  const env = await setup(t);
  const answer = await env.post("session", { label: "MCP" });
  assert.equal(answer.status, 200, answer.raw);
  assert.equal(answer.headers.get("cache-control"), "no-store");
  assert.equal(answer.body.baseUrl, publicUrl);
  assert.equal(answer.body.userId, env.org.owner.id);
  assert.deepEqual(answer.body.scopes, ["rth:read"]);
  assert.match(answer.body.refreshToken, /^rth_rt_/);
  assert.equal(answer.body.secretDebug, undefined);
  assert.deepEqual(env.calls[0], {
    path: "/internal/v1/session-read/sessions", bearer: `Bearer ${secret}`,
    body: { userId: env.org.owner.id, orgId: env.org.id, workspaceId: env.alpha.id,
      audience: publicUrl, scopes: ["rth:read"], label: "MCP" },
  });
  assert.equal(JSON.stringify(env.calls).includes(env.pair.accessToken), false, "Control token never reaches reader");
  assert.equal((await env.post("refresh", { refreshToken })).status, 200);
  assert.equal(env.calls[1]!.path, "/internal/v1/session-read/sessions/refresh");
  assert.equal(env.calls[1]!.body.refreshToken, refreshToken);
});

test("issue and refresh reject unauthenticated, pending, foreign-workspace and removed members before issuing", async (t) => {
  const env = await setup(t);
  const foreign = await new ControlPlaneStore(env.database, env.config.encryptionKeyring, 0, { tenancy: "multi" })
    .createOrganization({ name: "Foreign", ownerEmail: "foreign@example.test", ownerName: "Foreign" });
  const foreignWorkspace = await new ControlPlaneStore(env.database, env.config.encryptionKeyring, 0, { tenancy: "multi" })
    .createWorkspace({ organizationId: foreign.id, name: "Foreign", relaycastApiKey: "fake-foreign-key" });
  for (const action of ["session", "refresh"]) {
    const body = action === "refresh" ? { refreshToken } : {};
    for (const token of ["", env.config.bootstrapToken, env.config.internalServiceToken!, "sh_wk_fake"]) {
      assert.equal((await env.post(action, body, token)).status, 401);
    }
    assert.equal((await env.post(action, body, env.pending.accessToken)).status, 403);
    assert.equal((await request(env.origin, `/api/v1/workspaces/${env.beta.id}/session-read/${action}`,
      { method: "POST", token: env.pair.accessToken, body })).status, 404);
    assert.equal((await request(env.origin, `/api/v1/workspaces/${foreignWorkspace.id}/session-read/${action}`,
      { method: "POST", token: env.pair.accessToken, body })).status, 404);
  }
  await env.database.query("UPDATE selfhost_token_sessions SET scopes = ARRAY['cli:auth'] WHERE access_token_hash = $1", [hashSecret(env.pair.accessToken)]);
  assert.equal((await env.post()).status, 403);
  assert.equal((await env.post("refresh", { refreshToken })).status, 403);
  await env.database.query("DELETE FROM selfhost_organization_memberships WHERE user_id = $1", [env.org.owner.id]);
  assert.equal((await env.post()).status, 401);
  assert.equal((await env.post("refresh", { refreshToken })).status, 401);
  assert.deepEqual(env.calls, []);
});

test("revoked tokens and expired Control sessions never reach the reader", async (t) => {
  const env = await setup(t);
  env.config.sessionReadApi = { url: "http://unused.internal", publicUrl, secret };
  await env.database.query("UPDATE selfhost_token_sessions SET access_token_expires_at = now() - interval '1 second' WHERE access_token_hash = $1", [hashSecret(env.pair.accessToken)]);
  assert.equal((await env.post()).status, 401);
  assert.equal((await env.post("refresh", { refreshToken })).status, 401);
  await env.database.query("UPDATE selfhost_token_sessions SET access_token_expires_at = now() + interval '1 day', revoked_at = now() WHERE access_token_hash = $1", [hashSecret(env.pair.accessToken)]);
  assert.equal((await env.post()).status, 401);
  assert.equal((await env.post("refresh", { refreshToken })).status, 401);
  assert.deepEqual(env.calls, []);
});

test("the browser handoff requires CSRF checks and withholds refresh credentials", async (t) => {
  const env = await setup(t);
  const cookie = `agent_relay_session=${env.pair.accessToken}`;
  assert.equal((await request(env.origin, `/cloud${env.path}/session`, { method: "POST", cookie, body: {} })).status, 403);
  const browser = async (origin: string, action = "session") => fetch(`${env.origin}/cloud${env.path}/${action}`, {
    method: "POST", headers: { cookie, origin, "content-type": "application/json" }, body: "{}",
  });
  assert.equal((await browser("https://foreign.selfhosted.company")).status, 403);
  const answer = await browser(env.config.dashboardUrl);
  assert.equal(answer.status, 200);
  const body = await answer.json() as Record<string, unknown>;
  assert.match(String(body.accessToken), /^rth_at_/);
  assert.equal("refreshToken" in body, false);
  assert.equal("refreshTokenExpiresAt" in body, false);
  assert.equal((await browser(env.config.dashboardUrl, "refresh")).status, 403);
  assert.equal(env.calls.length, 1);
});

test("client tenant, scope and URL overrides are rejected", async (t) => {
  const env = await setup(t);
  for (const field of ["userId", "orgId", "workspaceId", "audience", "scopes", "baseUrl", "mode"]) {
    assert.equal((await env.post("session", { [field]: "override" })).status, 400, field);
  }
  assert.equal((await env.post("refresh", { refreshToken: "rth_rt_short" })).status, 400);
  assert.deepEqual(env.calls, []);
});

test("wrong identity, audience, scope, short tokens and expired replies fail closed without credentials", async (t) => {
  const env = await setup(t);
  for (const override of [
    { userId: "foreign" }, { orgId: "foreign" }, { workspaceId: env.beta.id }, { audience: "https://foreign.company" },
    { scopes: ["rth:read", "rth:sync"] }, { accessToken: "sh_at_foreign" }, { accessToken: "rth_at_short" },
    { accessToken: `rth_at_${"a".repeat(43)}` }, { accessToken: `rth_at_read_${"a".repeat(38)}` },
    { accessTokenExpiresAt: new Date(Date.now() + 7_200_000).toISOString() },
    { accessTokenExpiresAt: "2020-01-01T00:00:00Z" }, { refreshTokenExpiresAt: "2020-01-01T00:00:00Z" },
  ]) {
    env.respond((body) => ({ ...body, ...override }));
    const answer = await env.post();
    assert.equal(answer.status, 502, JSON.stringify(override));
    assert.equal(answer.raw.includes("rth_at_"), false);
    assert.equal(answer.raw.includes(secret), false);
  }
  env.respond((body) => ({ ...body, refreshToken }));
  assert.equal((await env.post("refresh", { refreshToken })).status, 502, "rotation must change refresh token");
  env.respond(() => ({ error: `secret ${secret} ${refreshToken}` }), 401);
  assert.equal((await env.post("refresh", { refreshToken })).status, 401);
  env.respond(() => ({ error: secret }), 503);
  const unavailable = await env.post();
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.raw.includes(secret), false);
  env.respond(() => ({ debug: "x".repeat(20_000) }));
  assert.equal((await env.post()).status, 502, "response body is bounded");
});
