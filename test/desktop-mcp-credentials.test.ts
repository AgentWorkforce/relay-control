import assert from "node:assert/strict";
import test from "node:test";
import { hashSecret } from "../src/crypto.js";
import { request } from "./support/harness.js";
import { copilotDesktopSetup, desktopSecret, installationId, MCP_PATH, tokensPath } from "./support/copilot-desktop.js";

// Requirement (1): desktop-provider MCP credentials.

const INITIALIZE = {
  jsonrpc: "2.0", id: 1, method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "copilot-test", version: "1" } },
};

async function mcp(origin: string, token: string, body: unknown = INITIALIZE, path = MCP_PATH) {
  const response = await fetch(`${origin}${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, accept: "application/json, text/event-stream", "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) as Record<string, any> : {} };
}

async function register(origin: string, workspaceId: string, parent: string, options: {
  provider?: string; installation?: string; secret?: string; path?: string;
} = {}) {
  const secret = options.secret ?? desktopSecret();
  const installation = options.installation ?? installationId();
  const response = await request(origin, options.path ?? tokensPath(workspaceId), {
    method: "POST", token: parent, body: { provider: options.provider ?? "copilot", installationId: installation, accessToken: secret },
  });
  return { response, secret, installation };
}

test("only a verified Desktop parent registers a credential; it is a 15-minute child usable at MCP", async (t) => {
  const env = await copilotDesktopSetup(t);
  const parent = await env.desktopSignIn({ hostName: "sf-mini" });
  const { response, secret } = await register(env.origin, env.workspaceId, parent.accessToken);
  assert.equal(response.status, 201, response.raw);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.body.provider, "copilot");
  assert.deepEqual(response.body.scopes, ["rth:read", "mcp:desktop"]);
  assert.equal(response.body.workspaceId, env.workspaceId);
  assert.equal(response.raw.includes(secret), false, "the secret is never echoed");
  const lease = Date.parse(response.body.leaseExpiresAt) - Date.now();
  assert(lease > 14 * 60_000 && lease <= 15 * 60_000, `lease ${lease}`);

  // Stored only as a hash.
  const stored = await env.database.query<{ access_token_hash: string }>(
    "SELECT access_token_hash FROM token_sessions WHERE id = $1", [response.body.id]);
  assert.equal(stored.rows[0]!.access_token_hash, hashSecret(secret));

  const initialized = await mcp(env.origin, secret);
  assert.equal(initialized.status, 200);
  assert.equal(initialized.body.result.capabilities.experimental["com.agentrelay/desktop-provider-credentials"].leaseSeconds, 900);
  // Also on the /cloud prefix.
  assert.equal((await mcp(env.origin, secret, INITIALIZE, `/cloud${MCP_PATH}`)).status, 200);

  const listed = await request(env.origin, tokensPath(env.workspaceId), { token: parent.accessToken });
  assert.equal(listed.status, 200);
  assert.deepEqual(listed.body.tokens.map((row: { id: string }) => row.id), [response.body.id]);
  assert.equal(listed.raw.includes(secret), false);
});

test("unverified parents are refused: device flow, a handoff without consent, the pending handoff and a child", async (t) => {
  const env = await copilotDesktopSetup(t);
  const device = await env.deviceLogin();
  const deviceAttempt = await register(env.origin, env.workspaceId, device);
  assert.equal(deviceAttempt.response.status, 403);
  assert.deepEqual(deviceAttempt.response.body, { error: "desktop_login_required", message: "An Agent Relay app login is required." });

  // A redeemed sign-in that never named its host on the consent screen.
  const unconsented = await env.desktopSignIn();
  assert.equal((await register(env.origin, env.workspaceId, unconsented.accessToken)).response.status, 403);

  // The one-time handoff bearer itself, before and after redemption.
  const verified = await env.desktopSignIn({ hostName: "sf-mini" });
  const handoff = await register(env.origin, env.workspaceId, verified.handoffToken);
  assert.equal(handoff.response.status, 403);
  assert.equal(handoff.response.body.error, "desktop_login_required");

  // A child cannot mint children (it does not authenticate at app routes at all).
  const child = await register(env.origin, env.workspaceId, verified.accessToken);
  assert.equal(child.response.status, 201);
  const grandchild = await register(env.origin, env.workspaceId, child.secret);
  assert.equal(grandchild.response.status, 401);
  assert.equal(grandchild.response.body.error, "unauthorized");

  // A browser cookie is never a Desktop sign-in, even under /cloud.
  const cookie = await request(env.origin, `/cloud${tokensPath(env.workspaceId)}`, {
    method: "POST", cookie: verified.session,
    body: { provider: "copilot", installationId: installationId(), accessToken: desktopSecret() },
  });
  assert.equal(cookie.status, 401);

  // A malformed body.
  const bad = await request(env.origin, tokensPath(env.workspaceId), {
    method: "POST", token: verified.accessToken, body: { provider: "copilot", installationId: installationId(), accessToken: "sh_at_short" },
  });
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error, "invalid_request");
});

test("Desktop's retry with the same secret is idempotent; a different secret conflicts", async (t) => {
  const env = await copilotDesktopSetup(t);
  const parent = await env.desktopSignIn({ hostName: "sf-mini" });
  const first = await register(env.origin, env.workspaceId, parent.accessToken);
  assert.equal(first.response.status, 201);
  const retry = await register(env.origin, env.workspaceId, parent.accessToken,
    { installation: first.installation.toUpperCase(), secret: first.secret, path: `/cloud${tokensPath(env.workspaceId)}` });
  assert.equal(retry.response.status, 201);
  assert.equal(retry.response.body.id, first.response.body.id);
  const other = await register(env.origin, env.workspaceId, parent.accessToken, { installation: first.installation });
  assert.equal(other.response.status, 409);
  assert.deepEqual(other.response.body, {
    error: "credential_conflict",
    message: "This provider credential must be removed before it can be replaced.",
    credential_id: first.response.body.id,
  });
  // The named id revokes the survivor, after which the new secret registers.
  const removed = await request(env.origin, `${tokensPath(env.workspaceId)}/${other.response.body.credential_id}`,
    { method: "DELETE", token: parent.accessToken });
  assert.equal(removed.status, 204);
  const replaced = await register(env.origin, env.workspaceId, parent.accessToken, { installation: first.installation });
  assert.equal(replaced.response.status, 201);
  assert.notEqual(replaced.response.body.id, first.response.body.id);
  first.secret = replaced.secret;
  // Another provider for the same installation is a separate credential.
  const second = await register(env.origin, env.workspaceId, parent.accessToken, { installation: first.installation, provider: "grok" });
  assert.equal(second.response.status, 201);
  assert.notEqual(second.response.body.id, first.response.body.id);
  // A secret that already is a token cannot be bound again.
  const reused = await register(env.origin, env.workspaceId, parent.accessToken, { secret: first.secret });
  assert.equal(reused.response.status, 409);
  const listed = await request(env.origin, tokensPath(env.workspaceId), { token: parent.accessToken });
  assert.equal(listed.body.tokens.length, 2);
});

test("renew extends the lease; an expired lease is refused until renewed", async (t) => {
  const env = await copilotDesktopSetup(t);
  const parent = await env.desktopSignIn({ hostName: "sf-mini" });
  const { response, secret } = await register(env.origin, env.workspaceId, parent.accessToken);
  const id = response.body.id as string;
  // Age the lease to one minute left, then renew.
  await env.database.query(
    "UPDATE token_sessions SET access_token_expires_at = now() + interval '1 minute' WHERE id = $1", [id]);
  const renewed = await request(env.origin, tokensPath(env.workspaceId, id), { method: "PUT", token: parent.accessToken });
  assert.equal(renewed.status, 200, renewed.raw);
  assert(Date.parse(renewed.body.leaseExpiresAt) - Date.now() > 14 * 60_000);

  // Expired: refused at MCP, and in introspection.
  await env.database.query(
    "UPDATE token_sessions SET access_token_expires_at = now() - interval '1 second' WHERE id = $1", [id]);
  const expired = await mcp(env.origin, secret);
  assert.equal(expired.status, 401);
  assert.equal((await request(env.origin, `/cloud${tokensPath(env.workspaceId, id)}`, { method: "PUT", token: parent.accessToken })).status, 200);
  assert.equal((await mcp(env.origin, secret)).status, 200);

  // The lease never outlives the parent's refresh lifetime.
  await env.database.query(
    "UPDATE token_sessions SET refresh_token_expires_at = now() + interval '2 minutes' WHERE access_token_hash = $1",
    [hashSecret(parent.accessToken)]);
  const capped = await request(env.origin, tokensPath(env.workspaceId, id), { method: "PUT", token: parent.accessToken });
  assert(Date.parse(capped.body.leaseExpiresAt) - Date.now() <= 2 * 60_000);

  const unknown = await request(env.origin, tokensPath(env.workspaceId, "00000000-0000-4000-8000-000000000000"),
    { method: "PUT", token: parent.accessToken });
  assert.equal(unknown.status, 404);
  assert.equal(unknown.body.error, "token_not_found");
});

test("revoke removes the credential and the child stops working", async (t) => {
  const env = await copilotDesktopSetup(t);
  const parent = await env.desktopSignIn({ hostName: "sf-mini" });
  const { response, secret } = await register(env.origin, env.workspaceId, parent.accessToken);
  const id = response.body.id as string;
  assert.equal((await mcp(env.origin, secret)).status, 200);
  const revoked = await request(env.origin, tokensPath(env.workspaceId, id), { method: "DELETE", token: parent.accessToken });
  assert.equal(revoked.status, 204);
  assert.equal((await mcp(env.origin, secret)).status, 401);
  assert.equal((await request(env.origin, tokensPath(env.workspaceId, id), { method: "DELETE", token: parent.accessToken })).status, 404);
  assert.deepEqual((await request(env.origin, tokensPath(env.workspaceId), { token: parent.accessToken })).body.tokens, []);
  const introspected = await request(env.origin, "/api/v1/auth/introspect", { method: "POST", body: { token: secret } });
  assert.notEqual(introspected.body.active, true);
});

test("a revoked parent takes its children with it; a refreshed parent keeps them", async (t) => {
  const env = await copilotDesktopSetup(t);
  const parent = await env.desktopSignIn({ hostName: "sf-mini" });
  const { secret } = await register(env.origin, env.workspaceId, parent.accessToken);

  const refreshed = await request(env.origin, "/cloud/api/v1/auth/token/refresh", {
    method: "POST", body: { refreshToken: parent.refreshToken },
  });
  assert.equal(refreshed.status, 200);
  assert.equal((await mcp(env.origin, secret)).status, 200);
  // The rotated access token still manages the credential.
  assert.equal((await request(env.origin, tokensPath(env.workspaceId), { token: refreshed.body.accessToken })).body.tokens.length, 1);

  const revoked = await request(env.origin, "/api/v1/auth/token/revoke", { method: "POST", token: refreshed.body.accessToken });
  assert.equal(revoked.status, 200);
  const refused = await mcp(env.origin, secret);
  assert.equal(refused.status, 401);
});

test("membership is checked on every request; another person cannot manage the credential", async (t) => {
  const env = await copilotDesktopSetup(t);
  const memberId = await env.addMember("member@acme.test");
  const member = await env.desktopSignIn({ hostName: "member-laptop", userId: memberId });
  const owner = await env.desktopSignIn({ hostName: "sf-mini" });
  const { response, secret } = await register(env.origin, env.workspaceId, member.accessToken);
  const id = response.body.id as string;

  // The owner's own verified sign-in sees none of it.
  assert.deepEqual((await request(env.origin, tokensPath(env.workspaceId), { token: owner.accessToken })).body.tokens, []);
  for (const method of ["PUT", "DELETE"]) {
    const attempt = await request(env.origin, tokensPath(env.workspaceId, id), { method, token: owner.accessToken });
    assert.equal(attempt.status, 404, method);
  }
  // A parent manages only the workspace it signed in to.
  const elsewhere = await register(env.origin, env.otherWorkspaceId, member.accessToken);
  assert.equal(elsewhere.response.status, 404);
  assert.equal(elsewhere.response.body.error, "workspace_not_found");

  assert.equal((await mcp(env.origin, secret)).status, 200);
  const removed = await request(env.origin, `/api/v1/organizations/${env.orgId}/memberships/${memberId}`, {
    method: "DELETE", token: owner.accessToken,
  });
  assert.equal(removed.status, 204, removed.raw);
  assert.equal((await mcp(env.origin, secret)).status, 401);
  assert.equal((await request(env.origin, tokensPath(env.workspaceId), { token: member.accessToken })).status, 401);
});

test("the child works only at the MCP endpoint", async (t) => {
  const env = await copilotDesktopSetup(t);
  const parent = await env.desktopSignIn({ hostName: "sf-mini" });
  const { secret } = await register(env.origin, env.workspaceId, parent.accessToken);
  for (const path of [
    "/api/v1/auth/whoami",
    `/api/v1/workspaces/${env.workspaceId}/resolve`,
    `/cloud/api/v1/workspaces/${env.workspaceId}/resolve`,
    tokensPath(env.workspaceId),
    `/api/v1/workspaces/${env.workspaceId}/messaging/desktop-identities?source_id=00000000-0000-4000-8000-000000000000`,
  ]) {
    const refused = await request(env.origin, path, { token: secret });
    assert.equal(refused.status, 401, path);
  }
  const refresh = await request(env.origin, "/api/v1/auth/token/refresh", { method: "POST", body: { refreshToken: secret } });
  assert.notEqual(refresh.status, 200);
  assert.equal((await mcp(env.origin, secret)).status, 200);
  // A cookie carrying the child is not admitted at /cloud MCP either.
  const cookie = await fetch(`${env.origin}/cloud${MCP_PATH}`, {
    method: "POST",
    headers: { cookie: `agent_relay_session=${secret}`, origin: env.origin, accept: "application/json, text/event-stream", "content-type": "application/json" },
    body: JSON.stringify(INITIALIZE),
  });
  assert.equal(cookie.status, 401);
});

test("credential routes answer 405 for other methods with {error, message}", async (t) => {
  const env = await copilotDesktopSetup(t);
  const parent = await env.desktopSignIn({ hostName: "sf-mini" });
  const wrong = await request(env.origin, tokensPath(env.workspaceId), { method: "DELETE", token: parent.accessToken });
  assert.equal(wrong.status, 405);
  assert.equal(wrong.headers.get("allow"), "GET, POST");
  assert.deepEqual(Object.keys(wrong.body).sort(), ["error", "message"]);
});
