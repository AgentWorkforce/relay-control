import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { hashSecret } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

// Design G (SELFHOST_TENANCY=multi): DG-001 transport never confers authority,
// and the account / desktop:workspaces capabilities are the only routes that
// reach across workspaces. Single-mode behaviour is covered by the existing
// suites, which run unchanged.

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const VERIFIER = "desktop-verifier-0123456789abcdefghijklmnopqrstuvwxyz0123456789";
const CHALLENGE = createHash("sha256").update(VERIFIER).digest("base64url");
const FOREIGN_WORKSPACE = "00000000-0000-4000-8000-000000000000";

async function setup(t: test.TestContext) {
  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.test",
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: "https://history.selfhosted.test", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/`,
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
  control.on("request", createApp({ config, store }));
  t.after(async () => {
    await close(control);
    await database.close();
  });

  const organization = async (name: string, ownerEmail: string, ownerName: string) => {
    const created = await request(origin, "/api/v1/organizations", {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, ownerEmail, ownerName },
    });
    assert.equal(created.status, 201);
    return { id: created.body.id as string, ownerId: created.body.owner.id as string };
  };
  const workspace = async (organizationId: string, name: string) => {
    const created = await request(origin, `/api/v1/organizations/${organizationId}/workspaces`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, relaycastApiKey: `rk_${name}`, relaycastWorkspaceId: `rw_${name}` },
    });
    assert.equal(created.status, 201);
    return created.body.id as string;
  };
  const member = async (organizationId: string, email: string, name: string) => {
    const put = await request(origin, `/api/v1/organizations/${organizationId}/memberships`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { email, name, role: "member" },
    });
    assert.equal(put.status, 200);
  };

  // Alice owns A and is a member of B; Bob owns B and is a member of A.
  const a = await organization("Org A", "alice@a.test", "Alice");
  const b = await organization("Org B", "bob@b.test", "Bob");
  await member(b.id, "alice@a.test", "Alice");
  await member(a.id, "bob@b.test", "Bob");
  const a1 = await workspace(a.id, "a1");
  const a2 = await workspace(a.id, "a2");
  const b1 = await workspace(b.id, "b1");
  return { database, store, origin, a, b, alice: a.ownerId, bob: b.ownerId, a1, a2, b1 };
}

type Env = Awaited<ReturnType<typeof setup>>;

/** A browser account session: /login, approved by the bootstrap bearer, redeemed by /login/poll. */
async function browserSession(env: Env, userId: string, workspaceId: string): Promise<string> {
  const login = await fetch(`${env.origin}/login`);
  const code = (await login.text()).match(/<code>([A-Z0-9]{4}-[A-Z0-9]{4})<\/code>/)?.[1];
  assert(code);
  const deviceCookie = login.headers.get("set-cookie")!.split(";")[0]!;
  const approved = await request(env.origin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: BOOTSTRAP,
    body: { action: "approve", user_code: code, user_id: userId, workspace_id: workspaceId },
  });
  assert.equal(approved.status, 200);
  const poll = await request(env.origin, "/login/poll", { method: "POST", cookie: deviceCookie });
  assert.equal(poll.status, 200);
  const session = poll.headers.get("set-cookie")?.match(/agent_relay_session=[^;]+/)?.[0];
  assert(session);
  return session;
}

/** A CLI device token (DEVICE_SCOPES), approved by the bootstrap bearer. */
async function deviceTokens(env: Env, userId: string, workspaceId: string) {
  const started = await request(env.origin, "/api/v1/auth/device/start", {
    method: "POST",
    body: { client_name: "multi-tenant-test" },
  });
  assert.equal(started.status, 201);
  const approved = await request(env.origin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: BOOTSTRAP,
    body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
  });
  assert.equal(approved.status, 200);
  const tokens = await request(env.origin, "/api/v1/auth/device/token", {
    method: "POST",
    body: { device_code: started.body.device_code },
  });
  assert.equal(tokens.status, 200);
  return { accessToken: tokens.body.access_token as string, refreshToken: tokens.body.refresh_token as string };
}

function loginPath(extra: Record<string, string> = {}): string {
  const params = new URLSearchParams({
    redirect_uri: "http://127.0.0.1:5123/callback/STATE1",
    state: "STATE1",
    client: "desktop",
    workspace_selection: "desktop",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    ...extra,
  });
  return `/cloud/api/v1/cli/login?${params}`;
}

/** Desktop browser sign-in for a workspace, then the verifier exchange. */
async function desktopTokens(env: Env, cookie: string, workspaceId: string) {
  const handoff = await fetch(`${env.origin}${loginPath({ workspace: workspaceId })}`, {
    redirect: "manual",
    headers: { cookie },
  });
  assert.equal(handoff.status, 307);
  const accessToken = new URL(handoff.headers.get("location")!).searchParams.get("access_token")!;
  const exchanged = await request(env.origin, "/cloud/api/v1/auth/desktop/session", {
    method: "POST",
    token: accessToken,
    body: { codeVerifier: VERIFIER },
  });
  assert.equal(exchanged.status, 200);
  return { accessToken: exchanged.body.accessToken as string, refreshToken: exchanged.body.refreshToken as string };
}

async function whoami(env: Env, token: string) {
  const response = await request(env.origin, "/cloud/api/v1/auth/whoami", { token });
  return response;
}

async function post(env: Env, path: string, init: {
  cookie?: string;
  token?: string;
  origin?: string | null;
  secFetchSite?: string;
  body: unknown;
}) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (init.cookie) headers.cookie = init.cookie;
  if (init.token) headers.authorization = `Bearer ${init.token}`;
  const origin = init.origin === undefined ? env.origin : init.origin;
  if (origin !== null) headers.origin = origin;
  if (init.secFetchSite) headers["sec-fetch-site"] = init.secFetchSite;
  const response = await fetch(`${env.origin}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(init.body),
    redirect: "manual",
  });
  const raw = await response.text();
  return { status: response.status, headers: response.headers, body: raw ? JSON.parse(raw) as Record<string, any> : {} };
}

async function setScopes(env: Env, accessToken: string, scopes: string[]) {
  await env.database.query(
    "UPDATE token_sessions SET scopes = $2::text[] WHERE access_token_hash = $1",
    [hashSecret(accessToken), scopes],
  );
}

test("DG-001: the account session lists every membership; tokens act only in their own organization", async (t) => {
  const env = await setup(t);
  const cookie = await browserSession(env, env.alice, env.a1);
  const session = await request(env.origin, "/cloud/api/auth/session", { cookie });
  assert.equal(session.status, 200);
  assert.deepEqual(session.body.currentOrganization, { id: env.a.id, name: "Org A", role: "owner" });
  assert.deepEqual(session.body.currentWorkspace, { id: env.a1, name: "a1" });
  assert.deepEqual(
    session.body.organizations.map((organization: { id: string; role: string }) => [organization.id, organization.role]),
    [[env.a.id, "owner"], [env.b.id, "member"]],
  );
  assert.deepEqual(session.body.workspaces.map((workspace: { id: string }) => workspace.id), [env.a1, env.a2, env.b1]);
  assert.equal((await request(env.origin, "/cloud/api/v1/auth/whoami", { cookie })).body.workspaceCount, 3);

  // A bearer is refused on the account routes; the cookie only counts under /cloud.
  const token = cookie.split("=")[1]!;
  assert.equal((await request(env.origin, "/cloud/api/auth/session", { token })).status, 401);

  // Transport never confers authority: as cookie or bearer, with any Origin
  // and Sec-Fetch-Site, a token bound to org A gets 404 for org B.
  const transports: Array<Record<string, string>> = [
    { cookie },
    { authorization: `Bearer ${token}` },
    { cookie, origin: env.origin, "sec-fetch-site": "same-origin" },
    { authorization: `Bearer ${token}`, origin: "https://evil.example", "sec-fetch-site": "cross-site" },
  ];
  for (const headers of transports) {
    const foreign = await fetch(`${env.origin}/cloud/api/v1/organizations/${env.b.id}/memberships`, { headers });
    assert.equal(foreign.status, 404, JSON.stringify(Object.keys(headers)));
    const own = await fetch(`${env.origin}/cloud/api/v1/organizations/${env.a.id}/memberships`, { headers });
    assert.equal(own.status, 200, JSON.stringify(Object.keys(headers)));
  }
  assert.equal((await request(env.origin, `/cloud/api/v1/workspaces/${env.b1}/resolve`, { cookie })).status, 404);
  assert.equal((await request(env.origin, `/cloud/api/v1/workspaces/${env.a2}/resolve`, { cookie })).status, 404,
    "a session is bound to its workspace, not just its organization");

  // Multi mode: bootstrap use leaves an audit row in the organization it touched.
  assert.equal((await request(env.origin, `/api/v1/organizations/${env.b.id}/workspaces`, { token: BOOTSTRAP })).status, 200);
  const audit = await env.database.query<{ actor_kind: string; target: string }>(
    "SELECT actor_kind, target FROM admin_audit_events WHERE action = 'bootstrap.access' AND organization_id = $1",
    [env.b.id],
  );
  assert(audit.rows.some((row) => row.actor_kind === "bootstrap" && row.target === `GET /api/v1/organizations/${env.b.id}/workspaces`));
});

test("DG-001: switching workspaces mints a new session, revokes the old access and refresh token, and takes the live role", async (t) => {
  const env = await setup(t);
  // A browser session with a known refresh token (the cookie never carries it).
  const issued = await env.database.transaction((tx) =>
    env.store.issueBrowserSession(tx, { userId: env.alice, organizationId: env.a.id, workspaceId: env.a1, label: "browser" }));
  const cookie = `agent_relay_session=${issued.accessToken}`;
  assert.deepEqual(issued.scopes, ["cli:auth", "rth:read", "rth:sync", "account"]);

  // CSRF: a cross-origin or non-JSON cookie POST is refused; a bearer is refused.
  assert.equal((await post(env, "/cloud/api/auth/workspace", {
    cookie, origin: "https://evil.example", body: { workspaceId: env.b1 },
  })).body.error, "csrf_rejected");
  assert.equal((await post(env, "/cloud/api/auth/workspace", {
    cookie, origin: null, secFetchSite: "cross-site", body: { workspaceId: env.b1 },
  })).status, 403);
  assert.equal((await post(env, "/cloud/api/auth/workspace", {
    token: issued.accessToken, body: { workspaceId: env.b1 },
  })).status, 401);
  // Not a member: 404, and the session survives.
  assert.equal((await post(env, "/cloud/api/auth/workspace", { cookie, body: { workspaceId: FOREIGN_WORKSPACE } })).status, 404);
  assert.equal((await request(env.origin, "/cloud/api/auth/session", { cookie })).status, 200);

  const switched = await post(env, "/cloud/api/auth/workspace", { cookie, body: { workspaceId: env.b1 } });
  assert.equal(switched.status, 200);
  assert.deepEqual(switched.body.currentOrganization, { id: env.b.id, name: "Org B", role: "member" });
  assert.deepEqual(switched.body.currentWorkspace, { id: env.b1, name: "b1" });
  const next = switched.headers.get("set-cookie")?.match(/agent_relay_session=[^;]+/)?.[0];
  assert(next);
  assert.match(switched.headers.get("set-cookie")!, /Path=\/cloud;.*HttpOnly/);
  assert.notEqual(next, cookie);

  // The old access and refresh token are dead.
  assert.equal((await request(env.origin, "/cloud/api/auth/session", { cookie })).status, 401);
  assert.equal(await env.store.refresh(issued.refreshToken), null);
  const revoked = await env.database.query<{ revoked_reason: string }>(
    "SELECT revoked_reason FROM token_sessions WHERE id = $1",
    [issued.sessionId],
  );
  assert.equal(revoked.rows[0]!.revoked_reason, "workspace_switch");
  const user = await env.database.query<{ last_organization_id: string; last_workspace_id: string }>(
    "SELECT last_organization_id, last_workspace_id FROM users WHERE id = $1",
    [env.alice],
  );
  assert.deepEqual(user.rows[0], { last_organization_id: env.b.id, last_workspace_id: env.b1 });

  // Owner in A, member in B: the new session is a member in B (403 on admin
  // writes) and has nothing in A (404).
  const membershipBody = { email: "carol@b.test", name: "Carol", role: "member" };
  assert.equal((await post(env, `/cloud/api/v1/organizations/${env.b.id}/memberships`, { cookie: next, body: membershipBody })).status, 403);
  assert.equal((await request(env.origin, `/cloud/api/v1/organizations/${env.b.id}/workspaces`, { cookie: next })).status, 200);
  assert.equal((await request(env.origin, `/cloud/api/v1/organizations/${env.a.id}/workspaces`, { cookie: next })).status, 404);

  // The reverse: Bob owns B and is a member of A.
  const bobA = await browserSession(env, env.bob, env.a1);
  assert.equal((await post(env, `/cloud/api/v1/organizations/${env.a.id}/memberships`, {
    cookie: bobA, body: { ...membershipBody, email: "carol@a.test" },
  })).status, 403);
  const bobB = await post(env, "/cloud/api/auth/workspace", { cookie: bobA, body: { workspaceId: env.b1 } });
  assert.equal(bobB.body.currentOrganization.role, "owner");
  const bobCookie = bobB.headers.get("set-cookie")!.match(/agent_relay_session=[^;]+/)![0];
  assert.equal((await post(env, `/cloud/api/v1/organizations/${env.b.id}/memberships`, {
    cookie: bobCookie, body: membershipBody,
  })).status, 200);

  // Membership removal takes effect on the next request.
  const removed = await fetch(`${env.origin}/api/v1/organizations/${env.b.id}/memberships/${env.alice}`, {
    method: "DELETE",
    headers: { authorization: `Bearer ${BOOTSTRAP}` },
  });
  assert.equal(removed.status, 204);
  assert.equal((await request(env.origin, "/cloud/api/auth/session", { cookie: next })).status, 401);
});

test("DG-001: legacy credentials get reauthentication_required on capability routes and keep their resource routes", async (t) => {
  const env = await setup(t);
  const cookie = await browserSession(env, env.alice, env.a1);
  const token = cookie.split("=")[1]!;
  await setScopes(env, token, ["cli:auth", "rth:read", "rth:sync"]);
  // The dashboard's session probe answers 401 so the SPA signs in again.
  const session = await request(env.origin, "/cloud/api/auth/session", { cookie });
  assert.equal(session.status, 401);
  assert.deepEqual(session.body, { authenticated: false, reason: "reauthentication_required" });
  assert.equal((await post(env, "/cloud/api/auth/workspace", { cookie, body: { workspaceId: env.a2 } })).body.error,
    "reauthentication_required");
  assert.equal((await request(env.origin, "/cloud/api/v1/auth/whoami", { cookie })).status, 200);
  assert.equal((await request(env.origin, `/cloud/api/v1/organizations/${env.a.id}/workspaces`, { cookie })).status, 200);
  assert.equal((await request(env.origin, `/cloud/api/v1/workspaces/${env.a1}/resolve`, { cookie })).status, 200);

  // A legacy cookie stays bound in the Desktop sign-in and in device approval.
  const bound = await fetch(`${env.origin}${loginPath({ workspace: env.a2 })}`, { redirect: "manual", headers: { cookie } });
  assert.equal(bound.status, 403);
  const own = await fetch(`${env.origin}${loginPath()}`, { redirect: "manual", headers: { cookie } });
  assert.equal(own.status, 307, "no picker: the bound workspace is used");

  // CLI device tokens never had a capability: 403 on the Desktop routes.
  const device = await deviceTokens(env, env.alice, env.a1);
  assert.deepEqual((await whoami(env, device.accessToken)).body.scopes, ["cli:auth", "rth:read", "rth:sync", "rth:acquire"]);
  const desktopList = await request(env.origin, "/cloud/api/v1/auth/desktop/workspaces", { token: device.accessToken });
  assert.equal(desktopList.status, 403);
  assert.equal(desktopList.body.error, "reauthentication_required");
  assert.equal((await request(env.origin, `/cloud/api/v1/workspaces/${env.a1}/resolve`, { token: device.accessToken })).status, 200);
  // Device approval with a bound bearer: other workspaces stay out of reach.
  const started = await request(env.origin, "/api/v1/auth/device/start", { method: "POST", body: { client_name: "x" } });
  const lookup = await post(env, "/cloud/api/v1/auth/device/approve", {
    token: device.accessToken, origin: null, body: { action: "lookup", user_code: started.body.user_code },
  });
  assert.deepEqual(lookup.body.workspaces.map((workspace: { id: string }) => workspace.id), [env.a1]);
  assert.equal((await post(env, "/cloud/api/v1/auth/device/approve", {
    token: device.accessToken, origin: null, body: { action: "approve", user_code: started.body.user_code, workspace_id: env.a2 },
  })).status, 404);
  // The dashboard's client name is reserved for the browser sign-in.
  // Invisible or surrounding characters are cleaned from the stored name, so
  // the check runs on the cleaned name too.
  for (const clientName of ["relay-dashboard", " relay-dashboard ", "relay-dashboard\u200b", "\u200brelay-dashboard"]) {
    const reserved = await request(env.origin, "/api/v1/auth/device/start", { method: "POST", body: { client_name: clientName } });
    assert.equal(reserved.status, 400, JSON.stringify(clientName));
    assert.equal(reserved.body.error, "invalid_request");
  }

  // Refresh copies the stored scopes verbatim: never gains a capability.
  const refreshed = await request(env.origin, "/cloud/api/v1/auth/token/refresh", {
    method: "POST", body: { refreshToken: device.refreshToken },
  });
  assert.equal(refreshed.status, 200);
  assert.deepEqual((await whoami(env, refreshed.body.accessToken)).body.scopes, ["cli:auth", "rth:read", "rth:sync", "rth:acquire"]);
});

test("DG-001: the Desktop picker, desktop:workspaces list and mint, and device approval across organizations", async (t) => {
  const env = await setup(t);
  const cookie = await browserSession(env, env.alice, env.a1);

  // Several workspaces and none chosen: the browser shows a picker.
  const picker = await fetch(`${env.origin}${loginPath()}`, { redirect: "manual", headers: { cookie } });
  assert.equal(picker.status, 200);
  const page = await picker.text();
  for (const name of ["a1", "a2", "b1", "Org A", "Org B"]) assert(page.includes(name), name);
  assert(page.includes(`<option value="${env.b1}">`));
  assert.match(page, /<select id="workspace" name="workspace" required>/);
  assert.equal((await fetch(`${env.origin}${loginPath({ workspace: FOREIGN_WORKSPACE })}`, {
    redirect: "manual", headers: { cookie },
  })).status, 403);

  // Choosing B1 (another organization) hands the Desktop a B1-bound session.
  const desktop = await desktopTokens(env, cookie, env.b1);
  const me = await whoami(env, desktop.accessToken);
  assert.equal(me.body.currentWorkspace.id, env.b1);
  assert.deepEqual(me.body.currentOrganization, { id: env.b.id, name: "Org B", role: "member" });
  assert.deepEqual(me.body.scopes, ["cli:auth", "rth:read", "rth:sync", "rth:acquire", "desktop:workspaces"]);

  const listed = await request(env.origin, "/cloud/api/v1/auth/desktop/workspaces", { token: desktop.accessToken });
  assert.equal(listed.status, 200);
  assert.equal(listed.body.current_workspace_id, env.b1);
  assert.deepEqual(listed.body.workspaces.map((workspace: any) => [workspace.id, workspace.organization_name, workspace.role]), [
    [env.a1, "Org A", "owner"],
    [env.a2, "Org A", "owner"],
    [env.b1, "Org B", "member"],
  ]);
  assert.equal((await post(env, "/cloud/api/v1/auth/desktop/workspaces", {
    token: desktop.accessToken, body: { workspaceId: FOREIGN_WORKSPACE },
  })).status, 404);
  const minted = await post(env, "/cloud/api/v1/auth/desktop/workspaces", {
    token: desktop.accessToken, body: { workspaceId: env.a2 },
  });
  assert.equal(minted.status, 200);
  assert.equal(minted.body.tokenType, "Bearer");
  assert.match(minted.body.refreshToken, /^sh_rt_/);
  const a2 = await whoami(env, minted.body.accessToken);
  assert.equal(a2.body.currentWorkspace.id, env.a2);
  assert.equal(a2.body.currentOrganization.role, "owner");
  assert.deepEqual(a2.body.scopes, ["cli:auth", "rth:read", "rth:sync", "rth:acquire", "desktop:workspaces"]);
  // The minted session is bound like any other.
  assert.equal((await request(env.origin, `/cloud/api/v1/workspaces/${env.b1}/resolve`, { token: minted.body.accessToken })).status, 404);
  // The account cookie is not a Desktop credential.
  assert.equal((await request(env.origin, "/cloud/api/v1/auth/desktop/workspaces", { cookie })).status, 401);

  // Refresh keeps desktop:workspaces and adds nothing.
  const refreshed = await request(env.origin, "/cloud/api/v1/auth/token/refresh", {
    method: "POST", body: { refreshToken: desktop.refreshToken },
  });
  assert.deepEqual((await whoami(env, refreshed.body.accessToken)).body.scopes,
    ["cli:auth", "rth:read", "rth:sync", "rth:acquire", "desktop:workspaces"]);

  // Device approval from the account session: every member workspace, any of them.
  const started = await request(env.origin, "/api/v1/auth/device/start", { method: "POST", body: { client_name: "cli" } });
  const lookup = await post(env, "/cloud/api/v1/auth/device/approve", {
    cookie, body: { action: "lookup", user_code: started.body.user_code },
  });
  assert.equal(lookup.status, 200);
  assert.equal(lookup.body.current_workspace_id, env.a1);
  assert.deepEqual(lookup.body.workspaces.map((workspace: any) => workspace.organization_name), ["Org A", "Org A", "Org B"]);
  assert.equal((await post(env, "/cloud/api/v1/auth/device/approve", {
    cookie, body: { action: "approve", user_code: started.body.user_code, workspace_id: env.b1 },
  })).status, 200);
  const issued = await request(env.origin, "/api/v1/auth/device/token", {
    method: "POST", body: { device_code: started.body.device_code },
  });
  const cli = await whoami(env, issued.body.access_token);
  assert.equal(cli.body.currentWorkspace.id, env.b1);
  assert.deepEqual(cli.body.scopes, ["cli:auth", "rth:read", "rth:sync", "rth:acquire"], "device tokens are unchanged");

  // Membership removal takes effect on the next request, on every credential.
  const removed = await fetch(`${env.origin}/api/v1/organizations/${env.b.id}/memberships/${env.alice}`, {
    method: "DELETE",
    headers: { authorization: `Bearer ${BOOTSTRAP}` },
  });
  assert.equal(removed.status, 204);
  assert.equal((await whoami(env, desktop.accessToken)).status, 401);
  assert.equal((await whoami(env, issued.body.access_token)).status, 401);
  const after = await request(env.origin, "/cloud/api/v1/auth/desktop/workspaces", { token: minted.body.accessToken });
  assert.deepEqual(after.body.workspaces.map((workspace: { id: string }) => workspace.id), [env.a1, env.a2]);
  assert.equal((await post(env, "/cloud/api/v1/auth/desktop/workspaces", {
    token: minted.body.accessToken, body: { workspaceId: env.b1 },
  })).status, 404);
});

test("DG-001: an unexchanged Desktop handoff token is refused until the verifier exchange", async (t) => {
  const env = await setup(t);
  const cookie = await browserSession(env, env.alice, env.a1);
  const handoff = await fetch(`${env.origin}${loginPath({ workspace: env.b1 })}`, { redirect: "manual", headers: { cookie } });
  assert.equal(handoff.status, 307);
  const pending = new URL(handoff.headers.get("location")!).searchParams.get("access_token")!;

  const listed = await request(env.origin, "/cloud/api/v1/auth/desktop/workspaces", { token: pending });
  assert.equal(listed.status, 403);
  assert.equal(listed.body.error, "handoff_not_exchanged");
  const minted = await post(env, "/cloud/api/v1/auth/desktop/workspaces", { token: pending, body: { workspaceId: env.a2 } });
  assert.equal(minted.status, 403);
  assert.equal(minted.body.error, "handoff_not_exchanged");
  // Nor does it reach the account routes (even planted as the session cookie)
  // or create organizations.
  const planted = `agent_relay_session=${pending}`;
  const probe = await request(env.origin, "/cloud/api/auth/session", { cookie: planted });
  assert.equal(probe.status, 401);
  assert.equal(probe.body.authenticated, false);
  const accountSwitch = await post(env, "/cloud/api/auth/workspace", { cookie: planted, body: { workspaceId: env.a2 } });
  assert.equal(accountSwitch.status, 403);
  assert.equal(accountSwitch.body.error, "reauthentication_required");
  const organization = await post(env, "/cloud/api/v1/organizations", { token: pending, origin: null, body: { name: "Handoff Org" } });
  assert.equal(organization.status, 403);

  const exchanged = await request(env.origin, "/cloud/api/v1/auth/desktop/session", {
    method: "POST", token: pending, body: { codeVerifier: VERIFIER },
  });
  assert.equal(exchanged.status, 200);

  // D02: redeeming the handoff must not promote the original redirect token.
  // Whoever holds only that token (never the verifier) still cannot list or
  // switch workspaces, and no session is minted for them.
  const sessions = async () => Number((await env.database.query<{ count: string | number }>(
    "SELECT count(*) AS count FROM token_sessions WHERE user_id = $1", [env.alice],
  )).rows[0]!.count);
  const before = await sessions();
  const replayList = await request(env.origin, "/cloud/api/v1/auth/desktop/workspaces", { token: pending });
  assert.equal(replayList.status, 403);
  assert.equal(replayList.body.error, "handoff_not_capable");
  assert.equal(replayList.body.workspaces, undefined);
  const replayMint = await post(env, "/cloud/api/v1/auth/desktop/workspaces", { token: pending, body: { workspaceId: env.a2 } });
  assert.equal(replayMint.status, 403);
  assert.equal(replayMint.body.error, "handoff_not_capable");
  assert.equal(replayMint.body.accessToken, undefined);
  assert.equal(await sessions(), before, "the exchanged handoff mints no session");
  const replayOrganization = await post(env, "/cloud/api/v1/organizations", { token: pending, origin: null, body: { name: "Replay Org" } });
  assert.equal(replayOrganization.status, 403);
  const replaySwitch = await post(env, "/cloud/api/auth/workspace", { cookie: planted, body: { workspaceId: env.a2 } });
  assert.equal(replaySwitch.status, 403);

  const after = await request(env.origin, "/cloud/api/v1/auth/desktop/workspaces", { token: exchanged.body.accessToken });
  assert.equal(after.status, 200);
  assert.equal(after.body.current_workspace_id, env.b1);
  const switched = await post(env, "/cloud/api/v1/auth/desktop/workspaces", {
    token: exchanged.body.accessToken, body: { workspaceId: env.a2 },
  });
  assert.equal(switched.status, 200);
});

test("DG-001: org admins add new people directly but must invite someone who already has an account", async (t) => {
  const env = await setup(t);
  const carolOrg = await request(env.origin, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, body: { name: "Org C", ownerEmail: "carol@c.test", ownerName: "Carol" },
  });
  assert.equal(carolOrg.status, 201);
  const alice = await deviceTokens(env, env.alice, env.a1);
  const put = (token: string, email: string, name: string, role = "member") =>
    request(env.origin, `/api/v1/organizations/${env.a.id}/memberships`, { method: "POST", token, body: { email, name, role } });
  const nameOf = async (email: string) =>
    (await env.database.query<{ name: string }>("SELECT name FROM users WHERE email = $1", [email])).rows[0]?.name;

  const refused = await put(alice.accessToken, "carol@c.test", "Mallory");
  assert.equal(refused.status, 409);
  assert.equal(refused.body.error, "invitation_required");
  assert.equal(await nameOf("carol@c.test"), "Carol");
  const memberships = await env.database.query(
    "SELECT 1 FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
    [env.a.id, carolOrg.body.owner.id],
  );
  assert.equal(memberships.rows.length, 0);

  // A brand-new address is still added directly.
  assert.equal((await put(alice.accessToken, "dave@a.test", "Dave")).status, 200);
  assert.equal(await nameOf("dave@a.test"), "Dave");
  // An existing member's role changes; their name is theirs, not the admin's.
  const promoted = await put(alice.accessToken, "bob@b.test", "Robert", "admin");
  assert.equal(promoted.status, 200);
  assert.equal(promoted.body.role, "admin");
  assert.equal(await nameOf("bob@b.test"), "Bob");
  // The installation operator may add an existing person; the name is kept.
  assert.equal((await put(BOOTSTRAP, "carol@c.test", "Renamed")).status, 200);
  assert.equal(await nameOf("carol@c.test"), "Carol");
});
