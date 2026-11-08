import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import { createAdminModule } from "../src/admin/routes.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * acquisition-operator workspace API tokens: minted by a workspace
 * owner/admin through the deployment-api-tokens user-token routes (also
 * served at /cloud/api/v1), presented by an operator service to RelayHistory
 * and verified through introspection as a `service` principal. Plus the
 * `rth:acquire` scope on Desktop-issued sessions.
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 6) } };
const FILES = "https://files.selfhosted.test";
const HISTORY = "https://history.selfhosted.test";
const DAY_MS = 24 * 60 * 60 * 1_000;
const VERIFIER = "desktop-verifier-0123456789abcdefghijklmnopqrstuvwxyz0123456789";
const CHALLENGE = createHash("sha256").update(VERIFIER).digest("base64url");
const DEVICE_SCOPES = ["cli:auth", "rth:read", "rth:sync", "rth:acquire"];
// Browser sign-in sessions carry "account" (DG-001, selfhost/multi-tenant), never rth:acquire.
const BROWSER_SCOPES = ["cli:auth", "rth:read", "rth:sync", "account"];
// Desktop handoff / exchange sessions carry rth:acquire plus "desktop:workspaces" (DG-001).
const DESKTOP_SCOPES = [...DEVICE_SCOPES, "desktop:workspaces"];

async function deviceToken(origin: string, userId: string, workspaceId: string): Promise<{
  accessToken: string;
  scope: string;
}> {
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
  return { accessToken: issued.body.access_token as string, scope: issued.body.scope as string };
}

/** Signs a dashboard browser in through /login, approved by the bootstrap bearer. */
async function browserSession(origin: string, userId: string, workspaceId: string): Promise<string> {
  const login = await fetch(`${origin}/login`);
  const code = (await login.text()).match(/<code>([A-Z0-9]{4}-[A-Z0-9]{4})<\/code>/)?.[1];
  assert(code);
  const deviceCookie = login.headers.get("set-cookie")!.split(";")[0]!;
  const approved = await request(origin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: BOOTSTRAP,
    body: { action: "approve", user_code: code, user_id: userId, workspace_id: workspaceId },
  });
  assert.equal(approved.status, 200);
  const poll = await request(origin, "/login/poll", { method: "POST", cookie: deviceCookie });
  assert.equal(poll.status, 200);
  const session = poll.headers.get("set-cookie")?.match(/agent_relay_session=[^;]+/)?.[0];
  assert(session);
  return session;
}

async function setup(t: TestContext, extra: Partial<SelfhostConfig> = {}) {
  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayauthUrl: null,
    relayauthApiKey: null,
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: HISTORY,
    introspectSecret: INTROSPECT_SECRET,
    introspectAudiences: [HISTORY, `${FILES}/`],
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: SERVICE,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/dashboard/`,
    port: 0,
    host: "127.0.0.1",
    ...extra,
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  const admin = createAdminModule({ config, database, keyring: KEYRING });
  control.on("request", createApp({ config, store, admin }));
  t.after(async () => {
    await close(control);
    await database.close();
  });

  const org = await request(origin, "/api/v1/organizations", {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const workspaces: string[] = [];
  for (const name of ["primary", "other"]) {
    const created = await request(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, relaycastApiKey: `rk_${name}` },
    });
    assert.equal(created.status, 201);
    workspaces.push(created.body.id as string);
  }
  const member = await request(origin, `/api/v1/organizations/${org.body.id}/memberships`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { email: "member@acme.test", name: "Member", role: "member" },
  });
  assert.equal(member.status, 200);
  const workspaceId = workspaces[0]!;
  const ownerId = org.body.owner.id as string;
  const base = `/api/v1/workspaces/${workspaceId}/deployment-api-tokens`;
  const owner = (await deviceToken(origin, ownerId, workspaceId)).accessToken;
  return {
    database,
    store,
    origin,
    base,
    cloudBase: `/cloud${base}`,
    organizationId: org.body.id as string,
    ownerId,
    workspaceId,
    otherWorkspaceId: workspaces[1]!,
    owner,
    member: (await deviceToken(origin, member.body.userId, workspaceId)).accessToken,
    mint: (body: Record<string, unknown>, token = owner, path = base) =>
      request(origin, path, { method: "POST", token, body }),
    introspect: (body: Record<string, unknown>) =>
      request(origin, "/internal/v1/auth/introspect", { method: "POST", token: INTROSPECT_SECRET, body }),
  };
}

const operatorBody = (extra: Record<string, unknown> = {}) => ({
  label: "acquisition operator",
  purpose: "acquisition-operator",
  aud: HISTORY,
  ...extra,
});

test("acquisition-operator tokens: minted, listed and revoked on /api/v1 and /cloud/api/v1", async (t) => {
  const ctx = await setup(t);
  for (const path of [ctx.base, ctx.cloudBase]) {
    const created = await ctx.mint(operatorBody({ aud: "HTTPS://History.SelfHosted.test:443/" }), ctx.owner, path);
    assert.equal(created.status, 201, path);
    const accessToken = created.body.accessToken as string;
    assert.match(accessToken, /^sh_wk_/);
    assert.equal(created.body.purpose, "acquisition-operator");
    assert.deepEqual(created.body.scopes, ["acquisition:operate"]);
    assert.equal(created.body.aud, HISTORY);
    assert.equal(created.body.agent_name, null);
    assert.equal(created.body.status, "active");

    for (const listPath of [ctx.base, ctx.cloudBase]) {
      const listed = await request(ctx.origin, listPath, { token: ctx.owner });
      assert.equal(listed.status, 200, listPath);
      assert(!listed.raw.includes(accessToken), "the token value is shown once");
      const row = listed.body.tokens.find((token: any) => token.id === created.body.id);
      assert(row, listPath);
      assert.equal(row.purpose, "acquisition-operator");
      assert.deepEqual(row.scopes, ["acquisition:operate"]);
      assert.equal(row.aud, HISTORY);
      assert.equal(row.agent_name, null);
    }

    const audit = await request(ctx.origin, `/api/v1/workspaces/${ctx.workspaceId}/admin/audit`, { token: ctx.owner });
    assert(audit.raw.includes(`${created.body.id} (acquisition-operator -> ${HISTORY})`));
    assert(!audit.raw.includes(accessToken));

    const removed = await request(ctx.origin, `${path}/${created.body.id}`, { method: "DELETE", token: ctx.owner });
    assert.equal(removed.status, 204, path);
    const again = await request(ctx.origin, `${path}/${created.body.id}`, { method: "DELETE", token: ctx.owner });
    assert.equal(again.status, 404, path);
    assert.equal(again.body.error, "token_not_found");
  }
});

test("acquisition-operator expiry: neverExpires allowed, expiryDays 1-365, default 90 days", async (t) => {
  const ctx = await setup(t);
  const forever = await ctx.mint(operatorBody({ neverExpires: true }));
  assert.equal(forever.status, 201);
  assert.equal(forever.body.accessTokenExpiresAt, null);

  for (const expiryDays of [0, 366, 400, 1.5, "30"]) {
    const bad = await ctx.mint(operatorBody({ expiryDays }));
    assert.equal(bad.status, 400, `expiryDays ${String(expiryDays)}`);
    assert.equal(bad.body.error, "invalid_request");
  }

  const before = Date.now();
  const defaulted = await ctx.mint(operatorBody());
  assert.equal(defaulted.status, 201);
  const expiresAt = Date.parse(defaulted.body.accessTokenExpiresAt);
  assert(expiresAt >= before + 90 * DAY_MS - 5_000 && expiresAt <= Date.now() + 90 * DAY_MS + 5_000);

  const week = await ctx.mint(operatorBody({ expiryDays: 7 }));
  assert.equal(week.status, 201);
  assert(Math.abs(Date.parse(week.body.accessTokenExpiresAt) - (Date.now() + 7 * DAY_MS)) < 10_000);

  // Still refused for purposes outside the never-expire list.
  const deployment = await ctx.mint({ label: "ci", purpose: "deployment", neverExpires: true });
  assert.equal(deployment.status, 400);
  assert.match(deployment.body.message, /workflow, relayfile-agent and acquisition-operator/);
});

test("acquisition-operator mint refusals: aud, agent_name, scopes, roles, workspace binding, callers", async (t) => {
  const ctx = await setup(t);
  const refused = async (response: Awaited<ReturnType<typeof ctx.mint>>, status: number, error: string, what: string) => {
    assert.equal(response.status, status, what);
    assert.equal(response.body.error, error, what);
  };

  for (const aud of [undefined, null, "", "https://elsewhere.test", "not a url", "ftp://history.selfhosted.test", 7]) {
    await refused(await ctx.mint(operatorBody({ aud })), 400, "invalid_request", `aud ${String(aud)}`);
  }
  await refused(await ctx.mint(operatorBody({ agent_name: "builder" })), 400, "invalid_request", "agent_name");
  const scoped = await ctx.mint(operatorBody({ scopes: ["acquisition:operate"] }));
  await refused(scoped, 400, "invalid_request", "scopes");
  assert.equal(scoped.body.message, "scopes are fixed by purpose");
  await refused(await ctx.mint(operatorBody({ scope: "acquisition:operate" })), 400, "invalid_request", "scope");
  // scope/scopes are refused for every purpose.
  for (const purpose of ["deployment", "workflow", "agent-runtime", "relayfile-agent"]) {
    const body = purpose === "relayfile-agent"
      ? { label: "x", purpose, agent_name: "builder", aud: FILES, scopes: ["fs:read"] }
      : { label: "x", purpose, scopes: [] };
    await refused(await ctx.mint(body), 400, "invalid_request", `scopes for ${purpose}`);
  }

  await refused(await ctx.mint(operatorBody(), ctx.member), 403, "forbidden", "member");

  // A user whose session is bound to the other workspace.
  const elsewhere = (await deviceToken(ctx.origin, ctx.ownerId, ctx.otherWorkspaceId)).accessToken;
  await refused(await ctx.mint(operatorBody(), elsewhere), 404, "workspace_not_found", "other workspace session");
  await refused(
    await ctx.mint(operatorBody(), ctx.owner, "/api/v1/workspaces/00000000-0000-4000-8000-000000000000/deployment-api-tokens"),
    404,
    "workspace_not_found",
    "unknown workspace",
  );

  const operator = await ctx.mint(operatorBody());
  assert.equal(operator.status, 201);
  for (const [caller, token] of [
    ["acquisition-operator sh_wk_", operator.body.accessToken as string],
    ["internal service token", SERVICE],
    ["bootstrap token", BOOTSTRAP],
  ] as const) {
    await refused(await ctx.mint(operatorBody(), token), 401, "unauthorized", caller);
    const listed = await request(ctx.origin, ctx.base, { token });
    assert.equal(listed.status, 401, `${caller} list`);
    const removed = await request(ctx.origin, `${ctx.base}/${operator.body.id}`, { method: "DELETE", token });
    assert.equal(removed.status, 401, `${caller} revoke`);
  }
  assert.equal((await request(ctx.origin, ctx.base, { token: ctx.member })).status, 403);
  assert.equal(
    (await request(ctx.origin, `${ctx.base}/${operator.body.id}`, { method: "DELETE", token: ctx.member })).status,
    403,
  );
});

test("acquisition-operator mint needs introspection enabled", async (t) => {
  const ctx = await setup(t, { introspectSecret: null });
  const refused = await ctx.mint(operatorBody());
  assert.equal(refused.status, 400);
  assert.equal(refused.body.error, "invalid_request");
  assert.match(refused.body.message, /acquisition-operator tokens need token introspection enabled/);
});

test("several acquisition-operator tokens coexist in one workspace", async (t) => {
  const ctx = await setup(t);
  const first = await ctx.mint(operatorBody({ label: "backend" }));
  const second = await ctx.mint(operatorBody({ label: "cloud", aud: FILES }));
  const third = await ctx.mint(operatorBody({ label: "backend" }));
  for (const created of [first, second, third]) assert.equal(created.status, 201);
  const listed = await request(ctx.origin, ctx.base, { token: ctx.owner });
  const operators = listed.body.tokens.filter((token: any) => token.purpose === "acquisition-operator");
  assert.equal(operators.length, 3);
  assert(operators.every((token: any) => token.status === "active"));
});

test("introspection answers for an acquisition-operator token as a service principal", async (t) => {
  const ctx = await setup(t);
  const created = await ctx.mint(operatorBody({ expiryDays: 30 }));
  const token = created.body.accessToken as string;
  const row = (await ctx.database.query<{ created_at: Date }>(
    "SELECT created_at FROM selfhost_workspace_api_tokens WHERE id = $1",
    [created.body.id],
  )).rows[0]!;

  const active = await ctx.introspect({ token, aud: `${HISTORY}/`, workspace: ctx.workspaceId });
  assert.equal(active.status, 200);
  assert.equal(active.headers.get("cache-control"), "no-store");
  assert.deepEqual(active.body, {
    active: true,
    principal_type: "service",
    sub: created.body.id,
    email: null,
    agent_name: null,
    machine_id: null,
    org: ctx.organizationId,
    workspace: ctx.workspaceId,
    scopes: ["acquisition:operate"],
    aud: HISTORY,
    iat: Math.floor(new Date(row.created_at).getTime() / 1_000),
    exp: Math.floor(Date.parse(created.body.accessTokenExpiresAt) / 1_000),
    token_id: created.body.id,
  });
  assert(!active.raw.includes(token), "the response never carries the token");

  // workspace absent: the token's workspace is authoritative.
  const absent = await ctx.introspect({ token, aud: HISTORY });
  assert.equal(absent.body.active, true);
  assert.equal(absent.body.workspace, ctx.workspaceId);

  // No expiry: exp is a rolling window, as for agent tokens.
  const forever = await ctx.mint(operatorBody({ neverExpires: true }));
  const before = Math.floor(Date.now() / 1_000);
  const rolling = await ctx.introspect({ token: forever.body.accessToken, aud: HISTORY });
  assert.equal(rolling.body.principal_type, "service");
  assert(rolling.body.exp >= before + 3_590 && rolling.body.exp <= Math.floor(Date.now() / 1_000) + 3_610);

  const used = (await ctx.database.query<{ last_used_at: Date | null }>(
    "SELECT last_used_at FROM selfhost_workspace_api_tokens WHERE id = $1",
    [created.body.id],
  )).rows[0]!;
  assert.notEqual(used.last_used_at, null);
});

test("introspection inactive reasons for acquisition-operator tokens", async (t) => {
  const ctx = await setup(t);
  const operator = (await ctx.mint(operatorBody())).body;
  const inactive = async (body: Record<string, unknown>, reason: string) => {
    const result = await ctx.introspect(body);
    assert.equal(result.status, 200, reason);
    assert.deepEqual(result.body, { active: false, reason }, reason);
  };

  await inactive({ token: operator.accessToken, aud: FILES }, "audience");
  await inactive({ token: operator.accessToken, aud: "https://elsewhere.test" }, "audience");
  await inactive({ token: operator.accessToken, aud: HISTORY, workspace: ctx.otherWorkspaceId }, "workspace");
  await inactive({ token: operator.accessToken, aud: HISTORY, machine: "node-1" }, "machine_not_owned");

  const expiring = (await ctx.mint(operatorBody())).body;
  await ctx.database.query(
    "UPDATE selfhost_workspace_api_tokens SET expires_at = now() - interval '1 second' WHERE id = $1",
    [expiring.id],
  );
  await inactive({ token: expiring.accessToken, aud: HISTORY }, "expired");

  assert.equal((await request(ctx.origin, `${ctx.base}/${operator.id}`, { method: "DELETE", token: ctx.owner })).status, 204);
  await inactive({ token: operator.accessToken, aud: HISTORY }, "revoked");
});

test("Desktop-issued sessions carry rth:acquire; dashboard browser sessions do not", async (t) => {
  const ctx = await setup(t);
  const scopesOf = async (accessToken: string) =>
    (await ctx.database.query<{ scopes: string[] }>(
      "SELECT scopes FROM selfhost_token_sessions WHERE access_token_hash = $1",
      [createHash("sha256").update(accessToken).digest("hex")],
    )).rows[0]?.scopes;

  // Device flow (Desktop and CLI).
  const device = await deviceToken(ctx.origin, ctx.ownerId, ctx.workspaceId);
  assert.equal(device.scope, DEVICE_SCOPES.join(" "));
  assert.deepEqual(await scopesOf(device.accessToken), DEVICE_SCOPES);
  const introspected = await ctx.introspect({ token: device.accessToken, aud: HISTORY });
  assert.equal(introspected.body.active, true);
  assert.equal(introspected.body.principal_type, "desktop-user");
  assert(introspected.body.scopes.includes("rth:acquire"));

  // Dashboard browser session through /login: no rth:acquire.
  const session = await browserSession(ctx.origin, ctx.ownerId, ctx.workspaceId);
  const sessionToken = session.slice("agent_relay_session=".length);
  assert.deepEqual(await scopesOf(sessionToken), BROWSER_SCOPES);
  const browserIntrospected = await ctx.introspect({ token: sessionToken, aud: HISTORY });
  assert.equal(browserIntrospected.body.active, true);
  assert(!browserIntrospected.body.scopes.includes("rth:acquire"));

  // OIDC / email-link browser sign-in: no rth:acquire either.
  const signedIn = await ctx.database.transaction((tx) => ctx.store.issueBrowserSession(tx, {
    userId: ctx.ownerId,
    organizationId: ctx.organizationId,
    workspaceId: ctx.workspaceId,
    label: "Browser sign-in (SSO)",
  }));
  assert.deepEqual(signedIn.scopes, BROWSER_SCOPES);
  assert.deepEqual(await scopesOf(signedIn.accessToken), BROWSER_SCOPES);

  // Desktop browser handoff (/cli/login) and its exchange.
  const params = new URLSearchParams({
    redirect_uri: "http://127.0.0.1:5123/callback/STATE1",
    state: "STATE1",
    client: "desktop",
    workspace_selection: "desktop",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    // An account session with several reachable workspaces gets the picker
    // (selfhost/multi-tenant); naming the workspace goes straight to the handoff.
    workspace: ctx.workspaceId,
  });
  const handoff = await fetch(`${ctx.origin}/cloud/api/v1/cli/login?${params}`, {
    redirect: "manual",
    headers: { cookie: session },
  });
  assert.equal(handoff.status, 307);
  const handoffToken = new URL(handoff.headers.get("location")!).searchParams.get("access_token")!;
  assert.match(handoffToken, /^sh_at_/);
  assert.deepEqual(await scopesOf(handoffToken), DESKTOP_SCOPES);
  const exchanged = await request(ctx.origin, "/cloud/api/v1/auth/desktop/session", {
    method: "POST", token: handoffToken, body: { codeVerifier: VERIFIER },
  });
  assert.equal(exchanged.status, 200);
  assert.deepEqual(await scopesOf(exchanged.body.accessToken), DESKTOP_SCOPES);
  const desktop = await ctx.introspect({ token: exchanged.body.accessToken, aud: HISTORY });
  assert.equal(desktop.body.active, true);
  assert.deepEqual(desktop.body.scopes, DESKTOP_SCOPES);

  // A refresh keeps the session's scopes.
  const refreshed = await request(ctx.origin, "/cloud/api/v1/auth/token/refresh", {
    method: "POST", body: { refreshToken: exchanged.body.refreshToken },
  });
  assert.equal(refreshed.status, 200);
  assert.deepEqual(await scopesOf(refreshed.body.accessToken), DESKTOP_SCOPES);
});
