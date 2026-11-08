import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import test from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { createApp, normalizeRoutePath } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import type { Database, SqlExecutor, SqlResult } from "../src/database.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";

class PGliteDatabase implements Database {
  readonly schema = "public";
  constructor(readonly client = new PGlite()) {}

  async query<T extends Record<string, unknown>>(
    sql: string,
    params: unknown[] = [],
  ): Promise<SqlResult<T>> {
    const result = params.length > 0
      ? await this.client.query<T>(sql, params)
      : await this.client.query<T>(sql);
    return { rows: result.rows };
  }

  async transaction<T>(run: (transaction: SqlExecutor) => Promise<T>): Promise<T> {
    return this.client.transaction(async (transaction) => run({
      query: async <R extends Record<string, unknown>>(
        sql: string,
        params: unknown[] = [],
      ) => {
        const result = params.length > 0
          ? await transaction.query<R>(sql, params)
          : await transaction.query<R>(sql);
        return { rows: result.rows };
      },
      exec: async (sql: string) => {
        await transaction.exec(sql);
      },
    }));
  }

  async close(): Promise<void> {
    await this.client.close();
  }

  async exec(sql: string): Promise<void> {
    await this.client.exec(sql);
  }
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");
  return `http://127.0.0.1:${address.port}`;
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => error ? reject(error) : resolve()));
}

async function jsonRequest(
  baseUrl: string,
  path: string,
  options: {
    method?: string;
    token?: string;
    cookie?: string;
    body?: Record<string, unknown>;
  } = {},
): Promise<{ status: number; body: Record<string, any>; headers: Headers }> {
  const response = await fetch(`${baseUrl}${path}`, {
    method: options.method ?? "GET",
    headers: {
      ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
      ...(options.cookie ? { cookie: options.cookie } : {}),
      ...(options.body ? { "content-type": "application/json" } : {}),
    },
    ...(options.body ? { body: JSON.stringify(options.body) } : {}),
  });
  const body = response.status === 204 ? {} : await response.json() as Record<string, any>;
  return { status: response.status, body, headers: response.headers };
}

test("the /cloud prefix aliases every versioned Desktop route", () => {
  for (const path of [
    "/api/v1/auth/device/start",
    "/api/v1/auth/device/approve",
    "/api/v1/auth/device/token",
    "/api/v1/auth/token/refresh",
    "/api/v1/auth/token/revoke",
    "/api/v1/auth/whoami",
    "/api/v1/organizations",
    "/api/v1/organizations/o/workspaces",
    "/api/v1/organizations/o/memberships",
    "/api/v1/workspaces/w/resolve",
    "/api/v1/workspaces/w/runtime",
    "/api/v1/workspaces/w/sessions",
    "/api/v1/workspaces/w/sessions/s/events",
    "/api/v1/workspaces/w/relayhistory/session",
    "/api/v1/workspaces/w/relayhistory/origin",
  ]) {
    assert.equal(normalizeRoutePath(`/cloud${path}`), path);
  }
});

function jwt(payload: Record<string, unknown>): string {
  return [
    Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url"),
    Buffer.from(JSON.stringify(payload)).toString("base64url"),
    "test-signature",
  ].join(".");
}

test("device flow, tenant isolation, token rotation, runtime, and History issuance", async (t) => {
  const publicRelaycastOrigin = "https://relaycast.selfhosted.company";
  const publicHistoryOrigin = "https://history.selfhosted.company";
  const upstreamRequests: Array<{
    method: string;
    path: string;
    query: Record<string, string>;
    body: Record<string, any>;
    authorization?: string;
  }> = [];
  let upstreamOrigin = "";
  const upstream = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = raw ? JSON.parse(raw) as Record<string, any> : {};
    const url = new URL(request.url!, upstreamOrigin);
    upstreamRequests.push({
      method: request.method!,
      path: url.pathname,
      query: Object.fromEntries(url.searchParams),
      body,
      authorization: request.headers.authorization,
    });
    response.setHeader("content-type", "application/json");
    if (url.pathname === "/v1/tokens/relayhistory-assertion") {
      response.end(JSON.stringify({
        accessToken: `relay_ag_${jwt({
          org: body.orgId,
          wks: body.workspaceId,
          sponsorId: body.sponsorId,
          scopes: body.scopes,
          aud: publicHistoryOrigin,
        })}`,
      }));
      return;
    }
    if (url.pathname === "/v1/cli/login") {
      response.end(JSON.stringify({
        sessionId: "history-session",
        accessToken: "history-access",
        accessTokenExpiresAt: "2030-01-01T00:00:00.000Z",
        refreshToken: "history-refresh",
        refreshTokenExpiresAt: "2030-02-01T00:00:00.000Z",
        tokenType: "Bearer",
        scopes: ["rth:read", "rth:sync"],
      }));
      return;
    }
    const attested = url.searchParams.get("workspace");
    if (attested) response.setHeader("x-relayhistory-workspace-id", attested);
    if (url.pathname === "/v1/sessions") {
      response.end(JSON.stringify({
        sessions: [{
          sessionId: "session/one",
          source: "codex",
          summary: "Fixed login",
          lastTs: "2026-11-02T18:00:00.000Z",
          projectId: "agent-relay",
        }],
        nextCursor: "next-page",
      }));
      return;
    }
    if (url.pathname === "/v1/sessions/session%2Fone/events") {
      response.end(JSON.stringify({
        events: [
          { eventId: "event-2", ts: "2026-11-02T18:00:02.000Z", source: "codex" },
          { eventId: "event-1", ts: "2026-11-02T18:00:01.000Z", source: "codex" },
        ],
      }));
      return;
    }
    response.statusCode = 404;
    response.end("{}");
  });
  upstreamOrigin = await listen(upstream);

  const database = new PGliteDatabase();
  let control: Server | undefined;
  t.after(async () => {
    if (control) await close(control);
    await close(upstream);
    await database.close();
  });
  const applied = await migrate(database);
  assert.deepEqual(applied.slice(0, 2), [
    "0001_control_plane.sql",
    "0002_single_organization.sql",
  ]);
  assert.deepEqual(applied, [...applied].sort(), "migrations apply in filename order");
  for (const name of [
    "0003_admin_api_tokens.sql",
    "0003_admin_env_vars.sql",
    "0003_admin_provider_connections.sql",
    "0003_flows_workers_runs.sql",
    "0003_telemetry.sql",
  ]) {
    assert.ok(applied.includes(name), `${name} is applied`);
  }
  assert.ok(applied.includes("0014_multi_tenant.sql"), "0014 is applied");
  assert.deepEqual(await migrate(database), [], "migrations are idempotent");
  const bootstrapToken = "bootstrap-token-that-is-at-least-32-bytes";
  const config: SelfhostConfig = {
    databaseSchema: "public",
    databaseUrl: "unused-in-test",
    publicBaseUrl: "https://control.internal.example",
    relaycastUrl: "http://relaycast.relay.svc.cluster.local",
    relaycastPublicUrl: publicRelaycastOrigin,
    relayauthUrl: upstreamOrigin,
    relayhistoryUrl: upstreamOrigin,
    relayhistoryPublicUrl: publicHistoryOrigin,
    relayauthApiKey: "rak_test",
    bootstrapToken,
    encryptionKeyring: {
      active: { id: "test-key", key: Buffer.alloc(32, 7) },
    },
    internalServiceToken: null,
    oauthRedirectUrl: "https://control.internal.example/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.internal.example/",
    port: 3000,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  control = createServer(createApp({ config, store }));
  const controlOrigin = await listen(control);

  const health = await jsonRequest(controlOrigin, "/healthz");
  assert.equal(health.status, 200);
  const readyz = await jsonRequest(controlOrigin, "/readyz");
  assert.equal(readyz.status, 200);
  assert.deepEqual(readyz.body.introspection, { enabled: false, audiences: [] });
  const cloudHealth = await jsonRequest(controlOrigin, "/cloud/api/health");
  assert.equal(cloudHealth.status, 200);
  assert.equal(cloudHealth.body.status, "ok");
  assert.equal(typeof cloudHealth.body.timestamp, "string");
  assert.equal(cloudHealth.body.version, "0.1.0");

  const firstOrg = await jsonRequest(controlOrigin, "/api/v1/organizations", {
    method: "POST",
    token: bootstrapToken,
    body: {
      name: "First tenant",
      ownerEmail: "owner-one@example.test",
      ownerName: "Owner One",
    },
  });
  assert.equal(firstOrg.status, 201);
  const firstWorkspace = await jsonRequest(
    controlOrigin,
    `/api/v1/organizations/${firstOrg.body.id}/workspaces`,
    {
      method: "POST",
      token: bootstrapToken,
      body: {
        name: "First workspace",
        relaycastWorkspaceId: "rc-first",
        relaycastApiKey: "rk_live_first",
      },
    },
  );
  assert.equal(firstWorkspace.status, 201);

  const secondOrg = await jsonRequest(controlOrigin, "/api/v1/organizations", {
    method: "POST",
    token: bootstrapToken,
    body: {
      name: "Second tenant",
      ownerEmail: "owner-two@example.test",
      ownerName: "Owner Two",
    },
  });
  assert.equal(secondOrg.status, 409);
  assert.equal(secondOrg.body.error, "organization_already_configured");
  const singletonSchema = await database.query<{ index: string | null; slot: number }>(
    `SELECT to_regclass('public.selfhost_single_organization_idx')::text AS index,
            (SELECT count(*)::int FROM information_schema.columns
              WHERE table_name = 'selfhost_organizations'
                AND column_name = 'installation_slot') AS slot`,
  );
  assert.deepEqual(
    singletonSchema.rows[0],
    { index: null, slot: 0 },
    "0014 moves the single-organization rule from the schema to SELFHOST_TENANCY",
  );

  const secondWorkspace = await jsonRequest(
    controlOrigin,
    `/api/v1/organizations/${firstOrg.body.id}/workspaces`,
    {
      method: "POST",
      token: bootstrapToken,
      body: {
        name: "Second workspace",
        relaycastWorkspaceId: "rc-second",
        relaycastApiKey: "rk_live_second",
      },
    },
  );

  const started = await jsonRequest(controlOrigin, "/api/v1/auth/device/start", {
    method: "POST",
    body: { client_name: "headless-test" },
  });
  assert.equal(started.status, 201);
  const mismatchedDeviceBindingRejected = await database.query(
    `UPDATE selfhost_device_authorizations
        SET organization_id = $2, workspace_id = $3
      WHERE user_code = $1`,
    [
      started.body.user_code,
      "00000000-0000-4000-8000-000000000002",
      firstWorkspace.body.id,
    ],
  ).then(() => false, () => true);
  assert(
    mismatchedDeviceBindingRejected,
    "the schema rejects cross-tenant device approval bindings",
  );
  const approved = await jsonRequest(controlOrigin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: bootstrapToken,
    body: {
      action: "approve",
      user_code: started.body.user_code,
      user_id: firstOrg.body.owner.id,
      workspace_id: firstWorkspace.body.id,
    },
  });
  assert.equal(approved.status, 200);
  const tokenResponse = await jsonRequest(controlOrigin, "/api/v1/auth/device/token", {
    method: "POST",
    body: { device_code: started.body.device_code },
  });
  assert.equal(tokenResponse.status, 200);
  const accessToken = tokenResponse.body.access_token as string;
  const refreshToken = tokenResponse.body.refresh_token as string;

  const whoami = await jsonRequest(controlOrigin, "/api/v1/auth/whoami", {
    token: accessToken,
  });
  assert.equal(whoami.status, 200);
  assert.equal(whoami.body.currentOrganization.id, firstOrg.body.id);
  assert.equal(whoami.body.currentWorkspace.id, firstWorkspace.body.id);
  const aliasedWhoami = await jsonRequest(controlOrigin, "/cloud/api/v1/auth/whoami", {
    token: accessToken,
  });
  assert.equal(aliasedWhoami.status, 200);
  assert.equal(aliasedWhoami.body.user.id, firstOrg.body.owner.id);

  const crossOrganizationMembership = await jsonRequest(
    controlOrigin,
    "/api/v1/organizations/00000000-0000-4000-8000-000000000002/memberships",
    {
      method: "POST",
      token: bootstrapToken,
      body: {
        email: "owner-one@example.test",
        name: "Owner One",
        role: "member",
      },
    },
  );
  assert.equal(crossOrganizationMembership.status, 404);

  const demoteLastOwner = await jsonRequest(
    controlOrigin,
    `/api/v1/organizations/${firstOrg.body.id}/memberships`,
    {
      method: "POST",
      token: accessToken,
      body: {
        email: "owner-one@example.test",
        name: "Owner One",
        role: "member",
      },
    },
  );
  assert.equal(demoteLastOwner.status, 409);

  // Single mode: an owner adds and renames people directly, including someone
  // whose account already exists without a membership (no invitation needed).
  const putMember = (name: string) => jsonRequest(controlOrigin, `/api/v1/organizations/${firstOrg.body.id}/memberships`, {
    method: "POST",
    token: accessToken,
    body: { email: "member-one@example.test", name, role: "member" },
  });
  const added = await putMember("Member One");
  assert.equal(added.status, 200);
  const removedMember = await fetch(
    `${controlOrigin}/api/v1/organizations/${firstOrg.body.id}/memberships/${added.body.userId}`,
    { method: "DELETE", headers: { authorization: `Bearer ${accessToken}` } },
  );
  assert.equal(removedMember.status, 204);
  const readded = await putMember("Member Renamed");
  assert.equal(readded.status, 200);
  assert.equal(readded.body.userId, added.body.userId);
  const renamed = await database.query<{ name: string }>(
    "SELECT name FROM selfhost_users WHERE id = $1",
    [added.body.userId],
  );
  assert.equal(renamed.rows[0]!.name, "Member Renamed");
  await database.query("DELETE FROM selfhost_organization_memberships WHERE user_id = $1", [added.body.userId]);
  await database.query("DELETE FROM selfhost_users WHERE id = $1", [added.body.userId]);

  const ownResolve = await jsonRequest(
    controlOrigin,
    `/api/v1/workspaces/${firstWorkspace.body.id}/resolve`,
    { token: accessToken },
  );
  assert.equal(ownResolve.status, 200);
  assert.equal(ownResolve.body.relaycastApiKey, "rk_live_first");
  assert.equal(ownResolve.body.urls.relaycastUrl, publicRelaycastOrigin);

  for (const path of [
    `/api/v1/workspaces/${secondWorkspace.body.id}/resolve`,
    `/api/v1/workspaces/${secondWorkspace.body.id}/runtime`,
  ]) {
    const isolated = await jsonRequest(controlOrigin, path, { token: accessToken });
    assert.equal(isolated.status, 404, path);
  }
  const isolatedHistory = await jsonRequest(
    controlOrigin,
    `/api/v1/workspaces/${secondWorkspace.body.id}/relayhistory/session`,
    { method: "POST", token: accessToken, body: { mode: "sync" } },
  );
  assert.equal(isolatedHistory.status, 404);

  const crossWorkspaceDevice = await jsonRequest(controlOrigin, "/api/v1/auth/device/start", {
    method: "POST",
    body: { client_name: "cross-workspace-attempt" },
  });
  const crossWorkspaceApproval = await jsonRequest(
    controlOrigin,
    "/api/v1/auth/device/approve",
    {
      method: "POST",
      token: accessToken,
      body: {
        action: "approve",
        user_code: crossWorkspaceDevice.body.user_code,
        workspace_id: secondWorkspace.body.id,
      },
    },
  );
  assert.equal(crossWorkspaceApproval.status, 404);
  const rejectedApprovalPoll = await jsonRequest(
    controlOrigin,
    "/api/v1/auth/device/token",
    {
      method: "POST",
      body: { device_code: crossWorkspaceDevice.body.device_code },
    },
  );
  assert.equal(rejectedApprovalPoll.status, 400);
  assert.equal(rejectedApprovalPoll.body.error, "authorization_pending");

  const runtime = { id: "kubernetes", config: { namespace: "agents" } };
  assert.equal((await jsonRequest(
    controlOrigin,
    `/api/v1/workspaces/${firstWorkspace.body.id}/runtime`,
    { method: "PUT", token: accessToken, body: { runtime } },
  )).status, 200);
  const loadedRuntime = await jsonRequest(
    controlOrigin,
    `/api/v1/workspaces/${firstWorkspace.body.id}/runtime`,
    { token: accessToken },
  );
  assert.deepEqual(loadedRuntime.body.runtime, runtime);

  const history = await jsonRequest(
    controlOrigin,
    `/api/v1/workspaces/${firstWorkspace.body.id}/relayhistory/session`,
    { method: "POST", token: accessToken, body: { mode: "sync", label: "test" } },
  );
  assert.equal(history.status, 200);
  assert.equal(history.body.baseUrl, publicHistoryOrigin);
  assert.equal(history.body.accessToken, "history-access");
  assert.deepEqual(upstreamRequests.map((entry) => entry.path), [
    "/v1/tokens/relayhistory-assertion",
    "/v1/cli/login",
  ]);
  assert.equal(upstreamRequests[0]!.body.workspaceId, firstWorkspace.body.id);
  assert.equal(upstreamRequests[0]!.body.historyOrigin, publicHistoryOrigin);

  const login = await fetch(`${controlOrigin}/login`);
  assert.equal(login.status, 200);
  const loginHtml = await login.text();
  const loginCode = loginHtml.match(/<code>([A-Z0-9]{4}-[A-Z0-9]{4})<\/code>/)?.[1];
  assert(loginCode);
  const deviceCookie = login.headers.get("set-cookie");
  assert(deviceCookie);
  assert(deviceCookie.includes("agent_relay_device="));
  assert.match(deviceCookie, /Secure; HttpOnly; SameSite=Lax/);
  const deviceCookieHeader = deviceCookie.split(";")[0]!;
  const pendingBrowserPoll = await jsonRequest(controlOrigin, "/login/poll", {
    method: "POST",
    cookie: deviceCookieHeader,
  });
  assert.equal(pendingBrowserPoll.status, 202);
  assert.deepEqual(pendingBrowserPoll.body, { status: "pending", interval: 0 });
  assert.doesNotMatch(JSON.stringify(pendingBrowserPoll.body), /access|refresh|token/i);
  assert.equal((await jsonRequest(controlOrigin, "/cloud/api/auth/session?renew=0", {
    token: accessToken,
  })).status, 401, "the browser session route does not accept a bearer substitute");
  const browserApproval = await jsonRequest(controlOrigin, "/cloud/api/v1/auth/device/approve", {
    method: "POST",
    token: bootstrapToken,
    body: {
      action: "approve",
      user_code: loginCode,
      user_id: firstOrg.body.owner.id,
      workspace_id: firstWorkspace.body.id,
    },
  });
  assert.equal(browserApproval.status, 200);
  const browserPoll = await jsonRequest(controlOrigin, "/login/poll", {
    method: "POST",
    cookie: deviceCookieHeader,
  });
  assert.equal(browserPoll.status, 200);
  assert.deepEqual(browserPoll.body, { status: "authenticated", redirect: "/" });
  assert.doesNotMatch(JSON.stringify(browserPoll.body), /access|refresh|token/i);
  const setCookie = browserPoll.headers.get("set-cookie") ?? "";
  assert.match(setCookie, /agent_relay_session=[^;]+; Path=\/cloud;/);
  assert.match(setCookie, /agent_relay_device=; Path=\/login; Max-Age=0;/);
  assert.match(setCookie, /Secure; HttpOnly; SameSite=Lax/);
  assert.doesNotMatch(setCookie, /refresh/i);
  const browserCookie = setCookie.match(/agent_relay_session=([^;]+)/)?.[0];
  assert(browserCookie);
  assert.equal((await jsonRequest(
    controlOrigin,
    "/api/v1/auth/whoami",
    { cookie: browserCookie },
  )).status, 401, "browser cookies are accepted only by the /cloud mount");
  assert.equal((await jsonRequest(
    controlOrigin,
    "/cloud/api/v1/auth/whoami",
    { cookie: browserCookie },
  )).status, 200);
  const browserSession = await jsonRequest(
    controlOrigin,
    "/cloud/api/auth/session?renew=0",
    { cookie: browserCookie },
  );
  assert.equal(browserSession.status, 200);
  assert.equal(browserSession.body.authenticated, true);
  assert.deepEqual(browserSession.body.user, {
    id: firstOrg.body.owner.id,
    name: "Owner One",
    email: browserSession.body.user.email,
  });
  assert.deepEqual(browserSession.body.currentWorkspace, { id: firstWorkspace.body.id, name: "First workspace" });
  assert.equal(browserSession.body.currentOrganization.id, firstOrg.body.id);
  assert(browserSession.body.workspaces.some((workspace: { id: string }) => workspace.id === firstWorkspace.body.id));

  const sessionPage = await jsonRequest(
    controlOrigin,
    `/cloud/api/v1/workspaces/${firstWorkspace.body.id}/sessions?metadata=deferred&q=fix+login&cursor=older`,
    { cookie: browserCookie },
  );
  assert.equal(sessionPage.status, 200);
  assert.equal(typeof sessionPage.body.now, "string");
  delete sessionPage.body.now;
  assert.deepEqual(sessionPage.body, {
    items: [{
      sessionId: "session/one",
      source: "codex",
      summary: "Fixed login",
      lastTs: "2026-11-02T18:00:00.000Z",
      projectId: "agent-relay",
      project: { name: "agent-relay" },
    }],
    members: [{ id: firstOrg.body.owner.id, name: "Owner One" }],
    nextCursor: "next-page",
    error: false,
  });
  const listRead = [...upstreamRequests].reverse().find(
    (entry) => entry.path === "/v1/sessions",
  );
  assert.deepEqual(listRead?.query, {
    workspace: firstWorkspace.body.id,
    limit: "50",
    q: "fix login",
    cursor: "older",
  });
  assert.equal(listRead?.authorization, "Bearer history-access");

  const eventPage = await jsonRequest(
    controlOrigin,
    `/cloud/api/v1/workspaces/${firstWorkspace.body.id}/sessions/session%2Fone/events?source=codex`,
    { cookie: browserCookie },
  );
  assert.equal(eventPage.status, 200);
  assert.deepEqual(eventPage.body.events.map((event: any) => event.eventId), [
    "event-1",
    "event-2",
  ]);
  const eventRead = [...upstreamRequests].reverse().find(
    (entry) => entry.path === "/v1/sessions/session%2Fone/events",
  );
  assert.deepEqual(eventRead?.query, {
    workspace: firstWorkspace.body.id,
    source: "codex",
    order: "asc",
    limit: "1000",
    maxContent: "100000",
    includeMessageId: "true",
  });

  const readsBeforeProxyRejection = upstreamRequests.length;
  for (const path of [
    `/cloud/api/v1/workspaces/${firstWorkspace.body.id}/sessions?workspace=${secondWorkspace.body.id}`,
    `/cloud/api/v1/workspaces/${firstWorkspace.body.id}/sessions?q=one&q=two`,
    `/cloud/api/v1/workspaces/${firstWorkspace.body.id}/sessions?cursor=one&cursor=two`,
    `/cloud/api/v1/workspaces/${firstWorkspace.body.id}/sessions?metadata=deferred&metadata=deferred`,
    `/cloud/api/v1/workspaces/${firstWorkspace.body.id}/sessions/session%2Fone/events?source=codex&workspace=${secondWorkspace.body.id}`,
    `/cloud/api/v1/workspaces/${firstWorkspace.body.id}/sessions/session%2Fone/events?source=codex&source=claude`,
  ]) {
    assert.equal((await jsonRequest(
      controlOrigin,
      path,
      { cookie: browserCookie },
    )).status, 400, path);
  }
  assert.equal(upstreamRequests.length, readsBeforeProxyRejection);

  const readsBeforeIsolationCheck = upstreamRequests.length;
  const browserIsolated = await jsonRequest(
    controlOrigin,
    `/cloud/api/v1/workspaces/${secondWorkspace.body.id}/sessions`,
    { cookie: browserCookie },
  );
  assert.equal(browserIsolated.status, 404);
  assert.equal(upstreamRequests.length, readsBeforeIsolationCheck);

  const secondDevice = await jsonRequest(controlOrigin, "/api/v1/auth/device/start", {
    method: "POST",
    body: { client_name: "second-device" },
  });
  await jsonRequest(controlOrigin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: bootstrapToken,
    body: {
      action: "approve",
      user_code: secondDevice.body.user_code,
      user_id: firstOrg.body.owner.id,
      workspace_id: firstWorkspace.body.id,
    },
  });
  const secondDeviceTokens = await jsonRequest(controlOrigin, "/api/v1/auth/device/token", {
    method: "POST",
    body: { device_code: secondDevice.body.device_code },
  });
  assert.equal(secondDeviceTokens.status, 200);

  const refreshed = await jsonRequest(controlOrigin, "/api/v1/auth/token/refresh", {
    method: "POST",
    body: { refreshToken },
  });
  assert.equal(refreshed.status, 200);
  assert.equal((await jsonRequest(controlOrigin, "/api/v1/auth/token/refresh", {
    method: "POST",
    body: { refreshToken },
  })).status, 403, "a refresh token is one-time use");
  assert.equal((await jsonRequest(controlOrigin, "/api/v1/auth/whoami", {
    token: accessToken,
  })).status, 401, "rotation invalidates the previous access token");
  assert.equal((await jsonRequest(controlOrigin, "/api/v1/auth/whoami", {
    token: refreshed.body.accessToken,
  })).status, 200);
  assert.equal((await jsonRequest(controlOrigin, "/api/v1/auth/whoami", {
    token: secondDeviceTokens.body.access_token,
  })).status, 200, "rotation is isolated to one device session");

  assert.equal((await jsonRequest(controlOrigin, "/api/v1/auth/token/revoke", {
    method: "POST",
    token: refreshed.body.accessToken,
  })).status, 200);
  assert.equal((await jsonRequest(controlOrigin, "/api/v1/auth/whoami", {
    token: refreshed.body.accessToken,
  })).status, 401);

  // A second organization written past the API under single tenancy fails
  // readiness with tenancy_mismatch (DG-005); nothing is deleted, and members
  // of the first still see nothing of it.
  await database.query(
    "INSERT INTO selfhost_organizations (id, name) VALUES ($1, $2)",
    ["00000000-0000-4000-8000-000000000002", "Direct second tenant"],
  );
  assert.equal(await store.ready(), false);
  const notReady = await jsonRequest(controlOrigin, "/readyz");
  assert.equal(notReady.status, 503);
  assert.equal(notReady.body.reason, "tenancy_mismatch");
  assert.equal(notReady.body.message, "SELFHOST_TENANCY=single but 2 organisations exist");
  assert.equal((await database.query("SELECT count(*)::int AS n FROM selfhost_organizations")).rows[0]!.n, 2);
  assert.deepEqual(
    (await store.listOrganizations(firstOrg.body.owner.id)).map((org) => org.id),
    [firstOrg.body.id],
  );
});
