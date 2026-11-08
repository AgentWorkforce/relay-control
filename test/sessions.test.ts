import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server } from "node:http";
import test, { type TestContext } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import type { Database, SqlExecutor, SqlResult } from "../src/database.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { readWorkspaceHistory } from "../src/sessions/history.js";
import { historyReader } from "../src/mcp/context.js";

class PGliteDatabase implements Database {
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
      query: async <R extends Record<string, unknown>>(sql: string, params: unknown[] = []) => {
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

async function call(
  origin: string,
  path: string,
  options: { method?: string; token?: string; body?: Record<string, unknown> } = {},
): Promise<{ status: number; body: Record<string, any>; headers: Headers }> {
  const response = await fetch(`${origin}${path}`, {
    method: options.method ?? "GET",
    headers: {
      ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
      ...(options.body ? { "content-type": "application/json" } : {}),
    },
    ...(options.body ? { body: JSON.stringify(options.body) } : {}),
  });
  const body = response.status === 204 ? {} : await response.json() as Record<string, any>;
  return { status: response.status, body, headers: response.headers };
}

function jwt(payload: Record<string, unknown>): string {
  return [
    Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url"),
    Buffer.from(JSON.stringify(payload)).toString("base64url"),
    "test-signature",
  ].join(".");
}

type UpstreamRequest = {
  path: string;
  query: Record<string, string>;
  workspaceParams: string[];
  token?: string;
};

function lastRequest(
  requests: UpstreamRequest[],
  predicate: (entry: UpstreamRequest) => boolean,
): UpstreamRequest | undefined {
  return [...requests].reverse().find(predicate);
}

type Session = { sessionId: string; source: string; workspaceId: string; summary: string };

/**
 * A RelayHistory double with the real tenancy rules: one org, sessions stored
 * per workspace, org-wide reads when `workspace` is omitted, 403 when it does
 * not match the token, and `X-Relayhistory-Workspace-Id` attestation.
 */
async function startHistory(t: TestContext, historyOrigin: string, direct = false) {
  const requests: UpstreamRequest[] = [];
  const tokens = new Map<string, string>();
  const sessions: Session[] = [];
  const overrides = new Map<string, (request: IncomingMessage, url: URL) => {
    status?: number;
    body?: unknown;
    headers?: Record<string, string>;
  } | undefined>();
  const logins: Array<Record<string, any>> = [];
  /** Caller-token mode: which workspace each relaycontrol `sh_at_` token is bound to. */
  const callerTokens = new Map<string, string>();
  let loginScopes: string[] | undefined = ["rth:read"];
  let mints = 0;
  let origin = "";
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = raw ? JSON.parse(raw) as Record<string, any> : {};
    const url = new URL(request.url!, origin);
    const token = /^Bearer (.+)$/.exec(request.headers.authorization ?? "")?.[1];
    requests.push({
      path: url.pathname,
      query: Object.fromEntries(url.searchParams),
      workspaceParams: url.searchParams.getAll("workspace"),
      token,
    });
    response.setHeader("content-type", "application/json");
    const send = (status: number, value: unknown) => {
      response.statusCode = status;
      response.end(JSON.stringify(value));
    };
    if (direct && request.method !== "GET") {
      send(405, { error: "method_not_allowed" });
      return;
    }
    if (url.pathname === "/v1/tokens/relayhistory-assertion") {
      send(200, {
        accessToken: `relay_ag_${jwt({
          org: body.orgId,
          wks: body.workspaceId,
          sponsorId: body.sponsorId,
          scopes: body.scopes,
          aud: historyOrigin,
        })}`,
      });
      return;
    }
    if (url.pathname === "/v1/cli/login" && String(body.agentRelayToken).startsWith("sh_at_")) {
      // The self-host read API container: introspect the caller's token and
      // answer the same token back (refresh == access), scopes limited to
      // what the backend serves.
      logins.push(body);
      const workspace = callerTokens.get(String(body.agentRelayToken));
      if (!workspace) {
        send(401, { error: "unauthorized" });
        return;
      }
      mints += 1;
      tokens.set(String(body.agentRelayToken), workspace);
      send(200, {
        accessToken: body.agentRelayToken,
        accessTokenExpiresAt: "2099-01-01T00:00:00.000Z",
        refreshToken: body.agentRelayToken,
        refreshTokenExpiresAt: "2099-01-01T00:00:00.000Z",
        tokenType: "Bearer",
        ...(loginScopes ? { scopes: loginScopes } : {}),
      });
      return;
    }
    if (url.pathname === "/v1/cli/login") {
      mints += 1;
      const claims = JSON.parse(Buffer.from(
        String(body.agentRelayToken).replace(/^relay_ag_/, "").split(".")[1]!,
        "base64url",
      ).toString("utf8")) as { wks: string };
      const accessToken = `rth_at_${mints}`;
      tokens.set(accessToken, claims.wks);
      send(200, {
        accessToken,
        accessTokenExpiresAt: "2099-01-01T00:00:00.000Z",
        refreshToken: `rth_rt_${mints}`,
        refreshTokenExpiresAt: "2099-02-01T00:00:00.000Z",
        tokenType: "Bearer",
        scopes: ["rth:read"],
      });
      return;
    }
    const tokenWorkspace = token ? (direct ? callerTokens : tokens).get(token) : undefined;
    if (!tokenWorkspace) {
      send(401, { error: { code: "unauthorized" } });
      return;
    }
    const requested = url.searchParams.getAll("workspace");
    if (requested.length > 0 && (requested.length !== 1 || requested[0] !== tokenWorkspace)) {
      send(403, { error: { code: "forbidden" } });
      return;
    }
    const scope = requested[0];
    if (scope) response.setHeader("x-relayhistory-workspace-id", scope);
    const override = overrides.get(url.pathname)?.(request, url);
    if (override) {
      for (const [name, value] of Object.entries(override.headers ?? {})) {
        response.setHeader(name, value);
      }
      send(override.status ?? 200, override.body ?? {});
      return;
    }
    const visible = sessions.filter((row) => !scope || row.workspaceId === scope);
    if (url.pathname === "/v1/sessions") {
      send(200, {
        sessions: visible.map(({ workspaceId: _workspace, ...row }) => ({
          ...row,
          projectId: "relay",
          lastTs: "2026-11-02T18:00:00.000Z",
          userIds: [],
        })),
        nextCursor: null,
      });
      return;
    }
    if (url.pathname === "/v1/events") {
      send(200, {
        events: visible.map((row, index) => ({
          eventId: `match-${index}`,
          sessionId: row.sessionId,
          source: row.source,
          ts: "2026-11-02T18:00:00.000Z",
          kind: "assistant",
          content: row.summary,
        })),
        nextCursor: "search-next",
      });
      return;
    }
    const detail = /^\/v1\/sessions\/([^/]+)\/(events|turns|timing|catalog)$/.exec(url.pathname);
    if (detail) {
      const sessionId = decodeURIComponent(detail[1]!);
      const own = visible.find((row) => row.sessionId === sessionId);
      if (detail[2] === "events") {
        send(200, {
          sessionId,
          events: own
            ? [
              { eventId: "e2", ts: "2026-11-02T18:00:02.000Z", kind: "assistant", content: "done" },
              { eventId: "e1", ts: "2026-11-02T18:00:01.000Z", kind: "prompt", content: own.summary },
            ]
            : [],
          nextCursor: own ? "events-next" : null,
        });
        return;
      }
      if (detail[2] === "turns") {
        send(200, {
          sessionId,
          turns: own
            ? [{ id: "t1", role: "user", content: own.summary, ts: "2026-11-02T18:00:01.000Z", metadata: {} }]
            : [],
        });
        return;
      }
      if (!own) {
        send(404, { error: { code: "not_found" } });
        return;
      }
      if (detail[2] === "timing") {
        send(200, {
          sessionId,
          source: url.searchParams.get("source"),
          startedAt: "2026-11-02T18:00:00.000Z",
          lastActionAt: "2026-11-02T18:10:00.000Z",
          workMs: 420_000,
          waitingMs: 180_000,
          coverage: { lifecycleIntervalCount: 2, unmatchedToolCallCount: 0 },
          correlationId: "c",
        });
        return;
      }
      send(200, {
        sessionId,
        source: own.source,
        workspaceId: tokenWorkspace,
        catalog: { title: own.summary, gitBranch: "main", childSessionCount: 1 },
        parents: [],
        children: [{
          parentSessionId: sessionId,
          childSessionId: `${sessionId}-child`,
          childAgentType: "subagent",
          childAgentName: "reviewer",
        }],
        commitLinks: [],
        truncated: false,
        correlationId: "c",
      });
      return;
    }
    send(404, { error: { code: "not_found" } });
  });
  origin = await listen(server);
  t.after(() => close(server));
  return {
    origin,
    requests,
    sessions,
    overrides,
    logins,
    callerTokens,
    /** `undefined` omits `scopes` from the login reply. */
    set loginScopes(value: string[] | undefined) {
      loginScopes = value;
    },
    get mints() {
      return mints;
    },
    revokeAll() {
      tokens.clear();
    },
  };
}

async function setup(
  t: TestContext,
  now = new Date("2026-11-02T20:00:00.000Z"),
  options: { relayauth?: boolean; directReadApi?: boolean } = {},
) {
  const relayauth = options.relayauth ?? true;
  const historyOrigin = "https://history.selfhosted.test";
  const history = await startHistory(t, historyOrigin);
  const readApi = options.directReadApi ? await startHistory(t, historyOrigin, true) : undefined;
  const database = new PGliteDatabase();
  await migrate(database);
  const bootstrapToken = "bootstrap-token-that-is-at-least-32-bytes";
  const config: SelfhostConfig = {
    databaseUrl: "unused-in-test",
    publicBaseUrl: "https://control.internal.example",
    relaycastUrl: "http://relaycast.internal",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayauthUrl: relayauth ? history.origin : null,
    relayhistoryUrl: history.origin,
    ...(readApi ? { relayhistoryReadApiUrl: readApi.origin } : {}),
    relayhistoryPublicUrl: historyOrigin,
    relayauthApiKey: relayauth ? "rak_test" : null,
    bootstrapToken,
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    port: 3000,
    host: "127.0.0.1",
    internalServiceToken: null,
    oauthRedirectUrl: "https://control.internal.example/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.internal.example/",
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const control = createServer(createApp({ config, store, now: () => now }));
  const origin = await listen(control);
  t.after(async () => {
    await close(control);
    await database.close();
  });

  const org = await call(origin, "/api/v1/organizations", {
    method: "POST",
    token: bootstrapToken,
    body: { name: "Tenant", ownerEmail: "owner@example.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const workspace = async (name: string) => {
    const created = await call(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
      method: "POST",
      token: bootstrapToken,
      body: { name, relaycastApiKey: `rk_${name}` },
    });
    assert.equal(created.status, 201);
    return created.body.id as string;
  };
  const alpha = await workspace("alpha");
  const beta = await workspace("beta");
  const member = await call(origin, `/api/v1/organizations/${org.body.id}/memberships`, {
    method: "POST",
    token: bootstrapToken,
    body: { email: "member@example.test", name: "Member", role: "member" },
  });
  assert.equal(member.status, 200);
  const login = async (userId: string, workspaceId: string) => {
    const started = await call(origin, "/api/v1/auth/device/start", {
      method: "POST",
      body: { client_name: "sessions-test" },
    });
    const approved = await call(origin, "/api/v1/auth/device/approve", {
      method: "POST",
      token: bootstrapToken,
      body: {
        action: "approve",
        user_code: started.body.user_code,
        user_id: userId,
        workspace_id: workspaceId,
      },
    });
    assert.equal(approved.status, 200);
    const tokens = await call(origin, "/api/v1/auth/device/token", {
      method: "POST",
      body: { device_code: started.body.device_code },
    });
    assert.equal(tokens.status, 200);
    const accessToken = tokens.body.access_token as string;
    history.callerTokens.set(accessToken, workspaceId);
    readApi?.callerTokens.set(accessToken, workspaceId);
    return accessToken;
  };
  history.sessions.push(
    { sessionId: "alpha-1", source: "codex", workspaceId: alpha, summary: "Alpha work" },
    { sessionId: "beta-1", source: "claude", workspaceId: beta, summary: "Beta secret" },
  );
  if (readApi) readApi.sessions.push(...history.sessions);
  return {
    origin,
    history,
    readApi,
    config,
    store,
    disableDirectRead: () => { config.relayhistoryReadApiUrl = null; },
    alpha,
    beta,
    ownerId: org.body.owner.id as string,
    memberId: member.body.userId as string,
    organizationId: org.body.id as string,
    bootstrapToken,
    login,
  };
}

test("session reads stay inside the caller's workspace", async (t) => {
  const env = await setup(t);
  const alphaToken = await env.login(env.ownerId, env.alpha);
  const betaToken = await env.login(env.memberId, env.beta);

  const alphaList = await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions`, {
    token: alphaToken,
  });
  assert.equal(alphaList.status, 200);
  assert.deepEqual(alphaList.body.items.map((row: any) => row.sessionId), ["alpha-1"]);
  const betaList = await call(env.origin, `/cloud/api/v1/workspaces/${env.beta}/sessions`, {
    token: betaToken,
  });
  assert.deepEqual(betaList.body.items.map((row: any) => row.sessionId), ["beta-1"]);

  // Every upstream read names exactly the authorized workspace.
  const reads = env.history.requests.filter((entry) => entry.path.startsWith("/v1/") &&
    !entry.path.startsWith("/v1/cli/") && !entry.path.startsWith("/v1/tokens/"));
  assert(reads.length > 0);
  for (const read of reads) assert.equal(read.workspaceParams.length, 1, read.path);

  // A workspace the token is not bound to is indistinguishable from a missing
  // one, for every session route, and never reaches RelayHistory.
  const before = env.history.requests.length;
  for (const path of [
    `/sessions`,
    `/sessions?q=secret`,
    `/sessions/activity?first=2026-11-01&last=2026-11-02`,
    `/sessions/output?first=2026-11-01&last=2026-11-02`,
    `/sessions/search?q=secret`,
    `/sessions/beta-1/events?source=claude`,
    `/sessions/beta-1/turns?source=claude`,
    `/sessions/beta-1/timing?source=claude`,
    `/sessions/beta-1/catalog?source=claude`,
  ]) {
    const response = await call(env.origin, `/cloud/api/v1/workspaces/${env.beta}${path}`, {
      token: alphaToken,
    });
    assert.equal(response.status, 404, path);
    assert.equal(response.body.error, "workspace_not_found", path);
  }
  assert.equal(env.history.requests.length, before);

  // Reading another workspace's session id through one's own workspace finds
  // nothing: RelayHistory scopes the read to the token's workspace.
  const crossEvents = await call(
    env.origin,
    `/cloud/api/v1/workspaces/${env.alpha}/sessions/beta-1/events?source=claude`,
    { token: alphaToken },
  );
  assert.equal(crossEvents.status, 200);
  assert.deepEqual(crossEvents.body.events, []);
  const crossTiming = await call(
    env.origin,
    `/cloud/api/v1/workspaces/${env.alpha}/sessions/beta-1/timing?source=claude`,
    { token: alphaToken },
  );
  assert.deepEqual(crossTiming.body, { timing: null });
  const crossSearch = await call(
    env.origin,
    `/cloud/api/v1/workspaces/${env.alpha}/sessions/search?q=secret`,
    { token: alphaToken },
  );
  assert.equal(crossSearch.status, 200);
  assert(!JSON.stringify(crossSearch.body).includes("Beta secret"));

  // Callers cannot widen the upstream scope.
  for (const path of [
    `/sessions?workspace=${env.beta}`,
    `/sessions/search?q=x&workspace=${env.beta}`,
    `/sessions/alpha-1/events?source=codex&workspace=${env.beta}`,
    `/sessions/activity?first=2026-11-01&last=2026-11-02&workspace=${env.beta}`,
  ]) {
    const response = await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}${path}`, {
      token: alphaToken,
    });
    assert.equal(response.status, 400, path);
  }

  // Unauthenticated callers are rejected before any upstream read.
  const anonymous = await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions`);
  assert.equal(anonymous.status, 401);

  // Removing the member revokes access to their workspace's sessions.
  const removed = await call(
    env.origin,
    `/api/v1/organizations/${env.organizationId}/memberships/${env.memberId}`,
    { method: "DELETE", token: env.bootstrapToken },
  );
  assert.equal(removed.status, 204);
  const afterRemoval = await call(env.origin, `/cloud/api/v1/workspaces/${env.beta}/sessions`, {
    token: betaToken,
  });
  assert.equal(afterRemoval.status, 401);
});

test("an unattested or mis-attested History response is never returned", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  env.history.overrides.set("/v1/sessions", () => ({
    headers: { "x-relayhistory-workspace-id": env.beta },
    body: { sessions: [{ sessionId: "beta-1", source: "claude", summary: "Beta secret" }] },
  }));
  const misattested = await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions`, {
    token,
  });
  assert.equal(misattested.status, 502);
  assert(!JSON.stringify(misattested.body).includes("Beta secret"));

  env.history.overrides.set("/v1/events", (_request, url) => {
    void url;
    return {
      headers: { "x-relayhistory-workspace-id": "" },
      body: { events: [{ eventId: "x", ts: "2026-11-02T18:00:00.000Z", content: "Beta secret" }] },
    };
  });
  const unattested = await call(
    env.origin,
    `/cloud/api/v1/workspaces/${env.alpha}/sessions/search?q=secret`,
    { token },
  );
  assert.equal(unattested.status, 502);
  assert(!JSON.stringify(unattested.body).includes("Beta secret"));
});

test("list, search, transcript, timing, and subagent catalog for the dashboard", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  const base = `/cloud/api/v1/workspaces/${env.alpha}`;

  const list = await call(
    env.origin,
    `${base}/sessions?metadata=deferred&q=work&source=codex&project=relay&since=2026-10-01&until=2026-11-02T23:59:59Z&cursor=c1`,
    { token },
  );
  assert.equal(list.status, 200);
  assert.equal(list.body.now, "2026-11-02T20:00:00.000Z");
  assert.deepEqual(list.body.items[0].project, { name: "relay" });
  assert.deepEqual(
    list.body.members.map((member: any) => member.name).sort(),
    ["Member", "Owner"],
  );
  assert(list.body.members.every((member: any) => !("email" in member)));
  const listRead = lastRequest(env.history.requests, (entry) => entry.path === "/v1/sessions");
  assert.deepEqual(listRead?.query, {
    workspace: env.alpha,
    limit: "50",
    q: "work",
    source: "codex",
    project: "relay",
    since: "2026-10-01T00:00:00.000Z",
    until: "2026-11-02T23:59:59.000Z",
    cursor: "c1",
  });

  const hybrid = await call(env.origin, `${base}/sessions?q=work&ranking=hybrid&limit=5`, { token });
  assert.equal(hybrid.status, 200);
  assert.equal(hybrid.body.ranking, "hybrid");
  assert.equal(hybrid.body.items[0].sessionURL, "/dashboard/sessions/alpha-1?source=codex");
  const hybridRead = lastRequest(env.history.requests, (entry) => entry.path === "/v1/sessions");
  assert.equal(hybridRead?.query.search, "hybrid");
  assert.equal(hybridRead?.query.limit, "5");

  const search = await call(env.origin, `${base}/sessions/search?q=work&source=codex&limit=10`, { token });
  assert.equal(search.status, 200);
  assert.equal(search.body.nextCursor, "search-next");
  assert.equal(search.body.matches[0].citationPath, "/dashboard/sessions/alpha-1?source=codex");
  const searchRead = lastRequest(env.history.requests, (entry) => entry.path === "/v1/events");
  assert.deepEqual(searchRead?.query, {
    workspace: env.alpha,
    q: "work",
    limit: "10",
    order: "desc",
    maxContent: "600",
    source: "codex",
  });

  const events = await call(env.origin, `${base}/sessions/alpha-1/events?source=codex&order=desc&limit=200&cursor=p2`, { token });
  assert.equal(events.status, 200);
  assert.deepEqual(events.body.events.map((event: any) => event.eventId), ["e1", "e2"]);
  assert.equal(events.body.nextCursor, "events-next");
  assert.equal(events.body.members.length, 2);
  const eventsRead = lastRequest(env.history.requests, (entry) => entry.path.endsWith("/events") && entry.path.includes("alpha-1"));
  assert.deepEqual(eventsRead?.query, {
    workspace: env.alpha,
    source: "codex",
    order: "desc",
    limit: "200",
    maxContent: "100000",
    includeMessageId: "true",
    cursor: "p2",
  });

  const turns = await call(env.origin, `${base}/sessions/alpha-1/turns?source=codex`, { token });
  assert.equal(turns.status, 200);
  assert.deepEqual(turns.body, {
    turns: [{ id: "t1", role: "user", content: "Alpha work", ts: "2026-11-02T18:00:01.000Z", metadata: {} }],
    nextCursor: null,
  });

  const timing = await call(env.origin, `${base}/sessions/alpha-1/timing?source=codex`, { token });
  assert.equal(timing.status, 200);
  assert.equal(timing.body.timing.workMs, 420_000);
  assert.equal(timing.body.timing.waitingMs, 180_000);
  assert(!("correlationId" in timing.body.timing));

  const catalog = await call(env.origin, `${base}/sessions/alpha-1/catalog?source=codex`, { token });
  assert.equal(catalog.status, 200);
  assert.equal(catalog.body.catalog.gitBranch, "main");
  assert.equal(catalog.body.children[0].childSessionId, "alpha-1-child");
  const missingCatalog = await call(env.origin, `${base}/sessions/missing/catalog?source=codex`, { token });
  assert.deepEqual(missingCatalog.body, {
    catalog: null,
    parents: [],
    children: [],
    commitLinks: [],
    truncated: false,
  });

  // One History read session serves every read above.
  assert.equal(env.history.mints, 1);

  const before = env.history.requests.length;
  for (const path of [
    `/sessions?bogus=1`,
    `/sessions?q=a&q=b`,
    `/sessions?limit=5`,
    `/sessions?ranking=hybrid&q=work&limit=26`,
    `/sessions?since=yesterday`,
    `/sessions/search`,
    `/sessions/search?q=x&limit=51`,
    `/sessions/alpha-1/events`,
    `/sessions/alpha-1/events?source=codex&order=sideways`,
    `/sessions/alpha-1/events?source=codex&limit=1001`,
    `/sessions/alpha-1/timing`,
    `/sessions/alpha-1/catalog?source=a&source=b`,
    `/sessions/activity?first=2026-11-02`,
    `/sessions/activity?first=2026-11-03&last=2026-11-03`,
    `/sessions/activity?first=2025-01-01&last=2026-11-02`,
    `/sessions/activity?first=2026-11-02&last=2026-11-01`,
  ]) {
    const response = await call(env.origin, `${base}${path}`, { token });
    assert.equal(response.status, 400, path);
  }
  assert.equal(env.history.requests.length, before, "invalid requests never reach History");
});

test("team activity reads History in 92-day windows and validates totals", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  env.history.overrides.set("/v1/sessions/activity", (_request, url) => {
    const since = Date.parse(url.searchParams.get("since")!);
    const until = Date.parse(url.searchParams.get("until")!);
    const days = [];
    for (let at = since; at <= until; at += 86_400_000) {
      days.push({ date: new Date(at).toISOString().slice(0, 10), total: 3, bySource: { codex: 2, claude: 1, cursor: 0 } });
    }
    return { body: { since: url.searchParams.get("since"), until: url.searchParams.get("until"), days } };
  });
  const activity = await call(
    env.origin,
    `/cloud/api/v1/workspaces/${env.alpha}/sessions/activity?first=2026-07-01&last=2026-11-02&q=fix`,
    { token },
  );
  assert.equal(activity.status, 200);
  assert.equal(activity.body.days.length, 125);
  assert.deepEqual(activity.body.days[0], {
    date: "2026-07-01",
    conversations: 3,
    bySource: { codex: 2, claude: 1 },
  });
  const reads = env.history.requests.filter((entry) => entry.path === "/v1/sessions/activity");
  assert.deepEqual(reads.map((entry) => [entry.query.since, entry.query.until, entry.query.q]), [
    ["2026-07-01T00:00:00.000Z", "2026-09-30T23:59:59.999Z", "fix"],
    // The window ending today stops at "now".
    ["2026-10-01T00:00:00.000Z", "2026-11-02T20:00:00.000Z", "fix"],
  ]);

  env.history.overrides.set("/v1/sessions/activity", () => ({
    body: { days: [{ date: "2026-11-02", total: 5, bySource: { codex: 2 } }] },
  }));
  const inconsistent = await call(
    env.origin,
    `/cloud/api/v1/workspaces/${env.alpha}/sessions/activity?first=2026-11-02&last=2026-11-02`,
    { token },
  );
  assert.equal(inconsistent.status, 502);
});

test("output metrics degrade on older History and sum across windows", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  const path = `/cloud/api/v1/workspaces/${env.alpha}/sessions/output?first=2026-10-01&last=2026-11-02`;
  const unsupported = await call(env.origin, path, { token });
  assert.equal(unsupported.status, 200);
  assert.deepEqual(unsupported.body, { output: null, unsupported: true });

  env.history.overrides.set("/v1/sessions/output", () => ({
    body: { output: { agentMessages: 4, commits: 2, linesAdded: 30, linesRemoved: 7, commitsWithoutLineCounts: 0 } },
  }));
  const supported = await call(env.origin, path, { token });
  assert.deepEqual(supported.body, {
    output: { agentMessages: 4, commits: 2, linesAdded: 30, linesRemoved: 7, commitsWithoutLineCounts: 0 },
  });
});

test("a revoked History read session is replaced once", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  const path = `/cloud/api/v1/workspaces/${env.alpha}/sessions`;
  assert.equal((await call(env.origin, path, { token })).status, 200);
  assert.equal(env.history.mints, 1);
  env.history.revokeAll();
  assert.equal((await call(env.origin, path, { token })).status, 200);
  assert.equal(env.history.mints, 2);
});

test("History read tokens are cached per user, organization and workspace", async (t) => {
  const env = await setup(t);
  // One person, two sessions bound to two workspaces: each gets its own
  // History read token and sees only its own workspace (DG-001).
  const alphaToken = await env.login(env.ownerId, env.alpha);
  const betaToken = await env.login(env.ownerId, env.beta);
  const list = async (workspaceId: string, token: string) => {
    const response = await call(env.origin, `/cloud/api/v1/workspaces/${workspaceId}/sessions`, { token });
    assert.equal(response.status, 200);
    return response.body.items.map((row: any) => row.sessionId);
  };
  assert.deepEqual(await list(env.alpha, alphaToken), ["alpha-1"]);
  assert.equal(env.history.mints, 1);
  assert.deepEqual(await list(env.beta, betaToken), ["beta-1"]);
  assert.equal(env.history.mints, 2, "the alpha read token is not reused for beta");
  assert.deepEqual(await list(env.alpha, alphaToken), ["alpha-1"]);
  assert.deepEqual(await list(env.beta, betaToken), ["beta-1"]);
  assert.equal(env.history.mints, 2, "each identity's token is cached");
  assert.equal((await call(env.origin, `/cloud/api/v1/workspaces/${env.beta}/sessions`, { token: alphaToken })).status, 404);
});

/* The self-host read API container (relayhistory-pipeline), reached with the
 * caller's own sh_at_ token because RelayAuth is not configured. See
 * docs/sessions-read-api.md. */
const READ_API_UNSUPPORTED_MESSAGE = "The configured session backend does not serve this view";

test("read API: login forwards the caller token and reads carry the token it answers", async (t) => {
  const env = await setup(t, undefined, { relayauth: false });
  const token = await env.login(env.ownerId, env.alpha);
  assert(token.startsWith("sh_at_"));
  const list = await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions`, { token });
  assert.equal(list.status, 200);
  assert.deepEqual(list.body.items.map((row: any) => row.sessionId), ["alpha-1"]);
  assert.deepEqual(env.history.logins, [{ agentRelayToken: token, label: "relay-dashboard" }]);
  const read = lastRequest(env.history.requests, (entry) => entry.path === "/v1/sessions");
  // The container answers the same token as accessToken; reads use it.
  assert.equal(read?.token, token);
  assert.equal(read?.query.workspace, env.alpha);
  assert.equal(env.history.requests.some((entry) => entry.path.startsWith("/v1/tokens/")), false);

  // Catalog 404 (unknown session) stays an empty catalog.
  const missing = await call(
    env.origin,
    `/cloud/api/v1/workspaces/${env.alpha}/sessions/unknown/catalog?source=codex`,
    { token },
  );
  assert.equal(missing.status, 200);
  assert.deepEqual(missing.body, { catalog: null, parents: [], children: [], commitLinks: [], truncated: false });
  assert.equal(env.history.mints, 1);
});

test("read API: an upstream 501 is answered as 501 unsupported_by_backend", async (t) => {
  const env = await setup(t, undefined, { relayauth: false });
  const token = await env.login(env.ownerId, env.alpha);
  const base = `/cloud/api/v1/workspaces/${env.alpha}`;

  // No workspace data comes back, so no attestation is needed for a 501.
  env.history.overrides.set("/v1/sessions/output", () => ({
    status: 501,
    headers: { "x-relayhistory-workspace-id": "" },
    body: { error: "unsupported_by_backend", reason: "output metrics are not served by this backend" },
  }));
  const output = await call(env.origin, `${base}/sessions/output?first=2026-10-01&last=2026-11-02`, { token });
  assert.equal(output.status, 501);
  assert.deepEqual(output.body, {
    error: "unsupported_by_backend",
    reason: "output metrics are not served by this backend",
    message: READ_API_UNSUPPORTED_MESSAGE,
  });
  assert.equal(output.headers.get("cache-control"), "no-store");

  // Any view, not only output: a first page the backend cannot answer exactly.
  env.history.overrides.set("/v1/sessions", () => ({
    status: 501,
    body: { error: "unsupported_by_backend", reason: "hybrid ranking is not served" },
  }));
  const list = await call(env.origin, `${base}/sessions?q=work&ranking=hybrid`, { token });
  assert.equal(list.status, 501);
  assert.equal(list.body.error, "unsupported_by_backend");
  assert.equal(list.body.reason, "hybrid ranking is not served");
  assert(!JSON.stringify(list.body).includes("Alpha work"));

  // Reason falls back to `error`, then to unsupported_by_backend.
  env.history.overrides.set("/v1/events", () => ({ status: 501, body: { error: "search_not_served" } }));
  const search = await call(env.origin, `${base}/sessions/search?q=work`, { token });
  assert.equal(search.status, 501);
  assert.equal(search.body.reason, "search_not_served");
  env.history.overrides.set("/v1/sessions/alpha-1/turns", () => ({ status: 501, body: [] }));
  const turns = await call(env.origin, `${base}/sessions/alpha-1/turns?source=codex`, { token });
  assert.equal(turns.status, 501);
  assert.equal(turns.body.reason, "unsupported_by_backend");

  // A 501 is not an auth failure: the cached read token is kept.
  assert.equal(env.history.mints, 1);
});

test("read API: a dormant container (503) is an upstream failure and keeps the cached token", async (t) => {
  const env = await setup(t, undefined, { relayauth: false });
  const token = await env.login(env.ownerId, env.alpha);
  const path = `/cloud/api/v1/workspaces/${env.alpha}/sessions`;
  assert.equal((await call(env.origin, path, { token })).status, 200);
  assert.equal(env.history.mints, 1);

  env.history.overrides.set("/v1/sessions", () => ({ status: 503, body: { error: "not_configured" } }));
  const before = env.history.requests.length;
  const dormant = await call(env.origin, path, { token });
  assert.equal(dormant.status, 502);
  assert.deepEqual(dormant.body, {
    error: "relayhistory_session_failed",
    stage: "read",
    upstreamStatus: 503,
  });
  // Exactly one upstream read, no retry and no re-login.
  assert.deepEqual(env.history.requests.slice(before).map((entry) => entry.path), ["/v1/sessions"]);

  env.history.overrides.delete("/v1/sessions");
  assert.equal((await call(env.origin, path, { token })).status, 200);
  assert.equal(env.history.mints, 1, "the 503 did not evict the cached token");

  // A 401 still evicts it and logs in again once.
  env.history.revokeAll();
  assert.equal((await call(env.origin, path, { token })).status, 200);
  assert.equal(env.history.mints, 2);
});

test("read API: sync sessions are refused when the backend grants only rth:read", async (t) => {
  const env = await setup(t, undefined, { relayauth: false });
  const token = await env.login(env.ownerId, env.alpha);
  const path = `/api/v1/workspaces/${env.alpha}/relayhistory/session`;

  const sync = await call(env.origin, path, { method: "POST", token, body: { mode: "sync" } });
  assert.equal(sync.status, 501);
  assert.deepEqual(sync.body, {
    error: "unsupported_by_backend",
    reason: "sync_not_served",
    message: "The configured session backend serves reads only; sync sessions are not available",
  });
  assert.equal(sync.headers.get("cache-control"), "no-store");
  assert(!JSON.stringify(sync.body).includes(token));
  assert.equal(env.history.logins.at(-1)?.agentRelayToken, token);

  // Nothing from the refused sync login is reused: a read logs in afresh.
  assert.equal(env.history.mints, 1);
  assert.equal((await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions`, { token })).status, 200);
  assert.equal(env.history.mints, 2);

  const read = await call(env.origin, path, { method: "POST", token, body: { mode: "read" } });
  assert.equal(read.status, 200);
  assert.equal(read.body.accessToken, token);
  assert.deepEqual(read.body.scopes, ["rth:read"]);
  assert.equal(read.body.workspaceId, env.alpha);

  // A backend that serves sync (scopes include rth:sync) still issues it.
  env.history.loginScopes = ["rth:read", "rth:sync"];
  const served = await call(env.origin, path, { method: "POST", token, body: { mode: "sync" } });
  assert.equal(served.status, 200);
  assert.deepEqual(served.body.scopes, ["rth:read", "rth:sync"]);

  // A reply without a scopes field is trusted as before (compatibility).
  env.history.loginScopes = undefined;
  const unscoped = await call(env.origin, path, { method: "POST", token, body: { mode: "read" } });
  assert.equal(unscoped.status, 200);
  assert.equal(unscoped.body.accessToken, token);
  assert.deepEqual(unscoped.body.scopes, []);

  // A reply without rth:read is an invalid session.
  env.history.loginScopes = ["rth:sync"];
  const invalid = await call(env.origin, path, { method: "POST", token, body: { mode: "read" } });
  assert.equal(invalid.status, 502);
  assert.equal(invalid.body.stage, "exchange");
});


test("direct read Worker: list and turns use the caller token without login; issuance stays on History", async (t) => {
  const env = await setup(t, undefined, { directReadApi: true });
  const token = await env.login(env.ownerId, env.alpha);
  const base = `/cloud/api/v1/workspaces/${env.alpha}`;
  const list = await call(env.origin, `${base}/sessions`, { token });
  assert.equal(list.status, 200);
  assert.deepEqual(list.body.items.map((row: any) => row.sessionId), ["alpha-1"]);
  const turns = await call(env.origin, `${base}/sessions/alpha-1/turns?source=codex`, { token });
  assert.equal(turns.status, 200);
  assert.equal(turns.body.turns[0].content, "Alpha work");
  assert.deepEqual(env.readApi!.requests.map((r) => r.path), ["/v1/sessions", "/v1/sessions/alpha-1/turns"]);
  assert(env.readApi!.requests.every((r) => r.token === token && r.workspaceParams.length === 1 && r.query.workspace === env.alpha));
  assert.equal(env.history.requests.length, 0);
  const issued = await call(env.origin, `${base}/relayhistory/session`, { method: "POST", token, body: { mode: "read" } });
  assert.equal(issued.status, 200);
  assert.equal(issued.body.baseUrl, "https://history.selfhosted.test");
  assert(env.history.requests.some((r) => r.path === "/v1/cli/login"));
  assert.equal(env.readApi!.requests.length, 2);
});

test("direct read Worker: search/events stay on History and foreign requests never reach the reader", async (t) => {
  const env = await setup(t, undefined, { directReadApi: true });
  const token = await env.login(env.ownerId, env.alpha);
  const base = `/cloud/api/v1/workspaces/${env.alpha}`;
  assert.equal((await call(env.origin, `${base}/sessions?q=work`, { token })).status, 200);
  assert.equal((await call(env.origin, `${base}/sessions/alpha-1/events?source=codex`, { token })).status, 200);
  assert.equal(env.readApi!.requests.length, 0);
  assert.equal((await call(env.origin, `/cloud/api/v1/workspaces/${env.beta}/sessions`, { token })).status, 404);
  assert.equal((await call(env.origin, `${base}/sessions?workspace=${env.beta}`, { token })).status, 400);
  assert.equal((await call(env.origin, `${base}/sessions`)).status, 401);
  assert.equal(env.readApi!.requests.length, 0);
});

test("direct read Worker: downstream refusal never falls back, logs in or retries", async (t) => {
  const env = await setup(t, undefined, { directReadApi: true });
  const token = await env.login(env.ownerId, env.alpha);
  const base = `/cloud/api/v1/workspaces/${env.alpha}`;
  for (const status of [401, 403, 503]) {
    env.readApi!.overrides.set("/v1/sessions", () => ({ status, body: { error: "buffered_fenced", private: "must-not-echo" } }));
    const before = env.readApi!.requests.length;
    const result = await call(env.origin, `${base}/sessions`, { token });
    assert.equal(result.status, status === 503 ? 503 : 502);
    assert.equal(result.body.upstreamStatus, status);
    assert(!JSON.stringify(result.body).includes("must-not-echo"));
    assert.equal(env.readApi!.requests.length, before + 1);
    assert.equal(env.history.requests.length, 0);
  }
});

test("direct read Worker: missing/wrong workspace attestation discards content without fallback", async (t) => {
  const env = await setup(t, undefined, { directReadApi: true });
  const token = await env.login(env.ownerId, env.alpha);
  for (const attestation of ["", env.beta]) {
    env.readApi!.overrides.set("/v1/sessions", () => ({ headers: { "x-relayhistory-workspace-id": attestation }, body: { sessions: [{ sessionId: "private", summary: "must-not-echo" }] } }));
    const result = await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions`, { token });
    assert.equal(result.status, 502);
    assert(!JSON.stringify(result.body).includes("must-not-echo"));
    assert.equal(env.history.requests.length, 0);
  }
});


test("direct read Worker: disabling the connection refuses native cursors instead of restarting History", async (t) => {
  const env = await setup(t, undefined, { directReadApi: true });
  const token = await env.login(env.ownerId, env.alpha);
  env.disableDirectRead();
  for (const path of ["sessions?cursor=b96s1:opaque", "sessions/alpha-1/turns?source=codex&cursor=b96t1:opaque"]) {
    const result = await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/${path}`, { token });
    assert.equal(result.status, 410);
    assert.deepEqual(result.body, { error: "cursor_expired", message: "This session cursor has expired. Restart from the first page." });
    assert.equal(env.history.requests.length, 0);
    assert.equal(env.readApi!.requests.length, 0);
  }
});

test("direct read Worker: redirects never forward the caller token to History", async (t) => {
  const env = await setup(t, undefined, { directReadApi: true });
  const token = await env.login(env.ownerId, env.alpha);
  env.readApi!.overrides.set("/v1/sessions", () => ({ status: 302, headers: { location: `${env.history.origin}/v1/sessions` } }));
  const result = await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions`, { token });
  assert.equal(result.status, 502);
  assert.equal(env.history.requests.length, 0);
  assert.equal(env.readApi!.requests.length, 1);
});


test("direct read Worker: non-sh_at callers keep their existing History transport", async (t) => {
  const env = await setup(t, undefined, { directReadApi: true });
  const read = await readWorkspaceHistory(env.config, {
    userId: env.ownerId, organizationId: env.organizationId,
    workspaceId: env.alpha, callerToken: "synthetic-admitted-oauth-token",
  }, "/v1/sessions", new URLSearchParams());
  assert.equal(read.status, "ok");
  if (read.status === "ok") assert.equal((read.body.sessions as any[])[0].sessionId, "alpha-1");
  assert.equal(env.readApi!.requests.length, 0);
  assert(env.history.requests.some((r) => r.path === "/v1/cli/login"));
});

test("direct read Worker: non-sh_at callers cannot restart a native cursor in History", async (t) => {
  const env = await setup(t, undefined, { directReadApi: true });
  await assert.rejects(() => readWorkspaceHistory(env.config, {
    userId: env.ownerId, organizationId: env.organizationId,
    workspaceId: env.alpha, callerToken: "synthetic-admitted-oauth-token",
  }, "/v1/sessions", new URLSearchParams({ cursor: "b96s1:opaque" })),
  { name: "ReadCursorExpiredError", message: "This session cursor has expired. Restart from the first page." });
  assert.equal(env.readApi!.requests.length, 0);
  assert.equal(env.history.requests.length, 0);
});


test("direct read Worker: MCP reports an expired cursor with an explicit restart instruction", async (t) => {
  const env = await setup(t, undefined, { directReadApi: true });
  const token = await env.login(env.ownerId, env.alpha);
  const principal = await env.store.authenticateAccessToken(token);
  assert(principal);
  const read = historyReader(env.config, principal, {
    id: env.alpha, organizationId: env.organizationId, name: "alpha",
    relaycastWorkspaceId: "synthetic-relay", relaycastApiKey: "synthetic-key", role: principal.role,
  }, token);
  env.disableDirectRead();
  await assert.rejects(() => read("/v1/sessions?cursor=b96s1:opaque"), {
    name: "SharedSessionsToolError", message: "This session cursor has expired. Restart from the first page.",
  });
  assert.equal(env.history.requests.length, 0);
  assert.equal(env.readApi!.requests.length, 0);
});
