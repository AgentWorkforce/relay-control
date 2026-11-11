import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server } from "node:http";
import test, { type TestContext } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import type { Database, SqlExecutor, SqlResult } from "../src/database.js";
import { migrate } from "../src/migrations.js";
import { NO_FEATURES, type SelectedFeatures } from "../src/features.js";
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

const READ_API_SECRET = "session-read-secret-".repeat(2);

/**
 * A sessions pipeline read API double with the real tenancy rules: the
 * Control handoff mints one read session per {user, org, workspace}, reads
 * are org-wide when `workspace` is omitted, 403 when it does not match the
 * token, and carry `X-Relayhistory-Workspace-Id` attestation.
 */
async function startHistory(t: TestContext) {
  const requests: UpstreamRequest[] = [];
  const tokens = new Map<string, string>();
  const sessions: Session[] = [];
  const overrides = new Map<string, (request: IncomingMessage, url: URL) => {
    status?: number;
    body?: unknown;
    headers?: Record<string, string>;
  } | undefined>();
  /** Handoff request bodies, in order. */
  const handoffs: Array<Record<string, any>> = [];
  const refreshTokens = new Map<string, string>();
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
    if (url.pathname.startsWith("/internal/v1/session-read/sessions")) {
      const refreshing = url.pathname.endsWith("/refresh");
      if (request.method !== "POST" || token !== READ_API_SECRET) {
        send(401, { error: "unauthorized" });
        return;
      }
      handoffs.push(body);
      if (refreshing && refreshTokens.get(String(body.refreshToken)) !== body.workspaceId) {
        send(401, { error: "invalid_refresh_token" });
        return;
      }
      mints += 1;
      const serial = String(mints).padStart(43, "0");
      const accessToken = `rth_at_read_${serial}`;
      const refreshToken = `rth_rt_read_${serial}`;
      tokens.set(accessToken, String(body.workspaceId));
      refreshTokens.set(refreshToken, String(body.workspaceId));
      send(200, {
        sessionId: `read-${mints}`,
        userId: body.userId,
        orgId: body.orgId,
        workspaceId: body.workspaceId,
        audience: body.audience,
        scopes: ["rth:read"],
        accessToken,
        accessTokenExpiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
        refreshToken,
        refreshTokenExpiresAt: new Date(Date.now() + 24 * 3_600_000).toISOString(),
        tokenType: "Bearer",
      });
      return;
    }
    const tokenWorkspace = token ? tokens.get(token) : undefined;
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
    handoffs,
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
  options: { agentTokens?: boolean; relaycastFetch?: typeof fetch; features?: SelectedFeatures } = {},
) {
  const historyOrigin = "https://history.selfhosted.test";
  const history = await startHistory(t);
  const database = new PGliteDatabase();
  await migrate(database);
  const bootstrapToken = "bootstrap-token-that-is-at-least-32-bytes";
  const config: SelfhostConfig = {
    databaseUrl: "unused-in-test",
    publicBaseUrl: "https://control.internal.example",
    relaycastUrl: "http://relaycast.internal",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: history.origin,
    relayhistoryPublicUrl: historyOrigin,
    sessionReadApi: { url: history.origin, publicUrl: historyOrigin, secret: READ_API_SECRET },
    bootstrapToken,
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    port: 3000,
    host: "127.0.0.1",
    internalServiceToken: null,
    oauthRedirectUrl: "https://control.internal.example/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.internal.example/",
    sessionSearchAgentTokens: options.agentTokens,
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const control = createServer(createApp({
    config, store, now: () => now, messagingFetch: options.relaycastFetch, features: options.features,
  }));
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
    return tokens.body.access_token as string;
  };
  history.sessions.push(
    { sessionId: "alpha-1", source: "codex", workspaceId: alpha, summary: "Alpha work" },
    { sessionId: "beta-1", source: "claude", workspaceId: beta, summary: "Beta secret" },
  );
  return {
    origin,
    history,
    config,
    store,
    alpha,
    beta,
    ownerId: org.body.owner.id as string,
    memberId: member.body.userId as string,
    organizationId: org.body.id as string,
    bootstrapToken,
    login,
    database,
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
  const reads = env.history.requests.filter((entry) => entry.path.startsWith("/v1/"));
  assert(reads.length > 0);
  for (const read of reads) assert.equal(read.workspaceParams.length, 1, read.path);

  // A workspace the token is not bound to is indistinguishable from a missing
  // one, for every session route, and never reaches RelayHistory.
  const before = env.history.requests.length;
  for (const path of [
    `/sessions`,
    `/sessions?q=secret`,
    `/sessions/members`,
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

test("members: names for the dashboard without a History read", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  const base = `/cloud/api/v1/workspaces/${env.alpha}`;

  const before = env.history.requests.length;
  const members = await call(env.origin, `${base}/sessions/members`, { token });
  assert.equal(members.status, 200);
  assert.deepEqual(members.body.members.map((member: any) => member.name).sort(), ["Member", "Owner"]);
  assert(members.body.members.every((member: any) => !("email" in member) && typeof member.id === "string"));
  assert.equal(env.history.requests.length, before);

  const extra = await call(env.origin, `${base}/sessions/members?limit=1`, { token });
  assert.equal(extra.status, 400);
  assert.equal(extra.body.error, "invalid_request");

  const anonymous = await call(env.origin, `${base}/sessions/members`);
  assert.equal(anonymous.status, 401);
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

/* The sessions pipeline read API: Control asks its handoff for a read session
 * for one authorized identity. See docs/sessions-read-api.md. */
const READ_API_UNSUPPORTED_MESSAGE = "The configured session backend does not serve this view";

test("read API: the handoff names one identity and reads carry the token it answers", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  assert(token.startsWith("sh_at_"));
  const list = await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions`, { token });
  assert.equal(list.status, 200);
  assert.deepEqual(list.body.items.map((row: any) => row.sessionId), ["alpha-1"]);
  assert.deepEqual(env.history.handoffs, [{
    userId: env.ownerId,
    orgId: env.organizationId,
    workspaceId: env.alpha,
    audience: "https://history.selfhosted.test",
    scopes: ["rth:read"],
    label: "relay-dashboard",
  }]);
  const read = lastRequest(env.history.requests, (entry) => entry.path === "/v1/sessions");
  // Reads use the read API's own token, never the caller's.
  assert(read?.token?.startsWith("rth_at_read_"));
  assert.notEqual(read?.token, token);
  assert.equal(read?.query.workspace, env.alpha);

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
  const env = await setup(t);
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

test("read API: nested reader refusal reasons survive without forwarding upstream messages", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  const base = `/cloud/api/v1/workspaces/${env.alpha}/sessions`;
  for (const [upstream, path] of [
    ["/v1/sessions", `${base}?q=needle`],
    ["/v1/sessions/activity", `${base}/activity?first=2026-11-02&last=2026-11-02&q=needle`],
  ] as const) {
    for (const [body, reason] of [
      [{ error: { code: "unsupported_by_backend", reason: "param_q", message: "private upstream detail" } }, "param_q"],
      [{ reason: "flat_reason", error: { reason: "nested_reason" } }, "flat_reason"],
      [{ error: { reason: "", message: "private upstream detail" } }, "unsupported_by_backend"],
      [{ error: { reason: { unexpected: true }, message: "private upstream detail" } }, "unsupported_by_backend"],
      [{ error: { code: "native_refusal", message: "private upstream detail" } }, "native_refusal"],
      [{ error: { code: {}, reason: [] } }, "unsupported_by_backend"],
    ] as const) {
      env.history.overrides.set(upstream, () => ({ status: 501, body }));
      const response = await call(env.origin, path, { token });
      assert.equal(response.status, 501);
      assert.deepEqual(response.body, {
        error: "unsupported_by_backend", reason, message: READ_API_UNSUPPORTED_MESSAGE,
      });
      assert.equal(response.headers.get("cache-control"), "no-store");
      assert(!JSON.stringify(response.body).includes("private upstream detail"));
    }
  }
  assert.equal(env.history.mints, 1);
});

test("read API: a dormant read API (503) is a retryable upstream failure and keeps the cached token", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  const path = `/cloud/api/v1/workspaces/${env.alpha}/sessions`;
  assert.equal((await call(env.origin, path, { token })).status, 200);
  assert.equal(env.history.mints, 1);

  env.history.overrides.set("/v1/sessions", () => ({ status: 503, body: { error: "not_configured" } }));
  const before = env.history.requests.length;
  const dormant = await call(env.origin, path, { token });
  assert.equal(dormant.status, 503);
  assert.deepEqual(dormant.body, {
    error: "relayhistory_session_failed",
    stage: "read",
    upstreamStatus: 503,
  });
  // Exactly one upstream read, no retry and no new handoff.
  assert.deepEqual(env.history.requests.slice(before).map((entry) => entry.path), ["/v1/sessions"]);

  env.history.overrides.delete("/v1/sessions");
  assert.equal((await call(env.origin, path, { token })).status, 200);
  assert.equal(env.history.mints, 1, "the 503 did not evict the cached token");

  // A 401 still evicts it and asks the handoff again once.
  env.history.revokeAll();
  assert.equal((await call(env.origin, path, { token })).status, 200);
  assert.equal(env.history.mints, 2);
});

test("read API: a downstream refusal is never echoed or retried", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  const base = `/cloud/api/v1/workspaces/${env.alpha}`;
  // Hold a read credential first so each refusal below is one upstream read.
  assert.equal((await call(env.origin, `${base}/sessions`, { token })).status, 200);
  for (const status of [403, 503]) {
    env.history.overrides.set("/v1/sessions", () => ({ status, body: { error: "buffered_fenced", private: "must-not-echo" } }));
    const before = env.history.requests.length;
    const result = await call(env.origin, `${base}/sessions`, { token });
    assert.equal(result.status, status === 503 ? 503 : 502);
    assert.equal(result.body.upstreamStatus, status);
    assert(!JSON.stringify(result.body).includes("must-not-echo"));
    assert.deepEqual(env.history.requests.slice(before).map((entry) => entry.path), ["/v1/sessions"]);
  }
  assert.equal(env.history.mints, 1, "a refusal never asks for another handoff");
});

test("recorded agent list opt-in forwards exactly once with scoped auth and preserves legacy defaults", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  const base = `/cloud/api/v1/workspaces/${env.alpha}/sessions`;
  const seen: URL[] = [];
  env.history.overrides.set("/v1/sessions", (_request, url) => {
    seen.push(url);
    return { body: { sessions: [{
      sessionId: "alpha-1", source: "codex", title: "Recorded title", models: ["recorded-model"],
      ...(url.searchParams.get("includeAgentName") === "recorded" ? { agentName: "example-agent" } : {}),
    }] } };
  });

  const legacy = await call(env.origin, `${base}?metadata=deferred`, { token });
  assert.equal(legacy.status, 200);
  assert.equal(seen[0]!.search, `?limit=50&workspace=${env.alpha}`);
  assert.equal(Object.hasOwn(legacy.body.items[0], "agentName"), false);
  const before = env.history.requests.length;
  const recorded = await call(env.origin, `${base}?metadata=deferred&agent=example-agent&includeAgentName=recorded`, { token });
  assert.equal(recorded.status, 200);
  assert.equal(recorded.body.items[0].agentName, "example-agent");
  assert.equal(recorded.body.items[0].title, "Recorded title");
  assert.deepEqual(recorded.body.items[0].models, ["recorded-model"]);
  assert.equal(recorded.headers.get("cache-control"), "no-store");
  assert.deepEqual(seen[1]!.searchParams.getAll("includeAgentName"), ["recorded"]);
  assert.equal(seen[1]!.searchParams.get("agent"), "example-agent");
  assert.equal(seen[1]!.searchParams.get("workspace"), env.alpha);
  const reads = env.history.requests.slice(before);
  assert.deepEqual(reads.map((entry) => entry.path), ["/v1/sessions"], "no catalog fan-out or extra handoff");
  assert.match(reads[0]!.token ?? "", /^rth_at_read_/);
  assert.notEqual(reads[0]!.token, token);
  assert.equal(env.history.mints, 1);

  const legacyAgain = await call(env.origin, `${base}?metadata=deferred`, { token });
  assert.deepEqual(legacyAgain.body, legacy.body);
  assert.equal(seen[2]!.search, seen[0]!.search);
});

test("recorded agent list opt-in rejects invalid or duplicate values before any upstream request", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  const base = `/api/v1/workspaces/${env.alpha}/sessions`;
  const before = env.history.requests.length;
  for (const suffix of [
    "includeAgentName=", "includeAgentName=Recorded", "includeAgentName=false",
    "includeAgentName=must-not-echo", "includeAgentName=%20recorded%20", "includeAgentName=%0Arecorded",
    "includeAgentName=recorded&includeAgentName=recorded", "includeAgentName=recorded&includeAgentName=false",
  ]) {
    const refused = await call(env.origin, `${base}?${suffix}`, { token });
    assert.equal(refused.status, 400, suffix);
    assert.equal(refused.body.error, "invalid_request");
    assert.equal(refused.body.message, "Invalid session parameter: includeAgentName");
    assert(!JSON.stringify(refused.body).includes("must-not-echo"));
  }
  assert.equal(env.history.requests.length, before);
  assert.equal(env.history.mints, 0);
});

test("recorded agent metadata preserves member and upstream workspace attestation guards", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.memberId, env.alpha);
  const path = `/api/v1/workspaces/${env.alpha}/sessions?includeAgentName=recorded`;
  const before = env.history.requests.length;
  assert.equal((await call(env.origin, path)).status, 401);
  assert.equal((await call(env.origin, `/api/v1/workspaces/${env.beta}/sessions?includeAgentName=recorded`, { token })).status, 404);
  assert.equal((await call(env.origin, `${path}&workspace=${env.beta}`, { token })).status, 400);
  assert.equal(env.history.requests.length, before);
  env.history.overrides.set("/v1/sessions", () => ({
    headers: { "x-relayhistory-workspace-id": env.beta },
    body: { sessions: [{ sessionId: "beta-1", source: "codex", agentName: "private-foreign-name" }] },
  }));
  const refused = await call(env.origin, path, { token });
  assert.equal(refused.status, 502);
  assert(!JSON.stringify(refused.body).includes("private-foreign-name"));
});

test("recorded agent list opt-in requires the native read context and returns safe unsupported metadata", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  // Current loadConfig requires native; simulate an unsupported legacy route context.
  Reflect.deleteProperty(env.config, "sessionReadApi");
  const before = env.history.requests.length;
  const result = await call(env.origin, `/api/v1/workspaces/${env.alpha}/sessions?includeAgentName=recorded`, { token });
  assert.equal(result.status, 501);
  assert.equal(result.body.error, "unsupported_by_backend");
  assert.equal(result.body.reason, "param_includeAgentName");
  assert.equal(result.body.message, "The configured session backend does not serve this view");
  assert.equal(result.headers.get("cache-control"), "no-store");
  assert.equal(env.history.requests.length, before);
  assert.equal(env.history.mints, 0);
});

test("agent filter: passes one agent to the read API and reports what it applied", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  const base = `/cloud/api/v1/workspaces/${env.alpha}/sessions`;
  const seen: URL[] = [];
  let reply: { status?: number; body?: unknown; headers?: Record<string, string> } = {
    body: { sessions: [{ sessionId: "alpha-1", source: "codex" }] },
  };
  env.history.overrides.set("/v1/sessions", (_request, url) => {
    seen.push(url);
    return reply;
  });

  const exact = await call(env.origin, `${base}?agent=Example-Agent`, { token });
  assert.equal(exact.status, 200);
  assert.equal(seen[0]!.searchParams.get("agent"), "example-agent");
  assert.equal(seen[0]!.searchParams.has("q"), false);
  assert.deepEqual(
    { agent: exact.body.agent, ignoredAgents: exact.body.ignoredAgents, agentMatch: exact.body.agentMatch },
    { agent: "example-agent", ignoredAgents: [], agentMatch: null },
  );

  // Without parsing enabled, an @token is still ordinary search text.
  const plain = await call(env.origin, `${base}?q=${encodeURIComponent("@builder")}`, { token });
  assert.equal(plain.status, 200);
  assert.equal(plain.body.agent, undefined);
  assert.equal(env.history.requests.at(-1)!.query.q, "@builder");

  const count = seen.length;
  for (const [suffix, status, code] of [
    ["agent=a&agent=b", 400, "invalid_request"],
    ["agent=has%20space", 400, "invalid_request"],
    ["agent=ab*", 400, "agent_prefix_too_short"],
    [`agent=${"a".repeat(201)}`, 400, "invalid_request"],
  ] as const) {
    const refused = await call(env.origin, `${base}?${suffix}`, { token });
    assert.equal(refused.status, status, suffix);
    assert.equal(refused.body.error, code, suffix);
  }
  const combined = await call(env.origin, `${base}?agent=builder&q=deploy`, { token });
  assert.equal(combined.status, 501);
  assert.equal(combined.body.reason, "agent_with_text");
  assert.equal(seen.length, count);

  // An older backend matches `foo*` literally, so its empty page is not a result.
  reply = { body: { sessions: [] } };
  const unconfirmed = await call(env.origin, `${base}?agent=example*`, { token });
  assert.equal(unconfirmed.status, 501);
  assert.equal(unconfirmed.body.reason, "agent_prefix_not_supported");
  reply = { headers: { "x-sessions-read-agent-match": "prefix" }, body: { sessions: [] } };
  const prefix = await call(env.origin, `${base}?agent=example*`, { token });
  assert.equal(prefix.status, 200);
  assert.equal(prefix.body.agentMatch, "prefix");
  assert.equal(seen.at(-1)!.searchParams.get("agent"), "example*");

  reply = { status: 501, body: { error: "agent_filter_not_ready" } };
  const notReady = await call(env.origin, `${base}?agent=builder`, { token });
  assert.equal(notReady.status, 501);
  assert.equal(notReady.body.reason, "agent_filter_not_ready");
  reply = { status: 400, body: { error: "agent_prefix_too_broad", private: "must-not-echo" } };
  const broad = await call(env.origin, `${base}?agent=example*`, { token });
  assert.equal(broad.status, 400);
  assert.equal(broad.body.error, "agent_prefix_too_broad");
  assert(!JSON.stringify(broad.body).includes("must-not-echo"));
  reply = { status: 400, body: { error: { code: "agent_prefix_too_broad", reason: "private explanatory reason", message: "must-not-echo" } } };
  const nativeBroad = await call(env.origin, `${base}?agent=example*`, { token });
  assert.equal(nativeBroad.status, 400);
  assert.equal(nativeBroad.body.error, "agent_prefix_too_broad");
  assert(!JSON.stringify(nativeBroad.body).includes("private explanatory reason"));
  assert(!JSON.stringify(nativeBroad.body).includes("must-not-echo"));
  reply = { status: 400, body: { error: { code: "bad_request", message: "must-not-echo" } } };
  const unrelated = await call(env.origin, `${base}?agent=example*`, { token });
  assert.equal(unrelated.status, 502);
  assert(!JSON.stringify(unrelated.body).includes("must-not-echo"));
});

test("agent filter: with parsing on, @tokens select the agent and the first wins", async (t) => {
  const env = await setup(t, undefined, { agentTokens: true });
  const token = await env.login(env.ownerId, env.alpha);
  const base = `/cloud/api/v1/workspaces/${env.alpha}/sessions`;
  let last: URL | undefined;
  env.history.overrides.set("/v1/sessions", (_request, url) => {
    last = url;
    return { body: { sessions: [] } };
  });
  const listed = await call(env.origin, `${base}?q=${encodeURIComponent("@Builder @other")}`, { token });
  assert.equal(listed.status, 200);
  assert.equal(last!.searchParams.get("agent"), "builder");
  assert.equal(last!.searchParams.has("q"), false);
  assert.deepEqual(listed.body.ignoredAgents, ["other"]);

  const withText = await call(env.origin, `${base}?q=${encodeURIComponent("@builder deploy")}`, { token });
  assert.equal(withText.status, 501);
  assert.equal(withText.body.reason, "agent_with_text");

  const search = await call(env.origin, `${base}/search?q=${encodeURIComponent("@builder")}`, { token });
  assert.equal(search.status, 501);
  assert.equal(search.body.reason, "agent_filter_not_on_search");
});

test("agent names for autocomplete: members only, names only, hidden agents left out", async (t) => {
  const relaycastFetch = (async () => Response.json({ data: [
    { id: "1", name: "zeta", token: "must-not-echo", metadata: {} },
    { id: "2", name: "alpha", metadata: {} },
    { id: "3", name: "alpha", metadata: {} },
    { id: "4", name: "old-name", metadata: { renamed_to: "new-name" } },
  ] })) as typeof fetch;
  const env = await setup(t, undefined, { relaycastFetch });
  const token = await env.login(env.ownerId, env.alpha);
  const path = `/cloud/api/v1/workspaces/${env.alpha}/session-agent-names`;
  const listed = await call(env.origin, path, { token });
  assert.equal(listed.status, 200);
  assert.deepEqual(listed.body, { names: ["alpha", "zeta"] });
  assert.equal((await call(env.origin, path)).status, 401);
  assert.equal((await call(env.origin, `/cloud/api/v1/workspaces/${env.beta}/session-agent-names`, { token })).status, 404);

  // One already used above; the roster call spends a server-side key.
  for (let used = 1; used < 60; used += 1) assert.equal((await call(env.origin, path, { token })).status, 200);
  const limited = await call(env.origin, path, { token });
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error, "rate_limited");
});

test("read API: redirects are refused and never followed", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  env.history.overrides.set("/v1/sessions", () => ({ status: 302, headers: { location: `${env.history.origin}/v1/events` } }));
  const result = await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions`, { token });
  assert.equal(result.status, 502);
  assert.deepEqual(env.history.requests.filter((entry) => entry.path.startsWith("/v1/")).map((entry) => entry.path), ["/v1/sessions"]);
});

test("read API: callers without an sh_at_ token read through the same handoff", async (t) => {
  const env = await setup(t);
  const read = await readWorkspaceHistory(env.config, {
    userId: env.ownerId, organizationId: env.organizationId,
    workspaceId: env.alpha, callerToken: "synthetic-admitted-oauth-token",
  }, "/v1/sessions", new URLSearchParams());
  assert.equal(read.status, "ok");
  if (read.status === "ok") assert.equal((read.body.sessions as any[])[0].sessionId, "alpha-1");
  assert.equal(env.history.handoffs.length, 1);
  assert.equal(env.history.handoffs[0]!.workspaceId, env.alpha);
});

test("read API: MCP reports an expired cursor with an explicit restart instruction", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  const principal = await env.store.authenticateAccessToken(token);
  assert(principal);
  const read = historyReader(env.config, principal, {
    id: env.alpha, organizationId: env.organizationId, name: "alpha",
    relaycastWorkspaceId: "synthetic-relay", relaycastApiKey: "synthetic-key", role: principal.role,
  }, token);
  env.history.overrides.set("/v1/sessions", () => ({ status: 410, body: { error: "cursor_expired" } }));
  await assert.rejects(() => read("/v1/sessions?cursor=b96s1:opaque"), {
    name: "SharedSessionsToolError", message: "This session cursor has expired. Restart from the first page.",
  });
  const dashboard = await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions?cursor=b96s1:opaque`, { token });
  assert.equal(dashboard.status, 410);
  assert.deepEqual(dashboard.body, { error: "cursor_expired", message: "This session cursor has expired. Restart from the first page." });
});

test("recorded summaries preserve provenance and workspace isolation through the read handoff", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  const upstream = "/v1/sessions/alpha-1/summary";
  const path = `/api/v1/workspaces/${env.alpha}/sessions/alpha-1/summary?source=codex&kind=short`;
  const ready = { status: "ready", kind: "short", summary: "Recorded model-written description", model: "recorded-model", builtAt: "2026-11-02T18:00:00Z", state: null };
  env.history.overrides.set(upstream, () => ({ body: { summary: ready } }));
  const response = await call(env.origin, path, { token });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { summary: ready });
  assert.equal(response.headers.get("cache-control"), "no-store");
  const request = env.history.requests.at(-1)!;
  assert.equal(request.path, upstream);
  assert.deepEqual(request.query, { source: "codex", kind: "short", workspace: env.alpha });
  // The read uses the internal issuer's read token, never the caller's own token.
  assert.match(request.token ?? "", /^rth_at_read_/);
  assert.notEqual(request.token, token);
  assert.equal(env.history.mints, 1);
  const count = env.history.requests.length;
  assert.equal((await call(env.origin, path)).status, 401);
  assert.equal((await call(env.origin, `/api/v1/workspaces/${env.beta}/sessions/alpha-1/summary?source=codex&kind=short`, { token })).status, 404);
  assert.equal((await call(env.origin, path + `&workspace=${env.beta}`, { token })).status, 400);
  assert.equal((await call(env.origin, path.replace("kind=short", "kind=long"), { token })).status, 400);
  assert.equal(env.history.requests.length, count);
});

test("recorded summaries fail closed on missing provenance, tenant attestation and read API errors", async (t) => {
  const env = await setup(t);
  const token = await env.login(env.ownerId, env.alpha);
  const upstream = "/v1/sessions/alpha-1/summary";
  const path = `/api/v1/workspaces/${env.alpha}/sessions/alpha-1/summary?source=codex`;
  const ready = { status: "ready", kind: "short", summary: "private-recorded-description", model: "recorded-model", builtAt: "2026-11-02T18:00:00Z", state: null };
  for (const invalid of [{ ...ready, model: "" }, { ...ready, model: null }, { ...ready, builtAt: "invalid" }, { ...ready, summary: " " }, { ...ready, state: { state: "completed", classifiedAt: ready.builtAt } }]) {
    env.history.overrides.set(upstream, () => ({ body: { summary: invalid } }));
    const result = await call(env.origin, path, { token });
    assert.equal(result.status, 502);
    assert(!JSON.stringify(result.body).includes("private-recorded-description"));
  }
  for (const workspace of ["", env.beta]) {
    env.history.overrides.set(upstream, () => ({ headers: { "x-relayhistory-workspace-id": workspace }, body: { summary: ready } }));
    assert.equal((await call(env.origin, path, { token })).status, 502);
  }
  env.history.overrides.set(upstream, () => ({ body: { summary: { status: "empty", kind: "short", state: null } } }));
  assert.deepEqual((await call(env.origin, path, { token })).body, { summary: { status: "empty", kind: "short", state: null } });
  env.history.overrides.set(upstream, () => ({ status: 404, body: { error: "missing" } }));
  assert.deepEqual((await call(env.origin, path, { token })).body, { summary: { status: "empty", kind: "short", state: null } });
  const reads = () => env.history.requests.filter((entry) => entry.path === upstream).length;
  for (const status of [401, 403, 501, 503]) {
    env.history.overrides.set(upstream, () => ({ status, body: { error: { code: "unsupported_by_backend", reason: "summary_unqualified" } } }));
    const before = reads();
    const result = await call(env.origin, path, { token });
    assert.equal(result.status, status === 501 ? 501 : status === 503 ? 503 : 502);
    // A 401 evicts the cached read token and retries once with a fresh handoff.
    assert.equal(reads(), before + (status === 401 ? 2 : 1));
  }
});

// Usage page (docs/usage.md): owner-only, counts only.

const USAGE_ON: SelectedFeatures = { ...NO_FEATURES, usage: true };

function dailyActivity(total: (date: string) => number) {
  return (_request: IncomingMessage, url: URL) => {
    const since = Date.parse(url.searchParams.get("since")!);
    const until = Date.parse(url.searchParams.get("until")!);
    const days = [];
    for (let at = since; at <= until; at += 86_400_000) {
      const date = new Date(at).toISOString().slice(0, 10);
      days.push({ date, total: total(date), bySource: { codex: total(date) } });
    }
    return { body: { days } };
  };
}

/** Counters are written off the request path; poll until `ready` holds. */
async function usageUntil(
  origin: string,
  path: string,
  token: string,
  ready: (body: Record<string, any>) => boolean,
) {
  let last: Awaited<ReturnType<typeof call>> | undefined;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    last = await call(origin, path, { token });
    if (last.status !== 200 || ready(last.body)) return last;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return last!;
}

test("usage: an owner gets daily counts from the session directory and Control counters", async (t) => {
  const env = await setup(t, undefined, { features: USAGE_ON });
  env.history.overrides.set("/v1/sessions/activity", dailyActivity((date) => date === "2026-11-02" ? 4 : 1));
  env.history.overrides.set("/v1/sessions/summaries/activity", dailyActivity((date) => date === "2026-11-01" ? 2 : 0));
  const owner = await env.login(env.ownerId, env.alpha);
  const member = await env.login(env.memberId, env.alpha);
  // Two first-page searches count; a later page of the same search does not.
  assert.equal((await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions/search?q=fix`, { token: member })).status, 200);
  assert.equal((await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions?q=fix`, { token: owner })).status, 200);
  assert.equal((await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions/search?q=fix&cursor=next`, { token: member })).status, 200);
  assert.equal((await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions`, { token: owner })).status, 200);

  const path = `/cloud/api/v1/organizations/${env.organizationId}/usage?days=7`;
  const result = await usageUntil(env.origin, path, owner, (body) =>
    body.usage.totals.searches === 2 && body.usage.totals.activeUsers === 2);
  assert.equal(result.status, 200);
  assert.equal(result.headers.get("cache-control"), "no-store");
  const usage = result.body.usage;
  assert.deepEqual(usage.range, { days: 7, from: "2026-10-27", to: "2026-11-02" });
  assert.equal(usage.days.length, 7);
  // The owner reads both workspaces (alpha and beta): 1 + 1 per day, 4 + 4 today.
  assert.deepEqual(usage.days.at(-1), { date: "2026-11-02", activeUsers: 2, sessionsUploaded: 8, searches: 2, summaries: 0 });
  assert.deepEqual(usage.days[0], { date: "2026-10-27", activeUsers: 0, sessionsUploaded: 2, searches: 0, summaries: 0 });
  assert.deepEqual(usage.totals, { activeUsers: 2, sessionsUploaded: 20, searches: 2, summaries: 4 });
  assert.deepEqual(usage.unavailable, []);
  const reads = env.history.requests.filter((entry) => entry.path === "/v1/sessions/activity");
  assert.deepEqual(new Set(reads.map((entry) => entry.query.workspace)), new Set([env.alpha, env.beta]));
  assert.equal(reads.at(-1)!.query.since, "2026-10-27T00:00:00.000Z");
  assert.equal(reads.at(-1)!.query.until, "2026-11-02T20:00:00.000Z");
});

test("usage: no identities, emails, names or the install secret in the response", async (t) => {
  const env = await setup(t, undefined, { features: USAGE_ON });
  env.history.overrides.set("/v1/sessions/activity", dailyActivity(() => 1));
  const owner = await env.login(env.ownerId, env.alpha);
  const result = await usageUntil(env.origin, `/cloud/api/v1/organizations/${env.organizationId}/usage`, owner,
    (body) => body.usage.totals.activeUsers === 1);
  assert.equal(result.status, 200);
  assert.deepEqual(Object.keys(result.body.usage).sort(), ["days", "range", "totals", "unavailable"]);
  for (const day of result.body.usage.days) {
    assert.deepEqual(Object.keys(day).sort(), ["activeUsers", "date", "searches", "sessionsUploaded", "summaries"]);
  }
  const text = JSON.stringify(result.body);
  const { rows: [state] } = await env.database.query<{ salt: string }>("SELECT salt FROM usage_state");
  const { rows: hashes } = await env.database.query<{ user_hash: string }>("SELECT user_hash FROM usage_daily_users");
  assert.ok(state && hashes.length === 1);
  for (const secret of [
    "owner@example.test", "member@example.test", "Owner", "Member", env.ownerId, env.memberId,
    env.alpha, env.beta, state.salt, hashes[0]!.user_hash,
  ]) {
    assert.equal(text.includes(secret), false, `response leaks ${secret}`);
  }
  // Stored rows are keyed by an HMAC under the install secret, never the user id.
  assert.notEqual(hashes[0]!.user_hash, env.ownerId);
});

test("usage: only an owner; admin, member and the bootstrap operator get 403", async (t) => {
  const env = await setup(t, undefined, { features: USAGE_ON });
  const admin = await call(env.origin, `/api/v1/organizations/${env.organizationId}/memberships`, {
    method: "POST",
    token: env.bootstrapToken,
    body: { email: "admin@example.test", name: "Admin", role: "admin" },
  });
  assert.equal(admin.status, 200);
  const path = `/cloud/api/v1/organizations/${env.organizationId}/usage`;
  for (const token of [
    await env.login(admin.body.userId, env.alpha),
    await env.login(env.memberId, env.alpha),
    env.bootstrapToken,
  ]) {
    const refused = await call(env.origin, path, { token });
    assert.equal(refused.status, 403);
    assert.equal(refused.body.error, "forbidden");
    assert.equal(refused.body.usage, undefined);
  }
  assert.equal((await call(env.origin, path)).status, 401);
  const owner = await env.login(env.ownerId, env.alpha);
  assert.equal((await call(env.origin, `/cloud/api/v1/organizations/00000000-0000-4000-8000-000000000000/usage`, { token: owner })).status, 404);
});

test("usage: off by default, with nothing recorded", async (t) => {
  const env = await setup(t);
  const owner = await env.login(env.ownerId, env.alpha);
  assert.equal((await call(env.origin, `/cloud/api/v1/workspaces/${env.alpha}/sessions/search?q=fix`, { token: owner })).status, 200);
  const refused = await call(env.origin, `/cloud/api/v1/organizations/${env.organizationId}/usage`, { token: owner });
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error, "feature_not_enabled");
  const capabilities = await call(env.origin, "/cloud/api/v1/capabilities", { token: owner });
  assert.equal(capabilities.body.capabilities.usage, false);
  await new Promise((resolve) => setTimeout(resolve, 50));
  for (const table of ["usage_daily_users", "usage_daily_counters", "usage_state"]) {
    const { rows } = await env.database.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${table}`);
    assert.equal(rows[0]!.n, 0, table);
  }
});

test("usage: empty state is zeros, and an unreadable source is null, never zero", async (t) => {
  const env = await setup(t, undefined, { features: USAGE_ON });
  env.history.overrides.set("/v1/sessions/activity", dailyActivity(() => 0));
  const owner = await env.login(env.ownerId, env.alpha);
  const path = `/cloud/api/v1/organizations/${env.organizationId}/usage?days=90`;
  const empty = await usageUntil(env.origin, path, owner, (body) => body.usage.totals.activeUsers === 1);
  assert.equal(empty.status, 200);
  assert.equal(empty.body.usage.days.length, 90);
  assert.deepEqual(empty.body.usage.range, { days: 90, from: "2026-08-05", to: "2026-11-02" });
  // The fake read API does not serve summaries (404): unavailable, not zero.
  assert.deepEqual(empty.body.usage.totals, { activeUsers: 1, sessionsUploaded: 0, searches: 0, summaries: null });
  assert.deepEqual(empty.body.usage.unavailable, ["summaries"]);
  assert.equal(empty.body.usage.days[0].summaries, null);

  // A page missing a day (or with days out of order) is not a complete answer.
  env.history.overrides.set("/v1/sessions/activity", (request, url) => {
    const full = dailyActivity(() => 1)(request, url);
    return { body: { days: full.body.days.slice(1) } };
  });
  const partial = await call(env.origin, path, { token: owner });
  assert.equal(partial.status, 200);
  assert.equal(partial.body.usage.totals.sessionsUploaded, null);
  assert.equal(partial.body.usage.days[5].sessionsUploaded, null);

  env.history.overrides.set("/v1/sessions/activity", () => ({ status: 503, body: { error: { code: "not_configured" } } }));
  const degraded = await call(env.origin, path, { token: owner });
  assert.equal(degraded.status, 200);
  assert.equal(degraded.body.usage.totals.sessionsUploaded, null);
  assert.deepEqual(degraded.body.usage.unavailable, ["sessionsUploaded", "summaries"]);
});

test("usage: the range is 7, 30 or 90 days ending today", async (t) => {
  const env = await setup(t, undefined, { features: USAGE_ON });
  env.history.overrides.set("/v1/sessions/activity", dailyActivity(() => 0));
  const owner = await env.login(env.ownerId, env.alpha);
  const base = `/cloud/api/v1/organizations/${env.organizationId}/usage`;
  const defaulted = await call(env.origin, base, { token: owner });
  assert.equal(defaulted.status, 200);
  assert.deepEqual(defaulted.body.usage.range, { days: 30, from: "2026-10-04", to: "2026-11-02" });
  for (const query of ["days=0", "days=14", "days=365", "days=-7", "days=abc", "days=7&days=30", "days=7&from=2026-01-01", "from=2026-01-01"]) {
    const refused = await call(env.origin, `${base}?${query}`, { token: owner });
    assert.equal(refused.status, 400, query);
    assert.equal(refused.body.error, "invalid_request", query);
  }
});

test("usage: any route that authenticates a token counts its user (not only the API helper)", async (t) => {
  const env = await setup(t, undefined, { features: USAGE_ON });
  const owner = await env.login(env.ownerId, env.alpha);
  const member = await env.login(env.memberId, env.alpha);
  // Desktop, MCP and dashboard account routes authenticate through the store directly.
  assert.ok(await env.store.authenticateAccessToken(member));
  const result = await usageUntil(env.origin, `/cloud/api/v1/organizations/${env.organizationId}/usage?days=7`, owner,
    (body) => body.usage.totals.activeUsers === 2);
  assert.equal(result.body.usage.totals.activeUsers, 2);
  const { rows } = await env.database.query<{ n: number }>("SELECT count(*)::int AS n FROM usage_daily_users");
  assert.equal(rows[0]!.n, 2);
});
