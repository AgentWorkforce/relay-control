import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import test, { type TestContext } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { createAdminModule } from "../src/admin/routes.js";
import { createApp } from "../src/app.js";
import { hashSecret } from "../src/crypto.js";
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

const historyOrigin = "https://history.selfhosted.test";

/**
 * Without RelayAuth: a RelayHistory double that exchanges the caller's own
 * sh_at_ token and records every request it receives.
 */
async function startHistory(t: TestContext) {
  const requests: string[] = [];
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as Record<string, any>;
    requests.push(new URL(request.url!, "http://history").pathname);
    response.setHeader("content-type", "application/json");
    if (request.url === "/v1/cli/login" && String(body.agentRelayToken).startsWith("sh_at_")) {
      response.end(JSON.stringify({
        accessToken: body.agentRelayToken,
        accessTokenExpiresAt: "2099-01-01T00:00:00.000Z",
        refreshToken: body.agentRelayToken,
        refreshTokenExpiresAt: "2099-01-01T00:00:00.000Z",
        tokenType: "Bearer",
        scopes: ["rth:read"],
      }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not_found" }));
  });
  const origin = await listen(server);
  t.after(() => close(server));
  return { origin, requests };
}

async function setup(t: TestContext, options: { tenancy?: "single" | "multi" } = {}) {
  const history = await startHistory(t);
  const database = new PGliteDatabase();
  await migrate(database);
  const bootstrapToken = "bootstrap-token-that-is-at-least-32-bytes";
  const serviceToken = "internal-service-token-that-is-at-least-32-bytes";
  const config: SelfhostConfig = {
    databaseSchema: "public",
    databaseUrl: "unused-in-test",
    publicBaseUrl: "https://control.internal.example",
    relaycastUrl: "http://relaycast.internal",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayauthUrl: null,
    relayhistoryUrl: history.origin,
    relayhistoryPublicUrl: historyOrigin,
    relayauthApiKey: null,
    bootstrapToken,
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    port: 3000,
    host: "127.0.0.1",
    internalServiceToken: serviceToken,
    oauthRedirectUrl: "https://control.internal.example/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.internal.example/",
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0, { tenancy: options.tenancy ?? "single" });
  const admin = createAdminModule({ config, database, keyring: config.encryptionKeyring });
  const control = createServer(createApp({ config, store, admin }));
  const origin = await listen(control);
  // Same database, RelayHistory left unconfigured.
  const unconfigured = createServer(createApp({
    config: { ...config, relayhistoryUrl: "", relayhistoryPublicUrl: "" },
    store,
  }));
  const unconfiguredOrigin = await listen(unconfigured);
  t.after(async () => {
    await close(control);
    await close(unconfigured);
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
      body: { client_name: "relayhistory-origin-test" },
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
  return {
    origin,
    unconfiguredOrigin,
    history,
    database,
    bootstrapToken,
    serviceToken,
    organizationId: org.body.id as string,
    ownerId: org.body.owner.id as string,
    memberId: member.body.userId as string,
    login,
    alpha,
    beta,
    memberToken: await login(member.body.userId as string, alpha),
  };
}

const originPath = (workspace: string) => `/api/v1/workspaces/${workspace}/relayhistory/origin`;

test("an authorized member reads the workspace History origin and audience", async (t) => {
  const { origin, history, alpha, memberToken } = await setup(t);
  for (const prefix of ["", "/cloud"]) {
    const answer = await call(origin, `${prefix}${originPath(alpha)}`, { token: memberToken });
    assert.equal(answer.status, 200, prefix);
    assert.deepEqual(answer.body, {
      workspace: alpha,
      origin: historyOrigin,
      audience: historyOrigin,
    });
    assert.equal(answer.headers.get("cache-control"), "no-store");
  }
  assert.deepEqual(history.requests, [], "nothing is issued and History is not called");
  assert.equal(
    (await call(origin, originPath(alpha), { method: "POST", token: memberToken })).status,
    404,
    "the route is GET only",
  );
});

test("the origin lookup refuses missing, invalid and foreign-workspace tokens", async (t) => {
  const { origin, history, alpha, beta, memberToken } = await setup(t);
  const anonymous = await call(origin, originPath(alpha));
  assert.equal(anonymous.status, 401);
  assert.equal(anonymous.body.error, "unauthorized");
  const invalid = await call(origin, originPath(alpha), { token: "sh_at_not-a-token" });
  assert.equal(invalid.status, 401);
  assert.equal(invalid.body.error, "unauthorized");

  // The member's organization reaches beta, but this token is bound to alpha.
  const foreign = await call(origin, originPath(beta), { token: memberToken });
  assert.equal(foreign.status, 403);
  assert.equal(foreign.body.error, "forbidden");
  assert.equal(
    (await call(origin, `/cloud${originPath(beta)}`, { token: memberToken })).status,
    403,
  );

  const unknown = await call(origin, originPath("00000000-0000-4000-8000-000000000000"), {
    token: memberToken,
  });
  assert.equal(unknown.status, 404);
  assert.equal(unknown.body.error, "workspace_not_found");
  assert.deepEqual(history.requests, []);
});

test("the origin lookup answers 404 relayhistory_not_configured without RelayHistory", async (t) => {
  const { unconfiguredOrigin, alpha, memberToken } = await setup(t);
  const answer = await call(unconfiguredOrigin, originPath(alpha), { token: memberToken });
  assert.equal(answer.status, 404);
  assert.equal(answer.body.error, "relayhistory_not_configured");
  assert.equal(
    (await call(unconfiguredOrigin, originPath(alpha))).status,
    401,
    "authentication is checked before configuration",
  );
});

test("origin lookups do not consume the session issue/renew path", async (t) => {
  const { origin, history, alpha, memberToken } = await setup(t);
  const issue = () => call(origin, `/api/v1/workspaces/${alpha}/relayhistory/session`, {
    method: "POST",
    token: memberToken,
    body: { mode: "read" },
  });
  const first = await issue();
  assert.equal(first.status, 200);
  assert.equal(first.body.baseUrl, historyOrigin);
  for (let index = 0; index < 50; index += 1) {
    const lookup = await call(origin, originPath(alpha), { token: memberToken });
    assert.equal(lookup.status, 200);
  }
  // Right after the lookups, issue and renew both still succeed, and the only
  // upstream traffic is their own exchanges.
  const second = await issue();
  assert.equal(second.status, 200);
  assert.equal(second.body.baseUrl, historyOrigin);
  const third = await issue();
  assert.equal(third.status, 200);
  assert.deepEqual(history.requests, ["/v1/cli/login", "/v1/cli/login", "/v1/cli/login"]);
});

const VERIFIER = "desktop-verifier-0123456789abcdefghijklmnopqrstuvwxyz0123456789";
const CHALLENGE = createHash("sha256").update(VERIFIER).digest("base64url");

/** Signs a dashboard browser in through /login, approved by the bootstrap bearer. */
async function browserSession(
  origin: string,
  bootstrapToken: string,
  userId: string,
  workspaceId: string,
): Promise<string> {
  const login = await fetch(`${origin}/login`);
  const code = (await login.text()).match(/<code>([A-Z0-9]{4}-[A-Z0-9]{4})<\/code>/)?.[1];
  assert(code);
  const deviceCookie = login.headers.get("set-cookie")!.split(";")[0]!;
  const approved = await call(origin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: bootstrapToken,
    body: { action: "approve", user_code: code, user_id: userId, workspace_id: workspaceId },
  });
  assert.equal(approved.status, 200);
  const poll = await fetch(`${origin}/login/poll`, { method: "POST", headers: { cookie: deviceCookie } });
  assert.equal(poll.status, 200);
  const session = poll.headers.get("set-cookie")?.match(/agent_relay_session=[^;]+/)?.[0];
  assert(session);
  return session;
}

/** The Desktop browser handoff bearer (/cli/login), not yet exchanged. */
async function desktopHandoff(origin: string, session: string, workspaceId: string): Promise<string> {
  const params = new URLSearchParams({
    redirect_uri: "http://127.0.0.1:5123/callback/STATE1",
    state: "STATE1",
    client: "desktop",
    workspace_selection: "desktop",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    workspace: workspaceId,
  });
  const handoff = await fetch(`${origin}/cloud/api/v1/cli/login?${params}`, {
    redirect: "manual",
    headers: { cookie: session },
  });
  assert.equal(handoff.status, 307);
  const token = new URL(handoff.headers.get("location")!).searchParams.get("access_token");
  assert.match(token ?? "", /^sh_at_/);
  return token!;
}

test("the origin lookup answers 404, not 403, for the caller's workspaces in another organization", async (t) => {
  const { origin, history, bootstrapToken, alpha, beta, memberId, memberToken } =
    await setup(t, { tenancy: "multi" });
  // The same person owns a second organization with its own workspace.
  const other = await call(origin, "/api/v1/organizations", {
    method: "POST",
    token: bootstrapToken,
    body: { name: "Other tenant", ownerEmail: "member@example.test", ownerName: "Member" },
  });
  assert.equal(other.status, 201);
  assert.equal(other.body.owner.id, memberId, "one person, two organizations");
  const gamma = await call(origin, `/api/v1/organizations/${other.body.id}/workspaces`, {
    method: "POST",
    token: bootstrapToken,
    body: { name: "gamma", relaycastApiKey: "rk_gamma" },
  });
  assert.equal(gamma.status, 201);

  // Token bound to alpha (organization one): gamma is another tenant -> 404.
  for (const prefix of ["", "/cloud"]) {
    const crossOrg = await call(origin, `${prefix}${originPath(gamma.body.id)}`, { token: memberToken });
    assert.equal(crossOrg.status, 404, prefix);
    assert.equal(crossOrg.body.error, "workspace_not_found");
  }
  // Same organization, other workspace -> 403; own workspace -> 200.
  const sameOrg = await call(origin, originPath(beta), { token: memberToken });
  assert.equal(sameOrg.status, 403);
  assert.equal(sameOrg.body.error, "forbidden");
  assert.equal((await call(origin, originPath(alpha), { token: memberToken })).status, 200);
  assert.deepEqual(history.requests, []);
});

test("the origin lookup refuses service, bootstrap and workspace API tokens with 401", async (t) => {
  const { origin, history, bootstrapToken, serviceToken, ownerId, login, alpha } = await setup(t);
  const ownerToken = await login(ownerId, alpha);
  const minted = await call(origin, `/api/v1/workspaces/${alpha}/deployment-api-tokens`, {
    method: "POST",
    token: ownerToken,
    body: { label: "runtime", purpose: "agent-runtime", expiryDays: 30 },
  });
  assert.equal(minted.status, 201);
  assert.match(minted.body.accessToken, /^sh_wk_/);
  for (const [caller, token] of [
    ["internal service token", serviceToken],
    ["bootstrap token", bootstrapToken],
    ["workspace API token", minted.body.accessToken as string],
  ] as const) {
    const answer = await call(origin, originPath(alpha), { token });
    assert.equal(answer.status, 401, caller);
    assert.equal(answer.body.error, "unauthorized", caller);
  }
  assert.equal((await call(origin, originPath(alpha), { token: ownerToken })).status, 200);
  assert.deepEqual(history.requests, []);
});

test("the origin lookup refuses revoked and expired user tokens with 401", async (t) => {
  const { origin, database, memberId, login, alpha } = await setup(t);
  const revoked = await login(memberId, alpha);
  assert.equal((await call(origin, originPath(alpha), { token: revoked })).status, 200);
  assert.equal((await call(origin, "/api/v1/auth/token/revoke", { method: "POST", token: revoked })).status, 200);
  const afterRevoke = await call(origin, originPath(alpha), { token: revoked });
  assert.equal(afterRevoke.status, 401);
  assert.equal(afterRevoke.body.error, "unauthorized");

  const expired = await login(memberId, alpha);
  assert.equal((await call(origin, originPath(alpha), { token: expired })).status, 200);
  await database.query(
    "UPDATE selfhost_token_sessions SET access_token_expires_at = now() - interval '1 second' WHERE access_token_hash = $1",
    [hashSecret(expired)],
  );
  const afterExpiry = await call(origin, originPath(alpha), { token: expired });
  assert.equal(afterExpiry.status, 401);
  assert.equal(afterExpiry.body.error, "unauthorized");
});

test("the origin lookup refuses an unexchanged Desktop handoff and serves exchanged, device and browser sessions", async (t) => {
  const { origin, history, bootstrapToken, memberId, memberToken, alpha, beta } = await setup(t);
  const session = await browserSession(origin, bootstrapToken, memberId, alpha);
  const handoff = await desktopHandoff(origin, session, alpha);

  const pending = await call(origin, originPath(alpha), { token: handoff });
  assert.equal(pending.status, 403);
  assert.equal(pending.body.error, "handoff_not_exchanged");
  assert.equal(pending.body.message, "Exchange the sign-in handoff (POST /api/v1/auth/desktop/session) first");
  // The handoff refusal comes before the workspace binding.
  const pendingForeign = await call(origin, originPath(beta), { token: handoff });
  assert.equal(pendingForeign.status, 403);
  assert.equal(pendingForeign.body.error, "handoff_not_exchanged");

  const exchanged = await call(origin, "/cloud/api/v1/auth/desktop/session", {
    method: "POST",
    token: handoff,
    body: { codeVerifier: VERIFIER },
  });
  assert.equal(exchanged.status, 200);
  for (const [caller, token] of [
    ["exchanged handoff", handoff],
    ["handoff exchange session", exchanged.body.accessToken as string],
    ["device session", memberToken],
  ] as const) {
    const answer = await call(origin, originPath(alpha), { token });
    assert.equal(answer.status, 200, caller);
    assert.deepEqual(answer.body, { workspace: alpha, origin: historyOrigin, audience: historyOrigin }, caller);
  }
  // Browser account session (cookie under /cloud).
  const browser = await fetch(`${origin}/cloud${originPath(alpha)}`, { headers: { cookie: session } });
  assert.equal(browser.status, 200);
  assert.deepEqual(await browser.json(), { workspace: alpha, origin: historyOrigin, audience: historyOrigin });
  assert.deepEqual(history.requests, []);
});
