import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import { createAdminModule } from "../src/admin/routes.js";
import {
  DEFAULT_PROVIDERS,
  ProviderTokenError,
  type OAuthProvider,
  type ProviderDefinition,
} from "../src/admin/providers.js";
import { maskValue, envKeyReachesRuntime } from "../src/admin/env-policy.js";
import type { SelfhostConfig } from "../src/config.js";
import { loadConfig, loadOperatorOAuthApps } from "../src/config.js";
import { decryptSecret } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 9) } };

type MockOAuth = {
  origin: string;
  server: Server;
  tokenRequests: Array<Record<string, string>>;
  nextRefreshError: string | null;
  issued: number;
};

/** Minimal RFC 6749 + PKCE authorization server. */
async function startMockOAuth(): Promise<MockOAuth> {
  const codes = new Map<string, { challenge: string | null; redirectUri: string }>();
  const mock: MockOAuth = {
    origin: "",
    server: createServer(),
    tokenRequests: [],
    nextRefreshError: null,
    issued: 0,
  };
  mock.server.on("request", async (req, res) => {
    const url = new URL(req.url!, mock.origin);
    if (url.pathname === "/authorize") {
      if (url.searchParams.get("client_id") !== "mock-client") {
        res.writeHead(400).end("bad client");
        return;
      }
      const code = `code-${codes.size + 1}`;
      codes.set(code, {
        challenge: url.searchParams.get("code_challenge"),
        redirectUri: url.searchParams.get("redirect_uri")!,
      });
      const back = new URL(url.searchParams.get("redirect_uri")!);
      back.searchParams.set("code", code);
      back.searchParams.set("state", url.searchParams.get("state")!);
      res.writeHead(302, { location: back.toString() }).end();
      return;
    }
    if (url.pathname === "/token" && req.method === "POST") {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(Buffer.from(chunk));
      const params = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()));
      mock.tokenRequests.push(params);
      res.setHeader("content-type", "application/json");
      if (params.client_id !== "mock-client" || params.client_secret !== "mock-secret-value-123") {
        res.writeHead(401).end(JSON.stringify({ error: "invalid_client" }));
        return;
      }
      if (params.grant_type === "authorization_code") {
        const issued = codes.get(params.code!);
        codes.delete(params.code!);
        const verifierOk = issued?.challenge
          ? createHash("sha256").update(params.code_verifier ?? "").digest("base64url") === issued.challenge
          : true;
        if (!issued || !verifierOk || issued.redirectUri !== params.redirect_uri) {
          res.writeHead(400).end(JSON.stringify({ error: "invalid_grant" }));
          return;
        }
      } else if (params.grant_type === "refresh_token") {
        if (mock.nextRefreshError) {
          const error = mock.nextRefreshError;
          mock.nextRefreshError = null;
          res.writeHead(400).end(JSON.stringify({ error }));
          return;
        }
        if (params.refresh_token !== `rt-${mock.issued}`) {
          res.writeHead(400).end(JSON.stringify({ error: "invalid_grant" }));
          return;
        }
      } else {
        res.writeHead(400).end(JSON.stringify({ error: "unsupported_grant_type" }));
        return;
      }
      mock.issued += 1;
      res.end(JSON.stringify({
        access_token: `at-${mock.issued}-secret-access`,
        refresh_token: `rt-${mock.issued}`,
        token_type: "bearer",
        expires_in: 3600,
        scope: "read write",
      }));
      return;
    }
    res.writeHead(404).end();
  });
  mock.origin = await listen(mock.server);
  return mock;
}

function mockProvider(origin: string): OAuthProvider {
  return {
    id: "mockhub",
    displayName: "MockHub",
    description: "Test provider",
    configKey: "mockhub-relay",
    vfsRoot: "/mockhub",
    categories: ["test"],
    docs: "https://docs.mockhub.test",
    envName: "MOCKHUB",
    authMode: "oauth2",
    authorizeUrl: `${origin}/authorize`,
    tokenUrl: `${origin}/token`,
    defaultScopes: ["read", "write"],
    scopeSeparator: " ",
    clientAuth: "body",
    tokenBody: "form",
    pkce: true,
    appSetupUrl: "https://mockhub.test/apps",
  };
}

async function deviceToken(
  origin: string,
  userId: string,
  workspaceId: string,
): Promise<string> {
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
}

async function setup(t: test.TestContext, extra: Partial<SelfhostConfig> = {}) {
  const mock = await startMockOAuth();
  const database = new PGliteDatabase();
  await migrate(database);
  let controlOrigin = "";
  const providers: ProviderDefinition[] = [...DEFAULT_PROVIDERS, mockProvider(mock.origin)];
  const control = createServer();
  controlOrigin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: controlOrigin,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://relaycast.selfhosted.company",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.company",
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: "https://history.selfhosted.company", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: SERVICE,
    oauthRedirectUrl: `${controlOrigin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${controlOrigin}/dashboard/`,
    port: 0,
    host: "127.0.0.1",
    ...extra,
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  const admin = createAdminModule({ config, database, keyring: KEYRING, providers });
  control.on("request", createApp({ config, store, admin }));
  t.after(async () => {
    await close(control);
    await close(mock.server);
    await database.close();
  });

  const org = await request(controlOrigin, "/api/v1/organizations", {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const workspaces = [];
  for (const name of ["Primary", "Other"]) {
    const workspace = await request(controlOrigin, `/api/v1/organizations/${org.body.id}/workspaces`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, relaycastApiKey: `rk_${name}` },
    });
    assert.equal(workspace.status, 201);
    workspaces.push(workspace.body.id as string);
  }
  const member = await request(controlOrigin, `/api/v1/organizations/${org.body.id}/memberships`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { email: "member@acme.test", name: "Member", role: "member" },
  });
  assert.equal(member.status, 200);
  const workspaceId = workspaces[0]!;
  return {
    database,
    mock,
    origin: controlOrigin,
    organizationId: org.body.id as string,
    workspaceId,
    otherWorkspaceId: workspaces[1]!,
    ownerId: org.body.owner.id as string,
    owner: await deviceToken(controlOrigin, org.body.owner.id, workspaceId),
    member: await deviceToken(controlOrigin, member.body.userId, workspaceId),
  };
}

const ANTHROPIC = "sk-ant-api03-very-secret-plaintext-value";

test("env vars: admin-only writes, write-only values, encryption at rest, runtime read", async (t) => {
  const ctx = await setup(t);
  const base = `/api/v1/workspaces/${ctx.workspaceId}/secrets`;

  const memberList = await request(ctx.origin, base, { token: ctx.member });
  assert.equal(memberList.status, 200);
  assert.deepEqual(memberList.body, { ok: true, data: { items: [] } });

  const memberWrite = await request(ctx.origin, base, {
    method: "POST",
    token: ctx.member,
    body: { name: "ANTHROPIC_API_KEY", value: ANTHROPIC },
  });
  assert.equal(memberWrite.status, 403, "members cannot write env vars");

  const created = await request(ctx.origin, base, {
    method: "POST",
    token: ctx.owner,
    body: { name: "ANTHROPIC_API_KEY", envVar: "ANTHROPIC_API_KEY", value: ANTHROPIC, kind: "environment" },
  });
  assert.equal(created.status, 201);
  assert.equal(created.body.name, "ANTHROPIC_API_KEY");
  assert.equal(created.body.kind, "environment");
  assert.equal(created.body.maskedValue, maskValue(ANTHROPIC));
  assert.match(created.body.maskedValue, /^sk\*+ue$/);
  assert.equal(created.body.deliveredToFlowRuns, true);
  assert.equal(created.body.createdBy, ctx.ownerId);
  assert.equal(created.body.setBy, ctx.ownerId);
  assert(!created.raw.includes(ANTHROPIC), "create response never echoes the value");
  assert(!("value" in created.body));

  const replaced = await request(ctx.origin, base, {
    method: "POST",
    token: ctx.owner,
    body: { name: "ANTHROPIC_API_KEY", value: `${ANTHROPIC}-rotated` },
  });
  assert.equal(replaced.status, 200, "replacing an existing name returns 200");
  assert.equal(replaced.body.createdAt, created.body.createdAt);

  for (const [name, value] of [
    ["SHORT", "abc"],
    ["RELAY_INTERNAL_THING", "launcher owned"],
  ]) {
    const response = await request(ctx.origin, base, { method: "POST", token: ctx.owner, body: { name, value } });
    assert.equal(response.status, 201, name);
  }

  for (const [name, value, why] of [
    ["PATH", "/evil", "reserved"],
    ["LD_PRELOAD", "x", "reserved"],
    ["DYLD_FOO", "x", "reserved"],
    ["E2B_API_KEY", "x", "sandbox credential"],
    ["1BAD", "x", "pattern"],
    ["has-dash", "x", "pattern"],
    ["EMPTY", "", "empty value"],
    ["NUL", "a\u0000b", "nul"],
    ["BIG", "x".repeat(32 * 1024 + 1), "size"],
  ] as const) {
    const response = await request(ctx.origin, base, { method: "POST", token: ctx.owner, body: { name, value } });
    assert.equal(response.status, 400, `${name} rejected (${why})`);
    assert.equal(response.body.error, "invalid_workspace_secret");
  }
  const wrongKind = await request(ctx.origin, base, {
    method: "POST",
    token: ctx.owner,
    body: { name: "X", value: "y", kind: "provider" },
  });
  assert.equal(wrongKind.status, 400);

  // Cookie-authenticated writes must be JSON (blocks cross-site form posts).
  const formPost = await request(ctx.origin, `/cloud${base}`, {
    method: "POST",
    cookie: `agent_relay_session=${ctx.owner}`,
    rawBody: "name=FOO&value=bar",
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(formPost.status, 415);
  const cookiePost = await request(ctx.origin, `/cloud${base}`, {
    method: "POST",
    cookie: `agent_relay_session=${ctx.owner}`,
    body: { name: "VIA_COOKIE", value: "cookie-value-123456" },
  });
  assert.equal(cookiePost.status, 201, "dashboard cookie path works");

  // Encryption at rest: ciphertext only, decryptable with the keyring.
  const rows = await ctx.database.query<{ name: string; value_ciphertext: string; masked_value: string }>(
    "SELECT name, value_ciphertext, masked_value FROM workspace_env_vars WHERE name = 'ANTHROPIC_API_KEY'",
  );
  const stored = rows.rows[0]!;
  assert.match(stored.value_ciphertext, /^v2\.test-key\./);
  assert(!stored.value_ciphertext.includes(ANTHROPIC));
  assert(!JSON.stringify(rows.rows).includes(ANTHROPIC), "no plaintext in any column");
  assert.equal(decryptSecret(stored.value_ciphertext, KEYRING), `${ANTHROPIC}-rotated`);
  const dump = await ctx.database.query("SELECT * FROM workspace_env_vars");
  assert(!JSON.stringify(dump.rows).includes("cookie-value-123456"));

  // No user-facing read returns plaintext.
  for (const path of [base, `${base}/ANTHROPIC_API_KEY`, `/api/v1/workspaces/${ctx.workspaceId}/admin/audit`]) {
    const response = await request(ctx.origin, path, { token: ctx.owner });
    assert.equal(response.status, 200, path);
    assert(!response.raw.includes(ANTHROPIC), `${path} leaks no plaintext`);
  }
  const listed = await request(ctx.origin, base, { token: ctx.owner });
  const relayRow = listed.body.data.items.find((item: any) => item.name === "RELAY_INTERNAL_THING");
  assert.equal(relayRow.deliveredToFlowRuns, false);
  assert.equal(listed.body.data.items.find((item: any) => item.name === "SHORT").maskedValue, "****");

  // Internal runtime read: never with user credentials.
  const internal = `/internal/v1/workspaces/${ctx.workspaceId}/environment`;
  assert.equal((await request(ctx.origin, internal)).status, 401);
  assert.equal((await request(ctx.origin, internal, { token: ctx.owner })).status, 401);
  assert.equal((await request(ctx.origin, internal, { token: BOOTSTRAP })).status, 401);
  assert.equal((await request(ctx.origin, internal, { token: `${SERVICE}x` })).status, 401);
  const runtime = await request(ctx.origin, internal, { token: SERVICE });
  assert.equal(runtime.status, 200);
  assert.equal(runtime.body.env.ANTHROPIC_API_KEY, `${ANTHROPIC}-rotated`);
  assert.equal(runtime.body.env.SHORT, "abc");
  assert.equal(runtime.body.env.RELAY_INTERNAL_THING, undefined);
  assert.deepEqual(runtime.body.skipped, [{ name: "RELAY_INTERNAL_THING", reason: "reserved" }]);
  assert.deepEqual(runtime.body.secretEnvNames, ["ANTHROPIC_API_KEY", "SHORT", "VIA_COOKIE"]);
  assert.equal(runtime.headers.get("cache-control"), "no-store");
  const unknownWorkspace = await request(
    ctx.origin,
    "/internal/v1/workspaces/00000000-0000-4000-8000-00000000dead/environment",
    { token: SERVICE },
  );
  assert.equal(unknownWorkspace.status, 404);
  const isolated = await request(ctx.origin, `/internal/v1/workspaces/${ctx.otherWorkspaceId}/environment`, {
    token: SERVICE,
  });
  assert.deepEqual(isolated.body.env, {}, "workspace scope isolates variables");

  // An undecryptable value is skipped and reported, never fatal.
  await ctx.database.query(
    `INSERT INTO workspace_env_vars (workspace_id, name, value_ciphertext, masked_value, value_bytes)
     VALUES ($1, 'BROKEN', 'v2.retired-key.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA.AAAA', '****', 4)`,
    [ctx.workspaceId],
  );
  const withBroken = await request(ctx.origin, internal, { token: SERVICE });
  assert.equal(withBroken.status, 200);
  assert.deepEqual(withBroken.body.skipped.find((item: any) => item.name === "BROKEN"), {
    name: "BROKEN",
    reason: "undecryptable",
  });

  // Delete: admin-only, then 404.
  const del = `${base}/SHORT`;
  assert.equal((await request(ctx.origin, del, { method: "DELETE", token: ctx.member })).status, 403);
  const deleted = await request(ctx.origin, del, { method: "DELETE", token: ctx.owner });
  assert.equal(deleted.status, 200);
  assert.equal(deleted.body.name, "SHORT");
  assert.equal((await request(ctx.origin, del, { method: "DELETE", token: ctx.owner })).status, 404);
  assert.equal((await request(ctx.origin, del, { token: ctx.owner })).status, 404);

  const audit = await request(ctx.origin, `/api/v1/workspaces/${ctx.workspaceId}/admin/audit`, { token: ctx.owner });
  const actions = audit.body.events.map((event: any) => event.action);
  for (const action of ["env_var.create", "env_var.update", "env_var.delete", "env_var.runtime_read"]) {
    assert(actions.includes(action), action);
  }
  assert.equal(
    (await request(ctx.origin, `/api/v1/workspaces/${ctx.workspaceId}/admin/audit`, { token: ctx.member })).status,
    403,
  );
});

test("workspace API tokens: owner-only, shown once, scoped runtime credentials", async (t) => {
  const ctx = await setup(t);
  const base = `/api/v1/workspaces/${ctx.workspaceId}/deployment-api-tokens`;
  await request(ctx.origin, `/api/v1/workspaces/${ctx.workspaceId}/secrets`, {
    method: "POST",
    token: ctx.owner,
    body: { name: "OPENAI_API_KEY", value: "sk-openai-plaintext-123" },
  });
  assert.equal((await request(ctx.origin, base, { token: ctx.member })).status, 403);
  assert.equal(
    (await request(ctx.origin, base, { method: "POST", token: ctx.member, body: { label: "x" } })).status,
    403,
  );
  const badExpiry = await request(ctx.origin, base, {
    method: "POST",
    token: ctx.owner,
    body: { label: "runtime", purpose: "agent-runtime", neverExpires: true },
  });
  assert.equal(badExpiry.status, 400, "only workflow tokens may never expire");

  const created = await request(ctx.origin, base, {
    method: "POST",
    token: ctx.owner,
    body: { label: "flows worker", purpose: "agent-runtime", expiryDays: 30 },
  });
  assert.equal(created.status, 201);
  const accessToken = created.body.accessToken as string;
  assert.match(accessToken, /^sh_wk_/);
  assert.deepEqual(created.body.scopes, ["runtime:env:read", "runtime:integrations:read"]);
  const listed = await request(ctx.origin, base, { token: ctx.owner });
  assert.equal(listed.body.tokens.length, 1);
  assert(!listed.raw.includes(accessToken), "token is never listed again");
  assert.equal(listed.body.tokens[0].status, "active");
  const hashes = await ctx.database.query("SELECT * FROM workspace_api_tokens");
  assert(!JSON.stringify(hashes.rows).includes(accessToken), "only the hash is stored");

  const env = await request(ctx.origin, `/internal/v1/workspaces/${ctx.workspaceId}/environment`, {
    token: accessToken,
  });
  assert.equal(env.status, 200);
  assert.equal(env.body.env.OPENAI_API_KEY, "sk-openai-plaintext-123");
  const otherWorkspace = await request(ctx.origin, `/internal/v1/workspaces/${ctx.otherWorkspaceId}/environment`, {
    token: accessToken,
  });
  assert.equal(otherWorkspace.status, 404, "API tokens are bound to their workspace");
  const userRoute = await request(ctx.origin, `/api/v1/workspaces/${ctx.workspaceId}/secrets`, {
    token: accessToken,
  });
  assert.equal(userRoute.status, 401, "API tokens do not authenticate user routes");

  const deployment = await request(ctx.origin, base, {
    method: "POST",
    token: ctx.owner,
    body: { label: "ci", purpose: "deployment" },
  });
  const insufficient = await request(ctx.origin, `/internal/v1/workspaces/${ctx.workspaceId}/environment`, {
    token: deployment.body.accessToken,
  });
  assert.equal(insufficient.status, 403);

  const revoke = await request(ctx.origin, `${base}/${created.body.id}`, { method: "DELETE", token: ctx.owner });
  assert.equal(revoke.status, 204);
  const afterRevoke = await request(ctx.origin, `/internal/v1/workspaces/${ctx.workspaceId}/environment`, {
    token: accessToken,
  });
  assert.equal(afterRevoke.status, 401);
  const statuses = (await request(ctx.origin, base, { token: ctx.owner })).body.tokens.map((token: any) => token.status);
  assert.deepEqual(statuses.sort(), ["active", "revoked"]);
});

test("provider connections: BYO OAuth round trip, encrypted tokens, refresh, disconnect", async (t) => {
  const ctx = await setup(t);
  const ws = `/api/v1/workspaces/${ctx.workspaceId}`;

  const catalog = await request(ctx.origin, "/api/v1/integrations/catalog");
  assert.equal(catalog.status, 200);
  const ids = catalog.body.providers.map((provider: any) => provider.id);
  for (const id of ["github", "slack", "linear", "notion", "posthog"]) assert(ids.includes(id), id);
  assert.equal(catalog.body.providers.find((p: any) => p.id === "posthog").authMode, "API_KEY");

  const notConfigured = await request(ctx.origin, `${ws}/integrations/connect-session`, {
    method: "POST",
    token: ctx.owner,
    body: { allowedIntegrations: ["mockhub"] },
  });
  assert.equal(notConfigured.status, 409);
  assert.equal(notConfigured.body.error, "oauth_app_not_configured");
  assert.equal(notConfigured.body.message, "Your administrator needs to configure the MockHub app before it can be connected.");
  const unknown = await request(ctx.origin, `${ws}/integrations/connect-session`, {
    method: "POST",
    token: ctx.owner,
    body: { allowedIntegrations: ["nope"] },
  });
  assert.equal(unknown.status, 409);
  assert.equal(unknown.body.error, "unknown_provider");

  const secret = "mock-secret-value-123";
  assert.equal((await request(ctx.origin, `${ws}/integrations/mockhub/oauth-app`, {
    method: "PUT",
    token: ctx.member,
    body: { clientId: "mock-client", clientSecret: secret },
  })).status, 403);
  const app = await request(ctx.origin, `${ws}/integrations/mockhub/oauth-app`, {
    method: "PUT",
    token: ctx.owner,
    body: { clientId: "mock-client", clientSecret: secret },
  });
  assert.equal(app.status, 200);
  assert.equal(app.body.clientId, "mock-client");
  assert.equal(app.body.redirectUri, `${ctx.origin}/api/v1/integrations/oauth/callback`);
  assert(!app.raw.includes(secret));
  const appRows = await ctx.database.query<{ client_secret_ciphertext: string }>(
    "SELECT * FROM integration_oauth_apps",
  );
  assert(!JSON.stringify(appRows.rows).includes(secret), "client secret encrypted at rest");
  assert.equal(decryptSecret(appRows.rows[0]!.client_secret_ciphertext, KEYRING), secret);
  // Updating without a secret keeps the stored secret.
  const scoped = await request(ctx.origin, `${ws}/integrations/mockhub/oauth-app`, {
    method: "PUT",
    token: ctx.owner,
    body: { clientId: "mock-client", scopes: ["read", "write"] },
  });
  assert.equal(scoped.status, 200);
  assert.equal(scoped.body.scopesOverridden, true);

  const providersView = await request(ctx.origin, `${ws}/integrations/providers`, { token: ctx.member });
  assert.equal(providersView.status, 200);
  assert.equal(providersView.body.canManage, false);
  assert.equal(providersView.body.providers.find((p: any) => p.id === "mockhub").configured, true);
  assert(!providersView.raw.includes(secret));

  assert.equal((await request(ctx.origin, `${ws}/integrations/connect-session`, {
    method: "POST",
    token: ctx.member,
    body: { allowedIntegrations: ["mockhub"] },
  })).status, 200, "members connect just in time (the OAuth app is operator configuration)");

  // Full authorization-code round trip with PKCE through the mock server.
  const session = await request(ctx.origin, `${ws}/integrations/connect-session`, {
    method: "POST",
    token: ctx.owner,
    body: { allowedIntegrations: ["mockhub-relay"] },
  });
  assert.equal(session.status, 200);
  assert.equal(session.body.backend, "selfhost");
  const link = new URL(session.body.connectLink);
  assert.equal(link.origin, ctx.mock.origin);
  assert.equal(link.searchParams.get("code_challenge_method"), "S256");
  assert.equal(link.searchParams.get("scope"), "read write");
  const authorize = await fetch(link, { redirect: "manual" });
  assert.equal(authorize.status, 302);
  const callbackUrl = authorize.headers.get("location")!;
  assert(callbackUrl.startsWith(`${ctx.origin}/api/v1/integrations/oauth/callback?`));
  const callback = await fetch(callbackUrl);
  assert.equal(callback.status, 200);
  const page = await callback.text();
  assert.match(page, /MockHub connected/);
  assert(!page.includes("secret-access"));
  const replay = await fetch(callbackUrl);
  assert.equal(replay.status, 400, "state is single-use");
  assert.equal(ctx.mock.tokenRequests[0]!.grant_type, "authorization_code");
  assert(ctx.mock.tokenRequests[0]!.code_verifier, "PKCE verifier sent");

  const list = await request(ctx.origin, `${ws}/integrations`, { token: ctx.member });
  assert.equal(list.status, 200);
  assert(Array.isArray(list.body), "hosted-compatible bare array");
  const entry = (list.body as unknown as any[])[0];
  assert.equal(entry.provider, "mockhub");
  assert.equal(entry.status, "ready");
  assert.equal(entry.refreshable, true);
  assert.deepEqual(entry.scopes, ["read", "write"]);
  assert(!list.raw.includes("secret-access") && !list.raw.includes("rt-1"));
  const status = await request(ctx.origin, `${ws}/integrations/mockhub/status?connectionId=${entry.connectionId}`, {
    token: ctx.owner,
  });
  assert.equal(status.body.ready, true);
  assert.equal(status.body.connectionMatched, true);

  const connectionRows = await ctx.database.query<{ credentials_ciphertext: string }>(
    "SELECT * FROM integration_connections",
  );
  const dumped = JSON.stringify(connectionRows.rows);
  assert(!dumped.includes("at-1-secret-access") && !dumped.includes("rt-1"), "tokens encrypted at rest");
  assert.deepEqual(
    JSON.parse(decryptSecret(connectionRows.rows[0]!.credentials_ciphertext, KEYRING)),
    { accessToken: "at-1-secret-access", refreshToken: "rt-1" },
  );
  const stateRows = await ctx.database.query("SELECT * FROM integration_oauth_states");
  assert(!JSON.stringify(stateRows.rows).includes(link.searchParams.get("state")!), "state stored hashed");

  // Runtime token fetch: service credential only.
  const tokenPath = `/internal/v1/workspaces/${ctx.workspaceId}/integrations/mockhub/token`;
  assert.equal((await request(ctx.origin, tokenPath, { method: "POST", token: ctx.owner, body: {} })).status, 401);
  const fresh = await request(ctx.origin, tokenPath, { method: "POST", token: SERVICE, body: {} });
  assert.equal(fresh.status, 200);
  assert.equal(fresh.body.accessToken, "at-1-secret-access");
  assert.equal(fresh.body.provider, "mockhub");
  assert(!("refreshToken" in fresh.body), "refresh tokens never leave the control plane");

  // Near expiry -> refreshed transparently, rotated refresh token stored.
  await ctx.database.query(
    "UPDATE integration_connections SET access_token_expires_at = now() + interval '30 seconds'",
  );
  const refreshed = await request(ctx.origin, tokenPath, { method: "POST", token: SERVICE, body: {} });
  assert.equal(refreshed.status, 200);
  assert.equal(refreshed.body.accessToken, "at-2-secret-access");
  assert.equal(ctx.mock.tokenRequests.at(-1)!.grant_type, "refresh_token");
  assert.equal(ctx.mock.tokenRequests.at(-1)!.refresh_token, "rt-1");
  const forced = await request(ctx.origin, tokenPath, { method: "POST", token: SERVICE, body: { forceRefresh: true } });
  assert.equal(forced.body.accessToken, "at-3-secret-access");

  // Refresh failure marks the connection errored and surfaces it.
  ctx.mock.nextRefreshError = "invalid_grant";
  const failed = await request(ctx.origin, tokenPath, { method: "POST", token: SERVICE, body: { forceRefresh: true } });
  assert.equal(failed.status, 409);
  assert.equal(failed.body.error, "refresh_failed");
  const errored = await request(ctx.origin, `${ws}/integrations/mockhub`, { token: ctx.owner });
  assert.equal(errored.body.status, "error");
  assert.match(errored.body.lastError, /invalid_grant/);
  // The next successful refresh recovers it.
  const recovered = await request(ctx.origin, tokenPath, { method: "POST", token: SERVICE, body: {} });
  assert.equal(recovered.status, 200);
  assert.equal(recovered.body.accessToken, "at-4-secret-access");

  // API-key provider.
  const apiKey = "phx_posthog_plaintext_key";
  const missing = await request(ctx.origin, `${ws}/integrations/posthog`, {
    method: "POST",
    token: ctx.owner,
    body: { credentials: { host: "https://eu.posthog.com" } },
  });
  assert.equal(missing.status, 400);
  const posthog = await request(ctx.origin, `${ws}/integrations/posthog`, {
    method: "POST",
    token: ctx.owner,
    body: { credentials: { apiKey, host: "https://eu.posthog.com" } },
  });
  assert.equal(posthog.status, 201);
  assert.equal(posthog.body.authMode, "api_key");
  assert.deepEqual(posthog.body.metadata, { config: { host: "https://eu.posthog.com" } });
  assert(!posthog.raw.includes(apiKey));
  assert.equal((await request(ctx.origin, `${ws}/integrations/github`, {
    method: "POST",
    token: ctx.owner,
    body: { credentials: { apiKey: "x" } },
  })).status, 400, "OAuth providers cannot be connected with a pasted key");

  const env = await request(
    ctx.origin,
    `/internal/v1/workspaces/${ctx.workspaceId}/environment?includeIntegrations=1`,
    { token: SERVICE },
  );
  assert.equal(env.status, 200);
  assert.equal(env.body.env.WORKFORCE_INTEGRATION_POSTHOG_TOKEN, apiKey);
  assert.equal(env.body.env.WORKFORCE_INTEGRATION_POSTHOG_HOST, "https://eu.posthog.com");
  assert.equal(env.body.env.WORKFORCE_INTEGRATION_MOCKHUB_TOKEN, "at-4-secret-access");

  const internalList = await request(ctx.origin, `/internal/v1/workspaces/${ctx.workspaceId}/integrations`, {
    token: SERVICE,
  });
  assert.equal(internalList.body.integrations.length, 2);
  assert(!internalList.raw.includes(apiKey) && !internalList.raw.includes("secret-access"));

  // Disconnect: admin-only, idempotent, then token fetch 404.
  assert.equal((await request(ctx.origin, `${ws}/integrations/mockhub`, { method: "DELETE", token: ctx.member })).status, 403);
  const disconnected = await request(ctx.origin, `${ws}/integrations/mockhub`, { method: "DELETE", token: ctx.owner });
  assert.equal(disconnected.status, 200);
  assert.equal(disconnected.body.localDeleted, true);
  const again = await request(ctx.origin, `${ws}/integrations/mockhub/status`, { method: "DELETE", token: ctx.owner });
  assert.equal(again.body.localDeleted, false);
  assert.equal((await request(ctx.origin, tokenPath, { method: "POST", token: SERVICE, body: {} })).status, 404);

  // Provider-denied authorization renders a failure page.
  const denied = await request(ctx.origin, `${ws}/integrations/connect-session`, {
    method: "POST",
    token: ctx.owner,
    body: { allowedIntegrations: ["mockhub"] },
  });
  const deniedState = new URL(denied.body.connectLink).searchParams.get("state")!;
  const deniedPage = await fetch(
    `${ctx.origin}/api/v1/integrations/oauth/callback?error=access_denied&state=${deniedState}`,
  );
  assert.equal(deniedPage.status, 400);
  assert.match(await deniedPage.text(), /did not authorize/);

  const audit = await request(ctx.origin, `${ws}/admin/audit`, { token: ctx.owner });
  const actions = audit.body.events.map((event: any) => event.action);
  for (const action of [
    "integration.oauth_app.put", "integration.connect", "integration.refresh",
    "integration.token_read", "integration.disconnect",
  ]) {
    assert(actions.includes(action), action);
  }
  assert(!audit.raw.includes("secret-access") && !audit.raw.includes(apiKey));
});

test("real provider authorize URLs carry the registered redirect, scopes, and PKCE", async (t) => {
  const ctx = await setup(t);
  const ws = `/api/v1/workspaces/${ctx.workspaceId}`;
  const expectations: Record<string, (url: URL) => void> = {
    github: (url) => {
      assert.equal(url.origin + url.pathname, "https://github.com/login/oauth/authorize");
      assert.equal(url.searchParams.get("scope"), "repo read:org read:user");
      assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    },
    slack: (url) => {
      assert.equal(url.origin + url.pathname, "https://slack.com/oauth/v2/authorize");
      assert.match(url.searchParams.get("scope")!, /^app_mentions:read,channels:history,/);
    },
    linear: (url) => {
      assert.equal(url.origin + url.pathname, "https://linear.app/oauth/authorize");
      assert.equal(url.searchParams.get("actor"), "app");
      assert.equal(url.searchParams.get("scope"), "read,write,app:assignable,app:mentionable");
    },
    notion: (url) => {
      assert.equal(url.origin + url.pathname, "https://api.notion.com/v1/oauth/authorize");
      assert.equal(url.searchParams.get("owner"), "user");
      assert.equal(url.searchParams.get("scope"), null);
    },
  };
  for (const [provider, check] of Object.entries(expectations)) {
    const put = await request(ctx.origin, `${ws}/integrations/${provider}/oauth-app`, {
      method: "PUT",
      token: ctx.owner,
      body: { clientId: `${provider}-client`, clientSecret: `${provider}-secret-value` },
    });
    assert.equal(put.status, 200, provider);
    const session = await request(ctx.origin, `${ws}/integrations/connect-session`, {
      method: "POST",
      token: ctx.owner,
      body: { allowedIntegrations: [provider] },
    });
    assert.equal(session.status, 200, provider);
    const url = new URL(session.body.connectLink);
    assert.equal(url.searchParams.get("client_id"), `${provider}-client`);
    assert.equal(url.searchParams.get("redirect_uri"), `${ctx.origin}/api/v1/integrations/oauth/callback`);
    assert.equal(url.searchParams.get("response_type"), "code");
    assert(url.searchParams.get("state")!.length >= 40);
    assert(!session.raw.includes(`${provider}-secret-value`));
    check(url);
  }
  const apiKeyConnect = await request(ctx.origin, `${ws}/integrations/connect-session`, {
    method: "POST",
    token: ctx.owner,
    body: { allowedIntegrations: ["posthog"] },
  });
  assert.equal(apiKeyConnect.status, 400);
});

test("organization rename is admin-only and normalized", async (t) => {
  const ctx = await setup(t);
  const path = `/api/v1/organizations/${ctx.organizationId}`;
  assert.equal((await request(ctx.origin, path, { method: "PATCH", token: ctx.member, body: { name: "x" } })).status, 403);
  const renamed = await request(ctx.origin, path, {
    method: "PATCH",
    token: ctx.owner,
    body: { name: "  Acme\u0007  Robotics " },
  });
  assert.equal(renamed.status, 200);
  assert.equal(renamed.body.organization.name, "Acme Robotics");
  assert.equal((await request(ctx.origin, path, { method: "PATCH", token: ctx.owner, body: { name: "x".repeat(81) } })).status, 400);
});

test("provider token parsers handle provider-specific envelopes", () => {
  const slack = DEFAULT_PROVIDERS.find((provider) => provider.id === "slack") as OAuthProvider;
  assert.throws(() => slack.parseTokenResponse!({ ok: false, error: "invalid_code" }), ProviderTokenError);
  const parsed = slack.parseTokenResponse!({
    ok: true,
    access_token: "xoxb-1",
    token_type: "bot",
    scope: "chat:write,channels:read",
    team: { id: "T1", name: "Acme" },
    bot_user_id: "U1",
  });
  assert.equal(parsed.accountLabel, "Acme");
  assert.deepEqual(parsed.scopes, ["chat:write", "channels:read"]);
  const notion = DEFAULT_PROVIDERS.find((provider) => provider.id === "notion") as OAuthProvider;
  assert.equal(notion.clientAuth, "basic");
  assert.equal(notion.parseTokenResponse!({
    access_token: "secret_1",
    workspace_id: "w1",
    workspace_name: "Docs",
    bot_id: "b1",
  }).accountLabel, "Docs");
  assert(envKeyReachesRuntime("ANTHROPIC_API_KEY"), "self-host delivers model provider keys");
  assert(!envKeyReachesRuntime("RELAYFILE_TOKEN"));
});

test("admin configuration is optional and validated", () => {
  const env = {
    DATABASE_URL: "postgres://runtime@db/selfhost",
    SELFHOST_PUBLIC_URL: "https://api.selfhosted.company",
    RELAYCAST_URL: "http://relaycast",
    RELAYCAST_PUBLIC_URL: "https://cast.selfhosted.company",
    SESSION_READ_API_URL: "http://relayhistory",
    SESSION_READ_API_PUBLIC_URL: "https://history.selfhosted.company",
    SESSION_READ_API_SECRET: "r".repeat(32),
    RELAYCONTROL_INTROSPECT_SECRET: "i".repeat(32),
    SELFHOST_BOOTSTRAP_TOKEN: "b".repeat(32),
    SELFHOST_ENCRYPTION_KEY_ID: "k1",
    SELFHOST_ENCRYPTION_KEY: "00".repeat(32),
  };
  const defaults = loadConfig(env);
  assert.equal(defaults.internalServiceToken, null);
  assert.equal(defaults.oauthRedirectUrl, "https://api.selfhosted.company/api/v1/integrations/oauth/callback");
  assert.equal(defaults.dashboardUrl, "https://api.selfhosted.company/");
  assert.throws(() => loadConfig({ ...env, SELFHOST_INTERNAL_TOKEN: "short" }), /at least 32 bytes/);
  assert.throws(
    () => loadConfig({ ...env, SELFHOST_OAUTH_REDIRECT_URL: "https://api.selfhosted.company/cb?x=1" }),
    /query string/,
  );
  const custom = loadConfig({
    ...env,
    SELFHOST_INTERNAL_TOKEN: "s".repeat(40),
    SELFHOST_DASHBOARD_URL: "https://selfhosted.company/dashboard/",
  });
  assert.equal(custom.internalServiceToken, "s".repeat(40));
  assert.equal(custom.dashboardUrl, "https://selfhosted.company/dashboard/");
});

test("every admin operation is documented in openapi.yaml", async () => {
  const { readFile } = await import("node:fs/promises");
  const spec = await readFile(new URL("../openapi.yaml", import.meta.url), "utf8");
  for (const path of [
    "/api/v1/organizations/{organizationId}:",
    "/api/v1/workspaces/{workspaceId}/secrets:",
    "/api/v1/workspaces/{workspaceId}/secrets/{name}:",
    "/api/v1/integrations/catalog:",
    "/api/v1/integrations/oauth/callback:",
    "/api/v1/workspaces/{workspaceId}/integrations:",
    "/api/v1/workspaces/{workspaceId}/integrations/providers:",
    "/api/v1/workspaces/{workspaceId}/integrations/connect-session:",
    "/api/v1/workspaces/{workspaceId}/integrations/{provider}/oauth-app:",
    "/api/v1/workspaces/{workspaceId}/integrations/{provider}:",
    "/api/v1/workspaces/{workspaceId}/integrations/{provider}/status:",
    "/api/v1/workspaces/{workspaceId}/deployment-api-tokens:",
    "/api/v1/workspaces/{workspaceId}/deployment-api-tokens/{tokenId}:",
    "/api/v1/workspaces/{workspaceId}/admin/audit:",
    "/api/v1/workspaces/{workspaceId}/cloud-agents:",
    "/api/v1/workspaces/{workspaceId}/cloud-agents/{agentId}:",
    "/api/v1/workspaces/{workspaceId}/cloud-agents/{agentId}/activate:",
    "/api/v1/workspaces/{workspaceId}/cloud-agents/{agentId}/check:",
    "/api/v1/workspaces/{workspaceId}/provider-credentials/byok:",
    "/api/v1/workspaces/{workspaceId}/provider-credentials/setup-token:",
    "/api/v1/workspaces/{workspaceId}/provider-credentials/openai-device/start:",
    "/api/v1/workspaces/{workspaceId}/provider-credentials/openai-device/status:",
    "/api/v1/workspaces/{workspaceId}/provider-credentials/xai-device/start:",
    "/api/v1/workspaces/{workspaceId}/provider-credentials/xai-device/status:",
    "/internal/v1/workspaces/{workspaceId}/environment:",
    "/internal/v1/workspaces/{workspaceId}/integrations:",
    "/internal/v1/workspaces/{workspaceId}/integrations/{provider}/token:",
  ]) {
    assert(spec.includes(`\n  ${path}\n`), path);
  }
});

test("just-in-time connect: operator OAuth app from config, admin message, return to the page, CLI shape", async (t) => {
  const ctx = await setup(t, {
    operatorOAuthApps: { mockhub: { clientId: "mock-client", clientSecret: "mock-secret-value-123", scopes: null } },
  });
  const ws = `/api/v1/workspaces/${ctx.workspaceId}`;
  const providers = await request(ctx.origin, `${ws}/integrations/providers`, { token: ctx.member });
  const mockhub = providers.body.providers.find((p: any) => p.id === "mockhub");
  assert.equal(mockhub.configured, true);
  assert.equal(mockhub.configuredBy, "operator");
  assert.equal(mockhub.oauthApp, null, "operator apps are not shown as a workspace app");
  assert(!providers.raw.includes("mock-secret-value-123"));
  const github = providers.body.providers.find((p: any) => p.id === "github");
  assert.equal(github.configured, false);
  assert.equal(github.adminMessage, "Your administrator needs to configure the GitHub app before it can be connected.");

  const unconfigured = await request(ctx.origin, `${ws}/integrations/connect-session`, {
    method: "POST",
    token: ctx.member,
    body: { allowedIntegrations: ["github"] },
  });
  assert.equal(unconfigured.status, 409);
  assert.equal(unconfigured.body.message, "Your administrator needs to configure the GitHub app before it can be connected.");

  // A member connects just in time from a flow page and comes back to it.
  const returnTo = `${ctx.origin}/dashboard/#/flows/f1`;
  const session = await request(ctx.origin, `${ws}/integrations/connect-session`, {
    method: "POST",
    token: ctx.member,
    body: { allowedIntegrations: ["mockhub"], returnTo },
  });
  assert.equal(session.status, 200);
  assert.equal(typeof session.body.relayWorkspaceId, "string");
  const link = new URL(session.body.connectLink);
  assert.equal(link.origin + link.pathname, `${ctx.mock.origin}/authorize`, "reaches the provider authorize URL");
  assert.equal(link.searchParams.get("client_id"), "mock-client");
  assert.equal(link.searchParams.get("redirect_uri"), `${ctx.origin}/api/v1/integrations/oauth/callback`);
  const authorize = await fetch(link, { redirect: "manual" });
  const callback = await fetch(authorize.headers.get("location")!);
  const page = await callback.text();
  assert.equal(callback.status, 200);
  assert(page.includes(`href="${returnTo}"`), "the callback page returns to where the user was");
  assert(page.includes("Return to where you were"));
  const status = await request(ctx.origin, `${ws}/integrations/mockhub/status`, { token: ctx.member });
  assert.equal(status.body.ready, true);

  // A returnTo on another origin is ignored.
  const offsite = await request(ctx.origin, `${ws}/integrations/connect-session`, {
    method: "POST",
    token: ctx.member,
    body: { allowedIntegrations: ["mockhub"], returnTo: "https://evil.example/phish" },
  });
  const offsiteCallback = await fetch((await fetch(new URL(offsite.body.connectLink), { redirect: "manual" })).headers.get("location")!);
  const offsitePage = await offsiteCallback.text();
  assert(!offsitePage.includes("evil.example"));
  assert(offsitePage.includes(`href="${ctx.origin}/dashboard/"`));
});

test("operator OAuth apps load from env and mounted Secret files", async () => {
  const { mkdtemp, writeFile, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "rc-oauth-"));
  try {
    await writeFile(join(dir, "secret"), "gh-secret-from-file\n");
    const apps = loadOperatorOAuthApps({
      SELFHOST_OAUTH_GITHUB_CLIENT_ID: "gh-client",
      SELFHOST_OAUTH_GITHUB_CLIENT_SECRET_FILE: join(dir, "secret"),
      SELFHOST_OAUTH_GOOGLE_MAIL_CLIENT_ID: "gm-client",
      SELFHOST_OAUTH_GOOGLE_MAIL_CLIENT_SECRET: "gm-secret",
      SELFHOST_OAUTH_GOOGLE_MAIL_SCOPES: "a b,c",
      SELFHOST_OAUTH_REDIRECT_URL: "https://x.test/cb",
    });
    assert.deepEqual(apps, {
      github: { clientId: "gh-client", clientSecret: "gh-secret-from-file", scopes: null },
      "google-mail": { clientId: "gm-client", clientSecret: "gm-secret", scopes: ["a", "b", "c"] },
    });
    assert.throws(() => loadOperatorOAuthApps({ SELFHOST_OAUTH_SLACK_CLIENT_ID: "s" }), /CLIENT_SECRET/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
