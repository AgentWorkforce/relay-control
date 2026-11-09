import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import { loadConfig, type SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * RELAYHISTORY_BACKEND=native: Control talks only to the read API handoff, and
 * hands bearer clients their own sh_at_ token as the ingest-edge credential.
 * The upstream double fails the test if anything calls a RelayAuth or History
 * path.
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const INTERNAL = "internal-service-token-at-least-32-bytes!";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const READ_SECRET = "session-read-secret-that-is-at-least-32-b";
const ORIGIN = "https://history.selfhosted.company";

function readReply(body: Record<string, unknown>, sessionId = "s-1") {
  const token = (kind: string) => `rth_${kind}_read_${"a".repeat(40)}${sessionId.padEnd(3, "x")}`;
  return {
    sessionId,
    userId: body.userId,
    orgId: body.orgId,
    workspaceId: body.workspaceId,
    audience: body.audience,
    scopes: ["rth:read"],
    accessToken: token("at"),
    accessTokenExpiresAt: new Date(Date.now() + 300_000).toISOString(),
    refreshToken: token("rt"),
    refreshTokenExpiresAt: new Date(Date.now() + 90 * 86_400_000).toISOString(),
    tokenType: "Bearer",
  };
}

async function startReadApi(t: TestContext) {
  const issued: Array<{ path: string; body: Record<string, unknown>; bearer: string | undefined }> = [];
  const reads: string[] = [];
  const unexpected: string[] = [];
  let n = 0;
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const path = new URL(req.url ?? "/", "http://x").pathname;
      if (path.startsWith("/internal/v1/session-read/sessions")) {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
        issued.push({ path, body, bearer: req.headers.authorization });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(readReply(body, `s-${++n}`)));
        return;
      }
      if (req.method === "GET" && path === "/v1/sessions") {
        reads.push(`${req.headers.authorization}`);
        const workspace = new URL(req.url ?? "/", "http://x").searchParams.get("workspace") ?? "";
        res.writeHead(200, { "content-type": "application/json", "x-relayhistory-workspace-id": workspace });
        res.end(JSON.stringify({ sessions: [{ sessionId: "s", id: "s", source: "claude", startedAt: new Date().toISOString() }], nextCursor: null }));
        return;
      }
      unexpected.push(`${req.method} ${path}`);
      res.writeHead(500);
      res.end("{}");
    });
  });
  const origin = await listen(server);
  t.after(() => close(server));
  return { origin, issued, reads, unexpected };
}

async function setup(t: TestContext) {
  const readApi = await startReadApi(t);
  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused-in-test",
    publicBaseUrl: "https://control.internal.example",
    relaycastUrl: "http://relaycast.internal",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayauthUrl: null,
    relayauthApiKey: null,
    relayhistoryBackend: "native",
    relayhistoryUrl: readApi.origin,
    relayhistoryPublicUrl: ORIGIN,
    sessionReadApi: { url: readApi.origin, publicUrl: ORIGIN, secret: READ_SECRET },
    introspectSecret: INTROSPECT_SECRET,
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    internalServiceToken: INTERNAL,
    oauthRedirectUrl: "https://control.internal.example/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.internal.example/",
    port: 3000,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const server = createServer(createApp({ config, store }));
  const origin = await listen(server);
  t.after(async () => {
    await close(server);
    await database.close();
  });
  const org = await request(origin, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, body: { name: "Tenant", ownerEmail: "owner@example.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const created = await request(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "alpha", relaycastApiKey: "rk_alpha" },
  });
  assert.equal(created.status, 201);
  const workspace = created.body.id as string;
  const started = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: { client_name: "native-test" } });
  await request(origin, "/api/v1/auth/device/approve", {
    method: "POST", token: BOOTSTRAP,
    body: { action: "approve", user_code: started.body.user_code, user_id: org.body.owner.id, workspace_id: workspace },
  });
  const tokens = await request(origin, "/api/v1/auth/device/token", { method: "POST", body: { device_code: started.body.device_code } });
  assert.equal(tokens.status, 200);
  return { origin, readApi, workspace, token: tokens.body.access_token as string };
}

test("native: sync hands the caller its own token for the ingest edge, with no RelayAuth or History", async (t) => {
  const env = await setup(t);
  const sync = await request(env.origin, `/api/v1/workspaces/${env.workspace}/relayhistory/session`, {
    method: "POST", token: env.token, body: { mode: "sync", label: "probe" },
  });
  assert.equal(sync.status, 200, sync.raw);
  assert.equal(sync.body.accessToken, env.token);
  assert.equal(sync.body.baseUrl, ORIGIN);
  assert.deepEqual(sync.body.scopes, ["rth:sync"]);
  assert.equal(sync.body.tokenType, "Bearer");
  assert.equal(sync.body.workspaceId, env.workspace);
  assert.notEqual(sync.body.refreshToken, env.token, "the credential is not duplicated as a refresh token");
  assert.ok(Date.parse(sync.body.accessTokenExpiresAt) <= Date.now() + 15 * 60_000 + 1000);
  assert.deepEqual(env.readApi.issued, []);
  assert.deepEqual(env.readApi.unexpected, []);
});

test("native: read mode is the read API handoff and never returns the caller's token", async (t) => {
  const env = await setup(t);
  const read = await request(env.origin, `/api/v1/workspaces/${env.workspace}/relayhistory/session`, {
    method: "POST", token: env.token, body: { mode: "read", label: "desktop" },
  });
  assert.equal(read.status, 200, read.raw);
  assert.match(read.body.accessToken, /^rth_at_read_/);
  assert.match(read.body.refreshToken, /^rth_rt_read_/);
  assert.equal(read.body.baseUrl, ORIGIN);
  assert.equal(env.readApi.issued[0]?.path, "/internal/v1/session-read/sessions");
  assert.equal(env.readApi.issued[0]?.bearer, `Bearer ${READ_SECRET}`);
  assert.equal(env.readApi.issued[0]?.body.label, "desktop");
  assert.equal(env.readApi.issued[0]?.body.workspaceId, env.workspace);
  assert.deepEqual(env.readApi.unexpected, []);
});

test("native: dashboard reads use the read API with its own token and cache it", async (t) => {
  const env = await setup(t);
  const url = `/cloud/api/v1/workspaces/${env.workspace}/sessions`;
  const first = await request(env.origin, url, { token: env.token });
  assert.equal(first.status, 200, first.raw);
  const second = await request(env.origin, url, { token: env.token });
  assert.equal(second.status, 200, second.raw);
  assert.equal(env.readApi.issued.length, 1, "the access token is reused within its lifetime");
  assert.equal(env.readApi.issued[0]?.body.label, "relay-dashboard");
  for (const bearer of env.readApi.reads) assert.match(bearer, /^Bearer rth_at_read_/);
  assert.deepEqual(env.readApi.unexpected, []);
});

test("native: browser and unauthorized callers are refused upload credentials", async (t) => {
  const env = await setup(t);
  const stranger = await request(env.origin, `/api/v1/workspaces/${env.workspace}/relayhistory/session`, {
    method: "POST", body: { mode: "sync" },
  });
  assert.equal(stranger.status, 401);
  const other = await request(env.origin, "/api/v1/workspaces/does-not-exist/relayhistory/session", {
    method: "POST", token: env.token, body: { mode: "sync" },
  });
  assert.equal(other.status, 404);
  const invalid = await request(env.origin, `/api/v1/workspaces/${env.workspace}/relayhistory/session`, {
    method: "POST", token: env.token, body: { mode: "bogus" },
  });
  assert.equal(invalid.status, 400);
});

const nativeEnv = {
  SELFHOST_BOOTSTRAP_TOKEN: BOOTSTRAP,
  SELFHOST_PUBLIC_URL: "https://control.example.test",
  DATABASE_URL: "postgresql://localhost:5432/test",
  RELAYCAST_URL: "http://relaycast:8787",
  RELAYCAST_PUBLIC_URL: "https://relaycast.selfhosted.company",
  SELFHOST_ENCRYPTION_KEY_ID: "test-key",
  SELFHOST_ENCRYPTION_KEY: "00".repeat(32),
  RELAYHISTORY_BACKEND: "native",
  SESSION_READ_API_URL: "http://read-api.svc.cluster.local",
  SESSION_READ_API_PUBLIC_URL: ORIGIN,
  SESSION_READ_API_SECRET: READ_SECRET,
  RELAYCONTROL_INTROSPECT_SECRET: INTROSPECT_SECRET,
};
const noisy = (env: NodeJS.ProcessEnv) => () => loadConfig(env);

test("native config: requires the handoff and introspection, refuses RelayAuth and a second origin", () => {
  assert.throws(noisy({ ...nativeEnv, RELAYHISTORY_BACKEND: "maybe" }), /RELAYHISTORY_BACKEND must be legacy or native/);
  assert.throws(noisy({ ...nativeEnv, RELAYCONTROL_INTROSPECT_SECRET: "" }), /requires RELAYCONTROL_INTROSPECT_SECRET/);
  assert.throws(noisy({ ...nativeEnv, SESSION_READ_API_SECRET: "", SESSION_READ_API_URL: "", SESSION_READ_API_PUBLIC_URL: "" }), /requires SESSION_READ_API_URL/);
  assert.throws(noisy({ ...nativeEnv, RELAYAUTH_URL: "http://relayauth:8787", RELAYAUTH_API_KEY: "k" }), /refuses RELAYAUTH_URL/);
  assert.throws(noisy({ ...nativeEnv, RELAYHISTORY_READ_API_URL: "https://reader.selfhosted.company" }), /refuses RELAYHISTORY_READ_API_URL/);
  assert.throws(noisy({ ...nativeEnv, RELAYHISTORY_PUBLIC_URL: "https://other.selfhosted.company" }), /RELAYHISTORY_PUBLIC_URL must equal/);
  assert.throws(noisy({ ...nativeEnv, RELAYHISTORY_URL: "http://other:8080" }), /RELAYHISTORY_URL must equal/);
  assert.throws(noisy({ ...nativeEnv, SELFHOST_INTROSPECT_AUDIENCES: "https://other.selfhosted.company" }), /must include SESSION_READ_API_PUBLIC_URL/);
});

test("native config: resolves the History origin to the read API", () => {
  const config = loadConfig(nativeEnv);
  assert.equal(config.relayhistoryBackend, "native");
  assert.equal(config.relayhistoryUrl, "http://read-api.svc.cluster.local");
  assert.equal(config.relayhistoryPublicUrl, ORIGIN);
  assert.equal(config.relayauthUrl, null);
  assert.deepEqual(config.introspectAudiences, [ORIGIN]);
});

test("legacy config is unaffected", () => {
  const config = loadConfig({
    ...nativeEnv,
    RELAYHISTORY_BACKEND: undefined,
    RELAYHISTORY_URL: "http://relayhistory:8080",
    RELAYHISTORY_PUBLIC_URL: "https://h.selfhosted.company",
  });
  assert.equal(config.relayhistoryBackend, null);
  assert.equal(config.relayhistoryUrl, "http://relayhistory:8080");
});
