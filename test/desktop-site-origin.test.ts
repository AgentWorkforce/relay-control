import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase } from "./support/harness.js";

// The GKE layout: the API host (SELFHOST_PUBLIC_URL) and the dashboard host
// both route /cloud/api here. Agent Relay Desktop requires
// api_url == <its site>/cloud, so every sign-in answer names the configured
// origin the request arrived on, and never an unconfigured Host.

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const VERIFIER = "desktop-verifier-0123456789abcdefghijklmnopqrstuvwxyz0123456789";
const CHALLENGE = createHash("sha256").update(VERIFIER).digest("base64url");
const API_SITE = "https://api.proof.test";
const DASHBOARD_SITE = "https://proof.test";

type Raw = { status: number; headers: Record<string, string | string[] | undefined>; body: any; text: string };

/** An HTTP request with an explicit Host header (fetch cannot set one). */
function raw(
  origin: string,
  path: string,
  options: { host: string; method?: string; token?: string; cookie?: string; body?: unknown },
): Promise<Raw> {
  const target = new URL(origin);
  const payload = options.body === undefined ? undefined : JSON.stringify(options.body);
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      hostname: target.hostname,
      port: target.port,
      path,
      method: options.method ?? "GET",
      headers: {
        host: options.host,
        ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
        ...(options.cookie ? { cookie: options.cookie } : {}),
        ...(payload ? { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } : {}),
      },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let body: any = null;
        try {
          body = text ? JSON.parse(text) : null;
        } catch {
          body = null;
        }
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body, text });
      });
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function setup(t: test.TestContext) {
  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseSchema: "public",
    databaseUrl: "unused",
    publicBaseUrl: API_SITE,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://cast.proof.test",
    relayauthUrl: "http://relayauth.invalid",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.proof.test",
    relayauthApiKey: "rak_test",
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: `${API_SITE}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${DASHBOARD_SITE}/`,
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  control.on("request", createApp({ config, store }));
  t.after(async () => {
    await close(control);
    await database.close();
  });
  const apiHost = new URL(API_SITE).host;
  const org = await raw(origin, "/api/v1/organizations", {
    host: apiHost,
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const workspace = await raw(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
    host: apiHost,
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Primary", relaycastApiKey: "rk_primary", relaycastWorkspaceId: "rw_primary" },
  });
  assert.equal(workspace.status, 201);
  return { origin, ownerId: org.body.owner.id as string, workspaceId: workspace.body.id as string };
}

async function approve(origin: string, userCode: string, ownerId: string, workspaceId: string) {
  const approved = await raw(origin, "/api/v1/auth/device/approve", {
    host: new URL(API_SITE).host,
    method: "POST",
    token: BOOTSTRAP,
    body: { action: "approve", user_code: userCode, user_id: ownerId, workspace_id: workspaceId },
  });
  assert.equal(approved.status, 200);
}

/** A browser session on `host` through /login, approved by the bootstrap bearer. */
async function browserSession(origin: string, host: string, ownerId: string, workspaceId: string) {
  const login = await raw(origin, "/login", { host });
  const code = login.text.match(/<code>([A-Z0-9]{4}-[A-Z0-9]{4})<\/code>/)?.[1];
  assert(code);
  const setCookie = login.headers["set-cookie"];
  const deviceCookie = (Array.isArray(setCookie) ? setCookie[0]! : String(setCookie)).split(";")[0]!;
  await approve(origin, code, ownerId, workspaceId);
  const poll = await raw(origin, "/login/poll", { host, method: "POST", cookie: deviceCookie });
  assert.equal(poll.status, 200);
  const cookies = poll.headers["set-cookie"];
  const session = (Array.isArray(cookies) ? cookies : [String(cookies)])
    .map((value) => value.match(/agent_relay_session=[^;]+/)?.[0])
    .find(Boolean);
  assert(session);
  return session;
}

function loginPath(): string {
  const params = new URLSearchParams({
    redirect_uri: "http://127.0.0.1:5123/callback/STATE1",
    state: "STATE1",
    client: "desktop",
    workspace_selection: "desktop",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
  });
  return `/cloud/api/v1/cli/login?${params}`;
}

for (const site of [DASHBOARD_SITE, API_SITE]) {
  test(`a Desktop signing in through ${site} gets api_url ${site}/cloud (browser flow)`, async (t) => {
    const { origin, ownerId, workspaceId } = await setup(t);
    const host = new URL(site).host;
    const session = await browserSession(origin, host, ownerId, workspaceId);
    const handoff = await raw(origin, loginPath(), { host, cookie: session });
    assert.equal(handoff.status, 307);
    const callback = new URL(String(handoff.headers.location));
    assert.equal(callback.searchParams.get("state"), "STATE1");
    assert.equal(callback.searchParams.get("api_url"), `${site}/cloud`);

    const exchanged = await raw(origin, "/cloud/api/v1/auth/desktop/session", {
      host,
      method: "POST",
      token: callback.searchParams.get("access_token")!,
      body: { codeVerifier: VERIFIER },
    });
    assert.equal(exchanged.status, 200);
    assert.equal(exchanged.body.apiUrl, `${site}/cloud`);

    const refreshed = await raw(origin, "/cloud/api/v1/auth/token/refresh", {
      host,
      method: "POST",
      body: { refreshToken: exchanged.body.refreshToken },
    });
    assert.equal(refreshed.status, 200);
    assert.equal(refreshed.body.apiUrl, `${site}/cloud`);
  });

  test(`a Desktop signing in through ${site} gets verification_uri and api_url on ${site} (device flow)`, async (t) => {
    const { origin, ownerId, workspaceId } = await setup(t);
    const host = new URL(site).host;
    const started = await raw(origin, "/cloud/api/v1/auth/device/start", {
      host,
      method: "POST",
      body: { client_name: "Agent Relay Desktop" },
    });
    assert.equal(started.status, 201);
    assert.equal(started.body.verification_uri, `${site}/cloud/api/v1/auth/device/approve`);
    assert(String(started.body.verification_uri_complete).startsWith(`${site}/cloud/api/v1/auth/device/approve?user_code=`));
    await approve(origin, started.body.user_code, ownerId, workspaceId);
    const tokens = await raw(origin, "/cloud/api/v1/auth/device/token", {
      host,
      method: "POST",
      body: { device_code: started.body.device_code },
    });
    assert.equal(tokens.status, 200);
    assert.equal(tokens.body.api_url, `${site}/cloud`);
  });
}

test("an unconfigured Host header falls back to SELFHOST_PUBLIC_URL, never the Host", async (t) => {
  const { origin, ownerId, workspaceId } = await setup(t);
  const started = await raw(origin, "/cloud/api/v1/auth/device/start", {
    host: "evil.example",
    method: "POST",
    body: { client_name: "Agent Relay Desktop" },
  });
  assert.equal(started.status, 201);
  assert.equal(started.body.verification_uri, `${API_SITE}/cloud/api/v1/auth/device/approve`);
  await approve(origin, started.body.user_code, ownerId, workspaceId);
  const tokens = await raw(origin, "/cloud/api/v1/auth/device/token", {
    host: "evil.example",
    method: "POST",
    body: { device_code: started.body.device_code },
  });
  assert.equal(tokens.status, 200);
  assert.equal(tokens.body.api_url, `${API_SITE}/cloud`);
  assert(!tokens.text.includes("evil.example"));
});
