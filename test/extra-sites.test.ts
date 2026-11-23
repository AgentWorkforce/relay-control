import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import test from "node:test";
import { browserOriginsFor, createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase } from "./support/harness.js";

// SELFHOST_EXTRA_SITES: a second public host set (its own dashboard and API
// hosts) in front of the same deployment. Browser origin checks accept it and
// Host-selected answers name the site the request arrived on; unknown hosts
// still fall back to SELFHOST_PUBLIC_URL.

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const API_SITE = "https://api.primary.example.com";
const DASHBOARD_SITE = "https://app.primary.example.com";
const EXTRA_API = "https://api.public.example.com";
const EXTRA_DASHBOARD = "https://app.public.example.com";
const EXTRA = { extraSites: [{ dashboardOrigin: EXTRA_DASHBOARD, apiOrigin: EXTRA_API }] };

type Raw = { status: number; headers: Record<string, string | string[] | undefined>; body: any; text: string };

/** An HTTP request with an explicit Host header (fetch cannot set one). */
function raw(
  origin: string,
  path: string,
  options: {
    host: string;
    method?: string;
    token?: string;
    cookie?: string;
    body?: unknown;
    headers?: Record<string, string | string[]>;
  },
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
        ...options.headers,
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

function baseConfig(overrides: Partial<SelfhostConfig> = {}): SelfhostConfig {
  return {
    databaseUrl: "unused",
    publicBaseUrl: API_SITE,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://cast.primary.example.com",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.primary.example.com",
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: "https://history.primary.example.com", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: `${API_SITE}/api/v1/integrations/oauth/callback`,
    // A dashboard path, so the extra-site redirect is seen to keep it.
    dashboardUrl: `${DASHBOARD_SITE}/app/`,
    port: 0,
    host: "127.0.0.1",
    ...overrides,
  };
}

async function setup(t: test.TestContext, overrides: Partial<SelfhostConfig> = {}) {
  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const store = new ControlPlaneStore(database, KEYRING, 0);
  control.on("request", createApp({ config: baseConfig(overrides), store }));
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
  return {
    origin,
    database,
    store,
    organizationId: org.body.id as string,
    ownerId: org.body.owner.id as string,
    workspaceId: workspace.body.id as string,
  };
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

test("browserOriginsFor lists the primary origins first, then each extra site's, deduplicated", () => {
  assert.deepEqual(browserOriginsFor(baseConfig()), [API_SITE, DASHBOARD_SITE]);
  assert.deepEqual(browserOriginsFor(baseConfig({
    extraSites: [
      { dashboardOrigin: EXTRA_DASHBOARD, apiOrigin: EXTRA_API },
      { dashboardOrigin: "https://one.public.example.com", apiOrigin: "https://one.public.example.com" },
    ],
  })), [API_SITE, DASHBOARD_SITE, EXTRA_DASHBOARD, EXTRA_API, "https://one.public.example.com"]);
});

test("a cookie-authenticated write from an extra dashboard origin is allowed, an unconfigured origin is refused", async (t) => {
  for (const configured of [true, false]) {
    const env = await setup(t, configured ? EXTRA : {});
    const issued = await env.database.transaction((tx) => env.store.issueBrowserSession(tx, {
      userId: env.ownerId, organizationId: env.organizationId, workspaceId: env.workspaceId, label: "browser",
    }));
    const cookie = `agent_relay_session=${issued.accessToken}`;
    const host = new URL(EXTRA_DASHBOARD).host;
    const evil = await raw(env.origin, "/cloud/api/auth/workspace", {
      host, method: "POST", cookie, headers: { origin: "https://evil.example.com" }, body: { workspaceId: env.workspaceId },
    });
    assert.equal(evil.status, 403);
    assert.equal(evil.body.error, "csrf_rejected");
    const extra = await raw(env.origin, "/cloud/api/auth/workspace", {
      host, method: "POST", cookie, headers: { origin: EXTRA_DASHBOARD }, body: { workspaceId: env.workspaceId },
    });
    if (configured) {
      assert.equal(extra.status, 200, extra.text);
      assert.equal(extra.body.currentWorkspace.id, env.workspaceId);
    } else {
      assert.equal(extra.status, 403, "unset: the extra origin is not allowed");
      assert.equal(extra.body.error, "csrf_rejected");
    }
  }
});

for (const site of [EXTRA_API, EXTRA_DASHBOARD]) {
  test(`a Desktop signing in through extra site host ${site} gets verification_uri and api_url on ${site}`, async (t) => {
    const { origin, ownerId, workspaceId } = await setup(t, EXTRA);
    const host = new URL(site).host;
    const started = await raw(origin, "/cloud/api/v1/auth/device/start", {
      host,
      method: "POST",
      body: { client_name: "Agent Relay Desktop" },
    });
    assert.equal(started.status, 201);
    assert.equal(started.body.verification_uri, `${site}/cloud/api/v1/auth/device/approve`);
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

test("with extra sites configured, an unknown Host still falls back to SELFHOST_PUBLIC_URL", async (t) => {
  const { origin, ownerId, workspaceId } = await setup(t, EXTRA);
  const started = await raw(origin, "/cloud/api/v1/auth/device/start", {
    host: "evil.example.com",
    method: "POST",
    body: { client_name: "Agent Relay Desktop" },
  });
  assert.equal(started.status, 201);
  assert.equal(started.body.verification_uri, `${API_SITE}/cloud/api/v1/auth/device/approve`);
  await approve(origin, started.body.user_code, ownerId, workspaceId);
  const tokens = await raw(origin, "/cloud/api/v1/auth/device/token", {
    host: "evil.example.com",
    method: "POST",
    body: { device_code: started.body.device_code },
  });
  assert.equal(tokens.status, 200);
  assert.equal(tokens.body.api_url, `${API_SITE}/cloud`);
  assert(!tokens.text.includes("evil.example.com"));
});

test("device approve GET redirects to the dashboard of the site the request arrived on", async (t) => {
  const { origin } = await setup(t, EXTRA);
  for (const [site, dashboard] of [
    [EXTRA_API, EXTRA_DASHBOARD],
    [EXTRA_DASHBOARD, EXTRA_DASHBOARD],
    [API_SITE, DASHBOARD_SITE],
    [DASHBOARD_SITE, DASHBOARD_SITE],
    ["https://evil.example.com", DASHBOARD_SITE],
  ] as const) {
    const redirect = await raw(origin, "/cloud/api/v1/auth/device/approve?user_code=BCDF-GHJK", { host: new URL(site).host });
    assert.equal(redirect.status, 303, site);
    const location = String(redirect.headers.location);
    assert(location.startsWith(`${dashboard}/app/#/device?user_code=`), `${site}: ${location}`);
  }
});

test("Desktop dashboard links open the dashboard of the site the request arrived on", async (t) => {
  const { origin } = await setup(t, EXTRA);
  for (const [site, dashboard] of [
    [EXTRA_API, EXTRA_DASHBOARD],
    [API_SITE, DASHBOARD_SITE],
    ["https://evil.example.com", DASHBOARD_SITE],
  ] as const) {
    const redirect = await raw(origin, "/cloud/dashboard/sessions/s-1", { host: new URL(site).host });
    assert.equal(redirect.status, 302, site);
    assert.equal(redirect.headers.location, `${dashboard}/app/?session=s-1`, site);
  }
  // Already on a dashboard host (primary or extra): nothing is redirected.
  for (const site of [EXTRA_DASHBOARD, DASHBOARD_SITE]) {
    const kept = await raw(origin, "/cloud/dashboard/sessions/s-1", { host: new URL(site).host });
    assert.notEqual(kept.status, 302, site);
  }
});
