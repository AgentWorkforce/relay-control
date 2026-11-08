import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import {
  deviceApprovalPageUrl,
  RateLimiter,
  safeNextPath,
  sanitizeDesktopHostName,
} from "../src/auth/device-approval.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const DASHBOARD = "https://dashboard.selfhosted.test/";
const DASHBOARD_ORIGIN = "https://dashboard.selfhosted.test";

async function setup(t: test.TestContext) {
  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseSchema: "public",
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayauthUrl: "http://relayauth.invalid",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.test",
    relayauthApiKey: "rak_test",
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: DASHBOARD,
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  control.on("request", createApp({ config, store }));
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
  const workspace = await request(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Primary", relaycastApiKey: "rk_primary" },
  });
  assert.equal(workspace.status, 201);
  const other = await request(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Other", relaycastApiKey: "rk_other" },
  });
  assert.equal(other.status, 201);
  return {
    origin,
    database,
    ownerId: org.body.owner.id as string,
    workspaceId: workspace.body.id as string,
    otherWorkspaceId: other.body.id as string,
  };
}

/** Signs a browser in through /login, approved by the bootstrap bearer. */
async function browserSession(
  origin: string,
  ownerId: string,
  workspaceId: string,
): Promise<string> {
  const login = await fetch(`${origin}/login`);
  const code = (await login.text()).match(/<code>([A-Z0-9]{4}-[A-Z0-9]{4})<\/code>/)?.[1];
  assert(code);
  const deviceCookie = login.headers.get("set-cookie")!.split(";")[0]!;
  const approved = await request(origin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: BOOTSTRAP,
    body: { action: "approve", user_code: code, user_id: ownerId, workspace_id: workspaceId },
  });
  assert.equal(approved.status, 200);
  const poll = await request(origin, "/login/poll", { method: "POST", cookie: deviceCookie });
  assert.equal(poll.status, 200);
  const session = poll.headers.get("set-cookie")?.match(/agent_relay_session=[^;]+/)?.[0];
  assert(session);
  return session;
}

/** A dashboard fetch: JSON body, session cookie, browser Origin header. */
async function browserPost(
  origin: string,
  path: string,
  options: {
    cookie: string;
    body: unknown;
    origin?: string | null;
    secFetchSite?: string;
    contentType?: string;
  },
) {
  const headers: Record<string, string> = {
    cookie: options.cookie,
    "content-type": options.contentType ?? "application/json",
  };
  if (options.origin !== null) headers.origin = options.origin ?? DASHBOARD_ORIGIN;
  if (options.secFetchSite) headers["sec-fetch-site"] = options.secFetchSite;
  const response = await fetch(`${origin}${path}`, {
    method: "POST",
    headers,
    body: options.contentType === "application/x-www-form-urlencoded"
      ? new URLSearchParams(options.body as Record<string, string>).toString()
      : JSON.stringify(options.body),
  });
  const raw = await response.text();
  return {
    status: response.status,
    headers: response.headers,
    body: (raw ? JSON.parse(raw) : {}) as Record<string, any>,
  };
}

const APPROVE = "/cloud/api/v1/auth/device/approve";

test("a Desktop device sign-in is approved from the dashboard and returns hosted Cloud's token shape", async (t) => {
  const { origin, ownerId, workspaceId, otherWorkspaceId } = await setup(t);

  // Desktop starts the flow (cloud_login.rs device_start_body).
  const started = await request(origin, "/cloud/api/v1/auth/device/start", {
    method: "POST",
    body: {
      client_name: "Agent Relay for macOS",
      desktop_code_challenge: "x".repeat(43),
      desktop_code_challenge_method: "S256",
      desktop_host_name: "studio\nmini",
    },
  });
  assert.equal(started.status, 201);
  assert.equal(started.headers.get("cache-control"), "no-store");
  const userCode = started.body.user_code as string;
  assert.match(userCode, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
  assert.equal(started.body.verification_uri, `${origin}/cloud/api/v1/auth/device/approve`);
  assert.equal(
    started.body.verification_uri_complete,
    `${origin}/cloud/api/v1/auth/device/approve?user_code=${encodeURIComponent(userCode)}`,
  );
  assert.equal(new URL(started.body.verification_uri).origin, origin, "Desktop requires the site origin");
  assert.equal(typeof started.body.expires_in, "number");
  assert.equal(typeof started.body.interval, "number");

  // Opening verification_uri(_complete) lands on the dashboard approval route.
  const opened = await request(origin, new URL(started.body.verification_uri_complete).pathname +
    new URL(started.body.verification_uri_complete).search);
  assert.equal(opened.status, 303);
  assert.equal(
    opened.headers.get("location"),
    `${DASHBOARD}#/device?user_code=${encodeURIComponent(userCode)}`,
  );
  assert.equal(opened.headers.get("cache-control"), "no-store");
  const bare = await request(origin, "/api/v1/auth/device/approve");
  assert.equal(bare.status, 303);
  assert.equal(bare.headers.get("location"), `${DASHBOARD}#/device`);
  const junk = await request(origin, "/cloud/api/v1/auth/device/approve?user_code=%3Cscript%3E");
  assert.equal(junk.headers.get("location"), `${DASHBOARD}#/device`, "an invalid code is dropped");

  const cookie = await browserSession(origin, ownerId, workspaceId);

  // CSRF: cookie-authenticated decisions must be JSON from the dashboard/API origin.
  for (const attempt of [
    { origin: null },
    { origin: "https://evil.example" },
    { origin: "null" },
    { origin: null, secFetchSite: "same-site" },
    { contentType: "application/x-www-form-urlencoded" },
    { contentType: "text/plain" },
  ]) {
    const refused = await browserPost(origin, APPROVE, {
      cookie,
      body: { action: "approve", user_code: userCode },
      ...attempt,
    });
    assert.equal(refused.status, 403, JSON.stringify(attempt));
    assert.equal(refused.body.error, "csrf_rejected");
  }
  const sameOrigin = await browserPost(origin, APPROVE, {
    cookie,
    origin: null,
    secFetchSite: "same-origin",
    body: { action: "lookup", user_code: userCode },
  });
  assert.equal(sameOrigin.status, 200, "a same-origin fetch without Origin is accepted");
  const apiOrigin = await browserPost(origin, APPROVE, {
    cookie,
    origin,
    body: { action: "lookup", user_code: userCode },
  });
  assert.equal(apiOrigin.status, 200, "the API's own origin is accepted");
  assert.equal((await browserPost(origin, "/api/v1/auth/device/approve", {
    cookie,
    body: { action: "lookup", user_code: userCode },
  })).status, 401, "the cookie is honoured only under /cloud");

  // Lookup names the client, the machine and the target workspace, never the device code.
  const lookup = await browserPost(origin, APPROVE, {
    cookie,
    body: { action: "lookup", user_code: userCode.toLowerCase().replace("-", "") },
  });
  assert.equal(lookup.status, 200);
  assert.equal(lookup.headers.get("cache-control"), "no-store");
  assert.deepEqual(lookup.body, {
    user_code: userCode,
    client_name: "Agent Relay for macOS",
    desktop_host_name: "studio mini",
    status: "pending",
    expires_at: lookup.body.expires_at,
    current_workspace_id: workspaceId,
    // The browser account session lists every member workspace (DG-001).
    workspaces: [
      { id: workspaceId, name: "Primary", organization_name: "Acme" },
      { id: otherWorkspaceId, name: "Other", organization_name: "Acme" },
    ],
  });
  assert.doesNotMatch(JSON.stringify(lookup.body), /sh_dc_/);
  const missing = await browserPost(origin, APPROVE, {
    cookie,
    body: { action: "lookup", user_code: "ZZZZ-ZZZZ" },
  });
  assert.equal(missing.status, 404);

  const pending = await request(origin, "/cloud/api/v1/auth/device/token", {
    method: "POST",
    body: {
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: started.body.device_code,
      desktop_code_verifier: "verifier",
    },
  });
  assert.equal(pending.status, 400);
  assert.equal(pending.body.error, "authorization_pending");
  assert.match(pending.body.error_description, /keep polling/);

  const wrongWorkspace = await browserPost(origin, APPROVE, {
    cookie,
    body: { action: "approve", user_code: userCode, workspace_id: "00000000-0000-4000-8000-000000000000" },
  });
  assert.equal(wrongWorkspace.status, 404, "a session approves only for a workspace it is a member of");

  const approved = await browserPost(origin, APPROVE, {
    cookie,
    body: { action: "approve", user_code: userCode },
  });
  assert.equal(approved.status, 200);
  assert.deepEqual(approved.body, { status: "approved" });
  const again = await browserPost(origin, APPROVE, {
    cookie,
    body: { action: "deny", user_code: userCode },
  });
  assert.equal(again.status, 409);

  // Every field Desktop (relay cloud_login.rs poll) and the CLI read.
  const issued = await request(origin, "/cloud/api/v1/auth/device/token", {
    method: "POST",
    body: {
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: started.body.device_code,
    },
  });
  assert.equal(issued.status, 200);
  assert.equal(issued.headers.get("cache-control"), "no-store");
  assert.equal(issued.body.api_url, `${origin}/cloud`);
  assert.equal(issued.body.token_type, "Bearer");
  assert.match(issued.body.access_token, /^sh_at_/);
  assert.match(issued.body.refresh_token, /^sh_rt_/);
  assert(Date.parse(issued.body.access_token_expires_at) > Date.now());
  assert(Date.parse(issued.body.refresh_token_expires_at) > Date.now());
  assert.equal(issued.body.scope, "cli:auth rth:read rth:sync rth:acquire");
  const consumed = await browserPost(origin, APPROVE, {
    cookie,
    body: { action: "lookup", user_code: userCode },
  });
  assert.equal(consumed.body.status, "consumed");

  const whoami = await request(origin, "/cloud/api/v1/auth/whoami", { token: issued.body.access_token });
  assert.equal(whoami.status, 200);
  assert.equal(whoami.body.currentWorkspace.id, workspaceId);

  const refreshed = await request(origin, "/cloud/api/v1/auth/token/refresh", {
    method: "POST",
    body: { refreshToken: issued.body.refresh_token },
  });
  assert.equal(refreshed.status, 200);
  assert.equal(refreshed.body.apiUrl, `${origin}/cloud`);
  assert.equal(refreshed.body.tokenType, "Bearer");
  for (const field of ["accessToken", "accessTokenExpiresAt", "refreshToken", "refreshTokenExpiresAt"]) {
    assert.equal(typeof refreshed.body[field], "string", field);
  }

  // Deny: no credentials; the device sees access_denied.
  const second = await request(origin, "/api/v1/auth/device/start", {
    method: "POST",
    body: { client_name: "Agent Relay for Linux" },
  });
  const denied = await browserPost(origin, APPROVE, {
    cookie,
    body: { action: "deny", user_code: second.body.user_code },
  });
  assert.equal(denied.status, 200);
  assert.deepEqual(denied.body, { status: "denied" });
  const refused = await request(origin, "/api/v1/auth/device/token", {
    method: "POST",
    body: { device_code: second.body.device_code },
  });
  assert.equal(refused.status, 400);
  assert.equal(refused.body.error, "access_denied");
  const deniedLookup = await browserPost(origin, APPROVE, {
    cookie,
    body: { action: "lookup", user_code: second.body.user_code },
  });
  assert.equal(deniedLookup.body.status, "denied");
  assert.equal(deniedLookup.body.desktop_host_name, null);

  // A bearer client (CLI, bootstrap) needs no Origin and keeps workspace_id required.
  const third = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: {} });
  const bootstrapLookup = await request(origin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: BOOTSTRAP,
    body: { action: "lookup", user_code: third.body.user_code },
  });
  assert.equal(bootstrapLookup.status, 200);
  assert.deepEqual(bootstrapLookup.body.workspaces, []);
  const bootstrapMissingWorkspace = await request(origin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: BOOTSTRAP,
    body: { action: "approve", user_code: third.body.user_code, user_id: ownerId },
  });
  assert.equal(bootstrapMissingWorkspace.status, 400);
});

test("/login returns to a safe same-origin next path after sign-in", async (t) => {
  const { origin } = await setup(t);
  const next = "/#/device?user_code=ABCD-EFGH";
  const page = await (await fetch(`${origin}/login?next=${encodeURIComponent(next)}`)).text();
  assert(page.includes(`const next=${JSON.stringify(next)};`));
  for (const unsafe of ["https://evil.example/", "//evil.example/x", "/\\evil.example", "javascript:alert(1)"]) {
    const html = await (await fetch(`${origin}/login?next=${encodeURIComponent(unsafe)}`)).text();
    assert(html.includes('const next="/";'), unsafe);
  }
  const escaped = await (await fetch(`${origin}/login?next=${encodeURIComponent("/</script><script>x")}`)).text();
  assert.doesNotMatch(escaped, /<\/script><script>x/);
});

test("device routes apply hosted Cloud's rate limits", async (t) => {
  const { origin, ownerId, workspaceId } = await setup(t);
  for (let index = 0; index < 10; index += 1) {
    const started = await request(origin, "/api/v1/auth/device/start", {
      method: "POST",
      body: {},
    });
    assert.equal(started.status, 201, `start ${index}`);
  }
  const limited = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: {} });
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error, "slow_down");
  assert(Number(limited.headers.get("retry-after")) > 0);
  const otherClient = await fetch(`${origin}/api/v1/auth/device/start`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": "203.0.113.9" },
    body: "{}",
  });
  assert.equal(otherClient.status, 201, "limits are per client address");

  const cookie = await browserSession(origin, ownerId, workspaceId);
  let last = 0;
  for (let index = 0; index < 31; index += 1) {
    last = (await browserPost(origin, APPROVE, {
      cookie,
      body: { action: "lookup", user_code: "ZZZZ-ZZZZ" },
    })).status;
  }
  assert.equal(last, 429, "approvals are limited per approver");

  for (let index = 0; index < 120; index += 1) {
    await request(origin, "/api/v1/auth/device/token", {
      method: "POST",
      body: { device_code: "sh_dc_unknown" },
    });
  }
  const tokenLimited = await request(origin, "/api/v1/auth/device/token", {
    method: "POST",
    body: { device_code: "sh_dc_unknown" },
  });
  assert.equal(tokenLimited.status, 429);
});

test("device approval helpers", () => {
  assert.equal(
    deviceApprovalPageUrl("https://dash.test/app/?x=1", "bcdf ghjk"),
    "https://dash.test/app/#/device?user_code=BCDF-GHJK",
  );
  assert.equal(deviceApprovalPageUrl("https://dash.test/", null), "https://dash.test/#/device");
  assert.equal(safeNextPath("/settings?a=1#/x"), "/settings?a=1#/x");
  assert.equal(safeNextPath(null), "/");
  assert.equal(safeNextPath("relative"), "/");
  assert.equal(safeNextPath("/a\u0000b"), "/");
  assert.equal(sanitizeDesktopHostName("  mini\tbox "), "mini box");
  assert.equal(sanitizeDesktopHostName("x".repeat(81)), null);
  assert.equal(sanitizeDesktopHostName(42), null);
  let now = 0;
  const limiter = new RateLimiter(() => now);
  assert(limiter.consume("k", 2, 1_000).allowed);
  assert(limiter.consume("k", 2, 1_000).allowed);
  const blocked = limiter.consume("k", 2, 1_000);
  assert(!blocked.allowed);
  assert.equal(blocked.retryAfterSeconds, 1);
  now = 1_001;
  assert(limiter.consume("k", 2, 1_000).allowed, "the window slides");
});
