import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, verify } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import { createAdminModule } from "../src/admin/routes.js";
import { ConnectionError, ConnectionStore, type FetchLike } from "../src/admin/connections.js";
import { GithubAppTokenError, mintGithubInstallationToken } from "../src/admin/github-app.js";
import { catalogEntry, GITHUB_APP_PROVIDER, ProviderRegistry } from "../src/admin/providers.js";
import { loadGithubAppConfig, type SelfhostConfig } from "../src/config.js";
import { decryptSecret, encryptSecret } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const app = { appId: "12345", privateKey: keys.privateKey };
const keyring = { active: { id: "test", key: Buffer.alloc(32, 7) } };
const actor = { kind: "service", subject: "cloud-import-test" } as const;
const json = (body: unknown, status = 201, headers = {}) => new Response(JSON.stringify(body), { status, headers });
const tokenBody = (token: string) => ({ token, expires_at: new Date(Date.now() + 3_600_000).toISOString() });

function testConfig(): SelfhostConfig {
  return {
    databaseUrl: "unused", publicBaseUrl: "https://control.test",
    relaycastUrl: "https://cast.test", relaycastPublicUrl: "https://cast.test",
    relayhistoryUrl: "https://history.test", relayhistoryPublicUrl: "https://history.test",
    sessionReadApi: { url: "https://history.test", publicUrl: "https://history.test", secret: "test-secret".repeat(4) },
    bootstrapToken: "bootstrap-test-secret".repeat(3), encryptionKeyring: keyring,
    oauthRedirectUrl: "https://control.test/callback", dashboardUrl: "https://control.test/",
    internalServiceToken: "internal-test-secret".repeat(3),
    githubApp: loadGithubAppConfig({ SELFHOST_GITHUB_APP_ID: app.appId, SELFHOST_GITHUB_APP_PRIVATE_KEY: pem }),
    port: 0, host: "127.0.0.1",
  };
}

async function seedWorkspace(db: PGliteDatabase, organizationId: string): Promise<string> {
  const id = randomUUID();
  await db.query(`INSERT INTO workspaces (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
    VALUES ($1, $2, 'Test', $4, $3)`, [id, organizationId, encryptSecret("test-cast", keyring.active), id]);
  return id;
}

test("GitHub App config uses the existing mounted secret pattern and rejects invalid keys without echoing them", (t) => {
  assert.equal(loadGithubAppConfig({}), null);
  const dir = mkdtempSync(join(tmpdir(), "github-app-test-"));
  t.after(() => rmSync(dir, { recursive: true }));
  const file = join(dir, "test-key.pem");
  writeFileSync(file, pem, { mode: 0o600 });
  assert.equal(loadGithubAppConfig({ SELFHOST_GITHUB_APP_ID: "12345", SELFHOST_GITHUB_APP_PRIVATE_KEY_FILE: file })!.appId, "12345");
  assert.equal(loadGithubAppConfig({ SELFHOST_GITHUB_APP_ID: "12345", SELFHOST_GITHUB_APP_PRIVATE_KEY: pem })!.privateKey.asymmetricKeyType, "rsa");
  assert.throws(() => loadGithubAppConfig({ SELFHOST_GITHUB_APP_ID: "12345" }), /required together/);
  assert.throws(() => loadGithubAppConfig({ SELFHOST_GITHUB_APP_PRIVATE_KEY: pem }), /required together/);
  assert.throws(() => loadGithubAppConfig({ SELFHOST_GITHUB_APP_ID: "12345", SELFHOST_GITHUB_APP_PRIVATE_KEY: "do-not-echo" }), error =>
    error instanceof Error && !error.message.includes("do-not-echo"));
  assert.throws(() => loadGithubAppConfig({ SELFHOST_GITHUB_APP_ID: "12345", SELFHOST_GITHUB_APP_PRIVATE_KEY: pem, SELFHOST_GITHUB_APP_PRIVATE_KEY_FILE: file }), /mutually exclusive/);
  const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  assert.throws(() => loadGithubAppConfig({ SELFHOST_GITHUB_APP_ID: "12345", SELFHOST_GITHUB_APP_PRIVATE_KEY: ec }), /RSA private key/);
  assert.equal(catalogEntry(GITHUB_APP_PROVIDER).authMode, "APP");
});

test("installation mint signs a valid RS256 App JWT, pins GitHub and refuses redirects", async () => {
  const result = await mintGithubInstallationToken(app, "98765", async (url, init) => {
    assert.equal(url, "https://api.github.com/app/installations/98765/access_tokens");
    assert.equal(init.method, "POST");
    assert.equal(init.redirect, "error");
    assert.ok(init.signal);
    assert.equal(init.body, "{}");
    const jwt = new Headers(init.headers).get("authorization")!.slice(7);
    const [header, payload, signature] = jwt.split(".") as [string, string, string];
    assert.deepEqual(JSON.parse(Buffer.from(header, "base64url").toString()), { alg: "RS256", typ: "JWT" });
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString());
    assert.equal(claims.iss, app.appId);
    const now = Math.floor(Date.now() / 1000);
    assert.ok(Math.abs(claims.iat - (now - 60)) <= 1);
    assert.ok(claims.exp > now && claims.exp <= now + 600);
    assert.ok(verify("RSA-SHA256", Buffer.from(`${header}.${payload}`), keys.publicKey, Buffer.from(signature, "base64url")));
    return json(tokenBody("ghs_installation-token"));
  });
  assert.equal(result.accessToken, "ghs_installation-token");
});

test("installation expiry tolerates GitHub clock skew and bounds the local cache lifetime", async (t) => {
  const now = Date.parse("2026-11-16T12:00:00Z");
  t.mock.method(Date, "now", () => now);
  for (const lifetime of [3_720_000, 86_400_000]) {
    const result = await mintGithubInstallationToken(app, "41", async () => json({
      token: "ghs_skew-test", expires_at: new Date(now + lifetime).toISOString(),
    }));
    assert.equal(result.expiresAt.getTime(), now + 3_600_000);
  }
  const shorter = await mintGithubInstallationToken(app, "41", async () => json({
    token: "ghs_short-test", expires_at: new Date(now + 1_800_000).toISOString(),
  }));
  assert.equal(shorter.expiresAt.getTime(), now + 1_800_000, "never extend GitHub's advertised expiry");
  await assert.rejects(mintGithubInstallationToken(app, "41", async () => json({
    token: "ghs_near-expiry", expires_at: new Date(now + 120_000).toISOString(),
  })), /invalid_token_response/);
});

test("mint errors expose only fixed codes and classify retryable failures", async () => {
  for (const [status, expected] of [[401, 409], [403, 409], [404, 409], [422, 409], [429, 503], [500, 503], [302, 503]]) {
    await assert.rejects(mintGithubInstallationToken(app, "41", async () => json({ message: "echoed-private-key-or-jwt" }, status)), error =>
      error instanceof GithubAppTokenError && error.status === expected && !error.message.includes("echoed"));
  }
  await assert.rejects(mintGithubInstallationToken(app, "41", async () => json({}, 403, { "x-ratelimit-remaining": "0" })), error =>
    error instanceof GithubAppTokenError && error.status === 503);
  await assert.rejects(mintGithubInstallationToken(app, "41", async () => { throw new Error(pem); }), error =>
    error instanceof GithubAppTokenError && !error.message.includes("PRIVATE KEY"));
  for (const body of [{}, null, { token: "secret", expires_at: "bad" }, { token: "secret", expires_at: new Date(0).toISOString() }]) {
    await assert.rejects(mintGithubInstallationToken(app, "41", async () => json(body)), /invalid_token_response/);
  }
  await assert.rejects(mintGithubInstallationToken(app, "41", async () => new Response("not-json", { status: 201 })), /invalid_token_response/);
  await assert.rejects(mintGithubInstallationToken(app, "../41", async () => { assert.fail("invalid id made a network request"); }), /invalid_installation_id/);
});

test("imported workspace installation mints, caches, refreshes and fails closed through ConnectionStore", async (t) => {
  const db = new PGliteDatabase();
  t.after(() => db.close());
  await migrate(db);
  let transactionDepth = 0;
  const transaction = db.transaction.bind(db);
  db.transaction = run => transaction(async tx => {
    transactionDepth++;
    try { return await run(tx); } finally { transactionDepth--; }
  });
  const organizationId = randomUUID(), workspaceId = randomUUID(), otherWorkspaceId = randomUUID();
  await db.query("INSERT INTO organizations (id, name) VALUES ($1, 'Test')", [organizationId]);
  for (const id of [workspaceId, otherWorkspaceId]) {
    await db.query(`INSERT INTO workspaces (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
      VALUES ($1, $2, 'Test', $4, $3)`, [id, organizationId, encryptSecret("test-cast", keyring.active), id]);
  }
  let calls = 0, failure = false;
  const fetchImpl: FetchLike = async (url) => {
    assert.equal(transactionDepth, 0, "GitHub mint never holds a database transaction open");
    calls++;
    assert.equal(url, "https://api.github.com/app/installations/98765/access_tokens");
    return failure ? json({ message: pem }, 404) : json(tokenBody(`ghs_test-${calls}`));
  };
  const registry = new ProviderRegistry();
  const store = new ConnectionStore(db, keyring, registry, "https://control.test/callback", fetchImpl, {}, app);
  const read = (forceRefresh = false) => store.runtimeToken({ workspaceId, provider: "github-relay", actor, forceRefresh });
  const imported = await store.importGithubAppConnection({ workspaceId, organizationId, installationId: "98765", actor });
  assert.equal(imported.authMode, "github_app");
  assert.equal(imported.installationId, "98765");
  assert.equal(imported.refreshable, true);
  assert.equal(calls, 0, "import needs no Nango token or GitHub call");
  assert.equal((await read()).accessToken, "ghs_test-1");
  assert.equal((await read()).accessToken, "ghs_test-1");
  assert.equal(calls, 1, "unexpired token is reused");
  await Promise.all(Array.from({ length: 6 }, () => read()));
  assert.equal(calls, 1, "concurrent cache readers do not mint");
  const encrypted = (await db.query<{ credentials_ciphertext: string }>("SELECT credentials_ciphertext FROM integration_connections WHERE workspace_id = $1", [workspaceId])).rows[0]!.credentials_ciphertext;
  assert.ok(!encrypted.includes("ghs_test"));
  assert.deepEqual(JSON.parse(decryptSecret(encrypted, keyring)), { accessToken: "ghs_test-1" });
  const restarted = new ConnectionStore(db, keyring, registry, "https://control.test/callback", fetchImpl, {}, app);
  assert.equal((await restarted.runtimeToken({ workspaceId, provider: "github", actor })).accessToken, "ghs_test-1");
  assert.equal(calls, 1, "cache survives a process restart");
  await db.query("UPDATE integration_connections SET access_token_expires_at = now() + interval '30 seconds' WHERE workspace_id = $1", [workspaceId]);
  const refreshed = await Promise.all(Array.from({ length: 6 }, () => read()));
  assert.ok(refreshed.every(token => ["ghs_test-1", "ghs_test-2"].includes(token.accessToken)));
  assert.equal(calls, 2, "concurrent stale readers share one mint lease and may reuse the still-valid cache");
  assert.equal((await read(true)).accessToken, "ghs_test-3");
  await assert.rejects(store.runtimeToken({ workspaceId: otherWorkspaceId, provider: "github", actor }), error =>
    error instanceof ConnectionError && error.code === "connection_not_found");
  const unconfigured = new ConnectionStore(db, keyring, registry, "https://control.test/callback", fetchImpl);
  await assert.rejects(unconfigured.runtimeToken({ workspaceId, provider: "github", actor }), error =>
    error instanceof ConnectionError && error.code === "github_app_not_configured");
  failure = true;
  await assert.rejects(read(true), error => error instanceof ConnectionError && error.status === 409 && !error.message.includes("PRIVATE KEY"));
  const failed = (await store.list(workspaceId))[0]!;
  assert.equal(failed.status, "error");
  assert.equal(failed.lastError, "github_http_404");
  failure = false;
  // Configuring App mode must not change a preexisting OAuth user connection's refresh protocol.
  await db.query(`INSERT INTO integration_connections
    (id, workspace_id, provider, auth_mode, status, credentials_ciphertext, access_token_expires_at)
    VALUES ($1, $2, 'github', 'oauth2', 'ready', $3, now() - interval '1 hour')`,
    [randomUUID(), otherWorkspaceId, encryptSecret(JSON.stringify({ accessToken: "old-oauth", refreshToken: "oauth-refresh" }), keyring.active)]);
  const legacy = new ConnectionStore(db, keyring, new ProviderRegistry(), "https://control.test/callback",
    async (url, init) => {
      assert.equal(url, "https://github.com/login/oauth/access_token");
      const body = new URLSearchParams(String(init.body));
      assert.equal(body.get("refresh_token"), "oauth-refresh");
      assert.equal(body.get("grant_type"), "refresh_token");
      return json({ access_token: "refreshed-oauth", expires_in: 3600 });
    }, { github: { clientId: "legacy-client", clientSecret: "legacy-secret", scopes: null } }, app);
  const oauth = await legacy.runtimeToken({ workspaceId: otherWorkspaceId, provider: "github", actor });
  assert.equal(oauth.authMode, "oauth2");
  assert.equal(oauth.accessToken, "refreshed-oauth");
  assert.equal((await read()).accessToken, "ghs_test-5", "a later mint recovers without reconnect");
  const publicState = JSON.stringify({ list: await store.list(workspaceId), audit: (await db.query("SELECT * FROM admin_audit_events")).rows });
  assert.ok(!publicState.includes("ghs_test") && !publicState.includes("PRIVATE KEY"));
  const config = testConfig();
  const admin = createAdminModule({ config, database: db, keyring, fetchImpl });
  assert.equal(admin.providers.get("github")!.authMode, "oauth2");
  assert.equal(admin.connections.operatorConfigured("github"), false, "App configuration does not advertise OAuth configuration");
  const server = createServer(createApp({ config, store: new ControlPlaneStore(db, keyring), admin }));
  const origin = await listen(server);
  t.after(() => close(server));
  const path = `/internal/v1/workspaces/${workspaceId}/integrations/github/token`;
  const beforeHttp = calls;
  assert.equal((await request(origin, path, { method: "POST", body: {} })).status, 401);
  assert.equal((await request(origin, path, { method: "POST", token: "invalid", body: {} })).status, 401);
  assert.equal(calls, beforeHttp, "unauthorized calls never mint");
  const http = await request(origin, path, { method: "POST", token: config.internalServiceToken!, body: {} });
  assert.equal(http.status, 200);
  assert.equal(http.body.authMode, "github_app");
  assert.equal(http.body.installationId, "98765");
  assert.equal(http.body.accessToken, "ghs_test-5");
  failure = true;
  const refused = await request(origin, path, { method: "POST", token: config.internalServiceToken!, body: { forceRefresh: true } });
  assert.equal(refused.status, 409);
  assert.equal(refused.body.error, "github_app_token_failed");
  assert.ok(!refused.raw.includes("PRIVATE KEY") && !refused.raw.includes("ghs_test"));
  failure = false;
  for (const installationId of ["", "0", "not-an-id", "../1"]) {
    await assert.rejects(store.importGithubAppConnection({ workspaceId, organizationId, installationId, actor }), /positive decimal/);
  }
  await assert.rejects(db.query("UPDATE integration_connections SET installation_id = NULL WHERE workspace_id = $1", [workspaceId]), /connection_github_installation/);
  await assert.rejects(db.query("UPDATE integration_connections SET provider = 'slack' WHERE workspace_id = $1", [workspaceId]), /connection_github_installation/);
  assert.equal(await store.disconnect({ workspaceId, organizationId, provider: "github", actor }), true);
  await assert.rejects(read(), /not connected/);
});

test("GitHub OAuth connect, callbacks and reconnect remain available alongside App connections", async (t) => {
  const db = new PGliteDatabase();
  t.after(() => db.close());
  await migrate(db);
  const control = new ControlPlaneStore(db, keyring);
  const organization = await control.createOrganization({ name: "Test", ownerEmail: "owner@example.test", ownerName: "Owner" });
  const workspaceId = await seedWorkspace(db, organization.id);
  const importedWorkspaceId = await seedWorkspace(db, organization.id);
  const config = testConfig();
  config.operatorOAuthApps = { github: { clientId: "oauth-client", clientSecret: "oauth-secret", scopes: null } };
  let oauthCalls = 0, appCalls = 0;
  const fetchImpl: FetchLike = async (url, init) => {
    if (url === "https://github.com/login/oauth/access_token") {
      const form = new URLSearchParams(String(init.body));
      assert.equal(form.get("grant_type"), "authorization_code");
      assert.equal(form.get("client_id"), "oauth-client");
      assert.ok(form.get("code_verifier"));
      return json({ access_token: `oauth-${++oauthCalls}`, refresh_token: "oauth-refresh", expires_in: 3600 });
    }
    assert.equal(url, "https://api.github.com/app/installations/41/access_tokens");
    appCalls++;
    return json(tokenBody("app-token"));
  };
  const beforeDeploy = createAdminModule({ config: { ...config, githubApp: null }, database: db, keyring, fetchImpl });
  const pending = await beforeDeploy.connections.startOAuth({ workspaceId, provider: "github", userId: organization.owner.id });
  const admin = createAdminModule({ config, database: db, keyring, fetchImpl });
  const complete = (connectLink: string) => admin.connections.completeOAuth({
    state: new URL(connectLink).searchParams.get("state")!, code: "test-code", error: null,
  });
  assert.equal((await complete(pending.connectLink)).connection.authMode, "oauth2", "callback started before App config was deployed still completes");
  const reconnect = await admin.connections.startOAuth({ workspaceId, provider: "github", userId: organization.owner.id });
  assert.equal((await complete(reconnect.connectLink)).connection.authMode, "oauth2");
  assert.equal((await admin.connections.runtimeToken({ workspaceId, provider: "github", actor })).accessToken, "oauth-2");
  await admin.connections.importGithubAppConnection({ workspaceId: importedWorkspaceId, organizationId: organization.id, installationId: "41", actor });
  assert.equal((await admin.connections.runtimeToken({ workspaceId: importedWorkspaceId, provider: "github", actor })).accessToken, "app-token");
  assert.equal(oauthCalls, 2);
  assert.equal(appCalls, 1, "runtime auth is selected per persisted connection row");
  const native = await seedWorkspace(db, organization.id);
  assert.ok((await admin.connections.startOAuth({ workspaceId: native, provider: "github", userId: organization.owner.id })).connectLink);
  const server = createServer(createApp({ config, store: control, admin }));
  const origin = await listen(server);
  t.after(() => close(server));
  const started = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: {} });
  const approved = await request(origin, "/api/v1/auth/device/approve", { method: "POST", token: config.bootstrapToken,
    body: { action: "approve", user_code: started.body.user_code, user_id: organization.owner.id, workspace_id: workspaceId } });
  assert.equal(approved.status, 200);
  const issued = await request(origin, "/api/v1/auth/device/token", { method: "POST", body: { device_code: started.body.device_code } });
  const catalog = await request(origin, `/api/v1/workspaces/${workspaceId}/integrations/providers`, { token: issued.body.access_token });
  assert.equal(catalog.status, 200);
  const github = catalog.body.providers.find((provider: { id: string }) => provider.id === "github");
  assert.equal(github.authMode, "OAUTH2");
  assert.deepEqual(github.supportedAuthModes, ["OAUTH2", "APP"]);
  assert.equal(github.configured, true);
  assert.equal(github.githubAppConfigured, true);
  assert.equal(github.githubAppSetup, "import");
});

test("installation imports enforce workspace ownership and one organization per installation", async (t) => {
  const db = new PGliteDatabase();
  t.after(() => db.close());
  await migrate(db);
  const organizationId = randomUUID(), otherOrganizationId = randomUUID();
  for (const id of [organizationId, otherOrganizationId]) await db.query("INSERT INTO organizations (id, name) VALUES ($1, 'Test')", [id]);
  const workspaceId = await seedWorkspace(db, organizationId);
  const sharedWorkspaceId = await seedWorkspace(db, organizationId);
  const outsider = await seedWorkspace(db, otherOrganizationId);
  const store = new ConnectionStore(db, keyring, new ProviderRegistry(), "https://control.test/callback");
  const importConnection = (workspaceId: string, organizationId: string, installationId = "41") =>
    store.importGithubAppConnection({ workspaceId, organizationId, installationId, actor });
  await assert.rejects(importConnection(workspaceId, otherOrganizationId), error =>
    error instanceof ConnectionError && error.code === "workspace_organization_mismatch");
  assert.equal((await db.query("SELECT * FROM github_app_installations")).rows.length, 0, "rejected mappings leave no owner claim");
  await importConnection(workspaceId, organizationId);
  await importConnection(sharedWorkspaceId, organizationId);
  await assert.rejects(importConnection(outsider, otherOrganizationId), error =>
    error instanceof ConnectionError && error.code === "installation_organization_mismatch");
  await importConnection(outsider, otherOrganizationId, "42");
  await assert.rejects(db.query(`UPDATE integration_connections SET installation_id = '41', github_app_organization_id = $2
    WHERE workspace_id = $1`, [outsider, organizationId]), /connection_github_workspace_owner/);
  await assert.rejects(db.query(`UPDATE integration_connections SET installation_id = '41' WHERE workspace_id = $1`, [outsider]), /connection_github_installation_owner/);
  const races = await Promise.allSettled([
    importConnection(workspaceId, organizationId, "99"), importConnection(outsider, otherOrganizationId, "99"),
  ]);
  assert.equal(races.filter(result => result.status === "fulfilled").length, 1);
  assert.equal(races.filter(result => result.status === "rejected").length, 1, "a concurrent cross-org claim cannot win twice");
});

test("App refresh leases preserve valid tokens on transient failures and fence reconnects", async (t) => {
  const db = new PGliteDatabase();
  t.after(() => db.close());
  await migrate(db);
  const organizationId = randomUUID();
  await db.query("INSERT INTO organizations (id, name) VALUES ($1, 'Test')", [organizationId]);
  const workspaceId = await seedWorkspace(db, organizationId);
  let status = 201, calls = 0;
  let pending: Promise<Response> | undefined, announce: (() => void) | undefined;
  const fetchImpl: FetchLike = async () => {
    calls++;
    if (pending) { announce!(); return pending; }
    return status === 201 ? json(tokenBody(`cached-${calls}`)) : json({ message: "do-not-echo" }, status);
  };
  const makeStore = () => new ConnectionStore(db, keyring, new ProviderRegistry(), "https://control.test/callback", fetchImpl, {}, app);
  const store = makeStore();
  const read = (forceRefresh = false) => store.runtimeToken({ workspaceId, provider: "github", actor, forceRefresh });
  const importConnection = (installationId: string) => store.importGithubAppConnection({ workspaceId, organizationId, installationId, actor });
  await importConnection("41");
  const initial = await read();
  status = 503;
  assert.equal((await read(true)).accessToken, initial.accessToken, "retryable mint failure reuses a still-valid token");
  assert.equal((await store.get(workspaceId, "github"))!.status, "ready");
  assert.equal((await store.get(workspaceId, "github"))!.lastError, "github_http_503");
  await db.query("UPDATE integration_connections SET access_token_expires_at = now() + interval '30 seconds' WHERE workspace_id = $1", [workspaceId]);
  assert.equal((await read()).accessToken, initial.accessToken, "pre-expiry refresh also falls back");
  await db.query("UPDATE integration_connections SET access_token_expires_at = now() - interval '1 second' WHERE workspace_id = $1", [workspaceId]);
  await assert.rejects(read(), error => error instanceof ConnectionError && error.status === 503);
  status = 201;
  const recovered = await read();
  let release!: (response: Response) => void;
  const started = new Promise<void>(resolve => { announce = resolve; });
  pending = new Promise<Response>(resolve => { release = resolve; });
  const inflight = read(true).then(token => ({ token, error: undefined }), error => ({ token: undefined, error }));
  await started;
  const beforePeer = calls;
  const peer = await makeStore().runtimeToken({ workspaceId, provider: "github", actor, forceRefresh: true });
  assert.equal(peer.accessToken, recovered.accessToken);
  assert.equal(calls, beforePeer, "a different store reuses the cache instead of duplicating a leased mint");
  await importConnection("42"); // Completes while the network request is suspended.
  release(json(tokenBody("late-token-from-old-installation")));
  const late = await inflight;
  assert.ok(late.error instanceof ConnectionError && late.error.code === "connection_changed");
  assert.equal((await store.get(workspaceId, "github"))!.installationId, "42");
  assert.equal((await store.get(workspaceId, "github"))!.accessTokenExpiresAt, null, "old mint cannot overwrite a reconnect");
  pending = undefined;
  await db.query(`UPDATE integration_connections SET github_app_refresh_id = $2,
    github_app_refresh_until = now() + interval '30 seconds' WHERE workspace_id = $1`, [workspaceId, randomUUID()]);
  await assert.rejects(read(), error => error instanceof ConnectionError && error.code === "github_app_refresh_in_progress");
  await db.query("UPDATE integration_connections SET github_app_refresh_until = now() - interval '1 second' WHERE workspace_id = $1", [workspaceId]);
  assert.ok((await read()).accessToken, "a crashed refresher's lease expires and can be reclaimed");
  const disconnectStarted = new Promise<void>(resolve => { announce = resolve; });
  pending = new Promise<Response>(resolve => { release = resolve; });
  const disconnecting = read(true).then(token => ({ token, error: undefined }), error => ({ token: undefined, error }));
  await disconnectStarted;
  await store.disconnect({ workspaceId, organizationId, provider: "github", actor });
  release(json(tokenBody("late-token-after-disconnect")));
  assert.equal((await disconnecting).error?.code, "connection_changed");
  assert.equal(await store.get(workspaceId, "github"), null, "a late mint cannot recreate a disconnected row");
});
