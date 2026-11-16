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
  const organizationId = randomUUID(), workspaceId = randomUUID(), otherWorkspaceId = randomUUID();
  await db.query("INSERT INTO organizations (id, name) VALUES ($1, 'Test')", [organizationId]);
  for (const id of [workspaceId, otherWorkspaceId]) {
    await db.query(`INSERT INTO workspaces (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
      VALUES ($1, $2, 'Test', $4, $3)`, [id, organizationId, encryptSecret("test-cast", keyring.active), id]);
  }
  let calls = 0, failure = false;
  const fetchImpl: FetchLike = async (url) => {
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
  assert.ok(refreshed.every(token => token.accessToken === "ghs_test-2"));
  assert.equal(calls, 2, "concurrent stale readers share one mint under the row lock");
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
  const legacy = new ConnectionStore(db, keyring, new ProviderRegistry([GITHUB_APP_PROVIDER]), "https://control.test/callback",
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
  const config: SelfhostConfig = {
    databaseUrl: "unused", publicBaseUrl: "https://control.test",
    relaycastUrl: "https://cast.test", relaycastPublicUrl: "https://cast.test",
    relayhistoryUrl: "https://history.test", relayhistoryPublicUrl: "https://history.test",
    sessionReadApi: { url: "https://history.test", publicUrl: "https://history.test", secret: "test-secret".repeat(4) },
    bootstrapToken: "bootstrap-test-secret".repeat(3), encryptionKeyring: keyring,
    oauthRedirectUrl: "https://control.test/callback", dashboardUrl: "https://control.test/",
    internalServiceToken: "internal-test-secret".repeat(3), githubApp: app, port: 0, host: "127.0.0.1",
  };
  const admin = createAdminModule({ config, database: db, keyring, fetchImpl });
  assert.equal(admin.providers.get("github")!.authMode, "github_app");
  assert.equal(admin.connections.operatorConfigured("github"), true);
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
