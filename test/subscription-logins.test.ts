import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import { createAdminModule } from "../src/admin/routes.js";
import {
  CredentialBlobStore,
  GcsObjectBackend,
  openCredential,
  PostgresObjectBackend,
  S3ObjectBackend,
  sealCredential,
  signV4,
} from "../src/admin/credential-blobs.js";
import { describeAuthFile, refreshAuthFile, REFRESH_WINDOW_MS } from "../src/admin/subscription-logins.js";
import { XAI_DEVICE_CREDENTIAL_SCOPE } from "../src/admin/xai-device-auth.js";
import type { SelfhostConfig } from "../src/config.js";
import { defaultFlowsConfig } from "../src/flows/config.js";
import { FlowsStore } from "../src/flows/store.js";
import { testFeatures } from "./support/features.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { apiClient, BOOTSTRAP, openQueue, seedTenant } from "./flows-helpers.js";
import { close, listen, PGliteDatabase } from "./support/harness.js";

const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };

const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
const jwt = (claims: object) => `${b64({ alg: "none" })}.${b64(claims)}.sig`;
const OPENAI_CLAIMS = { "https://api.openai.com/auth": { chatgpt_account_id: "acct-123" } };

function codexAuth(accessExp: number, refresh = "rt-openai-secret-1") {
  return JSON.stringify({
    auth_mode: "chatgpt",
    OPENAI_API_KEY: null,
    tokens: {
      id_token: jwt({ ...OPENAI_CLAIMS, email: "dev@acme.test" }),
      access_token: jwt({ ...OPENAI_CLAIMS, exp: accessExp }),
      refresh_token: refresh,
      account_id: "acct-123",
    },
    last_refresh: new Date().toISOString(),
  });
}

/** Mock auth.openai.com (device flow + refresh) and auth.x.ai. */
function providerMock() {
  const calls: Array<{ url: string; body: string }> = [];
  let polls = 0;
  let refreshStatus = 200;
  const fetchImpl = async (url: string, init: RequestInit) => {
    const body = typeof init.body === "string" ? init.body : "";
    calls.push({ url, body });
    const json = (status: number, value: unknown) =>
      new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
    if (url === "https://auth.openai.com/api/accounts/deviceauth/usercode") {
      return json(200, { device_auth_id: "dev-auth-1", user_code: "ABCD-1234", interval: "1" });
    }
    if (url === "https://auth.openai.com/api/accounts/deviceauth/token") {
      polls += 1;
      if (polls === 1) return json(403, {});
      const verifier = "verifier-xyz";
      return json(200, {
        authorization_code: "code-1",
        code_verifier: verifier,
        code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      });
    }
    if (url === "https://auth.openai.com/oauth/token") {
      const params = new URLSearchParams(body);
      if (params.get("grant_type") === "authorization_code") {
        return json(200, {
          id_token: jwt({ ...OPENAI_CLAIMS, email: "dev@acme.test" }),
          access_token: jwt({ ...OPENAI_CLAIMS, exp: Math.floor(Date.now() / 1000) + 600 }),
          refresh_token: "rt-openai-secret-1",
        });
      }
      if (refreshStatus !== 200) return json(refreshStatus, { error: "invalid_grant", detail: "rt-openai-secret" });
      return json(200, {
        access_token: jwt({ ...OPENAI_CLAIMS, exp: Math.floor(Date.now() / 1000) + 86_400 }),
        refresh_token: "rt-openai-secret-2",
      });
    }
    if (url === "https://auth.x.ai/oauth2/token") {
      return json(200, { access_token: "xai-access-2", refresh_token: "xai-refresh-2", expires_in: 3600 });
    }
    return json(404, {});
  };
  return { fetchImpl, calls, setRefreshStatus: (status: number) => { refreshStatus = status; } };
}

async function setup(t: test.TestContext) {
  const database = new PGliteDatabase();
  await migrate(database);
  const mock = providerMock();
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://relaycast.selfhosted.company",
    relayauthUrl: "http://relayauth.invalid",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.company",
    relayauthApiKey: "rak_test",
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/`,
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  const flows = new FlowsStore(database, KEYRING, defaultFlowsConfig({ queuePollMs: 25, queuePingMs: 200 }), config.relaycastPublicUrl);
  const admin = createAdminModule({
    config,
    database,
    keyring: KEYRING,
    fetchImpl: mock.fetchImpl,
    credentialBackend: new PostgresObjectBackend(database),
  });
  flows.cliCredentials = admin.logins;
  control.on("request", createApp({ config, store, flows, admin, features: testFeatures("flows") }));
  t.after(async () => {
    await close(control);
    await database.close();
  });
  const api = apiClient(origin);
  const tenant = await seedTenant(api);
  return { database, origin, api, tenant, admin, mock };
}

test("credential envelopes: per-object data key wrapped with the keyring, AAD-bound, rotation-safe", () => {
  const plaintext = codexAuth(2_000_000_000);
  const envelope = sealCredential(plaintext, KEYRING, "cred-1", 3);
  assert.equal(envelope.keyId, "test-key");
  assert.match(envelope.wrappedKey, /^v2\.test-key\./);
  assert(!JSON.stringify(envelope).includes("rt-openai-secret-1"), "no plaintext in the envelope");
  assert.equal(openCredential(envelope, KEYRING, "cred-1", 3), plaintext);
  assert.throws(() => openCredential(envelope, KEYRING, "cred-2", 3), /authentication/, "bound to the credential id");
  assert.throws(() => openCredential(envelope, KEYRING, "cred-1", 4), /authentication/, "bound to the version");
  const rotated = { active: { id: "next", key: Buffer.alloc(32, 8) }, previous: KEYRING.active };
  assert.equal(openCredential(envelope, rotated, "cred-1", 3), plaintext, "previous key still opens");
  assert.throws(() => openCredential(envelope, { active: { id: "other", key: Buffer.alloc(32, 1) } }, "cred-1", 3), /data key/);
  const again = sealCredential(plaintext, KEYRING, "cred-1", 3);
  assert.notEqual(again.wrappedKey, envelope.wrappedKey, "a fresh data key per write");
});

test("credential objects: GCS and S3 backends store only envelopes", async () => {
  const objects = new Map<string, string>();
  const seen: Array<{ url: string; headers: Record<string, string> }> = [];
  const fetchImpl = async (url: string, init: RequestInit) => {
    const headers = (init.headers ?? {}) as Record<string, string>;
    seen.push({ url, headers });
    if (url.startsWith("http://metadata")) return new Response(JSON.stringify({ access_token: "gcs-token", expires_in: 3600 }));
    const key = decodeURIComponent(new URL(url).searchParams.get("name") ?? new URL(url).pathname.split("/o/")[1] ?? new URL(url).pathname);
    if (init.method === "POST" || init.method === "PUT") {
      objects.set(key, String(init.body));
      return new Response("{}");
    }
    if (init.method === "DELETE") {
      objects.delete(key);
      return new Response(null, { status: 204 });
    }
    const body = objects.get(key);
    return body ? new Response(body) : new Response("", { status: 404 });
  };
  for (const backend of [
    new GcsObjectBackend("customer-bucket", "creds", fetchImpl),
    new S3ObjectBackend({
      bucket: "customer-bucket",
      region: "us-east-1",
      prefix: "creds",
      credentials: { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "secret-example" },
    }, fetchImpl),
  ]) {
    const blobs = new CredentialBlobStore(backend, KEYRING);
    const location = await blobs.write("ws-1", "cred-1", 1, codexAuth(2_000_000_000));
    assert.equal(location, "workspaces/ws-1/accounts/cred-1/v1.json.enc");
    assert(![...objects.values()].some((value) => value.includes("rt-openai-secret-1")), `${backend.kind}: no plaintext stored`);
    assert.equal(describeAuthFile("openai", await blobs.read(location, "cred-1", 1)).accountId, "acct-123");
    await blobs.remove(location);
    assert.equal(objects.size, 0, `${backend.kind}: delete removes the object`);
  }
  assert(seen.some((call) => call.headers.authorization === "Bearer gcs-token"), "GCS uses Workload Identity");
  assert(seen.some((call) => /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\//.test(call.headers.authorization ?? "")), "S3 requests are SigV4-signed");
});

test("S3 SigV4 matches the AWS documented GET Object example", () => {
  const headers = signV4({
    method: "GET",
    url: new URL("https://examplebucket.s3.amazonaws.com/test.txt"),
    region: "us-east-1",
    service: "s3",
    body: "",
    credentials: { accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" },
    now: new Date("2013-05-24T00:00:00Z"),
    extraHeaders: { range: "bytes=0-9" },
  });
  assert.equal(
    headers.authorization,
    "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
  );
});

test("Codex device login: start, poll, store encrypted, sandbox access, no secrets in responses", async (t) => {
  const ctx = await setup(t);
  const base = `/api/v1/workspaces/${ctx.tenant.workspaceId}`;
  const memberStart = await ctx.api(`${base}/provider-credentials/openai-device/start`, {
    method: "POST",
    token: ctx.tenant.memberToken,
    body: {},
  });
  assert.equal(memberStart.status, 403, "members cannot connect credentials");

  const started = await ctx.api(`${base}/provider-credentials/openai-device/start`, {
    method: "POST",
    token: ctx.tenant.ownerToken,
    body: {},
  });
  assert.equal(started.status, 201);
  assert.equal(started.body.userCode, "ABCD-1234");
  assert.equal(started.body.verificationUri, "https://auth.openai.com/codex/device");
  assert(!("browserBinding" in started.body), "the browser binding is only a cookie");
  const setCookie = started.headers.get("set-cookie") ?? "";
  assert.match(setCookie, /^agent_relay_openai_device_session=[^;]+; Path=\/; Max-Age=\d+; Secure; HttpOnly; SameSite=Strict$/);
  const cookie = setCookie.split(";")[0]!;

  const noCookie = await ctx.api(`${base}/provider-credentials/openai-device/status`, {
    method: "POST",
    token: ctx.tenant.ownerToken,
    body: { transactionId: started.body.transactionId },
  });
  assert.equal(noCookie.status, 404, "status needs the browser that started the login");

  const poll = async () => ctx.api(`${base}/provider-credentials/openai-device/status`, {
    method: "POST",
    token: ctx.tenant.ownerToken,
    headers: { cookie },
    body: { transactionId: started.body.transactionId },
  });
  // The first poll happens after the provider interval; force it due.
  await ctx.database.query("UPDATE selfhost_coding_agent_device_sessions SET next_poll_at = now() - interval '1 second'");
  const pending = await poll();
  assert.equal(pending.body.status, "pending");
  await ctx.database.query("UPDATE selfhost_coding_agent_device_sessions SET next_poll_at = now() - interval '1 second'");
  const connected = await poll();
  assert.equal(connected.status, 200);
  assert.equal(connected.body.status, "connected");
  const credentialId = connected.body.providerCredentialId as string;

  const listed = await ctx.api(`${base}/cloud-agents`, { token: ctx.tenant.ownerToken });
  const agent = listed.body.agents.find((item: { id: string }) => item.id === credentialId);
  assert.equal(agent.authType, "provider_oauth");
  assert.equal(agent.modelProvider, "openai");
  assert.equal(agent.harness, "codex");
  assert.equal(agent.harnessActive, true, "first login gets sandbox access");
  assert.equal(agent.isActive, false);
  assert.equal(agent.accountEmail, "dev@acme.test");
  const openai = listed.body.providers.find((item: { id: string }) => item.id === "openai");
  assert.deepEqual(openai.authTypes, ["provider_oauth", "byo_api_key"]);
  for (const response of [started, pending, connected, listed]) {
    assert(!response.text.includes("rt-openai-secret"), "no refresh token in any response");
  }
  const dump = await ctx.database.query("SELECT * FROM selfhost_coding_agent_credentials");
  const blobs = await ctx.database.query("SELECT * FROM selfhost_coding_agent_credential_blobs");
  const sessions = await ctx.database.query("SELECT * FROM selfhost_coding_agent_device_sessions");
  for (const rows of [dump.rows, blobs.rows, sessions.rows]) {
    assert(!JSON.stringify(rows).includes("rt-openai-secret"), "no plaintext at rest");
    assert(!JSON.stringify(rows).includes("dev-auth-1"), "device state is encrypted");
  }
  assert.equal(sessions.rows[0]!.encrypted_device_state, null, "device state is dropped when the login completes");

  const llm = await ctx.api(`${base}/cloud-agents/${credentialId}/activate`, {
    method: "POST",
    token: ctx.tenant.ownerToken,
    body: { selection: "model" },
  });
  assert.equal(llm.status, 409, "a subscription login is sandbox-only");

  const env = await ctx.admin.envVars.readRuntimeEnvironment(ctx.tenant.workspaceId, { kind: "bootstrap" });
  assert.deepEqual(env.env, {}, "a login is never delivered as an env var");
});

test("materialise and refresh: run reference, refresh-if-stale, write-back, revocation", async (t) => {
  const ctx = await setup(t);
  const base = `/api/v1/workspaces/${ctx.tenant.workspaceId}`;
  const owner = (await ctx.database.query<{ id: string }>("SELECT id FROM selfhost_users WHERE email = 'owner@acme.test'")).rows[0]!.id;
  // Expires inside the refresh window, so the first read refreshes it.
  const credentialId = await ctx.admin.logins.storeLogin({
    provider: "openai",
    workspaceId: ctx.tenant.workspaceId,
    organizationId: ctx.tenant.organizationId,
    actor: { kind: "user", userId: owner },
    authFile: codexAuth(Math.floor((Date.now() + REFRESH_WINDOW_MS / 2) / 1000)),
  });

  const enrollment = await ctx.api("/api/v1/workers/enrollment-tokens", {
    method: "POST",
    token: ctx.tenant.ownerToken,
    body: { name: "w1" },
  });
  const registered = await ctx.api("/api/v1/workers/register", {
    method: "POST",
    body: { enrollmentToken: enrollment.body.token, name: "w1" },
  });
  const { workerId, workerToken } = registered.body;
  const queue = openQueue(ctx.origin, workerId, workerToken);
  t.after(() => queue.close());
  await queue.ready;
  const run = await ctx.api("/api/v1/workflows/run", {
    method: "POST",
    token: ctx.tenant.ownerToken,
    body: { workflow: "version: '1.0'\nname: x\nworkflows:\n  - name: main\n    steps:\n      - name: a\n        type: deterministic\n        command: 'true'\n", fileType: "yaml" },
  });
  assert.equal(run.status, 201, JSON.stringify(run.body));
  const runId = run.body.runId as string;
  const assignment = await queue.next("assignment");
  const payload = JSON.parse(assignment.data.workflowRef.value);
  assert.equal(payload.cliCredentials.path, `/api/v1/workers/{workerId}/assignments/${runId}/cli-credentials`);
  assert.deepEqual(payload.cliCredentials.credentials, [{ credentialId, provider: "openai", cli: "codex" }]);
  assert.match(payload.cliCredentials.ref, /^sh_clicred_/);
  assert(!assignment.data.workflowRef.value.includes("rt-openai-secret"), "the payload carries no auth file");
  const ref = payload.cliCredentials.ref as string;
  await ctx.api(`/api/v1/workers/${workerId}/assignments/${runId}/ack`, { method: "POST", token: workerToken });

  const path = `/api/v1/workers/${workerId}/assignments/${runId}/cli-credentials`;
  assert.equal((await ctx.api(path, { token: workerToken })).status, 401, "the reference is required");
  assert.equal((await ctx.api(path, { headers: { "x-cli-credential-ref": ref } })).status, 401, "the worker credential is required");
  const read = await ctx.api(path, { token: workerToken, headers: { "x-cli-credential-ref": ref } });
  assert.equal(read.status, 200);
  assert.equal(read.headers.get("cache-control"), "no-store");
  const file = read.body.files[0];
  assert.deepEqual(
    { cli: file.cli, homeEnv: file.homeEnv, directory: file.directory, file: file.file },
    { cli: "codex", homeEnv: "CODEX_HOME", directory: ".codex", file: "auth.json" },
  );
  const delivered = JSON.parse(file.content);
  assert.equal(delivered.tokens.refresh_token, "rt-openai-secret-2", "stale login refreshed before delivery");
  const refreshCalls = ctx.mock.calls.filter((call) => call.url === "https://auth.openai.com/oauth/token");
  assert.equal(refreshCalls.length, 1);
  assert.equal(new URLSearchParams(refreshCalls[0]!.body).get("grant_type"), "refresh_token");

  const second = await ctx.api(path, { token: workerToken, headers: { "x-cli-credential-ref": ref } });
  assert.equal(JSON.parse(second.body.files[0].content).tokens.refresh_token, "rt-openai-secret-2");
  assert.equal(ctx.mock.calls.filter((call) => call.url === "https://auth.openai.com/oauth/token").length, 1, "fresh logins are not refreshed again");

  // The CLI refreshed during the run: the worker writes the file back.
  const rotated = { ...delivered, tokens: { ...delivered.tokens, refresh_token: "rt-openai-secret-3", access_token: jwt({ ...OPENAI_CLAIMS, exp: Math.floor(Date.now() / 1000) + 2 * 86_400 }) } };
  const writeBack = await ctx.api(`${path}/${credentialId}`, {
    method: "PUT",
    token: workerToken,
    headers: { "x-cli-credential-ref": ref },
    body: { content: JSON.stringify(rotated) },
  });
  assert.equal(writeBack.status, 200);
  assert.deepEqual(writeBack.body, { updated: true });
  const otherAccount = { ...rotated, tokens: { ...rotated.tokens, account_id: "acct-evil" } };
  assert.equal((await ctx.api(`${path}/${credentialId}`, {
    method: "PUT",
    token: workerToken,
    headers: { "x-cli-credential-ref": ref },
    body: { content: JSON.stringify(otherAccount) },
  })).status, 409, "write-back cannot swap the account");
  const after = await ctx.api(path, { token: workerToken, headers: { "x-cli-credential-ref": ref } });
  assert.equal(JSON.parse(after.body.files[0].content).tokens.refresh_token, "rt-openai-secret-3");
  const versions = await ctx.database.query<{ blob_version: number }>("SELECT blob_version FROM selfhost_coding_agent_credentials WHERE id = $1", [credentialId]);
  assert.equal(versions.rows[0]!.blob_version, 3);
  const objects = await ctx.database.query("SELECT object_key FROM selfhost_coding_agent_credential_blobs");
  assert.equal(objects.rows.length, 1, "superseded versions are removed");

  // Finishing the run revokes the reference.
  await ctx.api(`/api/v1/workers/${workerId}/assignments/${runId}/status`, {
    method: "POST",
    token: workerToken,
    body: { phase: "completed", exitCode: 0 },
  });
  assert.equal((await ctx.api(path, { token: workerToken, headers: { "x-cli-credential-ref": ref } })).status, 404);
  const refs = await ctx.database.query<{ revoked_at: unknown }>("SELECT revoked_at FROM selfhost_cli_credential_refs");
  assert(refs.rows[0]!.revoked_at, "reference revoked");
  const audit = await ctx.api(`${base}/admin/audit`, { token: ctx.tenant.ownerToken });
  assert(!audit.text.includes("rt-openai-secret"));
  assert(audit.body.events.some((event: { action: string }) => event.action === "coding_agent.login_write_back"));

  // Delete removes the stored object.
  await ctx.api(`${base}/cloud-agents/${credentialId}`, { method: "DELETE", token: ctx.tenant.ownerToken });
  assert.equal((await ctx.database.query("SELECT 1 FROM selfhost_coding_agent_credential_blobs")).rows.length, 0);
});

test("refresh failure: an expired login that cannot refresh is skipped and marked", async (t) => {
  const ctx = await setup(t);
  const owner = (await ctx.database.query<{ id: string }>("SELECT id FROM selfhost_users WHERE email = 'owner@acme.test'")).rows[0]!.id;
  const credentialId = await ctx.admin.logins.storeLogin({
    provider: "openai",
    workspaceId: ctx.tenant.workspaceId,
    organizationId: ctx.tenant.organizationId,
    actor: { kind: "user", userId: owner },
    authFile: codexAuth(Math.floor(Date.now() / 1000) - 60),
  });
  ctx.mock.setRefreshStatus(400);
  assert.equal(await ctx.admin.logins.freshAuthFile(ctx.tenant.workspaceId, credentialId), null);
  const row = await ctx.database.query<{ status: string; last_error: string }>(
    "SELECT status, last_error FROM selfhost_coding_agent_credentials WHERE id = $1",
    [credentialId],
  );
  assert.equal(row.rows[0]!.status, "refresh_failed");
  assert.match(row.rows[0]!.last_error, /HTTP 400/);
  assert(!row.rows[0]!.last_error.includes("rt-openai-secret"), "provider bodies never reach last_error");
});

test("Grok auth file: identity, expiry and refresh rotate the single-use refresh token", async () => {
  const file = JSON.stringify({
    [XAI_DEVICE_CREDENTIAL_SCOPE]: {
      key: jwt({ sub: "xai-user-1", exp: 1 }),
      auth_mode: "oidc",
      create_time: new Date().toISOString(),
      email: "dev@acme.test",
      refresh_token: "xai-refresh-1",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      oidc_issuer: "https://auth.x.ai",
      oidc_client_id: "b1a00492-073a-47ea-816f-4c329264a828",
    },
  });
  const described = describeAuthFile("xai", file);
  assert.equal(described.accountId, "xai-user-1");
  assert.equal(described.email, "dev@acme.test");
  const mock = providerMock();
  const refreshed = JSON.parse(await refreshAuthFile("xai", file, mock.fetchImpl));
  const entry = refreshed[XAI_DEVICE_CREDENTIAL_SCOPE];
  assert.equal(entry.key, "xai-access-2");
  assert.equal(entry.refresh_token, "xai-refresh-2");
  assert.equal(entry.email, "dev@acme.test");
  assert.equal(new URLSearchParams(mock.calls[0]!.body).get("client_id"), "b1a00492-073a-47ea-816f-4c329264a828");
});
