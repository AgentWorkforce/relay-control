import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import { createAdminModule } from "../src/admin/routes.js";
import { previewSecret } from "../src/admin/coding-agents.js";
import type { SelfhostConfig } from "../src/config.js";
import { decryptSecret } from "../src/crypto.js";
import { defaultMigrationsDirectory, migrate } from "../src/migrations.js";
import { copyFile, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encryptSecret } from "../src/crypto.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const ANTHROPIC_KEY = "sk-ant-api03-coding-agent-plaintext-0001";
const SETUP_TOKEN = "sk-ant-oat01-setup-token-plaintext-0002";
const OPENROUTER_KEY = "sk-or-v1-openrouter-plaintext-key-0003";

type ProbeCall = { url: string; headers: Record<string, string> };

async function deviceToken(origin: string, userId: string, workspaceId: string): Promise<string> {
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

async function setup(t: test.TestContext) {
  const database = new PGliteDatabase();
  await migrate(database);
  const probes: ProbeCall[] = [];
  let probeStatus = 200;
  const fetchImpl = async (url: string, init: RequestInit) => {
    probes.push({ url, headers: init.headers as Record<string, string> });
    return new Response("{}", { status: probeStatus });
  };
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
    internalServiceToken: SERVICE,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/dashboard/`,
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  const admin = createAdminModule({ config, database, keyring: KEYRING, fetchImpl });
  control.on("request", createApp({ config, store, admin }));
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
  const workspaces: string[] = [];
  for (const name of ["Primary", "Other"]) {
    const workspace = await request(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, relaycastApiKey: `rk_${name}` },
    });
    assert.equal(workspace.status, 201);
    workspaces.push(workspace.body.id as string);
  }
  const member = await request(origin, `/api/v1/organizations/${org.body.id}/memberships`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { email: "member@acme.test", name: "Member", role: "member" },
  });
  assert.equal(member.status, 200);
  const workspaceId = workspaces[0]!;
  return {
    database,
    origin,
    probes,
    setProbeStatus: (status: number) => { probeStatus = status; },
    workspaceId,
    otherWorkspaceId: workspaces[1]!,
    ownerId: org.body.owner.id as string,
    owner: await deviceToken(origin, org.body.owner.id, workspaceId),
    member: await deviceToken(origin, member.body.userId, workspaceId),
  };
}

test("coding agents: store masked, encrypted at rest, admin-only writes", async (t) => {
  const ctx = await setup(t);
  const base = `/api/v1/workspaces/${ctx.workspaceId}`;

  const empty = await request(ctx.origin, `${base}/cloud-agents`, { token: ctx.member });
  assert.equal(empty.status, 200);
  assert.deepEqual(empty.body.agents, []);
  assert.equal(empty.body.canManage, false);
  assert.deepEqual(
    empty.body.providers.map((provider: { id: string }) => provider.id),
    ["anthropic", "openai", "openrouter", "xai", "google"],
  );

  const memberWrite = await request(ctx.origin, `${base}/provider-credentials/byok`, {
    method: "POST",
    token: ctx.member,
    body: { modelProvider: "anthropic", key: ANTHROPIC_KEY },
  });
  assert.equal(memberWrite.status, 403, "members cannot store credentials");

  const created = await request(ctx.origin, `${base}/provider-credentials/byok`, {
    method: "POST",
    token: ctx.owner,
    body: { modelProvider: "claude", key: ANTHROPIC_KEY },
  });
  assert.equal(created.status, 201);
  assert(!created.raw.includes(ANTHROPIC_KEY), "create response never echoes the key");
  assert.equal(created.body.agent.modelProvider, "anthropic", "claude alias normalizes");
  assert.equal(created.body.agent.authType, "byo_api_key");
  assert.equal(created.body.agent.secretPreview, previewSecret(ANTHROPIC_KEY));
  assert.equal(created.body.agent.secretPreview, "sk-ant-…0001");
  assert.equal(created.body.agent.isActive, true, "first credential gets LLM call access");
  assert.equal(created.body.agent.harnessActive, false, "an API key is never the sandbox login");
  assert.equal(created.body.agent.owner.userId, ctx.ownerId);

  const again = await request(ctx.origin, `${base}/provider-credentials/byok`, {
    method: "POST",
    token: ctx.owner,
    body: { modelProvider: "anthropic", key: ANTHROPIC_KEY },
  });
  assert.equal(again.status, 200, "the same key stored twice is one credential");
  assert.equal(again.body.id, created.body.id);

  for (const body of [
    { modelProvider: "opencode", key: "x".repeat(30) },
    { modelProvider: "daytona", key: "dtn_" + "x".repeat(30) },
    { modelProvider: "anthropic", key: "" },
    { modelProvider: "anthropic", key: "two words here" },
    { modelProvider: "anthropic", key: ANTHROPIC_KEY, label: 7 },
  ]) {
    const response = await request(ctx.origin, `${base}/provider-credentials/byok`, {
      method: "POST",
      token: ctx.owner,
      body,
    });
    assert.equal(response.status, 400, JSON.stringify(body));
  }

  const formPost = await request(ctx.origin, `/cloud${base}/provider-credentials/byok`, {
    method: "POST",
    cookie: `agent_relay_session=${ctx.owner}`,
    rawBody: `modelProvider=openai&key=${"k".repeat(30)}`,
    contentType: "application/x-www-form-urlencoded",
  });
  assert.equal(formPost.status, 415, "cookie writes must be JSON");

  const rows = await ctx.database.query<{ secret_ciphertext: string }>(
    "SELECT * FROM selfhost_coding_agent_credentials",
  );
  assert.equal(rows.rows.length, 1);
  assert(!JSON.stringify(rows.rows).includes(ANTHROPIC_KEY), "no plaintext in any column");
  assert.match(rows.rows[0]!.secret_ciphertext, /^v2\.test-key\./);
  assert.equal(decryptSecret(rows.rows[0]!.secret_ciphertext, KEYRING), ANTHROPIC_KEY);

  for (const path of [`${base}/cloud-agents`, `${base}/admin/audit`]) {
    const response = await request(ctx.origin, path, { token: ctx.owner });
    assert.equal(response.status, 200, path);
    assert(!response.raw.includes(ANTHROPIC_KEY), `${path} leaks no plaintext`);
  }

  const crossWorkspace = await request(
    ctx.origin,
    `/api/v1/workspaces/${ctx.otherWorkspaceId}/cloud-agents/${created.body.id}`,
    { method: "DELETE", token: ctx.owner },
  );
  assert.equal(crossWorkspace.status, 404, "a credential is only addressable in its workspace");
});

test("coding agents: setup tokens, sandbox and LLM selection, runtime env", async (t) => {
  const ctx = await setup(t);
  const base = `/api/v1/workspaces/${ctx.workspaceId}`;
  const runtime = () => request(ctx.origin, `/internal/v1/workspaces/${ctx.workspaceId}/environment?includeIntegrations=1`, {
    token: SERVICE,
  });

  assert.deepEqual((await runtime()).body.env, {}, "nothing delivered before a credential exists");

  const apiKey = await request(ctx.origin, `${base}/provider-credentials/byok`, {
    method: "POST",
    token: ctx.owner,
    body: { modelProvider: "anthropic", key: ANTHROPIC_KEY, label: "Team key" },
  });
  assert.equal(apiKey.body.agent.displayName, "Team key");

  const setupToken = await request(ctx.origin, `${base}/provider-credentials/setup-token`, {
    method: "POST",
    token: ctx.owner,
    body: { token: SETUP_TOKEN, accountEmail: "dev@acme.test" },
  });
  assert.equal(setupToken.status, 201);
  assert.equal(setupToken.body.agent.authType, "oauth_token");
  assert.equal(setupToken.body.agent.displayName, "Claude setup token");
  assert.equal(setupToken.body.agent.accountEmail, "dev@acme.test");
  assert.equal(setupToken.body.agent.harnessActive, true, "first setup token gets sandbox access");
  assert.equal(setupToken.body.agent.isActive, false, "the API key keeps LLM call access");

  const badEmail = await request(ctx.origin, `${base}/provider-credentials/setup-token`, {
    method: "POST",
    token: ctx.owner,
    body: { token: `${SETUP_TOKEN}x`, accountEmail: "not-an-email" },
  });
  assert.equal(badEmail.status, 400);
  assert.equal(badEmail.body.error, "account_email_invalid");

  const rotated = await request(ctx.origin, `${base}/provider-credentials/setup-token`, {
    method: "POST",
    token: ctx.owner,
    body: { token: `${SETUP_TOKEN}-rotated`, accountEmail: "DEV@acme.test" },
  });
  assert.equal(rotated.status, 200, "same account email replaces that account's token");
  assert.equal(rotated.body.id, setupToken.body.id);

  let env = (await runtime()).body;
  assert.equal(env.env.ANTHROPIC_API_KEY, ANTHROPIC_KEY);
  assert.equal(env.env.CLAUDE_CODE_OAUTH_TOKEN, `${SETUP_TOKEN}-rotated`);
  assert(env.secretEnvNames.includes("ANTHROPIC_API_KEY"));
  assert(env.secretEnvNames.includes("CLAUDE_CODE_OAUTH_TOKEN"));

  const harnessForKey = await request(ctx.origin, `${base}/cloud-agents/${apiKey.body.id}/activate`, {
    method: "POST",
    token: ctx.owner,
    body: { selection: "harness" },
  });
  assert.equal(harnessForKey.status, 409, "an API key cannot take sandbox access");

  const memberSelect = await request(ctx.origin, `${base}/cloud-agents/${setupToken.body.id}/activate`, {
    method: "POST",
    token: ctx.member,
    body: { selection: "model" },
  });
  assert.equal(memberSelect.status, 403);

  const selectToken = await request(ctx.origin, `${base}/cloud-agents/${setupToken.body.id}/activate`, {
    method: "POST",
    token: ctx.owner,
    body: { selection: "model" },
  });
  assert.equal(selectToken.status, 200);
  assert.equal(selectToken.body.agent.isActive, true);
  const listed = await request(ctx.origin, `${base}/cloud-agents`, { token: ctx.owner });
  const active = listed.body.agents.filter((agent: { isActive: boolean }) => agent.isActive);
  assert.equal(active.length, 1, "exactly one LLM credential per provider");
  assert.equal(listed.body.canManage, true);

  env = (await runtime()).body;
  assert.equal(env.env.ANTHROPIC_API_KEY, undefined, "the deselected key is no longer delivered");
  assert.equal(env.env.CLAUDE_CODE_OAUTH_TOKEN, `${SETUP_TOKEN}-rotated`);

  // A workspace variable of the same name loses to the selected credential.
  const workspaceVar = await request(ctx.origin, `${base}/secrets`, {
    method: "POST",
    token: ctx.owner,
    body: { name: "OPENROUTER_API_KEY", value: "workspace-variable-value-123" },
  });
  assert.equal(workspaceVar.status, 201);
  const openrouter = await request(ctx.origin, `${base}/provider-credentials/byok`, {
    method: "POST",
    token: ctx.owner,
    body: { modelProvider: "openrouter", key: OPENROUTER_KEY },
  });
  assert.equal(openrouter.status, 201);
  env = (await runtime()).body;
  assert.equal(env.env.OPENROUTER_API_KEY, OPENROUTER_KEY);

  const lastUsed = await request(ctx.origin, `${base}/cloud-agents`, { token: ctx.owner });
  const used = lastUsed.body.agents.find((agent: { id: string }) => agent.id === openrouter.body.id);
  assert(used.lastUsedAt, "runtime delivery records last use");

  // Deleting the LLM credential promotes the remaining one.
  const deleted = await request(ctx.origin, `${base}/cloud-agents/${setupToken.body.id}`, {
    method: "DELETE",
    token: ctx.owner,
  });
  assert.equal(deleted.status, 200);
  const after = await request(ctx.origin, `${base}/cloud-agents`, { token: ctx.owner });
  const anthropic = after.body.agents.filter((agent: { modelProvider: string }) => agent.modelProvider === "anthropic");
  assert.equal(anthropic.length, 1);
  assert.equal(anthropic[0].isActive, true, "remaining credential is promoted");
  env = (await runtime()).body;
  assert.equal(env.env.ANTHROPIC_API_KEY, ANTHROPIC_KEY);
  assert.equal(env.env.CLAUDE_CODE_OAUTH_TOKEN, undefined);

  const unauthenticated = await request(ctx.origin, `/internal/v1/workspaces/${ctx.workspaceId}/environment`, {
    token: ctx.owner,
  });
  assert.equal(unauthenticated.status, 401, "user sessions cannot read runtime env");
});

test("coding agents: check probes the provider and records failures", async (t) => {
  const ctx = await setup(t);
  const base = `/api/v1/workspaces/${ctx.workspaceId}`;
  const created = await request(ctx.origin, `${base}/provider-credentials/byok`, {
    method: "POST",
    token: ctx.owner,
    body: { modelProvider: "openai", key: "sk-proj-openai-plaintext-key-0004" },
  });
  const ok = await request(ctx.origin, `${base}/cloud-agents/${created.body.id}/check`, {
    method: "POST",
    token: ctx.owner,
    body: {},
  });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.status, "available");
  assert.equal(ctx.probes[0]!.url, "https://api.openai.com/v1/models");
  assert.equal(ctx.probes[0]!.headers.authorization, "Bearer sk-proj-openai-plaintext-key-0004");

  ctx.setProbeStatus(401);
  const rejected = await request(ctx.origin, `${base}/cloud-agents/${created.body.id}/check`, {
    method: "POST",
    token: ctx.owner,
    body: {},
  });
  assert.equal(rejected.body.status, "error");
  const listed = await request(ctx.origin, `${base}/cloud-agents`, { token: ctx.owner });
  assert.equal(listed.body.agents[0].status, "error");
  assert.match(listed.body.agents[0].lastError, /rejected/);
  const env = await request(ctx.origin, `/internal/v1/workspaces/${ctx.workspaceId}/environment`, { token: SERVICE });
  assert.equal(env.body.env.OPENAI_API_KEY, undefined, "a rejected key is not delivered");
  const select = await request(ctx.origin, `${base}/cloud-agents/${created.body.id}/activate`, {
    method: "POST",
    token: ctx.owner,
    body: { selection: "model" },
  });
  assert.equal(select.status, 409);

  ctx.setProbeStatus(200);
  await request(ctx.origin, `${base}/cloud-agents/${created.body.id}/check`, {
    method: "POST",
    token: ctx.owner,
    body: {},
  });
  const recovered = await request(ctx.origin, `/internal/v1/workspaces/${ctx.workspaceId}/environment`, { token: SERVICE });
  assert.equal(recovered.body.env.OPENAI_API_KEY, "sk-proj-openai-plaintext-key-0004");

  const token = await request(ctx.origin, `${base}/provider-credentials/setup-token`, {
    method: "POST",
    token: ctx.owner,
    body: { token: SETUP_TOKEN },
  });
  const probesBefore = ctx.probes.length;
  const unsupported = await request(ctx.origin, `${base}/cloud-agents/${token.body.id}/check`, {
    method: "POST",
    token: ctx.owner,
    body: {},
  });
  assert.equal(unsupported.body.status, "unsupported");
  assert.equal(ctx.probes.length, probesBefore, "no provider request for a setup token");
});

test("coding agents: migration 0006 deletes stored Daytona credentials", async () => {
  const database = new PGliteDatabase();
  const partial = await mkdtemp(join(tmpdir(), "rc-migrations-"));
  try {
    for (const name of await readdir(defaultMigrationsDirectory())) {
      if (name < "0006") await copyFile(join(defaultMigrationsDirectory(), name), join(partial, name));
    }
    await migrate(database, partial);
    const org = "11111111-1111-4111-8111-111111111111";
    const ws = "22222222-2222-4222-8222-222222222222";
    await database.query("INSERT INTO selfhost_organizations (id, name) VALUES ($1, 'Acme')", [org]);
    await database.query(
      "INSERT INTO selfhost_workspaces (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext) VALUES ($1, $2, 'W', 'rw_x', $3)",
      [ws, org, encryptSecret("rk_x", KEYRING.active)],
    );
    for (const [id, provider] of [["33333333-3333-4333-8333-333333333333", "daytona"], ["44444444-4444-4444-8444-444444444444", "openai"]]) {
      await database.query(
        `INSERT INTO selfhost_coding_agent_credentials
           (id, organization_id, workspace_id, model_provider, harness, auth_type, display_name,
            secret_ciphertext, secret_preview, key_fingerprint, is_active)
         VALUES ($1, $2, $3, $4, $4, 'byo_api_key', $4, $5, '••••', $6, true)`,
        [id, org, ws, provider, encryptSecret("k", KEYRING.active), `fp-${provider}`],
      );
    }
    assert.equal((await migrate(database))[0], "0006_coding_agents_drop_daytona.sql");
    const rows = await database.query<{ model_provider: string }>("SELECT model_provider FROM selfhost_coding_agent_credentials");
    assert.deepEqual(rows.rows.map((row) => row.model_provider), ["openai"]);
    await assert.rejects(database.query(
      `INSERT INTO selfhost_coding_agent_credentials
         (id, organization_id, workspace_id, model_provider, harness, auth_type, display_name,
          secret_ciphertext, secret_preview, key_fingerprint)
       VALUES ('55555555-5555-4555-8555-555555555555', $1, $2, 'daytona', 'daytona', 'byo_api_key', 'd', $3, '••••', 'f')`,
      [org, ws, encryptSecret("k", KEYRING.active)],
    ), "the provider check refuses daytona");
  } finally {
    await rm(partial, { recursive: true, force: true });
    await database.close();
  }
});
