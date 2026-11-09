import assert from "node:assert/strict";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import { createAdminModule } from "../src/admin/routes.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * relayfile-agent workspace API tokens: minted by a workspace owner/admin,
 * presented by an agent to relayfile, verified through introspection.
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 5) } };
const FILES = "https://files.selfhosted.test";
const HISTORY = "https://history.selfhosted.test";
const AGENT_SCOPES = ["fs:read", "fs:write", "sync:read", "sync:trigger"];

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

async function setup(t: TestContext, extra: Partial<Omit<SelfhostConfig, "sessionReadApi">> = {}) {
  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: HISTORY,
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: HISTORY, secret: "r".repeat(32) },
    introspectSecret: INTROSPECT_SECRET,
    introspectAudiences: [HISTORY, `${FILES}/`],
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: SERVICE,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/dashboard/`,
    port: 0,
    host: "127.0.0.1",
    ...extra,
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  const admin = createAdminModule({ config, database, keyring: KEYRING });
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
  for (const name of ["primary", "other"]) {
    const created = await request(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, relaycastApiKey: `rk_${name}` },
    });
    assert.equal(created.status, 201);
    workspaces.push(created.body.id as string);
  }
  const member = await request(origin, `/api/v1/organizations/${org.body.id}/memberships`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { email: "member@acme.test", name: "Member", role: "member" },
  });
  assert.equal(member.status, 200);
  const workspaceId = workspaces[0]!;
  const base = `/api/v1/workspaces/${workspaceId}/deployment-api-tokens`;
  const owner = await deviceToken(origin, org.body.owner.id, workspaceId);
  return {
    database,
    origin,
    base,
    organizationId: org.body.id as string,
    workspaceId,
    otherWorkspaceId: workspaces[1]!,
    owner,
    member: await deviceToken(origin, member.body.userId, workspaceId),
    mint: (body: Record<string, unknown>, token = owner) => request(origin, base, { method: "POST", token, body }),
    introspect: (body: Record<string, unknown>) =>
      request(origin, "/internal/v1/auth/introspect", { method: "POST", token: INTROSPECT_SECRET, body }),
  };
}

const agentBody = (agentName = "builder-1", extra: Record<string, unknown> = {}) => ({
  label: "relayfile agent",
  purpose: "relayfile-agent",
  agent_name: agentName,
  aud: FILES,
  neverExpires: true,
  ...extra,
});

test("relayfile-agent tokens: owner mints with agent_name and aud, fixed scopes, listed without the token", async (t) => {
  const ctx = await setup(t);
  const created = await ctx.mint(agentBody());
  assert.equal(created.status, 201);
  const accessToken = created.body.accessToken as string;
  assert.match(accessToken, /^sh_wk_/);
  assert.equal(created.body.purpose, "relayfile-agent");
  assert.deepEqual(created.body.scopes, AGENT_SCOPES);
  assert.equal(created.body.agent_name, "builder-1");
  assert.equal(created.body.aud, FILES);
  assert.equal(created.body.accessTokenExpiresAt, null);
  assert(!created.body.scopes.some((scope: string) => scope.startsWith("admin:")));

  const other = await ctx.mint({ label: "ci", purpose: "deployment" });
  assert.equal(other.status, 201);
  assert.equal(other.body.agent_name, null);
  assert.equal(other.body.aud, null);

  const listed = await request(ctx.origin, ctx.base, { token: ctx.owner });
  assert.equal(listed.status, 200);
  assert(!listed.raw.includes(accessToken), "the token value is shown once");
  const row = listed.body.tokens.find((token: any) => token.id === created.body.id);
  assert.equal(row.agent_name, "builder-1");
  assert.equal(row.aud, FILES);
  assert.equal(row.status, "active");

  const audit = await request(ctx.origin, `/api/v1/workspaces/${ctx.workspaceId}/admin/audit`, { token: ctx.owner });
  assert.equal(audit.status, 200);
  assert(!audit.raw.includes(accessToken));
  assert(audit.raw.includes(`${created.body.id} (relayfile-agent: builder-1 -> ${FILES})`));

  // Not a runtime credential.
  const runtime = await request(ctx.origin, `/internal/v1/workspaces/${ctx.workspaceId}/environment`, {
    token: accessToken,
  });
  assert.equal(runtime.status, 403);

  // An expiring agent token is fine too.
  const expiring = await ctx.mint(agentBody("builder-2", { neverExpires: undefined, expiryDays: 7 }));
  assert.equal(expiring.status, 201);
  assert.notEqual(expiring.body.accessTokenExpiresAt, null);
});

test("relayfile-agent mint rules: member denied, agent_name and aud validated, one live token per agent", async (t) => {
  const ctx = await setup(t);
  assert.equal((await ctx.mint(agentBody(), ctx.member)).status, 403);

  for (const agentName of [undefined, "", "has space", "x".repeat(201), 42, "a/b"]) {
    const bad = await ctx.mint(agentBody("unused", { agent_name: agentName }));
    assert.equal(bad.status, 400, `agent_name ${String(agentName)}`);
    assert.equal(bad.body.error, "invalid_request");
  }
  for (const aud of [undefined, "https://elsewhere.test", "not a url", "ftp://files.selfhosted.test", 7]) {
    assert.equal((await ctx.mint(agentBody("builder", { aud }))).status, 400, `aud ${String(aud)}`);
  }
  for (const purpose of ["deployment", "workflow", "agent-runtime"]) {
    assert.equal((await ctx.mint({ label: "x", purpose, agent_name: "builder" })).status, 400, purpose);
    assert.equal((await ctx.mint({ label: "x", purpose, aud: FILES })).status, 400, purpose);
  }

  // aud normalizes: case, trailing slash and the default port.
  const first = await ctx.mint(agentBody("builder", { aud: "HTTPS://Files.SelfHosted.test:443/" }));
  assert.equal(first.status, 201);
  assert.equal(first.body.aud, FILES);

  const duplicate = await ctx.mint(agentBody("builder"));
  assert.equal(duplicate.status, 409);
  assert.equal(duplicate.body.error, "agent_name_conflict");

  // Another agent name is fine.
  assert.equal((await ctx.mint(agentBody("builder.2"))).status, 201);

  // Revoking frees the name.
  assert.equal((await request(ctx.origin, `${ctx.base}/${first.body.id}`, { method: "DELETE", token: ctx.owner })).status, 204);
  assert.equal((await ctx.mint(agentBody("builder"))).status, 201);
});

test("relayfile-agent mint needs introspection enabled", async (t) => {
  const ctx = await setup(t, { introspectSecret: null });
  const refused = await ctx.mint(agentBody());
  assert.equal(refused.status, 400);
  assert.match(refused.body.message, /introspection/);
});

test("introspection answers for a relayfile-agent token as an agent principal", async (t) => {
  const ctx = await setup(t);
  const created = await ctx.mint(agentBody());
  const token = created.body.accessToken as string;
  const row = (await ctx.database.query<{ created_at: Date }>(
    "SELECT created_at FROM workspace_api_tokens WHERE id = $1",
    [created.body.id],
  )).rows[0]!;

  const before = Math.floor(Date.now() / 1_000);
  const active = await ctx.introspect({ token, aud: `${FILES}/`, workspace: ctx.workspaceId });
  assert.equal(active.status, 200);
  assert.equal(active.headers.get("cache-control"), "no-store");
  const { exp, ...rest } = active.body;
  assert.deepEqual(rest, {
    active: true,
    principal_type: "agent",
    sub: created.body.id,
    email: null,
    agent_name: "builder-1",
    machine_id: null,
    org: ctx.organizationId,
    workspace: ctx.workspaceId,
    scopes: AGENT_SCOPES,
    aud: FILES,
    iat: Math.floor(new Date(row.created_at).getTime() / 1_000),
    token_id: created.body.id,
  });
  assert(exp >= before + 3_590 && exp <= Math.floor(Date.now() / 1_000) + 3_610, `exp ${exp}`);
  assert(!active.raw.includes(token), "the response never carries the token");

  // workspace absent: the token's workspace is authoritative.
  const absent = await ctx.introspect({ token, aud: FILES });
  assert.equal(absent.body.active, true);
  assert.equal(absent.body.workspace, ctx.workspaceId);

  // An expiring token reports its own expiry.
  const expiring = await ctx.mint(agentBody("builder-2", { neverExpires: undefined, expiryDays: 7 }));
  const fixed = await ctx.introspect({ token: expiring.body.accessToken, aud: FILES });
  assert.equal(fixed.body.exp, Math.floor(Date.parse(expiring.body.accessTokenExpiresAt) / 1_000));
});

test("introspection inactive reasons for workspace API tokens", async (t) => {
  const ctx = await setup(t);
  const agent = (await ctx.mint(agentBody())).body;
  const inactive = async (body: Record<string, unknown>, reason: string) => {
    const result = await ctx.introspect(body);
    assert.equal(result.status, 200, reason);
    assert.deepEqual(result.body, { active: false, reason }, reason);
    for (const value of Object.values(body)) {
      if (typeof value === "string" && value.startsWith("sh_wk_")) assert(!result.raw.includes(value));
    }
  };

  // Another purpose: wrong-kind, whatever else is asked; no such token: unknown.
  for (const purpose of ["deployment", "workflow", "agent-runtime"]) {
    const other = await ctx.mint({ label: purpose, purpose, ...(purpose === "workflow" ? { neverExpires: true } : {}) });
    assert.equal(other.status, 201);
    await inactive({ token: other.body.accessToken, aud: FILES, workspace: ctx.workspaceId }, "wrong-kind");
    await request(ctx.origin, `${ctx.base}/${other.body.id}`, { method: "DELETE", token: ctx.owner });
    await inactive({ token: other.body.accessToken, aud: FILES }, "wrong-kind");
  }
  await inactive({ token: "sh_wk_not-a-token", aud: FILES }, "unknown");

  await inactive({ token: agent.accessToken, aud: HISTORY }, "audience");
  await inactive({ token: agent.accessToken, aud: "https://elsewhere.test" }, "audience");
  await inactive({ token: agent.accessToken, aud: FILES, workspace: ctx.otherWorkspaceId }, "workspace");
  await inactive({ token: agent.accessToken, aud: FILES, workspace: ctx.workspaceId, machine: "node-1" }, "machine_not_owned");
  await inactive({ token: agent.accessToken, aud: FILES, machine: "node-1" }, "machine_not_owned");

  const expiring = (await ctx.mint(agentBody("builder-2"))).body;
  await ctx.database.query(
    "UPDATE workspace_api_tokens SET expires_at = now() - interval '1 second' WHERE id = $1",
    [expiring.id],
  );
  await inactive({ token: expiring.accessToken, aud: FILES }, "expired");

  assert.equal((await request(ctx.origin, `${ctx.base}/${agent.id}`, { method: "DELETE", token: ctx.owner })).status, 204);
  await inactive({ token: agent.accessToken, aud: FILES }, "revoked");
  await inactive({ token: agent.accessToken, aud: HISTORY, workspace: ctx.otherWorkspaceId }, "revoked");
});
