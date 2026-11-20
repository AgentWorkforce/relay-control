import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createAdminModule } from "../src/admin/routes.js";
import { createApp } from "../src/app.js";
import { loadConfig, type SelfhostConfig } from "../src/config.js";
import { STAFF_READ_GRANT_TOOLS } from "../src/mcp/catalog.js";
import { staffReadGrantAllows } from "../src/mcp/routes.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * Staff read grants (docs/staff-read-grants.md): an owner of the operator
 * organization, on the operator's domain, mints a short-lived sh_sr_
 * credential that reads one customer workspace's shared sessions over the
 * shared-sessions MCP facade, and nothing else.
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const HISTORY = "https://history.selfhosted.test";
// loadConfig accepts only public DNS names for public origins.
const LIVE_HISTORY = "https://history.selfhosted.company";
const TENANT_HISTORY = "https://history.tenant.selfhosted.company";
const RELAYFILE = "https://relayfile.selfhosted.company";
const MCP_PATH = "/api/v1/mcp/shared-sessions";

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

/**
 * `env` builds the config through loadConfig, as a deployment does: History
 * origins live only in relayhistoryAudiences, never in introspectAudiences.
 */
async function setup(t: TestContext, env?: Record<string, string>) {
  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = env ? {
    ...loadConfig({
      DATABASE_URL: "postgres://unused",
      SELFHOST_PUBLIC_URL: origin,
      RELAYCAST_URL: "http://relaycast.invalid",
      RELAYCAST_PUBLIC_URL: "https://relaycast.selfhosted.company",
      SESSION_READ_API_URL: "http://relayhistory.invalid",
      SESSION_READ_API_PUBLIC_URL: LIVE_HISTORY,
      RELAYHISTORY_PUBLIC_URL: LIVE_HISTORY,
      SESSION_READ_API_SECRET: "r".repeat(32),
      RELAYCONTROL_INTROSPECT_SECRET: INTROSPECT_SECRET,
      SELFHOST_BOOTSTRAP_TOKEN: BOOTSTRAP,
      SELFHOST_INTERNAL_TOKEN: SERVICE,
      SELFHOST_ENCRYPTION_KEY_ID: KEYRING.active.id,
      SELFHOST_ENCRYPTION_KEY: KEYRING.active.key.toString("base64"),
      ...env,
    }),
    port: 0,
    host: "127.0.0.1",
  } : {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: HISTORY,
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: HISTORY, secret: "r".repeat(32) },
    introspectSecret: INTROSPECT_SECRET,
    // What loadConfig produces: History only in its own audience list.
    introspectAudiences: [],
    relayhistoryAudiences: [HISTORY],
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: SERVICE,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/dashboard/`,
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
  const admin = createAdminModule({ config, database, keyring: KEYRING });
  control.on("request", createApp({ config, store, admin }));
  t.after(async () => {
    control.closeAllConnections();
    await close(control);
    await database.close();
  });

  const organization = async (name: string, ownerEmail: string) => {
    const created = await request(origin, "/api/v1/organizations", {
      method: "POST", token: BOOTSTRAP, body: { name, ownerEmail, ownerName: name },
    });
    assert.equal(created.status, 201);
    return { id: created.body.id as string, ownerId: created.body.owner.id as string };
  };
  const workspace = async (organizationId: string, name: string) => {
    const created = await request(origin, `/api/v1/organizations/${organizationId}/workspaces`, {
      method: "POST", token: BOOTSTRAP, body: { name, relaycastApiKey: `rk_${name}` },
    });
    assert.equal(created.status, 201);
    return created.body.id as string;
  };
  const member = async (organizationId: string, email: string, role: "member" | "owner" = "member") => {
    const added = await request(origin, `/api/v1/organizations/${organizationId}/memberships`, {
      method: "POST", token: BOOTSTRAP, body: { email, name: email, role },
    });
    assert.equal(added.status, 200);
    return added.body.userId as string;
  };
  const deviceToken = async (userId: string, workspaceId: string, desktopHostName?: string) => {
    const started = await request(origin, "/api/v1/auth/device/start", {
      method: "POST", body: desktopHostName ? { desktop_host_name: desktopHostName } : {},
    });
    assert.equal(started.status, 201);
    const approved = await request(origin, "/api/v1/auth/device/approve", {
      method: "POST", token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const issued = await request(origin, "/api/v1/auth/device/token", {
      method: "POST", body: { device_code: started.body.device_code },
    });
    assert.equal(issued.status, 200);
    return issued.body.access_token as string;
  };

  // The operator organization (recorded as the installation's own) and a customer.
  const operator = await organization("Operator", "staff@operator.test");
  const operatorWorkspace = await workspace(operator.id, "ops");
  await database.query(
    `INSERT INTO installation_bootstrap (installation_slot, organization_id) VALUES (1, $1)
     ON CONFLICT (installation_slot) DO UPDATE SET organization_id = EXCLUDED.organization_id`,
    [operator.id],
  );
  await database.query("INSERT INTO organization_domains (domain, organization_id) VALUES ('operator.test', $1)", [operator.id]);
  const customer = await organization("Customer", "owner@customer.test");
  const customerWorkspace = await workspace(customer.id, "primary");
  const otherCustomerWorkspace = await workspace(customer.id, "secondary");
  const staffToken = await deviceToken(operator.ownerId, operatorWorkspace);

  const grantsPath = (workspaceId = customerWorkspace) => `/api/v1/workspaces/${workspaceId}/staff-read-grants`;
  const mint = (token: string, body: Record<string, unknown> = { reason: "support ticket review" }, workspaceId = customerWorkspace) =>
    request(origin, grantsPath(workspaceId), { method: "POST", token, body });
  const mintGrant = async (body?: Record<string, unknown>) => {
    const minted = await mint(staffToken, body);
    assert.equal(minted.status, 201, `mint: ${minted.status} ${minted.body?.error ?? ""}`);
    return minted.body as { grant: Record<string, any>; token: { accessToken: string; workspaceId: string; expiresAt: string } };
  };
  const rpc = async (token: string, body: unknown, path = MCP_PATH, headers: Record<string, string> = {}) => {
    const response = await fetch(`${origin}${path}`, {
      method: "POST",
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        ...headers,
      },
      body: JSON.stringify(body),
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) as any : null };
  };
  const call = (token: string, name: string, args: Record<string, unknown> = {}) =>
    rpc(token, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } });
  const connect = async (token: string) => {
    const client = new Client({ name: "staff-read-grant-test", version: "1.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${origin}${MCP_PATH}`),
      { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
    t.after(() => client.close());
    return client;
  };
  const introspect = (body: Record<string, unknown>) =>
    request(origin, "/internal/v1/auth/introspect", { method: "POST", token: INTROSPECT_SECRET, body });
  const auditActions = async () => (await database.query<{ action: string; actor_id: string | null; organization_id: string | null; workspace_id: string | null; target: string | null }>(
    `SELECT action, actor_id, organization_id, workspace_id, target FROM admin_audit_events
      WHERE action LIKE 'staff_read_grant.%' ORDER BY created_at, id`,
  )).rows;

  return {
    database, origin, operator, operatorWorkspace, customer, customerWorkspace, otherCustomerWorkspace,
    staffToken, member, deviceToken, grantsPath, mint, mintGrant, rpc, call, connect, introspect, auditActions,
  };
}

test("staff mints over a CLI login, lists without token material, revokes idempotently with audit rows", async (t) => {
  const env = await setup(t);
  const minted = await env.mintGrant({ reason: "  support ticket review  ", expires_in_days: 7 });
  assert.match(minted.token.accessToken, /^sh_sr_/);
  assert.equal(minted.token.workspaceId, env.customerWorkspace);
  assert.equal(minted.grant.reason, "support ticket review");
  assert.equal(minted.grant.status, "active");
  assert.equal(minted.grant.staff_user_id, env.operator.ownerId);
  const days = (Date.parse(minted.grant.expires_at) - Date.parse(minted.grant.created_at)) / 86_400_000;
  assert.ok(Math.abs(days - 7) < 0.01, `expires after ${days} days`);
  const defaulted = await env.mintGrant();
  const defaultDays = (Date.parse(defaulted.grant.expires_at) - Date.parse(defaulted.grant.created_at)) / 86_400_000;
  // No expires_in_days: the default stays 90 days although the cap is 365.
  assert.ok(Math.abs(defaultDays - 90) < 0.01, `default expires after ${defaultDays} days`);

  // Stored only as a hash; never in a list or an audit row.
  const row = (await env.database.query<{ token_hash: string }>(
    "SELECT token_hash FROM staff_read_grants WHERE id = $1", [minted.grant.id])).rows[0]!;
  assert.equal(row.token_hash, sha256(minted.token.accessToken));
  const listed = await request(env.origin, env.grantsPath(), { token: env.staffToken });
  assert.equal(listed.status, 200);
  assert.equal(listed.body.workspace_id, env.customerWorkspace);
  assert.deepEqual(listed.body.grants.map((grant: any) => grant.id).sort(), [minted.grant.id, defaulted.grant.id].sort());
  const listedText = JSON.stringify(listed.body);
  for (const token of [minted.token.accessToken, defaulted.token.accessToken]) {
    assert.equal(listedText.includes(token), false);
    assert.equal(listedText.includes(sha256(token)), false);
    assert.equal(JSON.stringify(await env.auditActions()).includes(token), false);
  }

  const revoke = () => request(env.origin, `${env.grantsPath()}/${minted.grant.id}`, { method: "DELETE", token: env.staffToken });
  const revoked = await revoke();
  assert.equal(revoked.status, 200);
  assert.equal(revoked.body.grant.status, "revoked");
  assert.equal(revoked.body.grant.revoked_by, env.operator.ownerId);
  const again = await revoke();
  assert.equal(again.status, 200);
  assert.equal(again.body.grant.revoked_at, revoked.body.grant.revoked_at);
  const missing = await request(env.origin, `${env.grantsPath()}/${randomUUID()}`, { method: "DELETE", token: env.staffToken });
  assert.equal(missing.status, 404);
  const elsewhere = await request(env.origin, `${env.grantsPath(env.otherCustomerWorkspace)}/${defaulted.grant.id}`,
    { method: "DELETE", token: env.staffToken });
  assert.equal(elsewhere.status, 404);

  const audit = await env.auditActions();
  assert.deepEqual(audit.map((event) => event.action),
    ["staff_read_grant.minted", "staff_read_grant.minted", "staff_read_grant.revoked"]);
  for (const event of audit) {
    assert.equal(event.actor_id, env.operator.ownerId);
    assert.equal(event.organization_id, env.customer.id);
    assert.equal(event.workspace_id, env.customerWorkspace);
  }
  assert.equal(audit[2]!.target, `${minted.grant.id} workspace ${env.customerWorkspace}`);

  // The revoked credential no longer authenticates.
  assert.equal((await env.rpc(minted.token.accessToken, { jsonrpc: "2.0", id: 1, method: "tools/list" })).status, 401);
});

test("only an owner of the operator organization on its domain reaches the routes; every other caller gets 404", async (t) => {
  const env = await setup(t);
  const outsiderOrg = await request(env.origin, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, body: { name: "Outsider", ownerEmail: "boss@outsider.test", ownerName: "Boss" },
  });
  const outsiderWorkspace = (await request(env.origin, `/api/v1/organizations/${outsiderOrg.body.id}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "out", relaycastApiKey: "rk_out" },
  })).body.id as string;
  const outsider = await env.deviceToken(outsiderOrg.body.owner.id, outsiderWorkspace);
  const operatorMember = await env.deviceToken(await env.member(env.operator.id, "helper@operator.test"), env.operatorWorkspace);
  const customerOwner = await env.deviceToken(env.customer.ownerId, env.customerWorkspace);
  const customerMember = await env.deviceToken(await env.member(env.customer.id, "dev@customer.test"), env.customerWorkspace);

  // A Desktop session of the staff person (desktop:workspaces).
  const desktop = `sh_at_${randomUUID().replaceAll("-", "")}`;
  await env.database.query(
    `INSERT INTO token_sessions (id, token_family_id, user_id, organization_id, workspace_id, label, scopes,
       access_token_hash, refresh_token_hash, access_token_expires_at, refresh_token_expires_at)
     VALUES ($1, $1, $2, $3, $4, 'Agent Relay Desktop', $5, $6, $7, now() + interval '1 hour', now() + interval '1 day')`,
    [randomUUID(), env.operator.ownerId, env.operator.id, env.operatorWorkspace,
      ["cli:auth", "rth:read", "rth:sync", "rth:acquire", "desktop:workspaces"], sha256(desktop), sha256(`${desktop}-refresh`)],
  );
  // A device-code session Agent Relay Desktop started for the staff person
  // (DEVICE_SCOPES, the same as a CLI login, but the code names its host).
  const desktopDeviceCode = await env.deviceToken(env.operator.ownerId, env.operatorWorkspace, "build-01");
  // An enrollment-key session of the staff person.
  const key = await request(env.origin, `/api/v1/workspaces/${env.operatorWorkspace}/deployment-api-tokens`, {
    method: "POST", token: env.staffToken,
    body: { label: "laptop rollout", purpose: "desktop-enrollment", email: "staff@operator.test" },
  });
  assert.equal(key.status, 201);
  const enrolled = await request(env.origin, "/api/v1/auth/enrollment/token", {
    method: "POST", body: { enrollment_key: key.body.accessToken, client_name: "Agent Relay Desktop", desktop_host_name: "build-01" },
  });
  assert.equal(enrolled.status, 200);
  // A workspace runtime token. Self-host issues no launch-check token, so an
  // sh_lt_-shaped bearer is refused below as well.
  const runtime = await request(env.origin, `/api/v1/workspaces/${env.operatorWorkspace}/deployment-api-tokens`, {
    method: "POST", token: env.staffToken, body: { label: "runtime", purpose: "agent-runtime" },
  });
  assert.equal(runtime.status, 201);
  const grant = (await env.mintGrant()).token.accessToken;

  const refused: Array<[string, string]> = [
    ["outsider", outsider], ["operator member", operatorMember], ["customer owner", customerOwner],
    ["customer member", customerMember], ["desktop session", desktop],
    ["desktop device-code session", desktopDeviceCode], ["enrollment session", enrolled.body.access_token],
    ["runtime token", runtime.body.accessToken], ["the grant itself", grant], ["bootstrap", BOOTSTRAP],
    ["service token", SERVICE], ["garbage", "sh_at_not-a-token"],
    ["launch-check shape", `sh_lt_${randomUUID().replaceAll("-", "")}`],
  ];
  for (const [label, token] of refused) {
    for (const answer of [
      await env.mint(token),
      await request(env.origin, env.grantsPath(), { token }),
      await request(env.origin, `${env.grantsPath()}/${randomUUID()}`, { method: "DELETE", token }),
    ]) {
      assert.equal(answer.status, 404, `${label}: ${answer.status}`);
      assert.equal(answer.body.error, "not_found", label);
    }
  }
  assert.equal((await request(env.origin, env.grantsPath())).status, 404);
  // A grant credential never falls back to a membership anywhere else.
  assert.equal((await request(env.origin, `/api/v1/workspaces/${env.customerWorkspace}/admin/audit`, { token: grant })).status, 401);
  assert.equal((await request(env.origin, "/api/v1/auth/me", { token: grant })).status === 200, false);
  // Unknown workspace and a non-uuid id are 404 for staff too.
  assert.equal((await env.mint(env.staffToken, undefined, randomUUID())).status, 404);
  assert.equal((await request(env.origin, "/api/v1/workspaces/not-a-uuid/staff-read-grants", { token: env.staffToken })).status, 404);

  // The domain rule: an operator owner whose email is off the operator's domain is not staff.
  const offDomain = await env.deviceToken(await env.member(env.operator.id, "owner2@elsewhere.test", "owner"), env.operatorWorkspace);
  assert.equal((await env.mint(offDomain)).status, 404);
  // Without domain rows the owner rule alone applies.
  await env.database.query("DELETE FROM organization_domains WHERE organization_id = $1", [env.operator.id]);
  assert.equal((await env.mint(offDomain)).status, 201);
});

test("mint input is validated, the lifetime CHECK holds, and minting is rate limited", async (t) => {
  const env = await setup(t);
  const bad: Array<Record<string, unknown>> = [
    {}, { reason: "" }, { reason: "   " }, { reason: "x".repeat(501) }, { reason: 7 },
    { reason: "ok", expires_in_days: 0 }, { reason: "ok", expires_in_days: 366 }, { reason: "ok", expires_in_days: 1.5 },
    { reason: "ok", expires_in_days: "7" }, { reason: "ok", expires_in_days: -1 },
  ];
  for (const body of bad) {
    const answer = await env.mint(env.staffToken, body);
    assert.equal(answer.status, 400, JSON.stringify(body));
    assert.equal(answer.body.error, "invalid_request");
  }
  // The cap is 365 days (0080): a year may be asked for explicitly.
  const year = (await env.mintGrant({ reason: "x".repeat(500), expires_in_days: 365 })).grant;
  assert.equal(year.reason.length, 500);
  const yearDays = (Date.parse(year.expires_at) - Date.parse(year.created_at)) / 86_400_000;
  assert.ok(Math.abs(yearDays - 365) < 0.01, `expires after ${yearDays} days`);

  // The table enforces the same ceiling: 365 days fits, 366 does not.
  await env.database.query(
    `INSERT INTO staff_read_grants (id, workspace_id, organization_id, staff_user_id, staff_organization_id, reason, token_hash, expires_at)
     VALUES ($1, $2, $3, $4, $5, 'a year', $6, now() + interval '365 days')`,
    [randomUUID(), env.customerWorkspace, env.customer.id, env.operator.ownerId, env.operator.id, sha256("year")],
  );

  await assert.rejects(env.database.query(
    `INSERT INTO staff_read_grants (id, workspace_id, organization_id, staff_user_id, staff_organization_id, reason, token_hash, expires_at)
     VALUES ($1, $2, $3, $4, $5, 'too long', $6, now() + interval '366 days')`,
    [randomUUID(), env.customerWorkspace, env.customer.id, env.operator.ownerId, env.operator.id, sha256("x")],
  ), /staff_read_grant_lifetime/);
  // A grant cannot name a workspace under the wrong organization.
  await assert.rejects(env.database.query(
    `INSERT INTO staff_read_grants (id, workspace_id, organization_id, staff_user_id, staff_organization_id, reason, token_hash, expires_at)
     VALUES ($1, $2, $3, $4, $5, 'cross org', $6, now() + interval '1 day')`,
    [randomUUID(), env.customerWorkspace, env.operator.id, env.operator.ownerId, env.operator.id, sha256("y")],
  ), /staff_read_grant_workspace/);

  for (let index = 1; index < 10; index += 1) await env.mintGrant();
  const limited = await env.mint(env.staffToken);
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error, "rate_limited");
  // Ten minted grants plus the 365-day row inserted directly above.
  assert.equal((await env.database.query("SELECT 1 FROM staff_read_grants")).rows.length, 11);
});

test("the credential reaches only the shared-session read tools of its workspace", async (t) => {
  const env = await setup(t);
  const { token } = await env.mintGrant();
  const grant = token.accessToken;

  const client = await env.connect(grant);
  const tools = (await client.listTools()).tools.map((tool) => tool.name).sort();
  assert.deepEqual(tools, [...STAFF_READ_GRANT_TOOLS].sort());

  const report = (await client.callTool({ name: "describe_capabilities", arguments: {} })).structuredContent as Record<string, any>;
  assert.equal(report.connection.auth_mode, "staff_read_grant");
  assert.deepEqual(report.connection.scopes, ["rth:read"]);
  assert.equal(report.workspace.workspace_id, env.customerWorkspace);
  assert.equal(report.workspace.can_launch, false);
  const available = report.groups.filter((group: any) => group.status === "available").map((group: any) => group.id).sort();
  assert.deepEqual(available, ["capability_discovery", "shared_session_reads"]);
  const connect = report.groups.find((group: any) => group.id === "connect");
  assert.equal(connect.status, "unavailable");
  assert.match(connect.reason, /staff read grant/);

  // Another workspace is refused by the tool; its own workspace goes to History.
  const foreign = await env.call(grant, "search_shared_sessions", { query: "deploy", workspace_id: env.otherCustomerWorkspace });
  assert.equal(foreign.status, 200);
  assert.equal(foreign.body.result.isError, true);
  assert.match(foreign.body.result.content[0].text, /not available to this credential/);
  // The read is audited under the staff person, with the grant's auth mode.
  const audited = (await env.database.query<{ caller_user_id: string; workspace_id: string; auth_mode: string; identity_kind: string; outcome: string }>(
    "SELECT caller_user_id, workspace_id, auth_mode, identity_kind, outcome FROM shared_session_read_audit WHERE tool_name = 'search_shared_sessions'",
  )).rows;
  assert.deepEqual(audited, [{ caller_user_id: env.operator.ownerId, workspace_id: env.customerWorkspace,
    auth_mode: "staff_read_grant", identity_kind: "hosted", outcome: "error" }]);

  // Every other method and tool is refused before any server is built.
  const forbidden: unknown[] = [
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_team_activity", arguments: {} } },
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "send_relay_message", arguments: { to: "x", text: "y" } } },
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "create_connect", arguments: {} } },
    { jsonrpc: "2.0", id: 1, method: "resources/read", params: { uri: "ui://relay/inbox" } },
    { jsonrpc: "2.0", id: 1, method: "resources/list" },
    { jsonrpc: "2.0", method: "tools/call", params: { name: "list_team_activity", arguments: {} } },
    [
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "describe_capabilities", arguments: {} } },
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "list_relay_agents", arguments: {} } },
    ],
    [],
  ];
  for (const body of forbidden) {
    const answer = await env.rpc(grant, body);
    assert.equal(answer.status, 403, JSON.stringify(body));
    assert.equal(answer.body.error.code, -32003);
  }
  assert.equal(staffReadGrantAllows({ jsonrpc: "2.0", method: "notifications/initialized" }), true);
  assert.equal(staffReadGrantAllows({ jsonrpc: "2.0", id: 3, method: "ping" }), true);

  // A member session on the same facade keeps the full plan.
  const memberToken = await env.deviceToken(env.customer.ownerId, env.customerWorkspace);
  const memberTools = (await (await env.connect(memberToken)).listTools()).tools.map((tool) => tool.name);
  assert.ok(memberTools.includes("list_team_activity"));
  assert.ok(memberTools.length > STAFF_READ_GRANT_TOOLS.length);
});

test("forged rows, spoofed transports, revocation, expiry and a lost staff rule all stop the credential", async (t) => {
  const env = await setup(t);
  const list = (token: string, path?: string, headers?: Record<string, string>) =>
    env.rpc(token, { jsonrpc: "2.0", id: 1, method: "tools/list" }, path, headers);
  const { token, grant } = await env.mintGrant();
  const credential = token.accessToken;
  assert.equal((await list(credential)).status, 200);
  const used = (await env.database.query<{ last_used_at: Date | null }>(
    "SELECT last_used_at FROM staff_read_grants WHERE id = $1", [grant.id])).rows[0]!;
  assert.notEqual(used.last_used_at, null);

  // A forged row authenticates only the token whose hash it stores.
  const forged = `sh_sr_${randomUUID().replaceAll("-", "")}`;
  await env.database.query(
    `INSERT INTO staff_read_grants (id, workspace_id, organization_id, staff_user_id, staff_organization_id, reason, token_hash, expires_at)
     VALUES ($1, $2, $3, $4, $5, 'forged', $6, now() + interval '1 day')`,
    [randomUUID(), env.customerWorkspace, env.customer.id, env.operator.ownerId, env.operator.id, sha256(`${forged}x`)],
  );
  assert.equal((await list(forged)).status, 401);
  assert.equal((await list(`${credential}x`)).status, 401);
  // Header bearer only, shared-sessions facade only.
  const cookie = await fetch(`${env.origin}/cloud${MCP_PATH}`, {
    method: "POST",
    headers: { cookie: `agent_relay_session=${credential}`, "content-type": "application/json", accept: "application/json, text/event-stream", origin: env.origin },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  assert.equal(cookie.status, 401);
  await cookie.body?.cancel();
  assert.equal((await list(credential, `/cloud${MCP_PATH}`)).status, 200);
  assert.notEqual((await list(credential, "/mcp")).status, 200);
  // Spoofed desktop or workspace headers change nothing.
  const spoofed = await list(credential, MCP_PATH, { "x-agent-relay-desktop": "1", "x-workspace-id": env.otherCustomerWorkspace });
  assert.equal(spoofed.status, 200);

  // Introspection answers the desktop-user shape for its workspace only.
  const active = await env.introspect({ token: credential, aud: HISTORY });
  assert.equal(active.status, 200);
  assert.equal(active.body.active, true);
  assert.equal(active.body.principal_type, "desktop-user");
  assert.equal(active.body.sub, env.operator.ownerId);
  assert.equal(active.body.org, env.customer.id);
  assert.equal(active.body.workspace, env.customerWorkspace);
  assert.equal(active.body.role, "member");
  assert.deepEqual(active.body.scopes, ["rth:read"]);
  assert.equal(active.body.exp, Math.floor(Date.parse(grant.expires_at) / 1000));
  assert.equal((await env.introspect({ token: credential, aud: HISTORY, workspace: env.customerWorkspace })).body.active, true);
  for (const body of [
    { token: credential, aud: HISTORY, workspace: env.otherCustomerWorkspace },
    { token: credential, aud: HISTORY, machine: "build-01" },
    { token: credential, aud: "https://elsewhere.test" },
    { token: forged, aud: HISTORY },
  ]) {
    assert.equal((await env.introspect(body)).body.active, false, JSON.stringify(body));
  }

  // Demotion from owner ends the credential on the next request; restoring the role restores it.
  const setRole = (role: string) => env.database.query(
    "UPDATE organization_memberships SET role = $1 WHERE organization_id = $2 AND user_id = $3", [role, env.operator.id, env.operator.ownerId]);
  await setRole("member");
  assert.equal((await list(credential)).status, 401);
  assert.equal((await env.introspect({ token: credential, aud: HISTORY })).body.active, false);
  await setRole("owner");
  assert.equal((await list(credential)).status, 200);
  // Leaving the operator's domain ends it too.
  await env.database.query("UPDATE organization_domains SET domain = 'operator-renamed.test' WHERE organization_id = $1", [env.operator.id]);
  assert.equal((await list(credential)).status, 401);
  await env.database.query("UPDATE organization_domains SET domain = 'operator.test' WHERE organization_id = $1", [env.operator.id]);
  assert.equal((await list(credential)).status, 200);

  // Expiry.
  const second = await env.mintGrant();
  await env.database.query(
    "UPDATE staff_read_grants SET created_at = now() - interval '2 days', expires_at = now() - interval '1 second' WHERE id = $1",
    [second.grant.id]);
  assert.equal((await list(second.token.accessToken)).status, 401);
  assert.equal((await env.introspect({ token: second.token.accessToken, aud: HISTORY })).body.active, false);
  const listed = await request(env.origin, env.grantsPath(), { token: env.staffToken });
  assert.equal(listed.body.grants.find((row: any) => row.id === second.grant.id).status, "expired");

  // Revocation.
  assert.equal((await request(env.origin, `${env.grantsPath()}/${grant.id}`, { method: "DELETE", token: env.staffToken })).status, 200);
  assert.equal((await list(credential)).status, 401);
  assert.equal((await env.introspect({ token: credential, aud: HISTORY })).body.active, false);
});

test("introspection activates a grant only through the History audience fence", async (t) => {
  // A deployment's config: Relayfile is a general introspection audience,
  // History and a tenant's own History origin are History audiences.
  const env = await setup(t, {
    SELFHOST_INTROSPECT_AUDIENCES: RELAYFILE,
    SELFHOST_RELAYHISTORY_AUDIENCES: `${LIVE_HISTORY},${TENANT_HISTORY}`,
  });
  const credential = (await env.mintGrant()).token.accessToken;

  // A non-History service never sees the grant as active.
  const relayfile = await env.introspect({ token: credential, aud: RELAYFILE });
  assert.equal(relayfile.status, 200);
  assert.equal(relayfile.body.active, false);
  assert.equal(relayfile.body.reason, "audience");
  // History does, with History as the audience.
  const history = await env.introspect({ token: credential, aud: LIVE_HISTORY });
  assert.equal(history.body.active, true);
  assert.equal(history.body.aud, LIVE_HISTORY);
  assert.equal(history.body.workspace, env.customerWorkspace);
  // A tenant History origin is not the global workspace's History.
  const elsewhere = await env.introspect({ token: credential, aud: TENANT_HISTORY });
  assert.equal(elsewhere.body.active, false);
  assert.equal(elsewhere.body.reason, "audience");

  // A workspace with its own History origin: that origin only, never the global one.
  await env.database.query("UPDATE workspaces SET relayhistory_origin = $1 WHERE id = $2", [TENANT_HISTORY, env.customerWorkspace]);
  const tenant = await env.introspect({ token: credential, aud: TENANT_HISTORY });
  assert.equal(tenant.body.active, true);
  assert.equal(tenant.body.aud, TENANT_HISTORY);
  for (const aud of [LIVE_HISTORY, RELAYFILE]) {
    const refused = await env.introspect({ token: credential, aud });
    assert.equal(refused.body.active, false, aud);
    assert.equal(refused.body.reason, "audience", aud);
  }
});
