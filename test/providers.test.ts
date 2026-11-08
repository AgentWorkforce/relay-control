import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { Ajv2020 } from "ajv/dist/2020.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { parse as parseYaml } from "yaml";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { planToolGroups, TOOL_GROUPS } from "../src/mcp/catalog.js";
import { migrate } from "../src/migrations.js";
import {
  PROVIDERS,
  providerDescriptor,
  providerStatuses,
  type ProviderId,
  type ProviderProbes,
} from "../src/providers/registry.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

const PUBLIC_ORIGIN = "https://control.internal.example";
const ALL_IDS: ProviderId[] = ["amp", "factory", "copilot", "capy", "replicas", "dot", "grok-bot"];
const STATE_KEYS = ["implemented", "configured", "enabled"] as const;

async function setup(t: TestContext, providerProbes?: ProviderProbes) {
  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseSchema: "public",
    databaseUrl: "unused-in-test",
    publicBaseUrl: PUBLIC_ORIGIN,
    relaycastUrl: "http://relaycast.internal",
    relaycastPublicUrl: "https://cast.selfhosted.example",
    relayauthUrl: null,
    relayhistoryUrl: "http://history.internal",
    relayhistoryPublicUrl: "https://history.selfhosted.test",
    relayauthApiKey: null,
    bootstrapToken: "bootstrap-token-that-is-at-least-32-bytes",
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    internalServiceToken: "service-token-that-is-at-least-32-bytes",
    oauthRedirectUrl: `${PUBLIC_ORIGIN}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${PUBLIC_ORIGIN}/`,
    port: 3000,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const server = createServer(createApp({ config, store, providerProbes }));
  const origin = await listen(server);
  t.after(async () => {
    await close(server);
    await database.close();
  });
  const post = (path: string, body: unknown) => request(origin, path, { method: "POST", token: config.bootstrapToken, body });
  const org = await post("/api/v1/organizations", { name: "Tenant", ownerEmail: "owner@example.test", ownerName: "Owner" });
  assert.equal(org.status, 201);
  const workspace = await post(`/api/v1/organizations/${org.body.id}/workspaces`, {
    name: "Primary", relaycastWorkspaceId: "rc-first", relaycastApiKey: "rk_live_first",
  });
  assert.equal(workspace.status, 201);
  const other = await post(`/api/v1/organizations/${org.body.id}/workspaces`, {
    name: "Other", relaycastWorkspaceId: "rc-other", relaycastApiKey: "rk_live_other",
  });
  assert.equal(other.status, 201);
  const started = await post("/api/v1/auth/device/start", { client_name: "providers-test" });
  assert.equal(started.status, 201);
  const approved = await post("/api/v1/auth/device/approve", {
    action: "approve", user_code: started.body.user_code, user_id: org.body.owner.id, workspace_id: workspace.body.id,
  });
  assert.equal(approved.status, 200);
  const tokens = await post("/api/v1/auth/device/token", { device_code: started.body.device_code });
  assert.equal(tokens.status, 200);
  return {
    origin,
    workspaceId: workspace.body.id as string,
    otherWorkspaceId: other.body.id as string,
    accessToken: tokens.body.access_token as string,
  };
}

function states(statuses: Array<Record<string, unknown>>, id: ProviderId) {
  const status = statuses.find(item => item.id === id);
  assert.ok(status, id);
  return Object.fromEntries(STATE_KEYS.map(key => [key, status[key]]));
}

test("the registry is frozen and lists every provider once with real MCP group ids", () => {
  assert.deepEqual(PROVIDERS.map(provider => provider.id), ALL_IDS);
  assert.ok(Object.isFrozen(PROVIDERS));
  const groupIds = new Set(Object.keys(TOOL_GROUPS));
  for (const provider of PROVIDERS) {
    assert.ok(Object.isFrozen(provider), provider.id);
    assert.ok(Object.isFrozen(provider.history), provider.id);
    assert.ok(Object.isFrozen(provider.mcpGroups), provider.id);
    for (const group of provider.mcpGroups) assert.ok(groupIds.has(group), `${provider.id}: ${group}`);
    assert.equal(providerDescriptor(provider.id), provider);
  }
  assert.equal(providerDescriptor("unknown"), undefined);
  assert.throws(() => { (PROVIDERS as unknown[]).push({}); }, TypeError);
  assert.throws(() => { (providerDescriptor("amp")!.mcpGroups as string[]).push("events"); }, TypeError);
  assert.deepEqual(providerDescriptor("capy")!.mcpGroups, ["capy_binding", "capy_launch"]);
  assert.deepEqual(providerDescriptor("copilot")!.history, { kind: "desktop_owned", source: null, coverage: "n_a" });
  assert.equal(providerDescriptor("dot")!.history.source, "chatgpt");
});

test("default probes report every provider as not implemented, configured or enabled", async () => {
  const statuses = await providerStatuses();
  assert.equal(statuses.length, ALL_IDS.length);
  const planned = new Set(planToolGroups().map(entry => entry.group));
  for (const status of statuses) {
    assert.deepEqual(states(statuses, status.id), { implemented: false, configured: false, enabled: false });
    // None of the providers' groups is in the self-host plan on main.
    assert.equal(status.mcpGroupsRegistered, status.mcpGroups.length > 0 && status.mcpGroups.every(group => planned.has(group)));
    assert.equal(status.mcpGroupsRegistered, false);
  }
  // Status objects are copies: mutating one leaves the registry intact.
  statuses[0]!.mcpGroups.push("events");
  assert.deepEqual(providerDescriptor("amp")!.mcpGroups, ["amp"]);
});

test("an injected probe changes exactly its provider, each state separately", async () => {
  const statuses = await providerStatuses({
    factory: { implemented: true, configured: () => false, enabled: async () => true },
    dot: { implemented: false, configured: async () => true, enabled: () => { throw new Error("boom"); } },
  });
  assert.deepEqual(states(statuses, "factory"), { implemented: true, configured: false, enabled: true });
  assert.deepEqual(states(statuses, "dot"), { implemented: false, configured: true, enabled: false });
  for (const id of ALL_IDS.filter(id => id !== "factory" && id !== "dot")) {
    assert.deepEqual(states(statuses, id), { implemented: false, configured: false, enabled: false }, id);
  }
});

test("GET /api/v1/workspaces/:id/providers serves members only, on both mounts", async (t) => {
  const env = await setup(t, { copilot: { implemented: true, configured: () => true, enabled: () => false } });
  const path = `/api/v1/workspaces/${env.workspaceId}/providers`;

  const spec = parseYaml(readFileSync(new URL("../openapi.yaml", import.meta.url), "utf8"));
  const ajv = new Ajv2020({ strict: false });
  const validate = ajv.compile(spec.components.schemas.ProviderStatus);

  for (const route of [path, `/cloud${path}`]) {
    const ok = await request(env.origin, route, { token: env.accessToken });
    assert.equal(ok.status, 200, route);
    assert.equal(ok.headers.get("cache-control"), "no-store");
    assert.deepEqual(Object.keys(ok.body), ["providers"]);
    assert.deepEqual(ok.body.providers, await providerStatuses({
      copilot: { implemented: true, configured: () => true, enabled: () => false },
    }));
    for (const status of ok.body.providers) assert.ok(validate(status), JSON.stringify(validate.errors));
    assert.deepEqual(states(ok.body.providers, "copilot"), { implemented: true, configured: true, enabled: false });
  }

  const unauthenticated = await request(env.origin, path);
  assert.equal(unauthenticated.status, 401);
  assert.equal(unauthenticated.body.error, "unauthorized");

  for (const workspaceId of [env.otherWorkspaceId, "00000000-0000-4000-8000-000000000000"]) {
    const outside = await request(env.origin, `/api/v1/workspaces/${workspaceId}/providers`, { token: env.accessToken });
    assert.equal(outside.status, 404);
    assert.equal(outside.body.error, "workspace_not_found");
  }

  for (const method of ["POST", "PUT", "DELETE", "PATCH"]) {
    const refused = await request(env.origin, path, { method, token: env.accessToken, body: {} });
    assert.equal(refused.status, 405, method);
    assert.equal(refused.body.error, "method_not_allowed");
    assert.equal(refused.headers.get("allow"), "GET");
  }
});

test("describe_capabilities lists providers next to groups", async (t) => {
  const probes: ProviderProbes = { amp: { implemented: true, configured: () => false, enabled: () => false } };
  const env = await setup(t, probes);
  const client = new Client({ name: "providers-test", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${env.origin}/api/v1/mcp/shared-sessions`), {
    requestInit: { headers: { authorization: `Bearer ${env.accessToken}` } },
  }));
  t.after(() => client.close());
  const result = await client.callTool({ name: "describe_capabilities", arguments: {} });
  assert.notEqual(result.isError, true);
  const report = result.structuredContent as Record<string, any>;
  assert.ok(Array.isArray(report.groups));
  assert.deepEqual(report.providers, await providerStatuses(probes));
  assert.deepEqual(states(report.providers, "amp"), { implemented: true, configured: false, enabled: false });
  assert.deepEqual(states(report.providers, "factory"), { implemented: false, configured: false, enabled: false });
});
