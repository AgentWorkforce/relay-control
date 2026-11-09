import assert from "node:assert/strict";
import { test } from "node:test";
import { createMcpOAuthConsentHandlers, McpOAuthContinuationError, mcpOAuthSetupHandoff,
  type McpConsentSession } from "../src/mcp/oauth/consent.js";
import { createMcpOAuthProtocol, pkceS256 } from "../src/mcp/oauth/protocol.js";

import { McpOAuthAgentNameTakenError } from "../src/mcp/oauth/store.js";

const ORIGIN = "https://relay.example.test";
const SHARED = "/api/v1/mcp/shared-sessions";
const EVENTS = "/api/v1/mcp/relay-events";
const client = { clientId: "mcpc_fake", clientName: "fake-client", redirectUris: ["https://client.example.test/cb"] };
const principal = { userId: "fake-user", organizationId: "fake-org", workspaceId: "fake-workspace", scopes: ["account"] };
const params = { client_id: client.clientId, response_type: "code", redirect_uri: client.redirectUris[0]!,
  code_challenge: pkceS256("fake-verifier"), code_challenge_method: "S256", resource: `${ORIGIN}/cloud${SHARED}`, state: "" };
const body = { params, decision: "approve", workspace_id: principal.workspaceId, agent_name: "fake-agent" };

function harness(options: { session?: McpConsentSession | null; access?: boolean; grok?: boolean; connected?: boolean;
  continuationError?: boolean; nameTakenError?: boolean; setup?: boolean;
  availability?: "available" | "yours" | "taken" | "unknown" | Error } = {}) {
  const calls: Array<{ operation: string; input?: unknown }> = [];
  const protocol = createMcpOAuthProtocol({ publicOrigin: ORIGIN, enabledResources: [SHARED, EVENTS] });
  const handlers = createMcpOAuthConsentHandlers({
    protocol,
    resolveSession: async () => options.session === undefined ? { transport: "cookie", principal } : options.session,
    workspaceAccess: async owner => { calls.push({ operation: "access", input: owner }); return options.access !== false; },
    checkAgentNameAvailability: async (owner, name) => {
      calls.push({ operation: "name", input: { owner, name } });
      if (options.availability instanceof Error) throw options.availability;
      return options.availability ?? "available";
    },
    store: {
      async getMcpOAuthClient(id) { calls.push({ operation: "client", input: id }); return id === client.clientId
        ? { ...client, redirectUris: options.grok ? ["https://www.cursor.com/agents/fake/callback"] : client.redirectUris } : null; },
      async createMcpOAuthAuthorizationCode(request, owner, continuation) {
        calls.push({ operation: "code", input: { request, owner, continuation } });
        if (options.nameTakenError) throw new McpOAuthAgentNameTakenError();
        if (options.continuationError) throw new McpOAuthContinuationError("The selected connection changed.");
        return "mcpac_fake-code";
      },
      async listConnectedAgentNames(owner) { calls.push({ operation: "connected", input: owner });
        return options.connected ? [{ workspaceId: principal.workspaceId, agentName: "fake-agent" }] : []; },
    },
    grokSetupEnabled: options.setup,
    now: () => Date.parse("2026-01-01T00:00:00Z"),
  });
  return { handlers, calls };
}

function request(value: unknown = body, headers: Record<string, string> = {}, path = "/cloud/api/oauth/authorize") {
  return new Request(`${ORIGIN}${path}`, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN, ...headers }, body: JSON.stringify(value) });
}
function grokBody(extra = {}) {
  return { ...body, params: { ...params, redirect_uri: "https://www.cursor.com/agents/fake/callback", resource: `${ORIGIN}/cloud${EVENTS}`, scope: "relay:events" }, ...extra };
}

test("consent binds code to the authenticated tenant, ignoring user/org fields and preserving empty state", async () => {
  const { handlers, calls } = harness();
  const response = await handlers.authorize(request({ ...body, user_id: "fake-attacker", organization_id: "fake-other" }));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const redirect = new URL((await response.json()).redirect_to);
  assert.equal(redirect.searchParams.get("code"), "mcpac_fake-code");
  assert.equal(redirect.searchParams.get("state"), "");
  assert.equal(redirect.searchParams.get("iss"), `${ORIGIN}/cloud`);
  const call = calls.find(call => call.operation === "code")!.input as { owner: unknown };
  assert.deepEqual(call.owner, { userId: principal.userId, organizationId: principal.organizationId,
    workspaceId: principal.workspaceId, agentName: "fake-agent" });
});

test("bearer, absent session, legacy scopes and both handoff classes cannot consent via browser headers", async () => {
  for (const [session, status] of [[null, 401], [{ transport: "bearer", principal }, 401],
    [{ transport: "cookie", principal: { ...principal, scopes: ["relay:mcp"] } }, 403],
    [{ transport: "cookie", principal: { ...principal, pendingHandoff: true } }, 403],
    [{ transport: "cookie", principal: { ...principal, handoff: true, pendingHandoff: false } }, 403]] as const) {
    const { handlers, calls } = harness({ session: session as McpConsentSession | null });
    const response = await handlers.authorize(request(body, { "sec-fetch-site": "same-origin", authorization: "Bearer fake-token" }));
    assert.equal(response.status, status);
    assert.equal(calls.length, 0);
  }
  const { handlers } = harness();
  assert.equal((await handlers.authorize(request(body, {}, "/api/oauth/authorize"))).status, 401);
});

test("consent origin is the configured origin; missing/foreign origins fail before store access", async () => {
  for (const origin of ["https://attacker.example.test", "null", ""]) {
    const { handlers, calls } = harness();
    assert.equal((await handlers.authorize(request(body, { origin }))).status, 403);
    assert.equal(calls.length, 0);
  }
});

test("another workspace and revoked live access cannot issue a code", async () => {
  for (const [options, value] of [[{}, { ...body, workspace_id: "fake-other-workspace" }], [{ access: false }, body]] as const) {
    const { handlers, calls } = harness(options);
    const response = await handlers.authorize(request(value));
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, "invalid_workspace");
    assert.equal(calls.some(call => call.operation === "code"), false);
  }
});

test("untrusted callback is never redirected; trusted protocol failure and denial preserve issuer/state", async () => {
  const { handlers, calls } = harness();
  const untrusted = await handlers.authorize(request({ ...body, params: { ...params, redirect_uri: "https://attacker.example.test/cb" } }));
  assert.equal(untrusted.status, 400);
  assert.equal(Object.hasOwn(await untrusted.json(), "redirect_to"), false);
  for (const value of [{ ...body, params: { ...params, code_challenge_method: "plain" } }, { ...body, decision: "deny" }]) {
    const response = await handlers.authorize(request(value));
    const url = new URL((await response.json()).redirect_to);
    assert.equal(url.origin, "https://client.example.test");
    assert.equal(url.searchParams.get("state"), "");
    assert.equal(url.searchParams.get("iss"), `${ORIGIN}/cloud`);
    assert.ok(url.searchParams.has("error"));
  }
  assert.equal(calls.some(call => call.operation === "code"), false);
});

test("invalid/reserved agent names and malformed continuation never reach issuance", async () => {
  for (const value of [{ ...body, agent_name: "cloud-github" }, { ...body, agent_name: "-bad" }, { ...body, continue_grant_id: 3 }]) {
    const { handlers, calls } = harness();
    assert.equal((await handlers.authorize(request(value))).status, 400);
    assert.equal(calls.some(call => call.operation === "code"), false);
  }
});

test("Grok preserves one connection per agent and passes explicit continuation to the store", async () => {
  const occupied = harness({ grok: true, connected: true });
  assert.equal((await occupied.handlers.authorize(request(grokBody()))).status, 409);
  const existing = harness({ grok: true, connected: true });
  assert.equal((await existing.handlers.authorize(request(grokBody({ continue_grant_id: "fake-existing-grant" })))).status, 200);
  assert.equal(existing.calls.some(call => call.operation === "connected"), false);
  assert.equal((existing.calls.find(call => call.operation === "code")!.input as { continuation: string }).continuation, "fake-existing-grant");
  const changed = harness({ grok: true, continuationError: true });
  const response = await changed.handlers.authorize(request(grokBody({ continue_grant_id: "fake-existing-grant" })));
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "invalid_request");
});

test("Grok hint correlation never supplies identity and consumes only the matching tab hint", async () => {
  const id = "11111111-1111-1111-1111-111111111111";
  const cookie = `relay_grok_name_hint=${encodeURIComponent(JSON.stringify({ id, agentName: "fake-hint", expiresAt: Date.parse("2026-01-01T00:05:00Z") }))}`;
  for (const matches of [true, false]) {
    const { handlers, calls } = harness({ grok: true });
    const response = await handlers.authorize(request(grokBody({ name_handoff_id: matches ? id : "another-tab" }), { cookie }));
    assert.equal(Boolean(response.headers.get("set-cookie")), matches);
    const payload = await response.json();
    assert.equal(Object.hasOwn(payload, "setup_url"), false);
    assert.equal((calls.find(call => call.operation === "code")!.input as { owner: { agentName: string } }).owner.agentName, "fake-agent");
  }
  const setup = harness({ grok: true, setup: true });
  const response = await setup.handlers.authorize(request(grokBody()));
  const url = new URL((await response.json()).setup_url, ORIGIN);
  assert.equal(url.searchParams.get("handoff"), mcpOAuthSetupHandoff("mcpac_fake-code"));
  assert.equal(url.searchParams.get("workspace"), principal.workspaceId);
});

test("agent-name advisory stays session/workspace/live-member scoped", async () => {
  for (const [options, workspace, status] of [[{}, principal.workspaceId, 200], [{ access: false }, principal.workspaceId, 400], [{}, "fake-other", 400]] as const) {
    const { handlers, calls } = harness(options);
    const response = await handlers.agentName(new Request(`${ORIGIN}/cloud/api/oauth/authorize/agent-name?workspace_id=${workspace}&name=fake-agent`));
    assert.equal(response.status, status);
    assert.equal(calls.some(call => call.operation === "name"), status === 200);
  }
});


test("SQL store typed name collision maps to 409 even after advisory preflight passed", async () => {
  const { handlers }=harness({ nameTakenError:true });
  const response=await handlers.authorize(request());
  assert.equal(response.status,409);
  assert.equal((await response.json()).error,"agent_name_taken");
});

test("a new connection to the user's own agent needs attach_existing; another member's or a retiring name is refused", async () => {
  const yours = harness({ availability: "yours" });
  const refused = await yours.handlers.authorize(request());
  assert.equal(refused.status, 409);
  assert.equal((await refused.json()).error, "agent_name_in_use");
  assert.equal((await yours.handlers.authorize(request({ ...body, attach_existing: "true" }))).status, 400);
  assert.equal(yours.calls.some(call => call.operation === "code"), false);
  assert.equal((await yours.handlers.authorize(request({ ...body, attach_existing: true }))).status, 200);
  assert.deepEqual((yours.calls.find(call => call.operation === "name")!.input as { name: string }).name, "fake-agent");
  const taken = harness({ availability: "taken" });
  const response = await taken.handlers.authorize(request({ ...body, attach_existing: true }));
  assert.equal(response.status, 409);
  assert.equal((await response.json()).error, "agent_name_taken");
  assert.equal(taken.calls.some(call => call.operation === "code"), false);
  const denied = harness({ availability: "taken" });
  assert.ok(new URL((await (await denied.handlers.authorize(request({ ...body, decision: "deny" }))).json()).redirect_to).searchParams.has("error"));
  assert.equal(denied.calls.some(call => call.operation === "name"), false);
});

test("an unknown name check fails closed and an explicit continuation skips it", async () => {
  for (const availability of ["unknown", new Error("fake relay outage")] as const) {
    const { handlers, calls } = harness({ availability });
    const response = await handlers.authorize(request({ ...body, attach_existing: true }));
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error, "temporarily_unavailable");
    assert.equal(calls.some(call => call.operation === "code"), false);
  }
  const continued = harness({ availability: "yours" });
  assert.equal((await continued.handlers.authorize(request({ ...body, continue_grant_id: "fake-existing-grant" }))).status, 200);
  assert.equal(continued.calls.some(call => call.operation === "name"), false);
});
