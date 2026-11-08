import assert from "node:assert/strict";
import { test } from "node:test";
import { createMcpOAuthPublicHandlers, type McpOAuthPublicStore } from "../src/mcp/oauth/public-handlers.js";

function harness(allowRegistration = true) {
  const calls: Array<{ operation: string; input: unknown }> = [];
  const store: McpOAuthPublicStore = {
    async registerMcpOAuthClient(input) {
      calls.push({ operation: "register", input });
      return { ...input, clientId: "mcpc_fake", createdAt: new Date("2026-01-01T00:00:00Z") };
    },
    async exchangeMcpOAuthAuthorizationCode(input) {
      calls.push({ operation: "code", input });
      return { ok: true, body: { access_token: "fake-access", token_type: "Bearer", expires_in: 3600, refresh_token: "fake-refresh", scope: "relay:mcp" } };
    },
    async refreshMcpOAuthToken(input) {
      calls.push({ operation: "refresh", input });
      return { ok: false, status: 400, error: { error: "invalid_target", error_description: "resource does not match the grant." } };
    },
    async revokeMcpOAuthToken(input) { calls.push({ operation: "revoke", input }); },
  };
  return { calls, handlers: createMcpOAuthPublicHandlers({ store, allowRegistration: () => allowRegistration }) };
}

function request(body: unknown, form = false) {
  return new Request("https://relay.example.test/cloud/api/oauth/token", { method: "POST",
    headers: { "Content-Type": form ? "application/x-www-form-urlencoded; charset=utf-8" : "application/json" },
    body: form ? new URLSearchParams(body as Record<string, string>).toString() : JSON.stringify(body) });
}

test("public registration retains Cloud public-client wire shape and requires its limiter", async () => {
  const { handlers, calls } = harness();
  const response = await handlers.register(request({ client_name: "fake-client", redirect_uris: ["https://client.example.test/cb"] }));
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await response.json();
  assert.equal(body.token_endpoint_auth_method, "none");
  assert.equal(body.client_id, "mcpc_fake");
  assert.equal(Object.hasOwn(body, "client_secret"), false);
  assert.equal(Object.hasOwn(body, "id_token_signed_response_alg"), false);
  assert.equal(calls.length, 1);
  const denied = harness(false);
  assert.equal((await denied.handlers.register(request({}))).status, 429);
  assert.equal(denied.calls.length, 0);
});

test("JSON and RFC form clients pass the same exact code, PKCE, redirect and audience to storage", async () => {
  for (const form of [false, true]) {
    const { handlers, calls } = harness();
    const response = await handlers.token(request({ grant_type: "authorization_code", client_id: "mcpc_fake", code: "fake-code",
      code_verifier: "fake-verifier", redirect_uri: "https://client.example.test/cb", resource: "https://relay.example.test/mcp" }, form));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("pragma"), "no-cache");
    assert.deepEqual(calls, [{ operation: "code", input: { code: "fake-code", clientId: "mcpc_fake", codeVerifier: "fake-verifier",
      redirectUri: "https://client.example.test/cb", resource: "https://relay.example.test/mcp" } }]);
  }
});

test("malformed JSON, missing credentials and unsupported flows never call token storage", async () => {
  const { handlers, calls } = harness();
  const malformed = new Request("https://relay.example.test", { method: "POST", headers: { "Content-Type": "application/json" }, body: "client_id=fake" });
  assert.equal((await handlers.token(malformed)).status, 400);
  for (const [body, status, error] of [[{}, 401, "invalid_client"],
    [{ client_id: "fake", grant_type: "authorization_code", code: "fake" }, 400, "invalid_request"],
    [{ client_id: "fake", grant_type: "password" }, 400, "unsupported_grant_type"]] as const) {
    const response = await handlers.token(request(body));
    assert.equal(response.status, status);
    assert.equal((await response.json()).error, error);
  }
  assert.equal(calls.length, 0);
});

test("refresh forwards client/audience binding and retains the store refusal", async () => {
  const { handlers, calls } = harness();
  const response = await handlers.token(request({ client_id: "mcpc_fake", grant_type: "refresh_token", refresh_token: "fake-refresh", resource: "https://wrong.example.test/mcp" }, true));
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "invalid_target");
  assert.deepEqual(calls, [{ operation: "refresh", input: { clientId: "mcpc_fake", refreshToken: "fake-refresh", resource: "https://wrong.example.test/mcp" } }]);
});

test("RFC7009 revocation conceals token existence and carries optional client binding", async () => {
  const { handlers, calls } = harness();
  const response = await handlers.revoke(request({ token: "fake-unknown", client_id: "mcpc_fake" }, true));
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(calls, [{ operation: "revoke", input: { token: "fake-unknown", clientId: "mcpc_fake" } }]);
});
