import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createMcpOAuthProtocol, isAllowedRedirectUri, isValidCodeChallenge, isValidCodeVerifier,
  parseClientRegistration, pkceS256, type McpOAuthEndpoint,
} from "../src/mcp/oauth/protocol.js";

const ORIGIN = "https://relay.example.test";
const SHARED = "/api/v1/mcp/shared-sessions";
const EVENTS = "/api/v1/mcp/relay-events";
const SHARED_URL = `${ORIGIN}/cloud${SHARED}`;
const EVENTS_URL = `${ORIGIN}/cloud${EVENTS}`;
const REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect";
const client = { clientId: "mcpc_fake", redirectUris: [REDIRECT] };
const protocol = createMcpOAuthProtocol({ publicOrigin: ORIGIN, enabledResources: ["/mcp", SHARED, EVENTS],
  mountedEndpoints: ["authorization", "token", "registration", "revocation", "jwks"], oidcEnabled: true });
const params = (overrides: Record<string, string | undefined> = {}) => ({
  response_type: "code", client_id: client.clientId, redirect_uri: REDIRECT,
  code_challenge: pkceS256("a".repeat(43)), code_challenge_method: "S256",
  resource: SHARED_URL, state: "fake-state", ...overrides,
});

test("OAuth protocol defaults to no resources and snapshots explicitly enabled modules", () => {
  const disabled = createMcpOAuthProtocol({ publicOrigin: ORIGIN });
  assert.equal(disabled.parseMcpResource(EVENTS_URL), null);
  assert.throws(() => disabled.protectedResourceMetadata(EVENTS), /unavailable/);
  assert.deepEqual(disabled.authorizationServerMetadata().scopes_supported, []);
  const resources: Array<typeof SHARED | typeof EVENTS> = [SHARED];
  const core = createMcpOAuthProtocol({ publicOrigin: ORIGIN, enabledResources: resources });
  resources.push(EVENTS);
  assert.equal(core.parseMcpResource(EVENTS_URL), null);
  assert.deepEqual(core.authorizationServerMetadata().scopes_supported, []);
  assert.equal(core.parseMcpResource(SHARED_URL), SHARED);
  assert.throws(() => core.grantedScopesFor(EVENTS, undefined), /unavailable/);
  assert.throws(() => core.mcpResourceUrl(EVENTS), /unavailable/);
  assert.throws(() => core.protectedResourceMetadataUrl(EVENTS), /unavailable/);
});

test("issuer is configured, never inferred from request host, and public resource forms stay distinct", () => {
  for (const bad of ["", "http://public.example.test", `${ORIGIN}/cloud`, `${ORIGIN}?`, `${ORIGIN}#`,
    "https://user:secret@relay.example.test", "file:///var/run/test", `${ORIGIN}\n`]) {
    assert.throws(() => createMcpOAuthProtocol({ publicOrigin: bad }), /publicOrigin/);
  }
  assert.equal(createMcpOAuthProtocol({ publicOrigin: "http://127.0.0.1:3000" }).mcpOAuthIssuer(), "http://127.0.0.1:3000/cloud");
  assert.equal(protocol.mcpOAuthIssuer(), `${ORIGIN}/cloud`);
  assert.equal(protocol.parseMcpResource(`${ORIGIN}/mcp/`), "/mcp");
  assert.equal(protocol.parseMcpResource(`${SHARED_URL}/`), SHARED);
  for (const bad of [`${ORIGIN}/cloud/mcp`, `${ORIGIN}${SHARED}`, `${SHARED_URL}?extra=1`,
    `${SHARED_URL}#`, `${SHARED_URL}#fragment`, `https://user@relay.example.test/cloud${SHARED}`,
    `https://attacker.example.test/cloud${SHARED}`, "not a URL"]) {
    assert.equal(protocol.parseMcpResource(bad), null, bad);
  }
  assert.equal(protocol.protectedResourceMetadata("/mcp").resource, `${ORIGIN}/mcp`);
  assert.equal(protocol.protectedResourceMetadataUrl("/mcp"), `${ORIGIN}/.well-known/oauth-protected-resource/mcp`);
  assert.equal(protocol.protectedResourceMetadataUrl(SHARED), `${ORIGIN}/cloud/.well-known/oauth-protected-resource/cloud${SHARED}`);
  assert.ok(protocol.mcpOAuthChallenge(`https://attacker.example.test/cloud${SHARED}`).includes(`resource_metadata="${ORIGIN}/`));
});

test("Grok agent_name is one display hint, never an alternate audience", () => {
  const hint = `${EVENTS_URL}?agent_name=fake.bot_1-a`;
  assert.deepEqual(protocol.parseMcpResourceRequest(hint), { resourcePath: EVENTS, agentNameHint: "fake.bot_1-a" });
  assert.equal(protocol.canonicalMcpResourceParam(hint), EVENTS_URL);
  const result = protocol.validateAuthorizationRequest(params({ resource: hint }), client);
  assert.ok(result.ok);
  assert.equal(result.value.resource, EVENTS_URL);
  assert.equal(result.value.requestedAgentName, "fake.bot_1-a");
  for (const suffix of ["agent_name=", "agent_name=-bad", "agent_name=%0Abad", "agent_name=x&agent_name=y", "agent_name=x&extra=y", "AGENT_NAME=bot"]) {
    assert.equal(protocol.parseMcpResource(`${EVENTS_URL}?${suffix}`), null, suffix);
    assert.notEqual(protocol.canonicalMcpResourceParam(`${EVENTS_URL}?${suffix}`), EVENTS_URL);
  }
  assert.equal(protocol.parseMcpResource(`${SHARED_URL}?agent_name=bot`), null);
  assert.ok(protocol.mcpOAuthChallenge(hint).includes("?agent_name=fake.bot_1-a"));
  assert.ok(!protocol.mcpOAuthChallenge(`${EVENTS_URL}?agent_name=%22evil`).includes("agent_name"));
  assert.equal(protocol.protectedResourceMetadata(SHARED, "fake-bot").resource, SHARED_URL);
  assert.equal(protocol.protectedResourceMetadata(EVENTS, "-bad").resource, EVENTS_URL);
  assert.equal(protocol.protectedResourceMetadata(EVENTS, "fake-bot").resource, `${EVENTS_URL}?agent_name=fake-bot`);
  for (const raw of [`${EVENTS_URL}?agent_name=bot\n`, `${EVENTS_URL}?agent_name=bot#`, ` ${EVENTS_URL}?agent_name=bot`,
    `https://attacker.example.test/cloud${EVENTS}?agent_name=bot`]) {
    assert.equal(protocol.parseMcpResource(raw), null);
    assert.notEqual(protocol.canonicalMcpResourceParam(raw), EVENTS_URL);
  }
});

test("public client registration bounds redirect metadata and accepts no secret authentication", () => {
  for (const uri of [REDIRECT, "http://localhost:3000/callback", "http://127.0.0.1:5000/callback", "http://[::1]:5000/callback"]) {
    assert.equal(isAllowedRedirectUri(uri), true, uri);
  }
  for (const uri of ["http://localhost.attacker.test/cb", "http://192.168.1.1/cb", "javascript:alert(1)", `${REDIRECT}#`, `${REDIRECT}#x`,
    ` ${REDIRECT}`, `${REDIRECT}\n`, "https://user:secret@chatgpt.com/cb"]) assert.equal(isAllowedRedirectUri(uri), false, uri);
  assert.deepEqual(parseClientRegistration({ client_name: "  fake\u0000-client  ", redirect_uris: [REDIRECT, REDIRECT] }),
    { ok: true, value: { clientName: "fake-client", redirectUris: [REDIRECT] } });
  for (const body of [null, [], {}, { redirect_uris: Array(11).fill(REDIRECT) }, { redirect_uris: [42] },
    { redirect_uris: [REDIRECT], grant_types: ["password"] }, { redirect_uris: [REDIRECT], response_types: ["token"] },
    { redirect_uris: [REDIRECT], token_endpoint_auth_method: "client_secret_post" },
    { redirect_uris: [REDIRECT], id_token_signed_response_alg: "none" }, { redirect_uris: [REDIRECT], sector_identifier_uri: "https://other.test" }]) {
    assert.equal(parseClientRegistration(body).ok, false, JSON.stringify(body));
  }
});

test("PKCE S256 matches the RFC vector and rejects malformed verifier/challenge lengths", () => {
  assert.equal(pkceS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  for (const size of [43, 128]) assert.equal(isValidCodeVerifier("a".repeat(size)), true);
  for (const value of ["a".repeat(42), "a".repeat(129), "a".repeat(42) + " "]) assert.equal(isValidCodeVerifier(value), false);
  assert.equal(isValidCodeChallenge(pkceS256("fake")), true);
  assert.equal(isValidCodeChallenge("a".repeat(42)), false);
});

test("authorization failures redirect only after exact registered client/redirect trust", () => {
  assert.deepEqual(protocol.validateAuthorizationRequest(params(), null).ok, false);
  for (const overrides of [{ redirect_uri: "https://attacker.test/cb" }, { client_id: "mcpc_other" }]) {
    const result = protocol.validateAuthorizationRequest(params(overrides), client);
    assert.ok(!result.ok && !result.redirect);
  }
  for (const overrides of [{ response_type: "token" }, { code_challenge_method: "plain" }, { code_challenge: "bad" },
    { resource: `${ORIGIN}/api/admin` }]) {
    const result = protocol.validateAuthorizationRequest(params(overrides), client);
    assert.ok(!result.ok && result.redirect);
    assert.equal(result.redirectUri, REDIRECT);
  }
  const multiple = { ...client, redirectUris: [REDIRECT, "http://localhost:5000/cb"] };
  const ambiguous = protocol.validateAuthorizationRequest(params({ redirect_uri: undefined }), multiple);
  assert.ok(!ambiguous.ok && !ambiguous.redirect);
  assert.ok(protocol.validateAuthorizationRequest(params(), multiple).ok);
  assert.equal(protocol.validateAuthorizationRequest(params({ scope: "openid relay:mcp" }), multiple).ok, false);
});

test("oversized state fails locally rather than redirecting without the client's correlation value", () => {
  assert.deepEqual(protocol.validateAuthorizationRequest(params({ state: "x".repeat(4097) }), client), {
    ok: false, redirect: false,
    error: { error: "invalid_request", error_description: "state must be at most 4096 URL-encoded characters." },
  });
});

test("long opaque state survives consent and callbacks within a bounded encoded URL budget", () => {
  for (const state of ["x".repeat(2048), "x".repeat(4096), "é".repeat(682) + "xxxx"]) {
    for (const overrides of [{state}, {state,response_type:"token"}]) {
      const result=protocol.validateAuthorizationRequest(params(overrides),client);
      const response=result.ok ? {code:"fake-code",state:result.value.state}
        : result.redirect ? {...result.error,state:result.state} : assert.fail("accepted state should be echoed");
      const callback=new URL(protocol.authorizationResponseUrl(REDIRECT,response));
      assert.equal(callback.searchParams.get("state"),state);
      assert.ok(callback.toString().length < 8192);
    }
  }
  const tooLarge="é".repeat(682) + "xxxxx";
  assert.equal(new URLSearchParams({state:tooLarge}).toString().length - "state=".length,4097);
  const rejected=protocol.validateAuthorizationRequest(params({state:tooLarge}),client);
  assert.ok(!rejected.ok && !rejected.redirect);
});

test("authorization scopes stay resource-bound; OIDC is opt-in and iss accompanies success and denial", () => {
  assert.deepEqual(protocol.grantedScopesFor(SHARED, undefined), ["relay:mcp"]);
  assert.throws(() => protocol.grantedScopesFor(SHARED, "relay:events cli:auth"), /invalid_scope/);
  assert.deepEqual(protocol.grantedScopesFor(EVENTS, undefined), ["relay:events", "relay:mcp"]);
  assert.deepEqual(protocol.grantedAuthorizationScopes(EVENTS, "openid relay:events offline_access"), ["openid", "relay:events"]);
  const result = protocol.validateAuthorizationRequest(params({ scope: "openid relay:mcp", nonce: "fake-nonce" }), client);
  assert.ok(result.ok);
  assert.equal(result.value.oidcNonce, "fake-nonce");
  for (const response of [{ code: "fake-code", state: "fake-state" }, { error: "access_denied", state: "fake-state" }]) {
    const url = new URL(protocol.authorizationResponseUrl(REDIRECT, response));
    assert.equal(url.searchParams.get("iss"), `${ORIGIN}/cloud`);
    assert.equal(url.searchParams.get("state"), "fake-state");
  }
});

test("only Events step-up or genuine Grok callback permits baseline connection continuation", () => {
  const baseline = { resource: EVENTS_URL, scopes: ["relay:events"], redirectUri: REDIRECT };
  assert.equal(protocol.canContinueEventsConsent(baseline), false);
  assert.equal(protocol.canContinueEventsConsent({ ...baseline, scopes: ["relay:events", "relay:mcp", "relay:agents"] }), true);
  assert.equal(protocol.canContinueEventsConsent({ ...baseline, redirectUri: "https://www.cursor.com/agents/fake/callback" }), true);
  assert.equal(protocol.canContinueEventsConsent({ ...baseline, redirectUri: "https://x.ai/callback" }), true);
  assert.equal(protocol.canContinueEventsConsent({ ...baseline, redirectUri: "https://cursor.com.attacker.test/agents/fake" }), false);
  assert.equal(protocol.canContinueEventsConsent({ ...baseline, resource: SHARED_URL, redirectUri: "https://x.ai/callback" }), false);
});

test("OAuth denials carry no-store JSON-RPC challenges without header injection", async () => {
  const response = protocol.mcpOAuthUnauthorized({ url: SHARED_URL }, true);
  assert.equal(response.status, 401);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.match(response.headers.get("www-authenticate")!, /error="invalid_token"/);
  assert.deepEqual(await response.json(), { jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized" }, id: null });
  const denied = protocol.mcpOAuthInsufficientScope({ url: EVENTS_URL }, ["relay:events", "relay:mcp"]);
  assert.equal(denied.status, 403);
  assert.match(denied.headers.get("www-authenticate")!, /scope="relay:events relay:mcp"/);
  const header = protocol.mcpOAuthChallenge(EVENTS_URL, { description: 'bad"\\\r\nInjected: true' });
  assert.ok(!/[\r\n]/.test(header));
});

test("explicit scope requires resource access; omitted scope alone gets the baseline", () => {
  for (const scope of ["cli:auth", "openid", "offline_access", "relay:events", "", "  "]) {
    const result = protocol.validateAuthorizationRequest(params({ scope }), client);
    assert.ok(!result.ok && result.redirect, JSON.stringify({ scope, result }));
    assert.equal(result.error.error, "invalid_scope");
    assert.throws(() => protocol.grantedScopesFor(SHARED, scope), /invalid_scope/);
  }
  const omitted = protocol.validateAuthorizationRequest(params(), client);
  assert.ok(omitted.ok);
  assert.deepEqual(omitted.value.scopes, ["relay:mcp"]);
  assert.deepEqual(protocol.grantedScopesFor(SHARED, "cli:auth relay:mcp"), ["relay:mcp"]);
});

test("relative IncomingMessage URLs and malformed URLs produce safe bearer denials", () => {
  const relative = `/cloud${EVENTS}?agent_name=fake-bot`;
  const response = protocol.mcpOAuthUnauthorized({ url: relative }, true);
  assert.equal(response.status, 401);
  assert.match(response.headers.get("www-authenticate")!, /realm="Agent Relay"/);
  assert.ok(response.headers.get("www-authenticate")!.includes(`${ORIGIN}/cloud/.well-known/`));
  assert.ok(response.headers.get("www-authenticate")!.includes("agent_name=fake-bot"));
  const denied = protocol.mcpOAuthInsufficientScope({ url: relative }, ["relay:events"]);
  assert.equal(denied.status, 403);
  assert.match(denied.headers.get("www-authenticate")!, /error="insufficient_scope"/);
  assert.doesNotThrow(() => protocol.mcpOAuthUnauthorized({ url: "http://[invalid" }));
  assert.equal(protocol.mcpResourcePathFor("/cloud/mcp"), null);
  assert.equal(protocol.mcpResourcePathFor(SHARED), null);
  assert.ok(!protocol.mcpOAuthChallenge(`${ORIGIN}/cloud/mcp`).includes("resource_metadata"));
});

test("discovery advertises only mounted endpoints and separately enabled OIDC", () => {
  const discoveryOnly = createMcpOAuthProtocol({ publicOrigin: ORIGIN, enabledResources: [SHARED] });
  const metadata = discoveryOnly.authorizationServerMetadata();
  for (const field of ["authorization_endpoint", "token_endpoint", "registration_endpoint", "revocation_endpoint", "jwks_uri",
    "subject_types_supported", "id_token_signing_alg_values_supported", "claims_supported", "grant_types_supported"]) {
    assert.equal(Object.hasOwn(metadata, field), false, field);
  }
  assert.deepEqual(discoveryOnly.protectedResourceMetadata(SHARED).authorization_servers, []);
  const tokenOnly = createMcpOAuthProtocol({ publicOrigin: ORIGIN, mountedEndpoints: ["token"] }).authorizationServerMetadata();
  assert.equal(tokenOnly.token_endpoint, `${ORIGIN}/cloud/api/oauth/token`);
  assert.equal(Object.hasOwn(tokenOnly, "authorization_endpoint"), false);
  assert.equal(Object.hasOwn(tokenOnly, "revocation_endpoint_auth_methods_supported"), false);
  const oauth = createMcpOAuthProtocol({ publicOrigin: ORIGIN, enabledResources: [SHARED], mountedEndpoints: ["authorization", "token"] });
  assert.deepEqual(oauth.authorizationServerMetadata().scopes_supported, ["relay:mcp", "relay:agents"]);
  assert.equal(Object.hasOwn(oauth.authorizationServerMetadata(), "jwks_uri"), false);
  const narrowed = oauth.validateAuthorizationRequest(params({ scope: "openid relay:mcp" }), client);
  assert.ok(narrowed.ok);
  assert.deepEqual(narrowed.value.scopes, ["relay:mcp"]);
  assert.equal(narrowed.value.oidcNonce, null);
  const full = protocol.authorizationServerMetadata();
  assert.equal(full.authorization_endpoint, `${ORIGIN}/cloud/oauth/authorize`);
  assert.equal(full.token_endpoint, `${ORIGIN}/cloud/api/oauth/token`);
  assert.equal(full.registration_endpoint, `${ORIGIN}/cloud/api/oauth/register`);
  assert.equal(full.revocation_endpoint, `${ORIGIN}/cloud/api/oauth/revoke`);
  assert.equal(full.jwks_uri, `${ORIGIN}/cloud/.well-known/jwks.json`);
  assert.deepEqual(full.subject_types_supported, ["pairwise"]);
  assert.deepEqual(full.id_token_signing_alg_values_supported, ["RS256"]);
  const mounted: McpOAuthEndpoint[] = ["authorization", "token"];
  const snapshot = createMcpOAuthProtocol({ publicOrigin: ORIGIN, mountedEndpoints: mounted });
  mounted.push("registration", "revocation", "jwks");
  assert.equal(Object.hasOwn(snapshot.authorizationServerMetadata(), "registration_endpoint"), false);
  assert.equal(Object.hasOwn(snapshot.authorizationServerMetadata(), "revocation_endpoint"), false);
  assert.equal(Object.hasOwn(snapshot.authorizationServerMetadata(), "jwks_uri"), false);
  assert.throws(() => createMcpOAuthProtocol({ publicOrigin: ORIGIN, oidcEnabled: true }), /OIDC|oidc/);
});

test("challenge text is printable ASCII and can be passed to Headers", () => {
  for (const description of ['bad"\\\r\nInjected: true', "accent é; snowman ☃; emoji 🐱", "\u0000\u007f\u0080"]) {
    const challenge = protocol.mcpOAuthChallenge(EVENTS_URL, { description });
    assert.match(challenge, /^[\x20-\x7e]+$/);
    assert.doesNotThrow(() => new Headers({ "www-authenticate": challenge }));
  }
});

test("empty state is echoed on success and errors; nonce only applies to granted OIDC", () => {
  for (const overrides of [{ state: "" }, { state: "", response_type: "token" }]) {
    const result = protocol.validateAuthorizationRequest(params(overrides), client);
    const response = result.ok ? { code: "fake-code", state: result.value.state }
      : result.redirect ? { error: result.error.error, state: result.state } : assert.fail("trusted redirect expected");
    const url = new URL(protocol.authorizationResponseUrl(REDIRECT, response));
    assert.equal(url.searchParams.has("state"), true);
    assert.equal(url.searchParams.get("state"), "");
  }
  const withoutOidc = protocol.validateAuthorizationRequest(params({ nonce: "\u0000" }), client);
  assert.ok(withoutOidc.ok);
  assert.equal(withoutOidc.value.oidcNonce, null);
  const withOidc = protocol.validateAuthorizationRequest(params({ nonce: "\u0000", scope: "openid relay:mcp" }), client);
  assert.ok(!withOidc.ok && withOidc.redirect);
  assert.equal(withOidc.error.error, "invalid_request");
});

test("OAuth responses replace stale callback fields and preserve unrelated query parameters", () => {
  const callback = `${REDIRECT}?app=keep&code=stale&code=another&error=access_denied&error_description=stale&error_uri=https%3A%2F%2Fstale.test&state=old&iss=https%3A%2F%2Fstale.test`;
  const success = new URL(protocol.authorizationResponseUrl(callback, { code: "fresh-code", state: null }));
  assert.deepEqual(success.searchParams.getAll("code"), ["fresh-code"]);
  for (const key of ["error", "error_description", "error_uri", "state"]) assert.equal(success.searchParams.has(key), false, key);
  assert.equal(success.searchParams.get("app"), "keep");
  assert.deepEqual(success.searchParams.getAll("iss"), [`${ORIGIN}/cloud`]);
  const denied = new URL(protocol.authorizationResponseUrl(callback, { error: "access_denied", state: "" }));
  assert.equal(denied.searchParams.has("code"), false);
  assert.equal(denied.searchParams.has("error_description"), false);
  assert.equal(denied.searchParams.has("error_uri"), false);
  assert.deepEqual(denied.searchParams.getAll("error"), ["access_denied"]);
  assert.deepEqual(denied.searchParams.getAll("state"), [""]);
  assert.equal(denied.searchParams.get("app"), "keep");
});

test("registration refuses product names ignoring case, spaces and hyphens, and over-long names instead of truncating", () => {
  for (const name of ["Agent Relay Desktop", "agent-relay-desktop", " AGENTRELAY desktop ", "Agent Relay", "agent_relay for macOS",
    "relay-dashboard", "Relay Dashboard", "RELAY-control", "Ａｇｅｎｔ Ｒｅｌａｙ"]) {
    assert.deepEqual(parseClientRegistration({ client_name: name, redirect_uris: [REDIRECT] }),
      { ok: false, error: { error: "invalid_client_metadata", error_description: "client_name is reserved." } }, name);
  }
  for (const name of ["Fake relay helper", "my agent relay", "Desktop"]) {
    assert.equal(parseClientRegistration({ client_name: name, redirect_uris: [REDIRECT] }).ok, true, name);
  }
  assert.deepEqual(parseClientRegistration({ client_name: "x".repeat(101), redirect_uris: [REDIRECT] }),
    { ok: false, error: { error: "invalid_client_metadata", error_description: "client_name must be at most 100 characters." } });
  assert.deepEqual(parseClientRegistration({ client_name: " " + "x".repeat(100) + "\u0000 ", redirect_uris: [REDIRECT] }),
    { ok: true, value: { clientName: "x".repeat(100), redirectUris: [REDIRECT] } });
  assert.equal(parseClientRegistration({ redirect_uris: Array.from({ length: 10 }, (_, index) => `${REDIRECT}/${index}`) }).ok, true);
  assert.equal(parseClientRegistration({ redirect_uris: Array.from({ length: 11 }, (_, index) => `${REDIRECT}/${index}`) }).ok, false);
});
