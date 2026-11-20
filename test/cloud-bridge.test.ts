import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { encryptSecret } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { bootstrapOnce, relaycastProvisioner } from "../src/identity/bootstrap.js";
import { loadIdentityConfig } from "../src/identity/config.js";
import { createIdentityModule } from "../src/identity/routes.js";
import { IdentityStore } from "../src/identity/store.js";
import { close, listen, PGliteDatabase } from "./support/harness.js";

// Session bridge for organizations moved from Agent Relay Cloud
// (docs/identity.md), end to end against a database: the start and consume
// routes, the account checks in IdentityStore.bridgeSignIn, the signed-out
// fence and the operator routes. The verifier and its settings alone are in
// cloud-bridge-verifier.test.ts.

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const ISSUER = "https://cloud.example.test";
const AUDIENCE = "https://control.example.test/cloud";
const HANDOFF_URL = "https://cloud.example.test/bridge/handoff";
const HANDOFF_ORIGIN = "https://cloud.example.test";
const KID = "bridge-key-1";
const SIGNER = generateKeyPairSync("ed25519");
const FORGER = generateKeyPairSync("ed25519");
const ATTEMPT_COOKIE = "agent_relay_cloud_bridge";
const CONSUME = "/cloud/api/v1/auth/cloud-bridge/consume";
const LABEL = "Browser sign-in (moved from Cloud)";

// ---- harness -------------------------------------------------------------------

type Res = { status: number; body: any; text: string; headers: Headers; cookies: Record<string, string>; setCookies: string[] };

async function call(origin: string, path: string, init: {
  method?: string;
  cookie?: string;
  token?: string;
  json?: unknown;
  form?: Record<string, string>;
  /** Defaults to the Control origin on non-GET requests; null sends none. */
  originHeader?: string | null;
} = {}): Promise<Res> {
  const headers: Record<string, string> = {};
  if (init.cookie) headers.cookie = init.cookie;
  if (init.token) headers.authorization = `Bearer ${init.token}`;
  let body: string | undefined;
  if (init.json !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(init.json);
  }
  if (init.form) {
    headers["content-type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(init.form).toString();
  }
  if (init.originHeader !== null && (init.method ?? "GET") !== "GET") headers.origin = init.originHeader ?? origin;
  const response = await fetch(`${origin}${path}`, { method: init.method ?? "GET", headers, body, redirect: "manual" });
  const text = response.status === 204 ? "" : await response.text();
  let parsed: any = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  const setCookies = response.headers.getSetCookie();
  const cookies: Record<string, string> = {};
  for (const line of setCookies) {
    const [pair] = line.split(";");
    const index = pair!.indexOf("=");
    cookies[pair!.slice(0, index)] = decodeURIComponent(pair!.slice(index + 1));
  }
  return { status: response.status, body: parsed, text, headers: response.headers, cookies, setCookies };
}

function fakeRelaycast() {
  const state = { creates: 0, secret: "relaycast-internal-secret-0123456789abcdef" };
  const server = createServer((req, res) => {
    const reply = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (req.headers.authorization !== `Bearer ${state.secret}`) return reply(401, { ok: false });
    if (req.method === "POST" && req.url === "/internal/workspaces") {
      state.creates += 1;
      return reply(201, { ok: true, data: { workspace_id: `24357777387973${state.creates}`, api_key: `ar_ws_test_key_${state.creates}`, name: "Default" } });
    }
    reply(404, {});
  });
  return { server, state };
}

type LogLine = { message: string; fields: Record<string, unknown> };

async function setup(t: test.TestContext, options: { enabled?: boolean; multi?: boolean; env?: Record<string, string> } = {}) {
  const database = new PGliteDatabase();
  await migrate(database);
  const relaycast = fakeRelaycast();
  const relaycastUrl = await listen(relaycast.server);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl,
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.test",
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: "https://history.selfhosted.test", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/`,
    port: 0,
    host: "127.0.0.1",
  };
  const identityConfig = loadIdentityConfig({
    SELFHOST_BOOTSTRAP_ORG_NAME: "Acme",
    SELFHOST_BOOTSTRAP_ADMIN_EMAIL: "Admin@Acme.test",
    RELAYCAST_INTERNAL_SECRET: relaycast.state.secret,
    ...(options.enabled === false ? {} : {
      SELFHOST_CLOUD_BRIDGE_ENABLED: "true",
      SELFHOST_CLOUD_BRIDGE_ISSUER: ISSUER,
      SELFHOST_CLOUD_BRIDGE_AUDIENCE: AUDIENCE,
      SELFHOST_CLOUD_BRIDGE_HANDOFF_URL: HANDOFF_URL,
      SELFHOST_CLOUD_BRIDGE_PUBLIC_KEYS: JSON.stringify({ keys: [{ ...SIGNER.publicKey.export({ format: "jwk" }), kid: KID }] }),
    }),
    ...(options.multi ? { SELFHOST_TENANCY: "multi" } : {}),
    ...options.env,
  });
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: identityConfig.tenancy.mode });
  const provisioner = relaycastProvisioner(relaycastUrl, relaycast.state.secret);
  const identityStore = new IdentityStore(database, KEYRING, {
    inviteTtlMs: identityConfig.inviteTtlMs,
    autoJoinDomains: identityConfig.autoJoinDomains,
    ...(options.multi ? { tenancy: identityConfig.tenancy, provisioner } : {}),
    issueSession: (tx, session) => store.issueBrowserSession(tx, session),
  });
  const logs: LogLine[] = [];
  // The routes' clock only: moves the attempt cookie's expiry and the
  // verifier's "now" without touching the database's.
  const clock = { offsetMs: 0 };
  const identity = createIdentityModule({
    config: identityConfig,
    identityStore,
    controlStore: store,
    keyring: KEYRING,
    dashboardUrl: config.dashboardUrl,
    mailer: null,
    now: () => Date.now() + clock.offsetMs,
    log: (message, fields) => logs.push({ message, fields: fields ?? {} }),
  });
  control.on("request", createApp({ config, store, identity }));
  t.after(async () => {
    await close(control);
    await close(relaycast.server);
    await database.close();
  });
  assert.equal(await bootstrapOnce({ bootstrap: identityConfig.bootstrap!, store: identityStore, provisioner, log: () => undefined }), "done");
  const organization = await database.query<{ id: string }>("SELECT id FROM organizations ORDER BY created_at LIMIT 1");
  const organizationId = organization.rows[0]!.id;
  const workspace = await database.query<{ id: string }>("SELECT id FROM workspaces WHERE organization_id = $1 ORDER BY created_at LIMIT 1", [organizationId]);
  return { database, origin, identityStore, store, logs, clock, organizationId, workspaceId: workspace.rows[0]!.id };
}

type Ctx = Awaited<ReturnType<typeof setup>>;

/** An imported person: the user row and, unless `member` is false, a membership. */
async function person(ctx: Ctx, email: string, options: { member?: boolean; role?: "owner" | "admin" | "member"; organizationId?: string } = {}): Promise<string> {
  const id = randomUUID();
  await ctx.database.query("INSERT INTO users (id, email, name) VALUES ($1, $2, $3)", [id, email, email.split("@")[0]]);
  if (options.member !== false) {
    await ctx.database.query(
      "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, $3)",
      [options.organizationId ?? ctx.organizationId, id, options.role ?? "member"],
    );
  }
  return id;
}

async function addWorkspace(ctx: Ctx, organizationId: string, name: string): Promise<string> {
  const id = randomUUID();
  await ctx.database.query(
    "INSERT INTO workspaces (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext) VALUES ($1, $2, $3, $4, $5)",
    [id, organizationId, name, `rc-${id}`, encryptSecret(`ar_ws_${id}`, KEYRING.active)],
  );
  return id;
}

async function openWindow(ctx: Ctx, organizationId = ctx.organizationId): Promise<Res> {
  const opened = await call(ctx.origin, `/api/v1/installation/cloud-bridge/organizations/${organizationId}`, {
    method: "PUT",
    token: BOOTSTRAP,
    json: { closesAt: new Date(Date.now() + 24 * 60 * 60 * 1_000).toISOString(), setBy: "migration operator" },
  });
  assert.equal(opened.status, 200, opened.text);
  return opened;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1_000);
}

function part(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

/** An assertion as Cloud signs it; undefined in `claims` drops that claim. */
function mint(claims: Record<string, unknown>, options: { header?: Record<string, unknown>; key?: KeyObject } = {}): string {
  const now = nowSeconds();
  const payload: Record<string, unknown> = {
    iss: ISSUER,
    aud: AUDIENCE,
    use: "browser",
    auth_time: now - 300,
    auth_method: "password",
    jti: randomUUID(),
    iat: now - 5,
    exp: now + 55,
    email: "ignored@example.test",
  };
  for (const [name, value] of Object.entries(claims)) {
    if (value === undefined) delete payload[name];
    else payload[name] = value;
  }
  const signingInput = `${part({ alg: "EdDSA", typ: "cloud-bridge+jwt", kid: KID, ...options.header })}.${part(payload)}`;
  return `${signingInput}.${sign(null, Buffer.from(signingInput), options.key ?? SIGNER.privateKey).toString("base64url")}`;
}

async function start(ctx: Ctx, next = "/") {
  const started = await call(ctx.origin, `/cloud/api/v1/auth/cloud-bridge/start?next=${encodeURIComponent(next)}`);
  assert.equal(started.status, 302, started.text);
  const location = new URL(started.headers.get("location")!);
  const value = started.cookies[ATTEMPT_COOKIE];
  assert(value, "attempt cookie");
  return { started, location, nonce: location.searchParams.get("nonce")!, attempt: `${ATTEMPT_COOKIE}=${encodeURIComponent(value)}` };
}

function consume(ctx: Ctx, assertion: string | null, init: { cookie?: string; originHeader?: string | null } = {}): Promise<Res> {
  return call(ctx.origin, CONSUME, {
    method: "POST",
    ...(assertion === null ? { form: {} } : { form: { assertion } }),
    ...(init.cookie ? { cookie: init.cookie } : {}),
    originHeader: init.originHeader === undefined ? HANDOFF_ORIGIN : init.originHeader,
  });
}

/** A full browser round trip: start, Cloud signs for the nonce, the handoff page posts. */
async function bridge(ctx: Ctx, claims: Record<string, unknown>, options: { next?: string; header?: Record<string, unknown>; key?: KeyObject } = {}) {
  const begun = await start(ctx, options.next);
  const assertion = mint({ nonce: begun.nonce, org_id: ctx.organizationId, ...claims }, options);
  const result = await consume(ctx, assertion, { cookie: begun.attempt });
  const session = result.cookies.agent_relay_session;
  return {
    ...begun,
    assertion,
    result,
    token: session ?? null,
    cookie: session ? `agent_relay_session=${encodeURIComponent(session)}` : null,
  };
}

function assertRefused(result: Res, code: string) {
  assert.equal(result.status, code === "cloud_bridge_invalid" ? 400 : 403, result.text);
  assert.equal(result.headers.get("x-error-code"), code);
  assert.equal(result.headers.get("cache-control"), "no-store");
  assert.equal(result.cookies.agent_relay_session, undefined, "no session cookie");
  assert(result.setCookies.some((line) => line.startsWith(`${ATTEMPT_COOKIE}=;`) && line.includes("Max-Age=0") && line.includes("SameSite=None")), "attempt cookie cleared");
}

function lastRefusal(ctx: Ctx): LogLine {
  const line = ctx.logs.filter((entry) => entry.message === "cloud bridge refused").at(-1);
  assert(line, "a refusal log line");
  return line;
}

async function count(ctx: Ctx, table: string): Promise<number> {
  const result = await ctx.database.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${table}`);
  return result.rows[0]!.n;
}

async function bridgeAudit(ctx: Ctx): Promise<Array<{ action: string; actor_kind: string; target: any; organization_id: string }>> {
  const result = await ctx.database.query<{ action: string; actor_kind: string; target: string; organization_id: string }>(
    "SELECT action, actor_kind, target, organization_id FROM admin_audit_events WHERE action LIKE '%cloud_bridge%' ORDER BY created_at, id",
  );
  return result.rows.map((row) => ({ ...row, target: JSON.parse(row.target) }));
}

async function latestSession(ctx: Ctx, userId: string) {
  const result = await ctx.database.query<{ workspace_id: string; organization_id: string; label: string }>(
    "SELECT workspace_id, organization_id, label FROM token_sessions WHERE user_id = $1 ORDER BY created_at DESC, id LIMIT 1",
    [userId],
  );
  return result.rows[0];
}

// ---- off by default --------------------------------------------------------------

test("cloud bridge off: every bridge route answers 404", async (t) => {
  const ctx = await setup(t, { enabled: false });
  for (const path of ["/cloud/api/v1/auth/cloud-bridge/start", "/api/v1/auth/cloud-bridge/start"]) {
    assert.equal((await call(ctx.origin, path)).status, 404, path);
  }
  for (const path of [CONSUME, "/api/v1/auth/cloud-bridge/consume"]) {
    assert.equal((await call(ctx.origin, path, { method: "POST", form: { assertion: "x" }, originHeader: HANDOFF_ORIGIN })).status, 404, path);
  }
  assert.equal((await call(ctx.origin, "/api/v1/installation/cloud-bridge/organizations", { token: BOOTSTRAP })).status, 404);
  const one = `/api/v1/installation/cloud-bridge/organizations/${ctx.organizationId}`;
  assert.equal((await call(ctx.origin, one, { method: "PUT", token: BOOTSTRAP, json: { closesAt: new Date(Date.now() + 60_000).toISOString(), setBy: "x" } })).status, 404);
  assert.equal((await call(ctx.origin, one, { method: "DELETE", token: BOOTSTRAP })).status, 404);
  assert.equal(await count(ctx, "cloud_bridge_organizations"), 0);
});

// ---- start -------------------------------------------------------------------------

test("cloud bridge start: only the nonce goes to Cloud; next stays in a SameSite=None cookie on the consume path", async (t) => {
  const ctx = await setup(t);
  const begun = await start(ctx, "/settings?tab=people");
  assert.equal(`${begun.location.origin}${begun.location.pathname}`, HANDOFF_URL);
  assert.deepEqual([...begun.location.searchParams.keys()], ["nonce"]);
  assert.match(begun.nonce, /^[A-Za-z0-9_-]{43}$/, "32 random bytes");
  const line = begun.started.setCookies.find((entry) => entry.startsWith(`${ATTEMPT_COOKIE}=`) && !entry.includes("Max-Age=0"));
  assert(line, "attempt Set-Cookie");
  for (const attribute of ["Path=/cloud/api/v1/auth/cloud-bridge/consume", "Max-Age=300", "Secure", "HttpOnly", "SameSite=None"]) {
    assert(line.split("; ").includes(attribute), `${attribute} in ${line}`);
  }
  // Encrypted: neither the nonce nor next is readable in the cookie.
  assert(!line.includes(begun.nonce));
  assert(!decodeURIComponent(line).includes("/settings"));
  // A second start makes a different nonce.
  assert.notEqual((await start(ctx)).nonce, begun.nonce);
  // The unprefixed path is the same route.
  assert.equal((await call(ctx.origin, "/api/v1/auth/cloud-bridge/start")).status, 302);
});

// ---- consume: success ---------------------------------------------------------------

test("cloud bridge consume: signs an imported member in without creating anything", async (t) => {
  const ctx = await setup(t);
  const alice = await person(ctx, "alice@acme.test");
  await openWindow(ctx);
  const before = {
    users: await count(ctx, "users"),
    organizations: await count(ctx, "organizations"),
    memberships: await count(ctx, "organization_memberships"),
    workspaces: await count(ctx, "workspaces"),
    invitations: await count(ctx, "organization_invitations"),
  };
  const signedIn = await bridge(ctx, { sub: alice, email: "someone-else@acme.test" }, { next: "/settings?tab=people" });
  assert.equal(signedIn.result.status, 303, signedIn.result.text);
  assert.equal(signedIn.result.headers.get("location"), "/settings?tab=people");
  const sessionLine = signedIn.result.setCookies.find((line) => line.startsWith("agent_relay_session="));
  assert(sessionLine?.includes("Path=/cloud"), sessionLine);
  assert(signedIn.result.setCookies.some((line) => line.startsWith(`${ATTEMPT_COOKIE}=;`) && line.includes("Max-Age=0")), "attempt cookie cleared");

  // The session is the user named by sub, never the one the email names.
  const me = await call(ctx.origin, "/cloud/api/v1/auth/whoami", { cookie: signedIn.cookie! });
  assert.equal(me.status, 200, me.text);
  assert.equal(me.body.user.id, alice);
  assert.equal(me.body.user.email, "alice@acme.test");
  assert.equal(me.body.currentOrganization.id, ctx.organizationId);
  const session = await latestSession(ctx, alice);
  assert.equal(session?.label, LABEL);
  assert.equal(session?.workspace_id, ctx.workspaceId);

  assert.deepEqual({
    users: await count(ctx, "users"),
    organizations: await count(ctx, "organizations"),
    memberships: await count(ctx, "organization_memberships"),
    workspaces: await count(ctx, "workspaces"),
    invitations: await count(ctx, "organization_invitations"),
  }, before);
  const jti = JSON.parse(Buffer.from(signedIn.assertion.split(".")[1]!, "base64url").toString()).jti;
  const accepted = (await bridgeAudit(ctx)).filter((row) => row.action === "auth.cloud_bridge.accepted");
  assert.equal(accepted.length, 1);
  assert.equal(accepted[0]!.actor_kind, "user");
  assert.deepEqual(accepted[0]!.target, { jti, authMethod: "password" });

  // auth_method is optional.
  const second = await bridge(ctx, { sub: alice, auth_method: undefined });
  assert.equal(second.result.status, 303, second.result.text);
  assert.equal((await bridgeAudit(ctx)).filter((row) => row.action === "auth.cloud_bridge.accepted").at(-1)!.target.authMethod, null);
});

test("cloud bridge consume: next is checked as a same-site path", async (t) => {
  const ctx = await setup(t);
  const alice = await person(ctx, "alice@acme.test");
  await openWindow(ctx);
  for (const next of ["https://evil.example/steal", "//evil.example/steal", "javascript:alert(1)"]) {
    const signedIn = await bridge(ctx, { sub: alice }, { next });
    assert.equal(signedIn.result.status, 303, signedIn.result.text);
    assert.equal(signedIn.result.headers.get("location"), "/", next);
  }
});

test("cloud bridge consume: the workspace claim is used when it is the organization's, else last used, else oldest", async (t) => {
  const ctx = await setup(t);
  const alice = await person(ctx, "alice@acme.test");
  const second = await addWorkspace(ctx, ctx.organizationId, "Second");
  await openWindow(ctx);
  // No claim and nothing used yet: the oldest workspace.
  assert.equal((await bridge(ctx, { sub: alice })).result.status, 303);
  assert.equal((await latestSession(ctx, alice))?.workspace_id, ctx.workspaceId);
  // The claim, when it names one of the organization's workspaces.
  assert.equal((await bridge(ctx, { sub: alice, workspace_id: second })).result.status, 303);
  assert.equal((await latestSession(ctx, alice))?.workspace_id, second);
  // No claim: the last used one, which is now the second.
  assert.equal((await bridge(ctx, { sub: alice })).result.status, 303);
  assert.equal((await latestSession(ctx, alice))?.workspace_id, second);
  // A claim naming no workspace of the organization is ignored.
  for (const workspace_id of [randomUUID(), "fixture-workspace-0001"]) {
    assert.equal((await bridge(ctx, { sub: alice, workspace_id })).result.status, 303);
    assert.equal((await latestSession(ctx, alice))?.workspace_id, second, workspace_id);
  }
});

test("cloud bridge consume (multi): a workspace of another organization is never chosen", async (t) => {
  const ctx = await setup(t, { multi: true });
  const alice = await person(ctx, "alice@acme.test");
  const otherOrganization = randomUUID();
  await ctx.database.query("INSERT INTO organizations (id, name) VALUES ($1, 'Other')", [otherOrganization]);
  const foreignWorkspace = await addWorkspace(ctx, otherOrganization, "Foreign");
  await openWindow(ctx);
  const signedIn = await bridge(ctx, { sub: alice, workspace_id: foreignWorkspace });
  assert.equal(signedIn.result.status, 303, signedIn.result.text);
  const session = await latestSession(ctx, alice);
  assert.equal(session?.organization_id, ctx.organizationId);
  assert.equal(session?.workspace_id, ctx.workspaceId);
});

// ---- consume: request and assertion refusals ------------------------------------------

test("cloud bridge consume: the Origin must be exactly the handoff page's", async (t) => {
  const ctx = await setup(t);
  const alice = await person(ctx, "alice@acme.test");
  await openWindow(ctx);
  for (const originHeader of [null, "null", ctx.origin, "http://cloud.example.test", "https://cloud.example.test.evil.example", "https://evil.example"]) {
    const begun = await start(ctx);
    const assertion = mint({ sub: alice, org_id: ctx.organizationId, nonce: begun.nonce });
    const refused = await consume(ctx, assertion, { cookie: begun.attempt, originHeader });
    assertRefused(refused, "cloud_bridge_invalid");
    assert.equal(lastRefusal(ctx).fields.reason, "origin", String(originHeader));
    // Refused before the assertion was read: it is still unspent.
    assert.equal(await ctx.identityStore.burnCloudBridgeAssertion(randomUUID(), new Date(Date.now() + 60_000)), true);
  }
  assert.equal(await count(ctx, "cloud_bridge_assertions"), 6, "only the probe ids above were spent");
  assert.equal(await count(ctx, "token_sessions"), 0);
});

test("cloud bridge consume: request and assertion refusals all answer cloud_bridge_invalid", async (t) => {
  const ctx = await setup(t);
  const alice = await person(ctx, "alice@acme.test");
  await openWindow(ctx);
  const refusedWith = async (reason: string, result: Res) => {
    assertRefused(result, "cloud_bridge_invalid");
    assert.equal(lastRefusal(ctx).fields.reason, reason);
  };

  // No attempt cookie, a tampered one, an expired one.
  await refusedWith("attempt_missing", await consume(ctx, mint({ sub: alice, org_id: ctx.organizationId, nonce: "x" })));
  await refusedWith("attempt_missing", await consume(ctx, mint({ sub: alice, org_id: ctx.organizationId, nonce: "x" }), { cookie: `${ATTEMPT_COOKIE}=tampered` }));
  {
    const begun = await start(ctx);
    ctx.clock.offsetMs = 5 * 60 * 1_000 + 1_000;
    await refusedWith("attempt_missing", await consume(ctx, mint({ sub: alice, org_id: ctx.organizationId, nonce: begun.nonce }), { cookie: begun.attempt }));
    ctx.clock.offsetMs = 0;
  }
  // No assertion field, a JSON body, garbage.
  {
    const begun = await start(ctx);
    await refusedWith("malformed", await consume(ctx, null, { cookie: begun.attempt }));
  }
  {
    const begun = await start(ctx);
    const json = await call(ctx.origin, CONSUME, {
      method: "POST",
      json: { assertion: mint({ sub: alice, org_id: ctx.organizationId, nonce: begun.nonce }) },
      cookie: begun.attempt,
      originHeader: HANDOFF_ORIGIN,
    });
    await refusedWith("malformed", json);
  }
  {
    const begun = await start(ctx);
    await refusedWith("malformed", await consume(ctx, "not.a.jws", { cookie: begun.attempt }));
  }
  // Assertion-level refusals through the route.
  const cases: Array<[string, Record<string, unknown>, { header?: Record<string, unknown>; key?: KeyObject }]> = [
    ["wrong_alg", {}, { header: { alg: "none" } }],
    ["wrong_type", {}, { header: { typ: "JWT" } }],
    ["unknown_kid", {}, { header: { kid: "elsewhere" } }],
    ["bad_signature", {}, { key: FORGER.privateKey }],
    ["wrong_issuer", { iss: "https://elsewhere.example.test" }, {}],
    ["wrong_audience", { aud: [AUDIENCE] }, {}],
    ["wrong_use", { use: "desktop_refresh" }, {}],
    ["expired", { iat: nowSeconds() - 200, exp: nowSeconds() - 100 }, {}],
    ["lifetime_too_long", { exp: nowSeconds() + 600 }, {}],
    ["nonce_mismatch", { nonce: "another-browser" }, {}],
  ];
  for (const [reason, claims, options] of cases) {
    const result = await bridge(ctx, { sub: alice, ...claims }, options);
    await refusedWith(reason, result.result);
  }
  assert.equal(await count(ctx, "token_sessions"), 0);
});

test("cloud bridge consume: two internal reasons look the same to the browser and differ in the log", async (t) => {
  const ctx = await setup(t);
  const alice = await person(ctx, "alice@acme.test");
  await openWindow(ctx);
  const forged = await bridge(ctx, { sub: alice }, { key: FORGER.privateKey });
  assert.equal(lastRefusal(ctx).fields.reason, "bad_signature");
  const mismatched = await bridge(ctx, { sub: alice, nonce: "another-browser" });
  assert.equal(lastRefusal(ctx).fields.reason, "nonce_mismatch");
  assert.equal(forged.result.status, mismatched.result.status);
  assert.equal(forged.result.headers.get("x-error-code"), mismatched.result.headers.get("x-error-code"));
  assert.equal(forged.result.text, mismatched.result.text);
});

test("cloud bridge consume: logs name claims only once the signature verified, and never the assertion or nonce", async (t) => {
  const ctx = await setup(t);
  const alice = await person(ctx, "alice@acme.test");
  await openWindow(ctx);
  const forged = await bridge(ctx, { sub: alice }, { key: FORGER.privateKey });
  const forgedLine = lastRefusal(ctx);
  assert.deepEqual(forgedLine.fields, { reason: "bad_signature", kid: KID });
  // A forgery leaves no audit row in the organization it names.
  assert.equal((await bridgeAudit(ctx)).filter((row) => row.action === "auth.cloud_bridge.refused").length, 0);

  const wrongUse = await bridge(ctx, { sub: alice, use: "desktop_refresh" });
  const line = lastRefusal(ctx);
  assert.equal(line.fields.reason, "wrong_use");
  assert.equal(line.fields.sub, alice);
  assert.equal(line.fields.orgId, ctx.organizationId);
  assert.equal(typeof line.fields.jti, "string");
  const refused = (await bridgeAudit(ctx)).filter((row) => row.action === "auth.cloud_bridge.refused");
  assert.equal(refused.length, 1);
  assert.equal(refused[0]!.organization_id, ctx.organizationId);
  assert.equal(refused[0]!.actor_kind, "service");
  assert.equal(refused[0]!.target.reason, "wrong_use");

  // A kid that is not plain base64url text is left out of the line.
  await bridge(ctx, { sub: alice }, { header: { kid: "bad kid <script>" } });
  assert.deepEqual(lastRefusal(ctx).fields, { reason: "unknown_kid" });

  const logged = JSON.stringify(ctx.logs);
  for (const attempt of [forged, wrongUse]) {
    for (const segment of attempt.assertion.split(".")) assert(!logged.includes(segment), "no assertion segment in the log");
    assert(!logged.includes(attempt.nonce), "no nonce in the log");
  }
});

// ---- replay ----------------------------------------------------------------------------

test("cloud bridge consume: an assertion is single use, even when its sign-in was refused", async (t) => {
  const ctx = await setup(t);
  const alice = await person(ctx, "alice@acme.test");
  const outsider = await person(ctx, "outsider@acme.test", { member: false });
  await openWindow(ctx);

  // Replaying an accepted assertion with the same browser's attempt cookie.
  const first = await bridge(ctx, { sub: alice });
  assert.equal(first.result.status, 303, first.result.text);
  const sessions = await count(ctx, "token_sessions");
  const replay = await consume(ctx, first.assertion, { cookie: first.attempt });
  assertRefused(replay, "cloud_bridge_invalid");
  assert.equal(lastRefusal(ctx).fields.reason, "replayed");
  assert.equal(await count(ctx, "token_sessions"), sessions);
  const audited = (await bridgeAudit(ctx)).filter((row) => row.action === "auth.cloud_bridge.refused");
  assert.equal(audited.length, 1);
  assert.equal(audited[0]!.target.reason, "replayed");
  assert.equal(audited[0]!.target.sub, alice);

  // A refused sign-in spends the assertion too: no second try.
  const refused = await bridge(ctx, { sub: outsider });
  assertRefused(refused.result, "cloud_bridge_not_member");
  assertRefused(await consume(ctx, refused.assertion, { cookie: refused.attempt }), "cloud_bridge_invalid");
  assert.equal(lastRefusal(ctx).fields.reason, "replayed");

  // The store: the first burn wins.
  const jti = randomUUID();
  const expires = new Date(Date.now() + 60_000);
  assert.equal(await ctx.identityStore.burnCloudBridgeAssertion(jti, expires), true);
  assert.equal(await ctx.identityStore.burnCloudBridgeAssertion(jti, expires), false);
});

// ---- consume: account refusals ----------------------------------------------------------

test("cloud bridge consume: account refusals have their own codes and create nothing", async (t) => {
  const ctx = await setup(t, {
    env: { SELFHOST_CLOUD_BRIDGE_MAX_AUTH_AGE_SECONDS: "3600", SELFHOST_AUTO_JOIN_DOMAINS: "acme.test" },
  });
  const alice = await person(ctx, "alice@acme.test");
  const bob = await person(ctx, "bob@acme.test");

  // user_unknown: no user has that id, whatever the email says.
  const before = { users: await count(ctx, "users"), memberships: await count(ctx, "organization_memberships") };
  await openWindow(ctx);
  assertRefused((await bridge(ctx, { sub: randomUUID(), email: "alice@acme.test" })).result, "cloud_bridge_user_unknown");
  assertRefused((await bridge(ctx, { sub: "fixture-user-0001" })).result, "cloud_bridge_user_unknown");
  assert.equal(lastRefusal(ctx).fields.reason, "user_unknown");

  // org_not_moved: no window, a closed window, a window not open yet, an unknown organization.
  await call(ctx.origin, `/api/v1/installation/cloud-bridge/organizations/${ctx.organizationId}`, { method: "DELETE", token: BOOTSTRAP });
  assertRefused((await bridge(ctx, { sub: alice })).result, "cloud_bridge_org_not_moved");
  await openWindow(ctx);
  await ctx.database.query(
    "UPDATE cloud_bridge_organizations SET opens_at = now() - interval '2 days', closes_at = now() - interval '1 day' WHERE organization_id = $1",
    [ctx.organizationId],
  );
  assertRefused((await bridge(ctx, { sub: alice })).result, "cloud_bridge_org_not_moved");
  const later = await call(ctx.origin, `/api/v1/installation/cloud-bridge/organizations/${ctx.organizationId}`, {
    method: "PUT",
    token: BOOTSTRAP,
    json: { opensAt: new Date(Date.now() + 60 * 60 * 1_000).toISOString(), closesAt: new Date(Date.now() + 2 * 60 * 60 * 1_000).toISOString(), setBy: "operator" },
  });
  assert.equal(later.status, 200, later.text);
  assertRefused((await bridge(ctx, { sub: alice })).result, "cloud_bridge_org_not_moved");
  const auditBefore = (await bridgeAudit(ctx)).length;
  assertRefused((await bridge(ctx, { sub: alice, org_id: randomUUID() })).result, "cloud_bridge_org_not_moved");
  assert.equal((await bridgeAudit(ctx)).length, auditBefore, "no audit row without an organization here");
  await openWindow(ctx);

  // not_member: an invitation, an auto-join domain and the admin email do not help.
  const outsider = await person(ctx, "outsider@acme.test", { member: false });
  const invited = await call(ctx.origin, `/api/v1/organizations/${ctx.organizationId}/invitations`, {
    method: "POST",
    token: BOOTSTRAP,
    json: { email: "outsider@acme.test", role: "member" },
  });
  assert.equal(invited.status, 201, invited.text);
  // The bootstrap admin's email, with its membership gone, does not regain one.
  const adminRow = await ctx.database.query<{ id: string }>("SELECT id FROM users WHERE email = 'admin@acme.test'");
  const admin = adminRow.rows[0]!.id;
  await ctx.database.query("DELETE FROM organization_memberships WHERE user_id = $1", [admin]);
  const membersBefore = await count(ctx, "organization_memberships");
  const invitationsBefore = await ctx.database.query<{ n: number }>("SELECT count(*)::int AS n FROM organization_invitations WHERE accepted_at IS NULL");
  for (const sub of [outsider, admin]) {
    assertRefused((await bridge(ctx, { sub })).result, "cloud_bridge_not_member");
    assert.equal(lastRefusal(ctx).fields.reason, "not_member");
  }
  assert.equal(await count(ctx, "organization_memberships"), membersBefore);
  assert.deepEqual(
    (await ctx.database.query<{ n: number }>("SELECT count(*)::int AS n FROM organization_invitations WHERE accepted_at IS NULL")).rows,
    invitationsBefore.rows,
  );

  // auth_too_old: older than the maximum age, or in the future beyond the skew.
  assertRefused((await bridge(ctx, { sub: bob, auth_time: nowSeconds() - 3_700 })).result, "cloud_bridge_auth_too_old");
  assertRefused((await bridge(ctx, { sub: bob, auth_time: nowSeconds() + 120 })).result, "cloud_bridge_auth_too_old");
  assert.equal((await bridge(ctx, { sub: bob, auth_time: nowSeconds() - 3_500 })).result.status, 303);

  assert.equal(await count(ctx, "users"), before.users + 1, "only the outsider this test inserted");
  assert.equal((await ctx.database.query("SELECT 1 FROM token_sessions WHERE user_id <> $1", [bob])).rows.length, 0);

  const reasons = (await bridgeAudit(ctx))
    .filter((row) => row.action === "auth.cloud_bridge.refused")
    .map((row) => row.target.reason);
  for (const reason of ["user_unknown", "org_not_moved", "not_member", "auth_too_old"]) {
    assert(reasons.includes(reason), `${reason} audited`);
  }
});

// ---- signed-out fence ------------------------------------------------------------------

test("cloud bridge fence: a sign-out here ends bridging for earlier Cloud sign-ins only", async (t) => {
  const ctx = await setup(t);
  const alice = await person(ctx, "alice@acme.test");
  await openWindow(ctx);
  const authTime = nowSeconds() - 300;

  const first = await bridge(ctx, { sub: alice, auth_time: authTime });
  assert.equal(first.result.status, 303, first.result.text);
  // (a) The person signs out through the normal token revoke route ...
  const revoked = await call(ctx.origin, "/api/v1/auth/token/revoke", { method: "POST", token: first.token! });
  assert.equal(revoked.status, 200, revoked.text);
  assert.equal((await call(ctx.origin, "/cloud/api/v1/auth/whoami", { cookie: first.cookie! })).status, 401);
  // ... and a kept copy of the same Cloud sign-in can no longer bridge.
  const sessions = await count(ctx, "token_sessions");
  const fenced = await bridge(ctx, { sub: alice, auth_time: authTime });
  assertRefused(fenced.result, "cloud_bridge_signed_out");
  assert.equal(lastRefusal(ctx).fields.reason, "signed_out");
  assert.equal(await count(ctx, "token_sessions"), sessions, "no session created");

  // (b) A Cloud sign-in after the sign-out still bridges.
  const fresh = await bridge(ctx, { sub: alice, auth_time: nowSeconds() + 1 });
  assert.equal(fresh.result.status, 303, fresh.result.text);
  assert.equal((await call(ctx.origin, "/cloud/api/v1/auth/whoami", { cookie: fresh.cookie! })).body.user.id, alice);
});

test("cloud bridge fence: a workspace switch is not a sign-out", async (t) => {
  const ctx = await setup(t);
  const bob = await person(ctx, "bob@acme.test");
  await openWindow(ctx);
  const authTime = nowSeconds() - 300;
  const first = await bridge(ctx, { sub: bob, auth_time: authTime });
  assert.equal(first.result.status, 303, first.result.text);
  // (c) Switching workspace ends the old session row with reason workspace_switch.
  const switched = await call(ctx.origin, "/cloud/api/auth/workspace", { method: "POST", cookie: first.cookie!, json: { workspaceId: ctx.workspaceId } });
  assert.equal(switched.status, 200, switched.text);
  const reasons = await ctx.database.query<{ revoked_reason: string }>(
    "SELECT revoked_reason FROM token_sessions WHERE user_id = $1 AND revoked_at IS NOT NULL",
    [bob],
  );
  assert.deepEqual(reasons.rows.map((row) => row.revoked_reason), ["workspace_switch"]);
  const again = await bridge(ctx, { sub: bob, auth_time: authTime });
  assert.equal(again.result.status, 303, again.result.text);
});

// ---- rate limits ---------------------------------------------------------------------

test("cloud bridge rate limits: per address on start and consume, per person once verified", async (t) => {
  const ctx = await setup(t);
  const outsider = await person(ctx, "outsider@acme.test", { member: false });
  await openWindow(ctx);
  // Per person: 10 verified assertions in 10 minutes, then 429.
  for (let index = 0; index < 10; index += 1) {
    assertRefused((await bridge(ctx, { sub: outsider })).result, "cloud_bridge_not_member");
  }
  const limited = await bridge(ctx, { sub: outsider });
  assert.equal(limited.result.status, 429, limited.result.text);
  assert.equal(ctx.logs.at(-1)?.message, "cloud bridge rate limited");
  // 11 starts so far; per address the 31st start in 5 minutes is refused.
  let status = 0;
  for (let index = 0; index < 20; index += 1) status = (await call(ctx.origin, "/cloud/api/v1/auth/cloud-bridge/start")).status;
  assert.equal(status, 429);
  // 11 consumes so far; the 31st is refused before anything is read.
  for (let index = 0; index < 20; index += 1) status = (await consume(ctx, "x")).status;
  assert.equal(status, 429);
});

// ---- operator routes ------------------------------------------------------------------

test("cloud bridge operator routes: bootstrap only, validated, audited", async (t) => {
  const ctx = await setup(t);
  const owner = await person(ctx, "owner@acme.test", { role: "owner" });
  const base = "/api/v1/installation/cloud-bridge/organizations";
  const one = `${base}/${ctx.organizationId}`;
  const closesAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1_000).toISOString();

  // Not the bootstrap bearer: refused, even for an owner of the organization.
  await openWindow(ctx);
  const ownerSession = await bridge(ctx, { sub: owner });
  assert.equal(ownerSession.result.status, 303, ownerSession.result.text);
  assert.equal((await call(ctx.origin, base, { token: ownerSession.token! })).status, 403);
  assert.equal((await call(ctx.origin, one, { method: "PUT", token: ownerSession.token!, json: { closesAt, setBy: "owner" } })).status, 403);
  assert.equal((await call(ctx.origin, one, { method: "DELETE", token: ownerSession.token! })).status, 403);
  assert.notEqual((await call(ctx.origin, base)).status, 200);
  await call(ctx.origin, one, { method: "DELETE", token: BOOTSTRAP });

  // Validation.
  const put = (path: string, json: unknown) => call(ctx.origin, path, { method: "PUT", token: BOOTSTRAP, json });
  const invalid: unknown[] = [
    { closesAt },
    { closesAt, setBy: "   " },
    { closesAt, setBy: "x".repeat(121) },
    { closesAt: "next week", setBy: "ops" },
    { closesAt, setBy: "ops", extra: true },
    { closesAt: new Date(Date.now() - 60_000).toISOString(), setBy: "ops" },
    { closesAt: new Date(Date.now() + 91 * 24 * 60 * 60 * 1_000).toISOString(), setBy: "ops" },
    { opensAt: closesAt, closesAt, setBy: "ops" },
  ];
  for (const body of invalid) {
    const refused = await put(one, body);
    assert.equal(refused.status, 400, JSON.stringify(body));
    assert.equal(refused.body.error, "invalid_request");
  }
  assert.equal((await put(`${base}/${randomUUID()}`, { closesAt, setBy: "ops" })).status, 404);
  assert.equal((await put(`${base}/not-an-id`, { closesAt, setBy: "ops" })).status, 404);
  const empty = randomUUID();
  await ctx.database.query("INSERT INTO organizations (id, name) VALUES ($1, 'Not imported yet')", [empty]);
  const emptyRefused = await put(`${base}/${empty}`, { closesAt, setBy: "ops" });
  assert.equal(emptyRefused.status, 409, emptyRefused.text);
  assert.equal(emptyRefused.body.error, "organization_empty");
  assert.equal(await count(ctx, "cloud_bridge_organizations"), 0);

  // Set, change, list, remove.
  const set = await put(one, { closesAt, setBy: "  Migration operator  " });
  assert.equal(set.status, 200, set.text);
  assert.equal(set.body.organizationId, ctx.organizationId);
  assert.equal(set.body.setBy, "Migration operator");
  assert.equal(Date.parse(set.body.closesAt), Date.parse(closesAt));
  assert(Date.parse(set.body.opensAt) <= Date.now());
  const changedCloses = new Date(Date.now() + 14 * 24 * 60 * 60 * 1_000).toISOString();
  assert.equal((await put(one, { closesAt: changedCloses, setBy: "Second operator" })).status, 200);
  const listed = await call(ctx.origin, base, { token: BOOTSTRAP });
  assert.equal(listed.status, 200, listed.text);
  assert.equal(listed.body.organizations.length, 1);
  assert.equal(listed.body.organizations[0].setBy, "Second operator");
  assert.equal(Date.parse(listed.body.organizations[0].closesAt), Date.parse(changedCloses));

  const removed = await call(ctx.origin, one, { method: "DELETE", token: BOOTSTRAP });
  assert.equal(removed.status, 204);
  assert.equal((await call(ctx.origin, one, { method: "DELETE", token: BOOTSTRAP })).status, 404);
  assert.deepEqual((await call(ctx.origin, base, { token: BOOTSTRAP })).body, { organizations: [] });

  const audit = (await bridgeAudit(ctx)).filter((row) => row.action.startsWith("installation.cloud_bridge."));
  assert.deepEqual(audit.map((row) => [row.action, row.actor_kind]), [
    ["installation.cloud_bridge.organization_set", "bootstrap"], // openWindow
    ["installation.cloud_bridge.organization_removed", "bootstrap"],
    ["installation.cloud_bridge.organization_set", "bootstrap"],
    ["installation.cloud_bridge.organization_set", "bootstrap"],
    ["installation.cloud_bridge.organization_removed", "bootstrap"],
  ]);
  assert.equal(audit[2]!.target.setBy, "Migration operator");
  assert.equal(audit[3]!.target.setBy, "Second operator");
});
