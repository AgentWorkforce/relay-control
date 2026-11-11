import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { createServer, type Server } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { loadIdentityConfig, type IdentityConfig } from "../src/identity/config.js";
import { OidcClient, type FetchLike, type OidcError } from "../src/identity/oidc.js";
import { IdentityStore } from "../src/identity/store.js";
import { createIdentityModule } from "../src/identity/routes.js";
import { bootstrapOnce, relaycastProvisioner, startBootstrap, type RelaycastProvisioner } from "../src/identity/bootstrap.js";
import type { Mailer, OutgoingEmail } from "../src/identity/mailer.js";
import { close, listen, PGliteDatabase } from "./support/harness.js";

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const CLIENT_ID = "relay-test-client";
const CLIENT_SECRET = "relay-test-client-secret";

// ---- fakes -------------------------------------------------------------------

type IdpCode = { email: string; name?: string; nonce: string; challenge: string; redirectUri: string; emailVerified?: boolean | null; aud?: string; noEmail?: boolean; claims?: Record<string, unknown> };

/** A standards-shaped OIDC provider: discovery, JWKS, token endpoint (RS256). */
function fakeIdp() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const codes = new Map<string, IdpCode>();
  const state = {
    issuer: "",
    tokenCalls: 0,
    signWith: privateKey as KeyObject,
    kid: "k1",
    /** Overrides the discovery `issuer` (e.g. Microsoft's {tenantid} template). */
    discoveryIssuer: null as string | null,
    /** Overrides the base of the discovery endpoints (rewritten back by the client's fetch). */
    endpointBase: null as string | null,
  };
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", state.issuer);
    const reply = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (url.pathname === "/.well-known/openid-configuration") {
      const base = state.endpointBase ?? state.issuer;
      return reply(200, {
        issuer: state.discoveryIssuer ?? state.issuer,
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: `${base}/token`,
        jwks_uri: `${base}/jwks`,
        token_endpoint_auth_methods_supported: ["client_secret_basic"],
      });
    }
    if (url.pathname === "/jwks") {
      return reply(200, { keys: [{ ...publicKey.export({ format: "jwk" }), kid: "k1", use: "sig", alg: "RS256" }] });
    }
    if (url.pathname === "/token" && req.method === "POST") {
      state.tokenCalls += 1;
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const form = new URLSearchParams(raw);
      const basic = Buffer.from((req.headers.authorization ?? "").replace(/^Basic /, ""), "base64").toString();
      if (basic !== `${encodeURIComponent(CLIENT_ID)}:${encodeURIComponent(CLIENT_SECRET)}`) return reply(401, { error: "invalid_client" });
      const code = codes.get(form.get("code") ?? "");
      codes.delete(form.get("code") ?? "");
      if (!code) return reply(400, { error: "invalid_grant" });
      const challenge = createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url");
      if (challenge !== code.challenge || form.get("redirect_uri") !== code.redirectUri) return reply(400, { error: "invalid_grant" });
      const now = Math.floor(Date.now() / 1000);
      const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: state.kid, typ: "JWT" })).toString("base64url");
      const payload = Buffer.from(JSON.stringify({
        iss: state.issuer,
        aud: code.aud ?? CLIENT_ID,
        sub: `sub-${code.email}`,
        ...(code.noEmail ? {} : { email: code.email }),
        ...code.claims,
        // null: the provider sends no email_verified claim at all.
        ...(code.emailVerified === null ? {} : { email_verified: code.emailVerified ?? true }),
        name: code.name ?? "Test Person",
        nonce: code.nonce,
        iat: now,
        exp: now + 300,
      })).toString("base64url");
      const signature = sign("sha256", Buffer.from(`${header}.${payload}`), state.signWith).toString("base64url");
      return reply(200, { access_token: "at", token_type: "Bearer", id_token: `${header}.${payload}.${signature}` });
    }
    reply(404, {});
  });
  return {
    server,
    state,
    /** What a person signing in at the IdP does: returns the code for the callback. */
    approve(authorizeUrl: string, person: Partial<IdpCode> & { email: string }): { code: string; state: string } {
      const params = new URL(authorizeUrl).searchParams;
      assert.equal(params.get("client_id"), CLIENT_ID);
      assert.equal(params.get("code_challenge_method"), "S256");
      assert.equal(params.get("response_type"), "code");
      const code = randomUUID();
      codes.set(code, {
        nonce: params.get("nonce")!,
        challenge: params.get("code_challenge")!,
        redirectUri: params.get("redirect_uri")!,
        ...person,
      });
      return { code, state: params.get("state")! };
    },
  };
}

function fakeRelaycast() {
  const state = { creates: 0, deletes: [] as string[], fail: 0, secret: "relaycast-internal-secret-0123456789abcdef" };
  const server = createServer((req, res) => {
    const reply = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (req.headers.authorization !== `Bearer ${state.secret}`) return reply(401, { ok: false });
    if (req.method === "POST" && req.url === "/internal/workspaces") {
      if (state.fail > 0) {
        state.fail -= 1;
        return reply(502, { ok: false, error: { code: "workspace_unavailable" } });
      }
      state.creates += 1;
      return reply(201, { ok: true, data: { workspace_id: `24357777387973${state.creates}`, api_key: `ar_ws_test_key_${state.creates}`, name: "Default" } });
    }
    const del = /^\/internal\/workspaces\/([^/]+)$/.exec(req.url ?? "");
    if (req.method === "DELETE" && del) {
      state.deletes.push(del[1]!);
      res.writeHead(204);
      return res.end();
    }
    reply(404, {});
  });
  return { server, state };
}

function fakeMailer(): Mailer & { sent: OutgoingEmail[]; fail: boolean } {
  const mailer = {
    sent: [] as OutgoingEmail[],
    fail: false,
    async send(message: OutgoingEmail) {
      if (mailer.fail) throw new Error("smtp down");
      mailer.sent.push(message);
    },
  };
  return mailer;
}

// ---- harness -----------------------------------------------------------------

type Res = { status: number; body: any; text: string; headers: Headers; cookies: Record<string, string> };

async function call(origin: string, path: string, init: {
  method?: string;
  cookie?: string;
  token?: string;
  json?: unknown;
  form?: Record<string, string>;
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
  const cookies: Record<string, string> = {};
  for (const line of response.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const index = pair!.indexOf("=");
    cookies[pair!.slice(0, index)] = decodeURIComponent(pair!.slice(index + 1));
  }
  return { status: response.status, body: parsed, text, headers: response.headers, cookies };
}

async function setup(t: test.TestContext, options: {
  env?: Record<string, string>;
  mailer?: boolean;
  bootstrap?: boolean;
  /** SELFHOST_TENANCY=multi: the stores get the tenancy and the Relaycast provisioner. */
  multi?: boolean;
  /** Name the fake provider's issuer in SELFHOST_OIDC_TRUST_MISSING_EMAIL_VERIFIED_ISSUER. */
  trustMissingEmailVerified?: boolean;
  /**
   * SELFHOST_MICROSOFT_*, served by a second fake provider behind
   * login.microsoftonline.com. `discoveryIssuer` defaults to the template for
   * common/organizations and to the tenant issuer otherwise.
   */
  microsoft?: { tenant?: string; discoveryIssuer?: string };
} = {}) {
  const database = new PGliteDatabase();
  await migrate(database);
  const idp = fakeIdp();
  const idpUrl = await listen(idp.server);
  idp.state.issuer = idpUrl;
  const msIdp = options.microsoft ? fakeIdp() : null;
  const msIdpUrl = msIdp ? await listen(msIdp.server) : null;
  if (msIdp && options.microsoft) {
    const tenant = options.microsoft.tenant ?? "common";
    msIdp.state.issuer = msIdpUrl!;
    msIdp.state.discoveryIssuer = options.microsoft.discoveryIssuer
      ?? (tenant === "common" || tenant === "organizations" ? MICROSOFT_TEMPLATE_ISSUER : `${MICROSOFT_HOST}/${tenant}/v2.0`);
    msIdp.state.endpointBase = `${MICROSOFT_HOST}/${tenant}/oauth2/v2.0`;
  }
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
  const identityConfig: IdentityConfig = loadIdentityConfig({
    SELFHOST_OIDC_ISSUER: idpUrl,
    SELFHOST_OIDC_CLIENT_ID: CLIENT_ID,
    SELFHOST_OIDC_CLIENT_SECRET: CLIENT_SECRET,
    SELFHOST_OIDC_ALLOW_HTTP_ISSUER: "true",
    SELFHOST_OIDC_DISPLAY_NAME: "Acme SSO",
    SELFHOST_BOOTSTRAP_ORG_NAME: "Acme",
    SELFHOST_BOOTSTRAP_ADMIN_EMAIL: "Admin@Acme.test",
    RELAYCAST_INTERNAL_SECRET: relaycast.state.secret,
    ...(options.multi ? { SELFHOST_TENANCY: "multi" } : {}),
    ...(options.trustMissingEmailVerified ? { SELFHOST_OIDC_TRUST_MISSING_EMAIL_VERIFIED_ISSUER: idpUrl } : {}),
    ...(options.mailer ? { SELFHOST_SMTP_HOST: "smtp.acme.test", SELFHOST_EMAIL_FROM: "Relay <relay@acme.test>", SELFHOST_EMAIL_LOGIN: "true" } : {}),
    ...(options.microsoft ? {
      SELFHOST_MICROSOFT_CLIENT_ID: CLIENT_ID,
      SELFHOST_MICROSOFT_CLIENT_SECRET: CLIENT_SECRET,
      ...(options.microsoft.tenant ? { SELFHOST_MICROSOFT_TENANT: options.microsoft.tenant } : {}),
    } : {}),
    ...options.env,
  });
  const mailer = fakeMailer();
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: identityConfig.tenancy.mode });
  const provisioner = relaycastProvisioner(relaycastUrl, relaycast.state.secret);
  const identityStore = new IdentityStore(database, KEYRING, {
    inviteTtlMs: identityConfig.inviteTtlMs,
    autoJoinDomains: identityConfig.autoJoinDomains,
    ...(options.multi ? { tenancy: identityConfig.tenancy, provisioner } : {}),
    issueSession: (tx, session) => store.issueBrowserSession(tx, session),
  });
  const identity = createIdentityModule({
    config: identityConfig,
    identityStore,
    controlStore: store,
    keyring: KEYRING,
    dashboardUrl: config.dashboardUrl,
    mailer: options.mailer ? mailer : null,
    ...(msIdp ? { microsoftClient: new OidcClient(identityConfig.microsoft!, microsoftFetch(msIdpUrl!)) } : {}),
    log: () => undefined,
  });
  control.on("request", createApp({ config, store, identity }));
  t.after(async () => {
    await close(control);
    await close(idp.server);
    if (msIdp) await close(msIdp.server);
    await close(relaycast.server);
    await database.close();
  });
  if (options.bootstrap !== false) {
    assert.equal(await bootstrapOnce({ bootstrap: identityConfig.bootstrap!, store: identityStore, provisioner, log: () => undefined }), "done");
  }
  return { database, origin, idp, msIdp, relaycast, mailer, identityConfig, identityStore, provisioner, store };
}

const MICROSOFT_HOST = "https://login.microsoftonline.com";
const MICROSOFT_TEMPLATE_ISSUER = `${MICROSOFT_HOST}/{tenantid}/v2.0`;
const PERSONAL_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad";
const WORK_TENANT = "6f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b";

/** The client's fetch: login.microsoftonline.com URLs go to the fake provider. */
function microsoftFetch(idpUrl: string): FetchLike {
  return (input, init) => {
    const url = new URL(input);
    assert.equal(url.origin, MICROSOFT_HOST, `unexpected fetch ${input}`);
    const path = url.pathname.endsWith("/.well-known/openid-configuration")
      ? "/.well-known/openid-configuration"
      : `/${url.pathname.split("/").pop()}`;
    return globalThis.fetch(`${idpUrl}${path}${url.search}`, init);
  };
}

/** A Microsoft v2.0 id_token: per-tenant `iss`, `tid`, `oid`, no email_verified. */
function msAccount(email: string, tid: string | null = PERSONAL_TENANT, claims: Record<string, unknown> = {}): Partial<IdpCode> & { email: string } {
  return {
    email,
    emailVerified: null,
    claims: {
      iss: `${MICROSOFT_HOST}/${tid ?? PERSONAL_TENANT}/v2.0`,
      ...(tid === null ? {} : { tid }),
      oid: randomUUID(),
      ver: "2.0",
      ...claims,
    },
  };
}

/** Full browser round trip through /login/microsoft/*. */
async function microsoftSignIn(ctx: Awaited<ReturnType<typeof setup>>, person: Partial<IdpCode> & { email: string }, query = "") {
  const start = await call(ctx.origin, `/login/microsoft/start${query}`);
  assert.equal(start.status, 302, start.text);
  const attempt = start.cookies.agent_relay_microsoft;
  assert(attempt, "attempt cookie");
  const approved = ctx.msIdp!.approve(start.headers.get("location")!, person);
  const callback = await call(ctx.origin, `/login/microsoft/callback?code=${approved.code}&state=${approved.state}`, {
    cookie: `agent_relay_microsoft=${encodeURIComponent(attempt)}`,
  });
  const session = callback.cookies.agent_relay_session;
  return { start, callback, cookie: session ? `agent_relay_session=${encodeURIComponent(session)}` : null };
}

/** Full browser OIDC round trip; returns the session cookie header (or the failing response). */
async function oidcSignIn(ctx: Awaited<ReturnType<typeof setup>>, person: Partial<IdpCode> & { email: string }, query = "") {
  const start = await call(ctx.origin, `/login/oidc/start${query}`);
  assert.equal(start.status, 302, start.text);
  const attempt = start.cookies.agent_relay_oidc;
  assert(attempt, "attempt cookie");
  const approved = ctx.idp.approve(start.headers.get("location")!, person);
  const callback = await call(ctx.origin, `/login/oidc/callback?code=${approved.code}&state=${approved.state}`, {
    cookie: `agent_relay_oidc=${encodeURIComponent(attempt)}`,
  });
  const session = callback.cookies.agent_relay_session;
  return { callback, cookie: session ? `agent_relay_session=${encodeURIComponent(session)}` : null };
}

async function whoami(origin: string, cookie: string) {
  return call(origin, "/cloud/api/v1/auth/whoami", { cookie });
}

async function orgId(ctx: Awaited<ReturnType<typeof setup>>): Promise<string> {
  const result = await call(ctx.origin, "/api/v1/organizations", { token: BOOTSTRAP });
  return result.body.organizations[0].id;
}

// ---- config --------------------------------------------------------------------

test("identity config: pairs, https issuer, smtp and domain validation", () => {
  assert.equal(loadIdentityConfig({}).bootstrap, null);
  assert.equal(loadIdentityConfig({}).oidc, null);
  assert.throws(() => loadIdentityConfig({ SELFHOST_BOOTSTRAP_ORG_NAME: "Acme" }), /set together/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_BOOTSTRAP_ORG_NAME: "Acme", SELFHOST_BOOTSTRAP_ADMIN_EMAIL: "nope" }), /email address/);
  const boot = loadIdentityConfig({ SELFHOST_BOOTSTRAP_ORG_NAME: " Acme ", SELFHOST_BOOTSTRAP_ADMIN_EMAIL: "Ops@Acme.com" }).bootstrap!;
  assert.deepEqual(boot, { organizationName: "Acme", adminEmail: "ops@acme.com", adminEmails: ["ops@acme.com"], adminName: "ops", workspaceName: "Default" });
  assert.throws(() => loadIdentityConfig({ SELFHOST_OIDC_ISSUER: "http://idp.acme.com", SELFHOST_OIDC_CLIENT_ID: "a", SELFHOST_OIDC_CLIENT_SECRET: "b" }), /https/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_OIDC_ISSUER: "https://idp.acme.com", SELFHOST_OIDC_CLIENT_ID: "a" }), /CLIENT_SECRET/);
  const oidc = loadIdentityConfig({
    SELFHOST_OIDC_ISSUER: "https://accounts.google.com/",
    SELFHOST_OIDC_CLIENT_ID: "a",
    SELFHOST_OIDC_CLIENT_SECRET: "b",
    SELFHOST_OIDC_ALLOWED_DOMAINS: "Acme.com, @acme.io",
    SELFHOST_OIDC_SCOPES: "profile",
  }).oidc!;
  assert.equal(oidc.issuer, "https://accounts.google.com");
  assert.deepEqual(oidc.allowedDomains, ["acme.com", "acme.io"]);
  assert.deepEqual(oidc.scopes, ["openid", "profile", "email"]);
  assert.throws(() => loadIdentityConfig({ SELFHOST_OIDC_ISSUER: "https://x.acme.com", SELFHOST_OIDC_CLIENT_ID: "a", SELFHOST_OIDC_CLIENT_SECRET: "b", SELFHOST_OIDC_ALLOWED_DOMAINS: "not a domain!" }), /email domains/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_OIDC_ISSUER: "https://x.acme.com", SELFHOST_OIDC_CLIENT_ID: "a", SELFHOST_OIDC_CLIENT_SECRET: "b", SELFHOST_OIDC_REDIRECT_URL: "https://relay.acme.com/elsewhere" }), /login\/oidc\/callback/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_EMAIL_LOGIN: "true" }), /SMTP_HOST/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_SMTP_HOST: "smtp.acme.com" }), /EMAIL_FROM/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_SMTP_HOST: "smtp.acme.com", SELFHOST_EMAIL_FROM: "a@acme.com", SELFHOST_SMTP_USERNAME: "u" }), /set together/);
  assert.equal(loadIdentityConfig({ SELFHOST_SMTP_HOST: "smtp.acme.com", SELFHOST_SMTP_PORT: "465", SELFHOST_EMAIL_FROM: "a@acme.com" }).smtp!.security, "tls");
  assert.throws(() => loadIdentityConfig({ RELAYCAST_INTERNAL_SECRET: "short" }), /32 bytes/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_INVITE_TTL_HOURS: "0" }), /INVITE_TTL/);
});

// ---- bootstrap -------------------------------------------------------------------

test("bootstrap: creates org, owner and Relaycast-bound workspace once (idempotent)", async (t) => {
  const ctx = await setup(t);
  const orgs = await call(ctx.origin, "/api/v1/organizations", { token: BOOTSTRAP });
  assert.equal(orgs.body.organizations.length, 1);
  assert.equal(orgs.body.organizations[0].name, "Acme");
  const id = orgs.body.organizations[0].id;
  const members = await call(ctx.origin, `/api/v1/organizations/${id}/memberships`, { token: BOOTSTRAP });
  assert.deepEqual(members.body.memberships.map((m: any) => [m.email, m.role]), [["admin@acme.test", "owner"]]);
  const workspaces = await call(ctx.origin, `/api/v1/organizations/${id}/workspaces`, { token: BOOTSTRAP });
  assert.equal(workspaces.body.workspaces.length, 1);
  assert.equal(workspaces.body.workspaces[0].name, "Default");
  assert.equal(workspaces.body.workspaces[0].relaycastWorkspaceId, "243577773879731");
  assert.equal(ctx.relaycast.state.creates, 1);

  // A restart repeats nothing.
  for (let i = 0; i < 3; i += 1) {
    assert.equal(await bootstrapOnce({ bootstrap: ctx.identityConfig.bootstrap!, store: ctx.identityStore, provisioner: ctx.provisioner, log: () => undefined }), "done");
  }
  assert.equal(ctx.relaycast.state.creates, 1);
  const again = await call(ctx.origin, `/api/v1/organizations/${id}/workspaces`, { token: BOOTSTRAP });
  assert.equal(again.body.workspaces.length, 1);
  const audit = await ctx.database.query<{ action: string }>("SELECT action FROM admin_audit_events ORDER BY created_at");
  assert.deepEqual(audit.rows.map((r) => r.action), ["organization.bootstrap", "membership.bootstrap_owner", "workspace.bootstrap"]);

  // The key is stored encrypted and handed to members through resolve.
  const raw = await ctx.database.query<{ relaycast_api_key_ciphertext: string }>("SELECT relaycast_api_key_ciphertext FROM workspaces");
  assert.match(raw.rows[0]!.relaycast_api_key_ciphertext, /^v2\./);
  const signedIn = await oidcSignIn(ctx, { email: "admin@acme.test", name: "Ada Admin" });
  const me = await whoami(ctx.origin, signedIn.cookie!);
  const resolved = await call(ctx.origin, `/cloud/api/v1/workspaces/${me.body.currentWorkspace.id}/resolve`, { cookie: signedIn.cookie! });
  assert.equal(resolved.body.relaycastApiKey, "ar_ws_test_key_1");
});

test("bootstrap: existing org keeps its data; a new admin email is made owner exactly once", async (t) => {
  const ctx = await setup(t, { bootstrap: false });
  // An installation created by hand (the GKE proof): org, owner, workspace.
  const created = await call(ctx.origin, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, json: { name: "Hand Made", ownerEmail: "first@acme.test", ownerName: "First" },
  });
  await call(ctx.origin, `/api/v1/organizations/${created.body.id}/workspaces`, {
    method: "POST", token: BOOTSTRAP, json: { name: "Default", relaycastApiKey: "rk_live_existing" },
  });
  const run = () => bootstrapOnce({ bootstrap: ctx.identityConfig.bootstrap!, store: ctx.identityStore, provisioner: ctx.provisioner, log: () => undefined });
  assert.equal(await run(), "done");
  assert.equal(ctx.relaycast.state.creates, 0, "no new workspace when one exists");
  const orgs = await call(ctx.origin, "/api/v1/organizations", { token: BOOTSTRAP });
  assert.equal(orgs.body.organizations[0].name, "Hand Made", "name not overwritten");
  let members = await call(ctx.origin, `/api/v1/organizations/${created.body.id}/memberships`, { token: BOOTSTRAP });
  assert.deepEqual(members.body.memberships.map((m: any) => [m.email, m.role]), [["admin@acme.test", "owner"], ["first@acme.test", "owner"]]);
  // Another owner demotes the bootstrap admin; a restart does not undo it.
  await call(ctx.origin, `/api/v1/organizations/${created.body.id}/memberships`, {
    method: "POST", token: BOOTSTRAP, json: { email: "admin@acme.test", name: "admin", role: "member" },
  });
  assert.equal(await run(), "done");
  members = await call(ctx.origin, `/api/v1/organizations/${created.body.id}/memberships`, { token: BOOTSTRAP });
  assert.equal(members.body.memberships.find((m: any) => m.email === "admin@acme.test").role, "member");
});

test("bootstrap: retries while Relaycast is unavailable, then binds the workspace", async (t) => {
  const ctx = await setup(t, { bootstrap: false });
  ctx.relaycast.state.fail = 2;
  const logs: string[] = [];
  const sleeps: number[] = [];
  await startBootstrap({
    bootstrap: ctx.identityConfig.bootstrap!,
    store: ctx.identityStore,
    provisioner: ctx.provisioner,
    log: (message) => logs.push(message),
    sleep: async (ms) => { sleeps.push(ms); },
  });
  assert.deepEqual(sleeps, [5_000, 10_000]);
  assert.equal(logs.filter((m) => m === "bootstrap attempt failed").length, 2);
  assert.equal(ctx.relaycast.state.creates, 1);
  assert.equal(await ctx.identityStore.workspaceCount(await orgId(ctx)), 1);
});

test("bootstrap: a workspace that appears meanwhile wins and the extra Relaycast workspace is deleted", async (t) => {
  const ctx = await setup(t, { bootstrap: false });
  const racing: RelaycastProvisioner = {
    create: async (name) => {
      const made = await ctx.provisioner.create(name);
      const id = await orgId(ctx);
      await call(ctx.origin, `/api/v1/organizations/${id}/workspaces`, {
        method: "POST", token: BOOTSTRAP, json: { name: "Other", relaycastApiKey: "rk_live_other" },
      });
      return made;
    },
    remove: (id) => ctx.provisioner.remove(id),
  };
  assert.equal(await bootstrapOnce({ bootstrap: ctx.identityConfig.bootstrap!, store: ctx.identityStore, provisioner: racing, log: () => undefined }), "done");
  assert.deepEqual(ctx.relaycast.state.deletes, ["243577773879731"]);
});

// ---- OIDC sign-in ---------------------------------------------------------------

test("oidc: the admin email signs in as owner through the full code + PKCE flow", async (t) => {
  const ctx = await setup(t);
  const login = await call(ctx.origin, "/login?next=%2Fsettings");
  assert.equal(login.status, 200);
  assert.match(login.text, /Continue with Acme SSO/);
  assert.match(login.text, /Operator sign-in/);
  assert.match(login.headers.get("content-security-policy")!, /frame-ancestors 'none'/);

  const start = await call(ctx.origin, "/login/oidc/start?next=%2Fsettings");
  const location = new URL(start.headers.get("location")!);
  assert.equal(location.origin + location.pathname, `${ctx.idp.state.issuer}/authorize`);
  assert.equal(location.searchParams.get("redirect_uri"), `${ctx.origin}/login/oidc/callback`);
  assert.equal(location.searchParams.get("scope"), "openid email profile");
  assert.match(start.headers.get("set-cookie")!, /agent_relay_oidc=.*Path=\/login\/oidc.*HttpOnly/);

  const { callback, cookie } = await oidcSignIn(ctx, { email: "ADMIN@acme.test", name: "Ada Admin" }, "?next=%2Fsettings");
  assert.equal(callback.status, 303);
  assert.equal(callback.headers.get("location"), "/settings");
  assert.match(callback.headers.getSetCookie().join("\n"), /agent_relay_session=.*Path=\/cloud.*Secure; HttpOnly; SameSite=Lax/);
  const me = await whoami(ctx.origin, cookie!);
  assert.equal(me.status, 200);
  assert.equal(me.body.user.email, "admin@acme.test");
  assert.equal(me.body.user.name, "Ada Admin", "IdP name replaces the placeholder");
  assert.equal(me.body.currentOrganization.role, "owner");
  assert.equal(me.body.currentWorkspace.name, "Default");

  // Desktop / CLI provider start lands on the /login chooser, never on one provider.
  const google = await call(ctx.origin, "/cloud/api/auth/google/start?next=%2Fapi%2Fv1%2Fcli%2Flogin");
  assert.equal(google.status, 302);
  assert.equal(google.headers.get("location"), `/login?next=${encodeURIComponent("/cloud/api/v1/cli/login")}`);
});

test("oidc: refuses strangers, other domains, unverified email, forged state and bad tokens", async (t) => {
  const ctx = await setup(t, { env: { SELFHOST_OIDC_ALLOWED_DOMAINS: "acme.test" } });
  let result = await oidcSignIn(ctx, { email: "stranger@acme.test" });
  assert.equal(result.callback.status, 403);
  assert.match(result.callback.text, /doesn&#39;t have access to Acme/);
  assert.equal(result.cookie, null);

  result = await oidcSignIn(ctx, { email: "admin@evil.test" });
  assert.equal(result.callback.status, 403);
  assert.match(result.callback.text, /evil\.test can&#39;t sign in here/);

  result = await oidcSignIn(ctx, { email: "admin@acme.test", emailVerified: false });
  assert.equal(result.callback.status, 502);
  assert.match(result.callback.text, /not verified/);

  result = await oidcSignIn(ctx, { email: "admin@acme.test", aud: "someone-else" });
  assert.equal(result.callback.status, 502);
  assert.match(result.callback.text, /audience/);

  // Signed by a key the issuer never published.
  ctx.idp.state.signWith = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  result = await oidcSignIn(ctx, { email: "admin@acme.test" });
  assert.equal(result.callback.status, 502);
  assert.match(result.callback.text, /signature is invalid/);

  // A callback without the browser's attempt cookie, or with another state.
  const start = await call(ctx.origin, "/login/oidc/start");
  const approved = ctx.idp.approve(start.headers.get("location")!, { email: "admin@acme.test" });
  const noCookie = await call(ctx.origin, `/login/oidc/callback?code=${approved.code}&state=${approved.state}`);
  assert.equal(noCookie.status, 400);
  const wrongState = await call(ctx.origin, `/login/oidc/callback?code=${approved.code}&state=forged`, {
    cookie: `agent_relay_oidc=${encodeURIComponent(start.cookies.agent_relay_oidc!)}`,
  });
  assert.equal(wrongState.status, 400);
  const cancelled = await call(ctx.origin, `/login/oidc/callback?error=access_denied&state=${approved.state}`, {
    cookie: `agent_relay_oidc=${encodeURIComponent(start.cookies.agent_relay_oidc!)}`,
  });
  assert.match(cancelled.text, /cancelled/);
});

// ---- Microsoft Entra ID: an id_token without email_verified ----------------------

/** A v2.0 Entra id_token: no email_verified, plus the directory claims Entra adds. */
function entra(email: string, extra: Partial<IdpCode> = {}): Partial<IdpCode> & { email: string } {
  return {
    email,
    emailVerified: null,
    claims: {
      preferred_username: email,
      upn: email,
      oid: "00000000-0000-0000-0000-00000000e17a",
      tid: "11111111-2222-3333-4444-555555555555",
      ver: "2.0",
    },
    ...extra,
  };
}

const ENTRA_TRUST_ISSUER = "SELFHOST_OIDC_TRUST_MISSING_EMAIL_VERIFIED_ISSUER";

async function inviteFor(ctx: Awaited<ReturnType<typeof setup>>, email: string, role: "admin" | "member" = "admin") {
  const organizationId = await orgId(ctx);
  const created = await call(ctx.origin, `/api/v1/organizations/${organizationId}/invitations`, {
    method: "POST",
    token: BOOTSTRAP,
    json: { email, role },
  });
  assert.equal(created.status, 201, created.text);
  return { organizationId, token: created.body.token as string };
}

test("oidc entra, single mode: every path accepts a token without email_verified", async (t) => {
  const ctx = await setup(t, { env: { SELFHOST_AUTO_JOIN_DOMAINS: "acme.test", SELFHOST_OIDC_ALLOWED_DOMAINS: "acme.test" } });

  // Bootstrap owner.
  const owner = await oidcSignIn(ctx, entra("admin@acme.test"));
  assert.equal(owner.callback.status, 303, owner.callback.text);
  assert.equal((await whoami(ctx.origin, owner.cookie!)).body.currentOrganization.role, "owner");

  // Domain auto-join.
  const joined = await oidcSignIn(ctx, entra("new.person@acme.test"));
  assert.equal(joined.callback.status, 303, joined.callback.text);
  assert.equal((await whoami(ctx.origin, joined.cookie!)).body.currentOrganization.role, "member");

  // Existing member, again.
  const again = await oidcSignIn(ctx, entra("new.person@acme.test"));
  assert.equal(again.callback.status, 303, again.callback.text);

  // Invite keeps the invited role.
  const { token } = await inviteFor(ctx, "invited@acme.test");
  const invited = await oidcSignIn(ctx, entra("invited@acme.test"), `?invite=${encodeURIComponent(token)}`);
  assert.equal(invited.callback.status, 303, invited.callback.text);
  assert.equal((await whoami(ctx.origin, invited.cookie!)).body.currentOrganization.role, "admin");

  // The allow-list still applies.
  const other = await oidcSignIn(ctx, entra("admin@evil.test"));
  assert.equal(other.callback.status, 403);
  assert.equal(other.cookie, null);
});

test("oidc entra, single mode: without auto-join a stranger at the domain is refused", async (t) => {
  const ctx = await setup(t);
  const result = await oidcSignIn(ctx, entra("stranger@acme.test"));
  assert.equal(result.callback.status, 403);
  assert.match(result.callback.text, /doesn&#39;t have access to Acme/);
});

test("oidc entra: preferred_username and upn never stand in for a missing email claim", async (t) => {
  const ctx = await setup(t);
  const result = await oidcSignIn(ctx, entra("admin@acme.test", { noEmail: true }));
  assert.equal(result.callback.status, 502);
  assert.match(result.callback.text, /did not share an email address/);
  assert.equal(result.cookie, null);
});

test("oidc entra, multi mode: a token without email_verified skips domain auto-join only", async (t) => {
  const ctx = await setup(t, { multi: true });
  const organizationId = await orgId(ctx);
  assert.equal((await call(ctx.origin, `/api/v1/organizations/${organizationId}/domains/acme.test`, { method: "PUT", token: BOOTSTRAP })).status, 201);

  const owner = await oidcSignIn(ctx, entra("admin@acme.test"));
  assert.equal(owner.callback.status, 303, owner.callback.text);
  assert.equal((await whoami(ctx.origin, owner.cookie!)).body.currentOrganization.role, "owner");

  const { token } = await inviteFor(ctx, "invited@acme.test", "member");
  const invited = await oidcSignIn(ctx, entra("invited@acme.test"), `?invite=${encodeURIComponent(token)}`);
  assert.equal(invited.callback.status, 303, invited.callback.text);
  assert.equal((await whoami(ctx.origin, invited.cookie!)).body.currentOrganization.id, organizationId);

  // At the assigned domain, but not auto-joined: a personal organization instead.
  const domainUser = await oidcSignIn(ctx, entra("new.person@acme.test"));
  assert.equal(domainUser.callback.status, 303, domainUser.callback.text);
  const me = await whoami(ctx.origin, domainUser.cookie!);
  assert.notEqual(me.body.currentOrganization.id, organizationId);
  assert.equal(me.body.currentOrganization.role, "owner");
});

test("oidc entra, multi mode: naming the issuer auto-joins the domain; false stays refused", async (t) => {
  const ctx = await setup(t, { multi: true, trustMissingEmailVerified: true });
  const organizationId = await orgId(ctx);
  assert.equal((await call(ctx.origin, `/api/v1/organizations/${organizationId}/domains/acme.test`, { method: "PUT", token: BOOTSTRAP })).status, 201);

  const joined = await oidcSignIn(ctx, entra("new.person@acme.test"));
  assert.equal(joined.callback.status, 303, joined.callback.text);
  const me = await whoami(ctx.origin, joined.cookie!);
  assert.equal(me.body.currentOrganization.id, organizationId);
  assert.equal(me.body.currentOrganization.role, "member");

  const refused = await oidcSignIn(ctx, entra("other@acme.test", { emailVerified: false }));
  assert.equal(refused.callback.status, 502);
  assert.match(refused.callback.text, /not verified/);
});

test("oidc entra: the trust setting names one exact, single-directory issuer", () => {
  const tenant = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0";
  const load = (issuer: string, named?: string) => loadIdentityConfig({
    SELFHOST_OIDC_ISSUER: issuer,
    SELFHOST_OIDC_CLIENT_ID: "a",
    SELFHOST_OIDC_CLIENT_SECRET: "b",
    ...(named === undefined ? {} : { [ENTRA_TRUST_ISSUER]: named }),
  }).oidc!;
  assert.equal(load(tenant).trustMissingEmailVerified, false);
  assert.equal(load(tenant, `${tenant}/`).trustMissingEmailVerified, true);
  assert.throws(() => load(tenant, "https://login.microsoftonline.com/99999999-2222-3333-4444-555555555555/v2.0"), /must equal SELFHOST_OIDC_ISSUER/);
  for (const shared of [
    "https://login.microsoftonline.com/common/v2.0",
    "https://login.microsoftonline.com/Organizations/v2.0",
    "https://login.microsoftonline.com/consumers/v2.0",
    "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
    "https://login.microsoftonline.com/{tenantid}/v2.0",
    "https://login.microsoftonline.us/common/v2.0",
    "https://login.partner.microsoftonline.cn/organizations/v2.0",
  ]) {
    assert.throws(() => load(shared, shared), /must name one tenant/, shared);
  }
  // A realm that happens to be called "common" on another provider is fine.
  assert.equal(load("https://idp.acme.test/common", "https://idp.acme.test/common").trustMissingEmailVerified, true);
});

test("oidc entra: a shared 'common' or 'organizations' issuer fails discovery", async () => {
  for (const tenant of ["common", "organizations"]) {
    const issuer = `https://login.microsoftonline.com/${tenant}/v2.0`;
    const client = new OidcClient(
      loadIdentityConfig({ SELFHOST_OIDC_ISSUER: issuer, SELFHOST_OIDC_CLIENT_ID: "a", SELFHOST_OIDC_CLIENT_SECRET: "b" }).oidc!,
      // Microsoft's published document for both: a template, never the tenant-less URL.
      async () => new Response(JSON.stringify({
        issuer: "https://login.microsoftonline.com/{tenantid}/v2.0",
        authorization_endpoint: `${issuer.replace("/v2.0", "")}/oauth2/v2.0/authorize`,
        token_endpoint: `${issuer.replace("/v2.0", "")}/oauth2/v2.0/token`,
        jwks_uri: `${issuer.replace("/v2.0", "")}/discovery/v2.0/keys`,
      }), { status: 200 }),
    );
    await assert.rejects(client.discovery(), (error: OidcError) => error.code === "discovery_invalid");
  }
});

test("oidc: before the workspace exists, sign-in says the installation is still setting up", async (t) => {
  const ctx = await setup(t, { bootstrap: false });
  await ctx.identityStore.ensureOrganization(ctx.identityConfig.bootstrap!);
  const result = await oidcSignIn(ctx, { email: "admin@acme.test" });
  assert.equal(result.callback.status, 503);
  assert.match(result.callback.text, /still creating/);
});

// ---- Microsoft accounts (SELFHOST_MICROSOFT_*) ----------------------------------------

/** An owner signs in through the generic OIDC provider and invites `email`; returns the link token. */
async function ownerInvite(ctx: Awaited<ReturnType<typeof setup>>, email: string, role: "admin" | "member" = "member") {
  const owner = (await oidcSignIn(ctx, { email: "admin@acme.test", name: "Ada Admin" })).cookie!;
  const organizationId = (await whoami(ctx.origin, owner)).body.currentOrganization.id as string;
  const created = await call(ctx.origin, `/cloud/api/v1/organizations/${organizationId}/invitations`, {
    method: "POST", cookie: owner, json: { email, role },
  });
  assert.equal(created.status, 201, created.text);
  return { organizationId, owner, token: new URL(created.body.inviteUrl).searchParams.get("invite")! };
}

test("microsoft config: pairs, tenant, redirect URL, coexists with SELFHOST_OIDC_*", () => {
  assert.equal(loadIdentityConfig({}).microsoft, null);
  const base = { SELFHOST_MICROSOFT_CLIENT_ID: "a", SELFHOST_MICROSOFT_CLIENT_SECRET: "b" };
  assert.throws(() => loadIdentityConfig({ SELFHOST_MICROSOFT_CLIENT_ID: "a" }), /must be set together/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_MICROSOFT_CLIENT_SECRET: "b" }), /must be set together/);
  const microsoft = loadIdentityConfig(base).microsoft!;
  assert.deepEqual(microsoft, {
    kind: "microsoft",
    issuer: "https://login.microsoftonline.com/common/v2.0",
    clientId: "a",
    clientSecret: "b",
    scopes: ["openid", "email", "profile"],
    allowedDomains: [],
    displayName: "Microsoft",
    redirectUrl: null,
    allowHttpIssuer: false,
    trustMissingEmailVerified: false,
  });
  for (const tenant of ["common", "consumers", "organizations", WORK_TENANT]) {
    assert.equal(loadIdentityConfig({ ...base, SELFHOST_MICROSOFT_TENANT: tenant }).microsoft!.issuer, `https://login.microsoftonline.com/${tenant}/v2.0`);
  }
  for (const tenant of ["contoso", "Common", WORK_TENANT.toUpperCase(), "contoso.onmicrosoft.com", "common/v2.0"]) {
    assert.throws(() => loadIdentityConfig({ ...base, SELFHOST_MICROSOFT_TENANT: tenant }), /SELFHOST_MICROSOFT_TENANT must be/, tenant);
  }
  assert.equal(
    loadIdentityConfig({ ...base, SELFHOST_MICROSOFT_REDIRECT_URL: "https://relay.acme.test/login/microsoft/callback" }).microsoft!.redirectUrl,
    "https://relay.acme.test/login/microsoft/callback",
  );
  for (const redirect of ["https://relay.acme.test/login/oidc/callback", "https://relay.acme.test/login/microsoft/callback?x=1", "not a url"]) {
    assert.throws(() => loadIdentityConfig({ ...base, SELFHOST_MICROSOFT_REDIRECT_URL: redirect }), /SELFHOST_MICROSOFT_REDIRECT_URL must/, redirect);
  }
  const both = loadIdentityConfig({ ...base, SELFHOST_OIDC_ISSUER: "https://idp.acme.test", SELFHOST_OIDC_CLIENT_ID: "c", SELFHOST_OIDC_CLIENT_SECRET: "d" });
  assert.equal(both.oidc!.kind, "generic");
  assert.equal(both.oidc!.issuer, "https://idp.acme.test");
  assert.equal(both.microsoft!.kind, "microsoft");
});

test("microsoft: an invite to a personal account redeems through Continue with Microsoft", async (t) => {
  const ctx = await setup(t, { microsoft: {} });
  const { organizationId, owner, token } = await ownerInvite(ctx, "x@outlook.com", "member");

  const page = await call(ctx.origin, `/login?next=%2Fsettings&invite=${token}`);
  assert.equal(page.status, 200);
  assert.match(page.text, /<h1>Join Acme<\/h1>/);
  assert.match(page.text, /Ada Admin invited you to join as a member/);
  assert.match(page.text, /Sign in with your invited email to continue\./);
  const href = `/login/microsoft/start?next=%2Fsettings&amp;invite=${token}`;
  assert(page.text.includes(`<a class="btn secondary" href="${href}">Continue with Microsoft</a>`), page.text);

  // Wrong account first: refused, the way back keeps next + invite, no membership.
  const wrong = await microsoftSignIn(ctx, msAccount("other@outlook.com"), `?next=%2Fsettings&invite=${token}`);
  assert.equal(wrong.callback.status, 403);
  assert.match(wrong.callback.text, /This invite was sent to x@outlook\.com/);
  assert(wrong.callback.text.includes(`href="/login?next=%2Fsettings&amp;invite=${token}">Back to sign in</a>`), wrong.callback.text);
  assert.equal(wrong.cookie, null);
  const members = await call(ctx.origin, `/cloud/api/v1/organizations/${organizationId}/memberships`, { cookie: owner });
  assert.equal(members.status, 200, members.text);
  assert.equal(members.body.memberships.some((m: any) => m.email === "other@outlook.com" || m.email === "x@outlook.com"), false);

  const accepted = await microsoftSignIn(ctx, { ...msAccount("X@Outlook.com"), name: "Xavier" }, `?next=%2Fsettings&invite=${token}`);
  const location = new URL(accepted.start.headers.get("location")!);
  assert.equal(location.origin + location.pathname, `${MICROSOFT_HOST}/common/oauth2/v2.0/authorize`);
  assert.equal(location.searchParams.get("login_hint"), "x@outlook.com");
  assert.equal(location.searchParams.get("redirect_uri"), `${ctx.origin}/login/microsoft/callback`);
  assert.equal(location.searchParams.get("scope"), "openid email profile");
  assert.equal(location.searchParams.get("hd"), null);
  assert.match(accepted.start.headers.get("set-cookie")!, /agent_relay_microsoft=.*Path=\/login\/microsoft;.*HttpOnly/);
  assert.equal(accepted.callback.status, 303, accepted.callback.text);
  assert.equal(accepted.callback.headers.get("location"), "/settings");
  assert.match(accepted.callback.headers.getSetCookie().join("\n"), /agent_relay_microsoft=; Path=\/login\/microsoft; Max-Age=0/);
  const me = await whoami(ctx.origin, accepted.cookie!);
  assert.equal(me.body.user.email, "x@outlook.com");
  assert.equal(me.body.user.name, "Xavier");
  assert.equal(me.body.currentOrganization.id, organizationId);
  assert.equal(me.body.currentOrganization.role, "member");
  const audit = await ctx.database.query<{ target: string }>("SELECT target FROM admin_audit_events WHERE action = 'invitation.accept'");
  assert.equal(audit.rows.length, 1);
  assert.match(audit.rows[0]!.target, /x@outlook\.com role=member via=microsoft$/);
});

test("microsoft: tenant accounts need xms_edov; the issuer must name the token's tenant", async (t) => {
  const ctx = await setup(t, { microsoft: {} });
  const { token } = await ownerInvite(ctx, "dev@fabrikam.test", "member");
  const query = `?invite=${token}`;

  const unverified = await microsoftSignIn(ctx, msAccount("dev@fabrikam.test", WORK_TENANT), query);
  assert.equal(unverified.callback.status, 502);
  assert.match(unverified.callback.text, /isn&#39;t verified/);
  assert.equal(unverified.cookie, null);

  const falseClaim = await microsoftSignIn(ctx, msAccount("dev@fabrikam.test", WORK_TENANT, { xms_edov: false }), query);
  assert.equal(falseClaim.callback.status, 502);
  assert.match(falseClaim.callback.text, /isn&#39;t verified/);

  const otherIssuer = await microsoftSignIn(ctx, msAccount("dev@fabrikam.test", WORK_TENANT, {
    xms_edov: true,
    iss: `${MICROSOFT_HOST}/${PERSONAL_TENANT}/v2.0`,
  }), query);
  assert.equal(otherIssuer.callback.status, 502);
  assert.match(otherIssuer.callback.text, /issuer does not match/);

  const noTenant = await microsoftSignIn(ctx, msAccount("dev@fabrikam.test", null, { xms_edov: true }), query);
  assert.equal(noTenant.callback.status, 502);
  assert.match(noTenant.callback.text, /no Microsoft tenant/);

  const noEmail = await microsoftSignIn(ctx, { ...msAccount("dev@fabrikam.test", WORK_TENANT, { xms_edov: true }), noEmail: true }, query);
  assert.equal(noEmail.callback.status, 502);
  assert.match(noEmail.callback.text, /did not share an email address/);

  const verified = await microsoftSignIn(ctx, msAccount("dev@fabrikam.test", WORK_TENANT, { xms_edov: true }), query);
  assert.equal(verified.callback.status, 303, verified.callback.text);
  assert.equal((await whoami(ctx.origin, verified.cookie!)).body.currentOrganization.role, "member");

  // The string form Entra sometimes sends counts too.
  const { token: second } = await ownerInvite(ctx, "ops@fabrikam.test", "member");
  const stringClaim = await microsoftSignIn(ctx, msAccount("ops@fabrikam.test", WORK_TENANT, { xms_edov: "true" }), `?invite=${second}`);
  assert.equal(stringClaim.callback.status, 303, stringClaim.callback.text);
});

test("microsoft: consumers and single-tenant authorities only accept their own tenant", async (t) => {
  const consumers = await setup(t, { microsoft: { tenant: "consumers", discoveryIssuer: `${MICROSOFT_HOST}/${PERSONAL_TENANT}/v2.0` } });
  const { token } = await ownerInvite(consumers, "x@outlook.com", "member");
  const work = await microsoftSignIn(consumers, msAccount("x@outlook.com", WORK_TENANT, { xms_edov: true }), `?invite=${token}`);
  assert.equal(work.callback.status, 502);
  assert.match(work.callback.text, /issuer does not match/);
  assert.equal(new URL(work.start.headers.get("location")!).pathname, "/consumers/oauth2/v2.0/authorize");
  const personal = await microsoftSignIn(consumers, msAccount("x@outlook.com"), `?invite=${token}`);
  assert.equal(personal.callback.status, 303, personal.callback.text);

  // Discovery: the configured issuer, consumers' personal-account issuer, or the template; nothing else.
  const document = (issuer: string): FetchLike => async () => new Response(JSON.stringify({
    issuer,
    authorization_endpoint: `${MICROSOFT_HOST}/x/oauth2/v2.0/authorize`,
    token_endpoint: `${MICROSOFT_HOST}/x/oauth2/v2.0/token`,
    jwks_uri: `${MICROSOFT_HOST}/x/discovery/v2.0/keys`,
  }), { status: 200 });
  const client = (tenant: string, issuer: string) => new OidcClient(loadIdentityConfig({
    SELFHOST_MICROSOFT_CLIENT_ID: "a",
    SELFHOST_MICROSOFT_CLIENT_SECRET: "b",
    SELFHOST_MICROSOFT_TENANT: tenant,
  }).microsoft!, document(issuer));
  const accepted = async (tenant: string, issuer: string) => {
    try {
      return Boolean(await client(tenant, issuer).discovery());
    } catch (error) {
      assert.equal((error as OidcError).code, "discovery_invalid");
      return false;
    }
  };
  assert.equal(await accepted("consumers", `${MICROSOFT_HOST}/consumers/v2.0`), true);
  assert.equal(await accepted("consumers", `${MICROSOFT_HOST}/${PERSONAL_TENANT}/v2.0`), true);
  assert.equal(await accepted("consumers", `${MICROSOFT_HOST}/${WORK_TENANT}/v2.0`), false);
  assert.equal(await accepted("common", MICROSOFT_TEMPLATE_ISSUER), true);
  assert.equal(await accepted("common", `${MICROSOFT_HOST}/${WORK_TENANT}/v2.0`), false);
  assert.equal(await accepted(WORK_TENANT, `${MICROSOFT_HOST}/${WORK_TENANT}/v2.0`), true);
  assert.equal(await accepted(WORK_TENANT, `${MICROSOFT_HOST}/${PERSONAL_TENANT}/v2.0`), false);
  assert.equal(await accepted(WORK_TENANT, `${MICROSOFT_HOST}/${WORK_TENANT}/v2.0/`), false);
});

test("microsoft: a single-tenant authority refuses tokens from another tenant", async (t) => {
  const ctx = await setup(t, { microsoft: { tenant: WORK_TENANT } });
  const { token } = await ownerInvite(ctx, "dev@fabrikam.test", "member");
  const other = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
  const foreign = await microsoftSignIn(ctx, msAccount("dev@fabrikam.test", other, { xms_edov: true }), `?invite=${token}`);
  assert.equal(foreign.callback.status, 502);
  assert.match(foreign.callback.text, /issuer does not match/);
  const own = await microsoftSignIn(ctx, msAccount("dev@fabrikam.test", WORK_TENANT, { xms_edov: true }), `?invite=${token}`);
  assert.equal(own.callback.status, 303, own.callback.text);
});

test("microsoft beside generic OIDC: both buttons, both public configs, Desktop start", async (t) => {
  const ctx = await setup(t, { microsoft: {} });
  const login = await call(ctx.origin, "/login");
  const sso = login.text.indexOf(`<a class="btn" href="/login/oidc/start?next=%2F">Continue with Acme SSO</a>`);
  const ms = login.text.indexOf(`<a class="btn secondary" href="/login/microsoft/start?next=%2F">Continue with Microsoft</a>`);
  assert(sso >= 0 && ms > sso, login.text);

  // The generic flow is unchanged.
  const owner = await oidcSignIn(ctx, { email: "admin@acme.test" });
  assert.equal(owner.callback.status, 303, owner.callback.text);
  assert.equal((await whoami(ctx.origin, owner.cookie!)).body.currentOrganization.role, "owner");

  const config = await call(ctx.origin, "/api/v1/auth/login-config");
  assert.deepEqual(config.body.oidc, { displayName: "Acme SSO" });
  assert.deepEqual(config.body.microsoft, { displayName: "Microsoft" });
  const methods = await call(ctx.origin, "/cloud/api/v1/auth/methods", { cookie: owner.cookie! });
  assert.equal(methods.status, 200, methods.text);
  assert.deepEqual(methods.body.microsoft, { displayName: "Microsoft" });
  assert.equal(methods.body.oidc.displayName, "Acme SSO");

  const next = encodeURIComponent("/api/v1/cli/login");
  const microsoft = await call(ctx.origin, `/cloud/api/auth/microsoft/start?next=${next}`);
  assert.equal(microsoft.status, 302);
  assert.equal(microsoft.headers.get("location"), `/login/microsoft/start?next=${encodeURIComponent("/cloud/api/v1/cli/login")}`);
  assert.equal(microsoft.headers.get("set-cookie"), null);
  const google = await call(ctx.origin, `/cloud/api/auth/google/start?next=${next}`);
  assert.equal(google.status, 302);
  assert.equal(google.headers.get("location"), `/login?next=${encodeURIComponent("/cloud/api/v1/cli/login")}`);
});

test("microsoft not configured: no button, start answers 404, Desktop start lands on the /login chooser", async (t) => {
  const ctx = await setup(t);
  const login = await call(ctx.origin, "/login");
  assert.doesNotMatch(login.text, /Continue with Microsoft/);
  const start = await call(ctx.origin, "/login/microsoft/start");
  assert.equal(start.status, 404);
  assert.match(start.text, /Microsoft sign-in is not configured/);
  assert.equal((await call(ctx.origin, "/api/v1/auth/login-config")).body.microsoft, null);
  // Generic OIDC is configured here, yet the Microsoft start lands on the chooser.
  const next = encodeURIComponent("/api/v1/cli/login");
  const microsoft = await call(ctx.origin, `/cloud/api/auth/microsoft/start?next=${next}`);
  assert.equal(microsoft.status, 302);
  assert.equal(microsoft.headers.get("location"), `/login?next=${encodeURIComponent("/cloud/api/v1/cli/login")}`);
  assert.equal(microsoft.headers.get("set-cookie"), null);
  const google = await call(ctx.origin, `/cloud/api/auth/google/start?next=${next}`);
  assert.equal(google.headers.get("location"), `/login?next=${encodeURIComponent("/cloud/api/v1/cli/login")}`);
});

// ---- invites ------------------------------------------------------------------------

test("invites: owner invites, email + copyable link, invitee joins through SSO, audit rows", async (t) => {
  const ctx = await setup(t, { mailer: true });
  const owner = (await oidcSignIn(ctx, { email: "admin@acme.test", name: "Ada Admin" })).cookie!;
  const id = (await whoami(ctx.origin, owner)).body.currentOrganization.id;

  const created = await call(ctx.origin, `/cloud/api/v1/organizations/${id}/invitations`, {
    method: "POST", cookie: owner, json: { email: "Bob@Acme.test", role: "member" },
  });
  assert.equal(created.status, 201, created.text);
  assert.equal(created.body.invitation.email, "bob@acme.test");
  assert.equal(created.body.invitation.status, "pending");
  assert.equal(created.body.invitation.invitedBy.email, "admin@acme.test");
  assert.equal(created.body.emailDelivery, "sent");
  const inviteUrl = new URL(created.body.inviteUrl);
  assert.equal(inviteUrl.pathname, "/login");
  const token = inviteUrl.searchParams.get("invite")!;
  assert.match(token, /^sh_inv_/);
  assert.equal(ctx.mailer.sent.length, 1);
  assert.equal(ctx.mailer.sent[0]!.to, "bob@acme.test");
  assert.equal(ctx.mailer.sent[0]!.subject, "You've been invited to join Acme on Agent Relay");
  assert.match(ctx.mailer.sent[0]!.text, /Ada Admin invited you to join "Acme" on Agent Relay as a member/);
  assert(ctx.mailer.sent[0]!.text.includes(created.body.inviteUrl));
  // Only the hash is stored.
  const stored = await ctx.database.query<{ token_hash: string }>("SELECT token_hash FROM organization_invitations");
  assert.equal(stored.rows[0]!.token_hash, createHash("sha256").update(token).digest("hex"));

  const list = await call(ctx.origin, `/cloud/api/v1/organizations/${id}/invitations`, { cookie: owner });
  assert.equal(list.body.invitations.length, 1);
  assert.equal(JSON.stringify(list.body).includes(token), false, "list never returns the link");

  // The invite page.
  const page = await call(ctx.origin, `/login?invite=${token}`);
  assert.match(page.text, /Join Acme/);
  assert.match(page.text, /Ada Admin invited you to join as a member/);
  assert.match(page.text, /bob@acme\.test/);

  // Wrong account first: refused, invite still open.
  const wrong = await oidcSignIn(ctx, { email: "carol@acme.test" }, `?invite=${token}`);
  assert.equal(wrong.callback.status, 403);
  assert.match(wrong.callback.text, /This invite was sent to bob@acme\.test/);

  const accepted = await oidcSignIn(ctx, { email: "bob@acme.test", name: "Bob Builder" }, `?invite=${token}`);
  assert.equal(accepted.callback.status, 303);
  const bob = await whoami(ctx.origin, accepted.cookie!);
  assert.equal(bob.body.currentOrganization.role, "member");
  assert.equal(bob.body.user.name, "Bob Builder");

  // Single use.
  const reused = await oidcSignIn(ctx, { email: "carol@acme.test" }, `?invite=${token}`);
  assert.equal(reused.callback.status, 410);
  const members = await call(ctx.origin, `/cloud/api/v1/organizations/${id}/memberships`, { cookie: owner });
  assert.deepEqual(members.body.memberships.map((m: any) => [m.email, m.role]), [["admin@acme.test", "owner"], ["bob@acme.test", "member"]]);
  assert.equal((await call(ctx.origin, `/cloud/api/v1/organizations/${id}/invitations`, { cookie: owner })).body.invitations.length, 0);

  const audit = await ctx.database.query<{ action: string; actor_kind: string }>(
    "SELECT action, actor_kind FROM admin_audit_events WHERE action LIKE 'invitation.%' ORDER BY created_at",
  );
  assert.deepEqual(audit.rows.map((r) => [r.action, r.actor_kind]), [["invitation.create", "user"], ["invitation.accept", "user"]]);
});

test("invites: roles, revoke, rotate, expiry, auto-accept, duplicates and CSRF", async (t) => {
  let clock = Date.now();
  const ctx = await setup(t);
  const owner = (await oidcSignIn(ctx, { email: "admin@acme.test" })).cookie!;
  const id = (await whoami(ctx.origin, owner)).body.currentOrganization.id;
  const invite = (email: string, role: string, cookie = owner) => call(ctx.origin, `/cloud/api/v1/organizations/${id}/invitations`, {
    method: "POST", cookie, json: { email, role },
  });

  // Admin invited, joins without the link (auto-accept on sign-in).
  const adminInvite = await invite("dana@acme.test", "admin");
  assert.equal(adminInvite.body.emailDelivery, "not_configured");
  const dana = (await oidcSignIn(ctx, { email: "dana@acme.test" })).cookie!;
  assert.equal((await whoami(ctx.origin, dana)).body.currentOrganization.role, "admin");

  // Admins invite members and admins, never owners.
  assert.equal((await invite("erin@acme.test", "owner", dana)).status, 403);
  assert.equal((await invite("erin@acme.test", "member", dana)).status, 201);
  // Members can't invite.
  const memberInvite = await invite("finn@acme.test", "member");
  const finn = (await oidcSignIn(ctx, { email: "finn@acme.test" })).cookie!;
  void memberInvite;
  assert.equal((await invite("gail@acme.test", "member", finn)).status, 403);
  assert.equal((await call(ctx.origin, `/cloud/api/v1/organizations/${id}/invitations`, { cookie: finn })).status, 403);

  // Already a member; bad email.
  assert.equal((await invite("finn@acme.test", "member")).status, 409);
  assert.equal((await invite("not-an-email", "member")).status, 400);

  // Re-inviting replaces the open invite: the first link stops working.
  const first = await invite("hank@acme.test", "member");
  const second = await invite("hank@acme.test", "admin");
  const list = await call(ctx.origin, `/cloud/api/v1/organizations/${id}/invitations`, { cookie: owner });
  assert.deepEqual(list.body.invitations.map((i: any) => [i.email, i.role]), [["hank@acme.test", "admin"], ["erin@acme.test", "member"]]);
  const firstToken = new URL(first.body.inviteUrl).searchParams.get("invite")!;
  assert.equal((await oidcSignIn(ctx, { email: "hank@acme.test" }, `?invite=${firstToken}`)).callback.status, 410);

  // Rotate: a new link, the old one dies.
  const rotated = await call(ctx.origin, `/cloud/api/v1/organizations/${id}/invitations/${second.body.invitation.id}/link`, {
    method: "POST", cookie: owner, json: {},
  });
  assert.equal(rotated.status, 200);
  assert.notEqual(rotated.body.inviteUrl, second.body.inviteUrl);
  const oldToken = new URL(second.body.inviteUrl).searchParams.get("invite")!;
  assert.match((await call(ctx.origin, `/login?invite=${oldToken}`)).text, /not valid/);

  // Revoke.
  assert.equal((await call(ctx.origin, `/cloud/api/v1/organizations/${id}/invitations/${second.body.invitation.id}`, { method: "DELETE", cookie: owner })).status, 200);
  const newToken = new URL(rotated.body.inviteUrl).searchParams.get("invite")!;
  assert.match((await call(ctx.origin, `/login?invite=${newToken}`)).text, /canceled/);
  assert.equal((await oidcSignIn(ctx, { email: "hank@acme.test" }, `?invite=${newToken}`)).callback.status, 410);
  assert.equal((await call(ctx.origin, `/cloud/api/v1/organizations/${id}/invitations/${second.body.invitation.id}`, { method: "DELETE", cookie: owner })).status, 409);

  // Cookie mutations need a same-origin JSON request.
  const csrf = await call(ctx.origin, `/cloud/api/v1/organizations/${id}/invitations`, {
    method: "POST", cookie: owner, json: { email: "ivy@acme.test" }, originHeader: "https://evil.example",
  });
  assert.equal(csrf.status, 403);
  assert.equal(csrf.body.error, "csrf_rejected");
  // The bootstrap bearer (break-glass) can invite too.
  const breakGlass = await call(ctx.origin, `/api/v1/organizations/${id}/invitations`, { method: "POST", token: BOOTSTRAP, json: { email: "ivy@acme.test", role: "owner" } });
  assert.equal(breakGlass.status, 201);
  void clock;
  clock += 1;
});

test("invites: an expired link is refused", async (t) => {
  let now = Date.now();
  const ctx = await setup(t);
  const expiring = new IdentityStore(ctx.database, KEYRING, {
    inviteTtlMs: 60_000,
    autoJoinDomains: [],
    issueSession: (tx, session) => ctx.store.issueBrowserSession(tx, session),
    now: () => now,
  });
  const id = await orgId(ctx);
  const created = await expiring.createInvitation({ organizationId: id, email: "late@acme.test", role: "member", actor: { kind: "bootstrap" } });
  now += 61_000;
  await assert.rejects(
    expiring.signIn({ email: "late@acme.test", name: null, inviteTokenHash: createHash("sha256").update(created.token).digest("hex"), method: "oidc" }),
    /expired/,
  );
  assert.equal((await expiring.describeInvitation(created.token))!.status, "expired");
});

test("auto-join: a verified email in an allowed domain joins as member", async (t) => {
  const ctx = await setup(t, { env: { SELFHOST_AUTO_JOIN_DOMAINS: "acme.test" } });
  const joined = await oidcSignIn(ctx, { email: "newbie@acme.test" });
  assert.equal(joined.callback.status, 303);
  assert.equal((await whoami(ctx.origin, joined.cookie!)).body.currentOrganization.role, "member");
  assert.equal((await oidcSignIn(ctx, { email: "x@other.test" })).callback.status, 403);
  const audit = await ctx.database.query<{ action: string }>("SELECT action FROM admin_audit_events WHERE action = 'membership.auto_join'");
  assert.equal(audit.rows.length, 1);
});

// ---- email sign-in links ------------------------------------------------------------

test("email links: members and invitees get a single-use link; others get the same answer and no mail", async (t) => {
  const ctx = await setup(t, { mailer: true });
  const login = await call(ctx.origin, "/login");
  assert.match(login.text, /Email me a sign-in link/);

  const asked = await call(ctx.origin, "/login/email", { method: "POST", form: { email: "admin@acme.test", next: "/flows" } });
  assert.equal(asked.status, 200);
  assert.match(asked.text, /Check your email/);
  assert.equal(ctx.mailer.sent.length, 1);
  const link = new URL(/Sign in: (\S+)/.exec(ctx.mailer.sent[0]!.text)![1]!);
  assert.equal(link.pathname, "/login/email/verify");

  const stranger = await call(ctx.origin, "/login/email", { method: "POST", form: { email: "nobody@acme.test", next: "/" } });
  assert.equal(stranger.status, 200);
  assert.equal(stranger.text.replace(/nobody@acme\.test/, "X"), asked.text.replace(/admin@acme\.test/, "X").replace(/%2Fflows/g, "%2F"));
  assert.equal(ctx.mailer.sent.length, 1);

  // GET only confirms (mail scanners prefetch links); POST signs in.
  const confirm = await call(ctx.origin, `${link.pathname}${link.search}`);
  assert.match(confirm.text, /Continue as <strong>admin@acme\.test<\/strong>/);
  const token = link.searchParams.get("token")!;
  const crossSite = await call(ctx.origin, "/login/email/verify", { method: "POST", form: { token }, originHeader: "https://evil.example" });
  assert.equal(crossSite.status, 403);
  const done = await call(ctx.origin, "/login/email/verify", { method: "POST", form: { token } });
  assert.equal(done.status, 303);
  assert.equal(done.headers.get("location"), "/flows");
  const cookie = `agent_relay_session=${encodeURIComponent(done.cookies.agent_relay_session!)}`;
  assert.equal((await whoami(ctx.origin, cookie)).body.currentOrganization.role, "owner");
  const reused = await call(ctx.origin, "/login/email/verify", { method: "POST", form: { token } });
  assert.equal(reused.status, 410);

  // An invitee joins through the emailed link.
  const owner = cookie;
  const id = (await whoami(ctx.origin, owner)).body.currentOrganization.id;
  const created = await call(ctx.origin, `/cloud/api/v1/organizations/${id}/invitations`, { method: "POST", cookie: owner, json: { email: "zoe@acme.test", role: "admin" } });
  const inviteToken = new URL(created.body.inviteUrl).searchParams.get("invite")!;
  await call(ctx.origin, "/login/email", { method: "POST", form: { email: "zoe@acme.test", next: "/", invite: inviteToken } });
  const zoeLink = new URL(/Sign in: (\S+)/.exec(ctx.mailer.sent.at(-1)!.text)![1]!);
  const zoe = await call(ctx.origin, "/login/email/verify", { method: "POST", form: { token: zoeLink.searchParams.get("token")! } });
  assert.equal(zoe.status, 303);
  const zoeCookie = `agent_relay_session=${encodeURIComponent(zoe.cookies.agent_relay_session!)}`;
  assert.equal((await whoami(ctx.origin, zoeCookie)).body.currentOrganization.role, "admin");

  // Rate limit per address.
  for (let i = 0; i < 3; i += 1) await call(ctx.origin, "/login/email", { method: "POST", form: { email: "rate@acme.test", next: "/" } });
  assert.equal((await call(ctx.origin, "/login/email", { method: "POST", form: { email: "rate@acme.test", next: "/" } })).status, 429);
});

test("invites: SMTP failure still returns a copyable link", async (t) => {
  const ctx = await setup(t, { mailer: true });
  ctx.mailer.fail = true;
  const id = await orgId(ctx);
  const created = await call(ctx.origin, `/api/v1/organizations/${id}/invitations`, { method: "POST", token: BOOTSTRAP, json: { email: "q@acme.test" } });
  assert.equal(created.status, 201);
  assert.equal(created.body.emailDelivery, "failed");
  assert.match(created.body.inviteUrl, /\/login\?invite=sh_inv_/);
});

// ---- membership guards --------------------------------------------------------------

test("memberships: admins cannot grant, change or remove owners; changes are audited", async (t) => {
  const ctx = await setup(t);
  const owner = (await oidcSignIn(ctx, { email: "admin@acme.test" })).cookie!;
  const id = (await whoami(ctx.origin, owner)).body.currentOrganization.id;
  await call(ctx.origin, `/cloud/api/v1/organizations/${id}/invitations`, { method: "POST", cookie: owner, json: { email: "ad@acme.test", role: "admin" } });
  const admin = (await oidcSignIn(ctx, { email: "ad@acme.test" })).cookie!;
  const put = (cookie: string, email: string, role: string) => call(ctx.origin, `/cloud/api/v1/organizations/${id}/memberships`, {
    method: "POST", cookie, json: { email, name: email, role },
  });
  assert.equal((await put(admin, "new@acme.test", "owner")).status, 403);
  assert.equal((await put(admin, "admin@acme.test", "member")).status, 403);
  assert.equal((await put(admin, "new@acme.test", "member")).status, 200);
  const ownerRow = (await call(ctx.origin, `/cloud/api/v1/organizations/${id}/memberships`, { cookie: owner })).body.memberships.find((m: any) => m.email === "admin@acme.test");
  assert.equal((await call(ctx.origin, `/cloud/api/v1/organizations/${id}/memberships/${ownerRow.userId}`, { method: "DELETE", cookie: admin })).status, 403);
  assert.equal((await put(owner, "ad@acme.test", "owner")).status, 200);
  const audit = await ctx.database.query<{ action: string }>("SELECT action FROM admin_audit_events WHERE action LIKE 'membership.update' ");
  assert.equal(audit.rows.length, 2);
});

test("login page without SSO or email shows the operator code openly", async (t) => {
  const ctx = await setup(t, { env: {} });
  // A module with no sign-in methods at all.
  const bare = createIdentityModule({
    config: loadIdentityConfig({}),
    identityStore: ctx.identityStore,
    controlStore: ctx.store,
    keyring: KEYRING,
    dashboardUrl: `${ctx.origin}/`,
    mailer: null,
    log: () => undefined,
  });
  const server: Server = createServer(createApp({
    config: {
      databaseUrl: "unused", publicBaseUrl: ctx.origin, relaycastUrl: "http://relaycast.invalid", relaycastPublicUrl: "https://relaycast.selfhosted.test",
      relayhistoryUrl: "http://relayhistory.invalid", relayhistoryPublicUrl: "https://history.selfhosted.test",
      sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: "https://history.selfhosted.test", secret: "session-read-secret-".repeat(2) },
      bootstrapToken: BOOTSTRAP, encryptionKeyring: KEYRING, internalServiceToken: null,
      oauthRedirectUrl: `${ctx.origin}/cb`, dashboardUrl: `${ctx.origin}/`, port: 0, host: "127.0.0.1",
    },
    store: ctx.store,
    identity: bare,
  }));
  const origin = await listen(server);
  t.after(() => close(server));
  const page = await call(origin, "/login");
  assert.match(page.text, /No sign-in method is configured/);
  assert.match(page.text, /<details open>/);
  assert.equal((await call(origin, "/login/oidc/start")).status, 404);
});

// ---- multi tenancy (SELFHOST_TENANCY=multi) -------------------------------------

async function settings(origin: string, patch: Record<string, boolean | null>) {
  const result = await call(origin, "/api/v1/installation/settings", { method: "PATCH", token: BOOTSTRAP, json: patch });
  assert.equal(result.status, 200, result.text);
  return result.body;
}

async function currentOrganization(origin: string, cookie: string): Promise<string> {
  const session = await call(origin, "/cloud/api/auth/session", { cookie });
  assert.equal(session.status, 200, session.text);
  return session.body.currentOrganization.id;
}

test("multi: personalOrgSignupEnabled kill switch overrides the env default; null restores it", async (t) => {
  const ctx = await setup(t, { multi: true });
  const initial = await call(ctx.origin, "/api/v1/installation/settings", { token: BOOTSTRAP });
  assert.equal(initial.status, 200);
  assert.deepEqual(initial.body.effective, { personalOrgOnSignIn: true, selfServeOrganizations: true });
  assert.equal(initial.body.personalOrgSignupEnabled, null);

  // Env default (true): a stranger's first sign-in creates a personal organization.
  const creates = ctx.relaycast.state.creates;
  const first = await oidcSignIn(ctx, { email: "first@elsewhere.test", name: "First Person" });
  assert(first.cookie, first.callback.text);
  const personal = await call(ctx.origin, "/cloud/api/auth/session", { cookie: first.cookie });
  assert.equal(personal.body.currentOrganization.name, "First Person's Workspace");
  assert.equal(personal.body.currentOrganization.role, "owner");
  assert.equal(ctx.relaycast.state.creates, creates + 1);

  // Only the bootstrap bearer may change the switches.
  assert.equal((await call(ctx.origin, "/api/v1/installation/settings", { cookie: first.cookie })).status, 401);
  const asOwner = await call(ctx.origin, "/cloud/api/v1/installation/settings", { method: "PATCH", cookie: first.cookie, json: { personalOrgSignupEnabled: false } });
  assert.equal(asOwner.status, 403, asOwner.text);

  const off = await settings(ctx.origin, { personalOrgSignupEnabled: false });
  assert.equal(off.personalOrgSignupEnabled, false);
  assert.equal(off.effective.personalOrgOnSignIn, false);
  const refused = await oidcSignIn(ctx, { email: "second@elsewhere.test" });
  assert.equal(refused.callback.status, 403, refused.callback.text);
  assert.equal(refused.cookie, null);
  assert.match(refused.callback.text, /isn(&#39;|')t a member of any organization/);
  const leftover = await ctx.database.query("SELECT 1 FROM users WHERE email = 'second@elsewhere.test'");
  assert.equal(leftover.rows.length, 0, "a refused sign-in leaves no user row");
  // An existing member still signs in.
  assert((await oidcSignIn(ctx, { email: "first@elsewhere.test" })).cookie);

  const restored = await settings(ctx.origin, { personalOrgSignupEnabled: null });
  assert.equal(restored.personalOrgSignupEnabled, null);
  assert.equal(restored.effective.personalOrgOnSignIn, true);
  const again = await oidcSignIn(ctx, { email: "second@elsewhere.test", name: "Second Person" });
  assert(again.cookie, again.callback.text);
  const audit = await ctx.database.query<{ target: string }>(
    "SELECT target FROM admin_audit_events WHERE action = 'installation.settings' ORDER BY created_at",
  );
  assert.equal(audit.rows.length, 2);
});

test("multi: selfServeOrganizationsEnabled kill switch overrides the env default; null restores it", async (t) => {
  const ctx = await setup(t, { multi: true });
  const person = await oidcSignIn(ctx, { email: "maker@elsewhere.test", name: "Maker" });
  assert(person.cookie);
  const create = (name: string, init: { originHeader?: string | null } = {}) =>
    call(ctx.origin, "/cloud/api/v1/organizations", { method: "POST", cookie: person.cookie!, json: { name }, ...init });

  // Env default (true): a signed-in person creates an organization they own.
  const created = await create("Side Project");
  assert.equal(created.status, 201, created.text);
  assert.equal(created.body.name, "Side Project");
  assert.equal(created.body.workspace.name, "Default");
  const owners = await ctx.database.query<{ role: string }>(
    "SELECT role FROM organization_memberships WHERE organization_id = $1", [created.body.id],
  );
  assert.deepEqual(owners.rows.map((row) => row.role), ["owner"]);
  // A cross-site cookie request is refused before anything is created.
  assert.equal((await create("Forged", { originHeader: "https://evil.example" })).status, 403);

  await settings(ctx.origin, { selfServeOrganizationsEnabled: false });
  const refused = await create("Refused");
  assert.equal(refused.status, 403, refused.text);
  assert.equal(refused.body.error, "self_serve_disabled");
  // The bootstrap bearer still creates organizations (the operator route).
  const operator = await call(ctx.origin, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, json: { name: "Operator Made", ownerEmail: "op-owner@elsewhere.test", ownerName: "Op Owner" },
  });
  assert.equal(operator.status, 201, operator.text);

  const restored = await settings(ctx.origin, { selfServeOrganizationsEnabled: null });
  assert.equal(restored.effective.selfServeOrganizations, true);
  assert.equal((await create("Second Project")).status, 201);
  const names = await ctx.database.query<{ name: string }>("SELECT name FROM organizations ORDER BY created_at");
  assert(!names.rows.some((row) => row.name === "Refused" || row.name === "Forged"));
});

test("multi DG-002: operator-assigned domains, verified emails only, invites and memberships take precedence", async (t) => {
  const ctx = await setup(t, { multi: true });
  const acme = await orgId(ctx);
  const owner = await oidcSignIn(ctx, { email: "admin@acme.test" });
  assert(owner.cookie);

  // Only the bootstrap bearer assigns domains; owners get 403 and may read.
  const byOwner = await call(ctx.origin, `/cloud/api/v1/organizations/${acme}/domains/acme.test`, { method: "PUT", cookie: owner.cookie });
  assert.equal(byOwner.status, 403, byOwner.text);
  const assigned = await call(ctx.origin, `/api/v1/organizations/${acme}/domains/ACME.test`, { method: "PUT", token: BOOTSTRAP });
  assert.equal(assigned.status, 201, assigned.text);
  assert.equal(assigned.body.domain, "acme.test");
  assert.equal((await call(ctx.origin, `/api/v1/organizations/${acme}/domains/acme.test`, { method: "PUT", token: BOOTSTRAP })).status, 200);
  const listed = await call(ctx.origin, `/cloud/api/v1/organizations/${acme}/domains`, { cookie: owner.cookie });
  assert.deepEqual(listed.body.domains, ["acme.test"]);

  // A domain belongs to one organization: a competing assignment is 409.
  const other = await call(ctx.origin, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, json: { name: "Other Co", ownerEmail: "boss@other.test", ownerName: "Boss" },
  });
  assert.equal(other.status, 201, other.text);
  const otherId = other.body.id as string;
  const otherWorkspace = await call(ctx.origin, `/api/v1/organizations/${otherId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, json: { name: "Other", relaycastWorkspaceId: "rw_other", relaycastApiKey: "rk_other" },
  });
  assert.equal(otherWorkspace.status, 201, otherWorkspace.text);
  const competing = await call(ctx.origin, `/api/v1/organizations/${otherId}/domains/acme.test`, { method: "PUT", token: BOOTSTRAP });
  assert.equal(competing.status, 409, competing.text);
  assert.equal(competing.body.error, "domain_assigned");

  // A verified address at the domain joins as member.
  const verified = await oidcSignIn(ctx, { email: "dev@acme.test" });
  assert(verified.cookie, verified.callback.text);
  assert.equal(await currentOrganization(ctx.origin, verified.cookie), acme);

  // An address without the email_verified claim never auto-joins.
  await settings(ctx.origin, { personalOrgSignupEnabled: false });
  const unverified = await oidcSignIn(ctx, { email: "unverified@acme.test", emailVerified: null });
  assert.equal(unverified.callback.status, 403, unverified.callback.text);
  await settings(ctx.origin, { personalOrgSignupEnabled: null });
  const personal = await oidcSignIn(ctx, { email: "unverified@acme.test", emailVerified: null, name: "Unverified" });
  assert(personal.cookie, personal.callback.text);
  assert.notEqual(await currentOrganization(ctx.origin, personal.cookie), acme);

  // An open invite beats the domain.
  const invited = await call(ctx.origin, `/api/v1/organizations/${otherId}/invitations`, {
    method: "POST", token: BOOTSTRAP, json: { email: "invited@acme.test", role: "member" },
  });
  assert.equal(invited.status, 201, invited.text);
  const viaInvite = await oidcSignIn(ctx, { email: "invited@acme.test" });
  assert(viaInvite.cookie, viaInvite.callback.text);
  assert.equal(await currentOrganization(ctx.origin, viaInvite.cookie), otherId);

  // An existing membership beats the domain.
  const added = await call(ctx.origin, `/api/v1/organizations/${otherId}/memberships`, {
    method: "POST", token: BOOTSTRAP, json: { email: "member@acme.test", name: "Member", role: "member" },
  });
  assert.equal(added.status, 200, added.text);
  const viaMembership = await oidcSignIn(ctx, { email: "member@acme.test" });
  assert(viaMembership.cookie, viaMembership.callback.text);
  assert.equal(await currentOrganization(ctx.origin, viaMembership.cookie), otherId);

  const acmeMembers = await ctx.database.query<{ email: string }>(
    `SELECT u.email FROM organization_memberships m JOIN users u ON u.id = m.user_id
      WHERE m.organization_id = $1 ORDER BY u.email`, [acme],
  );
  assert.deepEqual(acmeMembers.rows.map((row) => row.email), ["admin@acme.test", "dev@acme.test"]);

  // Unassigning stops further auto-joins.
  assert.equal((await call(ctx.origin, `/api/v1/organizations/${acme}/domains/acme.test`, { method: "DELETE", token: BOOTSTRAP })).status, 204);
  assert.equal((await call(ctx.origin, `/api/v1/organizations/${acme}/domains/acme.test`, { method: "DELETE", token: BOOTSTRAP })).status, 404);
  const late = await oidcSignIn(ctx, { email: "late@acme.test", name: "Late" });
  assert(late.cookie);
  assert.notEqual(await currentOrganization(ctx.origin, late.cookie), acme);
});

test("single DG-002/DG-004: SELFHOST_AUTO_JOIN_DOMAINS is the authority; the domain routes refuse changes", async (t) => {
  const ctx = await setup(t, { env: { SELFHOST_AUTO_JOIN_DOMAINS: "acme.test" } });
  const acme = await orgId(ctx);
  const put = await call(ctx.origin, `/api/v1/organizations/${acme}/domains/other.test`, { method: "PUT", token: BOOTSTRAP });
  assert.equal(put.status, 409, put.text);
  assert.equal(put.body.error, "domains_managed_by_env");
  assert.equal((await call(ctx.origin, `/api/v1/organizations/${acme}/domains/acme.test`, { method: "DELETE", token: BOOTSTRAP })).status, 409);
  assert.deepEqual((await call(ctx.origin, `/api/v1/organizations/${acme}/domains`, { token: BOOTSTRAP })).body.domains, ["acme.test"]);
  // Single mode has no installation switches to turn on.
  const settingsView = await call(ctx.origin, "/api/v1/installation/settings", { token: BOOTSTRAP });
  assert.deepEqual(settingsView.body.effective, { personalOrgOnSignIn: false, selfServeOrganizations: false });
});

test("multi: self-serve organizations need the browser account session; CLI tokens get reauthentication_required", async (t) => {
  const ctx = await setup(t, { multi: true });
  const person = await oidcSignIn(ctx, { email: "maker@elsewhere.test", name: "Maker" });
  assert(person.cookie);
  const me = (await whoami(ctx.origin, person.cookie)).body;
  // A CLI device token for the same person (DEVICE_SCOPES, no account scope).
  const started = await call(ctx.origin, "/api/v1/auth/device/start", { method: "POST", json: { client_name: "cli" } });
  assert.equal(started.status, 201, started.text);
  const approved = await call(ctx.origin, "/api/v1/auth/device/approve", {
    method: "POST", token: BOOTSTRAP,
    json: { action: "approve", user_code: started.body.user_code, user_id: me.user.id, workspace_id: me.currentWorkspace.id },
  });
  assert.equal(approved.status, 200, approved.text);
  const issued = await call(ctx.origin, "/api/v1/auth/device/token", { method: "POST", json: { device_code: started.body.device_code } });
  assert.equal(issued.status, 200, issued.text);

  const creates = ctx.relaycast.state.creates;
  for (const path of ["/api/v1/organizations", "/cloud/api/v1/organizations"]) {
    const refused = await call(ctx.origin, path, { method: "POST", token: issued.body.access_token, json: { name: "From CLI" } });
    assert.equal(refused.status, 403, refused.text);
    assert.equal(refused.body.error, "reauthentication_required");
  }
  assert.equal(ctx.relaycast.state.creates, creates, "nothing was provisioned");
  const created = await call(ctx.origin, "/cloud/api/v1/organizations", { method: "POST", cookie: person.cookie, json: { name: "From Browser" } });
  assert.equal(created.status, 201, created.text);
});

test("multi: a Relaycast workspace is released when COMMIT reports a definite abort (SQLSTATE 40001)", async (t) => {
  const ctx = await setup(t, { multi: true });
  const person = await oidcSignIn(ctx, { email: "maker@elsewhere.test", name: "Maker" });
  assert(person.cookie);
  const me = (await whoami(ctx.origin, person.cookie)).body;

  // After the store's body ran, the wrapper throws inside the underlying
  // transaction instead of letting it commit, so it really rolls back, and
  // the rejection carries the serialization_failure SQLSTATE a server-side
  // COMMIT abort reports: a proven abort, so the workspace is released.
  const failing: typeof ctx.database = Object.create(ctx.database);
  failing.transaction = (run) => ctx.database.transaction(async (tx) => {
    let insertedWorkspace = false;
    const watched = Object.create(tx) as typeof tx;
    watched.query = (sql: string, params?: unknown[]) => {
      if (/INSERT INTO workspaces/.test(sql)) insertedWorkspace = true;
      return tx.query(sql, params);
    };
    const result = await run(watched);
    if (insertedWorkspace) {
      throw Object.assign(new Error("could not serialize access due to read/write dependencies"), { code: "40001" });
    }
    return result;
  }) as never;
  const { provisioned, store } = lossyIdentityStore(ctx, failing);

  // Self-serve organization.
  await assert.rejects(
    store.createOrganizationForUser({ userId: me.user.id, email: "maker@elsewhere.test", name: "Doomed" }),
    (error: any) => error.code === "40001" && /could not serialize/.test(error.message),
  );
  assert.deepEqual(provisioned.removed, ["rw_1"]);
  // Personal organization on first sign-in.
  await assert.rejects(
    store.signIn({ email: "newcomer@elsewhere.test", name: "Newcomer", inviteTokenHash: null, method: "email" }),
    (error: any) => error.code === "40001",
  );
  assert.deepEqual(provisioned.created, ["rw_1", "rw_2"]);
  assert.deepEqual(provisioned.removed, ["rw_1", "rw_2"]);
  const leftover = await ctx.database.query("SELECT 1 FROM workspaces WHERE relaycast_workspace_id LIKE 'rw\\_%'");
  assert.equal(leftover.rows.length, 0);
});

test("multi: a Relaycast workspace is retained when a rolled-back COMMIT reports no SQLSTATE", async (t) => {
  const ctx = await setup(t, { multi: true });
  const person = await oidcSignIn(ctx, { email: "maker@elsewhere.test", name: "Maker" });
  assert(person.cookie);
  const me = (await whoami(ctx.origin, person.cookie)).body;

  // The underlying transaction really rolls back, but the rejection carries
  // no SQLSTATE, so nothing proves the abort: the workspace is retained
  // (leaked to operator reconciliation rather than risked).
  const failing: typeof ctx.database = Object.create(ctx.database);
  failing.transaction = (run) => ctx.database.transaction(async (tx) => {
    let insertedWorkspace = false;
    const watched = Object.create(tx) as typeof tx;
    watched.query = (sql: string, params?: unknown[]) => {
      if (/INSERT INTO workspaces/.test(sql)) insertedWorkspace = true;
      return tx.query(sql, params);
    };
    const result = await run(watched);
    if (insertedWorkspace) throw new Error("commit failed");
    return result;
  }) as never;
  const { provisioned, store } = lossyIdentityStore(ctx, failing);

  await assert.rejects(
    store.createOrganizationForUser({ userId: me.user.id, email: "maker@elsewhere.test", name: "Unproven" }),
    /\(commit failed\); Relaycast workspace rw_1 was retained for operator reconciliation/,
  );
  await assert.rejects(
    store.signIn({ email: "newcomer@elsewhere.test", name: "Newcomer", inviteTokenHash: null, method: "email" }),
    /Relaycast workspace rw_2 was retained for operator reconciliation/,
  );
  assert.deepEqual(provisioned.created, ["rw_1", "rw_2"]);
  assert.deepEqual(provisioned.removed, [], "an unproven abort is never released");
});

test("multi: a Relaycast workspace is released without verification when the body throws after binding it", async (t) => {
  const ctx = await setup(t, { multi: true });
  const person = await oidcSignIn(ctx, { email: "maker@elsewhere.test", name: "Maker" });
  assert(person.cookie);
  const me = (await whoami(ctx.origin, person.cookie)).body;

  // The body throws on the first query after INSERT INTO workspaces,
  // before the callback returns: the transaction rolls back before COMMIT.
  let verifications = 0;
  const VERIFY = /SELECT 1 FROM workspaces WHERE relaycast_workspace_id/;
  const failing: typeof ctx.database = Object.create(ctx.database);
  failing.query = ((sql: string, params?: unknown[]) => {
    if (VERIFY.test(sql)) verifications += 1;
    return ctx.database.query(sql, params);
  }) as never;
  failing.transaction = ((run: Parameters<typeof ctx.database.transaction>[0]) => ctx.database.transaction((tx) => {
    let insertedWorkspace = false;
    const watched = Object.create(tx) as typeof tx;
    watched.query = (sql: string, params?: unknown[]) => {
      if (VERIFY.test(sql)) verifications += 1;
      if (insertedWorkspace) return Promise.reject(new Error("body failed after binding"));
      if (/INSERT INTO workspaces/.test(sql)) insertedWorkspace = true;
      return tx.query(sql, params);
    };
    return run(watched);
  })) as never;
  const provisioned = { created: [] as string[], removed: [] as string[] };
  const provisioner: RelaycastProvisioner = {
    async create() {
      const id = `rw_${provisioned.created.length + 1}`;
      provisioned.created.push(id);
      return { id, apiKey: `rk_${id}` };
    },
    async remove(id) {
      provisioned.removed.push(id);
    },
  };
  const store = new IdentityStore(failing, KEYRING, {
    inviteTtlMs: ctx.identityConfig.inviteTtlMs,
    autoJoinDomains: [],
    tenancy: ctx.identityConfig.tenancy,
    provisioner,
    issueSession: (tx, session) => ctx.store.issueBrowserSession(tx, session),
  });
  const bound = async (id: string) =>
    (await ctx.database.query("SELECT 1 FROM workspaces WHERE relaycast_workspace_id = $1", [id])).rows.length;

  // Self-serve organization.
  await assert.rejects(
    store.createOrganizationForUser({ userId: me.user.id, email: "maker@elsewhere.test", name: "Broken" }),
    /body failed after binding/,
  );
  assert.deepEqual(provisioned.removed, ["rw_1"]);
  assert.equal(await bound("rw_1"), 0);
  // Personal organization on first sign-in.
  await assert.rejects(
    store.signIn({ email: "newcomer@elsewhere.test", name: "Newcomer", inviteTokenHash: null, method: "email" }),
    /body failed after binding/,
  );
  assert.deepEqual(provisioned.created, ["rw_1", "rw_2"]);
  assert.deepEqual(provisioned.removed, ["rw_1", "rw_2"]);
  assert.equal(await bound("rw_2"), 0);
  assert.equal(verifications, 0, "a pre-commit rollback releases without a verification read");
});

test("multi: a Relaycast workspace is retained when COMMIT landed but its acknowledgement was lost", async (t) => {
  const ctx = await setup(t, { multi: true });
  const person = await oidcSignIn(ctx, { email: "maker@elsewhere.test", name: "Maker" });
  assert(person.cookie);
  const me = (await whoami(ctx.origin, person.cookie)).body;

  // The underlying transaction commits; the client then reports failure (a
  // lost COMMIT acknowledgement, no SQLSTATE) whenever the body inserted a
  // workspace. The outcome is unknown: retained, and no read decides it.
  let reads = 0;
  const lossy: typeof ctx.database = Object.create(ctx.database);
  lossy.query = ((sql: string, params?: unknown[]) => {
    if (/workspaces/.test(sql)) reads += 1;
    return ctx.database.query(sql, params);
  }) as never;
  lossy.transaction = (async (run: Parameters<typeof ctx.database.transaction>[0]) => {
    let insertedWorkspace = false;
    const runWithWatchedQuery = (tx: Parameters<typeof run>[0]) => {
      const watched = Object.create(tx) as typeof tx;
      watched.query = (sql: string, params?: unknown[]) => {
        if (/INSERT INTO workspaces/.test(sql)) insertedWorkspace = true;
        return tx.query(sql, params);
      };
      return run(watched);
    };
    const result = await ctx.database.transaction(runWithWatchedQuery);
    if (insertedWorkspace) throw new Error("connection lost during COMMIT");
    return result;
  }) as never;
  const { provisioned, store } = lossyIdentityStore(ctx, lossy);
  const bound = async (id: string) =>
    (await ctx.database.query("SELECT 1 FROM workspaces WHERE relaycast_workspace_id = $1", [id])).rows.length;
  const retained = (id: string) => (error: any) => {
    assert.match(error.message, new RegExp(`\\(connection lost during COMMIT\\); Relaycast workspace ${id} was retained for operator reconciliation`));
    assert.equal(error.cause?.message, "connection lost during COMMIT");
    return true;
  };

  // Self-serve organization: committed, and the workspace is kept.
  await assert.rejects(
    store.createOrganizationForUser({ userId: me.user.id, email: "maker@elsewhere.test", name: "Committed" }),
    retained("rw_1"),
  );
  // Personal organization on first sign-in: likewise.
  await assert.rejects(
    store.signIn({ email: "newcomer@elsewhere.test", name: "Newcomer", inviteTokenHash: null, method: "email" }),
    retained("rw_2"),
  );
  assert.deepEqual(provisioned.created, ["rw_1", "rw_2"]);
  assert.deepEqual(provisioned.removed, [], "a committed binding is never released");
  assert.equal(reads, 0, "no verification read decides an unknown outcome");
  assert.equal(await bound("rw_1"), 1);
  assert.equal(await bound("rw_2"), 1);
});

test("multi: a Relaycast workspace is never released while its COMMIT is still pending (pending-committer regression)", async (t) => {
  const ctx = await setup(t, { multi: true });
  const person = await oidcSignIn(ctx, { email: "maker@elsewhere.test", name: "Maker" });
  assert(person.cookie);
  const me = (await whoami(ctx.origin, person.cookie)).body;

  // The client gives up (a dying connection) after the body ran but before
  // the real COMMIT resolves: the outer call rejects while the underlying
  // transaction is still open. Only afterwards does the held COMMIT land.
  // A fresh read in that window would see no binding; the store must not
  // read or release anything.
  let window = false;
  let readsInWindow = 0;
  const pending: { release: () => void; committed: Promise<unknown> }[] = [];
  let rejection: Error = new Error("unset");
  const lossy: typeof ctx.database = Object.create(ctx.database);
  lossy.query = ((sql: string, params?: unknown[]) => {
    if (window) readsInWindow += 1;
    return ctx.database.query(sql, params);
  }) as never;
  lossy.transaction = (async (run: Parameters<typeof ctx.database.transaction>[0]) => {
    let insertedWorkspace = false;
    let bodyDone!: () => void;
    const bodyCompleted = new Promise<void>((resolve) => { bodyDone = resolve; });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const real = ctx.database.transaction(async (tx) => {
      const watched = Object.create(tx) as typeof tx;
      watched.query = (sql: string, params?: unknown[]) => {
        if (/INSERT INTO workspaces/.test(sql)) insertedWorkspace = true;
        return tx.query(sql, params);
      };
      const result = await run(watched);
      if (insertedWorkspace) {
        bodyDone();
        await gate; // COMMIT in flight
      }
      return result;
    });
    const HELD = Symbol("held");
    const first = await Promise.race([real, bodyCompleted.then(() => HELD)]);
    if (first !== HELD) return first;
    pending.push({ release, committed: real });
    window = true;
    throw rejection;
  }) as never;
  const { provisioned, store } = lossyIdentityStore(ctx, lossy);
  const bound = async (id: string) =>
    (await ctx.database.query("SELECT 1 FROM workspaces WHERE relaycast_workspace_id = $1", [id])).rows.length;
  const landPendingCommit = async () => {
    window = false;
    const held = pending.shift();
    assert(held, "the transaction was held at COMMIT");
    held.release();
    await held.committed;
  };

  const cases = [
    { label: "08006 connection_failure", error: () => Object.assign(new Error("terminating connection during COMMIT"), { code: "08006" }) },
    { label: "no SQLSTATE", error: () => new Error("Connection terminated unexpectedly") },
  ];
  let n = 0;
  for (const { label, error } of cases) {
    // Self-serve organization.
    rejection = error();
    const orgId = `rw_${++n}`;
    await assert.rejects(
      store.createOrganizationForUser({ userId: me.user.id, email: "maker@elsewhere.test", name: `Pending ${n}` }),
      (thrown: any) => {
        assert.match(thrown.message, new RegExp(`Relaycast workspace ${orgId} was retained for operator reconciliation`), label);
        assert.equal(thrown.cause, rejection, label);
        return true;
      },
    );
    assert.deepEqual(provisioned.removed, [], label);
    await landPendingCommit();
    assert.equal(await bound(orgId), 1, `${label}: the binding is visible once the pending COMMIT lands`);

    // Personal organization on first sign-in.
    rejection = error();
    const personalId = `rw_${++n}`;
    await assert.rejects(
      store.signIn({ email: `newcomer-${n}@elsewhere.test`, name: "Newcomer", inviteTokenHash: null, method: "email" }),
      (thrown: any) => {
        assert.match(thrown.message, new RegExp(`Relaycast workspace ${personalId} was retained for operator reconciliation`), label);
        assert.equal(thrown.cause, rejection, label);
        return true;
      },
    );
    assert.deepEqual(provisioned.removed, [], label);
    await landPendingCommit();
    assert.equal(await bound(personalId), 1, `${label}: the binding is visible once the pending COMMIT lands`);
  }
  assert.deepEqual(provisioned.created, ["rw_1", "rw_2", "rw_3", "rw_4"]);
  assert.deepEqual(provisioned.removed, [], "a pending committer's workspace is never released");
  assert.equal(readsInWindow, 0, "nothing reads the database while COMMIT is pending");
});

function lossyIdentityStore(ctx: Awaited<ReturnType<typeof setup>>, database: Awaited<ReturnType<typeof setup>>["database"]) {
  const provisioned = { created: [] as string[], removed: [] as string[] };
  const provisioner: RelaycastProvisioner = {
    async create() {
      const id = `rw_${provisioned.created.length + 1}`;
      provisioned.created.push(id);
      return { id, apiKey: `rk_${id}` };
    },
    async remove(id) {
      provisioned.removed.push(id);
    },
  };
  const store = new IdentityStore(database, KEYRING, {
    inviteTtlMs: ctx.identityConfig.inviteTtlMs,
    autoJoinDomains: [],
    tenancy: ctx.identityConfig.tenancy,
    provisioner,
    issueSession: (tx, session) => ctx.store.issueBrowserSession(tx, session),
  });
  return { provisioned, store };
}

// ---- a real provider: Keycloak, shaped like Okta and like Entra ID ------------------
//
// Skipped unless OIDC_E2E_KEYCLOAK_URL is set:
//   docker run -d --name oidc-e2e -p 127.0.0.1:8180:8080 \
//     -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
//     quay.io/keycloak/keycloak:26.4 start-dev
//   OIDC_E2E_KEYCLOAK_URL=http://127.0.0.1:8180 node --import tsx --test \
//     --test-name-pattern='oidc e2e' test/identity.test.ts

const KEYCLOAK = process.env.OIDC_E2E_KEYCLOAK_URL?.replace(/\/+$/, "");
const E2E_PASSWORD = "e2e-password";
const E2E_SECRET = "e2e-client-secret";
const E2E_VERIFIER = "e2e-verifier-0123456789abcdefghijklmnopqrstuvwxyz0123456789abc";

async function keycloakAdminToken(): Promise<string> {
  const response = await fetch(`${KEYCLOAK}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    body: new URLSearchParams({ grant_type: "password", client_id: "admin-cli", username: "admin", password: process.env.OIDC_E2E_KEYCLOAK_ADMIN_PASSWORD ?? "admin" }),
  });
  assert.equal(response.status, 200, "Keycloak admin sign-in");
  return (await response.json() as { access_token: string }).access_token;
}

/** A throwaway realm. `entra` removes email_verified and adds a upn claim. */
async function keycloakRealm(t: test.TestContext, shape: "okta" | "entra", emails: string[]) {
  const realm = `${shape}-${randomUUID().slice(0, 8)}`;
  const token = await keycloakAdminToken();
  const admin = async (method: string, path: string, json?: unknown) => {
    const response = await fetch(`${KEYCLOAK}/admin/realms${path}`, {
      method,
      headers: { authorization: `Bearer ${token}`, ...(json === undefined ? {} : { "content-type": "application/json" }) },
      body: json === undefined ? undefined : JSON.stringify(json),
    });
    assert(response.ok, `${method} ${path}: ${response.status}`);
    return response.status === 200 ? response.json() as Promise<any> : null;
  };
  await admin("POST", "", { realm, enabled: true });
  t.after(() => admin("DELETE", `/${realm}`));
  await admin("POST", `/${realm}/clients`, {
    clientId: CLIENT_ID,
    secret: E2E_SECRET,
    publicClient: false,
    standardFlowEnabled: true,
    directAccessGrantsEnabled: true,
    redirectUris: ["*"],
    protocol: "openid-connect",
  });
  for (const email of emails) {
    await admin("POST", `/${realm}/users`, {
      username: email,
      email,
      emailVerified: true,
      firstName: "Test",
      lastName: "Person",
      enabled: true,
      credentials: [{ type: "password", value: E2E_PASSWORD, temporary: false }],
    });
  }
  if (shape === "entra") {
    const scopes = await admin("GET", `/${realm}/client-scopes`) as { id: string; name: string }[];
    const scope = scopes.find((item) => item.name === "email")!;
    const mappers = await admin("GET", `/${realm}/client-scopes/${scope.id}/protocol-mappers/models`) as { id: string; name: string }[];
    const verified = mappers.find((item) => item.name === "email verified")!;
    await admin("DELETE", `/${realm}/client-scopes/${scope.id}/protocol-mappers/models/${verified.id}`);
    await admin("POST", `/${realm}/client-scopes/${scope.id}/protocol-mappers/models`, {
      name: "upn",
      protocol: "openid-connect",
      protocolMapper: "oidc-usermodel-property-mapper",
      config: { "user.attribute": "email", "claim.name": "upn", "jsonType.label": "String", "id.token.claim": "true" },
    });
  }
  const issuer = `${KEYCLOAK}/realms/${realm}`;
  // The claims Keycloak really issues, read straight from its token endpoint.
  const direct = await fetch(`${issuer}/protocol/openid-connect/token`, {
    method: "POST",
    body: new URLSearchParams({ grant_type: "password", client_id: CLIENT_ID, client_secret: E2E_SECRET, username: emails[0]!, password: E2E_PASSWORD, scope: "openid email profile" }),
  });
  assert.equal(direct.status, 200, "direct grant");
  const idToken = (await direct.json() as { id_token: string }).id_token;
  const claims = JSON.parse(Buffer.from(idToken.split(".")[1]!, "base64url").toString()) as Record<string, unknown>;
  assert.equal(claims.email, emails[0]);
  if (shape === "entra") {
    assert.equal("email_verified" in claims, false, "the Entra-shaped realm omits email_verified");
    assert.equal(claims.upn, emails[0]);
    assert.equal(claims.preferred_username, emails[0]);
  } else {
    assert.equal(claims.email_verified, true);
  }
  return {
    issuer,
    env: {
      SELFHOST_OIDC_ISSUER: issuer,
      SELFHOST_OIDC_CLIENT_ID: CLIENT_ID,
      SELFHOST_OIDC_CLIENT_SECRET: E2E_SECRET,
      SELFHOST_OIDC_ALLOW_HTTP_ISSUER: "true",
    },
  };
}

/** A browser's cookies, one jar across Control and the provider. Secure is ignored over loopback http. */
class Browser {
  #cookies = new Map<string, { value: string; origin: string; path: string }>();

  header(url: URL): string {
    return [...this.#cookies.entries()]
      .filter(([, cookie]) => cookie.origin === url.origin && url.pathname.startsWith(cookie.path))
      .map(([name, cookie]) => `${name}=${cookie.value}`)
      .join("; ");
  }

  async fetch(target: string, init: { method?: string; form?: Record<string, string> } = {}) {
    const url = new URL(target);
    const cookie = this.header(url);
    const response = await fetch(url, {
      method: init.method ?? "GET",
      redirect: "manual",
      headers: {
        ...(cookie ? { cookie } : {}),
        ...(init.form ? { "content-type": "application/x-www-form-urlencoded" } : {}),
      },
      body: init.form ? new URLSearchParams(init.form).toString() : undefined,
    });
    for (const line of response.headers.getSetCookie()) {
      const [pair, ...attributes] = line.split(";");
      const index = pair!.indexOf("=");
      const name = pair!.slice(0, index);
      const path = attributes.map((part) => /^\s*path=(.*)$/i.exec(part)?.[1]).find(Boolean) ?? "/";
      if (/max-age=0(;|$)/i.test(line) || pair!.slice(index + 1) === "") this.#cookies.delete(name);
      else this.#cookies.set(name, { value: pair!.slice(index + 1), origin: url.origin, path });
    }
    return { url, response, text: await response.text() };
  }

  /** Follows redirects until `stop` matches or a page renders. */
  async follow(target: string, stop: (url: URL) => boolean = () => false) {
    let current = await this.fetch(target);
    for (let hop = 0; hop < 12 && current.response.status >= 300 && current.response.status < 400; hop += 1) {
      const next = new URL(current.response.headers.get("location")!, current.url);
      if (stop(next)) return { stopped: next, current };
      current = await this.fetch(next.toString());
    }
    return { stopped: null, current };
  }
}

/** Signs in at the real provider's own login form, from Control's /login page. */
async function keycloakSignIn(browser: Browser, origin: string, email: string, next: string, stop?: (url: URL) => boolean) {
  const login = await browser.fetch(`${origin}/login?next=${encodeURIComponent(next)}`);
  assert.equal(login.response.status, 200);
  assert.match(login.text, /Continue with Acme SSO/);
  const href = /href="(\/login\/oidc\/start[^"]*)"/.exec(login.text)?.[1]?.replaceAll("&amp;", "&");
  assert(href, "the /login page links to the provider");
  const form = await browser.follow(`${origin}${href}`);
  assert.equal(form.current.response.status, 200, form.current.text.slice(0, 300));
  const action = /action="([^"]+)"/.exec(form.current.text)?.[1]?.replaceAll("&amp;", "&");
  assert(action, "the provider's login form");
  let current = await browser.fetch(action, { method: "POST", form: { username: email, password: E2E_PASSWORD, credentialId: "" } });
  for (let hop = 0; hop < 12 && current.response.status >= 300 && current.response.status < 400; hop += 1) {
    const location = new URL(current.response.headers.get("location")!, current.url);
    if (stop?.(location)) return { stopped: location, current };
    current = await browser.fetch(location.toString());
  }
  return { stopped: null, current };
}

async function e2eWhoami(browser: Browser, origin: string) {
  const url = new URL("/cloud/api/v1/auth/whoami", origin);
  const response = await fetch(url, { headers: { cookie: browser.header(url) } });
  assert.equal(response.status, 200);
  return await response.json() as any;
}

for (const shape of ["okta", "entra"] as const) {
  test(`oidc e2e (${shape}-shaped Keycloak), single mode: owner, auto-join, invite, repeat and desktop login`, { skip: !KEYCLOAK }, async (t) => {
    const realm = await keycloakRealm(t, shape, ["admin@acme.test", "person@acme.test", "invited@acme.test", "desktop@acme.test"]);
    const ctx = await setup(t, { env: { ...realm.env, SELFHOST_AUTO_JOIN_DOMAINS: "acme.test", SELFHOST_OIDC_ALLOWED_DOMAINS: "acme.test" } });

    const owner = new Browser();
    await keycloakSignIn(owner, ctx.origin, "admin@acme.test", "/");
    const ownerInfo = await e2eWhoami(owner, ctx.origin);
    assert.equal(ownerInfo.currentOrganization.role, "owner");
    assert.equal(ownerInfo.user.name, "Test Person");

    const person = new Browser();
    await keycloakSignIn(person, ctx.origin, "person@acme.test", "/");
    assert.equal((await e2eWhoami(person, ctx.origin)).currentOrganization.role, "member");
    const repeat = new Browser();
    await keycloakSignIn(repeat, ctx.origin, "person@acme.test", "/");
    assert.equal((await e2eWhoami(repeat, ctx.origin)).user.email, "person@acme.test");

    await inviteFor(ctx, "invited@acme.test");
    const invited = new Browser();
    await keycloakSignIn(invited, ctx.origin, "invited@acme.test", "/");
    assert.equal((await e2eWhoami(invited, ctx.origin)).currentOrganization.role, "admin");

    // The Desktop app's browser login, as desktop-core browser_login.rs opens it.
    const challenge = createHash("sha256").update(E2E_VERIFIER).digest("base64url");
    const params = new URLSearchParams({
      redirect_uri: "http://127.0.0.1:5123/callback/STATE1",
      state: "STATE1",
      client: "desktop",
      workspace_selection: "desktop",
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const desktopPath = `/cloud/api/v1/cli/login?${params}`;
    const desktop = new Browser();
    const signedOut = await desktop.fetch(`${ctx.origin}${desktopPath}`);
    assert.equal(signedOut.response.status, 302);
    const toLogin = new URL(signedOut.response.headers.get("location")!, ctx.origin);
    assert.equal(toLogin.pathname, "/login");
    const handoff = await keycloakSignIn(desktop, ctx.origin, "desktop@acme.test", toLogin.searchParams.get("next")!, (url) => url.port === "5123");
    assert(handoff.stopped, "reached the desktop loopback listener");
    assert.equal(handoff.stopped.searchParams.get("state"), "STATE1");
    const accessToken = handoff.stopped.searchParams.get("access_token");
    assert.match(accessToken ?? "", /^sh_at_/);
    const exchanged = await call(ctx.origin, "/cloud/api/v1/auth/desktop/session", { method: "POST", token: accessToken!, json: { codeVerifier: E2E_VERIFIER } });
    assert.equal(exchanged.status, 200, exchanged.text);
    assert.equal((await call(ctx.origin, "/cloud/api/v1/auth/whoami", { token: exchanged.body.accessToken })).body.user.email, "desktop@acme.test");
  });
}

test("oidc e2e (entra-shaped Keycloak), multi mode: domain auto-join needs the named issuer", { skip: !KEYCLOAK }, async (t) => {
  for (const trusted of [false, true]) {
    await t.test(`issuer named: ${trusted}`, async (st) => {
      const realm = await keycloakRealm(st, "entra", ["person@acme.test"]);
      const ctx = await setup(st, {
        multi: true,
        env: { ...realm.env, ...(trusted ? { [ENTRA_TRUST_ISSUER]: realm.issuer } : {}) },
      });
      const organizationId = await orgId(ctx);
      assert.equal((await call(ctx.origin, `/api/v1/organizations/${organizationId}/domains/acme.test`, { method: "PUT", token: BOOTSTRAP })).status, 201);
      const browser = new Browser();
      await keycloakSignIn(browser, ctx.origin, "person@acme.test", "/");
      const info = await e2eWhoami(browser, ctx.origin);
      assert.equal(info.currentOrganization.id === organizationId, trusted);
      assert.equal(info.currentOrganization.role, trusted ? "member" : "owner");
    });
  }
});
