// analytics lane: the client gateway (POST /api/v1/analytics/events) on the
// PGlite app. The port is the real bounded queue behind a recording sink, so
// nothing leaves the process and the exported envelopes can be inspected.
import { PGlite } from "@electric-sql/pglite";
import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import test from "node:test";
import type { AnalyticsLimits } from "../src/analytics/config.js";
import { propertyValue, VERSION_MAX_LENGTH } from "../src/analytics/events.js";
import {
  CLIENT_BATCH_SCHEMA,
  GATEWAY_RATE_LIMITS,
  GatewayRequestError,
  parseClientBatch,
} from "../src/analytics/gateway.js";
import { createAnalytics, type AnalyticsQueue } from "../src/analytics/queue.js";
import { noneSink } from "../src/analytics/sinks/none.js";
import type { AnalyticsDestination, AnalyticsEnvelope, AnalyticsSink } from "../src/analytics/types.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const DASHBOARD = "https://dashboard.selfhosted.test/";
const DASHBOARD_ORIGIN = "https://dashboard.selfhosted.test";
const OWNER_EMAIL = "ada.lovelace@acme.test";
const OWNER_NAME = "Ada Lovelace";
const EVENTS = "/api/v1/analytics/events";
const CLOUD_EVENTS = "/cloud/api/v1/analytics/events";
const GATEWAY = { maxBodyBytes: 32_768, maxEvents: 20 };

const LIMITS: AnalyticsLimits = {
  maxEventBytes: 4096,
  maxBatchEvents: 50,
  maxBatchBytes: 262_144,
  queueMaxEvents: 1000,
  queueMaxBytes: 1_048_576,
  requestTimeoutMs: 5000,
  deliveryDeadlineMs: 60_000,
  maxAttempts: 4,
  // Nothing is sent in the background during a test; flush() sends on demand.
  flushIntervalMs: 60_000,
  shutdownDeadlineMs: 3000,
};

function recordingSink(): AnalyticsSink & { sent: AnalyticsEnvelope[] } {
  const sent: AnalyticsEnvelope[] = [];
  return {
    name: "collector",
    sent,
    async send(events) {
      sent.push(...events);
      return { outcome: "accepted" };
    },
  };
}

/**
 * The migrated schema, built once per file. Every test still gets its own
 * database, loaded from this image, instead of re-running the migrations.
 */
let migratedImage: Promise<File | Blob> | undefined;
function migratedDataDir(): Promise<File | Blob> {
  migratedImage ??= (async () => {
    const database = new PGliteDatabase();
    await migrate(database);
    const image = await database.client.dumpDataDir("none");
    await database.close();
    return image;
  })();
  return migratedImage;
}

async function setup(
  t: test.TestContext,
  options: {
    destination?: AnalyticsDestination | null;
    limits?: Partial<AnalyticsLimits>;
    rateLimits?: Partial<Record<keyof typeof GATEWAY_RATE_LIMITS, { limit: number; windowMs: number }>>;
  } = {},
) {
  const database = new PGliteDatabase(new PGlite({ loadDataDir: await migratedDataDir() }));
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayauthUrl: "http://relayauth.invalid",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.test",
    relayauthApiKey: "rak_test",
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: DASHBOARD,
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  const destination = options.destination === undefined ? "collector" : options.destination;
  const sink = recordingSink();
  const port: AnalyticsQueue = createAnalytics({
    limits: { ...LIMITS, ...options.limits },
    sink: destination === "none" ? noneSink : sink,
    deploymentId: destination === "none" ? null : "dep_gateway_0001",
  });
  const serverNow = Date.parse("2026-11-08T12:00:00.000Z");
  control.on("request", createApp({
    config,
    store,
    now: () => new Date(serverNow),
    ...(destination === null ? {} : {
      analytics: { port, config: { destination, gateway: GATEWAY }, rateLimits: options.rateLimits },
    }),
  }));
  t.after(async () => {
    await close(control);
    await database.close();
  });

  const org = await request(origin, "/api/v1/organizations", {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Acme", ownerEmail: OWNER_EMAIL, ownerName: OWNER_NAME },
  });
  assert.equal(org.status, 201);
  const workspace = await request(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Primary", relaycastApiKey: "rk_primary" },
  });
  assert.equal(workspace.status, 201);
  const organizationId = org.body.id as string;
  const workspaceId = workspace.body.id as string;
  const userId = org.body.owner.id as string;
  /** A fresh personal session (the scopes every session gets: cli:auth, rth:read, rth:sync). */
  const session = async () => store.issueBrowserSession(database, {
    userId,
    organizationId,
    workspaceId,
    label: "gateway test",
  });
  /** Envelopes exported so far (flushes the queue into the recording sink). */
  const exported = async () => {
    await port.flush(Date.now() + 2000);
    return sink.sent;
  };
  return { origin, database, store, port, sink, exported, session, organizationId, workspaceId, userId, serverNow };
}

type PostOptions = {
  token?: string;
  cookie?: string;
  origin?: string | null;
  secFetchSite?: string;
  contentType?: string;
  body?: unknown;
  raw?: string;
  forwardedFor?: string;
};

async function post(baseUrl: string, path: string, options: PostOptions) {
  const headers: Record<string, string> = { "content-type": options.contentType ?? "application/json" };
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  if (options.cookie) headers.cookie = `agent_relay_session=${encodeURIComponent(options.cookie)}`;
  if (options.origin) headers.origin = options.origin;
  if (options.secFetchSite) headers["sec-fetch-site"] = options.secFetchSite;
  if (options.forwardedFor) headers["x-forwarded-for"] = options.forwardedFor;
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers,
    body: options.raw ?? JSON.stringify(options.body),
  });
  const raw = await response.text();
  let body: Record<string, any> = {};
  try {
    body = raw ? JSON.parse(raw) as Record<string, any> : {};
  } catch {
    body = {};
  }
  return { status: response.status, headers: response.headers, body };
}

function batch(client: "dashboard" | "desktop", events: unknown[], extra: Record<string, unknown> = {}) {
  return { schema: CLIENT_BATCH_SCHEMA, client, events, ...extra };
}

const PAGE_VIEW = { event: "dashboard.page_viewed", properties: { page: "sessions" } };
const APP_STARTED = { event: "desktop.app_started", properties: { desktop_version: "1.4.2-beta.1", os: "macos" } };

/** Client text that is not a version: identity, secret-shaped, product text, malformed releases, too long. */
const BAD_VERSIONS = [
  "ops@example.com",
  "sk_live_abc123",
  "AgentRelay-Desktop-Beta",
  "1.4",
  "v1.4.2",
  "1.4.2 beta",
  `1.4.2-${"a".repeat(VERSION_MAX_LENGTH - 5)}`, // 33 characters, otherwise valid
];
const GOOD_VERSIONS = ["1.4.2", "1.4.2-beta.1", "1.4.2+build.7", "1.4.2-rc.1+sha.abc", `1.4.2-${"a".repeat(26)}`];

test("the version spec accepts only MAJOR.MINOR.PATCH with optional prerelease and build, at most 32 characters", () => {
  assert.equal(BAD_VERSIONS.at(-1)!.length, 33);
  assert.equal(GOOD_VERSIONS.at(-1)!.length, 32);
  for (const value of BAD_VERSIONS) {
    assert.equal(propertyValue({ type: "version" }, value), undefined, value);
  }
  for (const value of GOOD_VERSIONS) {
    assert.equal(propertyValue({ type: "version" }, value), value, value);
  }
  for (const value of [1.4, true, null, "", "1.4.2-", "1.4.2+", "1.4.2-beta..1", "123456.0.0", "+1.4.2", "1.4.2\n"]) {
    assert.equal(propertyValue({ type: "version" }, value), undefined, JSON.stringify(value));
  }
});

test("parseClientBatch refuses a desktop_version outside the version grammar as invalid_event naming the index", () => {
  const now = Date.parse("2026-11-08T12:00:00.000Z");
  for (const value of BAD_VERSIONS) {
    const raw = JSON.stringify(batch("desktop", [
      APP_STARTED,
      { event: "desktop.app_started", properties: { desktop_version: value, os: "linux" } },
    ]));
    assert.throws(
      () => parseClientBatch(raw, { client: "desktop", maxEvents: 20, now }),
      (error: unknown) => error instanceof GatewayRequestError &&
        error.status === 400 &&
        error.code === "invalid_event" &&
        error.counter === "invalid" &&
        /^events\[1\]: property "desktop_version" has an invalid value$/.test(error.message),
      value,
    );
  }
  for (const value of GOOD_VERSIONS) {
    const raw = JSON.stringify(batch("desktop", [{ event: "desktop.app_started", properties: { desktop_version: value } }]));
    const [event] = parseClientBatch(raw, { client: "desktop", maxEvents: 20, now });
    assert.equal(event!.properties.desktop_version, value);
  }
});

test("a valid dashboard batch is accepted with server-derived workspace attribution, one trace id and no user identity", async (t) => {
  const ctx = await setup(t);
  const { accessToken, sessionId } = await ctx.session();
  const clientEventId = "6f1c2a4e-8b3d-4e5f-9a1b-2c3d4e5f6a7b";
  const response = await post(ctx.origin, CLOUD_EVENTS, {
    cookie: accessToken,
    origin: DASHBOARD_ORIGIN,
    body: batch("dashboard", [
      { ...PAGE_VIEW, client_event_id: clientEventId },
      { event: "dashboard.session_opened", properties: { source: "search" } },
    ]),
  });
  assert.equal(response.status, 202);
  assert.deepEqual(response.body, { accepted: 2, queued: true });
  assert.equal(response.headers.get("cache-control"), "no-store");

  const envelopes = await ctx.exported();
  assert.equal(envelopes.length, 2);
  for (const envelope of envelopes) {
    assert.equal(envelope.component, "relaycontrol");
    assert.equal(envelope.deployment_id, "dep_gateway_0001");
    assert.equal(envelope.tenant_id, ctx.organizationId);
    assert.equal(envelope.workspace_id, ctx.workspaceId);
    assert.equal(envelope.properties.client, "dashboard");
  }
  assert.deepEqual(envelopes.map((envelope) => envelope.event), ["dashboard.page_viewed", "dashboard.session_opened"]);
  assert.deepEqual(envelopes[0]!.properties, { page: "sessions", client: "dashboard", client_event_id: clientEventId });
  assert.deepEqual(envelopes[1]!.properties, { source: "search", client: "dashboard" });
  // One fresh trace id per request, shared by its events, not the boot trace.
  assert.equal(envelopes[0]!.trace_id, envelopes[1]!.trace_id);
  assert.notEqual(envelopes[0]!.trace_id, ctx.port.bootTraceId);
  // The exported event_id is minted by the port, never the client's id.
  assert.notEqual(envelopes[0]!.event_id, clientEventId);
  const wire = JSON.stringify(envelopes);
  for (const identity of [ctx.userId, OWNER_EMAIL, OWNER_NAME, sessionId, accessToken, "127.0.0.1"]) {
    assert.equal(wire.includes(identity), false, `envelope leaks ${identity}`);
  }

  // A second request gets its own trace id.
  const again = await post(ctx.origin, CLOUD_EVENTS, {
    cookie: accessToken,
    secFetchSite: "same-origin",
    body: batch("dashboard", [PAGE_VIEW]),
  });
  assert.equal(again.status, 202);
  const all = await ctx.exported();
  assert.equal(all.length, 3);
  assert.notEqual(all[2]!.trace_id, all[0]!.trace_id);
});

test("a desktop tenant-scoped event carries tenant_id and no workspace_id, on both mounts", async (t) => {
  const ctx = await setup(t);
  const { accessToken } = await ctx.session();
  for (const path of [EVENTS, CLOUD_EVENTS]) {
    const response = await post(ctx.origin, path, {
      token: accessToken,
      body: batch("desktop", [APP_STARTED, { event: "desktop.sign_in_completed" }]),
    });
    assert.equal(response.status, 202, path);
    assert.deepEqual(response.body, { accepted: 2, queued: true });
  }
  const envelopes = await ctx.exported();
  assert.equal(envelopes.length, 4);
  for (const envelope of envelopes) {
    assert.equal(envelope.tenant_id, ctx.organizationId);
    assert.equal("workspace_id" in envelope, false);
    assert.equal(envelope.properties.client, "desktop");
  }
  assert.deepEqual(envelopes[0]!.properties, { desktop_version: "1.4.2-beta.1", os: "macos", client: "desktop" });
  assert.deepEqual(envelopes[1]!.properties, { client: "desktop" });
});

test("a cookie POST without an allowed Origin or same-origin fetch is 403 and captures nothing", async (t) => {
  const ctx = await setup(t);
  const { accessToken } = await ctx.session();
  const body = batch("dashboard", [PAGE_VIEW]);
  for (const options of [
    { origin: null },
    { origin: "https://evil.example" },
    { origin: "null" },
    { origin: DASHBOARD_ORIGIN, contentType: "text/plain" },
    { secFetchSite: "cross-site" },
  ]) {
    const response = await post(ctx.origin, CLOUD_EVENTS, { cookie: accessToken, body, ...options });
    assert.equal(response.status, 403, JSON.stringify(options));
    assert.equal(response.body.error, "forbidden");
  }
  // The session cookie is never read outside /cloud/.
  const plain = await post(ctx.origin, EVENTS, { cookie: accessToken, origin: DASHBOARD_ORIGIN, body });
  assert.equal(plain.status, 401);
  assert.equal(plain.body.error, "unauthorized");

  const stats = ctx.port.stats();
  assert.equal(stats.captured, 0);
  assert.equal(stats.gateway.rejected.csrf, 5);
  assert.equal(stats.gateway.rejected.auth, 1);
  assert.equal((await ctx.exported()).length, 0);
});

test("the declared client must match the credential kind", async (t) => {
  const ctx = await setup(t);
  const { accessToken } = await ctx.session();
  const bearer = await post(ctx.origin, EVENTS, { token: accessToken, body: batch("dashboard", [PAGE_VIEW]) });
  assert.equal(bearer.status, 400);
  assert.equal(bearer.body.error, "client_mismatch");
  const cookie = await post(ctx.origin, CLOUD_EVENTS, {
    cookie: accessToken,
    origin: DASHBOARD_ORIGIN,
    body: batch("desktop", [APP_STARTED]),
  });
  assert.equal(cookie.status, 400);
  assert.equal(cookie.body.error, "client_mismatch");
  assert.equal(ctx.port.stats().captured, 0);
  assert.equal(ctx.port.stats().gateway.rejected.client_mismatch, 2);
});

test("bootstrap, unknown and missing credentials are 401; a session without cli:auth is 403", async (t) => {
  const ctx = await setup(t);
  const body = batch("desktop", [APP_STARTED]);
  for (const token of [BOOTSTRAP, "sh_at_not_a_real_token", undefined]) {
    const response = await post(ctx.origin, EVENTS, { token, body });
    assert.equal(response.status, 401, String(token));
    assert.equal(response.body.error, "unauthorized");
  }
  const { accessToken, sessionId } = await ctx.session();
  await ctx.database.query("UPDATE selfhost_token_sessions SET scopes = $1 WHERE id = $2", [["rth:read"], sessionId]);
  const scoped = await post(ctx.origin, EVENTS, { token: accessToken, body });
  assert.equal(scoped.status, 403);
  assert.equal(scoped.body.error, "forbidden");
  assert.equal(ctx.port.stats().captured, 0);
  assert.equal(ctx.port.stats().gateway.rejected.auth, 4);
});

test("reserved fields anywhere in the body are 400 reserved_field and nothing is captured", async (t) => {
  const ctx = await setup(t);
  const { accessToken } = await ctx.session();
  const bodies = [
    batch("desktop", [APP_STARTED], { tenant_id: "org_other" }),
    batch("desktop", [APP_STARTED], { deployment_id: "dep_other_0001" }),
    batch("desktop", [APP_STARTED, { ...APP_STARTED, workspace_id: "ws_other" }]),
    batch("desktop", [APP_STARTED, { ...APP_STARTED, trace_id: "trace_forged_01" }]),
    batch("desktop", [{ ...APP_STARTED, properties: { ...APP_STARTED.properties, tenant_id: "org_other" } }]),
    batch("desktop", [{ ...APP_STARTED, properties: { ...APP_STARTED.properties, deployment_id: "dep_other_0001" } }]),
    batch("desktop", [{ ...APP_STARTED, properties: { nested: { component: "x" } } }]),
    batch("desktop", [{ event: "desktop.sign_in_completed", event_id: "e", version: 1 }]),
  ];
  for (const body of bodies) {
    const response = await post(ctx.origin, EVENTS, { token: accessToken, body });
    assert.equal(response.status, 400, JSON.stringify(body));
    assert.equal(response.body.error, "reserved_field");
  }
  assert.equal(ctx.port.stats().captured, 0);
  assert.equal(ctx.port.stats().gateway.rejected.reserved_field, bodies.length);
});

test("more than MAX_EVENTS events is 400 too_many_events; exactly MAX_EVENTS is accepted", async (t) => {
  const ctx = await setup(t);
  const { accessToken } = await ctx.session();
  const tooMany = await post(ctx.origin, EVENTS, {
    token: accessToken,
    body: batch("desktop", Array.from({ length: 21 }, () => APP_STARTED)),
  });
  assert.equal(tooMany.status, 400);
  assert.equal(tooMany.body.error, "too_many_events");
  assert.equal(ctx.port.stats().captured, 0);
  const max = await post(ctx.origin, EVENTS, {
    token: accessToken,
    body: batch("desktop", Array.from({ length: 20 }, () => APP_STARTED)),
  });
  assert.equal(max.status, 202);
  assert.deepEqual(max.body, { accepted: 20, queued: true });
});

test("malformed bodies are 400 invalid_request and count as body rejections", async (t) => {
  const ctx = await setup(t);
  const { accessToken } = await ctx.session();
  const cases: Array<{ raw?: string; body?: unknown }> = [
    { raw: "{not json" },
    { raw: "[]" },
    { raw: "" },
    { body: { client: "desktop", events: [APP_STARTED] } },
    { body: batch("desktop", [APP_STARTED], { schema: "agent-relay.analytics.batch/v1" }) },
    { body: batch("browser" as never, [APP_STARTED]) },
    { body: batch("desktop", []) },
    { body: { schema: CLIENT_BATCH_SCHEMA, client: "desktop" } },
    { body: batch("desktop", [APP_STARTED], { extra: true }) },
  ];
  for (const options of cases) {
    const response = await post(ctx.origin, EVENTS, { token: accessToken, ...options });
    assert.equal(response.status, 400, JSON.stringify(options));
    assert.equal(response.body.error, "invalid_request", JSON.stringify(options));
  }
  assert.equal(ctx.port.stats().captured, 0);
  assert.equal(ctx.port.stats().gateway.rejected.body, cases.length);
});

test("a body over MAX_BODY_BYTES is refused with 413 on the streamed bytes, before the upload ends", async (t) => {
  const ctx = await setup(t);
  const { accessToken } = await ctx.session();
  const url = new URL(EVENTS, ctx.origin);
  // Chunked upload, no Content-Length: the limit can only be enforced on the
  // bytes read. The request is never ended, so a 413 proves the server stopped
  // reading at the limit instead of buffering the whole body first.
  const result = await new Promise<{ status: number; body: string; written: number }>((resolve, reject) => {
    let written = 0;
    let timer: NodeJS.Timeout | undefined;
    const outgoing = httpRequest(url, {
      method: "POST",
      headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json" },
    }, (response) => {
      clearInterval(timer);
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => body += chunk);
      response.on("end", () => {
        resolve({ status: response.statusCode ?? 0, body, written });
        outgoing.destroy();
      });
    });
    outgoing.on("error", (error) => {
      clearInterval(timer);
      reject(error);
    });
    assert.equal(outgoing.getHeader("content-length"), undefined);
    const chunk = Buffer.alloc(1024, "a");
    outgoing.write(`{"schema":"${CLIENT_BATCH_SCHEMA}","client":"desktop","pad":"`);
    timer = setInterval(() => {
      // Keeps streaming well past 33 KiB until the server answers; give up at 1 MiB.
      if (written > 1024 * 1024) {
        clearInterval(timer);
        reject(new Error("no early 413"));
        outgoing.destroy();
        return;
      }
      outgoing.write(chunk);
      written += chunk.length;
    }, 1);
  });
  assert.equal(result.status, 413);
  assert.equal(JSON.parse(result.body).error, "payload_too_large");
  assert.ok(result.written >= 32 * 1024, `answered after ${result.written} bytes`);
  assert.ok(result.written < 1024 * 1024);
  assert.equal(ctx.port.stats().captured, 0);
  assert.equal(ctx.port.stats().gateway.rejected.body, 1);

  // A 33 KiB body sent in one go is refused the same way.
  const big = await post(ctx.origin, EVENTS, {
    token: accessToken,
    raw: JSON.stringify(batch("desktop", [{ ...APP_STARTED, padding: "x".repeat(33 * 1024) }])),
  });
  assert.equal(big.status, 413);
  assert.equal(big.body.error, "payload_too_large");
});

test("a membership revoked after the token check is 404 workspace_not_found and captures nothing", async (t) => {
  const ctx = await setup(t);
  const { accessToken } = await ctx.session();
  // The token resolves, then the membership disappears before the gateway's
  // own re-check (a revocation racing the request).
  const authenticate = ctx.store.authenticateAccessToken.bind(ctx.store);
  ctx.store.authenticateAccessToken = async (token) => {
    const principal = await authenticate(token);
    if (principal) {
      await ctx.database.query(
        "DELETE FROM selfhost_organization_memberships WHERE organization_id = $1 AND user_id = $2",
        [principal.organizationId, principal.userId],
      );
    }
    return principal;
  };
  const response = await post(ctx.origin, EVENTS, { token: accessToken, body: batch("desktop", [APP_STARTED]) });
  assert.equal(response.status, 404);
  assert.equal(response.body.error, "workspace_not_found");
  ctx.store.authenticateAccessToken = authenticate;
  // Once revoked, the token itself no longer resolves.
  const after = await post(ctx.origin, EVENTS, { token: accessToken, body: batch("desktop", [APP_STARTED]) });
  assert.equal(after.status, 401);
  assert.equal(ctx.port.stats().captured, 0);
  assert.equal(ctx.port.stats().gateway.rejected.auth, 2);
});

test("events a client may not send are 400 invalid_event naming the index, and nothing is captured", async (t) => {
  const ctx = await setup(t);
  const { accessToken } = await ctx.session();
  const cases: Array<[unknown, RegExp]> = [
    // Installation (server-only) kinds are never client kinds.
    [{ event: "service_started", properties: { component_version: "1.0.0" } }, /not registered for the desktop client/],
    [{ event: "config_loaded" }, /not registered for the desktop client/],
    // Another client's kind.
    [PAGE_VIEW, /not registered for the desktop client/],
    [{ event: "desktop.unknown" }, /is not registered/],
    [{ event: "toString" }, /is not registered/],
    [{ ...APP_STARTED, properties: { os: "beos" } }, /invalid value/],
    [{ ...APP_STARTED, properties: { desktop_version: "x".repeat(33) } }, /invalid value/],
    [{ ...APP_STARTED, properties: { desktop_version: "https://evil" } }, /invalid value/],
    [{ ...APP_STARTED, properties: { user_email: "a@b.c" } }, /not registered/],
    [{ ...APP_STARTED, properties: { client: "desktop" } }, /set by the server/],
    [{ ...APP_STARTED, properties: { client_event_id: "6f1c2a4e-8b3d-4e5f-9a1b-2c3d4e5f6a7b" } }, /set by the server/],
    [{ ...APP_STARTED, properties: { os: ["macos"] } }, /invalid value/],
    [{ ...APP_STARTED, properties: [] }, /properties must be an object/],
    [{ ...APP_STARTED, client_event_id: "not-a-uuid" }, /client_event_id must be a UUID/],
    [{ ...APP_STARTED, occurred_at: 1_700_000_000_000 }, /occurred_at must be an ISO-8601 string/],
    [{ ...APP_STARTED, user_id: "u_1" }, /unknown field/],
    ["desktop.app_started", /must be an object/],
  ];
  for (const [event, message] of cases) {
    const response = await post(ctx.origin, EVENTS, {
      token: accessToken,
      body: batch("desktop", [APP_STARTED, event]),
    });
    assert.equal(response.status, 400, JSON.stringify(event));
    assert.equal(response.body.error, "invalid_event", JSON.stringify(event));
    assert.match(response.body.message, /^events\[1\]: /);
    assert.match(response.body.message, message);
  }
  // The valid first event of each batch was never captured either.
  assert.equal(ctx.port.stats().captured, 0);
  assert.equal(ctx.port.stats().gateway.rejected.invalid, cases.length);
});

test("the per-session limit answers 429 rate_limited with Retry-After", async (t) => {
  const ctx = await setup(t);
  const { accessToken } = await ctx.session();
  const body = batch("desktop", [{ event: "desktop.sign_in_completed" }]);
  for (let index = 0; index < 60; index += 1) {
    const ok = await post(ctx.origin, EVENTS, { token: accessToken, body });
    assert.equal(ok.status, 202, `request ${index}`);
  }
  const limited = await post(ctx.origin, EVENTS, { token: accessToken, body });
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error, "rate_limited");
  assert.equal(limited.headers.get("retry-after"), "60");
  // Another session from another address is not limited by this one.
  const other = await ctx.session();
  const fresh = await post(ctx.origin, EVENTS, { token: other.accessToken, body, forwardedFor: "203.0.113.9" });
  assert.equal(fresh.status, 202);
  const stats = ctx.port.stats();
  assert.equal(stats.captured, 61);
  assert.equal(stats.gateway.rejected.rate_limited, 1);
});

test("a desktop_version outside the version grammar is 400 invalid_event and nothing is captured or exported", async (t) => {
  const ctx = await setup(t);
  const { accessToken } = await ctx.session();
  for (const value of BAD_VERSIONS) {
    const response = await post(ctx.origin, EVENTS, {
      token: accessToken,
      body: batch("desktop", [APP_STARTED, { ...APP_STARTED, properties: { desktop_version: value, os: "macos" } }]),
    });
    assert.equal(response.status, 400, value);
    assert.equal(response.body.error, "invalid_event", value);
    assert.match(response.body.message, /^events\[1\]: property "desktop_version" has an invalid value$/, value);
  }
  assert.equal(ctx.port.stats().captured, 0);
  assert.equal(ctx.port.stats().gateway.rejected.invalid, BAD_VERSIONS.length);
  assert.deepEqual(await ctx.exported(), []);
  assert.deepEqual(ctx.sink.sent, []);
});

/** Sets SELFHOST_TRUSTED_PROXIES (read per request by clientIp) and restores it after the test. */
function trustProxies(t: test.TestContext, hops: string) {
  const previous = process.env.SELFHOST_TRUSTED_PROXIES;
  process.env.SELFHOST_TRUSTED_PROXIES = hops;
  t.after(() => {
    if (previous === undefined) delete process.env.SELFHOST_TRUSTED_PROXIES;
    else process.env.SELFHOST_TRUSTED_PROXIES = previous;
  });
}

test("sessions sharing one client IP exhaust the per-IP bucket while each session is under its own limit", async (t) => {
  // Production limits are unchanged; the test bucket is small so it stays fast.
  assert.deepEqual(GATEWAY_RATE_LIMITS, {
    session: { limit: 60, windowMs: 60_000 },
    ip: { limit: 300, windowMs: 60_000 },
  });
  // One trusted proxy, so the forwarded address below is the client IP.
  trustProxies(t, "1");
  const ctx = await setup(t, { rateLimits: { ip: { limit: 6, windowMs: 60_000 } } });
  const sessions = [await ctx.session(), await ctx.session(), await ctx.session()];
  assert.equal(new Set(sessions.map((session) => session.sessionId)).size, 3);
  const body = batch("desktop", [{ event: "desktop.sign_in_completed" }]);
  const forwardedFor = "198.51.100.7";
  // Two requests per session: six in the IP bucket, two in each session bucket.
  for (const { accessToken } of sessions) {
    for (let index = 0; index < 2; index += 1) {
      const ok = await post(ctx.origin, EVENTS, { token: accessToken, body, forwardedFor });
      assert.equal(ok.status, 202);
    }
  }
  assert.equal(ctx.port.stats().captured, 6);
  const limited = await post(ctx.origin, EVENTS, { token: sessions[0]!.accessToken, body, forwardedFor });
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error, "rate_limited");
  assert.equal(limited.headers.get("retry-after"), "60");
  assert.equal(ctx.port.stats().captured, 6);
  assert.equal(ctx.port.stats().gateway.rejected.rate_limited, 1);
  // The same session from another address is still accepted, so the 429 came
  // from the IP key, not the session (3 of 60 used).
  const elsewhere = await post(ctx.origin, EVENTS, { token: sessions[0]!.accessToken, body, forwardedFor: "198.51.100.8" });
  assert.equal(elsewhere.status, 202);
  assert.equal(ctx.port.stats().captured, 7);
});

test("the per-IP key is the socket address unless SELFHOST_TRUSTED_PROXIES trusts the rightmost hops", async (t) => {
  const body = batch("desktop", [{ event: "desktop.sign_in_completed" }]);

  // 0 trusted proxies (the default): X-Forwarded-For is ignored, so requests
  // with different forwarded values share the socket address bucket.
  trustProxies(t, "0");
  const direct = await setup(t, { rateLimits: { ip: { limit: 2, windowMs: 60_000 } } });
  const directToken = (await direct.session()).accessToken;
  const sendDirect = (forwardedFor?: string) => post(direct.origin, EVENTS, { token: directToken, body, forwardedFor });
  assert.equal((await sendDirect("203.0.113.1")).status, 202);
  assert.equal((await sendDirect("203.0.113.2")).status, 202);
  assert.equal((await sendDirect("198.51.100.1")).status, 429);
  assert.equal((await sendDirect()).status, 429);
  assert.equal(direct.port.stats().captured, 2);
  assert.equal(direct.port.stats().gateway.rejected.rate_limited, 2);

  // 1 trusted proxy: the rightmost entry (the one the proxy appended) is the
  // key; entries to its left are client-supplied and ignored. clientIp reads
  // the variable per request; trustProxies above restores it after the test.
  process.env.SELFHOST_TRUSTED_PROXIES = "1";
  const proxied = await setup(t, { rateLimits: { ip: { limit: 2, windowMs: 60_000 } } });
  const proxiedToken = (await proxied.session()).accessToken;
  const send = (forwardedFor?: string) => post(proxied.origin, EVENTS, { token: proxiedToken, body, forwardedFor });
  assert.equal((await send("203.0.113.1")).status, 202);
  assert.equal((await send("10.0.0.1, 203.0.113.1")).status, 202);
  // Same rightmost address after normalisation (port stripped): same bucket.
  assert.equal((await send("198.51.100.1, 203.0.113.1:443")).status, 429);
  // Another rightmost address: a fresh bucket, whatever the left entries say.
  assert.equal((await send("203.0.113.1, 10.0.0.1")).status, 202);
  // No header, or a rightmost entry that is not an IP: the socket address.
  assert.equal((await send()).status, 202);
  assert.equal((await send("not-an-ip")).status, 202);
  assert.equal((await send()).status, 429);
  assert.equal(proxied.port.stats().captured, 5);
  assert.equal(proxied.port.stats().gateway.rejected.rate_limited, 2);
});

test("with destination none (or no analytics port) the route is absent and other routes are unchanged", async (t) => {
  for (const destination of ["none", null] as const) {
    const ctx = await setup(t, { destination });
    const { accessToken } = await ctx.session();
    for (const path of [EVENTS, CLOUD_EVENTS]) {
      const response = await post(ctx.origin, path, { token: accessToken, body: batch("desktop", [APP_STARTED]) });
      assert.equal(response.status, 404, `${destination} ${path}`);
      assert.equal(response.body.error, "not_found");
    }
    assert.equal((await request(ctx.origin, "/healthz")).status, 200);
    const whoami = await request(ctx.origin, "/api/v1/auth/whoami", { token: accessToken });
    assert.equal(whoami.status, 200);
    assert.equal(ctx.port.stats().captured, 0);
    assert.equal(ctx.port.stats().gateway.requests, 0);
  }
});

test("a full port queue still answers 202 with queued false, and health is unaffected", async (t) => {
  const ctx = await setup(t, { limits: { queueMaxEvents: 1 } });
  const { accessToken } = await ctx.session();
  const response = await post(ctx.origin, EVENTS, {
    token: accessToken,
    body: batch("desktop", [APP_STARTED, { event: "desktop.sign_in_completed" }]),
  });
  assert.equal(response.status, 202);
  assert.deepEqual(response.body, { accepted: 2, queued: false });
  assert.equal((await request(ctx.origin, "/healthz")).status, 200);
  const stats = ctx.port.stats();
  assert.equal(stats.dropped.queueFull, 1);
  assert.equal(stats.queueEvents, 1);
  assert.equal(stats.gateway.accepted, 2);
});

test("occurred_at is kept inside the ±5 minute window and otherwise replaced by server time and counted", async (t) => {
  const ctx = await setup(t);
  const { accessToken } = await ctx.session();
  const server = new Date(ctx.serverNow).toISOString();
  const inWindow = new Date(ctx.serverNow - 4 * 60_000).toISOString();
  const offset = "2026-11-08T13:04:00+01:00"; // 4 minutes after server time
  const response = await post(ctx.origin, EVENTS, {
    token: accessToken,
    body: batch("desktop", [
      { ...APP_STARTED, occurred_at: inWindow },
      { ...APP_STARTED, occurred_at: offset },
      { ...APP_STARTED, occurred_at: new Date(ctx.serverNow - 10 * 60_000).toISOString() },
      { ...APP_STARTED, occurred_at: new Date(ctx.serverNow + 6 * 60_000).toISOString() },
      { ...APP_STARTED, occurred_at: "yesterday" },
      { ...APP_STARTED, occurred_at: "2026-11-08" },
      APP_STARTED,
    ]),
  });
  assert.equal(response.status, 202);
  const envelopes = await ctx.exported();
  assert.deepEqual(envelopes.map((envelope) => envelope.occurred_at), [
    inWindow,
    "2026-11-08T12:04:00.000Z",
    server,
    server,
    server,
    server,
    server,
  ]);
  // An omitted occurred_at is not an adjustment.
  assert.equal(ctx.port.stats().gateway.clock_adjusted, 4);
});

test("gateway counters are visible through the port's stats", async (t) => {
  const ctx = await setup(t);
  const { accessToken } = await ctx.session();
  await post(ctx.origin, EVENTS, { token: accessToken, body: batch("desktop", [APP_STARTED, APP_STARTED]) });
  await post(ctx.origin, EVENTS, { token: BOOTSTRAP, body: batch("desktop", [APP_STARTED]) });
  await post(ctx.origin, CLOUD_EVENTS, { cookie: accessToken, body: batch("dashboard", [PAGE_VIEW]) });
  await post(ctx.origin, EVENTS, { token: accessToken, body: batch("dashboard", [PAGE_VIEW]) });
  await post(ctx.origin, EVENTS, { token: accessToken, raw: "{" });
  await post(ctx.origin, EVENTS, { token: accessToken, body: batch("desktop", [{ event: "service_started" }]) });
  await post(ctx.origin, EVENTS, { token: accessToken, body: batch("desktop", [APP_STARTED], { tenant_id: "x" }) });
  await post(ctx.origin, EVENTS, {
    token: accessToken,
    body: batch("desktop", [{ ...APP_STARTED, occurred_at: "2020-01-01T00:00:00Z" }]),
  });
  assert.deepEqual(ctx.port.stats().gateway, {
    requests: 8,
    accepted: 3,
    rejected: { auth: 1, csrf: 1, client_mismatch: 1, body: 1, invalid: 1, reserved_field: 1, rate_limited: 0 },
    clock_adjusted: 1,
  });
  assert.equal(ctx.port.stats().captured, 3);
});
