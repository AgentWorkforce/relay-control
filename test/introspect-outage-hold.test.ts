import assert from "node:assert/strict";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import { IntrospectionHold } from "../src/auth/introspection-hold.js";
import type { SelfhostConfig } from "../src/config.js";
import { hashSecret } from "../src/crypto.js";
import { isDatabaseUnavailable, type Database, type SqlExecutor, type SqlResult } from "../src/database.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore, type IntrospectedToken } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * Database outage hold for POST /internal/v1/auth/introspect
 * (SELFHOST_INTROSPECT_OUTAGE_HOLD_MS, docs/identity.md).
 */

const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const INTERNAL = "internal-service-token-at-least-32-bytes!";
const HISTORY_PUBLIC = "https://history.selfhosted.test";
const NODE = "node_0123456789abcdef";

function refused(): Error {
  return Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
}

/** PGlite that refuses every statement while `outage` is set. */
class FailingDatabase implements Database {
  outage = false;
  constructor(readonly inner: PGliteDatabase) {}

  async query<T extends Record<string, unknown>>(sql: string, params?: unknown[]): Promise<SqlResult<T>> {
    if (this.outage) throw refused();
    return this.inner.query<T>(sql, params);
  }

  async exec(sql: string): Promise<void> {
    if (this.outage) throw refused();
    return this.inner.exec(sql);
  }

  async transaction<T>(run: (transaction: SqlExecutor) => Promise<T>): Promise<T> {
    if (this.outage) throw refused();
    return this.inner.transaction(run);
  }

  close(): Promise<void> {
    return this.inner.close();
  }
}

function quietLogs(t: TestContext): string[] {
  const logged: string[] = [];
  for (const level of ["log", "info", "warn", "error", "debug"] as const) {
    t.mock.method(console, level, (...args: unknown[]) => {
      logged.push(args.map((arg) => typeof arg === "string" ? arg : JSON.stringify(arg)).join(" "));
    });
  }
  return logged;
}

async function setup(t: TestContext, options: { holdMs?: number } = {}) {
  const logged = quietLogs(t);
  const database = new FailingDatabase(new PGliteDatabase());
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused-in-test",
    publicBaseUrl: "https://control.internal.example",
    relaycastUrl: "http://relaycast.internal",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: "http://history.internal",
    relayhistoryPublicUrl: HISTORY_PUBLIC,
    sessionReadApi: { url: "http://history.internal", publicUrl: HISTORY_PUBLIC, secret: "session-read-secret-".repeat(2) },
    introspectSecret: INTROSPECT_SECRET,
    ...(options.holdMs !== undefined ? { introspectOutageHoldMs: options.holdMs } : {}),
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    internalServiceToken: INTERNAL,
    oauthRedirectUrl: "https://control.internal.example/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.internal.example/",
    port: 3000,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const control = createServer(createApp({ config, store }));
  const origin = await listen(control);
  t.after(async () => {
    await close(control);
    await database.close();
  });

  const org = await request(origin, "/api/v1/organizations", {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Tenant", ownerEmail: "owner@example.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const workspace = async (name: string) => {
    const created = await request(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, relaycastApiKey: `rk_${name}` },
    });
    assert.equal(created.status, 201);
    return created.body.id as string;
  };
  const alpha = await workspace("alpha");
  const beta = await workspace("beta");
  const ownerId = org.body.owner.id as string;
  const login = async (workspaceId = alpha) => {
    const started = await request(origin, "/api/v1/auth/device/start", {
      method: "POST",
      body: { client_name: "outage-hold-test" },
    });
    const approved = await request(origin, "/api/v1/auth/device/approve", {
      method: "POST",
      token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: ownerId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const tokens = await request(origin, "/api/v1/auth/device/token", {
      method: "POST",
      body: { device_code: started.body.device_code },
    });
    assert.equal(tokens.status, 200);
    return tokens.body.access_token as string;
  };
  const introspect = (body: Record<string, unknown>) =>
    request(origin, "/internal/v1/auth/introspect", { method: "POST", token: INTROSPECT_SECRET, body });
  const revoke = async (token: string) => {
    const revoked = await request(origin, "/api/v1/auth/token/revoke", { method: "POST", token });
    assert.equal(revoked.status, 200);
  };
  return { origin, database, store, alpha, beta, ownerId, login, introspect, revoke, logged };
}

function assertOutageError(response: { status: number; body: any }) {
  assert.equal(response.status, 500);
  assert.equal(response.body.error, "internal");
}

test("hold off (default): an outage fails introspection even right after a successful check", async (t) => {
  const env = await setup(t);
  const token = await env.login();
  const ok = await env.introspect({ token, aud: HISTORY_PUBLIC });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.active, true);
  assert.equal("held" in ok.body, false);
  env.database.outage = true;
  assertOutageError(await env.introspect({ token, aud: HISTORY_PUBLIC }));
});

test("hold on: an outage answers the last active verdict, marked held with a clamped exp", async (t) => {
  const holdMs = 60_000;
  const env = await setup(t, { holdMs });
  const token = await env.login();
  const before = Date.now();
  const fresh = await env.introspect({ token, aud: HISTORY_PUBLIC });
  const after = Date.now();
  assert.equal(fresh.status, 200);
  assert.equal(fresh.body.active, true);
  assert.equal("held" in fresh.body, false);

  env.database.outage = true;
  const held = await env.introspect({ token, aud: HISTORY_PUBLIC });
  assert.equal(held.status, 200);
  assert.equal(held.body.active, true);
  assert.equal(held.body.held, true);
  for (const field of ["sub", "email", "principal_type", "org", "workspace", "role", "scopes", "aud", "iat", "token_id", "machine_id", "capture_policy"]) {
    assert.deepEqual(held.body[field], fresh.body[field], field);
  }
  assert.ok(held.body.exp <= Math.floor((after + holdMs) / 1_000) + 1);
  assert.ok(held.body.exp >= Math.floor((before + holdMs) / 1_000) - 1);
  assert.ok(held.body.exp <= fresh.body.exp);

  // Also with the matching workspace supplied.
  const scoped = await env.introspect({ token, aud: HISTORY_PUBLIC, workspace: env.alpha });
  assert.equal(scoped.status, 200);
  assert.equal(scoped.body.held, true);

  const line = env.logged.find((text) => text.includes("[selfhost-api] token introspection held"));
  assert.ok(line, "held answers are logged");
  assert.ok(line.includes(fresh.body.token_id));
  assert.ok(line.includes("ECONNREFUSED"));
  assert.ok(line.includes("age_ms"));
  assert.ok(!env.logged.some((text) => text.includes(token) || text.includes(hashSecret(token))), "never the token");

  // Recovery: the database answers again and the answer is no longer held.
  env.database.outage = false;
  const recovered = await env.introspect({ token, aud: HISTORY_PUBLIC });
  assert.equal(recovered.status, 200);
  assert.equal(recovered.body.active, true);
  assert.equal("held" in recovered.body, false);
  assert.equal(recovered.body.exp, fresh.body.exp);
});

test("hold on: only verified tokens are held; request checks still run; machine claims never held", async (t) => {
  const env = await setup(t, { holdMs: 60_000 });
  const token = await env.login();
  const unseen = await env.login();
  assert.equal((await env.introspect({ token, aud: HISTORY_PUBLIC })).body.active, true);

  env.database.outage = true;
  assertOutageError(await env.introspect({ token: unseen, aud: HISTORY_PUBLIC }));
  assert.deepEqual(
    (await env.introspect({ token, aud: HISTORY_PUBLIC, workspace: env.beta })).body,
    { active: false, reason: "workspace" },
  );
  assert.deepEqual(
    (await env.introspect({ token, aud: "https://elsewhere.selfhosted.test" })).body,
    { active: false, reason: "audience" },
  );
  assertOutageError(await env.introspect({ token, aud: HISTORY_PUBLIC, machine: NODE }));
  // Still answered for the verified token.
  assert.equal((await env.introspect({ token, aud: HISTORY_PUBLIC })).body.held, true);
});

test("hold on: an inactive verdict forgets the token", async (t) => {
  const env = await setup(t, { holdMs: 60_000 });
  const token = await env.login();
  assert.equal((await env.introspect({ token, aud: HISTORY_PUBLIC })).body.active, true);
  await env.revoke(token);
  assert.deepEqual((await env.introspect({ token, aud: HISTORY_PUBLIC })).body, { active: false, reason: "revoked" });
  env.database.outage = true;
  assertOutageError(await env.introspect({ token, aud: HISTORY_PUBLIC }));
});

test("hold on: a revocation not yet introspected stays invisible until the database returns (documented bound)", async (t) => {
  const env = await setup(t, { holdMs: 60_000 });
  const token = await env.login();
  assert.equal((await env.introspect({ token, aud: HISTORY_PUBLIC })).body.active, true);
  await env.revoke(token);
  env.database.outage = true;
  const held = await env.introspect({ token, aud: HISTORY_PUBLIC });
  assert.equal(held.status, 200);
  assert.equal(held.body.active, true);
  assert.equal(held.body.held, true);
  env.database.outage = false;
  assert.deepEqual((await env.introspect({ token, aud: HISTORY_PUBLIC })).body, { active: false, reason: "revoked" });
  env.database.outage = true;
  assertOutageError(await env.introspect({ token, aud: HISTORY_PUBLIC }));
});

test("readyz reports the outage hold in effect", async (t) => {
  const off = await setup(t);
  const offReady = await request(off.origin, "/readyz");
  assert.equal(offReady.body.introspection.outageHoldMs, 0);
  const on = await setup(t, { holdMs: 90_000 });
  const onReady = await request(on.origin, "/readyz");
  assert.equal(onReady.body.introspection.outageHoldMs, 90_000);
  assert.equal(onReady.body.introspection.enabled, true);
});

// ---------------------------------------------------------------------------
// IntrospectionHold

function token(hash: string, overrides: Partial<IntrospectedToken> = {}): IntrospectedToken {
  return {
    userId: "user",
    email: "user@example.test",
    organizationId: "org",
    workspaceId: "ws",
    role: "member",
    scopes: ["history:write"],
    accessTokenHash: hash,
    revoked: false,
    expired: false,
    issuedAt: new Date(0),
    expiresAt: new Date(1_000_000),
    capturePolicy: { version: 1, revision: 1, settings: {} },
    ...overrides,
  };
}

test("IntrospectionHold serves an entry only within holdMs and before token expiry", () => {
  let now = 10_000;
  const hold = new IntrospectionHold(5_000, { now: () => now });
  hold.observe(token("a"));
  now = 14_000;
  const entry = hold.lookup("a");
  assert.ok(entry, "exactly 1000 ms left: returned");
  assert.equal(entry.checkedAt, 10_000);
  assert.equal(entry.validUntil, 15_000);
  now = 14_001;
  assert.equal(hold.lookup("a"), null, "999 ms left of the hold: not served");
  assert.equal(hold.size, 0, "stale entries are deleted on lookup");

  now = 0;
  hold.observe(token("b", { expiresAt: new Date(3_000) }));
  now = 1_000;
  assert.equal(hold.lookup("b")?.validUntil, 3_000, "validUntil = min(expiry, checkedAt + holdMs)");
  now = 2_000;
  assert.ok(hold.lookup("b"), "1000 ms left of the token's life: returned");
  now = 2_001;
  assert.equal(hold.lookup("b"), null, "999 ms left of the token's life: not served");
});

test("IntrospectionHold forgets on unknown, revoked or expired verdicts", () => {
  const hold = new IntrospectionHold(60_000, { now: () => 0 });
  hold.observe(token("a"));
  hold.observe(token("b"));
  hold.observe(token("c"));
  hold.observe(null, "a");
  hold.observe(token("b", { revoked: true }));
  hold.observe(token("c", { expired: true }));
  assert.equal(hold.lookup("a"), null);
  assert.equal(hold.lookup("b"), null);
  assert.equal(hold.lookup("c"), null);
  assert.equal(hold.size, 0);
  hold.observe(null);
  assert.equal(hold.size, 0);
});

test("IntrospectionHold is a bounded LRU", () => {
  let now = 0;
  const hold = new IntrospectionHold(60_000, { maxEntries: 2, now: () => now });
  hold.observe(token("a"));
  hold.observe(token("b"));
  assert.ok(hold.lookup("a"), "touch a: b is now the oldest");
  hold.observe(token("c"));
  assert.equal(hold.size, 2);
  assert.equal(hold.lookup("b"), null);
  assert.ok(hold.lookup("a"));
  assert.ok(hold.lookup("c"));

  // At capacity, stale entries are pruned before a live one is evicted.
  now = 1;
  hold.observe(token("d", { expiresAt: new Date(2) }));
  assert.equal(hold.lookup("a"), null, "a was the least recently used");
  now = 5;
  hold.observe(token("e"));
  assert.ok(hold.lookup("c"), "the expired d made room, not c");
  assert.ok(hold.lookup("e"));
  assert.equal(hold.size, 2);
  assert.throws(() => new IntrospectionHold(0));
});

// ---------------------------------------------------------------------------
// isDatabaseUnavailable

test("isDatabaseUnavailable accepts connection-class errors only", () => {
  const coded = (code: string) => Object.assign(new Error("x"), { code });
  assert.equal(isDatabaseUnavailable(refused()), true);
  for (const code of ["08006", "08001", "08P01", "57P01", "57P02", "57P03", "53300", "ECONNRESET", "ETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH", "ENOTFOUND", "EAI_AGAIN", "EPIPE"]) {
    assert.equal(isDatabaseUnavailable(coded(code)), true, code);
  }
  assert.equal(isDatabaseUnavailable({ code: "08006" }), true);
  assert.equal(isDatabaseUnavailable(new Error("timeout exceeded when trying to connect")), true);
  assert.equal(isDatabaseUnavailable(new Error("Connection terminated unexpectedly")), true);
  assert.equal(isDatabaseUnavailable(new AggregateError([new Error("boom"), refused()])), true);
  assert.equal(isDatabaseUnavailable(new Error("wrapped", { cause: coded("57P01") })), true);

  assert.equal(isDatabaseUnavailable(coded("42P01")), false);
  assert.equal(isDatabaseUnavailable(coded("23505")), false);
  assert.equal(isDatabaseUnavailable(coded("42601")), false);
  assert.equal(isDatabaseUnavailable(new TypeError("x is undefined")), false);
  assert.equal(isDatabaseUnavailable(new Error("boom")), false);
  assert.equal(isDatabaseUnavailable(new AggregateError([new Error("boom")])), false);
  for (const value of [null, undefined, "ECONNREFUSED", 8006, true]) {
    assert.equal(isDatabaseUnavailable(value), false, String(value));
  }
  const cyclic: { code?: string; cause?: unknown } = {};
  cyclic.cause = cyclic;
  assert.equal(isDatabaseUnavailable(cyclic), false);
});
