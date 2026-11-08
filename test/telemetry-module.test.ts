// telemetry lane: module tests on PGlite with mocked Relaycast/RelayHistory and
// a mock hosted ingest that verifies signatures. Covers levels, preview,
// outbox retry/backoff, error bursts, issue reports, and air-gapped export.
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server } from "node:http";
import test from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import type { Database, SqlExecutor, SqlResult } from "../src/database.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { loadTelemetryConfig } from "../src/telemetry/config.js";
import { createTelemetryModule, type TelemetryModule } from "../src/telemetry/module.js";
import { INSTALL_HEADER, SIGNATURE_HEADER, verifySignature } from "../src/telemetry/sign.js";

class PGliteDatabase implements Database {
  readonly schema = "public";
  constructor(readonly client = new PGlite()) {}
  async query<T extends Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<SqlResult<T>> {
    const result = params.length > 0 ? await this.client.query<T>(sql, params) : await this.client.query<T>(sql);
    return { rows: result.rows };
  }
  async transaction<T>(run: (transaction: SqlExecutor) => Promise<T>): Promise<T> {
    return this.client.transaction(async (transaction) => run({
      query: async <R extends Record<string, unknown>>(sql: string, params: unknown[] = []) => {
        const result = params.length > 0 ? await transaction.query<R>(sql, params) : await transaction.query<R>(sql);
        return { rows: result.rows };
      },
      exec: async (sql: string) => { await transaction.exec(sql); },
    }));
  }
  async close(): Promise<void> { await this.client.close(); }
  async exec(sql: string): Promise<void> { await this.client.exec(sql); }
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");
  return `http://127.0.0.1:${address.port}`;
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

const BOOTSTRAP = "b".repeat(48);
const INTERNAL = "i".repeat(48);
const INSTALL_KEY = "install-key-".padEnd(48, "z");
const INSTALL_ID = "inst_testinstall01";
const RELAYCAST_KEY = "rk_live_" + "Q7x9".repeat(8);
const OWNER_EMAIL = "owner.person@acme-customer.example";

type Harness = {
  baseUrl: string;
  telemetry: TelemetryModule;
  database: PGliteDatabase;
  ingest: { bodies: string[]; statuses: number[]; respond: number[] };
  audits: unknown[];
  organizationId: string;
  ownerId: string;
  workspaceId: string;
  cleanup(): Promise<void>;
};

async function harness(env: Record<string, string>, tenancy: "single" | "multi" = "single"): Promise<Harness> {
  const ingest = { bodies: [] as string[], statuses: [] as number[], respond: [] as number[] };
  const upstream = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://x");
    if (url.pathname === "/relaycast/health") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, version: "8.5.2", build: "abc123", secretish: "do-not-forward" }));
      return;
    }
    if (url.pathname === "/relaycast/v1/console/stats") {
      if (request.headers.authorization !== `Bearer ${RELAYCAST_KEY}`) {
        response.writeHead(401).end();
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, data: { total_messages: 12, unique_agents: 3, channel_messages: 10, dm_messages: 2 } }));
      return;
    }
    if (url.pathname === "/history/readyz") {
      response.writeHead(503, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: false, reason: "schema_pending" }));
      return;
    }
    if (url.pathname === "/ingest" && request.method === "POST") {
      const body = await readBody(request);
      const valid = request.headers[INSTALL_HEADER] === INSTALL_ID &&
        verifySignature(INSTALL_KEY, body, String(request.headers[SIGNATURE_HEADER] ?? ""));
      const status = valid ? (ingest.respond.shift() ?? 202) : 401;
      ingest.statuses.push(status);
      if (valid && status < 300) ingest.bodies.push(body);
      response.writeHead(status, { "content-type": "application/json" });
      response.end("{}");
      return;
    }
    response.writeHead(404).end();
  });
  const upstreamUrl = await listen(upstream);

  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseSchema: "public",
    databaseUrl: "unused",
    publicBaseUrl: "https://control.internal.example",
    relaycastUrl: `${upstreamUrl}/relaycast`,
    relaycastPublicUrl: "https://cast.customer.example",
    relayauthUrl: upstreamUrl,
    relayhistoryUrl: `${upstreamUrl}/history`,
    relayhistoryPublicUrl: "https://history.customer.example",
    relayauthApiKey: "rak_test",
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    port: 0,
    host: "127.0.0.1",
    internalServiceToken: null,
    oauthRedirectUrl: "https://control.internal.example/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.internal.example/",
  };
  const audits: unknown[] = [];
  const telemetry = createTelemetryModule({
    config: loadTelemetryConfig({
      SELFHOST_TELEMETRY_INSTALL_ID: INSTALL_ID,
      SELFHOST_TELEMETRY_INSTALL_KEY: INSTALL_KEY,
      SELFHOST_TELEMETRY_ENDPOINT: `${upstreamUrl}/ingest`,
      SELFHOST_TELEMETRY_BURST_THRESHOLD: "3",
      SELFHOST_TELEMETRY_PROBES: `relaycast=${upstreamUrl}/relaycast/health,relayhistory=${upstreamUrl}/history/readyz`,
      SELFHOST_TELEMETRY_DEPLOYMENT: JSON.stringify({ chartVersion: "0.4.1", relaycast: { replicas: 1, backend: "sqlite" } }),
      SELFHOST_INTERNAL_TOKEN: INTERNAL,
      ...env,
    }),
    database,
    keyring: config.encryptionKeyring,
    relaycontrolVersion: "0.1.0-test",
    relaycastUrl: config.relaycastUrl,
    audit: async (event) => { audits.push(event); },
    log: () => undefined,
    tenancy,
  });
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0, { tenancy });
  const server = createServer(createApp({ config, store, telemetry }));
  const baseUrl = await listen(server);

  const org = await call(baseUrl, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, body: { name: "Acme Secret Project", ownerEmail: OWNER_EMAIL, ownerName: "Owner Person" },
  });
  assert.equal(org.status, 201, JSON.stringify(org.body));
  const organizationId = String(org.body.id);
  const workspace = await call(baseUrl, `/api/v1/organizations/${organizationId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "Default", relaycastWorkspaceId: "rw_1", relaycastApiKey: RELAYCAST_KEY },
  });
  assert.equal(workspace.status, 201, JSON.stringify(workspace.body));

  return {
    baseUrl,
    telemetry,
    database,
    ingest,
    audits,
    organizationId,
    ownerId: String(org.body.owner.id),
    workspaceId: String(workspace.body.id),
    async cleanup() {
      await telemetry.stop();
      await close(server);
      await close(upstream);
      await database.close();
    },
  };
}

async function call(
  baseUrl: string,
  path: string,
  options: { method?: string; token?: string; body?: unknown } = {},
): Promise<{ status: number; body: Record<string, any>; raw: string; headers: Headers }> {
  const response = await fetch(`${baseUrl}${path}`, {
    method: options.method ?? "GET",
    headers: {
      ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
      ...(options.body !== undefined ? { "content-type": "application/json" } : {}),
    },
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  const raw = await response.text();
  let body: Record<string, any> = {};
  try { body = raw ? JSON.parse(raw) as Record<string, any> : {}; } catch { body = {}; }
  return { status: response.status, body, raw, headers: response.headers };
}

/** Nothing identifying or secret may appear in anything we would send. */
function assertPrivate(raw: string, h: Harness): void {
  for (const forbidden of [RELAYCAST_KEY, OWNER_EMAIL, "Owner Person", "Acme Secret Project", h.workspaceId, h.organizationId, "do-not-forward", INSTALL_KEY]) {
    assert.equal(raw.includes(forbidden), false, `payload leaked ${forbidden.slice(0, 12)}…`);
  }
}

test("full level: preview shows exactly the scrubbed next digest; outbox retries then delivers", async (t) => {
  const h = await harness({ SELFHOST_TELEMETRY_LEVEL: "full" });
  t.after(() => h.cleanup());

  assert.equal((await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry/preview`)).status, 401);

  // Usage traffic and one secret-bearing error.
  await call(h.baseUrl, "/api/v1/organizations", { token: BOOTSTRAP });
  await call(h.baseUrl, `/cloud/api/v1/workspaces/${h.workspaceId}/runtime`, { token: BOOTSTRAP });
  await call(h.baseUrl, "/api/v1/nope");
  h.telemetry.observeError(
    Object.assign(new Error(`password=${RELAYCAST_KEY} for ${OWNER_EMAIL}`), { code: "EPIPE" }),
    { path: `/api/v1/workspaces/${h.workspaceId}/sessions`, status: 500 },
  );
  await new Promise((resolve) => setTimeout(resolve, 50));

  const preview = await call(h.baseUrl, `/cloud/api/v1/organizations/${h.organizationId}/telemetry/preview`, { token: BOOTSTRAP });
  assert.equal(preview.status, 200, preview.raw);
  assertPrivate(preview.raw, h);
  const next = preview.body.nextDigest;
  assert.equal(next.schema, "agent-relay.selfhost.telemetry/v1");
  assert.equal(next.kind, "digest");
  assert.equal(next.level, "full");
  assert.equal(next.installId, INSTALL_ID);
  assert.deepEqual(next.deployment, { chartVersion: "0.4.1", relaycast: { replicas: 1, backend: "sqlite" } });
  const relaycast = next.components.find((c: any) => c.name === "relaycast");
  assert.deepEqual({ healthy: relaycast.healthy, version: relaycast.version, build: relaycast.build }, { healthy: true, version: "8.5.2", build: "abc123" });
  const history = next.components.find((c: any) => c.name === "relayhistory");
  assert.deepEqual({ healthy: history.healthy, status: history.status, reason: history.reason }, { healthy: false, status: 503, reason: "schema_pending" });
  assert.equal(next.usage.relaycast.messages24h, 12);
  assert.equal(next.usage.relaycast.activeAgents24h, 3);
  assert.match(next.usage.relaycast.perWorkspace[0].workspace, /^h_[a-f0-9]{20}$/);
  assert.equal(next.usage.gauges.workspaces, 1);
  assert.ok(next.usage.requestsByArea.organizations.total >= 1);
  // Bootstrap tokens cannot read workspace runtime: counted as a 4xx.
  assert.equal(next.usage.requestsByArea.runtime["4xx"], 1);
  assert.equal(next.usage.activeWorkspaces, 1);
  const error = next.errors[0];
  assert.equal(error.errorClass, "Error:EPIPE");
  assert.equal(error.route, "/api/v1/workspaces/:id/sessions");
  assert.equal(error.count, 1);
  assert.match(error.fingerprint, /^fp_[a-f0-9]{16}$/);

  // Hypothetical preview at another level never changes config.
  const asErrors = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry/preview?level=errors`, { token: BOOTSTRAP });
  assert.equal(asErrors.body.hypothetical, true);
  assert.equal(asErrors.body.nextDigest.usage, undefined);

  // Digest -> outbox -> first attempt 503 -> retry -> delivered, signed.
  h.ingest.respond.push(503);
  const id = await h.telemetry.digestNow();
  assert.ok(id);
  await h.telemetry.sendDue();
  let rows = (await h.database.query<{ status: string; attempts: number; last_error: string }>(
    "SELECT status, attempts, last_error FROM selfhost_telemetry_outbox WHERE id = $1", [id])).rows;
  assert.deepEqual(rows[0], { status: "pending", attempts: 1, last_error: "http_503" });
  await h.database.query("UPDATE selfhost_telemetry_outbox SET next_attempt_at = now() WHERE id = $1", [id]);
  assert.equal(await h.telemetry.sendDue(), 1);
  rows = (await h.database.query<{ status: string; attempts: number; last_error: string }>(
    "SELECT status, attempts, last_error FROM selfhost_telemetry_outbox WHERE id = $1", [id])).rows;
  assert.deepEqual(rows[0], { status: "sent", attempts: 2, last_error: null });
  assert.deepEqual(h.ingest.statuses, [503, 202]);
  const delivered = JSON.parse(h.ingest.bodies[0]!);
  assert.equal(delivered.reportId, id);
  assertPrivate(h.ingest.bodies[0]!, h);

  // The window was consumed: the next preview starts empty.
  const after = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry/preview`, { token: BOOTSTRAP });
  assert.deepEqual(after.body.nextDigest.errors, []);
  const status = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry`, { token: BOOTSTRAP });
  assert.equal(status.body.outbox.sent, 1);
  assert.equal(status.body.config.installKeyConfigured, true);
  assert.equal(status.raw.includes(INSTALL_KEY), false);
});

test("error burst is reported immediately, once per quiet period", async (t) => {
  const h = await harness({ SELFHOST_TELEMETRY_LEVEL: "errors" });
  t.after(() => h.cleanup());
  const boom = () => {
    const error = new Error("upstream said no");
    error.stack = "Error: upstream said no\n    at readEvents (/app/dist/relayhistory.js:10:3)";
    Object.assign(error, { stage: "events", status: 502 });
    return error;
  };
  for (let i = 0; i < 7; i += 1) {
    h.telemetry.observeError(boom(), { path: "/api/v1/workspaces/x/sessions", status: 502 });
  }
  for (let i = 0; i < 50 && h.ingest.bodies.length === 0; i += 1) await new Promise((r) => setTimeout(r, 20));
  assert.equal(h.ingest.bodies.length, 1);
  const burst = JSON.parse(h.ingest.bodies[0]!);
  assert.equal(burst.kind, "error_burst");
  assert.equal(burst.level, "errors");
  assert.equal(burst.burst.component, "relayhistory");
  assert.equal(burst.burst.count, 3);
  assert.equal(burst.burst.status, 502);
  assert.equal(burst.usage, undefined);
  // Errors level: digest carries errors, components, versions, no usage.
  const preview = await h.telemetry.previewNext();
  assert.equal(preview?.usage, undefined);
  assert.equal((preview?.errors as unknown[]).length, 1);
  // Crossing the threshold again within 30 minutes does not re-report.
  for (let i = 0; i < 6; i += 1) h.telemetry.observeError(boom(), { path: "/x", status: 502 });
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(h.ingest.bodies.length, 1);
});

test("off level collects and sends nothing; issue reports still need explicit action", async (t) => {
  const h = await harness({ SELFHOST_TELEMETRY_LEVEL: "off" });
  t.after(() => h.cleanup());
  for (let i = 0; i < 10; i += 1) h.telemetry.observeError(new Error("x"), { path: "/x", status: 500 });
  h.telemetry.observeRequest({ method: "GET", path: "/api/v1/organizations", status: 200 });
  await h.telemetry.flush();
  assert.equal(await h.telemetry.digestNow(), null);
  const counts = await h.database.query<{ n: number }>(
    `SELECT (SELECT count(*) FROM selfhost_telemetry_counters)::int
          + (SELECT count(*) FROM selfhost_telemetry_errors)::int
          + (SELECT count(*) FROM selfhost_telemetry_outbox)::int AS n`);
  assert.equal(counts.rows[0]?.n, 0);
  const preview = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry/preview`, { token: BOOTSTRAP });
  assert.equal(preview.body.nextDigest, null);
  assert.match(preview.body.note, /off/);
  assert.equal(h.ingest.bodies.length, 0);
});

test("report an issue: service token, dry run, scrubbing, audit, delivery", async (t) => {
  const h = await harness({ SELFHOST_TELEMETRY_LEVEL: "errors" });
  t.after(() => h.cleanup());
  const issue = {
    title: "RelayHistory 5xx since 03:10",
    summary: `Sessions page fails. Token ghp_${"A1b2".repeat(9)} and ${OWNER_EMAIL} at 10.4.0.12, workspace ${h.workspaceId}`,
    severity: "high",
    component: "relayhistory",
    supportBundle: {
      manifest: { schemaVersion: 1, collectorVersion: "1.0.0", readOnly: true, kubernetesSecretsCollected: false },
      documents: {
        "versions.json": { images: [{ container: "relayhistory", version: "sha256:abc" }] },
        "network-health.json": { backends: [{ url: `https://u:${RELAYCAST_KEY}@history.acme.example/readyz` }] },
        "pods.log": "raw log lines",
      },
    },
  };
  assert.equal((await call(h.baseUrl, "/internal/v1/telemetry/issues", { method: "POST", body: issue })).status, 401);
  assert.equal((await call(h.baseUrl, "/internal/v1/telemetry/issues", { method: "POST", token: "wrong".repeat(10), body: issue })).status, 401);

  const dry = await call(h.baseUrl, "/internal/v1/telemetry/issues", { method: "POST", token: INTERNAL, body: { ...issue, dryRun: true } });
  assert.equal(dry.status, 200, dry.raw);
  assertPrivate(dry.raw, h);
  assert.ok(!dry.raw.includes("10.4.0.12"));
  assert.equal(dry.body.wouldSend.kind, "issue_report");
  assert.equal(dry.body.wouldSend.issue.severity, "high");
  assert.ok(dry.body.wouldSend.scrubber.redactions >= 1);
  assert.deepEqual(Object.keys(dry.body.wouldSend.supportBundle.documents).sort(), ["network-health.json", "versions.json"]);
  assert.equal(h.ingest.bodies.length, 0);

  const filed = await call(h.baseUrl, "/internal/v1/telemetry/issues", { method: "POST", token: INTERNAL, body: issue });
  assert.equal(filed.status, 202, filed.raw);
  assert.equal(filed.body.delivery, "queued");
  for (let i = 0; i < 50 && h.ingest.bodies.length === 0; i += 1) await new Promise((r) => setTimeout(r, 20));
  assert.equal(h.ingest.bodies.length, 1);
  assertPrivate(h.ingest.bodies[0]!, h);
  assert.equal(JSON.parse(h.ingest.bodies[0]!).reportId, filed.body.id);
  assert.deepEqual(h.audits, [{ organizationId: null, actor: { kind: "service", subject: "internal-service-token" }, action: "telemetry.issue.create", target: filed.body.id }]);

  // Org admins file through the org route; validation errors are 400.
  const bad = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry/issues`, { method: "POST", token: BOOTSTRAP, body: { title: "x" } });
  assert.equal(bad.status, 400);
  const tool = await call(h.baseUrl, "/cloud/api/v1/telemetry/mcp-tool");
  assert.equal(tool.body.tool.name, "report_selfhost_issue");
  const page = await fetch(`${h.baseUrl}/cloud/api/v1/telemetry/admin`);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /what we send/);
});

test("air-gapped: file transport never sends; export is signed and marks rows exported", async (t) => {
  const h = await harness({ SELFHOST_TELEMETRY_LEVEL: "full", SELFHOST_TELEMETRY_TRANSPORT: "file" });
  t.after(() => h.cleanup());
  h.telemetry.observeError(new Error("x"), { path: "/x", status: 500 });
  const id = await h.telemetry.digestNow();
  assert.ok(id);
  assert.equal(await h.telemetry.sendDue(), 0);
  const exported = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry/export?snapshot=1`, { token: BOOTSTRAP });
  assert.equal(exported.status, 200, exported.raw);
  assert.match(exported.headers.get("content-disposition") ?? "", /attachment; filename="agent-relay-telemetry-/);
  assert.equal(exported.body.envelopes.length, 2);
  for (const envelope of exported.body.envelopes) {
    assert.equal(envelope.format, "agent-relay-telemetry-export/v1");
    assert.equal(verifySignature(INSTALL_KEY, envelope.body, envelope.signature), true);
  }
  assertPrivate(exported.raw, h);
  const rows = await h.database.query<{ status: string }>("SELECT status FROM selfhost_telemetry_outbox WHERE id = $1", [id]);
  assert.equal(rows.rows[0]?.status, "exported");
  assert.equal(h.ingest.bodies.length, 0);
  assert.equal(h.audits.length, 1);
});

/** A CLI device token for userId, approved by the bootstrap bearer. */
async function ownerToken(h: Harness, userId: string, workspaceId: string): Promise<string> {
  const started = await call(h.baseUrl, "/api/v1/auth/device/start", { method: "POST", body: { client_name: "telemetry-test" } });
  assert.equal(started.status, 201, started.raw);
  const approved = await call(h.baseUrl, "/api/v1/auth/device/approve", {
    method: "POST", token: BOOTSTRAP,
    body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
  });
  assert.equal(approved.status, 200, approved.raw);
  const tokens = await call(h.baseUrl, "/api/v1/auth/device/token", { method: "POST", body: { device_code: started.body.device_code } });
  assert.equal(tokens.status, 200, tokens.raw);
  return String(tokens.body.access_token);
}

test("multi tenancy: an organization admin sees only its own telemetry; installation-wide views are bootstrap-only", async (t) => {
  const h = await harness({ SELFHOST_TELEMETRY_LEVEL: "full", SELFHOST_TELEMETRY_TRANSPORT: "file" }, "multi");
  t.after(() => h.cleanup());
  const other = await call(h.baseUrl, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, body: { name: "Other Org", ownerEmail: "other@other.example", ownerName: "Other Owner" },
  });
  assert.equal(other.status, 201, other.raw);
  const otherId = String(other.body.id);
  const otherWorkspace = await call(h.baseUrl, `/api/v1/organizations/${otherId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "OtherWs", relaycastWorkspaceId: "rw_2", relaycastApiKey: "rk_other" },
  });
  assert.equal(otherWorkspace.status, 201, otherWorkspace.raw);
  const owner = await ownerToken(h, h.ownerId, h.workspaceId);
  const otherOwner = await ownerToken(h, String(other.body.owner.id), String(otherWorkspace.body.id));

  // An installation-wide digest plus one issue report in each organisation.
  h.telemetry.observeError(new Error("x"), { path: "/x", status: 500 });
  assert.ok(await h.telemetry.digestNow());
  const mine = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry/issues`, {
    method: "POST", token: owner, body: { title: "Mine is broken", summary: "It fails" },
  });
  assert.equal(mine.status, 202, mine.raw);
  const theirs = await call(h.baseUrl, `/api/v1/organizations/${otherId}/telemetry/issues`, {
    method: "POST", token: otherOwner, body: { title: "Theirs is broken", summary: "It fails" },
  });
  assert.equal(theirs.status, 202, theirs.raw);

  // Another organisation's telemetry is not there at all.
  for (const action of ["", "/preview", "/export"]) {
    const foreign = await call(h.baseUrl, `/api/v1/organizations/${otherId}/telemetry${action}`, { token: owner });
    assert.equal(foreign.status, 404, `${action}: ${foreign.raw}`);
  }

  const status = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry`, { token: owner });
  assert.equal(status.status, 200, status.raw);
  assert.equal(status.body.scope, "organization");
  assert.deepEqual(status.body.issueReports, { pending: 1 });
  assert.equal(status.body.installId, undefined);

  const preview = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry/preview`, { token: owner });
  assert.equal(preview.status, 200, preview.raw);
  assert.equal(preview.body.nextDigest, null);
  assert.deepEqual(preview.body.pending.map((row: { id: string }) => row.id), [mine.body.id]);
  assert.equal((await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry/preview?level=full`, { token: owner })).status, 403);
  const snapshot = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry/export?snapshot=1`, { token: owner });
  assert.equal(snapshot.status, 403);
  assert.equal(snapshot.body.error, "installation_scope");

  const exported = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry/export`, { token: owner });
  assert.equal(exported.status, 200, exported.raw);
  assert.equal(exported.body.envelopes.length, 1);
  assert.equal(verifySignature(INSTALL_KEY, exported.body.envelopes[0].body, exported.body.envelopes[0].signature), true);
  assert.doesNotMatch(exported.raw, /Theirs is broken/);
  const stillPending = await h.database.query<{ count: string }>(
    "SELECT count(*)::text AS count FROM selfhost_telemetry_outbox WHERE status = 'pending'",
  );
  assert.equal(stillPending.rows[0]?.count, "3");

  // The bootstrap bearer keeps the installation-wide view.
  const full = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry/export?snapshot=1`, { token: BOOTSTRAP });
  assert.equal(full.status, 200, full.raw);
  assert.equal(full.body.envelopes.length, 4); // the digest, both issue reports, and the snapshot
  const fullStatus = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry`, { token: BOOTSTRAP });
  assert.equal(fullStatus.status, 200);
  assert.notEqual(fullStatus.body.scope, "organization");
});

test("multi tenancy: organisation admins' reports omit installation diagnostics and are rate-limited per organisation", async (t) => {
  const h = await harness({ SELFHOST_TELEMETRY_LEVEL: "errors", SELFHOST_TELEMETRY_TRANSPORT: "file" }, "multi");
  t.after(() => h.cleanup());
  const other = await call(h.baseUrl, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, body: { name: "Other Org", ownerEmail: "other@other.example", ownerName: "Other Owner" },
  });
  assert.equal(other.status, 201, other.raw);
  const otherId = String(other.body.id);
  const otherWorkspace = await call(h.baseUrl, `/api/v1/organizations/${otherId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "OtherWs", relaycastWorkspaceId: "rw_2", relaycastApiKey: "rk_other" },
  });
  assert.equal(otherWorkspace.status, 201, otherWorkspace.raw);
  const owner = await ownerToken(h, h.ownerId, h.workspaceId);
  const otherOwner = await ownerToken(h, String(other.body.owner.id), String(otherWorkspace.body.id));
  h.telemetry.observeError(new Error("installation-wide failure"), { path: "/x", status: 500 });
  const issue = { title: "Broken", summary: "It fails" };
  const route = (id: string) => `/api/v1/organizations/${id}/telemetry/issues`;

  const dry = await call(h.baseUrl, route(h.organizationId), { method: "POST", token: owner, body: { ...issue, dryRun: true } });
  assert.equal(dry.status, 200, dry.raw);
  assert.deepEqual(dry.body.wouldSend.diagnostics, { scope: "organization" });
  assert.doesNotMatch(dry.raw, /installation-wide failure|recentErrors|"components"|8\.5\.2/);
  const operatorDry = await call(h.baseUrl, route(h.organizationId), { method: "POST", token: BOOTSTRAP, body: { ...issue, dryRun: true } });
  assert.equal(operatorDry.status, 200, operatorDry.raw);
  assert.ok(Array.isArray(operatorDry.body.wouldSend.diagnostics.components), "the operator keeps installation diagnostics");

  for (let i = 0; i < 20; i += 1) {
    const filed = await call(h.baseUrl, route(h.organizationId), { method: "POST", token: owner, body: issue });
    assert.equal(filed.status, 202, filed.raw);
  }
  const limited = await call(h.baseUrl, route(h.organizationId), { method: "POST", token: owner, body: issue });
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error, "rate_limited");
  // Another organisation and the operator lanes have their own budgets.
  assert.equal((await call(h.baseUrl, route(otherId), { method: "POST", token: otherOwner, body: issue })).status, 202);
  assert.equal((await call(h.baseUrl, "/internal/v1/telemetry/issues", { method: "POST", token: INTERNAL, body: issue })).status, 202);
  assert.equal((await call(h.baseUrl, route(h.organizationId), { method: "POST", token: BOOTSTRAP, body: issue })).status, 202);

  // The organisation-admin telemetry view knows status, preview and export only.
  const unknown = await call(h.baseUrl, `/api/v1/organizations/${h.organizationId}/telemetry/settings`, { token: owner });
  assert.equal(unknown.status, 404, unknown.raw);
});
