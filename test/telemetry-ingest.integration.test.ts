// telemetry lane: end-to-end against a real hosted-ingest instance.
//
// Skipped unless TELEMETRY_INGEST_URL, TELEMETRY_INSTALL_ID and
// TELEMETRY_INSTALL_KEY are set. The cloud repo's
// packages/web/test/handlers/selfhost-telemetry.e2e.test.ts starts a local
// ingest (the real route handler on PGlite with a mocked Relay API) and runs
// this file against it with those variables, then checks what was stored and
// announced. It can also target any other ingest the operator controls.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { migrate } from "../src/migrations.js";
import { loadTelemetryConfig } from "../src/telemetry/config.js";
import { createTelemetryModule } from "../src/telemetry/module.js";
import { exportEnvelope } from "../src/telemetry/sign.js";
import { PGliteDatabase } from "./support/harness.js";

const endpoint = process.env.TELEMETRY_INGEST_URL;
const installId = process.env.TELEMETRY_INSTALL_ID;
const installKey = process.env.TELEMETRY_INSTALL_KEY;
const enabled = Boolean(endpoint && installId && installKey);
const INTERNAL = "e2e-internal-token-".padEnd(48, "x");

test("relaycontrol -> hosted ingest: digest, error burst, issue report, and an air-gapped export", { skip: !enabled }, async () => {
  const database = new PGliteDatabase();
  await migrate(database);
  const telemetry = createTelemetryModule({
    config: loadTelemetryConfig({
      SELFHOST_TELEMETRY_LEVEL: "full",
      SELFHOST_TELEMETRY_ENDPOINT: endpoint,
      SELFHOST_TELEMETRY_INSTALL_ID: installId,
      SELFHOST_TELEMETRY_INSTALL_KEY: installKey,
      SELFHOST_TELEMETRY_BURST_THRESHOLD: "3",
      SELFHOST_INTERNAL_TOKEN: INTERNAL,
      SELFHOST_TELEMETRY_DEPLOYMENT: JSON.stringify({ chartVersion: "0.4.1", relayhistory: { replicas: 1 } }),
    }),
    database,
    keyring: { active: { id: "k", key: Buffer.alloc(32, 1) } },
    relaycontrolVersion: "0.1.0-e2e",
    log: () => undefined,
  });
  try {
    // A healthy-looking digest with one low-volume client error: not notable.
    telemetry.observeRequest({ method: "GET", path: "/api/v1/organizations", status: 200 });
    const digestId = await telemetry.digestNow();
    assert.ok(digestId);

    // A RelayHistory 5xx burst: notable, sent immediately.
    for (let i = 0; i < 3; i += 1) {
      const error = Object.assign(new Error("RelayHistory events failed"), { stage: "events", status: 502 });
      error.stack = "Error: RelayHistory events failed\n    at readRelayhistorySessionEvents (/app/dist/relayhistory.js:120:11)";
      telemetry.observeError(error, { path: "/cloud/api/v1/workspaces/3f2c3a4e-1111-4222-8333-944445555666/sessions", status: 502 });
    }

    // Wait for the burst (sent asynchronously) and the digest to be delivered.
    for (let i = 0; i < 100; i += 1) {
      await telemetry.sendDue();
      const pending = await database.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM telemetry_outbox WHERE status <> 'sent'");
      const total = await database.query<{ n: number }>("SELECT count(*)::int AS n FROM telemetry_outbox");
      if (pending.rows[0]?.n === 0 && (total.rows[0]?.n ?? 0) >= 2) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const rows = await database.query<{ kind: string; status: string; last_error: string | null }>(
      "SELECT kind, status, last_error FROM telemetry_outbox ORDER BY kind");
    assert.deepEqual(rows.rows.map((row) => [row.kind, row.status]), [["digest", "sent"], ["error_burst", "sent"]]);

    // A customer's agent files an issue through the same channel (real route).
    const server = createServer((request, response) => {
      const url = new URL(request.url ?? "/", "http://local");
      void telemetry.handle(request, response, url.pathname, url, {
        organizationAccess: async () => ({ kind: "bootstrap" }),
        requestObject: async (req) => {
          const chunks: Buffer[] = [];
          for await (const chunk of req) chunks.push(Buffer.from(chunk));
          return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
        },
        bearer: (req) => /^Bearer\s+(.+)$/i.exec(req.headers.authorization ?? "")?.[1] ?? null,
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const filed = await fetch(`http://127.0.0.1:${port}/internal/v1/telemetry/issues`, {
        method: "POST",
        headers: { authorization: `Bearer ${INTERNAL}`, "content-type": "application/json" },
        body: JSON.stringify({
          title: "RelayHistory 5xx since 03:10",
          summary: "Sessions page fails for every workspace after upgrading the chart.",
          severity: "high",
          category: "outage",
          component: "relayhistory",
        }),
      });
      assert.equal(filed.status, 202, await filed.clone().text());
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    for (let i = 0; i < 100; i += 1) {
      await telemetry.sendDue();
      const pending = await database.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM telemetry_outbox WHERE kind = 'issue_report' AND status = 'sent'");
      if (pending.rows[0]?.n === 1) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }

    // An air-gapped export, POSTed as a file with no signature headers.
    const snapshot = await telemetry.previewNext("errors");
    const envelope = exportEnvelope(installId!, installKey!, JSON.stringify(snapshot), Date.now() - 3 * 24 * 3600 * 1000);
    const response = await fetch(endpoint!, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ format: "agent-relay-telemetry-export/v1+bundle", installId, envelopes: [envelope] }),
    });
    assert.equal(response.status, 200, await response.clone().text());
    assert.equal(((await response.json()) as { accepted: number }).accepted, 1);
  } finally {
    await telemetry.stop();
    await database.close();
  }
});
