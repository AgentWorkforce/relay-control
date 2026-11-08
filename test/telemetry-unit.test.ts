// telemetry lane: unit tests (levels/config, signing, aggregation, identity,
// backoff, issue reports).
import assert from "node:assert/strict";
import test from "node:test";
import { featureArea, TelemetryAggregator, describeError } from "../src/telemetry/aggregator.js";
import { loadTelemetryConfig, parseProbes, sanitizeDeploymentShape } from "../src/telemetry/config.js";
import { errorFingerprint, hashIdentifier, routeTemplate } from "../src/telemetry/identity.js";
import { parseIssue, sanitizeSupportBundle } from "../src/telemetry/issues.js";
import { backoffSeconds } from "../src/telemetry/sender.js";
import { exportEnvelope, parseSignature, signBody, verifySignature } from "../src/telemetry/sign.js";

const KEY = "k".repeat(40);
const base = {
  SELFHOST_TELEMETRY_INSTALL_ID: "inst_abcdef123456",
  SELFHOST_TELEMETRY_INSTALL_KEY: KEY,
  SELFHOST_TELEMETRY_ENDPOINT: "https://agentrelay.com/api/v1/selfhost/telemetry",
};

test("level is a single switch; unset means off and needs nothing else", () => {
  const off = loadTelemetryConfig({});
  assert.equal(off.level, "off");
  assert.equal(off.endpoint, null);
  assert.equal(loadTelemetryConfig({ ...base, SELFHOST_TELEMETRY_LEVEL: "errors" }).level, "errors");
  assert.equal(loadTelemetryConfig({ ...base, SELFHOST_TELEMETRY_LEVEL: "FULL" }).level, "full");
  assert.throws(() => loadTelemetryConfig({ SELFHOST_TELEMETRY_LEVEL: "verbose" }), /off, errors, or full/);
  assert.throws(() => loadTelemetryConfig({ SELFHOST_TELEMETRY_LEVEL: "errors" }), /required unless the level is off/);
  assert.throws(
    () => loadTelemetryConfig({ ...base, SELFHOST_TELEMETRY_ENDPOINT: undefined, SELFHOST_TELEMETRY_LEVEL: "full" }),
    /ENDPOINT is required/,
  );
  // Air-gapped: file transport needs no endpoint.
  const airgapped = loadTelemetryConfig({ ...base, SELFHOST_TELEMETRY_ENDPOINT: undefined, SELFHOST_TELEMETRY_LEVEL: "full", SELFHOST_TELEMETRY_TRANSPORT: "file" });
  assert.equal(airgapped.transport, "file");
});

test("endpoint must be https except loopback; key must be long and paired", () => {
  assert.throws(() => loadTelemetryConfig({ ...base, SELFHOST_TELEMETRY_ENDPOINT: "http://ingest.example.com/x" }), /https/);
  assert.equal(
    loadTelemetryConfig({ ...base, SELFHOST_TELEMETRY_ENDPOINT: "http://127.0.0.1:9999/ingest" }).endpoint,
    "http://127.0.0.1:9999/ingest",
  );
  assert.throws(() => loadTelemetryConfig({ ...base, SELFHOST_TELEMETRY_INSTALL_KEY: "short" }), /32 bytes/);
  assert.throws(() => loadTelemetryConfig({ SELFHOST_TELEMETRY_INSTALL_ID: "inst_abcdef123456" }), /together/);
  assert.throws(() => loadTelemetryConfig({ ...base, SELFHOST_TELEMETRY_INSTALL_ID: "acme" }), /inst_/);
});

test("probes and deployment shape are validated and allowlisted", () => {
  assert.throws(() => parseProbes("Bulls=http://alleyoop:8080/readyz"), /lowercase name/);
  assert.throws(() => parseProbes("x=http://user:pw@alleyoop:8080/readyz"), /credentials/);
  assert.throws(() => parseProbes("a=http://a/h,a=http://b/h"), /duplicate/);
  assert.deepEqual(parseProbes("96bulls=http://alleyoop:8080/readyz, relayfile=http://relayfile:8080/health,"), [
    { name: "96bulls", url: "http://alleyoop:8080/readyz" },
    { name: "relayfile", url: "http://relayfile:8080/health" },
  ]);
  assert.deepEqual(sanitizeDeploymentShape({
    chartVersion: "0.4.1",
    relaycast: { replicas: 2, backend: "durable-actors", version: "8.5.2" },
    storage: "gcs",
    databaseUrl: "postgres://user:pw@db/x",
    note: "free text with spaces",
    tooDeep: { a: { b: { c: { d: 1 } } } },
  }), {
    chartVersion: "0.4.1",
    relaycast: { replicas: 2, backend: "durable-actors", version: "8.5.2" },
    storage: "gcs",
  });
});

test("signatures: round trip, tamper, wrong key, export envelope", () => {
  const body = JSON.stringify({ kind: "digest", reportId: "r1" });
  const header = signBody(KEY, body, 1_700_000_000);
  assert.match(header, /^t=1700000000,v1=[a-f0-9]{64}$/);
  assert.deepEqual(parseSignature(header)?.timestamp, 1_700_000_000);
  assert.equal(verifySignature(KEY, body, header), true);
  assert.equal(verifySignature(KEY, body.replace("r1", "r2"), header), false);
  assert.equal(verifySignature("x".repeat(40), body, header), false);
  assert.equal(verifySignature(KEY, body, header.replace("t=1700000000", "t=1700000001")), false);
  assert.equal(verifySignature(KEY, body, "garbage"), false);
  const envelope = exportEnvelope("inst_abcdef123456", KEY, body, 1_700_000_000_000);
  assert.equal(envelope.format, "agent-relay-telemetry-export/v1");
  assert.equal(verifySignature(KEY, envelope.body, envelope.signature), true);
});

test("identifiers are salted hashes; routes become templates", () => {
  const a = hashIdentifier("salt-a", "3f2c3a4e-1111-4222-8333-944445555666");
  assert.match(a, /^h_[a-f0-9]{20}$/);
  assert.equal(a, hashIdentifier("salt-a", "3f2c3a4e-1111-4222-8333-944445555666"));
  assert.notEqual(a, hashIdentifier("salt-b", "3f2c3a4e-1111-4222-8333-944445555666"));
  assert.equal(routeTemplate("/api/v1/workspaces/3f2c3a4e-1111-4222-8333-944445555666/sessions/abc123/events?source=x"),
    "/api/v1/workspaces/:id/sessions/:id/events");
  assert.equal(routeTemplate("/cloud/api/v1/organizations/acme/memberships/u1"), "/cloud/api/v1/organizations/:id/memberships/:id");
  assert.equal(routeTemplate("/api/v1/workspaces/default/runtime"), "/api/v1/workspaces/:id/runtime");
  assert.equal(routeTemplate("/v1/files/jane.doe@corp.example/secret.txt"), "/v1/files/:id/:id");
});

test("error fingerprints ignore messages, paths and line numbers", () => {
  const make = (message: string, dir: string, line: number) => {
    const error = new TypeError(message);
    error.stack = `TypeError: ${message}\n    at readSessions (${dir}/dist/relayhistory.js:${line}:9)\n    at handle (${dir}/dist/app.js:${line + 10}:3)\n    at node:internal/process/task_queues:95:5`;
    return error;
  };
  const one = describeError(make("user alice@x.example missing", "/app/a", 10), { component: "relaycontrol", path: "/api/v1/workspaces/w1/sessions", status: 500 });
  const two = describeError(make("user bob missing", "/srv/b", 99), { component: "relaycontrol", path: "/api/v1/workspaces/w2/sessions", status: 500 });
  assert.equal(one.fingerprint, two.fingerprint);
  assert.equal(one.errorClass, "TypeError");
  assert.equal(one.route, "/api/v1/workspaces/:id/sessions");
  assert.ok(!JSON.stringify(one).includes("alice"));
  assert.notEqual(one.fingerprint, errorFingerprint({ component: "relayhistory", errorClass: "TypeError", stack: make("m", "/a", 1).stack }));
  const coded = Object.assign(new Error("connect ECONNREFUSED 10.0.0.4:5432"), { code: "ECONNREFUSED" });
  assert.equal(describeError(coded, { component: "relaycontrol", path: "/x", status: 500 }).errorClass, "Error:ECONNREFUSED");
});

test("aggregator counts, detects a burst once, drains and restores", () => {
  const aggregator = new TelemetryAggregator({ burstThreshold: 3, burstWindowSeconds: 60 });
  const observed = { component: "relayhistory", route: "/api/v1/workspaces/:id/sessions", status: 502, errorClass: "UpstreamError", fingerprint: "fp_1" };
  const t0 = 1_700_000_000_000;
  assert.equal(aggregator.error(observed, t0), false);
  assert.equal(aggregator.error(observed, t0 + 1000), false);
  assert.equal(aggregator.error(observed, t0 + 2000), true);
  assert.equal(aggregator.error(observed, t0 + 3000), false);
  // Outside the window the count restarts.
  assert.equal(aggregator.error(observed, t0 + 200_000), false);
  aggregator.count("req:sessions", "total", 2);
  aggregator.count("req:sessions", "total");
  const drained = aggregator.drain();
  assert.deepEqual(drained.counters, [{ area: "req:sessions", metric: "total", value: 3 }]);
  assert.equal(drained.errors[0]?.count, 5);
  assert.deepEqual(aggregator.drain(), { counters: [], errors: [] });
  aggregator.restore(drained);
  assert.equal(aggregator.drain().errors[0]?.count, 5);
});

test("feature areas", () => {
  assert.equal(featureArea("/cloud/api/v1/workspaces/w/sessions"), "sessions");
  assert.equal(featureArea("/api/v1/workspaces/w/flows/x/runs"), "flows");
  assert.equal(featureArea("/api/v1/auth/device/token"), "device-login");
  assert.equal(featureArea("/login/poll"), "login");
  assert.equal(featureArea("/internal/v1/workspaces/w/environment"), "internal");
  assert.equal(featureArea("/api/v1/workspaces/w/relayhistory/session"), "history");
});

test("backoff grows exponentially with jitter and caps at 6h", () => {
  assert.equal(backoffSeconds(0, () => 0.5), 30);
  assert.equal(backoffSeconds(3, () => 0.5), 240);
  assert.equal(backoffSeconds(30, () => 0.5), 21_600);
  assert.ok(backoffSeconds(5, () => 0) >= 30);
});

test("issue reports validate input and keep only known support-bundle documents", () => {
  assert.throws(() => parseIssue({ summary: "x" }), /title is required/);
  assert.throws(() => parseIssue({ title: "x", summary: "y", severity: "urgent" }), /severity/);
  assert.throws(() => parseIssue({ title: "x", summary: "y", component: "Relay History" }), /component/);
  const issue = parseIssue({ title: "History 5xx", summary: "since 03:10", component: "relayhistory", dryRun: true });
  assert.equal(issue.severity, "medium");
  assert.equal(issue.dryRun, true);
  const bundle = sanitizeSupportBundle({
    manifest: { schemaVersion: 1, readOnly: true, release: "acme-prod", kubernetesSecretsCollected: false },
    documents: {
      "versions.json": { relaycast: "8.5.2" },
      "raw-logs.txt": "everything",
      "workload-status.json": { blob: "x".repeat(70 * 1024) },
    },
  });
  assert.deepEqual(bundle, {
    manifest: { schemaVersion: 1, readOnly: true, kubernetesSecretsCollected: false },
    documents: { "versions.json": { relaycast: "8.5.2" } },
    omittedForSize: ["workload-status.json"],
    ignoredDocuments: 1,
  });
});
