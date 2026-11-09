import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { batch, installEvent, post, readSegments, tempDir, type Envelope } from "./support/collector.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DEPLOYMENT = "synthetic-install";
const PRODUCERS = ["relaycontrol", "session-ingest", "session-read-api", "session-pipeline-consumer"];
const token = (component: string): string => `synthetic-${component}-token-0123456789abcdef`;

// Wire fixtures from the pipeline's typed projector contract. These are real
// HTTP inputs to the production collector CLI, not an injected test registry.
function event(component: string, kind: string, properties: Record<string, unknown>, workspace = true): Envelope {
  return installEvent({
    component, event: kind, deployment_id: DEPLOYMENT, properties,
    ...(workspace ? { tenant_id: "synthetic-org", workspace_id: "synthetic-workspace" } : {}),
  });
}
const ingest = () => event("session-ingest", "session_ingest.batch_completed", {
  route: "delivery", outcome: "accepted", record_count: 2, latency_bucket: "lt_100ms",
});
const read = () => event("session-read-api", "session_read.request_completed", {
  route: "/v1/sessions/:sessionId/events", outcome: "served", status_class: "2xx", latency_bucket: "lt_500ms",
});
const consumer = () => event("session-pipeline-consumer", "session_pipeline.index_tick_completed", {
  collected: 2, failed: 0, requeued: 0, stale: 0, tombstoned: 0, complete: true, latency_bucket: "lt_1s",
}, false);

test("collector CLI persists each session producer and refuses foreign authority, scope and unregistered data", { timeout: 20_000 }, async (t) => {
  const dir = await tempDir(t);
  const dataDir = join(dir, "data");
  await mkdir(dataDir);
  const registrations = [];
  for (const component of PRODUCERS) {
    const file = join(dir, `${component}.token`);
    await writeFile(file, token(component), { mode: 0o600 });
    registrations.push({ name: component, component, deployment_id: DEPLOYMENT, token_file: file });
  }
  const producersFile = join(dir, "producers.json");
  await writeFile(producersFile, JSON.stringify(registrations));
  const child = spawn(process.execPath, ["--import", "tsx", "src/collector-cli.ts"], {
    cwd: ROOT,
    env: {
      PATH: process.env.PATH,
      ANALYTICS_COLLECTOR_HOST: "127.0.0.1", ANALYTICS_COLLECTOR_PORT: "0",
      ANALYTICS_COLLECTOR_DATA_DIR: dataDir, ANALYTICS_COLLECTOR_PRODUCERS_FILE: producersFile,
      ANALYTICS_COLLECTOR_SHUTDOWN_DEADLINE_MS: "2000",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(() => { if (child.exitCode === null) child.kill("SIGKILL"); });
  let output = "";
  child.stderr.on("data", (chunk) => output += chunk);
  const exited = new Promise<number | null>((resolve) => child.once("exit", resolve));
  const port = await new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("collector did not start within deadline")), 10_000);
    timer.unref();
    child.stdout.on("data", (chunk) => {
      output += chunk;
      const match = /listening[\s\S]*port: (\d+)/.exec(output);
      if (match) { clearTimeout(timer); resolve(Number(match[1])); }
    });
    void exited.then(() => { clearTimeout(timer); reject(new Error(`collector exited early: ${output}`)); });
  });
  const origin = `http://127.0.0.1:${port}`;
  const send = (e: Envelope, auth = String(e.component)) => post(origin, batch([e]), { token: token(auth) });
  const accepted = [
    installEvent({ deployment_id: DEPLOYMENT }), ingest(), read(), consumer(),
  ];
  for (const e of accepted) assert.equal((await send(e)).status, 204);
  const recorded = (await readSegments(dataDir)).flatMap((segment) => segment.events);
  assert.equal(recorded.length, 4);
  for (const e of accepted) assert.deepEqual(recorded.find((row) => row.event_id === e.event_id), e);

  assert.equal((await send(read(), "session-ingest")).status, 403);
  assert.equal((await send({ ...ingest(), deployment_id: "another-install" })).status, 403);
  assert.equal((await post(origin, batch([ingest()]), {})).status, 401);

  const properties = (e: Envelope, changes: Record<string, unknown>): Envelope => ({
    ...e, properties: { ...(e.properties as Record<string, unknown>), ...changes },
  });
  const missingTenant = ingest();
  delete missingTenant.tenant_id;
  const missingWorkspace = read();
  delete missingWorkspace.workspace_id;
  const invalid = [
    missingTenant, missingWorkspace,
    { ...consumer(), tenant_id: "synthetic-org" },
    { ...consumer(), workspace_id: "synthetic-workspace" },
    { ...ingest(), event: "service_started" },
    { ...read(), event: "session_ingest.batch_completed" },
    { ...consumer(), event: "session_read.request_completed" },
    { ...ingest(), component: "relaycontrol" },
    properties(ingest(), { record_count: -1 }),
    properties(ingest(), { record_count: 1.5 }),
    properties(ingest(), { record_count: 1_000_001 }),
    properties(ingest(), { route: "/PLANTED/private/path" }),
    properties(ingest(), { outcome: "PLANTED-error-message" }),
    properties(read(), { route: "/v1/sessions/PLANTED/events" }),
    properties(read(), { route: "/v1/events?q=PLANTED" }),
    properties(read(), { status_class: "200" }),
    properties(read(), { latency_bucket: "PLANTED-latency" }),
    properties(read(), { duration_ms: 123 }),
    properties(consumer(), { complete: "true" }),
    properties(consumer(), { failed: 1_000_001 }),
    properties(ingest(), { content: "PLANTED-session-content" }),
    properties(read(), { session_id: "PLANTED-session-id" }),
    properties(consumer(), { token: "PLANTED-secret" }),
  ];
  for (const e of invalid) {
    const answer = await send(e);
    assert.equal(answer.status, 400, JSON.stringify(e));
    assert.ok(!answer.raw.includes("PLANTED"));
  }
  // A malformed event rejects the entire batch before even a valid line writes.
  assert.equal((await post(origin, batch([ingest(), invalid[0]]), { token: token("session-ingest") })).status, 400);
  assert.equal((await readSegments(dataDir)).flatMap((segment) => segment.events).length, 4);

  const boundary = properties(ingest(), { record_count: 1_000_000 });
  assert.equal((await send(boundary)).status, 204);
  assert.equal((await send(properties(consumer(), { collected: 0 }))).status, 204);
  child.kill("SIGTERM");
  assert.equal(await exited, 0);
  assert.equal((await readSegments(dataDir)).flatMap((segment) => segment.events).length, 6);
  for (const component of PRODUCERS) assert.ok(!output.includes(token(component)));
  assert.ok(!output.includes("PLANTED"));
});
