import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import type { Database, SqlExecutor, SqlResult } from "../src/database.js";
import { defaultFlowsConfig } from "../src/flows/config.js";
import { FlowRunRelayfileCredentials } from "../src/flows/relayfile-credentials.js";
import { FlowsStore } from "../src/flows/store.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";
import { testFeatures } from "./support/features.js";

const FILES = "https://files.selfhosted.test";
const SECRET = "fixture-introspection-secret-at-least-32-bytes";
const WORKFLOW = "version: '0.1.0'\nname: credential-lifecycle\nsteps: []\n";

function barrier() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => { release = resolve; });
  return { promise, release };
}

async function waitForEntry(entered: Promise<void>, work: Promise<unknown>): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      entered,
      work.then(() => { throw new Error("fixture-work-ended-before-pause"); }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("fixture-pause-timeout")), 5000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** Fault/pause injection around actual PGlite transactions, not fake SQL results. */
class ObservedDatabase implements Database {
  before?: (sql: string) => void | Promise<void>;
  after?: (sql: string) => void | Promise<void>;
  constructor(readonly inner: PGliteDatabase) {}
  query<T extends Record<string, unknown>>(sql: string, params?: unknown[]): Promise<SqlResult<T>> {
    return this.inner.query<T>(sql, params);
  }
  exec(sql: string): Promise<void> { return this.inner.exec(sql); }
  close(): Promise<void> { return this.inner.close(); }
  transaction<T>(run: (tx: SqlExecutor) => Promise<T>): Promise<T> {
    return this.inner.transaction((tx) => run({
      query: async <R extends Record<string, unknown>>(sql: string, params?: unknown[]) => {
        await this.before?.(sql);
        const result = await tx.query<R>(sql, params);
        await this.after?.(sql);
        return result;
      },
      exec: (sql) => tx.exec(sql),
    }));
  }
}

async function setup(t: TestContext) {
  const database = new ObservedDatabase(new PGliteDatabase());
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused", publicBaseUrl: "https://control.selfhosted.test",
    relaycastUrl: "http://relaycast.internal", relaycastPublicUrl: "https://relay.selfhosted.test",
    relayhistoryUrl: "http://history.internal", relayhistoryPublicUrl: "https://history.selfhosted.test",
    sessionReadApi: { url: "http://history.internal", publicUrl: "https://history.selfhosted.test", secret: "fixture-session-secret-".repeat(2) },
    bootstrapToken: "fixture-bootstrap-secret-".repeat(2),
    encryptionKeyring: { active: { id: "test", key: Buffer.alloc(32, 7) } },
    introspectSecret: SECRET, introspectAudiences: [FILES], internalServiceToken: null,
    port: 3000, host: "127.0.0.1", oauthRedirectUrl: "https://control.selfhosted.test/callback",
    dashboardUrl: "https://control.selfhosted.test",
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const organization = await store.createOrganization({ name: "Fixture", ownerEmail: "owner@example.test", ownerName: "Owner" });
  const workspace = await store.createWorkspace({ organizationId: organization.id, name: "Primary", relaycastApiKey: "fixture-primary" });
  const other = await store.createWorkspace({ organizationId: organization.id, name: "Other", relaycastApiKey: "fixture-other" });
  const flows = new FlowsStore(database, config.encryptionKeyring, defaultFlowsConfig({ workerRelayfileUrl: FILES }), config.relaycastPublicUrl);
  const credentials = new FlowRunRelayfileCredentials(database, () => new Date(), {
    ttlMs: 60 * 60 * 1000, workerRelayfileUrl: FILES, audiences: () => [FILES],
  });
  flows.relayfileCredentials = credentials;
  const server = createServer(createApp({ config, store, flows, flowRelayfileCredentials: credentials, features: testFeatures("flows") }));
  const origin = await listen(server);
  t.after(async () => { await close(server); await database.close(); });
  const enrollment = await flows.createEnrollmentToken({ workspaceId: workspace.id, userId: organization.owner.id, name: "fixture-worker", tags: ["main"] });
  const registered = await flows.registerWorker({ enrollmentToken: enrollment.token, name: "fixture-worker" });
  const worker = await flows.authenticateWorker(registered.workerId, registered.workerToken);
  assert(worker);
  const newRun = (workspaceId = workspace.id, tags = ["main"]) => flows.createRun({ workspaceId, userId: null, workflow: WORKFLOW, fileType: "yaml", tags });
  const issue = (runId: string, workspaceId = workspace.id) => credentials.issueForLocalRun({ workspaceId, runId, mountPaths: [`/workflows/runs/${runId}`] });
  const verdict = async (token: string) => {
    const response = await request(origin, "/internal/v1/auth/introspect", { method: "POST", token: SECRET, body: { token, aud: FILES } });
    assert.equal(response.status, 200);
    return response.body;
  };
  return { database, flows, credentials, workspace, other, worker, newRun, issue, verdict };
}

for (const terminal of ["completed", "failed", "cancelled"] as const) {
  test(`local ${terminal} transition revokes the assignment credential and preserves other runs`, async (t) => {
    const env = await setup(t);
    const { run } = await env.newRun();
    const sibling = await env.newRun(env.workspace.id, ["other"]);
    const foreign = await env.newRun(env.other.id, ["other"]);
    const siblingCredential = await env.issue(sibling.run.runId);
    const foreignCredential = await env.issue(foreign.run.runId, env.other.id);
    const assignment = await env.flows.claimNext(env.worker);
    assert(assignment);
    assert.equal(assignment.runId, run.runId);
    const payload = JSON.parse(assignment.workflowRef.value);
    assert.equal((await env.verdict(payload.relayfileToken)).active, true);
    await env.flows.ackAssignment(env.worker.id, run.runId);
    if (terminal === "cancelled") await env.flows.cancelRun(env.workspace.id, run.runId);
    else await env.flows.reportStatus(env.worker.id, run.runId, { phase: terminal });
    assert.deepEqual(await env.verdict(payload.relayfileToken), { active: false, reason: "revoked" });
    assert.equal((await env.flows.getRun(env.workspace.id, run.runId))?.status, terminal);
    await assert.rejects(env.issue(run.runId), { code: "run_not_active" });
    if (terminal === "cancelled") await assert.rejects(env.flows.cancelRun(env.workspace.id, run.runId), { code: "run_already_terminal" });
    else await env.flows.reportStatus(env.worker.id, run.runId, { phase: terminal });
    assert.deepEqual(await env.verdict(payload.relayfileToken), { active: false, reason: "revoked" });
    assert.equal((await env.verdict(siblingCredential.relayfileToken)).active, true);
    assert.equal((await env.verdict(foreignCredential.relayfileToken)).active, true);
  });
}

test("local issuance refuses missing or foreign runs without revoking a valid credential", async (t) => {
  const env = await setup(t);
  const { run } = await env.newRun();
  const issued = await env.issue(run.runId);
  await assert.rejects(env.issue(run.runId, env.other.id), { code: "run_not_found" });
  await assert.rejects(env.issue(randomUUID()), { code: "run_not_found" });
  assert.equal((await env.verdict(issued.relayfileToken)).active, true);
  const external = randomUUID();
  const brokerCredential = await env.credentials.issue({ workspaceId: env.workspace.id, runId: external, mountPaths: [`/workflows/runs/${external}`] });
  assert.equal((await env.verdict(brokerCredential.relayfileToken)).active, true, "broker runs need no local workflow row");
});

test("finishing a local run preserves an external credential with the same run id in another workspace", async (t) => {
  const env = await setup(t);
  const { run } = await env.newRun();
  const assignment = await env.flows.claimNext(env.worker);
  assert(assignment);
  const localToken = JSON.parse(assignment.workflowRef.value).relayfileToken;
  // The existing external issuer rotates the prior credential globally by
  // run id. Its active-row uniqueness still permits this foreign credential
  // while the local workflow_runs row belongs to the original workspace.
  const foreign = await env.credentials.issue({
    workspaceId: env.other.id, runId: run.runId, mountPaths: [`/workflows/runs/${run.runId}`],
  });
  assert.deepEqual(await env.verdict(localToken), { active: false, reason: "revoked" });
  assert.equal((await env.verdict(foreign.relayfileToken)).workspace, env.other.id);
  await env.flows.reportStatus(env.worker.id, run.runId, { phase: "completed" });
  assert.equal((await env.verdict(foreign.relayfileToken)).active, true);
  await env.flows.reportStatus(env.worker.id, run.runId, { phase: "completed" });
  assert.equal((await env.verdict(foreign.relayfileToken)).active, true);
  await assert.rejects(env.issue(run.runId), { code: "run_not_active" });
});

test("terminal before delayed assignment mint produces no credential", async (t) => {
  const env = await setup(t);
  const { run } = await env.newRun();
  const entered = barrier();
  const resume = barrier();
  env.flows.relayfileCredentials = {
    issue: (input) => env.credentials.issue(input),
    issueForLocalRun: async (input) => {
      entered.release();
      await resume.promise;
      return env.credentials.issueForLocalRun(input);
    },
  };
  const pending = env.flows.claimNext(env.worker);
  try {
    await waitForEntry(entered.promise, pending);
    await env.flows.cancelRun(env.workspace.id, run.runId);
    resume.release();
    const assignment = await pending;
    assert(assignment);
    assert.equal(Object.hasOwn(JSON.parse(assignment.workflowRef.value), "relayfileToken"), false);
    const rows = await env.database.query("SELECT id FROM flow_run_relayfile_credentials WHERE run_id = $1", [run.runId]);
    assert.equal(rows.rows.length, 0);
  } finally {
    resume.release();
    await Promise.allSettled([pending]);
  }
});

test("mint transaction before cancellation cannot leave an active credential", async (t) => {
  const env = await setup(t);
  const { run } = await env.newRun();
  const entered = barrier();
  const resume = barrier();
  env.database.after = async (sql) => {
    if (sql.includes("SELECT status FROM workflow_runs")) {
      assert.match(sql, /FOR UPDATE\s*$/);
      entered.release();
      await resume.promise;
    }
  };
  const pending = env.flows.claimNext(env.worker);
  let cancelled: ReturnType<FlowsStore["cancelRun"]> | undefined;
  try {
    await waitForEntry(entered.promise, pending);
    cancelled = env.flows.cancelRun(env.workspace.id, run.runId);
    resume.release();
    const assignment = await pending;
    assert(assignment);
    await cancelled;
    assert.deepEqual(await env.verdict(JSON.parse(assignment.workflowRef.value).relayfileToken), { active: false, reason: "revoked" });
  } finally {
    resume.release();
    await Promise.allSettled([pending, cancelled]);
  }
  // PGlite serializes its transactions. Native multi-connection PostgreSQL
  // row-lock timing remains a separate PG17 qualification requirement.
});

test("credential revocation failure rolls back the terminal transition and assignment", async (t) => {
  const env = await setup(t);
  const { run } = await env.newRun();
  const assignment = await env.flows.claimNext(env.worker);
  assert(assignment);
  const token = JSON.parse(assignment.workflowRef.value).relayfileToken;
  env.database.before = (sql) => {
    if (sql.startsWith("UPDATE flow_run_relayfile_credentials")) throw new Error("fixture-revoke-failure");
  };
  await assert.rejects(env.flows.reportStatus(env.worker.id, run.runId, { phase: "completed" }), /fixture-revoke-failure/);
  env.database.before = undefined;
  assert.equal((await env.flows.getRun(env.workspace.id, run.runId))?.status, "pending");
  const state = await env.database.query<{ status: string }>("SELECT status FROM work_assignments WHERE run_id = $1", [run.runId]);
  assert.equal(state.rows[0]?.status, "assigned");
  assert.equal((await env.verdict(token)).active, true);
});
