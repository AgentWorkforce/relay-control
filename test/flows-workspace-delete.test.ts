import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { flowsDeleteBackoffMs, FlowsWorkspaceDeletions, type FlowsDeleteEvent } from "../src/flows-workspace-delete.js";
import { BOOTSTRAP, seedTenant, startControlPlane } from "./flows-helpers.js";

const secret = "flows-workspace-delete-secret-32-bytes-plus";
const endpoint = { url: "http://relayfile-control.flows.svc.cluster.local", secret };

const complete = {
  DATABASE_URL: "postgres://control:secret@postgres/control",
  SELFHOST_PUBLIC_URL: "https://control.internal.example",
  RELAYCAST_URL: "http://relaycast.relay.svc.cluster.local",
  RELAYCAST_PUBLIC_URL: "https://relaycast.selfhosted.company",
  RELAYHISTORY_BACKEND: "native",
  SESSION_READ_API_URL: "http://session-read.history.svc.cluster.local",
  SESSION_READ_API_PUBLIC_URL: "https://sessions.selfhosted.company",
  SESSION_READ_API_SECRET: "r".repeat(32),
  RELAYCONTROL_INTROSPECT_SECRET: "i".repeat(32),
  SELFHOST_BOOTSTRAP_TOKEN: "b".repeat(32),
  SELFHOST_ENCRYPTION_KEY_ID: "test-key",
  SELFHOST_ENCRYPTION_KEY: "00".repeat(32),
};

test("the hand-off is optional, needs both values, and its own secret", () => {
  assert.equal(loadConfig(complete).flowsWorkspaceDelete, null);
  const on = { ...complete, RELAYFILE_CONTROL_URL: endpoint.url, RELAYFILE_CONTROL_WORKSPACE_DELETE_SECRET: secret };
  assert.deepEqual(loadConfig(on).flowsWorkspaceDelete, endpoint);
  assert.throws(() => loadConfig({ ...complete, RELAYFILE_CONTROL_URL: endpoint.url }), /is required with RELAYFILE_CONTROL_URL/);
  assert.throws(() => loadConfig({ ...complete, RELAYFILE_CONTROL_WORKSPACE_DELETE_SECRET: secret }), /RELAYFILE_CONTROL_URL is required/);
  assert.throws(() => loadConfig({ ...on, RELAYFILE_CONTROL_WORKSPACE_DELETE_SECRET: "short" }), /at least 32 bytes/);
  for (const name of ["RELAYFILE_CONTROL_BROKER_SECRET", "RELAYCHIEF_CONTROL_RELAY_SECRET", "RELAYCONTROL_INTROSPECT_SECRET"]) {
    assert.throws(() => loadConfig({ ...on, [name]: secret }), /dedicated credential/, name);
  }
  assert.throws(() => loadConfig({ ...on, RELAYFILE_CONTROL_URL: "relayfile-control" }), /absolute URL/);
});

async function deleteWorkspace(api: Awaited<ReturnType<typeof startControlPlane>>["api"], organizationId: string, workspaceId: string) {
  const answer = await api(`/api/v1/organizations/${organizationId}/workspaces/${workspaceId}`, { method: "DELETE", token: BOOTSTRAP });
  assert.equal(answer.status, 204, answer.raw);
}

test("a workspace delete queues the relayfile-control delete only when configured", async (t) => {
  const off = await startControlPlane();
  t.after(() => off.stop());
  const offTenant = await seedTenant(off.api);
  await deleteWorkspace(off.api, offTenant.organizationId, offTenant.otherWorkspaceId);
  assert.equal((await off.database.query("SELECT * FROM flows_workspace_deletions")).rows.length, 0);

  const on = await startControlPlane({}, undefined, { flowsWorkspaceDelete: endpoint });
  t.after(() => on.stop());
  const tenant = await seedTenant(on.api);
  await deleteWorkspace(on.api, tenant.organizationId, tenant.otherWorkspaceId);
  const rows = (await on.database.query<{ workspace_id: string; organization_id: string; attempts: number }>(
    "SELECT workspace_id, organization_id, attempts FROM flows_workspace_deletions")).rows;
  assert.deepEqual(rows, [{ workspace_id: tenant.otherWorkspaceId, organization_id: tenant.organizationId, attempts: 0 }]);
  // A refused delete (the organization's last workspace) rolls back and owes nothing.
  const last = await on.api(`/api/v1/organizations/${tenant.organizationId}/workspaces/${tenant.workspaceId}`, {
    method: "DELETE", token: tenant.ownerToken,
  });
  assert.equal(last.status, 409);
  assert.equal((await on.database.query("SELECT * FROM flows_workspace_deletions")).rows.length, 1);
});

test("the worker completes on 200 or 404 and keeps every other answer with backoff", async (t) => {
  const c = await startControlPlane({}, undefined, { flowsWorkspaceDelete: endpoint });
  t.after(() => c.stop());
  const ids = ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555"];
  const answers = new Map<string, number | "throw">([[ids[0]!, 200], [ids[1]!, 404], [ids[2]!, 401], [ids[3]!, 503], [ids[4]!, "throw"]]);
  const org = "99999999-9999-4999-8999-999999999999";
  let now = new Date(Date.now() + 60_000);
  for (const id of ids) {
    await c.database.query("INSERT INTO flows_workspace_deletions (workspace_id, organization_id, next_attempt_at) VALUES ($1, $2, $3)",
      [id, org, new Date(now.getTime() - 1000)]);
  }
  const calls: Array<{ url: string; method: string; authorization: string | null }> = [];
  const logs: FlowsDeleteEvent[] = [];
  const worker = new FlowsWorkspaceDeletions({
    database: c.database,
    endpoint,
    now: () => now,
    log: (event) => logs.push(event),
    fetchImpl: async (input, init) => {
      const url = String(input);
      calls.push({ url, method: init?.method ?? "GET", authorization: new Headers(init?.headers).get("authorization") });
      const answer = answers.get(decodeURIComponent(url.split("/").pop()!))!;
      if (answer === "throw") throw new Error("connect ECONNREFUSED private-detail");
      return new Response(JSON.stringify({ error: "x" }), { status: answer });
    },
  });
  t.after(() => worker.stop());

  await worker.tick();
  assert.equal(calls.length, 5);
  for (const call of calls) {
    assert.equal(call.method, "DELETE");
    assert.equal(call.authorization, `Bearer ${secret}`);
    assert.match(call.url, /^http:\/\/relayfile-control\.flows\.svc\.cluster\.local\/internal\/v1\/flows\/workspaces\/[0-9a-f-]{36}$/);
  }
  const left = (await c.database.query<{ workspace_id: string; attempts: number; last_error: string; next_attempt_at: Date }>(
    "SELECT workspace_id, attempts, last_error, next_attempt_at FROM flows_workspace_deletions ORDER BY workspace_id")).rows;
  assert.deepEqual(left.map((row) => [row.workspace_id, row.attempts, row.last_error]),
    [[ids[2], 1, "http_401"], [ids[3], 1, "http_503"], [ids[4], 1, "unreachable"]]);
  for (const row of left) assert.equal(new Date(row.next_attempt_at).getTime(), now.getTime() + flowsDeleteBackoffMs(1));
  // UPDATE ... RETURNING has no order, so compare by workspace.
  const byWorkspace = [...logs].sort((a, b) => a.workspaceId!.localeCompare(b.workspaceId!));
  assert.deepEqual(byWorkspace.map((event) => [event.code, event.status]), [
    ["flows_workspace_delete_refused", 401], ["flows_workspace_delete_deferred", 503], ["flows_workspace_delete_deferred", undefined],
  ]);
  assert.equal(JSON.stringify(logs).includes(secret), false);
  assert.equal(JSON.stringify(logs).includes("private-detail"), false);

  // Not due yet: nothing is sent.
  await worker.tick();
  assert.equal(calls.length, 5);
  // Due again: a recovered relayfile-control completes the row.
  answers.set(ids[3]!, 200);
  now = new Date(now.getTime() + flowsDeleteBackoffMs(1));
  await worker.tick();
  assert.equal(calls.length, 8);
  const after = (await c.database.query<{ workspace_id: string; attempts: number }>(
    "SELECT workspace_id, attempts FROM flows_workspace_deletions ORDER BY workspace_id")).rows;
  assert.deepEqual(after.map((row) => [row.workspace_id, row.attempts]), [[ids[2], 2], [ids[4], 2]]);
});

test("backoff doubles from 30 s and stops at an hour", () => {
  assert.deepEqual([1, 2, 3, 8, 50].map(flowsDeleteBackoffMs), [30_000, 60_000, 120_000, 3_600_000, 3_600_000]);
});
