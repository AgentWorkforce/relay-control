import assert from "node:assert/strict";
import test from "node:test";
import { parseFactoryJob } from "../src/factory/routes.js";
import { bindingHash } from "../src/factory/service.js";
import {
  assertNoSecrets,
  connectAndBind,
  deliveryRows,
  INTERNAL,
  jobPath,
  queueRelayMessage,
  startFactoryEnv,
  type FactoryEnv,
} from "./factory-helpers.js";

const ABSENT = "00000000-0000-4000-8000-000000000000";
const job = (env: FactoryEnv, body: unknown, token = INTERNAL) =>
  env.api(jobPath, { method: "POST", token, body });

test("factory internal job route is the generic 404 when the flag is off, without an internal token, and under /cloud", async (t) => {
  const unknown = { error: "not_found", message: "Route not found" };
  const off = await startFactoryEnv(t, { enabled: false });
  const offResponse = await job(off, { v: 1, kind: "sweep" });
  assert.equal(offResponse.status, 404);
  assert.deepEqual(offResponse.body, unknown);
  const tokenless = await startFactoryEnv(t, { internalToken: null });
  assert.equal((await job(tokenless, { v: 1, kind: "sweep" })).status, 404);
  assert.equal((await job(tokenless, { v: 1, kind: "sweep" }, "")).status, 404);
  const on = await startFactoryEnv(t);
  const viaCloud = await on.api(`/cloud${jobPath}`, { method: "POST", token: INTERNAL, body: { v: 1, kind: "sweep" } });
  assert.equal(viaCloud.status, 404);
  // The same request on the raw path reaches the job.
  assert.equal((await job(on, { v: 1, kind: "sweep" })).status, 200);
});

test("factory internal job route refuses missing, wrong and user credentials, other methods and malformed envelopes", async (t) => {
  const env = await startFactoryEnv(t);
  const missing = await job(env, { v: 1, kind: "sweep" }, "");
  assert.deepEqual([missing.status, missing.body.error], [401, "unauthorized"]);
  const wrong = await job(env, { v: 1, kind: "sweep" }, `${INTERNAL}x`);
  assert.deepEqual([wrong.status, wrong.body.error], [403, "forbidden"]);
  const user = await job(env, { v: 1, kind: "sweep" }, env.ownerToken);
  assert.deepEqual([user.status, user.body.error], [403, "forbidden"]);
  const get = await env.api(jobPath, { token: INTERNAL });
  assert.deepEqual([get.status, get.body.error], [405, "method_not_allowed"]);
  for (const body of [
    { v: 1, kind: "export" },
    { v: 2, kind: "sweep" },
    { v: 1, kind: "inject", bindingId: "not-a-uuid", messageId: "m-1" },
    { v: 1, kind: "inject", bindingId: ABSENT, messageId: "bad id!" },
    { v: 1, kind: "history", bindingId: ABSENT, extra: true },
    { v: 1, kind: "sweep", after: "nope" },
    [],
  ]) {
    const refused = await job(env, body);
    assert.equal(refused.status, 400, JSON.stringify(body));
    assert.deepEqual(Object.keys(refused.body).sort(), ["error", "message"]);
    assert.equal(refused.body.error, "invalid_request");
  }
  const malformed = await env.api(jobPath, { method: "POST", token: INTERNAL, headers: { "content-type": "application/json" }, raw: "{" });
  assert.equal(malformed.status, 400);
  const huge = await env.api(jobPath, { method: "POST", token: INTERNAL, body: { v: 1, kind: "sweep", pad: "x".repeat(5000) } });
  assert.equal(huge.status, 400);
  assert.equal(env.logs.filter((entry) => entry.event === "factory.job").length, 0, "refused jobs never run");
  assert.equal(parseFactoryJob({ v: 1, kind: "history", bindingId: ABSENT, scheduledAt: "2026-11-08T00:00:00Z" })?.kind, "history");
});

test("factory internal inject job: authorized no-op for an absent delivery, sends one due row, leaves settled and leased rows alone", async (t) => {
  const env = await startFactoryEnv(t);
  const absent = await job(env, { v: 1, kind: "inject", bindingId: ABSENT, messageId: "m-1" });
  assert.equal(absent.status, 200);
  assert.deepEqual(absent.body, { ok: true, skipped: true });
  assert.equal(env.factory.posts, 0);

  const bound = await connectAndBind(env);
  for (const id of ["due", "settled", "leased", "expired"]) queueRelayMessage(env.relay, bound.agent.name, { id, text: `text ${id}` });
  assert.equal(await env.module.worker.pollInbox(), 4);
  const set = (id: string, sql: string) =>
    env.database.query(`UPDATE selfhost_factory_deliveries SET ${sql} WHERE message_id = $1`, [id]);
  await set("settled", "state = 'unknown', code = 'factory_http_500', payload_envelope = NULL");
  await set("leased", "state = 'sending', lease_owner = gen_random_uuid(), lease_until = now() + interval '5 minutes'");
  await set("expired", "state = 'sending', lease_owner = gen_random_uuid(), lease_until = now() - interval '1 second'");

  const kick = (messageId: string) => job(env, { v: 1, kind: "inject", bindingId: bound.binding_id, messageId });
  assert.deepEqual((await kick("due")).body, { ok: true, state: "delivered" });
  assert.deepEqual((await kick("due")).body, { ok: true, state: "delivered" });
  assert.deepEqual((await kick("settled")).body, { ok: true, state: "unknown" });
  assert.deepEqual((await kick("leased")).body, { ok: true, state: "sending" });
  assert.deepEqual((await kick("expired")).body, { ok: true, state: "unknown" });
  assert.equal(env.factory.posts, 1, "only the due row was sent, once");
  assert.deepEqual(env.factory.injected.map((entry) => entry.text.includes("text due")), [true]);
  const codes = Object.fromEntries((await deliveryRows(env, bound.binding_id)).map((row) => [row.message_id, [row.state, row.code]]));
  assert.deepEqual(codes.expired, ["unknown", "lease_expired"]);

  const lines = env.logs.filter((entry) => entry.event === "factory.job");
  assert.deepEqual(lines.at(-1), { event: "factory.job", kind: "inject", bindingHash: bindingHash(bound.binding_id), outcome: "ok" });
  assert.ok(lines.every((entry) => !JSON.stringify(entry).includes(bound.binding_id)), "the binding id is hashed in logs");
  assertNoSecrets(env, env.logs);
});

test("factory internal sweep and history jobs: sweep expires leases and advances dormant history; history is deferred", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await connectAndBind(env);
  queueRelayMessage(env.relay, bound.agent.name, { id: "m-1", text: "hello" });
  await env.module.worker.pollInbox();
  await env.database.query(
    "UPDATE selfhost_factory_deliveries SET state = 'sending', lease_owner = gen_random_uuid(), lease_until = now() - interval '1 second'",
  );
  const scheduled = await env.api(`/api/v1/workspaces/${env.workspaceId}/factory/bindings/${bound.binding_id}/history/schedule`, { method: "POST", token: env.ownerToken });
  assert.equal(scheduled.status, 202);
  await env.database.query("UPDATE selfhost_factory_history_syncs SET next_due_at = now() - interval '1 second'");

  const sweep = await job(env, { v: 1, kind: "sweep" });
  assert.deepEqual(sweep.body, { ok: true, expired: 1, scheduled: 1 });
  assert.equal((await deliveryRows(env, bound.binding_id))[0]!.state, "unknown");
  const history = await env.database.query<{ due: boolean }>("SELECT next_due_at > now() AS due FROM selfhost_factory_history_syncs");
  assert.deepEqual(history.rows, [{ due: true }]);
  assert.equal(env.factory.posts, 0);

  const deferred = await job(env, { v: 1, kind: "history", bindingId: bound.binding_id });
  assert.deepEqual(deferred.body, { ok: true, deferred: true });
  assert.deepEqual(env.logs.filter((entry) => entry.event === "factory.job").map((entry) => [entry.kind, entry.outcome]), [["sweep", "ok"], ["history", "ok"]]);
});
