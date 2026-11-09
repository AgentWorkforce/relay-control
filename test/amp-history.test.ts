import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import {
  AMP_HISTORY_INTERVAL_MS,
  AMP_HISTORY_QUEUE_LEASE_MS,
  claimHistory,
  hash,
  historyPass,
  runHistory,
  scheduleHistory,
  stableJson,
  type HistoryUploader,
  type PushSessionScope,
} from "../src/amp/history.js";
import { ampExport } from "../src/amp/provider.js";
import { startAmpWorker } from "../src/amp/worker.js";
import { AMP_KEY, THREAD, ampPath, connectAndBind, internalJob, startAmp, type AmpHarness } from "./amp-helpers.js";

const ACCESS_TOKEN = "rth_push_session_token_never_logged_0123456789";
const SECRET_TEXT = "confidential thread prose that must never be logged";
const REPLY_BEARER = `amp_reply_${"A".repeat(43)}`;

type Mode = "ok" | "http500" | "partial";

async function historyHarness(t: TestContext) {
  const sessions: PushSessionScope[] = [];
  const uploads: Array<{ token: string; body: any }> = [];
  const state: { mode: Mode } = { mode: "ok" };
  const historyUpload: HistoryUploader = async (session, body) => {
    const parsed = JSON.parse(body);
    uploads.push({ token: session.accessToken, body: parsed });
    if (state.mode === "http500") return { ok: false, status: 500, receipt: null };
    const accepted = state.mode === "partial" ? parsed.records.length - 1 : parsed.records.length;
    return { ok: true, status: 200, receipt: { batchId: parsed.batchId, received: parsed.records.length, accepted } };
  };
  const h = await startAmp(t, {
    pushSession: async (scope) => {
      sessions.push(scope);
      return { baseUrl: "https://history.selfhosted.company", accessToken: ACCESS_TOKEN };
    },
    historyUpload,
  });
  const binding = await connectAndBind(h);
  const thread = h.transport.threads.get(THREAD)!;
  const deps = h.amp!.deps;
  const exports = () => h.transport.calls.filter((call) => call.operation.kind === "export").length;
  const row = async () => (await h.database.query<{
    last_synced_at: Date | null; history_queued_at: Date | null; history_error: string | null;
    history_lease_owner: string | null;
  }>(
    "SELECT last_synced_at, history_queued_at, history_error, history_lease_owner FROM selfhost_amp_bindings WHERE id = $1",
    [binding.binding_id],
  )).rows[0]!;
  const ledger = async () => (await h.database.query<{ versions: Record<string, any>; pending_ciphertext: string | null }>(
    "SELECT versions, pending_ciphertext FROM selfhost_amp_history_syncs WHERE thread_id = $1",
    [THREAD],
  )).rows[0];
  const advance = (ms: number) => {
    h.clock.now = new Date(h.clock.now.getTime() + ms);
  };
  const message = (id: string, content: string, version?: number) => {
    thread.messages.push({
      messageID: id, role: "user", content, createdAt: "2026-11-08T00:00:02.000Z",
      ...(version === undefined ? {} : { messageVersion: version }),
    });
  };
  return { h, binding, thread, deps, sessions, uploads, state, exports, row, ledger, advance, message };
}

const summaryOf = async (h: AmpHarness) => (await h.api(ampPath(h), { token: h.ownerToken })).body;

test("amp history: a full upload advances the watermark and later polls upload only changed records", async (t) => {
  const x = await historyHarness(t);
  x.message("m1", "first", 1);
  x.message("m2", `reply with Authorization: Bearer ${REPLY_BEARER}`, 1);
  const before = x.exports();
  await historyPass(x.deps);
  assert.equal(x.exports(), before + 1);
  assert.equal(x.uploads.length, 1);
  const upload = x.uploads[0]!;
  assert.equal(upload.token, ACCESS_TOKEN);
  assert.deepEqual(upload.body.machine, { id: `amp:${x.h.workspaceId}`, label: "Amp" });
  assert.match(upload.body.batchId, /^amp:[0-9a-f]{48}$/);
  assert.equal(upload.body.records.length, 2);
  assert.equal(JSON.stringify(upload.body).includes(REPLY_BEARER), false, "reply capabilities are scrubbed before upload");
  assert.deepEqual(x.sessions, [{
    userId: x.h.ownerId, organizationId: x.h.organizationId, workspaceId: x.h.workspaceId, bindingId: x.binding.binding_id,
  }]);
  const synced = await x.row();
  assert.equal(new Date(synced.last_synced_at!).toISOString(), x.h.clock.now.toISOString());
  assert.equal(synced.history_queued_at, null);
  assert.equal(synced.history_lease_owner, null);
  assert.equal(synced.history_error, null);
  const ledger = await x.ledger();
  assert.equal(ledger!.pending_ciphertext, null);
  assert.deepEqual(Object.keys(ledger!.versions).sort(), [`amp:${THREAD}:m1`, `amp:${THREAD}:m2`]);
  assert.equal(ledger!.versions[`amp:${THREAD}:m1`].deliveryRevision, 1);
  assert.equal((await summaryOf(x.h)).bindings[0].history.state, "synced");

  // Not due inside the interval.
  x.advance(AMP_HISTORY_INTERVAL_MS - 1000);
  await historyPass(x.deps);
  assert.equal(x.exports(), before + 1);

  // Due: an unchanged thread is a successful poll with no upload and no session.
  x.advance(2000);
  await historyPass(x.deps);
  assert.equal(x.exports(), before + 2);
  assert.equal(x.uploads.length, 1);
  assert.equal(x.sessions.length, 1);
  assert.equal(new Date((await x.row()).last_synced_at!).toISOString(), x.h.clock.now.toISOString());

  // A new version and a new message upload; the older version never does.
  x.thread.messages[0] = { ...x.thread.messages[0]!, content: "first, edited", messageVersion: 2 };
  x.message("m3", "third", 1);
  x.advance(AMP_HISTORY_INTERVAL_MS);
  await historyPass(x.deps);
  assert.equal(x.uploads.length, 2);
  assert.deepEqual(x.uploads[1]!.body.records.map((record: any) => record.record.messageId), ["m1", "m3"]);
  assert.equal((await x.ledger())!.versions[`amp:${THREAD}:m1`].deliveryRevision, 2);
});

test("amp history: a failed or partial upload never advances the watermark and the pending page is retried first", async (t) => {
  const x = await historyHarness(t);
  x.message("m1", SECRET_TEXT, 1);
  x.message("m2", "second", 1);
  const logs: string[] = [];
  const original = { warn: console.warn, log: console.log, error: console.error, info: console.info };
  for (const name of ["warn", "log", "error", "info"] as const) {
    console[name] = (...args: unknown[]) => void logs.push(JSON.stringify(args));
  }
  try {
    x.state.mode = "http500";
    await historyPass(x.deps);
    let current = await x.row();
    assert.equal(current.last_synced_at, null, "a failed upload does not move the watermark");
    assert.equal(current.history_error, "history_http_500");
    assert.notEqual(current.history_queued_at, null, "the thread stays queued for retry");
    const pending = (await x.ledger())!.pending_ciphertext;
    assert(pending, "the prepared page is kept, encrypted");
    assert.equal(pending.includes(SECRET_TEXT), false);
    const summary = await summaryOf(x.h);
    assert.equal(summary.bindings[0].history.state, "error");
    assert.equal(summary.bindings[0].history.lastError, "history_http_500");

    // The failure's lease is the retry delay: nothing runs before it expires.
    await historyPass(x.deps);
    assert.equal(x.uploads.length, 1);

    x.state.mode = "partial";
    x.advance(AMP_HISTORY_QUEUE_LEASE_MS + 1000);
    await historyPass(x.deps);
    assert.equal(x.uploads.length, 2);
    assert.equal(x.uploads[1]!.body.batchId, x.uploads[0]!.body.batchId, "the exact pending page is re-sent");
    current = await x.row();
    assert.equal(current.last_synced_at, null, "a partial accept does not move the watermark");
    assert.equal(current.history_error, "history_partial_accept");
    assert.deepEqual((await x.ledger())!.versions, {}, "nothing is acknowledged without a full receipt");

    x.state.mode = "ok";
    x.advance(AMP_HISTORY_QUEUE_LEASE_MS + 1000);
    await historyPass(x.deps);
    assert.equal(x.uploads[2]!.body.batchId, x.uploads[0]!.body.batchId);
    current = await x.row();
    assert.equal(new Date(current.last_synced_at!).toISOString(), x.h.clock.now.toISOString());
    assert.equal(current.history_error, null);
    assert.equal((await x.ledger())!.pending_ciphertext, null);
  } finally {
    Object.assign(console, original);
  }
  assert(logs.some((line) => line.includes("history_sync_failed")));
  for (const line of logs) {
    for (const secret of [AMP_KEY, ACCESS_TOKEN, SECRET_TEXT, "second"]) {
      assert.equal(line.includes(secret), false, "logs carry only the binding id and an error code");
    }
  }
});

test("amp history: a metadata-only backfill is persisted without an upload", async (t) => {
  const x = await historyHarness(t);
  x.message("m1", "first", 1);
  const [record] = ampExport(THREAD, { id: THREAD, createdAt: "2026-11-08T00:00:00.000Z", messages: x.thread.messages });
  const key = record!.eventId;
  await x.h.database.query(
    "INSERT INTO selfhost_amp_history_syncs (workspace_id, thread_id, versions) VALUES ($1, $2, $3::jsonb)",
    [x.h.workspaceId, THREAD, JSON.stringify({ [key]: { version: 1, digest: hash(stableJson(record)) } })],
  );
  await historyPass(x.deps);
  assert.equal(x.uploads.length, 0);
  assert.equal(x.sessions.length, 0, "no push session is requested when nothing changed");
  const stored = (await x.ledger())!.versions[key];
  assert.equal(stored.version, 1);
  assert.match(stored.sourceDigest, /^[0-9a-f]{64}$/);
  assert.notEqual((await x.row()).last_synced_at, null);
});

test("amp history: queue requests and worker ticks coalesce into one run", async (t) => {
  const x = await historyHarness(t);
  x.message("m1", "first", 1);
  const before = x.exports();
  const job = { v: 1, kind: "history", bindingId: x.binding.binding_id };
  const first = await internalJob(x.h, job);
  assert.equal(first.status, 202);
  assert.deepEqual(first.body, { ok: true, queued: true });
  const queuedAt = (await x.row()).history_queued_at;
  x.advance(1000);
  assert.equal((await internalJob(x.h, job)).status, 202);
  assert.equal(new Date((await x.row()).history_queued_at!).getTime(), new Date(queuedAt!).getTime(),
    "a second request keeps the original queue time");
  const worker = startAmpWorker(x.deps, 600_000);
  t.after(() => worker.stop());
  await Promise.all([worker.tick(), worker.tick()]);
  await worker.tick();
  assert.equal(x.exports(), before + 1, "two requests and several ticks give one export");
  assert.equal(x.uploads.length, 1);
  // A request already covered by a later poll is satisfied without a run.
  const covered = await internalJob(x.h, { ...job, scheduledAt: new Date(x.h.clock.now.getTime() - 1).toISOString() });
  assert.equal(covered.status, 200);
  assert.deepEqual(covered.body, { ok: true, queued: false, skipped: true });
});

test("amp history: a live lease blocks a second run, an expired lease is reclaimable and the stale run stops", async (t) => {
  const x = await historyHarness(t);
  x.message("m1", "first", 1);
  assert.equal(await scheduleHistory(x.deps), 1);
  assert.equal(await scheduleHistory(x.deps), 0, "already queued");
  const [stale] = await claimHistory(x.deps);
  assert(stale);
  assert.deepEqual(await claimHistory(x.deps), [], "a live lease is never claimed twice");
  x.advance(AMP_HISTORY_QUEUE_LEASE_MS - 1000);
  assert.deepEqual(await claimHistory(x.deps), []);
  x.advance(2000);
  const [fresh] = await claimHistory(x.deps);
  assert(fresh, "an expired lease is reclaimable");
  assert.notEqual(fresh.owner, stale.owner);
  const before = x.exports();
  assert.deepEqual(await runHistory(x.deps, stale), { records: 0, skipped: true });
  assert.equal(x.exports(), before, "the stale run exports nothing");
  assert.equal((await x.row()).last_synced_at, null);
  assert.deepEqual(await runHistory(x.deps, fresh), { records: 1 });
  assert.equal(x.uploads.length, 1);
});

test("amp history: retired and disconnected bindings are never polled", async (t) => {
  const x = await historyHarness(t);
  x.message("m1", "first", 1);
  assert.equal(await scheduleHistory(x.deps), 1);
  const unbound = await x.h.api(ampPath(x.h, `/bindings/${x.binding.binding_id}`), { method: "DELETE", token: x.h.ownerToken });
  assert.equal(unbound.status, 200);
  const before = x.exports();
  x.advance(AMP_HISTORY_INTERVAL_MS * 3);
  await historyPass(x.deps);
  assert.equal(x.exports(), before);
  assert.equal((await internalJob(x.h, { v: 1, kind: "history", bindingId: x.binding.binding_id })).body.queued, false);

  // A second thread, then a disconnect of the whole connection.
  const y = await historyHarness(t);
  y.message("m1", "first", 1);
  assert.equal(await scheduleHistory(y.deps), 1);
  const [claim] = await claimHistory(y.deps);
  assert(claim);
  assert.equal((await y.h.api(ampPath(y.h, "/connection"), { method: "DELETE", token: y.h.ownerToken })).status, 200);
  const exported = y.exports();
  assert.deepEqual(await runHistory(y.deps, claim), { records: 0, skipped: true }, "an in-flight claim stops at its fence");
  y.advance(AMP_HISTORY_INTERVAL_MS * 3);
  await historyPass(y.deps);
  assert.equal(y.exports(), exported);
  assert.equal(y.uploads.length, 0);
});

test("amp history: without a push session nothing is exported or polled, only the reason is recorded", async (t) => {
  const h = await startAmp(t);
  const binding = await connectAndBind(h);
  h.transport.threads.get(THREAD)!.messages.push({ messageID: "m1", role: "user", content: "x", createdAt: "2026-11-08T00:00:02.000Z" });
  const before = h.transport.calls.filter((call) => call.operation.kind === "export").length;
  const worker = startAmpWorker(h.amp!.deps, 600_000);
  t.after(() => worker.stop());
  for (let index = 0; index < 3; index += 1) {
    await worker.tick();
    h.clock.now = new Date(h.clock.now.getTime() + AMP_HISTORY_INTERVAL_MS * 2);
  }
  assert.equal(h.transport.calls.filter((call) => call.operation.kind === "export").length, before);
  const row = (await h.database.query<{ history_error: string; history_queued_at: Date | null; last_synced_at: Date | null }>(
    "SELECT history_error, history_queued_at, last_synced_at FROM selfhost_amp_bindings WHERE id = $1",
    [binding.binding_id],
  )).rows[0]!;
  assert.equal(row.history_error, "push_session_unavailable");
  assert.equal(row.history_queued_at, null);
  assert.equal(row.last_synced_at, null);
  const summary = await summaryOf(h);
  assert.deepEqual(summary.history, { available: false, reason: "push_session_unavailable" });
  assert.equal(summary.bindings[0].history.state, "unavailable");
  const job = await internalJob(h, { v: 1, kind: "history", bindingId: binding.binding_id });
  assert.equal(job.status, 501);
  assert.equal(job.body.error, "history_push_unavailable");
  assert.equal((await h.database.query("SELECT 1 FROM selfhost_amp_history_syncs")).rows.length, 0);
});
