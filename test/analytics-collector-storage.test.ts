// Analytics collector storage: startup recovery, retention (reject-new and
// delete-oldest-closed, by count, bytes and age) and injected write/fsync
// failures through the storage fsImpl, and the startup data-directory fsync
// observed through a recording fsImpl.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import * as nodeFs from "node:fs/promises";
import { mkdir, stat, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import test from "node:test";
import { SEGMENT_NAME, type CollectorFs } from "../src/analytics-collector/index.js";
import {
  batch,
  dirState,
  faultyFs,
  fsError,
  installEvent,
  post,
  readSegments,
  setup,
  TOKEN_A,
  tempDir,
} from "./support/collector.js";

/** Logs every open(path, flags), handle sync/datasync/close, rename, unlink and mkdir in order, paths relative to DATA_DIR with generated names normalised. */
function recordingFs(dataDir: string, faults: { open?: (path: string) => void; sync?: (path: string) => void } = {}) {
  const ops: string[] = [];
  const name = (path: unknown) => {
    const rel = relative(dataDir, String(path)) || ".";
    return rel
      .replace(/^tmp\/probe-.*$/, "tmp/<probe>")
      .replace(/^tmp\/.*\.ndjson\.part$/, "tmp/<part>")
      .replace(/^segments\/.*\.ndjson$/, "segments/<segment>");
  };
  const fsImpl: CollectorFs = {
    ...nodeFs,
    open: (async (path: string, flags?: string, mode?: number) => {
      ops.push(`open ${name(path)} ${flags}`);
      faults.open?.(String(path));
      const handle = await nodeFs.open(path, flags, mode);
      return new Proxy(handle, {
        get(target, property, receiver) {
          const value = Reflect.get(target, property, receiver);
          if (property === "sync" || property === "datasync" || property === "close") {
            return async () => {
              ops.push(`${property} ${name(path)}`);
              if (property !== "close") faults.sync?.(String(path));
              return (value as () => Promise<void>).call(target);
            };
          }
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    }) as CollectorFs["open"],
    rename: async (from, to) => {
      ops.push(`rename ${name(from)} ${name(to)}`);
      return nodeFs.rename(from, to);
    },
    unlink: async (path) => {
      ops.push(`unlink ${name(path)}`);
      return nodeFs.unlink(path);
    },
    mkdir: (async (path: string, options?: unknown) => {
      ops.push(`mkdir ${name(path)}`);
      return nodeFs.mkdir(path, options as Parameters<typeof nodeFs.mkdir>[1]);
    }) as CollectorFs["mkdir"],
  };
  return { ops, fsImpl };
}

const STARTUP_OPS = [
  "mkdir segments",
  "mkdir tmp",
  "open . r",
  "sync .",
  "close .",
  "open tmp/<probe> wx",
  "close tmp/<probe>",
  "unlink tmp/<probe>",
];

const COMMIT_OPS = [
  "open tmp/<part> wx",
  "sync tmp/<part>",
  "close tmp/<part>",
  "rename tmp/<part> segments/<segment>",
  "open segments r",
  "sync segments",
  "close segments",
];

function segmentName(epochMs: number, seq: number): string {
  return `${String(epochMs).padStart(13, "0")}-${String(seq).padStart(10, "0")}-${randomUUID()}.ndjson`;
}

test("recovery: planted part files are removed, a stray file is kept and not counted, real segments are indexed", async (t) => {
  const dataDir = await tempDir(t);
  await mkdir(join(dataDir, "tmp"));
  await mkdir(join(dataDir, "segments"));
  const line = `${JSON.stringify(installEvent())}\n`;
  await writeFile(join(dataDir, "tmp", `7-${randomUUID()}.ndjson.part`), line.slice(0, 20));
  await writeFile(join(dataDir, "tmp", "leftover"), "x");
  const existing = segmentName(Date.now() - 1000, 41);
  await writeFile(join(dataDir, "segments", existing), line);
  await writeFile(join(dataDir, "segments", "README.txt"), "operator note");
  await writeFile(join(dataDir, "segments", "0000000000001-1-short.ndjson"), "not a segment name");
  await mkdir(join(dataDir, "segments", "archive"));

  const ctx = await setup(t, { dataDir });
  const state = await dirState(dataDir);
  assert.deepEqual(state.tmp, []);
  assert.deepEqual(state.segments, [existing, "0000000000001-1-short.ndjson", "README.txt", "archive"].sort());
  let health = ctx.collector.health();
  assert.equal(health.segments, 1);
  assert.equal(health.disk_bytes, Buffer.byteLength(line));
  const recovered = ctx.logs.find((entry) => entry.message === "recovered");
  assert.deepEqual(recovered?.fields, { segments: 1, disk_bytes: Buffer.byteLength(line), removed_parts: 2, ignored_files: 3, retention_removed: 0 });

  // The sequence continues after the highest indexed segment.
  assert.equal((await post(ctx.origin, batch([installEvent()]), { token: TOKEN_A })).status, 204);
  const added = (await dirState(dataDir)).segments.filter((name) => SEGMENT_NAME.test(name) && name !== existing);
  assert.equal(added.length, 1);
  assert.equal(SEGMENT_NAME.exec(added[0]!)?.[2], "0000000042");
  health = ctx.collector.health();
  assert.equal(health.segments, 2);
});

test("restart: committed segments survive and are re-indexed with the same accounting", async (t) => {
  const dataDir = await tempDir(t);
  const first = await setup(t, { dataDir });
  const events = [installEvent(), installEvent()];
  assert.equal((await post(first.origin, batch(events), { token: TOKEN_A })).status, 204);
  const before = first.collector.health();
  assert.deepEqual(await first.collector.shutdown(1000), { completed: true });

  const second = await setup(t, { dataDir });
  const after = second.collector.health();
  assert.equal(after.segments, before.segments);
  assert.equal(after.disk_bytes, before.disk_bytes);
  assert.deepEqual((await readSegments(dataDir))[0]!.events, events);
});

test("an unusable data directory is a startup error naming the variable only", async (t) => {
  const dir = await tempDir(t);
  await assert.rejects(
    setup(t, { dataDir: join(dir, "missing") }),
    /^Error: ANALYTICS_COLLECTOR_DATA_DIR must be an existing writable directory$/,
  );
  const file = join(dir, "file");
  await writeFile(file, "");
  await assert.rejects(setup(t, { dataDir: file }), /ANALYTICS_COLLECTOR_DATA_DIR must be an existing writable directory/);
});

test("durability order on a fresh DATA_DIR: segments/ and tmp/ are created, DATA_DIR is fsynced before any acknowledgement, the first commit syncs the part then segments/", async (t) => {
  const dataDir = await tempDir(t);
  const { ops, fsImpl } = recordingFs(dataDir);
  const ctx = await setup(t, { dataDir, fsImpl });
  assert.deepEqual(ops, STARTUP_OPS);
  const startup = ops.length;
  assert.equal((await post(ctx.origin, batch([installEvent()]), { token: TOKEN_A })).status, 204);
  assert.deepEqual(ops.slice(startup), COMMIT_OPS);
});

test("durability on an existing layout: DATA_DIR is still fsynced exactly once at startup and never per commit", async (t) => {
  const dataDir = await tempDir(t);
  await mkdir(join(dataDir, "segments"));
  await mkdir(join(dataDir, "tmp"));
  await writeFile(join(dataDir, "segments", segmentName(Date.now() - 1000, 3)), `${JSON.stringify(installEvent())}\n`);
  const { ops, fsImpl } = recordingFs(dataDir);
  const ctx = await setup(t, { dataDir, fsImpl });
  assert.deepEqual(ops, STARTUP_OPS);
  const startup = ops.length;
  for (let i = 0; i < 2; i += 1) {
    assert.equal((await post(ctx.origin, batch([installEvent()]), { token: TOKEN_A })).status, 204);
  }
  assert.deepEqual(ops.slice(startup), [...COMMIT_OPS, ...COMMIT_OPS]);
  assert.equal(ops.filter((op) => op === "sync .").length, 1);
});

for (const [label, faults] of [
  ["opening DATA_DIR fails with EACCES", (dataDir: string) => ({ open: (path: string) => { if (path === dataDir) throw fsError("EACCES"); } })],
  ["fsync of the DATA_DIR handle fails with EIO", (dataDir: string) => ({ sync: (path: string) => { if (path === dataDir) throw fsError("EIO"); } })],
] as const) {
  test(`startup DATA_DIR fsync fault (${label}): the collector never starts, the error names the variable only, nothing is written`, async (t) => {
    const dataDir = await tempDir(t);
    const { ops, fsImpl } = recordingFs(dataDir, faults(dataDir));
    // Anchored: the message is the variable-only startup error, no path, errno or fault text.
    await assert.rejects(setup(t, { dataDir, fsImpl }), /^Error: ANALYTICS_COLLECTOR_DATA_DIR must be an existing writable directory$/);
    // setup() rejects inside createCollector, before any server exists: no 204 is possible.
    // Startup stopped at the DATA_DIR step: no probe, no part file, no segment.
    assert.equal(ops.at(-1), label.startsWith("opening") ? "open . r" : "close .");
    assert.ok(!ops.some((op) => op.startsWith("open tmp/") || op.startsWith("rename")));
    assert.deepEqual(await dirState(dataDir), { tmp: [], segments: [] });
  });
}

test("reject-new at MAX_SEGMENTS: 507 storage_exhausted with Retry-After, nothing written, counters", async (t) => {
  const ctx = await setup(t, { config: { maxSegments: 2 } });
  for (let i = 0; i < 2; i += 1) {
    assert.equal((await post(ctx.origin, batch([installEvent()]), { token: TOKEN_A })).status, 204);
  }
  const before = await dirState(ctx.dataDir);
  const response = await post(ctx.origin, batch([installEvent()]), { token: TOKEN_A });
  assert.equal(response.status, 507);
  assert.equal(response.headers.get("retry-after"), "5");
  assert.deepEqual(response.body, { error: "storage_exhausted" });
  assert.deepEqual(await dirState(ctx.dataDir), before);
  const health = ctx.collector.health();
  assert.equal(health.segments, 2);
  assert.equal(health.rejected.capacity, 1);
  assert.equal(health.write_failures, 0);
  assert.deepEqual(health.retention_loss, { segments: 0, bytes: 0 });
  assert.deepEqual(health.producers["control-a"], { accepted_batches: 2, rejected: 1 });
});

test("reject-new at MAX_DISK_BYTES: a batch that would pass the byte cap is 507 and nothing is written", async (t) => {
  const lineBytes = Buffer.byteLength(`${JSON.stringify(installEvent())}\n`);
  const ctx = await setup(t, { config: { maxDiskBytes: lineBytes * 3 } });
  assert.equal((await post(ctx.origin, batch([installEvent(), installEvent()]), { token: TOKEN_A })).status, 204);
  const before = await dirState(ctx.dataDir);
  const response = await post(ctx.origin, batch([installEvent(), installEvent()]), { token: TOKEN_A });
  assert.equal(response.status, 507);
  assert.equal(response.headers.get("retry-after"), "5");
  assert.deepEqual(response.body, { error: "storage_exhausted" });
  assert.deepEqual(await dirState(ctx.dataDir), before);
  // Exactly up to the cap still fits.
  assert.equal((await post(ctx.origin, batch([installEvent()]), { token: TOKEN_A })).status, 204);
  const health = ctx.collector.health();
  assert.equal(health.disk_bytes, lineBytes * 3);
  assert.equal(health.rejected.capacity, 1);
});

test("delete-oldest-closed: the oldest closed segments are removed, retention_loss counted, the batch committed", async (t) => {
  const ctx = await setup(t, { config: { maxSegments: 2, retention: "delete-oldest-closed" } });
  const sent = [installEvent(), installEvent(), installEvent()];
  for (const event of sent.slice(0, 2)) {
    assert.equal((await post(ctx.origin, batch([event]), { token: TOKEN_A })).status, 204);
  }
  const [oldest] = (await dirState(ctx.dataDir)).segments;
  const oldestBytes = (await stat(join(ctx.dataDir, "segments", oldest!))).size;
  assert.equal((await post(ctx.origin, batch([sent[2]]), { token: TOKEN_A })).status, 204);
  const segments = await readSegments(ctx.dataDir);
  assert.deepEqual(segments.map((segment) => segment.events[0]!.event_id), [sent[1]!.event_id, sent[2]!.event_id]);
  assert.ok(!segments.some((segment) => segment.name === oldest));
  const health = ctx.collector.health();
  assert.equal(health.segments, 2);
  assert.deepEqual(health.retention_loss, { segments: 1, bytes: oldestBytes });
  assert.equal(health.rejected.capacity, 0);
});

test("delete-oldest-closed by bytes evicts as many as needed; a batch larger than the whole cap is 507 and evicts nothing", async (t) => {
  const lineBytes = Buffer.byteLength(`${JSON.stringify(installEvent())}\n`);
  const ctx = await setup(t, { config: { maxDiskBytes: lineBytes * 3, retention: "delete-oldest-closed" } });
  for (let i = 0; i < 3; i += 1) {
    assert.equal((await post(ctx.origin, batch([installEvent()]), { token: TOKEN_A })).status, 204);
  }
  assert.equal((await post(ctx.origin, batch([installEvent(), installEvent()]), { token: TOKEN_A })).status, 204);
  let health = ctx.collector.health();
  assert.equal(health.segments, 2);
  assert.equal(health.disk_bytes, lineBytes * 3);
  assert.deepEqual(health.retention_loss, { segments: 2, bytes: lineBytes * 2 });

  const tooBig = await post(ctx.origin, batch([installEvent(), installEvent(), installEvent(), installEvent()]), { token: TOKEN_A });
  assert.equal(tooBig.status, 507);
  health = ctx.collector.health();
  assert.equal(health.segments, 2);
  assert.deepEqual(health.retention_loss, { segments: 2, bytes: lineBytes * 2 });
});

test("RETENTION_MAX_AGE_MS removes segments older than the age at startup and on each commit", async (t) => {
  let now = Date.UTC(2026, 10, 8, 12);
  const dataDir = await tempDir(t);
  const config = { retention: "delete-oldest-closed" as const, retentionMaxAgeMs: 60_000 };
  const first = await setup(t, { dataDir, config, now: () => now });
  assert.equal((await post(first.origin, batch([installEvent()]), { token: TOKEN_A })).status, 204);
  now += 30_000;
  assert.equal((await post(first.origin, batch([installEvent()]), { token: TOKEN_A })).status, 204);
  now += 45_000; // the first segment is now 75 s old, the second 45 s
  assert.equal((await post(first.origin, batch([installEvent()]), { token: TOKEN_A })).status, 204);
  let health = first.collector.health();
  assert.equal(health.segments, 2);
  assert.equal(health.retention_loss.segments, 1);
  await first.collector.shutdown(1000);

  now += 120_000;
  const second = await setup(t, { dataDir, config, now: () => now });
  health = second.collector.health();
  assert.equal(health.segments, 0);
  assert.equal(health.retention_loss.segments, 2);
  assert.deepEqual((await dirState(dataDir)).segments, []);
});

for (const [label, hooks, code] of [
  ["write fails with ENOSPC", { write: () => { throw fsError("ENOSPC"); } }, "ENOSPC"],
  ["part file fsync fails", { sync: (path: string) => { if (path.endsWith(".part")) throw fsError("EIO"); } }, "EIO"],
  ["rename fails", { rename: () => { throw fsError("EXDEV"); } }, "EXDEV"],
  ["segments directory fsync fails after rename", { sync: (path: string) => { if (path.endsWith("segments")) throw fsError("EIO"); } }, "EIO"],
] as const) {
  test(`injected failure (${label}): 507 with Retry-After, no part or segment left, write_failures counted, next batch succeeds`, async (t) => {
    let armed = true;
    const once = <A extends unknown[]>(hook: ((...args: A) => void) | undefined) =>
      hook && ((...args: A) => {
        if (!armed) return;
        try {
          hook(...args);
        } catch (error) {
          armed = false;
          throw error;
        }
      });
    const ctx = await setup(t, {
      fsImpl: faultyFs({
        write: once("write" in hooks ? hooks.write : undefined),
        sync: once("sync" in hooks ? hooks.sync : undefined),
        rename: once("rename" in hooks ? hooks.rename : undefined),
      }),
    });
    const response = await post(ctx.origin, batch([installEvent()]), { token: TOKEN_A });
    assert.equal(response.status, 507);
    assert.equal(response.headers.get("retry-after"), "5");
    assert.deepEqual(response.body, { error: "storage_exhausted" });
    assert.ok(!armed, "the fault fired");
    assert.deepEqual(await dirState(ctx.dataDir), { tmp: [], segments: [] });
    let health = ctx.collector.health();
    assert.equal(health.write_failures, 1);
    assert.equal(health.segments, 0);
    assert.equal(health.disk_bytes, 0);
    assert.equal(health.rejected.capacity, 0);
    const failure = ctx.logs.find((entry) => entry.message === "write failure");
    assert.deepEqual(failure?.fields, { producer: "control-a", events: 1, code });
    assert.ok(!JSON.stringify(ctx.logs).includes("secret text"));
    assert.ok(!response.raw.includes(code));

    const event = installEvent();
    assert.equal((await post(ctx.origin, batch([event]), { token: TOKEN_A })).status, 204);
    assert.deepEqual((await readSegments(ctx.dataDir)).map((segment) => segment.events), [[event]]);
    health = ctx.collector.health();
    assert.equal(health.write_failures, 1);
    assert.equal(health.segments, 1);
    assert.deepEqual(health.producers["control-a"], { accepted_batches: 1, rejected: 1 });
  });
}
