// analytics collector: segment storage. Each accepted batch becomes its own
// immutable closed NDJSON segment: written privately under tmp/, fsynced,
// renamed into segments/, and the segments/ directory fsynced. Only then is
// the batch acknowledged. At startup, after creating segments/ and tmp/, the
// (operator-provisioned, pre-existing) data directory is fsynced so those
// entries are durable before the first acknowledgement. There is no open
// segment and no rotation step.
// Commits are serialized through one promise chain so sequence numbers and
// accounting stay consistent. Startup recovery deletes every file in tmp/ and
// indexes segments/; files that do not match the segment name are left alone
// and not counted.
import { randomUUID } from "node:crypto";
import * as nodeFs from "node:fs/promises";
import { join } from "node:path";
import type { RetentionPolicy } from "./config.js";

/** The subset of node:fs/promises the store uses; tests inject failures through it. Fsync goes through the FileHandle. */
export type CollectorFs = Pick<typeof nodeFs, "open" | "rename" | "unlink" | "readdir" | "stat" | "mkdir">;

export type StorageLog = (message: string, fields?: Record<string, unknown>) => void;

export type SegmentStoreOptions = {
  dataDir: string;
  maxSegments: number;
  maxDiskBytes: number;
  retention: RetentionPolicy;
  retentionMaxAgeMs: number | null;
  fsImpl?: CollectorFs;
  now?: () => number;
  log?: StorageLog;
};

export type CommitResult =
  | { ok: true; segment: string }
  /** capacity: reject-new exhaustion (or a batch larger than the whole disk cap); write: any write/fsync/rename/unlink failure. */
  | { ok: false; reason: "capacity" | "write"; fsCode?: string };

export type StorageStats = {
  segments: number;
  diskBytes: number;
  writeFailures: number;
  retentionLoss: { segments: number; bytes: number };
};

/** `<epoch-ms 13 digits>-<seq 10 digits>-<uuid>.ndjson` */
export const SEGMENT_NAME = /^(\d{13})-(\d{10})-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.ndjson$/;
const MAX_SEQ = 9_999_999_999;

type Segment = { name: string; epochMs: number; seq: number; bytes: number };

/** An errno-style code such as ENOSPC, never the exception text. */
function fsCode(error: unknown): string | undefined {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && /^E[A-Z0-9]{1,32}$/.test(code) ? code : undefined;
}

function compareSegments(a: Segment, b: Segment): number {
  return a.epochMs - b.epochMs || a.seq - b.seq;
}

export class SegmentStore {
  readonly segmentsDir: string;
  readonly tmpDir: string;
  private readonly fs: CollectorFs;
  private readonly now: () => number;
  private readonly log: StorageLog;
  /** Oldest first. */
  private readonly index: Segment[] = [];
  private diskBytes = 0;
  private nextSeq = 1;
  private writeFailures = 0;
  private retentionLoss = { segments: 0, bytes: 0 };
  private chain: Promise<unknown> = Promise.resolve();

  private constructor(private readonly options: SegmentStoreOptions) {
    this.segmentsDir = join(options.dataDir, "segments");
    this.tmpDir = join(options.dataDir, "tmp");
    this.fs = options.fsImpl ?? nodeFs;
    this.now = options.now ?? Date.now;
    this.log = options.log ?? (() => {});
  }

  /** Recovers and indexes the data directory. Throws (naming the variable only) when it is unusable. */
  static async open(options: SegmentStoreOptions): Promise<SegmentStore> {
    const store = new SegmentStore(options);
    await store.recover();
    return store;
  }

  private async recover(): Promise<void> {
    const unusable = new Error("ANALYTICS_COLLECTOR_DATA_DIR must be an existing writable directory");
    try {
      if (!(await this.fs.stat(this.options.dataDir)).isDirectory()) throw unusable;
      await this.fs.mkdir(this.segmentsDir, { recursive: true, mode: 0o700 });
      await this.fs.mkdir(this.tmpDir, { recursive: true, mode: 0o700 });
      // Persist the segments/ and tmp/ entries in DATA_DIR before any batch can
      // be acknowledged: fsync of a file or of segments/ does not make a newly
      // created directory entry durable, only an fsync of its parent does. Done
      // on every start (idempotent). DATA_DIR itself must pre-exist (checked
      // above, never created here), so nothing above it is synced.
      const parent = await this.fs.open(this.options.dataDir, "r");
      try {
        await parent.sync();
      } finally {
        await parent.close();
      }
      // Probe writability where part files go.
      const probe = join(this.tmpDir, `probe-${randomUUID()}`);
      const handle = await this.fs.open(probe, "wx", 0o600);
      await handle.close();
      await this.fs.unlink(probe);
    } catch {
      throw unusable;
    }

    try {
      await this.scan();
    } catch (error) {
      const code = fsCode(error);
      throw new Error(`ANALYTICS_COLLECTOR_DATA_DIR recovery failed${code ? ` (${code})` : ""}`);
    }
  }

  private async scan(): Promise<void> {
    // Incomplete private segments are never exposed: delete every file in tmp/.
    let removedParts = 0;
    for (const entry of await this.fs.readdir(this.tmpDir, { withFileTypes: true })) {
      if (!entry.isFile() && !entry.isSymbolicLink()) continue;
      await this.fs.unlink(join(this.tmpDir, entry.name));
      removedParts += 1;
    }

    let ignored = 0;
    for (const entry of await this.fs.readdir(this.segmentsDir, { withFileTypes: true })) {
      const match = entry.isFile() ? SEGMENT_NAME.exec(entry.name) : null;
      if (!match) {
        ignored += 1;
        continue;
      }
      const { size } = await this.fs.stat(join(this.segmentsDir, entry.name));
      this.index.push({ name: entry.name, epochMs: Number(match[1]), seq: Number(match[2]), bytes: size });
      this.diskBytes += size;
    }
    this.index.sort(compareSegments);
    this.nextSeq = this.index.reduce((max, segment) => Math.max(max, segment.seq), 0) + 1;
    const aged = await this.applyAge();
    this.log("recovered", {
      segments: this.index.length,
      disk_bytes: this.diskBytes,
      removed_parts: removedParts,
      ignored_files: ignored,
      retention_removed: aged,
    });
  }

  stats(): StorageStats {
    return {
      segments: this.index.length,
      diskBytes: this.diskBytes,
      writeFailures: this.writeFailures,
      retentionLoss: { ...this.retentionLoss },
    };
  }

  /** Resolves once every commit queued so far has finished. */
  idle(): Promise<void> {
    return this.chain.then(() => undefined);
  }

  /** Commits the lines as one closed segment. Never rejects. */
  commit(lines: readonly string[]): Promise<CommitResult> {
    const result = this.chain.then(() => this.commitNow(lines));
    this.chain = result.catch(() => undefined);
    return result.catch((error: unknown) => {
      this.writeFailures += 1;
      return { ok: false as const, reason: "write" as const, fsCode: fsCode(error) };
    });
  }

  /** Removes one closed segment, counting it as retention loss. */
  private async removeOldest(): Promise<void> {
    const oldest = this.index[0]!;
    try {
      await this.fs.unlink(join(this.segmentsDir, oldest.name));
    } catch (error) {
      // Already gone: only the index was stale.
      if (fsCode(error) !== "ENOENT") throw error;
    }
    this.index.shift();
    this.diskBytes -= oldest.bytes;
    this.retentionLoss.segments += 1;
    this.retentionLoss.bytes += oldest.bytes;
  }

  /** delete-oldest-closed with RETENTION_MAX_AGE_MS: removes closed segments older than the age. */
  private async applyAge(): Promise<number> {
    const maxAge = this.options.retention === "delete-oldest-closed" ? this.options.retentionMaxAgeMs : null;
    if (maxAge === null) return 0;
    const cutoff = this.now() - maxAge;
    let removed = 0;
    while (this.index.length > 0 && this.index[0]!.epochMs < cutoff) {
      await this.removeOldest();
      removed += 1;
    }
    return removed;
  }

  private fits(bytes: number): boolean {
    return this.index.length + 1 <= this.options.maxSegments && this.diskBytes + bytes <= this.options.maxDiskBytes;
  }

  private async commitNow(lines: readonly string[]): Promise<CommitResult> {
    const data = lines.map((line) => `${line}\n`).join("");
    const bytes = Buffer.byteLength(data, "utf8");
    const aged = await this.applyAge();
    let evicted = 0;
    if (!this.fits(bytes)) {
      if (this.options.retention === "reject-new" || bytes > this.options.maxDiskBytes) {
        if (aged > 0) this.log("retention removed segments", { segments: aged });
        return { ok: false, reason: "capacity" };
      }
      // Only closed segments are ever removed; this commit is not yet visible.
      while (!this.fits(bytes) && this.index.length > 0) {
        await this.removeOldest();
        evicted += 1;
      }
    }
    if (aged + evicted > 0) this.log("retention removed segments", { segments: aged + evicted });
    if (this.nextSeq > MAX_SEQ) return { ok: false, reason: "capacity" };

    const seq = this.nextSeq++;
    const id = randomUUID();
    const epochMs = this.now();
    const part = join(this.tmpDir, `${seq}-${id}.ndjson.part`);
    const name = `${String(epochMs).padStart(13, "0")}-${String(seq).padStart(10, "0")}-${id}.ndjson`;
    const final = join(this.segmentsDir, name);
    let renamed = false;
    try {
      const handle = await this.fs.open(part, "wx", 0o600);
      try {
        await handle.writeFile(data, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
      await this.fs.rename(part, final);
      renamed = true;
      const directory = await this.fs.open(this.segmentsDir, "r");
      try {
        await directory.sync();
      } finally {
        await directory.close();
      }
    } catch (error) {
      this.writeFailures += 1;
      let left = false;
      // A batch answered 507 must not stay visible: remove it from wherever it got to.
      try {
        await this.fs.unlink(renamed ? final : part);
      } catch (unlinkError) {
        left = fsCode(unlinkError) !== "ENOENT";
      }
      if (renamed && left) {
        // Could not remove the renamed file: keep the accounting truthful.
        this.index.push({ name, epochMs, seq, bytes });
        this.index.sort(compareSegments);
        this.diskBytes += bytes;
      }
      return { ok: false, reason: "write", fsCode: fsCode(error) };
    }
    this.index.push({ name, epochMs, seq, bytes });
    if (this.index.length > 1 && compareSegments(this.index.at(-2)!, this.index.at(-1)!) > 0) {
      this.index.sort(compareSegments);
    }
    this.diskBytes += bytes;
    return { ok: true, segment: name };
  }
}
