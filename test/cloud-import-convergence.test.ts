import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { CodingAgentStore } from "../src/admin/coding-agents.js";
import { CredentialBlobStore, PostgresObjectBackend } from "../src/admin/credential-blobs.js";
import { SubscriptionLoginStore } from "../src/admin/subscription-logins.js";
import type { EncryptionKeyring } from "../src/crypto.js";
import type { Database } from "../src/database.js";
import { migrate } from "../src/migrations.js";
import { CLOUD_FIXTURE_DDL, cloudEnvelope, cloudFixtureSeed, id } from "../scripts/cloud-import/cloud-fixture.js";
import { bindConvergence, ConvergenceRefused, parseArgs, runProducer, type CliArgs } from "../scripts/cloud-import/cli.js";
import { copyCodingAgentCredentials } from "../scripts/cloud-import/credentials.js";
import { runImport } from "../scripts/cloud-import/importer.js";
import { computeCredentialCheckpoint, type CredentialConvergenceSnapshot } from "../scripts/cloud-import-verify/convergence.js";
import { PGliteDatabase } from "./support/harness.js";

/*
 * The producer half of the convergence receipt
 * (scripts/cloud-import-verify/CONVERGENCE_CONTRACT.md): the CLI recomputes
 * the target's credential state itself before any write, refuses on a
 * mismatch, and the receipt carries the digest it computed.
 */
const CLOUD_KEY = randomBytes(32).toString("hex");
const KEYRING: EncryptionKeyring = { active: { id: "convergence", key: randomBytes(32) } };
const jwt = (payload: Record<string, unknown>) => `e30.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.sig`;
const auth = JSON.stringify({
  auth_mode: "chatgpt",
  tokens: { access_token: jwt({ exp: Math.floor(Date.now() / 1000) + 3600 }), id_token: jwt({ email: "alice@example.test" }), refresh_token: "rt-cloud", account_id: "acct-synthetic-1" },
});
const ARGS: CliArgs = { mode: "apply", orgIds: null, copyCredentials: true, initLedger: false, convergenceCheckpoint: "before.json", report: "apply.json", credentialsReport: "copy.json" };

async function setup(t: { after(fn: () => Promise<void>): void }) {
  const source = new PGliteDatabase();
  const target = new PGliteDatabase();
  t.after(async () => {
    await source.close();
    await target.close();
  });
  await source.exec(CLOUD_FIXTURE_DDL);
  await source.exec(cloudFixtureSeed(CLOUD_KEY));
  await migrate(target);
  const objects = new Map([[`${id(1)}/accounts/${id(0x806)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(auth, CLOUD_KEY))]]);
  const blobs = new CredentialBlobStore(new PostgresObjectBackend(target), KEYRING);
  const deps = {
    source, target, reader: { get: async (key: string) => objects.get(key) ?? null }, cloudKeyHex: CLOUD_KEY, keyring: KEYRING,
    codingAgents: new CodingAgentStore(target, KEYRING, undefined, blobs),
    logins: new SubscriptionLoginStore(target, KEYRING, blobs), blobs,
  };
  // The initial apply and copy, before any convergence rerun.
  assert.equal((await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply")).ok, true);
  await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  return { source, target, deps };
}

const digestNow = async (target: Database) => (await target.transaction(async (tx) => {
  await tx.exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
  return computeCredentialCheckpoint(tx, { orgIds: null });
})).digest;

/** What capture-credential-convergence.mjs writes, built from the same helper. */
async function beforeCheckpoint(target: Database): Promise<CredentialConvergenceSnapshot> {
  const state = await target.transaction(async (tx) => {
    await tx.exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
    return computeCredentialCheckpoint(tx, { orgIds: null });
  });
  return {
    ...state, kind: "credential-convergence", phase: "before", nonce: randomBytes(32).toString("hex"),
    sessionSafety: { transactionReadOnly: "on", isolation: "repeatable read", statementTimeout: "1min", lockTimeout: "5s" },
  };
}

function producer(source: Database, target: Database, deps: Parameters<typeof copyCodingAgentCredentials>[0], checkpoint: unknown) {
  const written = new Map<string, unknown>();
  let copies = 0;
  const run = () => runProducer(ARGS, {
    source, target, keyring: KEYRING, cloudKey: CLOUD_KEY, checkpoint,
    copy: () => {
      copies += 1;
      return copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
    },
    write: (path, value) => written.set(path, value),
  });
  return { run, written, copies: () => copies };
}

test("convergence rerun: the receipt is the digest the run computed and the checkpoint's nonce", async (t) => {
  const { source, target, deps } = await setup(t);
  const checkpoint = await beforeCheckpoint(target);
  assert.ok(checkpoint.credentials.length > 0);
  // Outside the checkpoint but part of a converged rerun: the identity
  // secrets and their secret_written markers (#191) are not rewritten either.
  const secrets = async () => (await target.query<{ x: string | null }>(
    `SELECT string_agg(k, ',' ORDER BY k) AS x FROM (
       SELECT 'ledger:' || row_key || '@' || xmin::text AS k FROM cloud_import_ledger WHERE table_name = 'secret_written'
       UNION ALL SELECT 'ws:' || id::text || '@' || xmin::text FROM workspaces WHERE relaycast_api_key_ciphertext IS NOT NULL
       UNION ALL SELECT 'pi:' || id::text || '@' || xmin::text FROM person_identities
       UNION ALL SELECT 'hp:' || id::text || '@' || xmin::text FROM hosted_relay_participants
       UNION ALL SELECT 'dr:' || id::text || '@' || xmin::text FROM desktop_relay_identities) s`)).rows[0]!.x;
  const secretsBefore = await secrets();
  assert.match(secretsBefore ?? "", /ledger:/, "the import recorded secret markers");
  const { run, written } = producer(source, target, deps, checkpoint);
  await run();
  assert.equal(await secrets(), secretsBefore, "no secret row or secret_written marker rewritten");
  const copy = written.get("copy.json") as { convergence?: unknown; writes: Record<string, number> };
  assert.deepEqual(copy.convergence, { beforeDigest: checkpoint.digest, nonce: checkpoint.nonce });
  assert.deepEqual(copy.writes, { inserted: 0, updated: 0, blobWrites: 0, metadataWrites: 0, selectionWrites: 0 });
  // The whole rerun (identity import + copy) left every credential row,
  // blob and marker tuple as it was: no same-value UPDATE anywhere.
  assert.equal(await digestNow(target), checkpoint.digest, "a convergence rerun changes no credential tuple");
});

test("convergence rerun: a checkpoint that no longer matches the target refuses before any write", async (t) => {
  const { source, target, deps } = await setup(t);
  const checkpoint = await beforeCheckpoint(target);
  // The target moved after the checkpoint was taken.
  await target.query("UPDATE coding_agent_credentials SET label = 'changed after the checkpoint' WHERE id = (SELECT id FROM coding_agent_credentials ORDER BY id LIMIT 1)");
  const moved = await digestNow(target);
  const ledgerAt = async () => (await target.query<{ n: number; latest: string | null }>(
    "SELECT count(*)::int AS n, max(imported_at)::text AS latest FROM cloud_import_ledger")).rows[0]!;
  const ledgerBefore = await ledgerAt();
  const { run, written, copies } = producer(source, target, deps, checkpoint);
  await assert.rejects(run(), (error: unknown) => error instanceof ConvergenceRefused && error.message === "convergence_checkpoint_mismatch");
  assert.equal(copies(), 0, "the copy never started");
  assert.equal(written.size, 0, "no report was written");
  assert.deepEqual(await ledgerAt(), ledgerBefore, "the identity import never ran");
  assert.equal(await digestNow(target), moved, "zero credential writes");
});

test("convergence rerun: an invalid, empty or relabelled checkpoint refuses before any write", async (t) => {
  const { source, target, deps } = await setup(t);
  const checkpoint = await beforeCheckpoint(target);
  const before = await digestNow(target);
  for (const bad of [
    { ...checkpoint, digest: "0".repeat(64) },
    { ...checkpoint, credentials: [], blobs: [], markers: [] },
    { ...checkpoint, phase: "after" },
    { ...checkpoint, nonce: "not-hex" },
    null,
  ]) {
    const { run, copies } = producer(source, target, deps, bad);
    await assert.rejects(run(), (error: unknown) => error instanceof ConvergenceRefused && error.message === "convergence_checkpoint_invalid");
    assert.equal(copies(), 0);
  }
  assert.equal(await digestNow(target), before);
  // bindConvergence alone: a matching checkpoint binds, with its own nonce.
  assert.deepEqual(await bindConvergence(target, checkpoint), { beforeDigest: before, nonce: checkpoint.nonce });
});

test("convergence flag: apply with --copy-credentials over all organizations only", () => {
  assert.equal(parseArgs(["--mode", "apply", "--copy-credentials", "--convergence-checkpoint", "b.json"]).convergenceCheckpoint, "b.json");
  assert.throws(() => parseArgs(["--mode", "apply", "--convergence-checkpoint", "b.json"]), /--convergence-checkpoint needs/);
  assert.throws(() => parseArgs(["--mode", "plan", "--copy-credentials", "--convergence-checkpoint", "b.json"]), /--convergence-checkpoint needs/);
  assert.throws(() => parseArgs(["--mode", "apply", "--copy-credentials", "--org", id(0xa), "--convergence-checkpoint", "b.json"]), /--convergence-checkpoint needs/);
});
