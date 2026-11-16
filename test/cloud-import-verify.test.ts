import assert from "node:assert/strict";
import { after, before, beforeEach, test, type TestFn } from "node:test";
import { Client } from "pg";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { fixtureContract, fixtureIds, fixtureKeyring, seedFixtures } from "../scripts/cloud-import-verify/fixtures.js";
import { verify } from "../scripts/cloud-import-verify/verify.js";

// Dedicated ephemeral cluster supplied by dry-run.ts, never inherited database URLs.
const port = process.env.CLOUD_VERIFY_FIXTURE_PORT;
const enabled = Boolean(port) && process.env.CLOUD_VERIFY_FIXTURE_CLUSTER === "synthetic-only";
const fixtureTest = (name: string, fn: TestFn) => test(name,
  { skip: enabled ? false : "Run scripts/cloud-import-verify/dry-run.ts for the dedicated synthetic cluster" },fn);
const config = { host: "127.0.0.1", port: Number(port), database: "postgres", user: "cloud_verify_fixture", password: "" };
const admin = new Client(config);
const source = new Client(config);
const target = new Client(config);
before(async () => { if (enabled) { await admin.connect(); await source.connect(); await target.connect(); } });
after(async () => { if (enabled) { await source.end(); await target.end(); await admin.end(); } });
beforeEach(async () => { if (enabled) await seedFixtures(admin); });
const check = () => verify(source, target, fixtureContract(), fixtureKeyring);

fixtureTest("counts, per-org hashes, rw_ identity, key rotation, FK, unique and bigint sequence pass", async () => {
  const report = await check();
  assert.equal(report.ok, true, JSON.stringify(report.findings.filter((f) => !f.ok)));
  const workspace = report.findings.find((f) => f.name === "workspaces")!;
  const detail = workspace.detail as { source: { count: number; orgs: Record<string, unknown> } };
  assert.equal(detail.source.count, 2);
  assert.equal(Object.keys(detail.source.orgs).length, 2);
  assert.equal(report.smoke.length, 6);
  assert.ok(report.smoke.every((s) => s.status === "pending"));
  assert.ok(!JSON.stringify(report).includes("synthetic-relaycast-key"));
  assert.ok(!JSON.stringify(report).includes("v2.synthetic."));
});

fixtureTest("same row count with altered contents fails checksum", async () => {
  await admin.query("UPDATE control_fixture.workspaces SET name='Changed' WHERE id=$1", [fixtureIds.workspace]);
  const report = await check();
  assert.equal(report.ok, false);
  assert.equal(report.findings.find((f) => f.name === "workspaces")!.ok, false);
});

fixtureTest("missing row and wrong organization fail table and per-org comparison", async () => {
  await admin.query("DELETE FROM control_fixture.workspaces WHERE id=$1", [fixtureIds.otherWorkspace]);
  await admin.query("UPDATE control_fixture.workspaces SET organization_id=$1", [fixtureIds.otherOrg]);
  const report = await check();
  assert.equal(report.findings.find((f) => f.name === "workspaces")!.ok, false);
});

fixtureTest("rw_ mapping corruption fails identity comparison even when payload matches", async () => {
  await admin.query("UPDATE control_fixture.workspaces SET cloud_relay_workspace_id='rw_wrong' WHERE id=$1", [fixtureIds.workspace]);
  const report = await check();
  assert.equal(report.findings.find((f) => f.name === "workspaces")!.ok, true);
  assert.equal(report.findings.find((f) => f.kind === "identity")!.ok, false);
});

fixtureTest("FK scan detects orphans left by disabled triggers", async () => {
  await admin.query("SET session_replication_role=replica");
  try { await admin.query("DELETE FROM control_fixture.organizations WHERE id=$1", [fixtureIds.org]); }
  finally { await admin.query("SET session_replication_role=origin"); }
  const report = await check();
  assert.ok(report.findings.some((f) => f.kind === "foreign_key" && !f.ok));
});

fixtureTest("failed concurrent unique-index build reports duplicates and invalid index", async () => {
  await admin.query("CREATE TABLE control_fixture.duplicates (v text); INSERT INTO control_fixture.duplicates VALUES ('a'),('a')");
  await assert.rejects(admin.query("CREATE UNIQUE INDEX CONCURRENTLY duplicate_probe ON control_fixture.duplicates(v)"));
  const contract = fixtureContract();
  contract.targetRelations.push("control_fixture.duplicates");
  const report = await verify(source,target,contract,fixtureKeyring);
  const failure = report.findings.find((f) => f.kind === "unique" && f.name.endsWith("duplicate_probe"))!;
  assert.equal(failure.ok,false);
  assert.deepEqual(failure.detail,{valid:false,ready:false,violations:1});
});

fixtureTest("composite MATCH FULL rejects partially null foreign keys", async () => {
  await admin.query(`CREATE TABLE control_fixture.parents (a integer, b integer, UNIQUE(a,b));
    CREATE TABLE control_fixture.children (id integer PRIMARY KEY, a integer, b integer,
      FOREIGN KEY(a,b) REFERENCES control_fixture.parents(a,b) MATCH FULL NOT VALID);
    SET session_replication_role=replica;
    INSERT INTO control_fixture.children VALUES(1,1,NULL);
    SET session_replication_role=origin`);
  const contract = fixtureContract();
  contract.targetRelations.push("control_fixture.children");
  const report = await verify(source,target,contract,fixtureKeyring);
  assert.ok(report.findings.some((f) => f.kind === "foreign_key" && !f.ok
    && (f.detail as { violations: number }).violations === 1));
});

fixtureTest("unique indexes include expression, predicate and NULLS NOT DISTINCT semantics", async () => {
  await admin.query(`CREATE TABLE control_fixture.unique_probe (v text, active boolean);
    CREATE UNIQUE INDEX unique_probe_expression ON control_fixture.unique_probe(lower(v)) WHERE active;
    CREATE UNIQUE INDEX unique_probe_nulls ON control_fixture.unique_probe(v) NULLS NOT DISTINCT;
    INSERT INTO control_fixture.unique_probe VALUES('A',true),('a',false),(NULL,false)`);
  const contract = fixtureContract();
  contract.targetRelations.push("control_fixture.unique_probe");
  const report = await verify(source,target,contract,fixtureKeyring);
  assert.equal(report.ok, true);
  assert.equal(report.findings.filter((f) => f.kind === "unique" && f.name.includes("unique_probe")).length, 2);
});

fixtureTest("stale sequence fails without consuming a sequence value", async () => {
  await admin.query("SELECT setval(pg_get_serial_sequence('control_fixture.sequence_probe','id'),1,false)");
  const report = await check();
  assert.ok(report.findings.some((f) => f.kind === "sequence" && !f.ok));
  const value = await admin.query("SELECT last_value::text,is_called FROM control_fixture.sequence_probe_id_seq");
  assert.deepEqual(value.rows[0], { last_value: "1", is_called: false });
});

fixtureTest("undecryptable and absent encrypted samples fail without logging their values", async () => {
  await admin.query("UPDATE control_fixture.workspaces SET key_ciphertext='private-corrupt-ciphertext'");
  const report = await check();
  assert.ok(report.findings.some((f) => f.kind === "decrypt" && !f.ok));
  assert.ok(!JSON.stringify(report).includes("private-corrupt-ciphertext"));
  await admin.query("DELETE FROM control_fixture.provider_connections");
  await admin.query("DELETE FROM control_fixture.workspaces");
  assert.ok((await check()).findings.some((f) => f.kind === "decrypt" && !f.ok));
});

fixtureTest("duplicate projection keys fail; JSON key order and timestamp offsets normalize", async () => {
  await admin.query(`UPDATE control_fixture.workspaces SET
    settings='{"n":9007199254740993,"nested":{"a":1,"b":2}}',
    created_at='2026-11-09T05:00:00+01:00' WHERE id=$1`, [fixtureIds.workspace]);
  assert.equal((await check()).ok,true);
  const contract = fixtureContract();
  contract.tables[0]!.sourceSql = "SELECT uuid AS __key,uuid AS __org,name FROM cloud_fixture.organizations UNION ALL SELECT uuid,uuid,name FROM cloud_fixture.organizations";
  const report = await verify(source,target,contract,fixtureKeyring);
  assert.equal(report.findings[0]!.ok,false);
});

fixtureTest("writes in contract SQL are rejected by read-only transactions; snapshots release on failure", async () => {
  const contract = fixtureContract();
  contract.tables[0]!.sourceSql = "SELECT uuid AS __key,uuid AS __org,name FROM cloud_fixture.organizations FOR UPDATE";
  await assert.rejects(verify(source,target,contract,fixtureKeyring));
  assert.equal((await check()).ok,true);
});

fixtureTest("streamed checksums span multiple batches with exact large numeric values", async () => {
  await admin.query(`INSERT INTO cloud_fixture.organizations
    SELECT md5('fixture-org-'||n)::uuid,'Org '||n FROM generate_series(1,300) n;
    INSERT INTO control_fixture.organizations SELECT uuid,name FROM cloud_fixture.organizations ON CONFLICT DO NOTHING`);
  const report = await check();
  assert.equal(report.ok,true);
  assert.equal((report.findings[0]!.detail as {source:{count:number}}).source.count,302);
  await admin.query(`UPDATE control_fixture.workspaces SET settings=jsonb_set(settings,'{n}','9007199254740992') WHERE id=$1`,[fixtureIds.workspace]);
  assert.equal((await check()).findings.find((f) => f.name === "workspaces")!.ok,false);
});

fixtureTest("CLI emits JSON with useful exit codes and hides URL/SQL errors", async () => {
  const directory = await mkdtemp(join(tmpdir(),"verify-cli-"));
  try {
    const path = join(directory,"contract.json");
    await writeFile(path,JSON.stringify(fixtureContract()));
    const url = new URL("postgresql:/");
    url.hostname = "127.0.0.1"; url.port = port!;
    url.username = config.user; url.pathname = "/postgres";
    const env = {...process.env,CLOUD_VERIFY_SOURCE_URL:url.toString(),CLOUD_VERIFY_TARGET_URL:url.toString(),
      SELFHOST_ENCRYPTION_KEY_ID:fixtureKeyring.active.id,
      SELFHOST_ENCRYPTION_KEY:fixtureKeyring.active.key.toString("base64"),
      SELFHOST_ENCRYPTION_PREVIOUS_KEY_ID:fixtureKeyring.previous!.id,
      SELFHOST_ENCRYPTION_PREVIOUS_KEY:fixtureKeyring.previous!.key.toString("base64")};
    const run = (extra: Record<string,string> = {}) => spawnSync(process.execPath,
      ["--import","tsx",fileURLToPath(new URL("../scripts/cloud-import-verify/cli.ts",import.meta.url)),path],
      {env:{...env,...extra},encoding:"utf8",timeout:10000});
    const passed = run();
    assert.equal(passed.status,0,passed.stderr);
    assert.equal(JSON.parse(passed.stdout).ok,true);
    await admin.query("UPDATE control_fixture.workspaces SET name='Different'");
    assert.equal(run().status,1);
    const remote = new URL(url);
    remote.hostname = "192.0.2.1"; remote.password = "synthetic_private_marker";
    const refused = run({CLOUD_VERIFY_SOURCE_URL:remote.toString()});
    assert.equal(refused.status,2);
    assert.ok(!refused.stderr.includes(remote.password));
    assert.ok(!refused.stderr.includes(remote.hostname));
    const override = new URL(url);
    override.searchParams.set("host",remote.hostname);
    assert.equal(run({CLOUD_VERIFY_SOURCE_URL:override.toString()}).status,2);
  } finally { await rm(directory,{recursive:true,force:true}); }
});
