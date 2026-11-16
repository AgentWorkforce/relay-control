import assert from "node:assert/strict";
import { before,after,beforeEach,test,type TestFn } from "node:test";
import { Client } from "pg";
import type { Database,SqlExecutor } from "../src/database.js";
import { migrate } from "../src/migrations.js";
import { runImport } from "../scripts/cloud-import/importer.js";
import { CLOUD_FIXTURE_DDL,cloudFixtureSeed,cloudEnvelope,id,ORG_A,ORG_B } from "../scripts/cloud-import/cloud-fixture.js";
import { fixtureKeyring } from "../scripts/cloud-import-verify/fixtures.js";
import { verifyImport } from "../scripts/cloud-import-verify/import-contract.js";
import { writeFile,mkdtemp,rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const port = Number(process.env.CLOUD_VERIFY_FIXTURE_PORT);
const enabled = Boolean(port) && process.env.CLOUD_VERIFY_FIXTURE_CLUSTER === "synthetic-only";
const fixtureTest = (name:string,fn:TestFn) => test(name,{skip:enabled ? false : "Run scripts/cloud-import-verify/dry-run.ts"},fn);
const config = {host:"127.0.0.1",port,user:"cloud_verify_fixture",password:""};
const admin = new Client({...config,database:"postgres"});
const source = new Client({...config,database:"cloud_import_source_fixture"});
const target = new Client({...config,database:"cloud_import_target_fixture"});
const cloudKeyHex = Buffer.alloc(32,11).toString("hex");
function database(client:Client):Database {
  const executor:SqlExecutor = {
    query:async <T extends Record<string,unknown>>(sql:string,params:unknown[] = []) => ({rows:(await client.query(sql,params)).rows as T[]}),
    exec:async (sql) => {await client.query(sql);},
  };
  return {...executor,close:async () => {},transaction:async (run) => {
    await client.query("BEGIN");
    try {const value = await run(executor); await client.query("COMMIT"); return value;}
    catch (error) {await client.query("ROLLBACK");throw error;}
  }};
}
const sourceDb = database(source);
const targetDb = database(target);
const scope = {orgIds:null};
const apply = (selected=scope) => runImport({source:sourceDb,target:targetDb,keyring:fixtureKeyring,cloudKeyHex,batchSize:2},selected,"apply");
before(async () => {
  if (!enabled) return;
  await admin.connect();
  await admin.query("CREATE DATABASE cloud_import_source_fixture");
  await admin.query("CREATE DATABASE cloud_import_target_fixture");
  await source.connect();await target.connect();
});
after(async () => {if (enabled) {await source.end();await target.end();await admin.end();}});
beforeEach(async () => {
  if (!enabled) return;
  await source.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
  await target.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
  await source.query(CLOUD_FIXTURE_DDL);
  // The shared fixture at #155/240e84d omitted a column its mapping reads.
  // Harmless once the owning importer adds it; no owned source file is edited.
  await source.query("ALTER TABLE relay_workspaces ADD COLUMN IF NOT EXISTS relaycast_api_key_generation integer DEFAULT 1");
  await source.query(cloudFixtureSeed(cloudKeyHex,cloudKeyHex));
  await source.query(`UPDATE relay_workspaces SET id='rw_0000b202' WHERE id='rw_legacy-01';
    UPDATE workspaces SET relay_workspace_id='rw_0000b202' WHERE relay_workspace_id='rw_legacy-01'`);
  await migrate(targetDb);
  // Run actual checked-in migrations first. Model the published optional
  // 0053/0056/0057 column shapes until those separate schema PRs land.
  await target.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS cloud_relay_workspace_id text UNIQUE;
    ALTER TABLE organizations ADD COLUMN IF NOT EXISTS slug text;
    ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS slug text;
    ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS relayhistory_origin text;
    ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS relaycast_api_key_generation integer;
    ALTER TABLE desktop_relay_identities ALTER COLUMN source_id TYPE text USING source_id::text;
    ALTER TABLE fleet_node_owners ALTER COLUMN node_name DROP NOT NULL`);
});

fixtureTest("actual importer rollback, apply and rerun reconcile all nine tables and keep invite hashes",async () => {
  const dry = await runImport({source:sourceDb,target:targetDb,keyring:fixtureKeyring,cloudKeyHex,batchSize:2},scope,"dry-run");
  assert.equal(dry.ok,true,JSON.stringify(dry));
  assert.equal((await target.query("SELECT count(*)::int AS n FROM users")).rows[0].n,0);
  const first = await apply();
  assert.equal(first.ok,true,JSON.stringify(first));
  const one = await verifyImport(source,target,scope,first,fixtureKeyring,cloudKeyHex);
  assert.equal(one.ok,true,JSON.stringify(one.findings.filter((f) => !f.ok)));
  assert.equal(one.findings.filter((f) => f.kind === "table").length,9);
  assert.equal(one.findings.filter((f) => f.kind === "decrypt").length,4);
  const hashes = (await target.query("SELECT id,token_hash FROM organization_invitations ORDER BY id")).rows;
  const second = await apply();
  const two = await verifyImport(source,target,scope,second,fixtureKeyring,cloudKeyHex);
  assert.equal(two.ok,true,JSON.stringify(two.findings.filter((f) => !f.ok)));
  assert.deepEqual(one.findings.filter((f) => f.kind === "table"),two.findings.filter((f) => f.kind === "table"));
  const afterHashes = (await target.query("SELECT id,token_hash FROM organization_invitations ORDER BY id")).rows;
  assert.ok(JSON.stringify(hashes) === JSON.stringify(afterHashes),"rerun preserves invite hashes");
  const rw = (await target.query("SELECT cloud_relay_workspace_id,relaycast_workspace_id FROM workspaces WHERE id=$1",[id(0x201)])).rows[0];
  assert.deepEqual(rw,{cloud_relay_workspace_id:"rw_0000a201",relaycast_workspace_id:"rc-ws-a1"});
  assert.ok(one.smoke.every((s) => s.status === "pending"));
  for (const table of ["token_sessions","device_authorizations","workspace_api_tokens","mcp_oauth_grants","desktop_relay_session_bindings","desktop_attestation_keys"]) {
    assert.equal((await target.query(`SELECT count(*)::int AS n FROM public.${table}`)).rows[0].n,0,`${table} remains empty`);
  }
  if (process.env.CLOUD_VERIFY_IMPORT_REPORT_PATH) {
    await writeFile(process.env.CLOUD_VERIFY_IMPORT_REPORT_PATH,
      `${JSON.stringify({...two,evidenceKind:"synthetic-local-postgres"},null,2)}\n`,{mode:0o600});
  }
});

fixtureTest("tampered importer ledger cannot authorize dropped rows or invented skips",async () => {
  const ledger = await apply();
  ledger.tables.users.imported++;
  ledger.tables.users.skipped.invented_reason=1;
  const report = await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.ok,false);
  assert.equal(report.findings.find((f) => f.kind === "ledger" && f.name === "users")!.ok,false);
});

fixtureTest("undecryptable Cloud envelopes reconcile by independent keys but block qualification",async () => {
  await source.query("UPDATE workspace_person_identities SET token_envelope=$1 WHERE id=$2",
    [cloudEnvelope("synthetic-unreadable",Buffer.alloc(32,12).toString("hex")),id(0x403)]);
  const ledger = await apply();
  assert.equal(ledger.tables.person_identities.skipped.cloud_decrypt_failed,1);
  const report = await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.findings.find((f) => f.kind === "ledger" && f.name === "person_identities")!.ok,true);
  assert.equal(report.findings.find((f) => f.kind === "table" && f.name === "person_identities")!.ok,true);
  assert.equal(report.ok,false);
  assert.ok(report.findings.some((f) => f.kind === "importer_skip_policy" && !f.ok));
});

fixtureTest("pre-0057 non-UUID Desktop source IDs remain visible as unresolved importer skips",async () => {
  await target.query("ALTER TABLE desktop_relay_identities ALTER COLUMN source_id TYPE uuid USING source_id::uuid");
  await target.query("ALTER TABLE fleet_node_owners ALTER COLUMN node_name SET NOT NULL");
  const ledger = await apply();
  assert.equal(ledger.tables.desktop_relay_identities.skipped.source_id_not_uuid,1);
  const report = await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.findings.find((f) => f.kind === "table" && f.name === "desktop_relay_identities")!.ok,true);
  assert.equal(report.ok,false);
});

fixtureTest("cohort scope counts and encrypted samples exclude another org's corrupt key",async () => {
  assert.equal((await apply()).ok,true);
  await target.query("UPDATE workspaces SET relaycast_api_key_ciphertext='synthetic-corrupt' WHERE organization_id=$1",[ORG_B]);
  const selected = {orgIds:[ORG_A]};
  const ledger = await runImport({source:sourceDb,target:targetDb,keyring:fixtureKeyring,cloudKeyHex,batchSize:2},selected,"apply");
  const report = await verifyImport(source,target,selected,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.ok,true,JSON.stringify(report.findings.filter((f) => !f.ok)));
  assert.ok(report.findings.some((f) => f.kind === "decrypt" && f.detail === "not_applicable_no_imported_rows"));
});

fixtureTest("missing rw_ target column and a rollback-mode ledger cannot qualify",async () => {
  await target.query("ALTER TABLE workspaces DROP COLUMN cloud_relay_workspace_id");
  const ledger = await apply();
  const report = await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.ok,false);
  assert.equal(report.findings.find((f) => f.name === "rw_column_present")!.ok,false);
  ledger.mode="dry-run";
  assert.equal((await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex)).findings.find((f) => f.name === "run")!.ok,false);
});

fixtureTest("legacy rw_ values normalized away by mapping still block continuity qualification",async () => {
  await source.query(`UPDATE relay_workspaces SET id='rw_legacy-01' WHERE id='rw_0000b202';
    UPDATE workspaces SET relay_workspace_id='rw_legacy-01' WHERE relay_workspace_id='rw_0000b202'`);
  const ledger = await apply();
  const report = await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(ledger.ok,true);
  assert.equal(report.findings.find((f) => f.kind === "table" && f.name === "workspaces")!.ok,true);
  assert.equal(report.findings.find((f) => f.name === "all_rw_bindings_preserved")!.ok,false);
  assert.equal(report.ok,false);
});

fixtureTest("import-ledger CLI requires explicit scope and emits a complete actual-mapping receipt",async () => {
  const ledger = await apply();
  const directory = await mkdtemp(join(tmpdir(),"import-verify-cli-"));
  try {
    const path = join(directory,"ledger.json");
    await writeFile(path,JSON.stringify(ledger),{mode:0o600});
    const url = new URL("postgresql:/");
    url.hostname=config.host;url.port=String(port);url.username=config.user;
    url.pathname="/cloud_import_source_fixture";
    const sourceUrl = url.toString();url.pathname="/cloud_import_target_fixture";
    const inherited = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^(SELFHOST_|CLOUD_IMPORT_|CLOUD_VERIFY_)/.test(name)));
    const env = {...inherited,CLOUD_VERIFY_SOURCE_URL:sourceUrl,CLOUD_VERIFY_TARGET_URL:url.toString(),
      CLOUD_IMPORT_CREDENTIAL_ENCRYPTION_KEY:cloudKeyHex,
      SELFHOST_ENCRYPTION_KEY_ID:fixtureKeyring.active.id,SELFHOST_ENCRYPTION_KEY:fixtureKeyring.active.key.toString("base64"),
      SELFHOST_ENCRYPTION_PREVIOUS_KEY_ID:"",SELFHOST_ENCRYPTION_PREVIOUS_KEY:"",SELFHOST_PASSWORD_PEPPER_FILE:""};
    const run = (args:string[]) => spawnSync(process.execPath,["--import","tsx",
      fileURLToPath(new URL("../scripts/cloud-import-verify/import-cli.ts",import.meta.url)),path,...args],
      {env,encoding:"utf8",timeout:20000});
    const passed = run(["--all-organizations"]);
    assert.equal(passed.status,0,passed.stderr);
    assert.equal(JSON.parse(passed.stdout).mappingRevision,ledger.mappingRevision);
    assert.equal(run([]).status,2);
    assert.equal(run(["--org-ids",ORG_A]).status,1);
  } finally {await rm(directory,{recursive:true,force:true});}
});
