import { credentialConvergenceCohort,captureCredentialConvergence,compareCredentialConvergence,computeCredentialCheckpoint,validateCredentialCheckpoint } from "../scripts/cloud-import-verify/convergence.js";
import { credentialCloudSelection,type SourceSelection,type TargetSelection } from "../scripts/cloud-import-verify/credential-selection.js";
import { unboundWorkspaceMarkers } from "../scripts/cloud-import-verify/unbound-markers.js";
import { beginReadOnlySnapshot } from "../scripts/cloud-import-verify/read-only.js";
import assert from "node:assert/strict";
import { before,after,beforeEach,test,type TestFn } from "node:test";
import { Client } from "pg";
import type { Database,SqlExecutor } from "../src/database.js";
import { migrate,grantRuntimeDatabaseRole } from "../src/migrations.js";
import { canonicalRelayhistoryOrigin } from "../src/relayhistory-origin.js";
import { runImport,decryptCloudEnvelope,type ImportReport } from "../scripts/cloud-import/importer.js";
import { CLOUD_FIXTURE_DDL,cloudFixtureSeed,cloudEnvelope,id,ORG_A,ORG_B } from "../scripts/cloud-import/cloud-fixture.js";
import { fixtureKeyring } from "../scripts/cloud-import-verify/fixtures.js";
import { verifyImport } from "../scripts/cloud-import-verify/import-contract.js";
import { SOURCE_TABLES,MAPPING_REVISION,TARGET_RELATIONS,verifierComparisons,encryptedSamples,type ImportScope } from "../scripts/cloud-import/mapping.js";
import { writeFile,mkdtemp,rm,readFile,stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { CodingAgentStore } from "../src/admin/coding-agents.js";
import { CredentialBlobStore,PostgresObjectBackend } from "../src/admin/credential-blobs.js";
import { SubscriptionLoginStore } from "../src/admin/subscription-logins.js";
import { copyCodingAgentCredentials } from "../scripts/cloud-import/credentials.js";
import { normalizedScope,cutoverScopeFinding,requireAllSourceScope } from "../scripts/cloud-import-verify/organization-scope.js";
import { schemaCatalog,migrationFiles,sealManifest,manifestJson,type SchemaEntry } from "../scripts/cloud-import-verify/schema.js";
import { captureCredentialTarget,credentialCopyFindings } from "../scripts/cloud-import-verify/credential-copy.js";
import { captureOwnership } from "../scripts/cloud-import-verify/reconciliation.js";
import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";

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
const apply = (selected:ImportScope=scope) => runImport(
  {source:sourceDb,target:targetDb,keyring:fixtureKeyring,cloudKeyHex,canonicalOrigin:canonicalRelayhistoryOrigin,batchSize:2},selected,"apply");
async function copiedFixture() {
  await source.query("DELETE FROM provider_credentials WHERE id=ANY($1::uuid[])",[[id(0x807),id(0x80c)]]);
  await source.query("UPDATE provider_credentials SET is_active=true WHERE id=ANY($1::uuid[])",[[id(0x80e),id(0x80f)]]);
  // Cloud object keys retain the pre-merge user id, while Control uses the survivor.
  await source.query("UPDATE provider_credentials SET user_id=$1 WHERE id=$2",[id(5),id(0x803)]);
  const ledger = await apply();
  assert.equal(ledger.ok,true,JSON.stringify(ledger.orgs));
  const jwt = (value:Record<string,unknown>) => `e30.${Buffer.from(JSON.stringify(value)).toString("base64url")}.sig`;
  const auth = JSON.stringify({auth_mode:"chatgpt",tokens:{
    access_token:jwt({exp:1893456000}),id_token:jwt({email:"alice@example.test"}),
    refresh_token:"rt-synthetic-only",account_id:"acct-synthetic-1"}});
  const objects = new Map<string,string>([
    [`${id(5)}/${id(0x803)}/credentials.json.enc`,JSON.stringify(cloudEnvelope(JSON.stringify({key:"sk-synthetic-openai-key-0000000000"}),cloudKeyHex))],
    [`${id(2)}/anthropic/credentials.json.enc`,JSON.stringify(cloudEnvelope(JSON.stringify({token:"sk-ant-oat01-synthetic-token-00000000"}),cloudKeyHex))],
    [`${id(1)}/accounts/${id(0x806)}/credentials.json.enc`,JSON.stringify(cloudEnvelope(auth,cloudKeyHex))],
    // Rows the cloud-import stack's fixture adds: an account-less legacy
    // ChatGPT login (0x810) and the claude/gemini alias keys (0x814, 0x817).
    [`${id(1)}/openai/credentials.json.enc`,JSON.stringify(cloudEnvelope(JSON.stringify({auth_mode:"chatgpt",tokens:{
      access_token:jwt({exp:1893456000}),id_token:jwt({email:"alice.legacy@example.test"}),
      refresh_token:"rt-synthetic-legacy",account_id:"acct-synthetic-legacy"}}),cloudKeyHex))],
    [`${id(2)}/${id(0x814)}/credentials.json.enc`,JSON.stringify(cloudEnvelope(JSON.stringify({key:"sk-ant-api03-synthetic-alias-0000000"}),cloudKeyHex))],
    [`${id(2)}/${id(0x817)}/credentials.json.enc`,JSON.stringify(cloudEnvelope(JSON.stringify({key:"AIza-synthetic-gemini-alias-key-000000"}),cloudKeyHex))],
    [`${id(2)}/${id(0x80b)}/credentials.json.enc`,JSON.stringify(cloudEnvelope(JSON.stringify({key:"sk-ant-api03-unselected-synthetic-00000"}),cloudKeyHex))],
    [`${id(1)}/${id(0x80d)}/credentials.json.enc`,JSON.stringify(cloudEnvelope(JSON.stringify({key:"sk-ant-api03-selected-synthetic-0000000"}),cloudKeyHex))],
    [`${id(1)}/${id(0x80e)}/credentials.json.enc`,JSON.stringify(cloudEnvelope(JSON.stringify({key:"AIza-synthetic-google-key-000000000000"}),cloudKeyHex))],
    [`${id(2)}/${id(0x80f)}/credentials.json.enc`,JSON.stringify(cloudEnvelope(JSON.stringify({key:"sk-or-v1-synthetic-router-key-0000000"}),cloudKeyHex))],
    [`${id(2)}/${id(0x808)}/credentials.json.enc`,JSON.stringify(cloudEnvelope(JSON.stringify({key:"sk-synthetic-second-key-00000000000"}),cloudKeyHex))],
  ]);
  const reader = {get:async (key:string) => objects.get(key) ?? null};
  const blobs = new CredentialBlobStore(new PostgresObjectBackend(targetDb),fixtureKeyring);
  const deps = {source:sourceDb,target:targetDb,reader,cloudKeyHex,keyring:fixtureKeyring,blobs,
    codingAgents:new CodingAgentStore(targetDb,fixtureKeyring,undefined,blobs),
    logins:new SubscriptionLoginStore(targetDb,fixtureKeyring,blobs),blobs};
  const copy = await copyCodingAgentCredentials(deps,scope,"apply");
  assert.equal(copy.ok,true,JSON.stringify(copy));
  return {ledger,copy,deps,objects,blobs,reader};
}
before(async () => {
  if (!enabled) return;
  await admin.connect();
  await admin.query("CREATE DATABASE cloud_import_source_fixture");
  await admin.query("CREATE DATABASE cloud_import_target_fixture");
  await admin.query("CREATE ROLE cloud_verify_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT");
  await source.connect();await target.connect();
});
after(async () => {if (enabled) {await source.end();await target.end();await admin.end();}});
let manifestWritten=false;
beforeEach(async () => {
  if (!enabled) return;
  // Main fixtures use UTC; the dedicated regression switches the source to Oslo.
  await source.query("SET TIME ZONE 'UTC'");await target.query("SET TIME ZONE 'UTC'");
  await source.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
  await target.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public");
  await source.query(CLOUD_FIXTURE_DDL);
  await source.query(cloudFixtureSeed(cloudKeyHex,cloudKeyHex));
  await source.query(`UPDATE relay_workspaces SET id='rw_0000b202' WHERE id='rw_legacy-01';
    UPDATE workspaces SET relay_workspace_id='rw_0000b202' WHERE relay_workspace_id='rw_legacy-01'`);
  await migrate(targetDb);
  // All checked-in migrations, including 0053/0054/0056/0057/0058/0061/0062, ran above.
  if (process.env.CLOUD_VERIFY_SCHEMA_MANIFEST_PATH && !manifestWritten) {
    await target.query("BEGIN READ ONLY");
    let required:SchemaEntry[];
    try {required=await schemaCatalog(target);} finally {await target.query("ROLLBACK");}
    const manifest=sealManifest({version:1,baseline:"control-main-b79cb5f",migrations:await migrationFiles(),required,optional:{}});
    await writeFile(process.env.CLOUD_VERIFY_SCHEMA_MANIFEST_PATH!,manifestJson(manifest));manifestWritten=true;
  }
  await target.query("INSERT INTO organizations(id,name) VALUES($1,'Synthetic operator')",[id(0xcafe)]);
  await target.query("INSERT INTO installation_bootstrap(installation_slot,organization_id) VALUES(1,$1) ON CONFLICT(installation_slot) DO UPDATE SET organization_id=EXCLUDED.organization_id",[id(0xcafe)]);
});

fixtureTest("actual importer rollback, apply and rerun reconcile all mapped tables and keep invite hashes",async () => {
  const dry = await runImport({source:sourceDb,target:targetDb,keyring:fixtureKeyring,cloudKeyHex,canonicalOrigin:canonicalRelayhistoryOrigin,batchSize:2},scope,"dry-run");
  assert.equal(dry.ok,true,JSON.stringify(dry));
  assert.equal((await target.query("SELECT count(*)::int AS n FROM users")).rows[0].n,0);
  const first = await apply();
  assert.equal(first.ok,true,JSON.stringify(first));
  assert.equal(first.tables.github_app_connections.skipped.duplicate_default_connection,1);
  const one = await verifyImport(source,target,scope,first,fixtureKeyring,cloudKeyHex);
  assert.equal(one.ok,true,JSON.stringify(one.findings.filter((f) => !f.ok)));
  assert.equal(one.findings.filter((f) => f.kind === "table").length,SOURCE_TABLES.length);
  assert.equal(one.findings.filter((f) => f.kind === "decrypt").length,encryptedSamples(20,scope).length);
  const hashes = (await target.query("SELECT id,token_hash FROM organization_invitations ORDER BY id")).rows;
  const ownership=await captureOwnership(target,scope);
  const second = await apply();
  const two = await verifyImport(source,target,scope,second,fixtureKeyring,cloudKeyHex,{previousReport:first,previousOwnership:ownership});
  assert.equal(two.ok,true,JSON.stringify(two.findings.filter((f) => !f.ok)));
  assert.deepEqual(one.findings.filter((f) => f.kind === "table"),two.findings.filter((f) => f.kind === "table"));
  const afterHashes = (await target.query("SELECT id,token_hash FROM organization_invitations ORDER BY id")).rows;
  assert.ok(JSON.stringify(hashes) === JSON.stringify(afterHashes),"rerun preserves invite hashes");
  const rw = (await target.query("SELECT cloud_relay_workspace_id,relaycast_workspace_id FROM workspaces WHERE id=$1",[id(0x201)])).rows[0];
  assert.deepEqual(rw,{cloud_relay_workspace_id:"rw_0000a201",relaycast_workspace_id:"rc-ws-a1"});
  assert.ok(one.smoke.every((s) => s.status === "pending"));
  assert.equal((await target.query("SELECT count(*)::int AS n FROM coding_agent_credentials WHERE secret_ciphertext IS NOT NULL OR harness_active")).rows[0].n,0);
  for (const table of ["token_sessions","device_authorizations","workspace_api_tokens","mcp_oauth_grants","desktop_relay_session_bindings","desktop_attestation_keys"]) {
    assert.equal((await target.query(`SELECT count(*)::int AS n FROM public.${table}`)).rows[0].n,0,`${table} remains empty`);
  }
});

fixtureTest("delta reconciles removed identities and replaced invites against previous owned keys",async () => {
  const first=await apply();assert.equal(first.ok,true);
  const ownership=await captureOwnership(target,scope);
  await source.query("DELETE FROM workspace_person_identities WHERE id=$1",[id(0x401)]);
  await source.query("UPDATE organization_invites SET canceled_at=now() WHERE id=$1",[id(0x302)]);
  const second=await apply();
  assert.equal(second.ok,true,JSON.stringify(second.orgs));
  assert.equal(second.tables.person_identities.deleted,1);
  assert.equal(second.tables.organization_invitations.deleted,1);
  const report=await verifyImport(source,target,scope,second,fixtureKeyring,cloudKeyHex,{previousReport:first,previousOwnership:ownership});
  assert.equal(report.ok,true,JSON.stringify(report.findings.filter((f) => !f.ok)));
  assert.equal((await target.query("SELECT count(*)::int AS n FROM person_identities WHERE id=$1",[id(0x401)])).rows[0].n,0);
  assert.equal((await verifyImport(source,target,scope,second,fixtureKeyring,cloudKeyHex)).ok,false,"deletes require a previous ledger");
  const bad=structuredClone(second);bad.tables.person_identities.deleted=0;
  const tampered=await verifyImport(source,target,scope,bad,fixtureKeyring,cloudKeyHex,{previousReport:first,previousOwnership:ownership});
  assert.equal(tampered.findings.find((f) => f.kind === "deleted_total" && f.name === "person_identities")!.ok,false);
});

fixtureTest("cascade removals must be included in logical deleted counts",async () => {
  const first=await apply();assert.equal(first.ok,true);
  const ownership=await captureOwnership(target,scope);
  await source.query("UPDATE organization_memberships SET status='suspended' WHERE organization_id=$1 AND user_id=$2",[ORG_A,id(2)]);
  const second=await apply();assert.equal(second.ok,true,JSON.stringify(second.orgs));
  assert.equal(second.tables.desktop_relay_identities.deleted,1,"actual importer accounts for cascade removals");
  assert.equal((await verifyImport(source,target,scope,second,fixtureKeyring,cloudKeyHex,
    {previousReport:first,previousOwnership:ownership})).ok,true);
  assert.equal((await target.query("SELECT count(*)::int AS n FROM desktop_relay_identities WHERE id=$1",[id(0x602)])).rows[0].n,0);
  const undercount=structuredClone(second);
  undercount.orgs[ORG_A]!.deleted.desktop_relay_identities=0;undercount.tables.desktop_relay_identities.deleted=0;
  const rejected=await verifyImport(source,target,scope,undercount,fixtureKeyring,cloudKeyHex,{previousReport:first,previousOwnership:ownership});
  assert.equal(rejected.findings.find((f) => f.kind === "deletions" && f.name === `${ORG_A}:desktop_relay_identities`)!.ok,false);
  const accounted=structuredClone(second);
  accounted.orgs[ORG_A]!.deleted.desktop_relay_identities=1;accounted.tables.desktop_relay_identities.deleted=1;
  assert.equal((await verifyImport(source,target,scope,accounted,fixtureKeyring,cloudKeyHex,{previousReport:first,previousOwnership:ownership})).ok,true);
});

fixtureTest("current manifests cannot substitute invented keys with matching row counts",async () => {
  const ledger=await apply();
  ledger.orgs[ORG_A]!.keys.desktop_relay_identities![0]=id(0x9999);
  const report=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.findings.find((f) => f.kind === "table" && f.name === "desktop_relay_identities")!.ok,true);
  assert.equal(report.findings.find((f) => f.kind === "ledger_keys" && f.name === `${ORG_A}:desktop_relay_identities`)!.ok,false);
  assert.equal(report.ok,false);
});

fixtureTest("0063 ownership ledger is readable by owner and denied to runtime",async () => {
  const ledger=await apply();assert.equal(ledger.ok,true);
  assert.ok((await captureOwnership(target,scope)).rows.length > 0);
  await grantRuntimeDatabaseRole(targetDb,"cloud_verify_runtime");
  await target.query("SET ROLE cloud_verify_runtime");
  try {
    assert.ok((await target.query("SELECT count(*)::int AS n FROM users")).rows[0].n > 0);
    await assert.rejects(target.query("SELECT * FROM cloud_import_ledger"),{code:"42501"});
    await assert.rejects(target.query("DELETE FROM cloud_import_ledger WHERE false"),{code:"42501"});
  } finally {await target.query("RESET ROLE");}
});

fixtureTest("persisted ownership revisions and keys must match the imported data",async () => {
  const ledger=await apply();
  await target.query("UPDATE cloud_import_ledger SET mapping_revision='cloud-identity-2000-01-01.0' WHERE table_name='desktop_relay_identities' AND row_key=$1",[id(0x601)]);
  const stale=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(stale.findings.find((f) => f.kind === "ownership_ledger")!.ok,false);
  await target.query("UPDATE cloud_import_ledger SET mapping_revision=$1",[MAPPING_REVISION]);
  await target.query("DELETE FROM cloud_import_ledger WHERE table_name='desktop_relay_identities' AND row_key=$1",[id(0x601)]);
  const missing=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(missing.findings.find((f) => f.kind === "table" && f.name === "desktop_relay_identities")!.ok,false);
  assert.equal(missing.findings.find((f) => f.kind === "ownership_ledger")!.ok,false);
});

fixtureTest("rerun never deletes or claims a Control row absent from the ownership ledger",async () => {
  const first=await apply();const ownership=await captureOwnership(target,scope);
  await target.query(`INSERT INTO organization_invitations(id,organization_id,email,role,token_hash,expires_at)
    VALUES($1,$2,'control-only@example.test','member',repeat('f',64),'2030-01-01T00:00:00Z')`,[id(0xc0ffee),ORG_A]);
  const second=await apply();assert.equal(second.ok,true);
  assert.equal((await target.query("SELECT count(*)::int AS n FROM organization_invitations WHERE id=$1",[id(0xc0ffee)])).rows[0].n,1);
  assert.equal((await target.query("SELECT count(*)::int AS n FROM cloud_import_ledger WHERE row_key=$1",[id(0xc0ffee)])).rows[0].n,0);
  const report=await verifyImport(source,target,scope,second,fixtureKeyring,cloudKeyHex,{previousReport:first,previousOwnership:ownership});
  assert.equal(report.findings.find((f) => f.kind === "ownership_ledger")!.ok,true);
  assert.equal(report.findings.find((f) => f.kind === "table" && f.name === "organization_invitations")!.ok,true);
});

fixtureTest("dedicated canonical-origin checks detect drift without printing private hosts",async () => {
  const ledger=await apply();
  const marker="tampered-private-origin.example.test";
  await target.query("UPDATE workspaces SET relayhistory_origin=$1 WHERE id=$2",[`https://${marker}`,id(0x201)]);
  ledger.relayhistoryOrigins=[`https://${marker}`];
  const report=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.findings.find((f) => f.kind === "table" && f.name === "workspaces")!.ok,true);
  assert.equal(report.findings.find((f) => f.kind === "canonical_history_origins")!.ok,false);
  assert.ok(!JSON.stringify(report).includes(marker));
});

fixtureTest("actual 0062 origins use Control canonicalization before import and verification",async () => {
  await source.query("UPDATE workspaces SET relayhistory_origin=$1 WHERE id=$2",["https://HISTORY.Example.test.:443/",id(0x201)]);
  const ledger=await apply();assert.equal(ledger.ok,true);
  assert.equal((await target.query("SELECT relayhistory_origin FROM workspaces WHERE id=$1",[id(0x201)])).rows[0].relayhistory_origin,"https://history.example.test");
  const report=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.ok,true,JSON.stringify(report.findings.filter((f) => !f.ok)));
  assert.equal(report.findings.find((f) => f.kind === "canonical_history_origins")!.ok,true);
});

fixtureTest("staff grants are revoked history with a stable fresh hash and one import audit",async () => {
  const first=await apply();assert.equal(first.ok,true);
  const stored=(await target.query("SELECT token_hash,revoked_at,staff_user_id,staff_organization_id FROM staff_read_grants WHERE id=$1",[id(0xa01)])).rows[0];
  assert.match(stored.token_hash,/^[0-9a-f]{64}$/);assert.ok(stored.revoked_at);
  assert.equal(stored.staff_user_id,id(1));assert.equal(stored.staff_organization_id,id(0xcafe));
  const second=await apply();
  assert.deepEqual((await target.query("SELECT token_hash,revoked_at,staff_user_id,staff_organization_id FROM staff_read_grants WHERE id=$1",[id(0xa01)])).rows[0],stored);
  assert.equal((await verifyImport(source,target,scope,second,fixtureKeyring,cloudKeyHex)).ok,true);
  await target.query("UPDATE staff_read_grants SET revoked_at=NULL WHERE id=$1",[id(0xa01)]);
  const report=await verifyImport(source,target,scope,second,fixtureKeyring,cloudKeyHex);
  assert.equal(report.findings.find((f) => f.kind === "table" && f.name === "staff_read_grants")!.ok,true);
  assert.equal(report.findings.find((f) => f.kind === "staff_grant_history")!.ok,false);
});

fixtureTest("older source without staff grants reports explicit absence and verifies other tables",async () => {
  await source.query("DROP TABLE staff_read_grants");
  const ledger=await apply();assert.equal(ledger.warnings.source_lacks_staff_read_grants,1);
  const report=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.ok,true,JSON.stringify(report.findings.filter((f) => !f.ok)));
  assert.equal(report.findings.find((f) => f.kind === "source_availability")!.ok,true);
});

fixtureTest("staff grants require an operator organization and a target without 0061 halts on its schema",async () => {
  await target.query("UPDATE installation_bootstrap SET organization_id=NULL");
  const noOperator=await apply();
  assert.equal(noOperator.tables.staff_read_grants.skipped.no_operator_organization,1);
  const one=await verifyImport(source,target,scope,noOperator,fixtureKeyring,cloudKeyHex);
  assert.equal(one.findings.find((f) => f.kind === "ledger" && f.name === "staff_read_grants")!.ok,true);
  assert.equal(one.ok,false);
  await target.query("DROP TABLE staff_read_grants");
  const noSchema=await apply();
  assert.equal(noSchema.tables.staff_read_grants.skipped.target_lacks_staff_read_grants,1);
  const two=await verifyImport(source,target,scope,noSchema,fixtureKeyring,cloudKeyHex);
  assert.equal(two.findings.find((f) => f.kind === "schema_manifest")!.ok,false);
  assert.ok(two.targetSchema.missing.includes("table:public.staff_read_grants"));
  assert.equal(two.ok,false);
});

fixtureTest("unrecognized ledger annotations never enter a verification report",async () => {
  const ledger=await apply();
  const marker="private-ledger-annotation-must-stay-local";
  Object.assign(ledger.tables.users,{annotation:marker});Object.assign(ledger.orgs[ORG_A]!,{annotation:marker});
  const report=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.ok,true);
  assert.ok(!JSON.stringify(report).includes(marker));
});

fixtureTest("new person/hosted membership and Desktop control-character skips reconcile",async () => {
  await source.query("UPDATE desktop_relay_identities SET source_id=$1 WHERE id=$2",["opaque\ncontrol",id(0x602)]);
  const ledger=await apply();
  assert.equal(ledger.tables.person_identities.skipped.not_a_member,1);
  assert.equal(ledger.tables.hosted_relay_participants.skipped.not_a_member,1);
  assert.equal(ledger.tables.desktop_relay_identities.skipped.source_id_control_character,1);
  const report=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.ok,true,JSON.stringify(report.findings.filter((f) => !f.ok)));
});

fixtureTest("copied credential natural keys verify reminted IDs, encrypted blobs, reruns and local CLI",async () => {
  const fixture = await copiedFixture();
  const evidence = {report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs};
  const first = await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,{credentialCopy:evidence});
  assert.equal(first.ok,true,JSON.stringify(first.findings.filter((f) => !f.ok)));
  assert.equal(first.credentialCopy,"verified");
  const copiedRows = (await target.query("SELECT id FROM coding_agent_credentials WHERE auth_type <> 'relay_managed'")).rows;
  assert.equal(copiedRows.length,8);
  assert.ok(copiedRows.every((row) => ![id(0x803),id(0x805),id(0x806),id(0x808)].includes(row.id)));
  await target.query("UPDATE coding_agent_credentials SET id=$1 WHERE auth_type='byo_api_key' AND model_provider='openai' AND workspace_id=$2",[id(0xdeadbeef),id(0x201)]);
  fixture.copy.controlIds[id(0x803)]=id(0xdeadbeef);
  assert.equal((await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,{credentialCopy:evidence})).ok,true);
  const again = await copyCodingAgentCredentials(fixture.deps,scope,"apply");
  const report = await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{...evidence,report:again}});
  assert.equal(report.ok,true,JSON.stringify(report.findings.filter((f) => !f.ok)));
  assert.deepEqual(report.findings.find((f) => f.kind === "credential_natural_keys"),first.findings.find((f) => f.kind === "credential_natural_keys"));
  if (process.env.CLOUD_VERIFY_IMPORT_REPORT_PATH) await writeFile(process.env.CLOUD_VERIFY_IMPORT_REPORT_PATH,
    `${JSON.stringify({...report,evidenceKind:"synthetic-local-postgres",credentialCopyVerified:true},null,2)}\n`,{mode:0o600});

  const directory = await mkdtemp(join(tmpdir(),"copy-verifier-cli-"));
  try {
    const objectRoot = join(directory,"objects");await mkdir(objectRoot,{mode:0o700});
    for (const [key,body] of fixture.objects) {
      const path = join(objectRoot,key);await mkdir(dirname(path),{recursive:true,mode:0o700});
      await writeFile(path,body,{mode:0o600});
    }
    const ledgerPath=join(directory,"ledger.json"),copyPath=join(directory,"copy.json");
    await writeFile(ledgerPath,JSON.stringify(fixture.ledger),{mode:0o600});
    await writeFile(copyPath,JSON.stringify(again),{mode:0o600});
    const url = new URL("postgresql:/");url.hostname=config.host;url.port=String(port);url.username=config.user;
    url.pathname="/cloud_import_source_fixture";const sourceUrl=url.toString();url.pathname="/cloud_import_target_fixture";
    const inherited=Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^(SELFHOST_|CLOUD_IMPORT_|CLOUD_VERIFY_|CLOUD_CREDENTIAL_)/.test(name)));
    const baselinePath=join(directory,"credential-baseline.json");await writeFile(baselinePath,"{}",{mode:0o644});
    const captured=spawnSync(process.execPath,["--import","tsx",fileURLToPath(new URL("../scripts/cloud-import-verify/credential-snapshot-cli.ts",import.meta.url)),
      baselinePath,"--all-organizations"],{encoding:"utf8",timeout:20000,env:{...inherited,CLOUD_VERIFY_TARGET_URL:url.toString()}});
    assert.equal(captured.status,0,captured.stderr);assert.equal((await stat(baselinePath)).mode & 0o077,0);
    const baseline=await readFile(baselinePath,"utf8");
    assert.equal(JSON.parse(baseline).rows.length,8);assert.ok(!/acct-|sk-|fingerprint|account_email/.test(baseline));
    const child=spawnSync(process.execPath,["--import","tsx",fileURLToPath(new URL("../scripts/cloud-import-verify/import-cli.ts",import.meta.url)),
      ledgerPath,"--all-organizations","--credential-copy-report",copyPath,"--previous-credentials",baselinePath],{encoding:"utf8",timeout:20000,env:{...inherited,
      CLOUD_VERIFY_SOURCE_URL:sourceUrl,CLOUD_VERIFY_TARGET_URL:url.toString(),CLOUD_VERIFY_CREDENTIAL_OBJECTS_DIR:objectRoot,
      CLOUD_CREDENTIAL_ENCRYPTION_KEY:cloudKeyHex,SELFHOST_ENCRYPTION_KEY_ID:fixtureKeyring.active.id,
      SELFHOST_ENCRYPTION_KEY:fixtureKeyring.active.key.toString("base64")}});
    assert.equal(child.status,0,child.stderr);
    assert.equal(JSON.parse(child.stdout).ok,true);
  } finally {await rm(directory,{recursive:true,force:true});}
});

fixtureTest("copy report Control IDs must resolve to independently derived natural keys",async () => {
  const fixture=await copiedFixture();
  fixture.copy.controlIds[id(0x803)]=fixture.copy.controlIds[id(0x805)]!;
  const one=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(one.findings.find((f) => f.kind === "credential_natural_keys")!.ok,true);
  assert.equal(one.findings.find((f) => f.kind === "credential_control_ids")!.ok,false);
  fixture.copy.controlIds[id(0x803)]="private-control-id-must-not-echo";
  fixture.copy.controlIds[id(0x809)]=fixture.copy.controlIds[id(0x805)]!;
  const two=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(two.credentialCopy,"failed");assert.ok(!JSON.stringify(two).includes("private-control-id-must-not-echo"));
});

fixtureTest("latest Cloud selection wins across users and demotion counters reconcile",async () => {
  const fixture=await copiedFixture();
  await source.query("UPDATE provider_credentials SET is_active=true,updated_at='2027-01-01T00:00:00Z' WHERE id=$1",[id(0x80b)]);
  const copy=await copyCodingAgentCredentials(fixture.deps,scope,"apply");
  assert.equal(copy.selection!.activeDemoted,1);
  const report=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(report.ok,true,JSON.stringify(report.findings.filter((f) => !f.ok)));
  copy.selection!.activeDemoted=0;
  assert.equal((await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:copy,reader:fixture.reader,targetBlobs:fixture.blobs}})).findings.find((f) => f.kind === "credential_cloud_selection")!.ok,false);
});

fixtureTest("wrong Cloud credential selection fails even with unchanged cardinality and content",async () => {
  const fixture=await copiedFixture();
  const rows=(await target.query("SELECT id,is_active FROM coding_agent_credentials WHERE workspace_id=$1 AND model_provider='anthropic' AND auth_type='byo_api_key'",[id(0x201)])).rows;
  const inactive=rows.find((row) => !row.is_active)!;
  await target.query("UPDATE coding_agent_credentials SET is_active=false WHERE workspace_id=$1 AND model_provider='anthropic'",[id(0x201)]);
  await target.query("UPDATE coding_agent_credentials SET is_active=true WHERE id=$1",[inactive.id]);
  const report=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.ok(report.findings.filter((f) => f.kind === "credential_selection").every((f) => f.ok));
  assert.equal(report.findings.find((f) => f.kind === "credential_natural_keys")!.ok,true);
  assert.equal(report.findings.find((f) => f.kind === "credential_cloud_selection")!.ok,false);
});

fixtureTest("written-only consumer preserves a real Control-deactivated login on an untouched rerun",async () => {
  const fixture=await copiedFixture();
  const login=fixture.copy.controlIds[id(0x806)]!;
  await target.query("UPDATE coding_agent_credentials SET harness_active=false WHERE id=$1",[login]);
  const flags=async () => new Map((await target.query("SELECT id,workspace_id,model_provider,is_active,harness_active FROM coding_agent_credentials")).rows
    .map((row) => [row.id,{group:`${row.workspace_id}:${row.model_provider}`,active:row.is_active,harness:row.harness_active}] as [string,TargetSelection]));
  const baseline=await flags();
  const sourceRows=new Map((await source.query("SELECT * FROM provider_credentials")).rows.map((row) => [row.id,row]));
  const entries:SourceSelection[]=Object.entries(fixture.copy.controlIds).map(([sourceId,controlId]) => {
    const row=sourceRows.get(sourceId)!;
    return {id:sourceId,key:controlId,group:baseline.get(controlId)!.group,active:row.is_active,
      harness:row.harness_active && ["oauth_token","provider_oauth"].includes(row.auth_type),updated:new Date(row.updated_at).getTime()};
  });
  const check=async () => {
    const current=await flags();
    return credentialCloudSelection({revision:"cloud-identity-2026-11-16.25",entries,
      outcomes:Object.fromEntries(entries.map((row) => [row.id,"already_present"])),flags:current,
      nativeFlags:new Map(),baseline,allFlags:[...current.values()],unchangedKeys:new Set(),reported:undefined});
  };
  assert.equal((await check()).ok,true);
  await target.query("UPDATE coding_agent_credentials SET harness_active=true WHERE id=$1",[login]);
  assert.equal((await check()).ok,false,"re-activating an untouched login fails independently of the producer's empty selection summary");
});

fixtureTest("retained workspace binding warnings do not waive visible comparison drift",async () => {
  const ledger=await apply();
  ledger.warnings.workspaces_binding_conflict=1;
  ledger.warnings.workspaces_generation_kept=1;
  await target.query("UPDATE workspaces SET relaycast_workspace_id='synthetic-retained-provider-binding' WHERE id=$1",[id(0x201)]);
  const report=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.ok,false);
  assert.equal(report.findings.find((finding) => finding.kind === "table" && finding.name === "workspaces")!.ok,false);
});

fixtureTest("unselected copied credentials preserve native selections and report fallback conflicts",async () => {
  const fixture=await copiedFixture();
  await source.query("UPDATE provider_credentials SET is_active=false WHERE id=ANY($1::uuid[])",[[id(0x80e),id(0x80f)]]);
  const native=await fixture.deps.codingAgents.putApiKey({workspaceId:id(0x201),organizationId:ORG_A,
    modelProvider:"google",key:"AIza-native-synthetic-google-key-000000",label:"Synthetic native",actor:{kind:"user",userId:id(1)}});
  await fixture.deps.codingAgents.activate({workspaceId:id(0x201),organizationId:ORG_A,id:native.record.id,
    selection:"model",actor:{kind:"user",userId:id(1)}});
  const previousTarget=await captureCredentialTarget(target,scope);
  const copy=await copyCodingAgentCredentials(fixture.deps,scope,"apply");
  assert.equal(copy.selection!.selectionConflicts,1);
  assert.equal((await target.query("SELECT is_active FROM coding_agent_credentials WHERE id=$1",[native.record.id])).rows[0].is_active,true);
  const conflict=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:copy,reader:fixture.reader,targetBlobs:fixture.blobs,previousTarget}});
  assert.equal(conflict.findings.find((f) => f.kind === "credential_natural_keys")!.ok,true);
  assert.equal(conflict.findings.find((f) => f.kind === "credential_cloud_selection")!.ok,false);
  await source.query("UPDATE provider_credentials SET is_active=true WHERE id=$1",[id(0x80f)]);
  const resolved=await copyCodingAgentCredentials(fixture.deps,scope,"apply");
  const passed=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:resolved,reader:fixture.reader,targetBlobs:fixture.blobs,previousTarget}});
  assert.equal(passed.ok,true,JSON.stringify(passed.findings.filter((f) => !f.ok)));
  const withoutBaseline=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:resolved,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(withoutBaseline.findings.find((f) => f.kind === "credential_natural_keys")!.ok,false);
  resolved.selection!.active++;
  assert.equal((await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:resolved,reader:fixture.reader,targetBlobs:fixture.blobs,previousTarget}})).findings.find((f) => f.kind === "credential_cloud_selection")!.ok,false);
});

fixtureTest("ambiguous legacy objects are never used and cannot qualify a credential copy",async () => {
  const fixture=await copiedFixture();
  await source.query(`INSERT INTO provider_credentials SELECT $1,organization_id,workspace_id,user_id,harness,model_provider,
    auth_type,label,key_fingerprint,display_name,account_email,$2,is_active,harness_active,status,refresh_exhausted,
    last_authenticated_at,last_used_at,last_error,created_at,updated_at FROM provider_credentials WHERE id=$3`,[id(0x80c),"acct-synthetic-2",id(0x806)]);
  const reads:string[]=[];
  const reader={get:async (key:string) => {reads.push(key);return fixture.objects.get(key) ?? null;}};
  const copy=await copyCodingAgentCredentials({...fixture.deps,reader},scope,"apply");
  assert.equal(copy.rows[id(0x80c)],"skipped:legacy_key_ambiguous");
  assert.ok(!reads.includes(`${id(1)}/openai/credentials.json.enc`));
  const report=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:copy,reader,targetBlobs:fixture.blobs}});
  assert.equal(report.findings.find((f) => f.kind === "credential_copy_ledger")!.ok,true);
  assert.equal(report.credentialCopy,"failed");
});

fixtureTest("a copy with only intentional exclusions needs no selection report",async () => {
  const fixture=await copiedFixture();
  await source.query("UPDATE provider_credentials SET status='error' WHERE auth_type <> 'relay_managed'");
  const copy=await copyCodingAgentCredentials(fixture.deps,scope,"apply");
  assert.equal(copy.selection,undefined);
  const previousTarget=await captureCredentialTarget(target,scope);
  const report=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:copy,reader:fixture.reader,targetBlobs:fixture.blobs,previousTarget}});
  assert.equal(report.credentialCopy,"verified",JSON.stringify(report.findings.filter((f) => !f.ok)));
});

fixtureTest("zero active credentials fails exact model/harness selection cardinality",async () => {
  const fixture=await copiedFixture();
  await target.query("UPDATE coding_agent_credentials SET is_active=false WHERE model_provider='openai'");
  const report=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(report.findings.find((f) => f.kind === "credential_natural_keys")!.ok,true);
  assert.ok(report.findings.some((f) => f.kind === "credential_selection" && !f.ok));
  assert.equal(report.ok,false);
});

fixtureTest("equal-count credential fingerprint or blob corruption fails natural-key/content checks",async () => {
  const fixture=await copiedFixture();
  await target.query("UPDATE coding_agent_credentials SET blob_backend='s3' WHERE auth_type='provider_oauth'");
  const backendMismatch=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(backendMismatch.credentialCopy,"failed");
  const backendDetail=backendMismatch.findings.find((f) => f.kind === "credential_natural_keys")!.detail as {contentFailureReasons:Record<string,number>};
  assert.ok(backendDetail.contentFailureReasons.blobBackendMismatch! > 0);
  assert.equal(backendDetail.contentFailureReasons.targetReadOrDecryptFailed,0);
  await target.query("UPDATE coding_agent_credentials SET blob_backend='postgres' WHERE auth_type='provider_oauth'");
  await target.query("UPDATE coding_agent_credentials SET key_fingerprint=repeat('0',64) WHERE auth_type='byo_api_key' AND model_provider='openai' AND workspace_id=$1",[id(0x201)]);
  await target.query("UPDATE coding_agent_credentials SET key_fingerprint=repeat('0',64) WHERE auth_type='provider_oauth'");
  await target.query("UPDATE coding_agent_credential_blobs SET envelope='{}'");
  const report=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(report.ok,false);
  assert.equal(report.credentialCopy,"failed");
  assert.equal(report.findings.find((f) => f.kind === "credential_natural_keys")!.ok,false);
  const reasons=(report.findings.find((f) => f.kind === "credential_natural_keys")!.detail as {contentFailureReasons:Record<string,number>}).contentFailureReasons;
  assert.ok(reasons.fingerprintMismatch! > 0);assert.ok(reasons.targetReadOrDecryptFailed! > 0);
  assert.ok(!JSON.stringify(report).includes("rt-synthetic-only"));
  assert.ok(!JSON.stringify(report).includes("sk-synthetic"));
});

fixtureTest("missing Cloud credential objects and a plan report cannot qualify copied secrets",async () => {
  const fixture=await copiedFixture();
  fixture.objects.delete(`${id(2)}/${id(0x808)}/credentials.json.enc`);
  const copy=await copyCodingAgentCredentials(fixture.deps,scope,"apply");
  const report=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(report.ok,false);
  copy.mode="plan";
  assert.equal((await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:copy,reader:fixture.reader,targetBlobs:fixture.blobs}})).findings.find((f) => f.kind === "credential_copy_ledger")!.ok,false);
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
  ledger.tables.person_identities.importerSkips.cloud_decrypt_failed = [id(0x401)];
  const tampered = await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(tampered.findings.find((f) => f.kind === "ledger" && f.name === "person_identities")!.ok,false);
  assert.equal(tampered.findings.find((f) => f.kind === "table" && f.name === "person_identities")!.ok,true);
});

fixtureTest("target without relay_managed support accounts for coding credential keys and blocks qualification",async () => {
  await target.query(`ALTER TABLE coding_agent_credentials
    DROP CONSTRAINT coding_agent_auth_type,DROP CONSTRAINT coding_agent_secret_storage,
    ADD CONSTRAINT coding_agent_auth_type CHECK(auth_type IN ('byo_api_key','oauth_token','provider_oauth')),
    ADD CONSTRAINT coding_agent_secret_storage CHECK(
      (auth_type='provider_oauth' AND secret_ciphertext IS NULL AND blob_location IS NOT NULL)
      OR (auth_type <> 'provider_oauth' AND secret_ciphertext IS NOT NULL))`);
  const ledger = await apply();
  assert.equal(ledger.tables.coding_agent_credentials.skipped.target_lacks_relay_managed,2);
  assert.equal(ledger.tables.coding_agent_credentials.importerSkips.target_lacks_relay_managed!.length,2);
  const report = await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.findings.find((f) => f.kind === "schema_manifest")!.ok,false);
  assert.ok(report.targetSchema.changed.some((name) => name.includes("coding_agent_auth_type")));
  assert.equal(report.ok,false);
});

fixtureTest("opaque Desktop source IDs preserve case and a lowercase target corruption fails",async () => {
  await source.query("UPDATE desktop_relay_identities SET source_id='Opaque-Case-Source' WHERE id=$1",[id(0x602)]);
  const ledger = await apply();
  assert.equal((await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex)).ok,true);
  await target.query("UPDATE desktop_relay_identities SET source_id=lower(source_id) WHERE id=$1",[id(0x602)]);
  const report = await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.findings.find((f) => f.kind === "table" && f.name === "desktop_relay_identities")!.ok,false);
});

fixtureTest("history origins dropped by normalization cannot silently qualify a workspace",async () => {
  await source.query("UPDATE workspaces SET relayhistory_origin='https://history.example.test/path' WHERE id=$1",[id(0x201)]);
  const ledger = await apply();
  const report = await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(ledger.warnings.relayhistory_origin_invalid_dropped,1);
  assert.equal(report.findings.find((f) => f.kind === "table" && f.name === "workspaces")!.ok,true);
  assert.equal(report.findings.find((f) => f.name === "workspace_metadata_preserved")!.ok,false);
  assert.equal(report.ok,false);
});

fixtureTest("pre-0057 non-UUID Desktop source IDs remain visible as unresolved importer skips",async () => {
  await target.query("ALTER TABLE desktop_relay_identities ALTER COLUMN source_id TYPE uuid USING source_id::uuid");
  await target.query("ALTER TABLE fleet_node_owners ALTER COLUMN node_name SET NOT NULL");
  const ledger = await apply();
  assert.equal(ledger.tables.desktop_relay_identities.skipped.source_id_not_uuid,1);
  const report = await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.findings.find((f) => f.kind === "schema_manifest")!.ok,false);
  assert.ok(report.targetSchema.changed.includes("column:public.desktop_relay_identities.source_id"));
  assert.equal(report.ok,false);
});

fixtureTest("cohort scope counts and encrypted samples exclude another org's corrupt key",async () => {
  const first=await apply();assert.equal(first.ok,true);
  const ownership=await captureOwnership(target,scope);
  await target.query("UPDATE workspaces SET relaycast_api_key_ciphertext='synthetic-corrupt' WHERE organization_id=$1",[ORG_B]);
  const selected = {orgIds:[ORG_A]};
  const ledger = await runImport({source:sourceDb,target:targetDb,keyring:fixtureKeyring,cloudKeyHex,canonicalOrigin:canonicalRelayhistoryOrigin,batchSize:2},selected,"apply");
  const report = await verifyImport(source,target,selected,ledger,fixtureKeyring,cloudKeyHex,{previousReport:first,previousOwnership:ownership});
  assert.equal(report.ok,true,JSON.stringify(report.findings.filter((f) => !f.ok)));
  assert.ok(report.findings.some((f) => f.kind === "decrypt" && f.detail === "not_applicable_no_imported_rows"));
});

fixtureTest("zero-source gated tables still require the committed target schema",async () => {
  await source.query("DELETE FROM workspace_integrations WHERE provider='github'");
  const ledger=await apply();
  const before=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(before.ok,true);assert.equal(ledger.tables.github_app_installations.candidates,0);
  await target.query("DROP TABLE github_app_installations CASCADE");
  const after=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(after.ok,false);assert.equal(after.findings.find((f) => f.kind === "schema_manifest")!.ok,false);
  assert.ok(after.targetSchema.missing.includes("table:public.github_app_installations"));
  assert.ok(!after.findings.some((f) => f.kind === "table"),"unsafe data checks stop after missing table");
});

fixtureTest("missing and weakened selector indexes fail independently of credential rows",async () => {
  await source.query("DELETE FROM provider_credentials");
  const ledger=await apply();
  assert.equal((await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex)).ok,true);
  await target.query("DROP INDEX coding_agent_one_llm");
  const missing=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(missing.ok,false);
  assert.ok(missing.targetSchema.missing.includes("index:public.coding_agent_credentials.coding_agent_one_llm"));
  await target.query("CREATE UNIQUE INDEX coding_agent_one_llm ON coding_agent_credentials(workspace_id,model_provider) WHERE false");
  const weakened=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(weakened.ok,false);
  assert.ok(weakened.targetSchema.changed.includes("index:public.coding_agent_credentials.coding_agent_one_llm"));
});

fixtureTest("missing constraints fail with empty tables",async () => {
  await source.query("DELETE FROM workspace_integrations WHERE provider='github'");
  const ledger=await apply();
  await target.query("ALTER TABLE github_app_installations DROP CONSTRAINT github_app_installations_pkey CASCADE");
  const missing=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(missing.ok,false);
  assert.ok(missing.targetSchema.missing.includes("constraint:public.github_app_installations.github_app_installations_pkey"));
});

fixtureTest("disabled FK triggers fail independently of row counts",async () => {
  await source.query("DELETE FROM organization_invites");const ledger=await apply();
  assert.equal((await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex)).ok,true);
  await target.query("ALTER TABLE organization_invitations DISABLE TRIGGER ALL");
  const triggers=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(triggers.ok,false);
  assert.ok(triggers.targetSchema.changed.some((name) => name.startsWith("constraint:public.organization_invitations.")));
});

fixtureTest("weakened column definitions fail with zero source rows",async () => {
  await source.query("DELETE FROM workspace_integrations WHERE provider='github'");const ledger=await apply();
  assert.equal((await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex)).ok,true);
  await target.query("ALTER TABLE github_app_installations ALTER COLUMN organization_id DROP NOT NULL");
  const after=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(after.ok,false);assert.ok(after.targetSchema.changed.includes("column:public.github_app_installations.organization_id"));
});

fixtureTest("changed CHECK validator functions fail without leaking their bodies",async () => {
  const ledger=await apply();assert.equal((await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex)).ok,true);
  await target.query("CREATE OR REPLACE FUNCTION relayhistory_origin_is_canonical(origin text) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT AS 'SELECT true /* private-schema-definition-must-not-echo */'");
  const after=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(after.ok,false);assert.ok(after.targetSchema.changed.some((name) => name.startsWith("function:") && name.includes("relayhistory_origin_is_canonical")));
  assert.ok(!JSON.stringify(after).includes("private-schema-definition-must-not-echo"));
});

fixtureTest("unexpected non-extension schema objects fail without exposing their names",async () => {
  const ledger=await apply();assert.equal((await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex)).ok,true);
  await target.query('CREATE TABLE "private-unreviewed-schema-object"(value text)');
  const after=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(after.ok,false);assert.ok(after.targetSchema.unexpectedCount > 0);
  assert.ok(!JSON.stringify(after).includes("private-unreviewed-schema-object"));
});

fixtureTest("subset reports bind normalized scope and a census outside that scope",async () => {
  const selected={orgIds:[ORG_A]};const ledger=await apply(selected);
  const one=await verifyImport(source,target,{orgIds:[ORG_A.toUpperCase(),ORG_A]},ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(one.ok,true,JSON.stringify(one.findings.filter((f) => !f.ok)));
  assert.deepEqual(one.scope,normalizedScope(selected));
  assert.equal(one.sourceOrganizationCensus.all.count,2);assert.equal(one.sourceOrganizationCensus.selected.count,1);
  await source.query("INSERT INTO organizations(id,slug,name,created_by_user_id,created_at,updated_at) VALUES($1,'unselected-census','Synthetic outside scope',$2,now(),now())",[id(0xc3),id(1)]);
  const two=await verifyImport(source,target,selected,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(two.ok,true);assert.equal(two.sourceOrganizationCensus.all.count,3);
  assert.notEqual(two.sourceOrganizationCensus.all.sha256,one.sourceOrganizationCensus.all.sha256);
  assert.equal(two.sourceOrganizationCensus.selected.sha256,one.sourceOrganizationCensus.selected.sha256);
  assert.equal(cutoverScopeFinding(two).ok,false);
});

fixtureTest("gated-table visibility cannot hide absent SELECT privileges",async () => {
  await source.query("DELETE FROM workspace_integrations WHERE provider='github'");
  const ledger=await apply();
  await grantRuntimeDatabaseRole(targetDb,"cloud_verify_runtime");
  await target.query("GRANT SELECT ON cloud_import_ledger TO cloud_verify_runtime");
  await target.query("REVOKE ALL ON github_app_installations FROM cloud_verify_runtime");
  await target.query("SET ROLE cloud_verify_runtime");
  try {await assert.rejects(verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex),(error:Error & {code?:string}) => {
    assert.equal(error.code,"42501");assert.match(error.message,/github_app_installations/);return true;
  });}
  finally {await target.query("RESET ROLE");}
});

fixtureTest("all-source scope and the production manifest bind successful copier evidence",async () => {
  const fixture=await copiedFixture();
  const report=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(report.ok,true,JSON.stringify(report.findings.filter((f) => !f.ok)));
  assert.equal(report.targetSchema.profile,"main");assert.equal(report.targetSchema.ok,true);
  assert.deepEqual(report.scope,{orgIds:null});
  assert.deepEqual(report.sourceOrganizationCensus.all,report.sourceOrganizationCensus.selected);
  assert.equal(report.credentialCopy,"verified");assert.equal(cutoverScopeFinding(report).ok,true);
});

fixtureTest("missing rw_ target column and a rollback-mode ledger cannot qualify",async () => {
  await target.query("ALTER TABLE workspaces DROP COLUMN cloud_relay_workspace_id");
  const ledger = await apply();
  const report = await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.ok,false);
  assert.equal(report.findings.find((f) => f.kind === "schema_manifest")!.ok,false);
  assert.ok(report.targetSchema.missing.includes("column:public.workspaces.cloud_relay_workspace_id"));
  ledger.mode="dry-run";
  assert.equal((await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex)).ok,false);
});

fixtureTest("missing GitHub installation storage reconciles decimal keys and blocks qualification",async () => {
  await target.query("DROP TABLE github_app_installations CASCADE");
  const ledger=await apply();
  assert.deepEqual(ledger.tables.github_app_installations.importerSkips.target_lacks_github_app,["12345"]);
  const report=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.findings.find((f) => f.kind === "schema_manifest")!.ok,false);
  assert.ok(report.targetSchema.missing.includes("table:public.github_app_installations"));
  assert.equal(report.ok,false);
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
    const inherited = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^(SELFHOST_|CLOUD_IMPORT_|CLOUD_VERIFY_|CLOUD_CREDENTIAL_)/.test(name)));
    const env = {...inherited,CLOUD_VERIFY_SOURCE_URL:sourceUrl,CLOUD_VERIFY_TARGET_URL:url.toString(),
      CLOUD_CREDENTIAL_ENCRYPTION_KEY:cloudKeyHex,
      SELFHOST_ENCRYPTION_KEY_ID:fixtureKeyring.active.id,SELFHOST_ENCRYPTION_KEY:fixtureKeyring.active.key.toString("base64"),
      SELFHOST_ENCRYPTION_PREVIOUS_KEY_ID:"",SELFHOST_ENCRYPTION_PREVIOUS_KEY:"",SELFHOST_PASSWORD_PEPPER_FILE:""};
    const run = (args:string[],ledgerPath=path) => spawnSync(process.execPath,["--import","tsx",
      fileURLToPath(new URL("../scripts/cloud-import-verify/import-cli.ts",import.meta.url)),ledgerPath,...args],
      {env,encoding:"utf8",timeout:20000});
    const passed = run(["--all-organizations"]);
    assert.equal(passed.status,0,passed.stderr);
    assert.equal(JSON.parse(passed.stdout).mappingRevision,ledger.mappingRevision);
    assert.equal(run([]).status,2);
    assert.equal(run(["--org-ids",ORG_A]).status,1);
    const ownershipPath=join(directory,"ownership.json");await writeFile(ownershipPath,"{}",{mode:0o644});
    const capture=spawnSync(process.execPath,["--import","tsx",
      fileURLToPath(new URL("../scripts/cloud-import-verify/ownership-cli.ts",import.meta.url)),ownershipPath,"--all-organizations"],
      {env,encoding:"utf8",timeout:20000});
    assert.equal(capture.status,0,capture.stderr);
    assert.equal((await stat(ownershipPath)).mode & 0o077,0);
    assert.ok(JSON.parse(await readFile(ownershipPath,"utf8")).rows.length > 0);
    await source.query("DELETE FROM workspace_person_identities WHERE id=$1",[id(0x401)]);
    const next=await apply();const nextPath=join(directory,"next.json");await writeFile(nextPath,JSON.stringify(next),{mode:0o600});
    assert.equal(run(["--all-organizations"],nextPath).status,1);
    assert.equal(run(["--all-organizations","--previous-ownership",ownershipPath,"--previous-report",path],nextPath).status,0);
    const contractPath = join(directory,"contract.json");
    await writeFile(contractPath,JSON.stringify({version:1,mappingRevision:MAPPING_REVISION,
      tables:verifierComparisons(scope,new Set(ledger.optionalColumns)),identities:[],
      targetRelations:TARGET_RELATIONS,encryptedSamples:encryptedSamples(20,scope)}));
    const generic = spawnSync(process.execPath,["--import","tsx",
      fileURLToPath(new URL("../scripts/cloud-import-verify/cli.ts",import.meta.url)),contractPath],
      {env,encoding:"utf8",timeout:20000});
    assert.equal(generic.status,0,generic.stderr);
  } finally {await rm(directory,{recursive:true,force:true});}
});

fixtureTest("source Oslo sessions retain UTC expiry and conflicts fail copy",async () => {
  await source.query("SET TIME ZONE 'Europe/Oslo'");
  const fixture=await copiedFixture();
  const expiry=(await target.query("SELECT to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS.US') AS expiry FROM staff_read_grants WHERE id=$1",[id(0xa01)])).rows[0].expiry;
  assert.equal(expiry,"2026-04-01 00:00:00.123456");
  const report=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(report.ok,true,JSON.stringify(report.findings.filter((f) => !f.ok)));
  assert.equal((await source.query("SELECT current_setting('TimeZone') AS zone")).rows[0].zone,"Europe/Oslo");
  await source.query("UPDATE provider_credentials SET is_active=false WHERE id=$1",[id(0x80f)]);
  const conflict=await copyCodingAgentCredentials(fixture.deps,scope,"apply");
  assert.equal(conflict.selection!.selectionConflicts,1);assert.equal(conflict.ok,false);
  assert.equal((await source.query("SELECT current_setting('TimeZone') AS zone")).rows[0].zone,"Europe/Oslo");
});

for (const relation of ["relay_node_credentials","relay_launch_credentials"]) {
  fixtureTest(`new credential schema ${relation} is required even when empty`,async () => {
    const ledger=await apply();
    assert.equal((await target.query(`SELECT count(*)::int AS n FROM public.${relation}`)).rows[0].n,0);
    assert.equal((await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex)).ok,true);
    await target.query(`DROP TABLE public.${relation}`);
    const missing=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
    assert.equal(missing.ok,false);
    assert.ok(missing.targetSchema.missing.includes(`table:public.${relation}`));
    assert.ok(!missing.findings.some((finding) => finding.kind === "table"));
  });
}

fixtureTest("target content diagnostics distinguish copied-row failures from intentional source exclusions",async () => {
  const fixture=await copiedFixture();
  const controlId=fixture.copy.controlIds[id(0x803)]!;
  const before=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(before.credentialCopy,"verified");
  // Ciphertext stays valid: prove exact content checks independently of key
  // identity, source exclusions and read/decrypt exceptions.
  const {encryptSecret}=await import("../src/crypto.js");
  const marker="synthetic-private-wrong-content";
  await target.query("UPDATE coding_agent_credentials SET status='error',secret_ciphertext=$1 WHERE id=$2",
    [encryptSecret(marker,fixtureKeyring.active),controlId]);
  const after=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  const detail=after.findings.find((f) => f.kind === "credential_natural_keys")!.detail as {
    contentFailures:number;sourceFailures:number;unresolvedSourceSkips:number;sourceChecksum:string;targetChecksum:string;
    contentFailureReasons:Record<string,number>};
  assert.equal(after.credentialCopy,"failed");assert.equal(detail.contentFailures,1);
  assert.equal(detail.sourceFailures,0);assert.equal(detail.unresolvedSourceSkips,0);
  assert.equal(detail.sourceChecksum,detail.targetChecksum,"natural key equality does not establish content equality");
  assert.deepEqual(detail.contentFailureReasons,{organizationMismatch:0,statusNotConnected:1,fingerprintMismatch:0,
    contentMismatch:1,blobBackendMismatch:0,targetReadOrDecryptFailed:0});
  assert.ok(!JSON.stringify(after).includes(marker));assert.ok(!JSON.stringify(detail).includes(controlId));
});

for (const [provider,accounted] of [["opencode",true],["synthetic-unknown-provider",false]] as const) {
  fixtureTest(`relay-managed exclusion ${provider} is explicitly ${accounted ? "accounted" : "unresolved"}`,async () => {
    await source.query("UPDATE provider_credentials SET model_provider=$1 WHERE id=$2",[provider,id(0x801)]);
    const ledger=await apply();
    assert.equal(ledger.tables.coding_agent_credentials.skipped.unsupported_model_provider,1);
    const report=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
    const finding=report.findings.find((f) => f.kind === "credential_exclusions" && f.name === "identity_metadata")!;
    assert.equal(finding.ok,accounted);assert.equal(report.ok,accounted);
    assert.deepEqual((finding.detail as {classes:unknown}).classes,[
      {reason:"unsupported_dropped",accounted:0,unresolved:0},{reason:"dead_login",accounted:0,unresolved:0},
      {reason:"unsupported_model_provider",accounted:Number(accounted),unresolved:Number(!accounted)}]);
  });
}

fixtureTest("convergence snapshots detect in-place OAuth rewrites and same-value updates",async () => {
  const fixture=await copiedFixture();
  const before=await captureCredentialConvergence(target);
  const unchanged=await captureCredentialConvergence(target,"after");
  const cohort=credentialConvergenceCohort(Object.values(fixture.copy.controlIds));
  const zeroReport={version:1,mappingRevision:MAPPING_REVISION,mode:"apply",ok:true,outcomes:{},
    writes:{inserted:0,updated:0,blobWrites:0,metadataWrites:0,selectionWrites:0},
    convergence:{beforeDigest:before.digest,nonce:before.nonce}};
  assert.equal(compareCredentialConvergence(before,unchanged,zeroReport,cohort).ok,true);
  assert.equal(compareCredentialConvergence(before,unchanged,undefined,cohort).ok,false,"missing counters never mean zero");
  const sameId=fixture.copy.controlIds[id(0x803)]!;
  await target.query("UPDATE coding_agent_credentials SET status=status WHERE id=$1",[sameId]);
  const sameValue=await captureCredentialConvergence(target,"after");
  const changed=compareCredentialConvergence(before,sameValue,zeroReport,cohort);
  assert.equal(changed.ok,false,"same-value DML is independently detected despite a false zero-write claim");
  assert.equal((changed.detail as {credentialChanges:{changed:number}}).credentialChanges.changed,1);
  const beforeCopy=await captureCredentialConvergence(target);
  zeroReport.convergence={beforeDigest:beforeCopy.digest,nonce:beforeCopy.nonce};
  const rerun=await copyCodingAgentCredentials(fixture.deps,scope,"apply");
  assert.equal(rerun.ok,true);
  const afterCopy=await captureCredentialConvergence(target,"after");
  const nonConverged=compareCredentialConvergence(beforeCopy,afterCopy,zeroReport,cohort);
  assert.equal(nonConverged.ok,false);
  assert.ok((nonConverged.detail as {blobVersionChanges:number}).blobVersionChanges > 0);
  assert.ok(!JSON.stringify(before).includes(sameId));
  assert.ok(!JSON.stringify(before).includes("acct-synthetic"));
});

fixtureTest("qualified convergence binds the real checkpoint and rejects old copier mutations despite zero claims",async () => {
  const fixture=await copiedFixture();
  const before=await captureCredentialConvergence(target);
  const rows=Object.fromEntries(Object.entries(fixture.copy.rows).map(([key,outcome]) => [key,outcome === "copied" ? "already_present" : outcome]));
  const outcomes:Record<string,number>={};for (const outcome of Object.values(rows)) outcomes[outcome]=(outcomes[outcome] ?? 0)+1;
  const noOp={...fixture.copy,rows,outcomes,convergence:{beforeDigest:before.digest,nonce:before.nonce},writes:{inserted:0,updated:0,blobWrites:0,metadataWrites:0,selectionWrites:0},
    selection:fixture.copy.selection ? {...fixture.copy.selection,writes:0} : undefined};
  const options={credentialCopy:{report:noOp,reader:fixture.reader,targetBlobs:fixture.blobs,convergenceBefore:before}};
  const positive=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,options);
  assert.equal(positive.ok,true,JSON.stringify(positive.findings.filter((f) => !f.ok)));
  assert.equal(positive.credentialConvergence,"verified");
  await copyCodingAgentCredentials(fixture.deps,scope,"apply");
  const changed=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,options);
  assert.equal(changed.ok,false);assert.equal(changed.credentialConvergence,"failed");assert.equal(changed.credentialCopy,"failed");
  assert.ok((changed.findings.find((f) => f.kind === "credential_convergence")!.detail as {blobVersionChanges:number}).blobVersionChanges > 0);
  assert.ok(changed.findings.filter((f) => f.kind.startsWith("credential_") && f.kind !== "credential_convergence").every((f) => f.ok));
  await assert.rejects(verifyImport(source,target,{orgIds:[ORG_A]},fixture.ledger,fixtureKeyring,cloudKeyHex,options),/all source organizations/);
});

fixtureTest("updated copy outcomes require valid explicit write receipts and exact target contents",async () => {
  const fixture=await copiedFixture();
  const row=id(0x806);
  const controlId=fixture.copy.controlIds[row]!;
  await target.query(`INSERT INTO cloud_import_ledger(organization_id,table_name,row_key,mapping_revision)
    SELECT organization_id,'copier_login',id::text||':'||blob_version::text,$2 FROM coding_agent_credentials WHERE id=$1`,[controlId,MAPPING_REVISION]);
  const outcomes={...fixture.copy.outcomes,copied:fixture.copy.outcomes.copied!-1,updated:1};
  const report={...fixture.copy,rows:{...fixture.copy.rows,[row]:"updated"},outcomes,
    writes:{inserted:outcomes.copied,updated:1,blobWrites:1,metadataWrites:0,selectionWrites:0},
    selection:fixture.copy.selection ? {...fixture.copy.selection,writes:0} : undefined};
  const checked=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:report as unknown as typeof fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(checked.credentialCopy,"verified",JSON.stringify(checked.findings.filter((f) => !f.ok)));
  assert.equal(checked.credentialConvergence,"not_requested");
  report.writes.updated=0;
  const invalid=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:report as unknown as typeof fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(invalid.credentialCopy,"failed");
  for (const outcome of ["control_newer","blob_read_failed"]) {
    report.rows[row]=outcome;
    report.outcomes={...fixture.copy.outcomes,copied:outcomes.copied,[outcome]:1} as typeof report.outcomes;
    report.writes={inserted:outcomes.copied,updated:0,blobWrites:0,metadataWrites:0,selectionWrites:0};
    const refused=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
      {credentialCopy:{report:report as unknown as typeof fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
    assert.equal(refused.credentialCopy,"failed",outcome);
    assert.equal(refused.findings.find((f) => f.kind === "credential_natural_keys")!.ok,true);
    assert.equal(refused.findings.find((f) => f.kind === "credential_copy_ledger")!.ok,false);
  }
});

fixtureTest("convergence capture CLI requires all scope and creates a private non-overwritable checkpoint",async () => {
  const directory=await mkdtemp(join(tmpdir(),"verify-convergence-cli-"));
  try {
    const output=join(directory,"before.json");
    const url=new URL("postgresql:/");url.hostname="127.0.0.1";url.port=String(port);
    url.username=config.user;url.pathname="/cloud_import_target_fixture";
    const env:NodeJS.ProcessEnv={...process.env,CLOUD_VERIFY_TARGET_URL:url.href};
    delete env.CLOUD_VERIFY_TARGET_URL_FILE;
    const run=(args:string[]) => spawnSync(process.execPath,["--import","tsx",
      fileURLToPath(new URL("../scripts/cloud-import-verify/convergence-snapshot-cli.ts",import.meta.url)),...args],
      {env,encoding:"utf8",timeout:10000});
    assert.equal(run([output,"--org-ids",ORG_A]).status,2);
    assert.equal(run([output,"--all-organizations"]).status,2,"empty checkpoint is refused");
    await copiedFixture();
    const captured=run([output,"--all-organizations"]);assert.equal(captured.status,0,captured.stderr);
    const body=await readFile(output,"utf8");assert.equal(JSON.parse(body).phase,"before");
    assert.equal((await stat(output)).mode & 0o077,0);
    assert.equal(run([output,"--all-organizations"]).status,2);
    assert.equal(await readFile(output,"utf8"),body);
  } finally {await rm(directory,{recursive:true,force:true});}
});

fixtureTest("copier marker namespace is accounted separately without hiding unknown or malformed ownership",async () => {
  const fixture=await copiedFixture();const controlId=fixture.copy.controlIds[id(0x806)]!;
  await target.query(`INSERT INTO cloud_import_ledger(organization_id,table_name,row_key,mapping_revision)
    SELECT organization_id,'copier_login',id::text||':'||blob_version::text,$2 FROM coding_agent_credentials WHERE id=$1`,[controlId,MAPPING_REVISION]);
  const ownership=await captureOwnership(target,scope);
  assert.ok(ownership.rows.every((row) => String(row.table_name) !== 'copier_login'));
  const checked=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(checked.credentialCopy,"verified");
  assert.equal((checked.findings.find((f) => f.kind === "credential_copy_markers")!.detail as {observed:number}).observed,1);
  await target.query("UPDATE cloud_import_ledger SET row_key='synthetic-private-invalid-marker' WHERE table_name='copier_login'");
  const invalid=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(invalid.ok,false);assert.ok(!JSON.stringify(invalid).includes('synthetic-private-invalid-marker'));
  await target.query("DELETE FROM cloud_import_ledger WHERE table_name='copier_login'");
  await target.query(`INSERT INTO cloud_import_ledger(organization_id,table_name,row_key,mapping_revision) VALUES($1,'unknown-namespace',$2,$3)`,[ORG_A,id(0xbeef),MAPPING_REVISION]);
  await assert.rejects(captureOwnership(target,scope),/Invalid ownership/);
});

fixtureTest("copier marker writes fail convergence independently of credential and blob state",async () => {
  const fixture=await copiedFixture();const controlId=fixture.copy.controlIds[id(0x806)]!;
  const before=await captureCredentialConvergence(target);
  await target.query(`INSERT INTO cloud_import_ledger(organization_id,table_name,row_key,mapping_revision)
    SELECT organization_id,'copier_login',id::text||':'||blob_version::text,$2 FROM coding_agent_credentials WHERE id=$1`,[controlId,MAPPING_REVISION]);
  const after=await captureCredentialConvergence(target,"after");
  const report={version:1,mappingRevision:MAPPING_REVISION,mode:'apply',ok:true,outcomes:{},
    writes:{inserted:0,updated:0,blobWrites:0,metadataWrites:0,selectionWrites:0},
    convergence:{beforeDigest:before.digest,nonce:before.nonce}};
  const finding=compareCredentialConvergence(before,after,report,credentialConvergenceCohort(Object.values(fixture.copy.controlIds)));
  assert.equal(finding.ok,false);
  const detail=finding.detail as {credentialChanges:{changed:number};blobChanges:{changed:number};markerChanges:{inserted:number}};
  assert.equal(detail.credentialChanges.changed,0);assert.equal(detail.blobChanges.changed,0);assert.equal(detail.markerChanges.inserted,1);
});

fixtureTest("Claude copied auth files use the source account email held beside the envelope",async () => {
  const fixture=await copiedFixture();const credentialId=id(0x810);
  await source.query(`INSERT INTO provider_credentials(id,organization_id,workspace_id,user_id,harness,model_provider,auth_type,
    display_name,account_email,is_active,harness_active,status,created_at,updated_at)
    VALUES($1,$2,$3,$4,'claude','anthropic','provider_oauth','Synthetic Claude','ALICE@example.test',false,true,'connected',
      '2026-01-10T00:00:00Z','2026-01-10T00:00:00Z')`,[credentialId,ORG_A,id(0x201),id(1)]);
  const refreshToken='synthetic-private-claude-refresh';
  const auth=JSON.stringify({claudeAiOauth:{accessToken:'synthetic-private-claude-access',refreshToken,expiresAt:1893456000000}});
  fixture.objects.set(`${id(1)}/anthropic/credentials.json.enc`,JSON.stringify(cloudEnvelope(auth,cloudKeyHex)));
  const ledger=await apply();
  const copy=await copyCodingAgentCredentials(fixture.deps,scope,'apply');
  assert.equal(copy.rows[credentialId],'copied');assert.equal(copy.ok,true);
  const checked=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(checked.credentialCopy,'verified',JSON.stringify(checked.findings.filter((finding) => !finding.ok)));
  assert.ok(!JSON.stringify(checked).includes(refreshToken));
});

fixtureTest("producer transaction computes the checkpoint digest freshly before any writes",async () => {
  await copiedFixture();const before=await captureCredentialConvergence(target);
  validateCredentialCheckpoint(before,scope);
  await targetDb.transaction(async (tx) => {
    await tx.exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY');
    assert.equal((await computeCredentialCheckpoint(tx,scope)).digest,before.digest);
  });
  await target.query('UPDATE coding_agent_credentials SET status=status');
  let writes=0;
  await assert.rejects(targetDb.transaction(async (tx) => {
    await tx.exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY');
    const fresh=await computeCredentialCheckpoint(tx,scope);
    if (fresh.digest !== before.digest) throw new Error('checkpoint_mismatch');
    writes++;
  }),/checkpoint_mismatch/);
  assert.equal(writes,0);
});

fixtureTest("historical marker revisions cannot prove a current updated login",async () => {
  const fixture=await copiedFixture();const row=id(0x806),controlId=fixture.copy.controlIds[row]!;
  await target.query(`INSERT INTO cloud_import_ledger(organization_id,table_name,row_key,mapping_revision)
    SELECT organization_id,'copier_login',id::text||':'||blob_version::text,'cloud-identity-2000-01-01.0'
    FROM coding_agent_credentials WHERE id=$1`,[controlId]);
  const report={...fixture.copy,rows:{...fixture.copy.rows,[row]:'updated'},
    outcomes:{...fixture.copy.outcomes,copied:fixture.copy.outcomes.copied!-1,updated:1},
    writes:{inserted:fixture.copy.outcomes.copied!-1,updated:1,blobWrites:1,metadataWrites:0,selectionWrites:0},
    selection:fixture.copy.selection ? {...fixture.copy.selection,writes:0} : undefined};
  const options={credentialCopy:{report:report as unknown as typeof fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}};
  const stale=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,options);
  assert.equal(stale.credentialCopy,'failed');
  assert.equal(stale.findings.find((f) => f.kind === 'credential_copy_markers')!.ok,true,'historical marker is well-formed');
  assert.equal(stale.findings.find((f) => f.kind === 'credential_natural_keys')!.ok,true);
  assert.equal(stale.findings.find((f) => f.kind === 'credential_copy_ledger')!.ok,true);
  const links=stale.findings.find((f) => f.kind === 'credential_marker_links')!;
  assert.equal(links.ok,false);
  assert.deepEqual(links.detail,{receiptStatus:'valid',expected:1,missing:0,mismatches:0,revisionMismatches:1});
  await target.query("UPDATE cloud_import_ledger SET mapping_revision=$1 WHERE table_name='copier_login'",[MAPPING_REVISION]);
  const current=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,options);
  assert.equal(current.credentialCopy,'verified',JSON.stringify(current.findings.filter((f) => !f.ok)));
});

fixtureTest("unbound namespace validates source set and live org/ownership links before hiding a later binding",async () => {
  const ledger=await apply();
  const key=id(0x201),expected=new Map([[key,ORG_A]]);
  const inspect=async (set=expected,selectedScope:ImportScope=scope) => {
    await beginReadOnlySnapshot(target);
    try {return await unboundWorkspaceMarkers(target,selectedScope,set);} finally {await target.query("ROLLBACK");}
  };
  assert.equal((await inspect()).ok,false,"an expected marker cannot be omitted");
  await target.query("INSERT INTO cloud_import_ledger(organization_id,table_name,row_key,mapping_revision) VALUES($1,'workspace_unbound',$2,$3)",[ORG_A,key,MAPPING_REVISION]);
  assert.equal((await inspect()).ok,true,"a later live Control binding is allowed by the namespace contract");
  const ownership=await captureOwnership(target,scope);
  assert.ok(ownership.rows.every((row) => String(row.table_name) !== "workspace_unbound"));
  const forged=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(forged.ok,false,"the actual source is bound, so this marker cannot authorize projection masking");
  assert.equal((forged.findings.find((row) => row.kind === "workspace_unbound_markers")!.detail as {unexpected:number}).unexpected,1);
  await target.query("UPDATE cloud_import_ledger SET mapping_revision='cloud-identity-2000-01-01.0' WHERE table_name='workspace_unbound'");
  assert.equal((await inspect()).ok,false);
  await target.query("UPDATE cloud_import_ledger SET mapping_revision=$1 WHERE table_name='workspace_unbound'",[MAPPING_REVISION]);
  await target.query("DELETE FROM cloud_import_ledger WHERE table_name='workspaces' AND row_key=$1",[key]);
  assert.equal((await inspect()).ok,false,"a marker cannot claim a workspace outside the identity ownership ledger");
  await target.query("INSERT INTO cloud_import_ledger(organization_id,table_name,row_key,mapping_revision) VALUES($1,'workspaces',$2,$3)",[ORG_A,key,MAPPING_REVISION]);
  await target.query("UPDATE cloud_import_ledger SET organization_id=$1 WHERE table_name='workspace_unbound'",[ORG_B]);
  assert.equal((await inspect()).ok,false,"org links must match both the workspace and its ownership");
  assert.equal((await inspect(expected,{orgIds:[ORG_A]})).ok,false,"a foreign-org marker affecting an in-scope projection is still checked");
  await target.query("UPDATE cloud_import_ledger SET organization_id=$1,row_key='synthetic-private-invalid-unbound-marker' WHERE table_name='workspace_unbound'",[ORG_A]);
  const invalid=await inspect();assert.equal(invalid.ok,false);
  assert.ok(!JSON.stringify(invalid).includes("synthetic-private-invalid-unbound-marker"));
});

fixtureTest("duplicate-login consumer derives content from the newest decrypted source and rejects false duplicate labels",async () => {
  const fixture=await copiedFixture(),older=id(0x806),fresh=id(0x810);
  await source.query(`INSERT INTO provider_credentials(id,organization_id,workspace_id,user_id,harness,model_provider,auth_type,display_name,label,account_email,
    provider_account_id,is_active,harness_active,status,created_at,updated_at)
    SELECT $1,organization_id,workspace_id,user_id,harness,model_provider,auth_type,display_name,label,account_email,provider_account_id,
      false,false,status,created_at,updated_at+interval '1 day' FROM provider_credentials WHERE id=$2`,[fresh,older]);
  const oldKey=`${id(1)}/accounts/${older}/credentials.json.enc`;
  const auth=JSON.parse(decryptCloudEnvelope(JSON.parse(fixture.objects.get(oldKey)!),cloudKeyHex));
  auth.tokens.refresh_token="synthetic-newest-refresh-only";
  fixture.objects.set(`${id(1)}/accounts/${fresh}/credentials.json.enc`,JSON.stringify(cloudEnvelope(JSON.stringify(auth),cloudKeyHex)));
  // Use the current main writer to construct real encrypted target content.
  // This is a future-contract consumer probe, never a relabelled qualification.
  const actual=await copyCodingAgentCredentials(fixture.deps,scope,"apply");
  const rows={...actual.rows,[older]:"duplicate_login"};
  const report={...actual,mappingRevision:"cloud-identity-2026-11-16.25",rows,
    outcomes:{...actual.outcomes,copied:actual.outcomes.copied!-1,duplicate_login:1},controlIds:{...actual.controlIds}};
  delete report.controlIds[older];
  const inspect=async () => {
    await beginReadOnlySnapshot(source);await beginReadOnlySnapshot(target);
    try {return await credentialCopyFindings(source,target,scope,
      {report:report as unknown as typeof actual,reader:fixture.reader,targetBlobs:fixture.blobs},fixtureKeyring,cloudKeyHex);
    } finally {await source.query("ROLLBACK");await target.query("ROLLBACK");}
  };
  const findings=await inspect();
  const ledger=findings.find((row) => row.kind === "credential_copy_ledger")!;
  assert.equal(ledger.ok,false,"the .25 consumer probe must not qualify against the .11 producer revision");
  assert.equal((ledger.detail as {outcomesMatch:boolean}).outcomesMatch,true);
  assert.equal((ledger.detail as {duplicateLogins:number}).duplicateLogins,1);
  assert.equal(findings.find((row) => row.kind === "credential_natural_keys")!.ok,true);
  assert.equal(findings.find((row) => row.kind === "credential_control_ids")!.ok,true);
  report.rows[older]="copied";
  const wrong=await inspect();
  assert.equal((wrong.find((row) => row.kind === "credential_copy_ledger")!.detail as {outcomesMatch:boolean}).outcomesMatch,false);
  report.rows[older]="duplicate_login";
  await source.query("UPDATE provider_credentials SET updated_at=updated_at+interval '2 days' WHERE id=$1",[older]);
  const staleContent=await inspect();
  assert.equal(staleContent.find((row) => row.kind === "credential_natural_keys")!.ok,false,"a newer source login cannot be waived by labelling it duplicate");
});
