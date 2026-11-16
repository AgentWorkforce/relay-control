import assert from "node:assert/strict";
import { before,after,beforeEach,test,type TestFn } from "node:test";
import { Client } from "pg";
import type { Database,SqlExecutor } from "../src/database.js";
import { migrate } from "../src/migrations.js";
import { runImport } from "../scripts/cloud-import/importer.js";
import { CLOUD_FIXTURE_DDL,cloudFixtureSeed,cloudEnvelope,id,ORG_A,ORG_B } from "../scripts/cloud-import/cloud-fixture.js";
import { fixtureKeyring } from "../scripts/cloud-import-verify/fixtures.js";
import { verifyImport } from "../scripts/cloud-import-verify/import-contract.js";
import { SOURCE_TABLES,MAPPING_REVISION,TARGET_RELATIONS,verifierComparisons,encryptedSamples } from "../scripts/cloud-import/mapping.js";
import { writeFile,mkdtemp,rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { CodingAgentStore } from "../src/admin/coding-agents.js";
import { CredentialBlobStore,PostgresObjectBackend } from "../src/admin/credential-blobs.js";
import { SubscriptionLoginStore } from "../src/admin/subscription-logins.js";
import { copyCodingAgentCredentials } from "../scripts/cloud-import/credentials.js";
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
const apply = (selected=scope) => runImport({source:sourceDb,target:targetDb,keyring:fixtureKeyring,cloudKeyHex,batchSize:2},selected,"apply");
async function copiedFixture() {
  await source.query("DELETE FROM provider_credentials WHERE id=$1",[id(0x807)]);
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
    [`${id(2)}/${id(0x808)}/credentials.json.enc`,JSON.stringify(cloudEnvelope(JSON.stringify({key:"sk-synthetic-second-key-00000000000"}),cloudKeyHex))],
  ]);
  const reader = {get:async (key:string) => objects.get(key) ?? null};
  const blobs = new CredentialBlobStore(new PostgresObjectBackend(targetDb),fixtureKeyring);
  const deps = {source:sourceDb,reader,cloudKeyHex,keyring:fixtureKeyring,
    codingAgents:new CodingAgentStore(targetDb,fixtureKeyring,undefined,blobs),
    logins:new SubscriptionLoginStore(targetDb,fixtureKeyring,blobs)};
  const copy = await copyCodingAgentCredentials(deps,scope,"apply");
  assert.equal(copy.ok,true,JSON.stringify(copy));
  return {ledger,copy,deps,objects,blobs,reader};
}
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
  await source.query(cloudFixtureSeed(cloudKeyHex,cloudKeyHex));
  await source.query(`UPDATE relay_workspaces SET id='rw_0000b202' WHERE id='rw_legacy-01';
    UPDATE workspaces SET relay_workspace_id='rw_0000b202' WHERE relay_workspace_id='rw_legacy-01'`);
  await migrate(targetDb);
  // Run actual checked-in migrations first. Model the published optional
  // 0053/0054/0056/0057/0058 shapes until those separate schema PRs land.
  await target.query(`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS cloud_relay_workspace_id text UNIQUE;
    ALTER TABLE organizations ADD COLUMN IF NOT EXISTS slug text;
    ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS slug text;
    ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS relayhistory_origin text;
    ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS relaycast_api_key_generation integer;
    ALTER TABLE desktop_relay_identities ALTER COLUMN source_id TYPE text USING source_id::text;
    ALTER TABLE fleet_node_owners ALTER COLUMN node_name DROP NOT NULL;
    CREATE TABLE github_app_installations (
      installation_id text PRIMARY KEY CHECK(installation_id ~ '^[1-9][0-9]{0,19}$'),
      organization_id uuid NOT NULL REFERENCES organizations(id),UNIQUE(installation_id,organization_id));
    ALTER TABLE integration_connections ADD COLUMN installation_id text,
      ADD COLUMN github_app_organization_id uuid,ADD COLUMN github_app_refresh_id uuid,
      ADD COLUMN github_app_refresh_until timestamptz;
    ALTER TABLE integration_connections DROP CONSTRAINT IF EXISTS selfhost_connection_auth_mode,
      DROP CONSTRAINT IF EXISTS connection_auth_mode,
      ADD CONSTRAINT connection_auth_mode CHECK(auth_mode IN ('oauth2','api_key','github_app')),
      ADD CONSTRAINT connection_github_installation_owner FOREIGN KEY(installation_id,github_app_organization_id)
        REFERENCES github_app_installations(installation_id,organization_id),
      ADD CONSTRAINT connection_github_workspace_owner FOREIGN KEY(workspace_id,github_app_organization_id)
        REFERENCES workspaces(id,organization_id);
    ALTER TABLE coding_agent_credentials
      ALTER COLUMN secret_preview DROP NOT NULL,ALTER COLUMN key_fingerprint DROP NOT NULL,
      DROP CONSTRAINT IF EXISTS selfhost_coding_agent_auth_type,
      DROP CONSTRAINT IF EXISTS coding_agent_auth_type,
      DROP CONSTRAINT IF EXISTS selfhost_coding_agent_secret_storage,
      DROP CONSTRAINT IF EXISTS coding_agent_secret_storage,
      ADD CONSTRAINT coding_agent_auth_type CHECK(auth_type IN ('byo_api_key','oauth_token','provider_oauth','relay_managed')),
      ADD CONSTRAINT coding_agent_secret_storage CHECK(
        (auth_type='relay_managed' AND secret_ciphertext IS NULL AND NOT harness_active)
        OR (auth_type='provider_oauth' AND secret_ciphertext IS NULL AND blob_location IS NOT NULL)
        OR (auth_type IN ('byo_api_key','oauth_token') AND secret_ciphertext IS NOT NULL))`);
});

fixtureTest("actual importer rollback, apply and rerun reconcile all mapped tables and keep invite hashes",async () => {
  const dry = await runImport({source:sourceDb,target:targetDb,keyring:fixtureKeyring,cloudKeyHex,batchSize:2},scope,"dry-run");
  assert.equal(dry.ok,true,JSON.stringify(dry));
  assert.equal((await target.query("SELECT count(*)::int AS n FROM users")).rows[0].n,0);
  const first = await apply();
  assert.equal(first.ok,true,JSON.stringify(first));
  const one = await verifyImport(source,target,scope,first,fixtureKeyring,cloudKeyHex);
  assert.equal(one.ok,true,JSON.stringify(one.findings.filter((f) => !f.ok)));
  assert.equal(one.findings.filter((f) => f.kind === "table").length,SOURCE_TABLES.length);
  assert.equal(one.findings.filter((f) => f.kind === "decrypt").length,encryptedSamples(20,scope).length);
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
  assert.equal((await target.query("SELECT count(*)::int AS n FROM coding_agent_credentials WHERE secret_ciphertext IS NOT NULL OR harness_active")).rows[0].n,0);
  for (const table of ["token_sessions","device_authorizations","workspace_api_tokens","mcp_oauth_grants","desktop_relay_session_bindings","desktop_attestation_keys"]) {
    assert.equal((await target.query(`SELECT count(*)::int AS n FROM public.${table}`)).rows[0].n,0,`${table} remains empty`);
  }
});

fixtureTest("copied credential natural keys verify reminted IDs, encrypted blobs, reruns and local CLI",async () => {
  const fixture = await copiedFixture();
  const evidence = {report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs};
  const first = await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,{credentialCopy:evidence});
  assert.equal(first.ok,true,JSON.stringify(first.findings.filter((f) => !f.ok)));
  assert.equal(first.credentialCopy,"verified");
  const copiedRows = (await target.query("SELECT id FROM coding_agent_credentials WHERE auth_type <> 'relay_managed'")).rows;
  assert.equal(copiedRows.length,4);
  assert.ok(copiedRows.every((row) => ![id(0x803),id(0x805),id(0x806),id(0x808)].includes(row.id)));
  await target.query("UPDATE coding_agent_credentials SET id=$1 WHERE auth_type='byo_api_key' AND workspace_id=$2",[id(0xdeadbeef),id(0x201)]);
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
    const child=spawnSync(process.execPath,["--import","tsx",fileURLToPath(new URL("../scripts/cloud-import-verify/import-cli.ts",import.meta.url)),
      ledgerPath,"--all-organizations","--credential-copy-report",copyPath],{encoding:"utf8",timeout:20000,env:{...inherited,
      CLOUD_VERIFY_SOURCE_URL:sourceUrl,CLOUD_VERIFY_TARGET_URL:url.toString(),CLOUD_VERIFY_CREDENTIAL_OBJECTS_DIR:objectRoot,
      CLOUD_CREDENTIAL_ENCRYPTION_KEY:cloudKeyHex,SELFHOST_ENCRYPTION_KEY_ID:fixtureKeyring.active.id,
      SELFHOST_ENCRYPTION_KEY:fixtureKeyring.active.key.toString("base64")}});
    assert.equal(child.status,0,child.stderr);
    assert.equal(JSON.parse(child.stdout).ok,true);
  } finally {await rm(directory,{recursive:true,force:true});}
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
  await target.query("UPDATE coding_agent_credentials SET blob_backend='postgres' WHERE auth_type='provider_oauth'");
  await target.query("UPDATE coding_agent_credentials SET key_fingerprint=repeat('0',64) WHERE auth_type='byo_api_key' AND workspace_id=$1",[id(0x201)]);
  await target.query("UPDATE coding_agent_credential_blobs SET envelope='{}'");
  const report=await verifyImport(source,target,scope,fixture.ledger,fixtureKeyring,cloudKeyHex,
    {credentialCopy:{report:fixture.copy,reader:fixture.reader,targetBlobs:fixture.blobs}});
  assert.equal(report.ok,false);
  assert.equal(report.credentialCopy,"failed");
  assert.equal(report.findings.find((f) => f.kind === "credential_natural_keys")!.ok,false);
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
  assert.equal(report.findings.find((f) => f.kind === "ledger" && f.name === "coding_agent_credentials")!.ok,true);
  assert.equal(report.findings.find((f) => f.kind === "table" && f.name === "coding_agent_credentials")!.ok,true);
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

fixtureTest("missing GitHub installation storage reconciles decimal keys and blocks qualification",async () => {
  await target.query("DROP TABLE github_app_installations CASCADE");
  const ledger=await apply();
  assert.deepEqual(ledger.tables.github_app_installations.importerSkips.target_lacks_github_app,["12345"]);
  const report=await verifyImport(source,target,scope,ledger,fixtureKeyring,cloudKeyHex);
  assert.equal(report.findings.find((f) => f.kind === "ledger" && f.name === "github_app_installations")!.ok,true);
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
    const run = (args:string[]) => spawnSync(process.execPath,["--import","tsx",
      fileURLToPath(new URL("../scripts/cloud-import-verify/import-cli.ts",import.meta.url)),path,...args],
      {env,encoding:"utf8",timeout:20000});
    const passed = run(["--all-organizations"]);
    assert.equal(passed.status,0,passed.stderr);
    assert.equal(JSON.parse(passed.stdout).mappingRevision,ledger.mappingRevision);
    assert.equal(run([]).status,2);
    assert.equal(run(["--org-ids",ORG_A]).status,1);
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
