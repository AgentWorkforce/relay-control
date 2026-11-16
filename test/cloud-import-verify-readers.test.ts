import { accountCredentialExclusion,exclusionAccounting } from "../scripts/cloud-import-verify/exclusions.js";
import { migrationFiles,sealManifest,type SchemaManifest } from "../scripts/cloud-import-verify/schema.js";
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp,writeFile,rm,readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { requireAllSourceScope,cutoverScopeFinding,normalizedScope } from "../scripts/cloud-import-verify/organization-scope.js";
import { readOnlyCloudCredentials } from "../scripts/cloud-import-verify/credential-readers.js";

const inputs={CLOUD_CREDENTIAL_R2_ENDPOINT:"https://objects.example.test",CLOUD_CREDENTIAL_R2_BUCKET:"synthetic-fixtures",
  CLOUD_CREDENTIAL_R2_ACCESS_KEY_ID:"SYNTHETIC_ACCESS",CLOUD_CREDENTIAL_R2_SECRET_ACCESS_KEY:"synthetic-secret-only"};

test("Cloud credential reader exposes signed GET only with no redirects",async () => {
  const calls:{url:string;init:RequestInit}[]=[];
  const reader=readOnlyCloudCredentials(inputs,async (url,init) => {calls.push({url,init});return new Response("synthetic-envelope");});
  assert.deepEqual(Object.keys(reader),["get"]);assert.ok(Object.isFrozen(reader));
  assert.equal(await reader.get("user/accounts/row/credentials.json.enc"),"synthetic-envelope");
  assert.equal(calls.length,1);
  assert.equal(calls[0]!.url,"https://objects.example.test/synthetic-fixtures/credentials/user/accounts/row/credentials.json.enc");
  assert.equal(calls[0]!.init.method,"GET");assert.equal(calls[0]!.init.redirect,"error");
  assert.ok(calls[0]!.init.signal instanceof AbortSignal);
  assert.ok(new Headers(calls[0]!.init.headers).get("authorization")!.includes("Credential=SYNTHETIC_ACCESS/"));
});

test("Cloud credential reader uses explicit FILE inputs rather than ambient AWS",async () => {
  const directory=await mkdtemp(join(tmpdir(),"cloud-reader-fixture-"));
  try {
    const env:Record<string,string>={AWS_ACCESS_KEY_ID:"unused-ambient-id",AWS_SECRET_ACCESS_KEY:"unused-ambient-secret"};
    for (const [name,value] of Object.entries(inputs)) {
      const path=join(directory,name);await writeFile(path,value,{mode:0o600});env[`${name}_FILE`]=path;
    }
    let auth="";
    const reader=readOnlyCloudCredentials(env,async (_url,init) => {auth=new Headers(init.headers).get("authorization")!;return new Response(null,{status:404});});
    assert.equal(await reader.get("missing"),null);
    assert.ok(auth.includes("Credential=SYNTHETIC_ACCESS/"));assert.ok(!auth.includes("unused-ambient-id"));
  } finally {await rm(directory,{recursive:true,force:true});}
});

test("Cloud credential reader refuses unsafe endpoints and disabled TLS before fetching",() => {
  let requests=0;
  const fetcher=async () => {requests++;return new Response();};
  for (const endpoint of ["http://objects.example.test","https://user:private@objects.example.test","https://objects.example.test?private=value","https://objects.example.test#private"]) {
    assert.throws(() => readOnlyCloudCredentials({...inputs,CLOUD_CREDENTIAL_R2_ENDPOINT:endpoint},fetcher),/verified HTTPS/);
  }
  assert.throws(() => readOnlyCloudCredentials({...inputs,NODE_TLS_REJECT_UNAUTHORIZED:"0"},fetcher),/verified HTTPS/);
  assert.throws(() => readOnlyCloudCredentials({},fetcher),/Missing Cloud credential reader input/);
  assert.equal(requests,0);
});

test("Cloud credential reader reports HTTP status without object body or endpoint",async () => {
  const marker="synthetic-body-must-stay-private";
  const reader=readOnlyCloudCredentials(inputs,async () => new Response(marker,{status:503}));
  await assert.rejects(reader.get("user/accounts/row/credentials.json.enc"),(error:Error) => {
    assert.match(error.message,/503/);assert.ok(!error.message.includes(marker));
    assert.ok(!error.message.includes("example.test"));return true;
  });
});

test("cutover scope rejects subsets and unbound or incomplete global census",() => {
  const id="00000000-0000-4000-8000-0000000000a1";
  assert.deepEqual(normalizedScope({orgIds:[id.toUpperCase(),id]}),{orgIds:[id]});
  assert.throws(() => requireAllSourceScope({orgIds:[id]}),/all source/);
  assert.doesNotThrow(() => requireAllSourceScope({orgIds:null}));
  const record={evidenceKind:"identity-import",scope:{orgIds:null},targetSchema:{profile:"main",ok:true},
    sourceOrganizationCensus:{algorithm:"sha256-length-framed-uuid-c-order-v1",all:{count:2,sha256:"a".repeat(64)},
      selected:{count:2,sha256:"a".repeat(64)},requestedCount:null,unknownRequested:0}};
  assert.equal(cutoverScopeFinding(record).ok,true);
  assert.equal(cutoverScopeFinding({...record,scope:{orgIds:[id]}}).ok,false);
  assert.equal(cutoverScopeFinding({...record,evidenceKind:"contract-only"}).ok,false);
  assert.equal(cutoverScopeFinding({...record,targetSchema:{profile:"main-plus-proposed-0061",ok:true}}).ok,false);
  assert.equal(cutoverScopeFinding({...record,sourceOrganizationCensus:{...record.sourceOrganizationCensus,selected:{count:1,sha256:"other"}}}).ok,false);
});

test("committed verifier manifest tracks every checked-in migration in ordinary CI",async () => {
  const manifest=JSON.parse(await readFile(new URL("../scripts/cloud-import-verify/schema-manifest.json",import.meta.url),"utf8")) as SchemaManifest;
  const {sha256,...content}=manifest;
  assert.equal(sha256,sealManifest(content).sha256,"manifest seal must cover the complete inventory");
  assert.deepEqual(manifest.migrations,await migrationFiles(),
    "Migration drift requires a reviewed manifest generated from a fresh local migration database; never use the qualification target");
});

test("deliberate credential exclusions require exact source predicates and retain named counts",() => {
  const summary=exclusionAccounting();
  for (const provider of ["openrouter","daytona"]) assert.equal(accountCredentialExclusion(summary,
    {reason:"unsupported_dropped",provider,authType:"provider_oauth",status:"connected",refreshExhausted:false}),true);
  assert.equal(accountCredentialExclusion(summary,{reason:"dead_login",provider:"anthropic",authType:"provider_oauth",refreshExhausted:true}),true);
  assert.equal(accountCredentialExclusion(summary,{reason:"dead_login",provider:"anthropic",authType:"oauth_token",status:"refresh_failed",refreshExhausted:false}),true);
  assert.equal(accountCredentialExclusion(summary,{reason:"unsupported_model_provider",provider:"opencode",authType:"relay_managed"}),true);
  assert.deepEqual(summary,[{reason:"unsupported_dropped",accounted:2,unresolved:0},{reason:"dead_login",accounted:2,unresolved:0},
    {reason:"unsupported_model_provider",accounted:1,unresolved:0}]);
});

test("labels alone cannot waive unknown providers, live logins, API keys or ambiguous legacy objects",() => {
  const summary=exclusionAccounting();
  for (const provider of ["google","opencode","synthetic-private-provider-marker"]) assert.equal(accountCredentialExclusion(summary,
    {reason:"unsupported_dropped",provider,authType:"provider_oauth",status:"connected",refreshExhausted:false}),false);
  assert.equal(accountCredentialExclusion(summary,{reason:"unsupported_dropped",provider:"daytona",authType:"byo_api_key",status:"connected",refreshExhausted:false}),false);
  assert.equal(accountCredentialExclusion(summary,{reason:"dead_login",provider:"openai",authType:"provider_oauth",status:"connected",refreshExhausted:false}),false);
  assert.equal(accountCredentialExclusion(summary,{reason:"dead_login",provider:"openai",authType:"byo_api_key",status:"refresh_failed",refreshExhausted:false}),false);
  assert.equal(accountCredentialExclusion(summary,{reason:"unsupported_model_provider",provider:"opencode",authType:"provider_oauth"}),false);
  assert.equal(accountCredentialExclusion(summary,{reason:"unsupported_model_provider",provider:"unknown",authType:"relay_managed"}),false);
  for (const reason of ["legacy_key_ambiguous","object_missing","unknown_skip"]) assert.equal(accountCredentialExclusion(summary,
    {reason,provider:"opencode",authType:"relay_managed"}),null);
  assert.ok(!JSON.stringify(summary).includes("synthetic-private-provider-marker"));
  assert.equal(summary.reduce((total,item) => total+item.accounted,0),0);
});
