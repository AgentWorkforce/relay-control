import { accountCredentialExclusion,exclusionAccounting } from "../scripts/cloud-import-verify/exclusions.js";
import { credentialCloudSelection,writtenOnlySelection,type SourceSelection,type TargetSelection } from "../scripts/cloud-import-verify/credential-selection.js";
import { credentialLoginCohort,deduplicatesLogins } from "../scripts/cloud-import-verify/credential-cohort.js";
import { reportedSelectionDiverged } from "../scripts/cloud-import-verify/selection-divergence.js";

import { credentialConvergenceCohort,credentialWriteCounts,compareCredentialConvergence,credentialCheckpointDigest,validateCredentialCheckpoint,type CredentialConvergenceSnapshot } from "../scripts/cloud-import-verify/convergence.js";
import { MAPPING_REVISION } from "../scripts/cloud-import/mapping.js";
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

test("selection divergence counters require exact sparse per-org flag counts",() => {
  const org="00000000-0000-4000-8000-0000000000a1",known=new Set([org]);
  assert.deepEqual(reportedSelectionDiverged({},known),{});
  assert.deepEqual(reportedSelectionDiverged({[org]:{harness:2,active:1}},known),{[org]:{active:1,harness:2}});
  for (const value of [null,[],{unknown:{active:1,harness:0}},
    {[org]:{active:0,harness:0}},{[org]:{active:-1,harness:0}},{[org]:{active:1.5,harness:0}},
    {[org]:{active:Number.MAX_SAFE_INTEGER+1,harness:0}},{[org]:{active:true,harness:0}},
    {[org]:{active:1}},{[org]:{active:1,harness:0,credential:"synthetic-private-counter"}}]) {
    assert.equal(reportedSelectionDiverged(value,known),null);
  }
  assert.equal(reportedSelectionDiverged({[org]:{active:1,harness:0}},new Set()),null);
});

test("duplicate login winner is independently freshest then lowest id and inherits all Cloud choices",() => {
  const make=(id:string,updated:number,active:boolean,harness:boolean) => ({authType:"provider_oauth",content:id,
    selection:{id,key:"decrypted-account-key",group:"workspace:provider",updated,active,harness}});
  const old=make("001",1,true,false),fresh=make("003",2,false,false),tie=make("002",2,false,true);
  const cohort=credentialLoginCohort([old,fresh,tie],true);
  assert.equal(cohort.selected.length,1);assert.equal(cohort.selected[0]!.content,"002");
  assert.deepEqual([...cohort.duplicates].sort(),["001","003"]);
  assert.equal(cohort.selected[0]!.selection.active,true);assert.equal(cohort.selected[0]!.selection.harness,true);
  assert.equal(tie.selection.active,false,"source values are not mutated");
  const separate={...old,selection:{...old.selection,id:"004",key:"different-decrypted-account"}};
  const api={...fresh,authType:"byo_api_key",selection:{...fresh.selection,id:"005"}};
  assert.equal(credentialLoginCohort([old,fresh,tie,separate,api],true).selected.length,3);
  assert.equal(credentialLoginCohort([old,fresh,tie],false).selected.length,3);
  assert.equal(deduplicatesLogins("cloud-identity-2026-11-16.11"),false);
  assert.equal(deduplicatesLogins("cloud-identity-2026-11-16.21"),true);
});

test("written-only selection preserves Control choices and rejects missing or changed prior evidence",() => {
  const entry:SourceSelection={id:"source",key:"existing",group:"workspace:provider",active:true,harness:true,updated:1};
  const prior:TargetSelection={group:entry.group,active:false,harness:false};
  const input={revision:"cloud-identity-2026-11-16.25",entries:[entry],outcomes:{source:"already_present"},
    flags:new Map([[entry.key,prior]]),nativeFlags:new Map<string,TargetSelection>(),baseline:new Map([[entry.key,prior]]),
    allFlags:[prior],unchangedKeys:new Set<string>(),reported:undefined};
  const finding=credentialCloudSelection(input);
  assert.equal(finding.ok,true);assert.equal((finding.detail as {untouchedKeys:number}).untouchedKeys,1);
  assert.equal(credentialCloudSelection({...input,outcomes:{source:"control_newer"}}).ok,true);
  assert.equal(credentialCloudSelection({...input,revision:"cloud-identity-2026-11-16.24"}).ok,false);
  assert.equal(credentialCloudSelection({...input,baseline:new Map()}).ok,false);
  assert.equal(credentialCloudSelection({...input,baseline:new Map(),unchangedKeys:new Set([entry.key])}).ok,true);
  assert.equal(credentialCloudSelection({...input,baseline:new Map([[entry.key,{...prior,active:true}]]),
    unchangedKeys:new Set([entry.key])}).ok,true,"the genuine pre-rerun tuple supersedes pre-first-copy flags");
  assert.equal(credentialCloudSelection({...input,flags:new Map([[entry.key,{...prior,harness:true}]])}).ok,false);
  assert.equal(credentialCloudSelection({...input,reported:{groups:1,active:1,harness:1,activeDemoted:0,harnessDemoted:0,selectionConflicts:0}}).ok,false);
  assert.equal(writtenOnlySelection("cloud-identity-2026-11-16.11"),false);
  assert.equal(writtenOnlySelection("cloud-identity-2026-11-16.26"),true);
});

test("written selection cohorts exclude untouched source winners without weakening written winner checks",() => {
  const entries:SourceSelection[]=[
    {id:"new",key:"written",group:"workspace:provider",active:false,harness:false,updated:1},
    {id:"old",key:"existing",group:"workspace:provider",active:true,harness:true,updated:2},
  ];
  const prior:TargetSelection={group:entries[0]!.group,active:true,harness:true};
  const written={...prior,active:false,harness:false};
  const input={revision:"cloud-identity-2026-11-16.25",entries,outcomes:{new:"copied",old:"already_present"},
    flags:new Map([["written",written],["existing",prior]]),nativeFlags:new Map<string,TargetSelection>(),
    baseline:new Map([["existing",prior]]),allFlags:[written,prior],unchangedKeys:new Set<string>(),
    reported:{groups:1,active:0,harness:0,activeDemoted:0,harnessDemoted:0,selectionConflicts:0}};
  assert.equal(credentialCloudSelection(input).ok,true);
  assert.equal(credentialCloudSelection({...input,flags:new Map([["written",prior],["existing",written]])}).ok,false);
  const selected={...input,entries:entries.map((entry) => ({...entry,active:true,harness:true})),
    outcomes:{new:"updated",old:"already_present"},flags:new Map([["written",prior],["existing",written]]),
    allFlags:[prior,written],reported:{...input.reported,active:1,harness:1}};
  assert.equal(credentialCloudSelection(selected).ok,true);
  assert.equal(credentialCloudSelection({...selected,flags:input.flags}).ok,false);
  assert.equal(credentialCloudSelection({...selected,reported:{...selected.reported,activeDemoted:1}}).ok,false);
});

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
  assert.equal(cutoverScopeFinding({...record,targetSchema:{profile:"main-plus-optional",ok:true}}).ok,false);
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

test("exhausted API key cannot be accounted as a dead OAuth login",() => {
  const summary=exclusionAccounting();
  assert.equal(accountCredentialExclusion(summary,{reason:"dead_login",provider:"openai",authType:"byo_api_key",
    status:"connected",refreshExhausted:true}),false);
  assert.deepEqual(summary.find((entry) => entry.reason === "dead_login"),{reason:"dead_login",accounted:0,unresolved:1});
});

const convergenceReport=() => ({version:1,mappingRevision:MAPPING_REVISION,mode:"apply",ok:true,outcomes:{} as Record<string,number>,
  writes:{inserted:0,updated:0,blobWrites:0,metadataWrites:0,selectionWrites:0}});
const independentCohort=credentialConvergenceCohort(["00000000-0000-4000-8000-000000000001"]);
const checkpoint=(phase:"before"|"after",empty=false):CredentialConvergenceSnapshot => {
  const state={version:2 as const,mappingRevision:MAPPING_REVISION,scope:{orgIds:null},
    credentials:empty ? [] : [{key:independentCohort.keys[0]!,stateSha256:"b".repeat(64),blobVersion:null}],blobs:[],markers:[]};
  return {...state,kind:"credential-convergence",phase,nonce:(phase === "before" ? "c" : "d").repeat(64),
    digest:credentialCheckpointDigest(state),sessionSafety:{transactionReadOnly:"on",isolation:"repeatable read",statementTimeout:"1min",lockTimeout:"5s"}};
};
const receiptReport=(before:CredentialConvergenceSnapshot) => ({...convergenceReport(),
  convergence:{beforeDigest:before.digest,nonce:before.nonce}});

test("convergence requires all five explicit valid write counters and bound report outcomes",() => {
  const report=convergenceReport();assert.deepEqual(credentialWriteCounts(report),report.writes);
  for (const key of Object.keys(report.writes)) {
    const absent=structuredClone(report) as unknown as {writes:Record<string,unknown>};delete absent.writes[key];
    assert.equal(credentialWriteCounts(absent),null);
    for (const invalid of [-1,0.5,"0",null,Number.MAX_SAFE_INTEGER+1]) {
      const malformed=structuredClone(report) as unknown as {writes:Record<string,unknown>};malformed.writes[key]=invalid;
      assert.equal(credentialWriteCounts(malformed),null);
    }
  }
  assert.equal(credentialWriteCounts({...report,writes:{...report.writes,unknownWrites:0}}),null);
  assert.equal(credentialWriteCounts({...report,mappingRevision:"old-revision"}),null);
  assert.equal(credentialWriteCounts({...report,mode:"plan"}),null);
  assert.equal(credentialWriteCounts({...report,outcomes:{updated:1}}),null);
  assert.equal(credentialWriteCounts({...report,selection:{writes:1}}),null);
});

test("nonzero counters fail convergence even when all independent target state is unchanged",() => {
  const before=checkpoint("before"),after=checkpoint("after");
  assert.equal(compareCredentialConvergence(before,after,receiptReport(before),independentCohort).ok,true);
  assert.equal(compareCredentialConvergence(before,after,{},independentCohort).ok,false);
  for (const key of Object.keys(convergenceReport().writes) as (keyof ReturnType<typeof convergenceReport>["writes"])[]) {
    const report=receiptReport(before);report.writes[key]=1;
    if (key === "inserted") report.outcomes.copied=1;
    if (key === "updated") report.outcomes.updated=1;
    const complete=key === "selectionWrites" ? {...report,selection:{writes:1}} : report;
    assert.notEqual(credentialWriteCounts(complete),null);
    assert.equal(compareCredentialConvergence(before,after,complete,independentCohort).ok,false,key);
  }
  assert.throws(() => compareCredentialConvergence(after,after,convergenceReport(),independentCohort),/baseline/);
});

test("empty state cannot qualify convergence even with zero counters and a matching receipt",() => {
  const before=checkpoint('before',true),after=checkpoint('after',true);
  assert.throws(() => validateCredentialCheckpoint(before,{orgIds:null}),/empty/);
  const finding=compareCredentialConvergence(before,after,receiptReport(before),independentCohort);
  assert.equal(finding.ok,false);
  assert.equal((finding.detail as {nonemptyBefore:boolean}).nonemptyBefore,false);
  assert.deepEqual((finding.detail as {binding:unknown}).binding,{receiptValid:true,digestMatches:true,nonceMatches:true});
});

test("post-rerun relabelled checkpoints fail receipt nonce or fresh-before digest binding",() => {
  const before=checkpoint('before'),after=checkpoint('after');
  const report=receiptReport(before);
  const relabelled={...after,phase:'before' as const};
  assert.doesNotThrow(() => validateCredentialCheckpoint(relabelled,{orgIds:null}));
  const wrongNonce=compareCredentialConvergence(relabelled,after,report,independentCohort);
  assert.equal(wrongNonce.ok,false);
  assert.deepEqual((wrongNonce.detail as {binding:unknown}).binding,{receiptValid:true,digestMatches:true,nonceMatches:false});
  const changed={...after,credentials:[{...after.credentials[0]!,stateSha256:'e'.repeat(64)}]};
  changed.digest=credentialCheckpointDigest(changed);
  const replayedNonce={...changed,phase:'before' as const,nonce:before.nonce};
  const wrongDigest=compareCredentialConvergence(replayedNonce,changed,report,independentCohort);
  assert.equal(wrongDigest.ok,false);
  assert.deepEqual((wrongDigest.detail as {binding:unknown}).binding,{receiptValid:true,digestMatches:false,nonceMatches:true});
  assert.deepEqual((wrongDigest.detail as {credentialChanges:unknown}).credentialChanges,{inserted:0,removed:0,changed:0});
});

test("nonempty unrelated state cannot substitute for the independent source cohort",() => {
  const before=checkpoint('before'),after=checkpoint('after'),report=receiptReport(before);
  assert.equal(compareCredentialConvergence(before,after,report).ok,false,'missing source cohort fails');
  assert.equal(compareCredentialConvergence(before,after,report,credentialConvergenceCohort([])).ok,false,'empty source cohort fails even with nonempty target');
  const unrelated=credentialConvergenceCohort(['00000000-0000-4000-8000-000000000002']);
  const finding=compareCredentialConvergence(before,after,report,unrelated);
  assert.equal(finding.ok,false);
  assert.equal((finding.detail as {nonemptyBefore:boolean}).nonemptyBefore,true);
  const cohort=(finding.detail as {cohort:{expectedCount:number;beforeCount:number;afterCount:number}}).cohort;
  assert.equal(cohort.expectedCount,1);assert.equal(cohort.beforeCount,0);assert.equal(cohort.afterCount,0);
});
