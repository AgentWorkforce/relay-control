import { accountCredentialExclusion,exclusionAccounting } from "./exclusions.js";

import { readCopierMarkers } from "./copier-markers.js";
import { credentialWriteCounts,readCredentialConvergence,compareCredentialConvergence,type CredentialConvergenceSnapshot } from "./convergence.js";
import { beginReadOnlySnapshot,type ReadOnlySettings } from "./read-only.js";
import { createHash,createHmac } from "node:crypto";
import type { Client } from "pg";
import { decryptSecret,type EncryptionKeyring } from "../../src/crypto.js";
import { CredentialBlobStore,PostgresObjectBackend } from "../../src/admin/credential-blobs.js";
import type { Database } from "../../src/database.js";
import { describeAuthFile,type SubscriptionProvider } from "../../src/admin/subscription-logins.js";
import { canonicalProvider,cloudObjectKeys,type CloudObjectReader,type CredentialCopyReport } from "../cloud-import/credentials.js";
import { decryptCloudEnvelope } from "../cloud-import/importer.js";
import { credentialCopyQuery,MAPPING_REVISION,assertScope,type ImportScope } from "../cloud-import/mapping.js";
import type { Finding } from "./verify.js";

export interface CredentialEvidence {
  report:CredentialCopyReport;
  reader:CloudObjectReader;
  targetBlobs:CredentialBlobStore;
  previousTarget?:CredentialTargetSnapshot;
  convergenceBefore?:CredentialConvergenceSnapshot;
}

/** CLI backend deliberately exposes local Postgres GETs only. */
export function readOnlyPostgresBlobs(target:Client,keyring:EncryptionKeyring):CredentialBlobStore {
  const db:Database = {
    query:async <T extends Record<string,unknown>>(sql:string,params:unknown[] = []) => ({rows:(await target.query(sql,params)).rows as T[]}),
    exec:async () => {throw new Error("read_only");},
    transaction:async () => {throw new Error("read_only");},close:async () => {},
  };
  return new CredentialBlobStore(new PostgresObjectBackend(db),keyring);
}
const hash = (value:string) => createHash("sha256").update(value).digest("hex");
const fingerprint = (provider:string,type:string,secret:string,keyring:EncryptionKeyring) =>
  createHmac("sha256",keyring.active.key).update(`selfhost-coding-agent-credential\0${provider}\0${type}\0${secret}`).digest("hex");
const naturalKey = (workspace:string,provider:string,type:string,identity:string) =>
  hash(JSON.stringify([workspace,provider,type,identity]));
const digestKeys = (keys:Iterable<string>) => hash(JSON.stringify([...keys].sort()));

export interface CredentialTargetSnapshot {
  sessionSafety?:ReadOnlySettings;
  version:1;
  scope:ImportScope;
  rows:{key:string;group:string;org:string;active:boolean;harness:boolean}[];
}
const targetKey = (row:{workspace_id:string;model_provider:string;auth_type:string;provider_account_id:string|null;account_email:string|null;key_fingerprint:string|null}) => naturalKey(row.workspace_id,row.model_provider,row.auth_type,
  row.auth_type === "provider_oauth" ? `account:${row.provider_account_id}`
    : row.auth_type === "oauth_token" && row.account_email?.trim()
      ? `account:${row.account_email.trim().toLowerCase()}` : `fingerprint:${row.key_fingerprint}`);

/** Capture before copying to establish which unmatched rows are Control-owned.
 * Account ids and fingerprints never leave this read-only transaction. */
export async function captureCredentialTarget(target:Client,scope:ImportScope):Promise<CredentialTargetSnapshot> {
  assertScope(scope);
  try {
    const sessionSafety=await beginReadOnlySnapshot(target);
    await target.query(`DECLARE credential_before_cursor NO SCROLL CURSOR FOR SELECT c.* FROM public.coding_agent_credentials c
      JOIN public.workspaces w ON w.id=c.workspace_id WHERE c.auth_type <> 'relay_managed'
        AND ($1::uuid[] IS NULL OR w.organization_id=ANY($1::uuid[])) ORDER BY c.id`,[scope.orgIds]);
    const rows:CredentialTargetSnapshot["rows"]=[];
    for (;;) {
      const batch=await target.query("FETCH FORWARD 250 FROM credential_before_cursor");if (!batch.rows.length) break;
      for (const row of batch.rows) {
        if (rows.length >= 10000) throw new Error("Credential snapshot requires a smaller cohort");
        rows.push({key:targetKey(row),group:`${row.workspace_id}:${row.model_provider}`,org:row.organization_id,
          active:row.is_active,harness:row.harness_active});
      }
    }
    return {version:1,sessionSafety,scope:{orgIds:scope.orgIds === null ? null : [...scope.orgIds]},rows};
  } finally {await target.query("ROLLBACK");}
}

function priorCredentials(snapshot:CredentialTargetSnapshot|undefined,scope:ImportScope) {
  const rows=new Map<string,CredentialTargetSnapshot["rows"][number]>();
  if (!snapshot) return rows;
  assertScope(snapshot.scope);
  if (snapshot.version !== 1 || !Array.isArray(snapshot.rows) || snapshot.rows.length > 10000
    || (snapshot.scope.orgIds !== null && (scope.orgIds === null || scope.orgIds.some((id) =>
      !snapshot.scope.orgIds!.some((prior) => prior.toLowerCase() === id.toLowerCase()))))) throw new Error("Invalid credential baseline");
  for (const row of snapshot.rows) {
    if (!/^[0-9a-f]{64}$/.test(row.key) || !/^[0-9a-f-]{36}:[a-z][a-z0-9_]*$/.test(row.group)
      || !/^[0-9a-f-]{36}$/.test(row.org) || typeof row.active !== "boolean" || typeof row.harness !== "boolean"
      || rows.has(row.key) || (snapshot.scope.orgIds !== null && !snapshot.scope.orgIds.some((id) => id.toLowerCase() === row.org.toLowerCase()))) throw new Error("Invalid credential baseline entry");
    rows.set(row.key,row);
  }
  return rows;
}

/** Read-only selection cardinality: model and sandbox are distinct selectors.
 * Sandbox selection may be empty; copied Cloud choices are checked separately.
 */
export async function credentialSelections(target:Client,scope:ImportScope):Promise<Finding[]> {
  const groups = await target.query(`SELECT c.workspace_id::text,c.model_provider,
    count(*) FILTER(WHERE c.auth_type <> 'provider_oauth')::int AS model_eligible,
    count(*) FILTER(WHERE c.auth_type IN ('oauth_token','provider_oauth'))::int AS harness_eligible,
    count(*) FILTER(WHERE c.is_active)::int AS model_active,
    count(*) FILTER(WHERE c.harness_active)::int AS harness_active
    FROM public.coding_agent_credentials c JOIN public.workspaces w ON w.id=c.workspace_id
    WHERE $1::uuid[] IS NULL OR w.organization_id=ANY($1::uuid[])
    GROUP BY c.workspace_id,c.model_provider ORDER BY c.workspace_id,c.model_provider`,[scope.orgIds]);
  return groups.rows.map((group) => ({kind:"credential_selection",name:`${group.workspace_id}:${group.model_provider}`,
    ok:group.model_active <= 1 && group.model_active >= (group.model_eligible > 0 ? 1 : 0)
      && group.harness_active <= 1 && (group.harness_eligible > 0 || group.harness_active === 0),detail:group}));
}

type Expected = {org:string;workspace:string;provider:string;authType:string;identity:string;fingerprint:string;contentHash:string};

/** Caller owns frozen read-only source/target snapshots. No store methods that
 * mint, rotate, refresh or mutate credentials are called. Reports retain only
 * counts and hashes; plaintext, fingerprints and account identities stay out.
 */
export async function credentialCopyFindings(source:Client,target:Client,scope:ImportScope,
  evidence:CredentialEvidence,keyring:EncryptionKeyring,cloudKeyHex:string):Promise<Finding[]> {
  const expected = new Map<string,Expected>();
  const sourceIds = new Set<string>();
  const expectedBySourceId=new Map<string,string>();
  const selections:{id:string;key:string;group:string;active:boolean;harness:boolean;updated:number}[]=[];
  const expectedOutcomes:Record<string,number> = {};
  const {report} = evidence;
  const baseline=priorCredentials(evidence.previousTarget,scope);
  let candidates = 0;
  let sourceFailures = 0;
  let unresolvedSourceSkips = 0;
  let rowOutcomesMatch = true;
  const deliberateExclusions=exclusionAccounting();
  await source.query(`DECLARE credential_copy_cursor NO SCROLL CURSOR FOR
    SELECT q.*,p.status AS __source_status,p.refresh_exhausted AS __source_refresh_exhausted
    FROM (${credentialCopyQuery(scope)}) q JOIN public.provider_credentials p ON p.id=q.id`);
  try {for (;;) {
    const batch = await source.query("FETCH FORWARD 250 FROM credential_copy_cursor");
    if (!batch.rows.length) break;
    for (const row of batch.rows) {
      if (++candidates > 10000) throw new Error("Credential verification exceeds the bounded cohort size");
      sourceIds.add(row.id);
      const outcome:unknown = report.rows?.[row.id];
      if (typeof outcome === "string") expectedOutcomes[outcome] = (expectedOutcomes[outcome] ?? 0)+1;
      if (row.skip_reason) {
        rowOutcomesMatch &&= outcome === `skipped:${row.skip_reason}`;
        const accounted=accountCredentialExclusion(deliberateExclusions,{reason:row.skip_reason,provider:row.model_provider,
          authType:row.auth_type,status:row.__source_status,refreshExhausted:row.__source_refresh_exhausted});
        if (accounted === false || (accounted === null
          && !["workspace_not_imported","user_not_imported","not_a_member","credential_not_usable"].includes(row.skip_reason))) unresolvedSourceSkips++;
        continue;
      }
      let plaintext:string|undefined;
      try {
        for (const key of cloudObjectKeys(row as Parameters<typeof cloudObjectKeys>[0])) {
          const body = await evidence.reader.get(key);
          if (body === null) continue;
          plaintext = decryptCloudEnvelope(JSON.parse(body),cloudKeyHex); break;
        }
        if (plaintext === undefined) {
          sourceFailures++;rowOutcomesMatch &&= outcome === (Object.hasOwn(row,"legacy_allowed") && row.auth_type !== "byo_api_key" && !row.legacy_allowed
            ? "skipped:legacy_key_ambiguous" : "object_missing");continue;
        }
        const provider = canonicalProvider(row.model_provider);
        let identity:string;
        let content:string;
        let fp:string;
        if (row.auth_type === "provider_oauth") {
          const described = describeAuthFile(provider as SubscriptionProvider,plaintext,row.account_email);
          identity = `account:${described.accountId}`;
          content = plaintext;
          fp = fingerprint(provider,row.auth_type,described.refreshToken,keyring);
        } else {
          const payload = JSON.parse(plaintext);
          const value = row.auth_type === "byo_api_key" ? payload.key : payload.token;
          if (typeof value !== "string" || !value.trim()) throw new Error("invalid_secret_payload");
          content = value.trim();
          fp = fingerprint(provider,row.auth_type,content,keyring);
          identity = row.auth_type === "oauth_token" && row.account_email?.trim()
            ? `account:${row.account_email.trim().toLowerCase()}` : `fingerprint:${fp}`;
        }
        // Last source row wins when Control replaces a setup token or login
        // for the same account. Only hashes, never plaintext, are retained.
        const key=naturalKey(row.workspace_id,provider,row.auth_type,identity);
        expectedBySourceId.set(row.id,key);
        selections.push({id:row.id,key,group:`${row.workspace_id}:${provider}`,active:row.is_active,
          harness:row.harness_active && ["oauth_token","provider_oauth"].includes(row.auth_type),updated:new Date(row.updated_at).getTime()});
        expected.set(key,{
          org:row.organization_id,workspace:row.workspace_id,provider,authType:row.auth_type,identity,
          fingerprint:fp,contentHash:hash(content),
        });
        rowOutcomesMatch &&= outcome === "copied" || outcome === "already_present"
          || (outcome === "updated" && Boolean(credentialWriteCounts(report)?.updated));
      } catch {sourceFailures++;rowOutcomesMatch = false;}
    }
  }} finally {await source.query("CLOSE credential_copy_cursor");}
  const reportedIds = Object.keys(report.rows ?? {});
  const totals = (values:Record<string,number>) => JSON.stringify(Object.entries(values).sort(([a],[b]) => a.localeCompare(b)));
  const findings:Finding[] = [{kind:"credential_copy_ledger",name:"run",
    ok:report.version === 1 && report.mappingRevision === MAPPING_REVISION && report.mode === "apply" && report.ok
      && report.candidates === candidates && reportedIds.length === sourceIds.size
      && reportedIds.every((id) => sourceIds.has(id)) && rowOutcomesMatch
      && totals(report.outcomes) === totals(expectedOutcomes),
    detail:{candidates,sourceFailures,unresolvedSourceSkips,reportedCandidates:Number.isSafeInteger(report.candidates) ? report.candidates : null}},
    {kind:"credential_exclusions",name:"credential_copy",ok:!unresolvedSourceSkips,
      detail:{classes:deliberateExclusions,unresolvedSourceSkips}}];
  const seen = new Set<string>();
  const targetKeysById=new Map<string,string>();
  const targetVersions=new Map<string,number>();
  let duplicateKeys = 0;
  let contentFailures = 0;
  // Fixed reason names and counts only: no target IDs, ciphertext, account
  // values, plaintext, driver messages or object locations enter diagnostics.
  // A row can have several reasons; contentFailures still counts rows once.
  const contentFailureReasons={organizationMismatch:0,statusNotConnected:0,fingerprintMismatch:0,
    contentMismatch:0,blobBackendMismatch:0,targetReadOrDecryptFailed:0};
  let extra = 0;
  let unexplainedTarget=0;
  const nativeFlags=new Map<string,{group:string;active:boolean;harness:boolean}>();
  const flags=new Map<string,{group:string;active:boolean;harness:boolean}>();
  const targetExecutor = {
    query:async <T extends Record<string,unknown>>(sql:string,params:unknown[] = []) => ({rows:(await target.query(sql,params)).rows as T[]}),
    exec:async (sql:string) => {await target.query(sql);},
  };
  await target.query(`DECLARE credential_target_cursor NO SCROLL CURSOR FOR
    SELECT c.* FROM public.coding_agent_credentials c JOIN public.workspaces w ON w.id=c.workspace_id
    WHERE c.auth_type <> 'relay_managed' AND ($1::uuid[] IS NULL OR w.organization_id=ANY($1::uuid[]))`,[scope.orgIds]);
  try {for (;;) {
    const batch = await target.query("FETCH FORWARD 250 FROM credential_target_cursor");
    if (!batch.rows.length) break;
    for (const row of batch.rows) {
      if (seen.size > 10000) throw new Error("Credential verification exceeds the bounded cohort size");
      const key = targetKey(row);
      targetKeysById.set(row.id,key);
      if (row.auth_type === "provider_oauth") targetVersions.set(row.id,row.blob_version);
      if (seen.has(key)) duplicateKeys++;
      seen.add(key);
      const wanted = expected.get(key);
      if (!wanted) {
        extra++;
        const prior=baseline.get(key);
        if (!prior || prior.org !== row.organization_id || prior.group !== `${row.workspace_id}:${row.model_provider}`) unexplainedTarget++;
        else nativeFlags.set(key,{group:prior.group,active:row.is_active,harness:row.harness_active});
        continue;
      }
      flags.set(key,{group:`${row.workspace_id}:${row.model_provider}`,active:row.is_active,harness:row.harness_active});
      let failed=false;
      if (row.organization_id !== wanted.org) {contentFailureReasons.organizationMismatch++;failed=true;}
      if (row.status !== "connected") {contentFailureReasons.statusNotConnected++;failed=true;}
      if (row.key_fingerprint !== wanted.fingerprint) {contentFailureReasons.fingerprintMismatch++;failed=true;}
      if (row.auth_type === "provider_oauth" && row.blob_backend !== evidence.targetBlobs.kind) {
        contentFailureReasons.blobBackendMismatch++;failed=true;
      } else {
        try {
          const content = row.auth_type === "provider_oauth"
            ? await evidence.targetBlobs.read(row.blob_location,row.id,Number(row.blob_version),targetExecutor)
            : decryptSecret(row.secret_ciphertext,keyring);
          if (hash(content) !== wanted.contentHash) {contentFailureReasons.contentMismatch++;failed=true;}
        } catch {contentFailureReasons.targetReadOrDecryptFailed++;failed=true;}
      }
      if (failed) contentFailures++;
    }
  }} finally {await target.query("CLOSE credential_target_cursor");}
  const missing = [...expected.keys()].filter((key) => !seen.has(key)).length;
  findings.push({kind:"credential_natural_keys",name:"coding_agent_credentials",
    ok:!sourceFailures && !unresolvedSourceSkips && !duplicateKeys && !contentFailures && !missing && !unexplainedTarget,
    detail:{expected:expected.size,target:seen.size,missing,unmatchedTarget:extra,unexplainedTarget,duplicateKeys,contentFailures,contentFailureReasons,
      sourceFailures,unresolvedSourceSkips,sourceChecksum:digestKeys(expected.keys()),targetChecksum:digestKeys(flags.keys())}});
  const controlIds=report.controlIds;
  const validMap=controlIds !== null && typeof controlIds === "object" && !Array.isArray(controlIds);
  const mapEntries=validMap ? Object.entries(controlIds) : [];
  let idMismatches=0;
  for (const [sourceId,key] of expectedBySourceId) {
    const controlId=validMap ? controlIds[sourceId] : undefined;
    if (typeof controlId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(controlId)
      || targetKeysById.get(controlId) !== key) idMismatches++;
  }
  const extraIds=mapEntries.filter(([id]) => !expectedBySourceId.has(id)).length;
  findings.push({kind:"credential_control_ids",name:"coding_agent_credentials",
    ok:validMap && mapEntries.length === expectedBySourceId.size && !idMismatches && !extraIds,
    detail:{expected:expectedBySourceId.size,reported:validMap ? mapEntries.length : null,idMismatches,extraIds}});
  const summary={groups:0,active:0,harness:0,activeDemoted:0,harnessDemoted:0,selectionConflicts:0};
  let selectionMismatches=0;
  const allFlags=(await target.query(`SELECT workspace_id::text,model_provider,is_active,harness_active FROM public.coding_agent_credentials c
    JOIN public.workspaces w ON w.id=c.workspace_id WHERE $1::uuid[] IS NULL OR w.organization_id=ANY($1::uuid[])`,[scope.orgIds])).rows;
  const selectionGroups=new Map<string,typeof selections>();
  for (const entry of selections) {
    const group=selectionGroups.get(entry.group) ?? [];group.push(entry);selectionGroups.set(entry.group,group);
  }
  const flagGroups=new Map<string,[string,{group:string;active:boolean;harness:boolean}][]>();
  for (const entry of flags) {
    const group=flagGroups.get(entry[1].group) ?? [];group.push(entry);flagGroups.set(entry[1].group,group);
  }
  const groupCounts=new Map<string,{active:number;harness:number}>();
  for (const row of allFlags) {
    const key=`${row.workspace_id}:${row.model_provider}`;
    const count=groupCounts.get(key) ?? {active:0,harness:0};
    count.active+=Number(row.is_active);count.harness+=Number(row.harness_active);groupCounts.set(key,count);
  }
  for (const [group,entries] of selectionGroups) {
    summary.groups++;
    const copiedKeys=new Set(entries.map((entry) => entry.key));
    const groupFlags=flagGroups.get(group) ?? [];
    for (const column of ["active","harness"] as const) {
      const candidates=entries.filter((entry) => entry[column]);
      const chosen=[...candidates].sort((a,b) => b.updated-a.updated || a.id.localeCompare(b.id))[0];
      const selectedCopies=groupFlags.filter(([,entry]) => entry[column]);
      if (chosen) {
        summary[column]++;
        const demoted=Math.max(0,new Set(candidates.map((entry) => entry.key)).size-1);
        if (column === "active") summary.activeDemoted+=demoted;else summary.harnessDemoted+=demoted;
        const total=groupCounts.get(group)?.[column] ?? 0;
        if (selectedCopies.length !== 1 || selectedCopies[0]![0] !== chosen.key || total !== 1) selectionMismatches++;
      } else if (selectedCopies.length) {
        if (column === "active") summary.selectionConflicts++;else selectionMismatches++;
      }
    }
    if (groupFlags.length !== copiedKeys.size) selectionMismatches++;
  }
  for (const [key,prior] of baseline) {
    if (expected.has(key) || (scope.orgIds !== null && !scope.orgIds.some((id) => id.toLowerCase() === prior.org.toLowerCase()))) continue;
    const native=nativeFlags.get(key);
    if (!native) {selectionMismatches++;continue;}
    const entries=selectionGroups.get(prior.group) ?? [];
    for (const column of ["active","harness"] as const) {
      const chosen=entries.some((entry) => entry[column]);
      if (native[column] !== (chosen ? false : prior[column])) selectionMismatches++;
    }
  }
  const markerState=await readCopierMarkers(target,scope);
  const receipt=credentialWriteCounts(report);
  const hasReceipt=Object.hasOwn(report,"writes");
  let markerExpected=0,markerMissing=0,markerMismatches=0;
  if (receipt) for (const [sourceId,key] of expectedBySourceId) {
    const outcome:unknown=report.rows[sourceId];
    const expectedRow=expected.get(key)!;
    if (expectedRow.authType !== "provider_oauth" || (outcome !== "copied" && outcome !== "updated")) continue;
    markerExpected++;
    const controlId=report.controlIds?.[sourceId];const marker=markerState.markers.get(controlId!);
    if (!marker) markerMissing++;
    else if (marker.org !== expectedRow.org || marker.version !== targetVersions.get(controlId!)) markerMismatches++;
  }
  findings.push({kind:"credential_marker_links",name:"written_logins",
    ok:(!hasReceipt || receipt !== null) && !markerMissing && !markerMismatches,
    detail:{receiptStatus:hasReceipt ? receipt ? "valid" : "invalid" : "legacy_without_write_receipt",
      expected:markerExpected,missing:markerMissing,mismatches:markerMismatches}});
  const reported=report.selection;
  const matches=reported === undefined ? selectionGroups.size === 0 : Object.entries(summary).every(([key,value]) =>
    reported[key as keyof typeof summary] === value);
  findings.push({kind:"credential_cloud_selection",name:"coding_agent_credentials",
    ok:matches && !selectionMismatches && !summary.selectionConflicts,
    detail:{...summary,selectionMismatches,reportMatches:matches}});
  if (evidence.convergenceBefore) findings.push(compareCredentialConvergence(evidence.convergenceBefore,
    await readCredentialConvergence(target,"after"),report));
  return findings;
}
