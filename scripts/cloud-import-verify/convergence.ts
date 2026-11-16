import type { SqlExecutor } from "../../src/database.js";
import { createHash,randomBytes } from "node:crypto";
import type { Client } from "pg";
import { MAPPING_REVISION,type ImportScope } from "../cloud-import/mapping.js";
import { beginReadOnlySnapshot,inspectReadOnlySnapshot,type ReadOnlySettings } from "./read-only.js";
import type { Finding } from "./verify.js";

const hash=(value:string) => createHash("sha256").update(value).digest("hex");
export type StateRow={key:string;stateSha256:string;blobVersion:number|null};
export type CredentialCheckpointState={version:2;mappingRevision:string;scope:{orgIds:null};
  credentials:StateRow[];blobs:StateRow[];markers:StateRow[]};
export type ComputedCredentialCheckpoint=CredentialCheckpointState & {digest:string};
export type CredentialConvergenceSnapshot=ComputedCredentialCheckpoint & {kind:"credential-convergence";
  phase:"before"|"after";nonce:string;sessionSafety:ReadOnlySettings};
export type CredentialConvergenceReceipt={beforeDigest:string;nonce:string};

const canonical=(value:unknown):unknown => Array.isArray(value) ? value.map(canonical)
  : value !== null && typeof value === "object" ? Object.fromEntries(Object.entries(value).sort(([a],[b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([key,v]) => [key,canonical(v)])) : value;
/** Lowercase hex SHA-256 of UTF-8 canonical state JSON. Nonce, phase and
 * session settings are excluded so the writer can independently reread it. */
export function credentialCheckpointDigest(state:CredentialCheckpointState):string {
  const ordered=(rows:StateRow[]) => [...rows].sort((a,b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
  return hash(JSON.stringify(canonical({version:state.version,mappingRevision:state.mappingRevision,scope:state.scope,
    credentials:ordered(state.credentials),blobs:ordered(state.blobs),markers:ordered(state.markers)})));
}

/** Shared producer/verifier computation. Caller owns a quiescent transaction;
 * this function issues SELECT/cursor and canonical SET LOCAL statements only.
 * All source organizations are required. It never begins/commits or writes. */
export async function computeCredentialCheckpoint(tx:SqlExecutor,scope:ImportScope):Promise<ComputedCredentialCheckpoint> {
  if (scope.orgIds !== null) throw new Error("Convergence requires all source organizations");
  if ((await tx.query<{transaction_isolation:string}>("SHOW transaction_isolation")).rows[0]?.transaction_isolation !== "repeatable read")
    throw new Error("Checkpoint computation requires a repeatable-read transaction");
  await tx.exec("SET LOCAL statement_timeout='60s'");
  await tx.exec("SET LOCAL lock_timeout='5s'");
  await tx.exec("SET LOCAL TIME ZONE 'UTC'");
  await tx.exec("SET LOCAL DateStyle='ISO, YMD'");
  await tx.exec("SET LOCAL row_security=off");
  if ((await tx.query<{unsupported:boolean}>(`SELECT EXISTS(SELECT 1 FROM public.coding_agent_credentials
    WHERE auth_type='provider_oauth' AND blob_backend IS DISTINCT FROM 'postgres') AS unsupported`)).rows[0]!.unsupported)
    throw new Error("Convergence capture requires Postgres credential blobs");
  const credentials:StateRow[]=[],blobs:StateRow[]=[],markers:StateRow[]=[];
  for (const [relation,key,version,rows,limit,where] of [
    ["coding_agent_credentials","id::text","blob_version",credentials,10000,""],
    ["coding_agent_credential_blobs","object_key","NULL::int",blobs,50000,""],
    ["cloud_import_ledger","organization_id::text||':'||row_key","NULL::int",markers,10000,"WHERE table_name='copier_login'"],
  ] as const) {
    await tx.exec(`DECLARE convergence_cursor NO SCROLL CURSOR FOR SELECT ${key} AS key,${version} AS version,
      to_jsonb(t)::text AS state,t.xmin::text AS xmin,t.ctid::text AS ctid
      FROM public.${relation} t ${where} ORDER BY ${key} COLLATE "C"`);
    try {for (;;) {
      const batch=await tx.query<{key:string;version:number|null;state:string;xmin:string;ctid:string}>("FETCH FORWARD 25 FROM convergence_cursor");
      if (!batch.rows.length) break;
      for (const row of batch.rows) {
        if (rows.length >= limit) throw new Error("Convergence snapshot exceeds bounded size");
        rows.push({key:hash(row.key),stateSha256:hash(JSON.stringify([row.state,row.xmin,row.ctid])),blobVersion:row.version});
      }
    }} finally {await tx.exec("CLOSE convergence_cursor");}
  }
  const state:CredentialCheckpointState={version:2,mappingRevision:MAPPING_REVISION,scope:{orgIds:null},credentials,blobs,markers};
  return {...state,digest:credentialCheckpointDigest(state)};
}

/** Read verifier-owned state in its existing checked read-only snapshot. */
export async function readCredentialConvergence(target:Client,phase:"before"|"after"):Promise<CredentialConvergenceSnapshot> {
  const sessionSafety=await inspectReadOnlySnapshot(target);
  const tx:SqlExecutor={query:async <T extends Record<string,unknown>>(sql:string,params:unknown[]=[]) =>
    ({rows:(await target.query(sql,params)).rows as T[]}),exec:async (sql:string) => {await target.query(sql);}};
  return {...await computeCredentialCheckpoint(tx,{orgIds:null}),kind:"credential-convergence",phase,
    nonce:randomBytes(32).toString("hex"),sessionSafety};
}

/** Capture before the rerun; writer must independently compute the same state
 * before any writes and bind its computed digest plus this nonce in receipt. */
export async function captureCredentialConvergence(target:Client,phase:"before"|"after"="before") {
  try {
    await beginReadOnlySnapshot(target);
    const snapshot=await readCredentialConvergence(target,phase);
    if (phase === "before") validateCredentialCheckpoint(snapshot,{orgIds:null});
    return snapshot;
  } finally {await target.query("ROLLBACK");}
}

function rowsByKey(rows:StateRow[],limit:number) {
  if (!Array.isArray(rows) || rows.length > limit) throw new Error("Invalid convergence snapshot");
  const result=new Map<string,StateRow>();
  for (const row of rows) {
    if (!row || typeof row.key !== "string" || typeof row.stateSha256 !== "string"
      || !/^[0-9a-f]{64}$/.test(row.key) || !/^[0-9a-f]{64}$/.test(row.stateSha256) || result.has(row.key)
      || (row.blobVersion !== null && (!Number.isSafeInteger(row.blobVersion) || row.blobVersion < 0))) throw new Error("Invalid convergence snapshot");
    result.set(row.key,row);
  }
  return result;
}

function validateSnapshot(snapshot:CredentialConvergenceSnapshot,phase:"before"|"after") {
  if (!snapshot || snapshot.version !== 2 || snapshot.kind !== "credential-convergence" || snapshot.phase !== phase
    || snapshot.mappingRevision !== MAPPING_REVISION || snapshot.scope?.orgIds !== null
    || typeof snapshot.nonce !== "string" || typeof snapshot.digest !== "string"
    || !/^[0-9a-f]{64}$/.test(snapshot.nonce) || !/^[0-9a-f]{64}$/.test(snapshot.digest)
    || snapshot.sessionSafety?.transactionReadOnly !== "on" || snapshot.sessionSafety.isolation !== "repeatable read"
    || snapshot.sessionSafety.statementTimeout !== "1min" || snapshot.sessionSafety.lockTimeout !== "5s") throw new Error("Invalid convergence baseline");
  rowsByKey(snapshot.credentials,10000);rowsByKey(snapshot.blobs,50000);rowsByKey(snapshot.markers,10000);
  if (credentialCheckpointDigest(snapshot) !== snapshot.digest) throw new Error("Invalid convergence checkpoint digest");
}
/** Pure validation shared with the producer CLI. It must run before any write.
 * No missing/empty/mutated/revision-mismatched checkpoint may authorize a run. */
export function validateCredentialCheckpoint(value:unknown,scope:ImportScope):CredentialConvergenceSnapshot {
  if (scope.orgIds !== null) throw new Error("Convergence requires all source organizations");
  const snapshot=value as CredentialConvergenceSnapshot;validateSnapshot(snapshot,"before");
  if (!snapshot.credentials.length) throw new Error("Convergence checkpoint is empty");
  return snapshot;
}

export type CredentialConvergenceCohort={count:number;sha256:string;keys:readonly string[]};
/** IDs come from independently source-derived expected natural keys and their
 * validated actual target ID links, never from a before checkpoint roster. */
export function credentialConvergenceCohort(controlIds:Iterable<string>):CredentialConvergenceCohort {
  const keys=[...new Set([...controlIds].map((id) => {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) throw new Error("Invalid expected cohort ID");
    return hash(id.toLowerCase());
  }))].sort();
  return {count:keys.length,sha256:hash(JSON.stringify(keys)),keys};
}

/** Report write counts and independently computed before digest/nonce must
 * agree with the genuine before artifact. Same-value UPDATEs remain visible. */
export function compareCredentialConvergence(before:CredentialConvergenceSnapshot,after:CredentialConvergenceSnapshot,
  report:unknown,expected?:CredentialConvergenceCohort):Finding {
  validateSnapshot(before,"before");validateSnapshot(after,"after");
  const nonemptyBefore=before.credentials.length > 0;
  const raw=report && typeof report === "object" ? (report as Record<string,unknown>).convergence : undefined;
  const receipt=raw && typeof raw === "object" && !Array.isArray(raw) ? raw as Record<string,unknown> : undefined;
  const receiptValid=Boolean(receipt && JSON.stringify(Object.keys(receipt).sort()) === JSON.stringify(["beforeDigest","nonce"])
    && typeof receipt.beforeDigest === "string" && /^[0-9a-f]{64}$/.test(receipt.beforeDigest)
    && typeof receipt.nonce === "string" && /^[0-9a-f]{64}$/.test(receipt.nonce));
  const binding={receiptValid,digestMatches:receiptValid && receipt!.beforeDigest === before.digest,
    nonceMatches:receiptValid && receipt!.nonce === before.nonce};
  const previous=rowsByKey(before.credentials,10000),current=rowsByKey(after.credentials,10000);
  const previousBlobs=rowsByKey(before.blobs,50000),currentBlobs=rowsByKey(after.blobs,50000);
  const previousMarkers=rowsByKey(before.markers,10000),currentMarkers=rowsByKey(after.markers,10000);
  const expectedKeys=Array.isArray(expected?.keys) ? [...expected.keys].sort() : [];
  const expectedValid=Boolean(expected && Number.isSafeInteger(expected.count) && expected.count >= 0 && expected.count <= 10000
    && expectedKeys.length === expected.count && new Set(expectedKeys).size === expectedKeys.length
    && expectedKeys.every((key) => typeof key === "string" && /^[0-9a-f]{64}$/.test(key))
    && expected.sha256 === hash(JSON.stringify(expectedKeys)));
  const beforeKeys=expectedKeys.filter((key) => previous.has(key));
  const afterKeys=expectedKeys.filter((key) => current.has(key));
  const cohort={expectedValid,expectedCount:expectedValid ? expected!.count : null,expectedSha256:expectedValid ? expected!.sha256 : null,
    beforeCount:beforeKeys.length,beforeSha256:hash(JSON.stringify(beforeKeys)),afterCount:afterKeys.length,afterSha256:hash(JSON.stringify(afterKeys))};
  const cohortMatches=expectedValid && expected!.count > 0 && beforeKeys.length === expected!.count && afterKeys.length === expected!.count
    && cohort.beforeSha256 === expected!.sha256 && cohort.afterSha256 === expected!.sha256;
  const differences=(a:Map<string,StateRow>,b:Map<string,StateRow>) => ({
    inserted:[...b.keys()].filter((key) => !a.has(key)).length,removed:[...a.keys()].filter((key) => !b.has(key)).length,
    changed:[...a].filter(([key,row]) => b.has(key) && row.stateSha256 !== b.get(key)!.stateSha256).length});
  const credentialChanges=differences(previous,current),blobChanges=differences(previousBlobs,currentBlobs);
  const markerChanges=differences(previousMarkers,currentMarkers);
  const blobVersionChanges=[...previous].filter(([key,row]) => current.has(key) && row.blobVersion !== current.get(key)!.blobVersion).length;
  const writes=credentialWriteCounts(report);
  const reportedWriteCount=writes ? writes.inserted+writes.updated+writes.metadataWrites+writes.selectionWrites : null;
  const reportedBlobWriteCount=writes?.blobWrites ?? null;
  const noStateChanges=[...Object.values(credentialChanges),...Object.values(blobChanges),...Object.values(markerChanges),blobVersionChanges].every((n) => n === 0);
  return {kind:"credential_convergence",name:"no_writes_or_blob_version_changes",
    ok:nonemptyBefore && cohortMatches && binding.digestMatches && binding.nonceMatches && noStateChanges && reportedWriteCount === 0 && reportedBlobWriteCount === 0,
    detail:{nonemptyBefore,cohort,binding,credentialChanges,blobChanges,markerChanges,blobVersionChanges,reportedWrites:writes,reportedWriteCount,reportedBlobWriteCount,
      evidenceScope:"all_target_credentials_postgres_blobs_and_copier_markers",physicalTupleIdentityIncluded:true}};
}

const WRITE_KEYS=["inserted","updated","blobWrites","metadataWrites","selectionWrites"] as const;
export type CredentialWriteCounts=Record<typeof WRITE_KEYS[number],number>;
/** #181's actual-write contract. Missing, future/unknown fields or malformed
 * counters never become a zero-write claim. The report revision stays bound. */
export function credentialWriteCounts(report:unknown):CredentialWriteCounts|null {
  if (!report || typeof report !== "object") return null;
  const value=report as Record<string,unknown>;
  if (value.version !== 1 || value.mode !== "apply" || value.ok !== true || value.mappingRevision !== MAPPING_REVISION
    || !value.writes || typeof value.writes !== "object" || Array.isArray(value.writes)) return null;
  const writes=value.writes as Record<string,unknown>;
  if (JSON.stringify(Object.keys(writes).sort()) !== JSON.stringify([...WRITE_KEYS].sort())
    || !WRITE_KEYS.every((name) => typeof writes[name] === "number" && Number.isSafeInteger(writes[name]) && (writes[name] as number) >= 0)) return null;
  const result=Object.fromEntries(WRITE_KEYS.map((name) => [name,writes[name]])) as CredentialWriteCounts;
  if (!Number.isSafeInteger(Object.values(result).reduce((total,count) => total+count,0))) return null;
  const outcomes=value.outcomes as Record<string,unknown>|undefined;
  if (!outcomes || typeof outcomes !== "object" || Array.isArray(outcomes)
    || (outcomes.copied ?? 0) !== result.inserted || (outcomes.updated ?? 0) !== result.updated) return null;
  const selection=value.selection as Record<string,unknown>|undefined;
  if (selection !== undefined ? !selection || typeof selection !== "object" || selection.writes !== result.selectionWrites
    : result.selectionWrites !== 0) return null;
  return result;
}
