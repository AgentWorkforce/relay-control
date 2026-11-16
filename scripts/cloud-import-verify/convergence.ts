import { createHash } from "node:crypto";
import type { Client } from "pg";
import { MAPPING_REVISION } from "../cloud-import/mapping.js";
import { beginReadOnlySnapshot,inspectReadOnlySnapshot,type ReadOnlySettings } from "./read-only.js";
import type { Finding } from "./verify.js";

const hash=(value:string) => createHash("sha256").update(value).digest("hex");
type StateRow={key:string;stateSha256:string;blobVersion:number|null};
export type CredentialConvergenceSnapshot={version:1;kind:"credential-convergence";phase:"before"|"after";
  mappingRevision:string;scope:{orgIds:null};sessionSafety:ReadOnlySettings;credentials:StateRow[];blobs:StateRow[]};

/** All target credential rows, including native and relay-managed rows, and
 * all Postgres blob objects. Caller holds a quiescent read-only snapshot.
 * Full tuple contents and MVCC identity are hashed locally, never serialized. */
export async function readCredentialConvergence(target:Client,phase:"before"|"after"):Promise<CredentialConvergenceSnapshot> {
  const sessionSafety=await inspectReadOnlySnapshot(target);
  if ((await target.query(`SELECT EXISTS(SELECT 1 FROM public.coding_agent_credentials
    WHERE auth_type='provider_oauth' AND blob_backend IS DISTINCT FROM 'postgres') AS unsupported`)).rows[0].unsupported)
    throw new Error("Convergence capture requires Postgres credential blobs");
  const credentials:StateRow[]=[],blobs:StateRow[]=[];
  for (const [relation,key,version,rows,limit] of [
    ["coding_agent_credentials","id::text","blob_version",credentials,10000],
    ["coding_agent_credential_blobs","object_key","NULL::int",blobs,50000],
  ] as const) {
    await target.query(`DECLARE convergence_cursor NO SCROLL CURSOR FOR SELECT ${key} AS key,${version} AS version,
      to_jsonb(t)::text AS state,t.xmin::text AS xmin,t.ctid::text AS ctid
      FROM public.${relation} t ORDER BY ${key} COLLATE "C"`);
    try {for (;;) {
      const batch=await target.query("FETCH FORWARD 25 FROM convergence_cursor");if (!batch.rows.length) break;
      for (const row of batch.rows) {
        if (rows.length >= limit) throw new Error("Convergence snapshot exceeds bounded size");
        rows.push({key:hash(row.key),stateSha256:hash(JSON.stringify([row.state,row.xmin,row.ctid])),blobVersion:row.version});
      }
    }} finally {await target.query("CLOSE convergence_cursor");}
  }
  return {version:1,kind:"credential-convergence",phase,mappingRevision:MAPPING_REVISION,scope:{orgIds:null},sessionSafety,credentials,blobs};
}

/** Capture immediately before a convergence re-run, in a separate private
 * artifact. This baseline cannot be reconstructed after the re-run. */
export async function captureCredentialConvergence(target:Client,phase:"before"|"after"="before") {
  try {
    await beginReadOnlySnapshot(target);
    return await readCredentialConvergence(target,phase);
  } finally {await target.query("ROLLBACK");}
}

function rowsByKey(rows:StateRow[],limit:number) {
  if (!Array.isArray(rows) || rows.length > limit) throw new Error("Invalid convergence snapshot");
  const result=new Map<string,StateRow>();
  for (const row of rows) {
    if (!/^[0-9a-f]{64}$/.test(row.key) || !/^[0-9a-f]{64}$/.test(row.stateSha256) || result.has(row.key)
      || (row.blobVersion !== null && (!Number.isSafeInteger(row.blobVersion) || row.blobVersion < 0))) throw new Error("Invalid convergence snapshot");
    result.set(row.key,row);
  }
  return result;
}

/** Report adapters must supply actual producer write counts, not infer zero
 * from stable row counts or absent fields. Snapshot checks independently catch
 * committed same-value UPDATEs via xmin/ctid, plus blob/version mutations. */
export function compareCredentialConvergence(before:CredentialConvergenceSnapshot,after:CredentialConvergenceSnapshot,
  report:unknown):Finding {
  for (const [snapshot,phase] of [[before,"before"],[after,"after"]] as const) {
    if (snapshot.version !== 1 || snapshot.kind !== "credential-convergence" || snapshot.phase !== phase
      || snapshot.mappingRevision !== MAPPING_REVISION || snapshot.scope?.orgIds !== null
      || snapshot.sessionSafety?.transactionReadOnly !== "on" || snapshot.sessionSafety.isolation !== "repeatable read"
      || snapshot.sessionSafety.statementTimeout !== "1min" || snapshot.sessionSafety.lockTimeout !== "5s") throw new Error("Invalid convergence baseline");
  }
  const previous=rowsByKey(before.credentials,10000),current=rowsByKey(after.credentials,10000);
  const previousBlobs=rowsByKey(before.blobs,50000),currentBlobs=rowsByKey(after.blobs,50000);
  const differences=(a:Map<string,StateRow>,b:Map<string,StateRow>) => ({
    inserted:[...b.keys()].filter((key) => !a.has(key)).length,removed:[...a.keys()].filter((key) => !b.has(key)).length,
    changed:[...a].filter(([key,row]) => b.has(key) && row.stateSha256 !== b.get(key)!.stateSha256).length});
  const credentialChanges=differences(previous,current),blobChanges=differences(previousBlobs,currentBlobs);
  const blobVersionChanges=[...previous].filter(([key,row]) => current.has(key) && row.blobVersion !== current.get(key)!.blobVersion).length;
  const writes=credentialWriteCounts(report);
  const reportedWriteCount=writes ? writes.inserted+writes.updated+writes.metadataWrites+writes.selectionWrites : null;
  const reportedBlobWriteCount=writes?.blobWrites ?? null;
  const noStateChanges=[...Object.values(credentialChanges),...Object.values(blobChanges),blobVersionChanges].every((n) => n === 0);
  return {kind:"credential_convergence",name:"no_writes_or_blob_version_changes",
    ok:noStateChanges && reportedWriteCount === 0 && reportedBlobWriteCount === 0,
    detail:{credentialChanges,blobChanges,blobVersionChanges,reportedWrites:writes,reportedWriteCount,reportedBlobWriteCount,
      evidenceScope:"all_target_credentials_and_postgres_blobs",physicalTupleIdentityIncluded:true}};
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
