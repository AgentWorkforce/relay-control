import { beginReadOnlySnapshot,type ReadOnlySettings } from "./read-only.js";
import type { Client } from "pg";
import type { ImportReport } from "../cloud-import/importer.js";
import { ORG_TABLES,RECONCILED_TABLES,SOURCE_TABLES,TARGETS,IMPORT_LEDGER_TABLE,MAPPING_REVISION,assertScope,type ImportTable,type ImportScope } from "../cloud-import/mapping.js";
import type { Finding } from "./verify.js";

export type OrgKeys = Map<string,Partial<Record<ImportTable,string[]>>>;
export interface OwnershipSnapshot {
  sessionSafety?:ReadOnlySettings;
  version:1;
  table:typeof IMPORT_LEDGER_TABLE;
  scope:ImportScope;
  rows:{organization_id:string;table_name:ImportTable;row_key:string;mapping_revision:string}[];
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function validImportKey(table:ImportTable,key:unknown):key is string {
  if (typeof key !== "string") return false;
  if (table === "github_app_installations") return /^[1-9][0-9]{0,19}$/.test(key);
  if (table === "organization_memberships") return key.split(":").length === 2 && key.split(":").every((id) => uuid.test(id));
  return uuid.test(key);
}
const sameKeys = (left:readonly string[],right:readonly string[]) => new Set(right).size === right.length
  && JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
const safeCount = (value:unknown) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;

/** Caller holds a read-only transaction. Snapshot files contain ownership IDs,
 * never credentials or customer History hosts. */
async function readOwnership(target:Client,scope:ImportScope):Promise<OwnershipSnapshot> {
  assertScope(scope);
  const rows:OwnershipSnapshot["rows"] = [];
  await target.query(`DECLARE ownership_cursor NO SCROLL CURSOR FOR SELECT organization_id::text,
    table_name,row_key,mapping_revision FROM public.${IMPORT_LEDGER_TABLE}
    WHERE table_name NOT IN ('copier_login','workspace_unbound','secret_written') AND ($1::uuid[] IS NULL OR organization_id=ANY($1::uuid[]))
    ORDER BY organization_id,table_name,row_key`,[scope.orgIds]);
  try {for (;;) {
    const batch=await target.query("FETCH FORWARD 250 FROM ownership_cursor");
    if (!batch.rows.length) break;
    for (const row of batch.rows) {
      if (rows.length >= 100000) throw new Error("Ownership snapshot requires a smaller cohort");
      rows.push(row);
    }
  }} finally {await target.query("CLOSE ownership_cursor");}
  const snapshot:OwnershipSnapshot={version:1,table:IMPORT_LEDGER_TABLE,
    scope:{orgIds:scope.orgIds === null ? null : [...scope.orgIds]},rows};
  snapshotKeys(snapshot);
  return snapshot;
}

function snapshotKeys(snapshot:OwnershipSnapshot):OrgKeys {
  if (snapshot.version !== 1 || snapshot.table !== IMPORT_LEDGER_TABLE || !Array.isArray(snapshot.rows)) throw new Error("Invalid ownership snapshot");
  assertScope(snapshot.scope);
  const orgs:OrgKeys=new Map();
  const seen=new Set<string>();
  for (const row of snapshot.rows) {
    if (!uuid.test(row.organization_id) || !ORG_TABLES.includes(row.table_name)
      || !validImportKey(row.table_name,row.row_key)
      || !/^cloud-identity-\d{4}-\d{2}-\d{2}\.\d+$/.test(row.mapping_revision)
      || (snapshot.scope.orgIds !== null && !snapshot.scope.orgIds.some((id) => id.toLowerCase() === row.organization_id))) {
      throw new Error("Invalid ownership entry");
    }
    const identity=`${row.organization_id}:${row.table_name}:${row.row_key}`;
    if (seen.has(identity)) throw new Error("Duplicate ownership entry");seen.add(identity);
    const keys=orgs.get(row.organization_id) ?? {};
    (keys[row.table_name] ??= []).push(row.row_key);orgs.set(row.organization_id,keys);
  }
  return orgs;
}

/** Capture immediately before the importer runs; it never authorizes writes.
 * The importer trusts only its own transactional database ledger. */
export async function captureOwnership(target:Client,scope:ImportScope):Promise<OwnershipSnapshot> {
  try {
    const sessionSafety=await beginReadOnlySnapshot(target);
    return {...await readOwnership(target,scope),sessionSafety};
  } finally {await target.query("ROLLBACK");}
}

export async function reconciliationFindings(target:Client,current:ImportReport,observed:OrgKeys,
  present:ReadonlySet<ImportTable>,scope:ImportScope,previous?:ImportReport,previousOwnership?:OwnershipSnapshot):Promise<Finding[]> {
  const findings:Finding[] = [];
  const totals = new Map<ImportTable,number>();
  const persisted=await readOwnership(target,scope);
  const persistedKeys=snapshotKeys(persisted);
  const priorKeys=previousOwnership ? snapshotKeys(previousOwnership) : new Map();
  const covered=previousOwnership && (previousOwnership.scope.orgIds === null
    || (scope.orgIds !== null && scope.orgIds.every((id) =>
      previousOwnership.scope.orgIds!.some((before) => before.toLowerCase() === id.toLowerCase()))));
  if (previousOwnership) findings.push({kind:"previous_ownership",name:"scope",ok:Boolean(covered),detail:{coversCurrentScope:Boolean(covered)}});
  let ledgerKeyMismatches=0;
  let ledgerRevisionMismatches=0;
  const currentIdentities=new Set<string>();
  for (const [org,expected] of observed) for (const table of ORG_TABLES) {
    const actual=persistedKeys.get(org)?.[table] ?? [];
    if (!sameKeys(expected[table] ?? [],actual)) ledgerKeyMismatches++;
    for (const key of expected[table] ?? []) currentIdentities.add(`${org}:${table}:${key}`);
  }
  ledgerRevisionMismatches=persisted.rows.filter((row) => currentIdentities.has(`${row.organization_id}:${row.table_name}:${row.row_key}`)
    && row.mapping_revision !== MAPPING_REVISION).length;
  const extraOrgs=[...persistedKeys.keys()].filter((org) => !observed.has(org)).length;
  findings.push({kind:"ownership_ledger",name:IMPORT_LEDGER_TABLE,
    ok:!ledgerKeyMismatches && !ledgerRevisionMismatches && !extraOrgs,
    detail:{entries:persisted.rows.length,keyMismatches:ledgerKeyMismatches,revisionMismatches:ledgerRevisionMismatches,extraOrgs}});
  if (previous) findings.push({kind:"previous_ledger",name:"run",
    ok:previous.version === 1 && previous.mode === "apply" && previous.ok === true,
    detail:{revisionPresent:typeof previous.mappingRevision === "string",mode:previous.mode === "apply" ? "apply" : "invalid",ok:previous.ok === true}});
  for (const [org,expected] of observed) {
    const report = current.orgs?.[org];
    const prior = previous?.orgs?.[org];
    for (const table of ORG_TABLES) {
      const keys = report?.keys?.[table];
      if (keys !== undefined && (!Array.isArray(keys) || keys.some((key) => !validImportKey(table,key)))) {
        throw new Error("Invalid imported-key manifest");
      }
      findings.push({kind:"ledger_keys",name:`${org}:${table}`,
        ok:Array.isArray(keys) && sameKeys(expected[table] ?? [],keys),
        detail:{observed:(expected[table] ?? []).length,reported:keys?.length ?? null}});
      const before = priorKeys.get(org)?.[table] ?? [];
      const priorCount = prior?.imported?.[table] ?? 0;
      if (!Array.isArray(before) || before.some((key) => !validImportKey(table,key))) throw new Error("Invalid previous imported-key manifest");
      if (prior) findings.push({kind:"previous_manifest",name:`${org}:${table}`,
        ok:prior.status === "ok" && (!previousOwnership || (priorCount === before.length
          && sameKeys(before,prior.keys?.[table] ?? []))),
        detail:{imported:safeCount(priorCount),keys:before.length}});
      const reconciled = RECONCILED_TABLES.includes(table);
      const now = new Set(expected[table] ?? []);
      const gone = reconciled ? before.filter((key) => !now.has(key)) : [];
      const deleted = report?.deleted?.[table] ?? 0;
      totals.set(table,(totals.get(table) ?? 0)+(safeCount(deleted) ?? Number.NaN));
      let remaining = 0;
      if (gone.length && present.has(table)) {
        const spec = TARGETS[table];
        const key = spec.primaryKey.map((column) => `x.${column}::text`).join(" || ':' || ");
        const joinsWorkspace = table === "person_identities" || table === "hosted_relay_participants";
        const from = `public.${spec.table} x${joinsWorkspace ? " JOIN public.workspaces w ON w.id=x.workspace_id" : ""}`;
        const tenant = joinsWorkspace ? "w.organization_id" : table === "github_app_connections" ? "x.github_app_organization_id" : "x.organization_id";
        const extra = table === "coding_agent_credentials" ? " AND x.auth_type='relay_managed'"
          : table === "github_app_connections" ? " AND x.auth_mode='github_app'" : "";
        const result = await target.query(`SELECT count(*)::text AS n FROM ${from}
          WHERE ${tenant}=$1::uuid AND (${key})=ANY($2::text[])${extra}`,[org,gone]);
        remaining=Number(result.rows[0].n);
      }
      findings.push({kind:"deletions",name:`${org}:${table}`,
        ok:Number.isSafeInteger(deleted) && deleted >= 0 && deleted === gone.length
          && remaining === 0 && (!gone.length || present.has(table)),
        detail:{expected:gone.length,reported:safeCount(deleted),remaining,previousSupplied:Boolean(previousOwnership)}});
    }
  }
  for (const table of SOURCE_TABLES) {
    const reported = current.tables?.[table]?.deleted;
    const expected = totals.get(table) ?? 0;
    findings.push({kind:"deleted_total",name:table,
      ok:Number.isSafeInteger(reported) && reported === expected && (Boolean(previousOwnership) || reported === 0),
      detail:{orgTotal:safeCount(expected),reported:safeCount(reported),previousSupplied:Boolean(previousOwnership)}});
  }
  return findings;
}
