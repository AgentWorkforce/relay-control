import type { Client } from "pg";
import type { ImportReport } from "../cloud-import/importer.js";
import { ORG_TABLES,RECONCILED_TABLES,SOURCE_TABLES,TARGETS,type ImportTable } from "../cloud-import/mapping.js";
import type { Finding } from "./verify.js";

export type OrgKeys = Map<string,Partial<Record<ImportTable,string[]>>>;
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

export async function reconciliationFindings(target:Client,current:ImportReport,observed:OrgKeys,
  present:ReadonlySet<ImportTable>,previous?:ImportReport):Promise<Finding[]> {
  const findings:Finding[] = [];
  const totals = new Map<ImportTable,number>();
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
      const before = prior?.keys?.[table] ?? [];
      const priorCount = prior?.imported?.[table] ?? 0;
      if (!Array.isArray(before) || before.some((key) => !validImportKey(table,key))) throw new Error("Invalid previous imported-key manifest");
      if (prior) findings.push({kind:"previous_manifest",name:`${org}:${table}`,
        ok:prior.status === "ok" && priorCount === before.length && new Set(before).size === before.length,
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
        detail:{expected:gone.length,reported:safeCount(deleted),remaining,previousSupplied:Boolean(previous)}});
    }
  }
  for (const table of SOURCE_TABLES) {
    const reported = current.tables?.[table]?.deleted;
    const expected = totals.get(table) ?? 0;
    findings.push({kind:"deleted_total",name:table,
      ok:Number.isSafeInteger(reported) && reported === expected && (Boolean(previous) || reported === 0),
      detail:{orgTotal:safeCount(expected),reported:safeCount(reported),previousSupplied:Boolean(previous)}});
  }
  return findings;
}
