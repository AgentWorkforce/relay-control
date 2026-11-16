import type { Client } from "pg";
import { sourceQuery,type ImportScope } from "../cloud-import/mapping.js";
import type { Finding } from "./verify.js";

export type SelectionCounts={active:number;harness:number};
/** Sparse: omit organizations with zero differences in both flags. */
export type SelectionDiverged=Record<string,SelectionCounts>;
export type LinkedSourceSelection={id:string;org:string;workspace:string;active:boolean;harness:boolean};
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const canonical=(counts:SelectionDiverged) => JSON.stringify(Object.entries(counts).sort(([a],[b]) => a.localeCompare(b)));

/** Normalize an optional producer diagnostic, never its authority over data.
 * Unknown fields/orgs, unsafe counts and zero-only entries are rejected. */
export function reportedSelectionDiverged(value:unknown,organizations:ReadonlySet<string>):SelectionDiverged|null {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length > 10000) return null;
  const result:SelectionDiverged={};
  for (const [org,entry] of Object.entries(value)) {
    if (!UUID.test(org) || !organizations.has(org) || !entry || typeof entry !== "object" || Array.isArray(entry)
      || Object.keys(entry).sort().join(",") !== "active,harness") return null;
    const {active,harness}=entry as SelectionCounts;
    if (![active,harness].every((n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0)
      || active === 0 && harness === 0) return null;
    result[org]={active,harness};
  }
  return result;
}

/** Caller owns frozen read-only source/target transactions. Metadata flags
 * come from the effective source mapping; copied flags come only from the
 * verifier's decrypted cohort with independently validated natural-key links.
 * Count distinct target credentials, OR-ing flags for shared source links.
 * Differences are visible diagnostics; existing selection/content/provenance
 * gates remain independently fatal. Counts cannot account for missing rows. */
export async function selectionDivergence(source:Client,target:Client,scope:ImportScope,
  copied:readonly LinkedSourceSelection[] = [],unmappedCopied=0,
  reported?:{present:boolean;value:unknown}):Promise<Finding> {
  const expected=new Map<string,LinkedSourceSelection & {kind:"metadata"|"copied"}>();
  let invalidSource=0,metadataRows=0;
  await source.query(`DECLARE selection_source_cursor NO SCROLL CURSOR FOR
    SELECT id::text,organization_id::text AS org,workspace_id::text AS workspace,is_active AS active,harness_active AS harness
    FROM (${sourceQuery("coding_agent_credentials",scope)}) q WHERE skip_reason IS NULL AND auth_type='relay_managed'`);
  try {for (;;) {
    const batch=await source.query("FETCH FORWARD 250 FROM selection_source_cursor");if (!batch.rows.length) break;
    for (const row of batch.rows) {
      if (++metadataRows > 10000) throw new Error("Selection metadata exceeds bounded size");
      if (![row.id,row.org,row.workspace].every((id) => typeof id === "string" && UUID.test(id))
        || typeof row.active !== "boolean" || typeof row.harness !== "boolean" || expected.has(row.id)) {invalidSource++;continue;}
      expected.set(row.id,{id:row.id,org:row.org,workspace:row.workspace,active:row.active,harness:row.harness,kind:"metadata"});
    }
  }} finally {await source.query("CLOSE selection_source_cursor");}
  if (copied.length > 10000) throw new Error("Selection copied cohort exceeds bounded size");
  for (const row of copied) {
    if (![row.id,row.org,row.workspace].every((id) => UUID.test(id))
      || typeof row.active !== "boolean" || typeof row.harness !== "boolean") {invalidSource++;continue;}
    const prior=expected.get(row.id);
    if (prior && (prior.kind !== "copied" || prior.org !== row.org || prior.workspace !== row.workspace)) {invalidSource++;continue;}
    expected.set(row.id,{...row,active:row.active || prior?.active === true,harness:row.harness || prior?.harness === true,kind:"copied"});
  }
  const counts:SelectionDiverged={},seen=new Set<string>();
  const compared={metadata:0,copied:0};
  let targetRows=0,invalidTarget=0;
  await target.query(`DECLARE selection_target_cursor NO SCROLL CURSOR FOR
    SELECT c.id::text,c.organization_id::text AS org,c.workspace_id::text AS workspace,c.auth_type,
      w.organization_id::text AS workspace_org,c.is_active AS active,c.harness_active AS harness
    FROM public.coding_agent_credentials c JOIN public.workspaces w ON w.id=c.workspace_id
    WHERE $1::uuid[] IS NULL OR w.organization_id=ANY($1::uuid[])`,[scope.orgIds]);
  try {for (;;) {
    const batch=await target.query("FETCH FORWARD 250 FROM selection_target_cursor");if (!batch.rows.length) break;
    for (const row of batch.rows) {
      if (++targetRows > 20000) throw new Error("Selection target exceeds bounded size");
      const want=expected.get(row.id);if (!want) continue;
      if (seen.has(row.id) || row.org !== want.org || row.workspace !== want.workspace || row.workspace_org !== want.org
        || (row.auth_type === "relay_managed") !== (want.kind === "metadata")
        || typeof row.active !== "boolean" || typeof row.harness !== "boolean") {invalidTarget++;continue;}
      seen.add(row.id);compared[want.kind]++;
      const difference={active:Number(row.active !== want.active),harness:Number(row.harness !== want.harness)};
      if (difference.active || difference.harness) {
        const prior=counts[want.org] ?? {active:0,harness:0};
        counts[want.org]={active:prior.active+difference.active,harness:prior.harness+difference.harness};
      }
    }
  }} finally {await target.query("CLOSE selection_target_cursor");}
  const organizations=new Set([...expected.values()].map((row) => row.org));
  const parsed=reported?.present ? reportedSelectionDiverged(reported.value,organizations) : null;
  const reportMatches=reported?.present ? parsed !== null && canonical(parsed) === canonical(counts) : null;
  const missing=expected.size-seen.size;
  return {kind:"selection_diverged",name:"coding_agent_credentials",
    ok:!invalidSource && !invalidTarget && !unmappedCopied && !missing && reportMatches !== false,
    detail:{unit:"distinct_linked_credential_flags",classification:"cloud_control_selection_differences",perOrg:counts,compared,
      missing,unmappedCopied,invalidSource,invalidTarget,
      producerCounter:!reported ? "not_requested" : !reported.present ? "not_reported" : reportMatches ? "matched" : "mismatched"}};
}
