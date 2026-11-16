import { createHash } from "node:crypto";
import type { Client } from "pg";
import type { Finding } from "./verify.js";
import { assertScope,type ImportScope } from "../cloud-import/mapping.js";

export function normalizedScope(scope:ImportScope):ImportScope {
  assertScope(scope);
  return {orgIds:scope.orgIds === null ? null : [...new Set(scope.orgIds.map((id) => id.toLowerCase()))].sort()};
}
export async function organizationCensus(source:Client,scope:ImportScope) {
  const requested=scope.orgIds === null ? null : new Set(scope.orgIds);
  const all=createHash("sha256").update("cloud-source-org-census-v1\0");
  const selected=createHash("sha256").update("cloud-source-org-census-v1\0");
  let allCount=0,selectedCount=0;
  const found=new Set<string>();
  await source.query("DECLARE org_census_cursor NO SCROLL CURSOR FOR SELECT id::text AS id FROM public.organizations ORDER BY id::text COLLATE \"C\"");
  try {for (;;) {
    const batch=await source.query("FETCH FORWARD 250 FROM org_census_cursor");if (!batch.rows.length) break;
    for (const {id} of batch.rows) {
      const frame=`${Buffer.byteLength(id)}:${id}`;all.update(frame);allCount++;
      if (requested === null || requested.has(id)) {selected.update(frame);selectedCount++;if (requested !== null) found.add(id);}
    }
  }} finally {await source.query("CLOSE org_census_cursor");}
  return {algorithm:"sha256-length-framed-uuid-c-order-v1",all:{count:allCount,sha256:all.digest("hex")},
    selected:{count:selectedCount,sha256:selected.digest("hex")},
    requestedCount:requested?.size ?? null,unknownRequested:requested === null ? 0 : requested.size-found.size};
}

export function requireAllSourceScope(scope:ImportScope):void {
  if (normalizedScope(scope).orgIds !== null) throw new Error("Cutover requires all source organizations");
}

export function cutoverScopeFinding(report:{evidenceKind?:string;scope?:ImportScope;
  sourceOrganizationCensus?:Awaited<ReturnType<typeof organizationCensus>>;targetSchema?:{profile:string;ok:boolean}}):Finding {
  const census=report.sourceOrganizationCensus;
  const all=report.evidenceKind === "identity-import" && report.scope?.orgIds === null;
  const censusMatches=Boolean(census && census.algorithm === "sha256-length-framed-uuid-c-order-v1"
    && Number.isSafeInteger(census.all.count) && census.all.count > 0 && Number.isSafeInteger(census.selected.count)
    && census.unknownRequested === 0 && census.all.count === census.selected.count
    && /^[0-9a-f]{64}$/.test(census.all.sha256) && census.all.sha256 === census.selected.sha256);
  const productionSchema=report.targetSchema?.profile === "main" && report.targetSchema.ok;
  return {kind:"cutover_scope",name:"all_source_organizations",ok:Boolean(all && censusMatches && productionSchema),
    detail:{allOrganizations:all,censusMatches,productionSchema:Boolean(productionSchema)}};
}
