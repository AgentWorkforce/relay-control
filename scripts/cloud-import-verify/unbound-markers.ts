import type { Client } from "pg";
import { MAPPING_REVISION,type ImportScope } from "../cloud-import/mapping.js";
import type { Finding } from "./verify.js";

export const UNBOUND_MARKER="workspace_unbound";
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A marker affects the workspace projection, so target references alone are
 * insufficient: its exact org/workspace set must match independently observed
 * imported source rows with a NULL provider binding. A later Control binding
 * is allowed, but a marker may never hide drift on a bound source workspace. */
export async function unboundWorkspaceMarkers(target:Client,scope:ImportScope,expected:ReadonlyMap<string,string>):Promise<Finding> {
  const seen=new Set<string>();
  let observed=0,invalidKeys=0,invalidReferences=0,revisionMismatches=0,unexpected=0,duplicates=0;
  await target.query(`DECLARE unbound_marker_cursor NO SCROLL CURSOR FOR
    SELECT l.organization_id::text AS org,l.row_key,l.mapping_revision,
      w.id::text AS workspace_id,w.organization_id::text AS workspace_org,
      owner.row_key AS owned_key,owner.mapping_revision AS owner_revision
    FROM public.cloud_import_ledger l LEFT JOIN public.workspaces w ON w.id::text=l.row_key
    LEFT JOIN public.cloud_import_ledger owner ON owner.table_name='workspaces'
      AND owner.row_key=l.row_key AND owner.organization_id=l.organization_id
    WHERE l.table_name='workspace_unbound' AND ($1::uuid[] IS NULL
      OR l.organization_id=ANY($1::uuid[]) OR w.organization_id=ANY($1::uuid[]))
    ORDER BY l.organization_id,l.row_key`,[scope.orgIds]);
  try {for (;;) {
    const batch=await target.query("FETCH FORWARD 250 FROM unbound_marker_cursor");if (!batch.rows.length) break;
    for (const row of batch.rows) {
      if (++observed > 10000) throw new Error("Unbound marker count exceeds bounded size");
      if (!UUID.test(row.row_key)) {invalidKeys++;continue;}
      if (seen.has(row.row_key)) duplicates++;
      seen.add(row.row_key);
      if (!row.workspace_id || row.workspace_org !== row.org || !row.owned_key) invalidReferences++;
      if (row.mapping_revision !== MAPPING_REVISION || row.owner_revision !== MAPPING_REVISION) revisionMismatches++;
      if (expected.get(row.row_key) !== row.org) unexpected++;
    }
  }} finally {await target.query("CLOSE unbound_marker_cursor");}
  const missing=[...expected.keys()].filter((key) => !seen.has(key)).length;
  return {kind:"workspace_unbound_markers",name:UNBOUND_MARKER,
    ok:!invalidKeys && !invalidReferences && !revisionMismatches && !unexpected && !duplicates && !missing,
    detail:{observed,expected:expected.size,missing,unexpected,invalidKeys,invalidReferences,revisionMismatches,duplicates}};
}
