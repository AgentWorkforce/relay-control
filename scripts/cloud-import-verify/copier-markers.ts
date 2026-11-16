import type { Client } from "pg";
import type { ImportScope } from "../cloud-import/mapping.js";
import type { Finding } from "./verify.js";

export const COPIER_LOGIN_MARKER="copier_login";
const KEY=/^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):([1-9][0-9]*)$/i;
/** The copier owns this exact namespace, not identity reconciliation. History
 * can outlive a deleted credential; report orphan pointers without treating
 * them as current write authority. Unknown namespaces are never exempted. */
export async function readCopierMarkers(target:Client,scope:ImportScope) {
  const markers=new Map<string,{org:string;version:number}>();
  let observed=0,invalidKeys=0,invalidRevisions=0,duplicateCredentials=0,invalidReferences=0,orphanMarkers=0,olderVersions=0;
  await target.query(`DECLARE copier_marker_cursor NO SCROLL CURSOR FOR
    SELECT l.organization_id::text AS org,l.row_key,l.mapping_revision,c.id::text AS credential_id,
      c.organization_id::text AS credential_org,c.auth_type,c.blob_version
    FROM public.cloud_import_ledger l LEFT JOIN public.coding_agent_credentials c
      ON c.id::text=lower(split_part(l.row_key,':',1))
    WHERE l.table_name='copier_login' AND ($1::uuid[] IS NULL OR l.organization_id=ANY($1::uuid[]))
    ORDER BY l.organization_id,l.row_key`,[scope.orgIds]);
  try {for (;;) {
    const batch=await target.query("FETCH FORWARD 250 FROM copier_marker_cursor");if (!batch.rows.length) break;
    for (const row of batch.rows) {
      if (++observed > 10000) throw new Error("Copier marker count exceeds bounded size");
      const match=KEY.exec(row.row_key);const version=match ? Number(match[2]) : NaN;
      if (!match || !Number.isSafeInteger(version) || version > 2147483647) {invalidKeys++;continue;}
      const id=match[1]!.toLowerCase();
      if (markers.has(id)) duplicateCredentials++;
      markers.set(id,{org:row.org,version});
      if (!/^cloud-identity-\d{4}-\d{2}-\d{2}\.\d+$/.test(row.mapping_revision)) invalidRevisions++;
      if (!row.credential_id) {orphanMarkers++;continue;}
      if (row.credential_org !== row.org || row.auth_type !== "provider_oauth"
        || !Number.isSafeInteger(row.blob_version) || version > row.blob_version) invalidReferences++;
      else if (version < row.blob_version) olderVersions++;
    }
  }} finally {await target.query("CLOSE copier_marker_cursor");}
  const finding:Finding={kind:"credential_copy_markers",name:COPIER_LOGIN_MARKER,
    ok:!invalidKeys && !invalidRevisions && !duplicateCredentials && !invalidReferences,
    detail:{observed,invalidKeys,invalidRevisions,duplicateCredentials,invalidReferences,orphanMarkers,olderVersions}};
  return {finding,markers};
}
