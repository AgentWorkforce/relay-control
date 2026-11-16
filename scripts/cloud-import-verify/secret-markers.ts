import type { Client } from "pg";
import { MAPPING_REVISION,SOURCE_TABLES,TARGETS,type ImportScope } from "../cloud-import/mapping.js";
import type { Finding } from "./verify.js";

export const SECRET_WRITTEN_MARKER="secret_written";
const UUID="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const KEY=new RegExp(`^([a-z][a-z0-9_]*):(${UUID}):([0-9a-f]{64})$`);
const quote=(value:string) => `"${value.replaceAll('"','""')}"`;
const literal=(value:string) => `'${value.replaceAll("'","''")}'`;

/** Immutable historical write provenance, not current-row authority. A
 * changed digest means the target is no longer the import's exact ciphertext;
 * decryption and ordinary data checks still apply. Old revisions/orphans can
 * legitimately outlive a no-op run or a reconciled deletion. Live pointers
 * require the exact imported relation, tenant and identity ownership link. */
export async function secretMarkerFinding(target:Client,scope:ImportScope):Promise<Finding> {
  const specs=SOURCE_TABLES.flatMap((logical) => {
    const spec=TARGETS[logical];return spec.secret ? [{logical,relation:spec.table,column:spec.secret.target}] : [];
  });
  const allowed=new Set(specs.map((spec) => spec.relation));
  const queries=specs.map(({logical,relation,column}) => {
    const workspace=logical === "workspaces";
    const joinedOrg=logical === "person_identities" || logical === "hosted_relay_participants";
    const github=logical === "github_app_connections";
    const org=joinedOrg ? "w.organization_id" : github ? "t.github_app_organization_id" : "t.organization_id";
    const workspaceOrg=workspace ? "t.organization_id" : "w.organization_id";
    return `SELECT l.organization_id::text AS org,l.row_key,l.mapping_revision,
      t.id::text AS target_id,${org}::text AS target_org,${workspaceOrg}::text AS workspace_org,
      owner.row_key AS owned_key,${github ? "t.auth_mode='github_app'" : "true"} AS valid_type,
      encode(sha256(convert_to(t.${quote(column)},'UTF8')),'hex') AS current_digest
      FROM public.cloud_import_ledger l LEFT JOIN public.${quote(relation)} t ON t.id::text=split_part(l.row_key,':',2)
      ${workspace ? "" : "LEFT JOIN public.workspaces w ON w.id=t.workspace_id"}
      LEFT JOIN public.cloud_import_ledger owner ON owner.organization_id=l.organization_id
        AND owner.table_name=${literal(logical)} AND owner.row_key=t.id::text
      WHERE l.table_name='secret_written' AND split_part(l.row_key,':',1)=${literal(relation)}
        AND ($1::uuid[] IS NULL OR l.organization_id=ANY($1::uuid[]) OR ${org}=ANY($1::uuid[]) OR ${workspaceOrg}=ANY($1::uuid[]))`;
  });
  queries.push(`SELECT l.organization_id::text AS org,l.row_key,l.mapping_revision,
    NULL::text AS target_id,NULL::text AS target_org,NULL::text AS workspace_org,NULL::text AS owned_key,
    false AS valid_type,NULL::text AS current_digest FROM public.cloud_import_ledger l
    WHERE l.table_name='secret_written' AND split_part(l.row_key,':',1) NOT IN (${[...allowed].map(literal).join(",")})
      AND ($1::uuid[] IS NULL OR l.organization_id=ANY($1::uuid[]))`);
  let observed=0,invalidKeys=0,invalidRevisions=0,duplicates=0,invalidReferences=0,
    historicalRevisions=0,orphanMarkers=0,matched=0,changedSinceImport=0,cleared=0;
  const seen=new Set<string>();
  await target.query(`DECLARE secret_marker_cursor NO SCROLL CURSOR FOR ${queries.join(" UNION ALL ")}`,[scope.orgIds]);
  try {for (;;) {
    const batch=await target.query("FETCH FORWARD 250 FROM secret_marker_cursor");if (!batch.rows.length) break;
    for (const row of batch.rows) {
      if (++observed > 20000) throw new Error("Secret marker count exceeds bounded size");
      const key=KEY.exec(row.row_key);
      if (!key || !allowed.has(key[1]!)) {invalidKeys++;continue;}
      const identity=`${key[1]}:${key[2]}`;
      if (seen.has(identity)) duplicates++;seen.add(identity);
      if (!/^cloud-identity-\d{4}-\d{2}-\d{2}\.\d+$/.test(row.mapping_revision)) invalidRevisions++;
      if (row.mapping_revision !== MAPPING_REVISION) historicalRevisions++;
      if (!row.target_id) {orphanMarkers++;continue;}
      if (row.target_org !== row.org || row.workspace_org !== row.org || !row.owned_key || !row.valid_type) invalidReferences++;
      if (row.current_digest === null) cleared++;
      else if (row.current_digest === key[3]) matched++;
      else changedSinceImport++;
    }
  }} finally {await target.query("CLOSE secret_marker_cursor");}
  return {kind:"secret_markers",name:SECRET_WRITTEN_MARKER,
    ok:!invalidKeys && !invalidRevisions && !duplicates && !invalidReferences,
    detail:{observed,invalidKeys,invalidRevisions,duplicates,invalidReferences,historicalRevisions,
      orphanMarkers,matched,changedSinceImport,cleared}};
}
