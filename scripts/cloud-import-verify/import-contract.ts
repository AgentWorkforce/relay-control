import { validateCredentialCheckpoint } from "./convergence.js";
import { accountCredentialExclusion,exclusionAccounting } from "./exclusions.js";
import { readCopierMarkers } from "./copier-markers.js";
import type { Client } from "pg";
import { schemaFindings } from "./schema.js";
import { normalizedScope,organizationCensus } from "./organization-scope.js";
import { canonicalRelayhistoryOrigin } from "../../src/relayhistory-origin.js";
import type { EncryptionKeyring } from "../../src/crypto.js";
import { decryptCloudEnvelope,type ImportReport } from "../cloud-import/importer.js";
import { MAPPING_REVISION, ORG_TABLES, SOURCE_TABLES, TARGETS, TARGET_RELATIONS,IMPORTER_SKIP_REASONS,
  encryptedSamples, sourceQuery, verifierComparisons, type ImportScope, type ImportTable } from "../cloud-import/mapping.js";
import { verify, type Comparison, type Contract, type Finding } from "./verify.js";
import { credentialCopyFindings,credentialSelections,type CredentialEvidence } from "./credential-copy.js";
import { reconciliationFindings,validImportKey,type OrgKeys,type OwnershipSnapshot } from "./reconciliation.js";

const literal = (s:string) => `'${s.replaceAll("'","''")}'`;
const safeCount = (value:unknown) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
const sorted = (values:Record<string,number>) => JSON.stringify(Object.entries(values).filter(([,n]) => n !== 0).sort(([a],[b]) => a.localeCompare(b)));
const sortedKeys = (values:Record<string,string[]>) => JSON.stringify(Object.entries(values).filter(([,keys]) => keys.length)
  .sort(([a],[b]) => a.localeCompare(b)).map(([reason,keys]) => [reason,[...keys].sort()]));
const equalScope = (a:ImportScope,b:ImportScope) => JSON.stringify(normalizedScope(a)) === JSON.stringify(normalizedScope(b));

function comparisons(scope:ImportScope,columns:ReadonlySet<string>,gated:ReadonlySet<ImportTable>|null = null): Comparison[] {
  return verifierComparisons(scope,columns,gated).map((item) => item.name === "coding_agent_credentials"
    ? {...item,targetSql:`SELECT p.* FROM (${item.targetSql}) p WHERE auth_type='relay_managed'`} : item);
}

function contractFor(scope:ImportScope,columns:ReadonlySet<string>,tables=comparisons(scope,columns)):Contract {
  const identities = ["users","organizations","workspaces"].map((name) => {
    const item = tables.find((t) => t.name === name)!;
    const extra = name === "workspaces" ? ",relaycast_workspace_id"
      + (columns.has("workspaces.cloud_relay_workspace_id") ? ",cloud_relay_workspace_id" : "") : "";
    return {name:`${name}_identity`,sourceSql:`SELECT __key,__org,id${extra} FROM (${item.sourceSql}) p`,
      targetSql:`SELECT __key,__org,id${extra} FROM (${item.targetSql}) p`};
  });
  return {version:1,mappingRevision:MAPPING_REVISION,tables,identities,targetRelations:TARGET_RELATIONS,
    encryptedSamples:encryptedSamples(20,scope),
    standaloneSequences:[{name:"desktop_feed_publish_seq",relation:"public.desktop_feed_publish_seq",
      // Desktop release state is Control-owned, has no Cloud source and is
      // deliberately not imported. Compare against its existing target data.
      sourceBoundsSql:"SELECT NULL::bigint AS min_value,NULL::bigint AS max_value",
      targetBoundsSql:"SELECT min(publish_seq) AS min_value,max(publish_seq) AS max_value FROM public.desktop_feed_releases"}],
    pepperChecks:[{name:"password_credentials",sql:"SELECT pepper_version FROM public.password_credentials"},
      {name:"temporary_passwords",sql:"SELECT pepper_version FROM public.temporary_passwords"}]};
}

/** Verifies a committed importer run. Ledger counts never authorize dropping
 * rows from checksums: every dynamic skip is independently reproduced from
 * the frozen source using the Cloud key and actual target column type.
 * Source/target reads, skip reconciliation and checksums share the snapshots.
 */
export async function verifyImport(source:Client,target:Client,scope:ImportScope,ledger:ImportReport,
  keyring:EncryptionKeyring,cloudKeyHex:string,options:{pepperVersions?:readonly number[];credentialCopy?:CredentialEvidence;previousReport?:ImportReport;
    previousOwnership?:OwnershipSnapshot;canonicalOrigin?:(raw:string) => string|null} = {}) {
  scope=normalizedScope(scope);
  if (options.credentialCopy?.convergenceBefore) validateCredentialCheckpoint(options.credentialCopy.convergenceBefore,scope);
  if (!/^[0-9a-f]{64}$/i.test(cloudKeyHex)) throw new Error("Cloud key must be 32 bytes of hex");
  const base = contractFor(scope,new Set());
  let sourceOrganizationCensus:Awaited<ReturnType<typeof organizationCensus>>|undefined;
  let targetSchema:Awaited<ReturnType<typeof schemaFindings>>["summary"]|undefined;
  const checked = await verify(source,target,base,keyring,{...options,prepare:async (s,t) => {
    const findings:Finding[] = [];
    sourceOrganizationCensus=await organizationCensus(s,scope);
    findings.push({kind:"scope_coverage",name:"source_organizations",ok:sourceOrganizationCensus.unknownRequested === 0,
      detail:{scope,sourceOrganizationCensus}});
    const schema=await schemaFindings(t);targetSchema=schema.summary;findings.push(schema.finding);
    if (schema.halt) return {contract:base,findings,halt:true};
    findings.push((await readCopierMarkers(t,scope)).finding);
    findings.push({kind:"ledger",name:"run",ok:ledger.version === 1 && ledger.mappingRevision === MAPPING_REVISION
      && ledger.mode === "apply" && ledger.ok === true && !ledger.refused && equalScope(scope,ledger.scope),
      detail:{expectedRevision:MAPPING_REVISION,revisionMatches:ledger.mappingRevision === MAPPING_REVISION,
        mode:["plan","dry-run","apply"].includes(ledger.mode) ? ledger.mode : "invalid",ok:ledger.ok === true}});
    const metadata = await t.query(`SELECT c.relname AS table_name,a.attname AS column_name,ty.typname AS udt_name
      FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_type ty ON ty.oid=a.atttypid WHERE n.nspname='public' AND c.relkind IN ('r','p')
      AND a.attnum>0 AND NOT a.attisdropped`);
    const columns = new Set<string>(metadata.rows.map((r) => `${r.table_name}.${r.column_name}`));
    const gatedPresent = new Set<ImportTable>(SOURCE_TABLES.filter((table) => {
      const spec = TARGETS[table];
      return !spec.gate || [...spec.columns,...(spec.secret ? [spec.secret.target] : []),...(spec.freshTokenHash ? [spec.freshTokenHash] : [])]
        .every((column) => columns.has(`${spec.table}.${column}`));
    }));
    const desktopUuid = metadata.rows.some((r) => r.table_name === "desktop_relay_identities" && r.column_name === "source_id" && r.udt_name === "uuid");
    const relayManaged = (await t.query(`SELECT EXISTS (SELECT 1 FROM pg_constraint c
      WHERE c.conrelid='public.coding_agent_credentials'::regclass AND c.contype='c'
      AND pg_get_constraintdef(c.oid) LIKE '%auth_type%' AND pg_get_constraintdef(c.oid) LIKE '%relay_managed%') AS ok`)).rows[0].ok;
    findings.push({kind:"identity",name:"rw_column_present",ok:columns.has("workspaces.cloud_relay_workspace_id"),
      detail:columns.has("workspaces.cloud_relay_workspace_id") ? "present" : "missing_required_mapping_column"});
    const actualOptional = SOURCE_TABLES.flatMap((table) => (TARGETS[table].optional ?? [])
      .filter((c) => columns.has(`${table}.${c}`)).map((c) => `${table}.${c}`)).sort();
    findings.push({kind:"ledger",name:"optional_columns",ok:JSON.stringify(actualOptional) === JSON.stringify([...(ledger.optionalColumns ?? [])].sort()),
      detail:{expected:actualOptional,reportedCount:Array.isArray(ledger.optionalColumns) ? ledger.optionalColumns.length : null}});
    const operatorOrg=(await t.query("SELECT organization_id::text FROM public.installation_bootstrap WHERE organization_id IS NOT NULL LIMIT 1")).rows[0]?.organization_id;
    const absentSources=new Set<ImportTable>();
    const perOrg = new Map<string,Partial<Record<ImportTable,number>>>();
    const perOrgKeys:OrgKeys = new Map();
    const canonicalOrigin=options.canonicalOrigin ?? canonicalRelayhistoryOrigin;
    const origins=new Map<string,string|null>();
    const exclusions = new Map<string,string[]>();
    const counts = new Map<ImportTable,number>();
    for (const table of SOURCE_TABLES) {
      const spec = TARGETS[table];
      if (spec.sourceRelation && !(await s.query("SELECT to_regclass(format('public.%I',$1::text)) IS NOT NULL AS present",[spec.sourceRelation])).rows[0].present) {
        absentSources.add(table);exclusions.set(table,[]);counts.set(table,0);
        const reported=ledger.tables?.[table];
        findings.push({kind:"source_availability",name:table,ok:reported?.candidates === 0 && reported.imported === 0
          && Object.values(reported.skipped).every((n) => n === 0) && Object.values(reported.importerSkips).every((keys) => keys.length === 0)
          && ledger.warnings?.[`source_lacks_${spec.sourceRelation}`] === 1,detail:"source_relation_absent"});
        continue;
      }
      const key = spec.primaryKey.map((c) => `q.${c}::text`).join(" || ':' || ");
      await s.query(`DECLARE import_ledger_cursor NO SCROLL CURSOR FOR SELECT ${key} AS key,skip_reason,
        ${table === "users" ? "NULL::text" : "q.organization_id::text"} AS org,
        ${spec.secret?.source === "secret_envelope" ? "q.secret_envelope::text" : "NULL::text"} AS envelope,
        ${table === "desktop_relay_identities" ? "q.source_id_is_uuid" : "true"} AS source_id_is_uuid,
        ${table === "workspaces" ? "q.cloud_relay_workspace_id IS NOT NULL" : "true"} AS preserves_rw,
        ${table === "workspaces" ? "q.has_dashboard_url" : "false"} AS loses_history_route,
        ${table === "workspaces" ? "q.relayhistory_origin_raw" : "NULL::text"} AS history_origin_raw,
        ${table === "workspaces" ? "q.relaycast_api_key_generation IS NOT NULL" : "false"} AS has_generation,
        ${table === "coding_agent_credentials" ? "q.model_provider" : "NULL::text"} AS credential_provider,
        ${table === "coding_agent_credentials" ? "q.auth_type" : "NULL::text"} AS credential_auth_type
        FROM (${sourceQuery(table,scope)}) q`);
      const skipped:Record<string,number> = {};
      const deliberateExclusions=exclusionAccounting();
      const dynamicKeys:string[] = [];
      const dynamicReasons:Record<string,string[]> = {};
      let imported = 0;
      let candidates = 0;
      let missingRw = 0;
      let historyLoss = 0;
      let metadataLoss = 0;
      try {for (;;) {
        const batch = await s.query("FETCH FORWARD 250 FROM import_ledger_cursor");
        if (!batch.rows.length) break;
        candidates += batch.rows.length;
        for (const row of batch.rows) {
        let reason:string|null = row.skip_reason;
        if (reason === null && spec.secret?.source === "secret_envelope") {
          try { decryptCloudEnvelope(JSON.parse(row.envelope),cloudKeyHex); }
          catch { reason = "cloud_decrypt_failed"; }
        }
        if (reason === null && table === "desktop_relay_identities" && desktopUuid && !row.source_id_is_uuid) reason = "source_id_not_uuid";
        if (reason === null && spec.gate && !gatedPresent.has(table)) reason = spec.gate;
        if (reason === null && table === "staff_read_grants" && !operatorOrg) reason = "no_operator_organization";
        if (reason === null && table === "coding_agent_credentials" && !relayManaged) reason = "target_lacks_relay_managed";
        if (reason !== null) {
          if (table === "coding_agent_credentials") accountCredentialExclusion(deliberateExclusions,
            {reason,provider:row.credential_provider,authType:row.credential_auth_type});
          skipped[reason] = (skipped[reason] ?? 0)+1;
          if (row.skip_reason === null) {
            if (dynamicKeys.length >= 10000) throw new Error("Excessive unresolved dynamic skips; repair source/keys before qualification");
            dynamicKeys.push(row.key);
            (dynamicReasons[reason] ??= []).push(row.key);
          }
        } else {
          imported++;
          if (!row.preserves_rw) missingRw++;
          const origin=table === "workspaces" && row.history_origin_raw !== null ? canonicalOrigin(row.history_origin_raw) : null;
          if (table === "workspaces") origins.set(row.key,origin);
          if (row.loses_history_route || (table === "workspaces" && row.history_origin_raw !== null && origin === null)) historyLoss++;
          if ((origin !== null && !columns.has("workspaces.relayhistory_origin"))
            || (row.has_generation && !columns.has("workspaces.relaycast_api_key_generation"))) metadataLoss++;
          if (row.org) {
            const group = perOrg.get(row.org) ?? {};
            group[table] = (group[table] ?? 0)+1; perOrg.set(row.org,group);
            const keys = perOrgKeys.get(row.org) ?? {};
            (keys[table] ??= []).push(row.key);perOrgKeys.set(row.org,keys);
          }
        }
      }}} finally {await s.query("CLOSE import_ledger_cursor");}
      exclusions.set(table,dynamicKeys); counts.set(table,imported);
      if (table === "coding_agent_credentials") findings.push({kind:"credential_exclusions",name:"identity_metadata",
        ok:deliberateExclusions.every((entry) => entry.unresolved === 0),detail:{classes:deliberateExclusions}});
      if (table === "workspaces") findings.push({kind:"identity",name:"all_rw_bindings_preserved",ok:missingRw === 0,detail:{missing:missingRw}});
      if (table === "workspaces") findings.push({kind:"continuity",name:"workspace_metadata_preserved",
        ok:historyLoss === 0 && metadataLoss === 0,detail:{historyRoutesDropped:historyLoss,optionalMetadataDropped:metadataLoss}});
      if (dynamicKeys.length) findings.push({kind:"importer_skip_policy",name:table,ok:false,
        detail:{unresolvedDynamicSkips:dynamicKeys.length}});
      const reported = ledger.tables?.[table];
      for (const keys of Object.values(reported?.importerSkips ?? {})) {
        if (!Array.isArray(keys) || keys.some((key) => !validImportKey(table,key))) {
          throw new Error("Importer skip keys do not match the table key type");
        }
      }
      findings.push({kind:"ledger",name:table,ok:reported?.candidates === candidates && reported.imported === imported
        && sorted(reported.skipped) === sorted(skipped) && sortedKeys(reported.importerSkips) === sortedKeys(dynamicReasons),
        detail:{observed:{candidates,imported,skipped,importerSkips:dynamicReasons},reported:{
          candidates:safeCount(reported?.candidates),imported:safeCount(reported?.imported),deleted:safeCount(reported?.deleted),
          skipped:Object.fromEntries([...new Set([...Object.keys(skipped),...IMPORTER_SKIP_REASONS])]
            .filter((reason) => reported?.skipped?.[reason] !== undefined).map((reason) => [reason,safeCount(reported.skipped[reason])])),
        }}});
    }
    const expectedOrgs = [...perOrg.keys()].sort();
    findings.push({kind:"ledger",name:"organization_set",ok:JSON.stringify(expectedOrgs) === JSON.stringify(Object.keys(ledger.orgs ?? {}).sort()),detail:{expected:expectedOrgs}});
    for (const [org,expected] of perOrg) {
      const actual = ledger.orgs?.[org];
      findings.push({kind:"ledger_org",name:org,ok:actual?.status === "ok" && ORG_TABLES.every((table) =>
        (expected[table] ?? 0) === (actual.imported[table] ?? 0)),detail:{expected,reported:{
          status:actual && ["ok","failed","planned"].includes(actual.status) ? actual.status : "invalid",
          imported:Object.fromEntries(ORG_TABLES.map((table) => [table,safeCount(actual?.imported?.[table] ?? 0)])),
        }}});
    }
    findings.push(...await reconciliationFindings(t,ledger,perOrgKeys,gatedPresent,scope,options.previousReport,options.previousOwnership));
    const distinctOrigins=[...new Set([...origins.values()].filter((origin):origin is string => origin !== null))].sort();
    const originRows=columns.has("workspaces.relayhistory_origin")
      ? (await t.query("SELECT id::text,relayhistory_origin FROM public.workspaces WHERE id::text=ANY($1::text[])",[[...origins.keys()]])).rows : [];
    const storedOrigins=new Map(originRows.map((row) => [row.id,row.relayhistory_origin]));
    const originMismatches=[...origins].filter(([id,origin]) => !storedOrigins.has(id) || storedOrigins.get(id) !== origin).length;
    findings.push({kind:"canonical_history_origins",name:"workspaces",
      ok:originMismatches === 0 && Array.isArray(ledger.relayhistoryOrigins)
        && JSON.stringify(distinctOrigins) === JSON.stringify([...ledger.relayhistoryOrigins].sort()),
      detail:{workspaces:origins.size,distinctOrigins:distinctOrigins.length,mismatches:originMismatches,
        reportedDistinctCount:Array.isArray(ledger.relayhistoryOrigins) ? ledger.relayhistoryOrigins.length : null}});
    const tables = comparisons(scope,columns,gatedPresent).filter((item) => !absentSources.has(item.name as ImportTable)).map((item) => {
      const keys = exclusions.get(item.name)!;
      return keys.length ? {...item,sourceSql:`SELECT p.* FROM (${item.sourceSql}) p WHERE __key::text <> ALL(ARRAY[${keys.map(literal).join(",")}]::text[])`} : item;
    });
    if (options.credentialCopy) {
      const coding=tables.find((item) => item.name === "coding_agent_credentials");
      if (coding) for (const side of ["sourceSql","targetSql"] as const) coding[side]=`SELECT __key,__org,__workspace,
        to_jsonb(p)-'__key'-'__org'-'__workspace'-'is_active'-'harness_active' AS payload FROM (${coding[side]}) p`;
    }
    if (gatedPresent.has("staff_read_grants")) {
      const grants=await t.query(`SELECT count(*)::int AS imported,
        count(*) FILTER(WHERE g.revoked_at IS NULL OR g.revoked_by IS NOT NULL OR g.last_used_at IS NOT NULL
          OR g.staff_organization_id::text IS DISTINCT FROM $1::text OR g.token_hash !~ '^[0-9a-f]{64}$'
          OR (SELECT count(*) FROM public.admin_audit_events a WHERE a.action='staff_read_grant.imported'
            AND a.organization_id=g.organization_id AND a.workspace_id=g.workspace_id AND a.actor_kind='service'
            AND a.actor_id='cloud-import' AND a.target=g.id::text || ' workspace ' || g.workspace_id::text) <> 1)::int AS invalid
        FROM public.staff_read_grants g JOIN public.cloud_import_ledger l
          ON l.table_name='staff_read_grants' AND l.row_key=g.id::text AND l.organization_id=g.organization_id
        WHERE $2::uuid[] IS NULL OR g.organization_id=ANY($2::uuid[])`,[operatorOrg ?? null,scope.orgIds]);
      findings.push({kind:"staff_grant_history",name:"staff_read_grants",ok:grants.rows[0].invalid === 0,detail:grants.rows[0]});
    }
    const contract = contractFor(scope,columns,tables);
    contract.targetRelations = SOURCE_TABLES.filter((table) => gatedPresent.has(table)).map((table) => `public.${TARGETS[table].table}`);
    contract.targetRelations.push("public.cloud_import_ledger");
    contract.encryptedSamples = encryptedSamples(20,scope).flatMap((sample) => {
      const table = sample.name.split(".")[0] as ImportTable;
      if (counts.get(table) === 0) {
        findings.push({kind:"decrypt",name:sample.name,ok:true,detail:"not_applicable_no_imported_rows"}); return [];
      }
      return [sample];
    });
    // Preserve fail-closed sampling if the entire cohort lacks an importable
    // workspace: an empty cohort cannot qualify the credential migration.
    if (!contract.encryptedSamples.length) contract.encryptedSamples = base.encryptedSamples;
    findings.push(...await credentialSelections(t,scope));
    if (options.credentialCopy) findings.push(...await credentialCopyFindings(s,t,scope,options.credentialCopy,keyring,cloudKeyHex));
    return {contract,findings};
  }});
  const copyChecks=["credential_copy_ledger","credential_natural_keys","credential_control_ids","credential_cloud_selection","credential_copy_markers","credential_marker_links"];
  return {...checked,evidenceKind:"identity-import" as const,scope,sourceOrganizationCensus:sourceOrganizationCensus!,targetSchema:targetSchema!,
    credentialConvergence:options.credentialCopy?.convergenceBefore
      ? checked.findings.some((f) => f.kind === "credential_convergence" && f.ok) ? "verified" : "failed" : "not_requested",
    credentialCopy:options.credentialCopy
    ? copyChecks.every((kind) => checked.findings.some((f) => f.kind === kind))
      && checked.findings.filter((f) => f.kind.startsWith("credential_")).every((f) => f.ok) ? "verified" : "failed"
    : "not_requested"};
}
