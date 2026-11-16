import type { Client } from "pg";
import type { EncryptionKeyring } from "../../src/crypto.js";
import { decryptCloudEnvelope, type ImportReport } from "../cloud-import/importer.js";
import { MAPPING_REVISION, ORG_TABLES, SOURCE_TABLES, TARGETS, TARGET_RELATIONS,
  assertScope, encryptedSamples, sourceQuery, verifierComparisons, type ImportScope, type ImportTable } from "../cloud-import/mapping.js";
import { verify, type Comparison, type Contract, type Finding } from "./verify.js";

const literal = (s:string) => `'${s.replaceAll("'","''")}'`;
const sorted = (values:Record<string,number>) => JSON.stringify(Object.entries(values).filter(([,n]) => n !== 0).sort(([a],[b]) => a.localeCompare(b)));
const sortedKeys = (values:Record<string,string[]>) => JSON.stringify(Object.entries(values).filter(([,keys]) => keys.length)
  .sort(([a],[b]) => a.localeCompare(b)).map(([reason,keys]) => [reason,[...keys].sort()]));
const equalScope = (a:ImportScope,b:ImportScope) => JSON.stringify(a.orgIds?.map((s) => s.toLowerCase()).sort() ?? null)
  === JSON.stringify(b.orgIds?.map((s) => s.toLowerCase()).sort() ?? null);

function comparisons(scope:ImportScope,columns:ReadonlySet<string>): Comparison[] {
  return verifierComparisons(scope,columns);
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
  keyring:EncryptionKeyring,cloudKeyHex:string,options:{pepperVersions?:readonly number[]} = {}) {
  assertScope(scope);
  if (!/^[0-9a-f]{64}$/i.test(cloudKeyHex)) throw new Error("Cloud key must be 32 bytes of hex");
  const base = contractFor(scope,new Set());
  return verify(source,target,base,keyring,{...options,prepare:async (s,t) => {
    const findings:Finding[] = [];
    findings.push({kind:"ledger",name:"run",ok:ledger.version === 1 && ledger.mappingRevision === MAPPING_REVISION
      && ledger.mode === "apply" && ledger.ok === true && !ledger.refused && equalScope(scope,ledger.scope),
      detail:{expectedRevision:MAPPING_REVISION,actualRevision:ledger.mappingRevision,mode:ledger.mode,ok:ledger.ok}});
    const metadata = await t.query(`SELECT table_name,column_name,udt_name FROM information_schema.columns WHERE table_schema='public'`);
    const columns = new Set<string>(metadata.rows.map((r) => `${r.table_name}.${r.column_name}`));
    const desktopUuid = metadata.rows.some((r) => r.table_name === "desktop_relay_identities" && r.column_name === "source_id" && r.udt_name === "uuid");
    const relayManaged = (await t.query(`SELECT EXISTS (SELECT 1 FROM pg_constraint c
      WHERE c.conrelid='public.coding_agent_credentials'::regclass AND c.contype='c'
      AND pg_get_constraintdef(c.oid) LIKE '%auth_type%' AND pg_get_constraintdef(c.oid) LIKE '%relay_managed%') AS ok`)).rows[0].ok;
    findings.push({kind:"identity",name:"rw_column_present",ok:columns.has("workspaces.cloud_relay_workspace_id"),
      detail:columns.has("workspaces.cloud_relay_workspace_id") ? "present" : "missing_required_mapping_column"});
    const actualOptional = SOURCE_TABLES.flatMap((table) => (TARGETS[table].optional ?? [])
      .filter((c) => columns.has(`${table}.${c}`)).map((c) => `${table}.${c}`)).sort();
    findings.push({kind:"ledger",name:"optional_columns",ok:JSON.stringify(actualOptional) === JSON.stringify([...(ledger.optionalColumns ?? [])].sort()),
      detail:{expected:actualOptional,reported:ledger.optionalColumns}});
    const perOrg = new Map<string,Partial<Record<ImportTable,number>>>();
    const exclusions = new Map<string,string[]>();
    const counts = new Map<ImportTable,number>();
    for (const table of SOURCE_TABLES) {
      const spec = TARGETS[table];
      const key = spec.primaryKey.map((c) => `q.${c}::text`).join(" || ':' || ");
      await s.query(`DECLARE import_ledger_cursor NO SCROLL CURSOR FOR SELECT ${key} AS key,skip_reason,
        ${table === "users" ? "NULL::text" : "q.organization_id::text"} AS org,
        ${spec.secret?.source === "secret_envelope" ? "q.secret_envelope::text" : "NULL::text"} AS envelope,
        ${table === "desktop_relay_identities" ? "q.source_id_is_uuid" : "true"} AS source_id_is_uuid,
        ${table === "workspaces" ? "q.cloud_relay_workspace_id IS NOT NULL" : "true"} AS preserves_rw,
        ${table === "workspaces" ? "q.origin_invalid OR q.has_dashboard_url" : "false"} AS loses_history_route,
        ${table === "workspaces" ? "q.relayhistory_origin IS NOT NULL" : "false"} AS has_history_origin,
        ${table === "workspaces" ? "q.relaycast_api_key_generation IS NOT NULL" : "false"} AS has_generation
        FROM (${sourceQuery(table,scope)}) q`);
      const skipped:Record<string,number> = {};
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
        if (reason === null && table === "coding_agent_credentials" && !relayManaged) reason = "target_lacks_relay_managed";
        if (reason !== null) {
          skipped[reason] = (skipped[reason] ?? 0)+1;
          if (row.skip_reason === null) {
            if (dynamicKeys.length >= 10000) throw new Error("Excessive unresolved dynamic skips; repair source/keys before qualification");
            dynamicKeys.push(row.key);
            (dynamicReasons[reason] ??= []).push(row.key);
          }
        } else {
          imported++;
          if (!row.preserves_rw) missingRw++;
          if (row.loses_history_route) historyLoss++;
          if ((row.has_history_origin && !columns.has("workspaces.relayhistory_origin"))
            || (row.has_generation && !columns.has("workspaces.relaycast_api_key_generation"))) metadataLoss++;
          if (row.org) {
            const group = perOrg.get(row.org) ?? {};
            group[table] = (group[table] ?? 0)+1; perOrg.set(row.org,group);
          }
        }
      }}} finally {await s.query("CLOSE import_ledger_cursor");}
      exclusions.set(table,dynamicKeys); counts.set(table,imported);
      if (table === "workspaces") findings.push({kind:"identity",name:"all_rw_bindings_preserved",ok:missingRw === 0,detail:{missing:missingRw}});
      if (table === "workspaces") findings.push({kind:"continuity",name:"workspace_metadata_preserved",
        ok:historyLoss === 0 && metadataLoss === 0,detail:{historyRoutesDropped:historyLoss,optionalMetadataDropped:metadataLoss}});
      if (dynamicKeys.length) findings.push({kind:"importer_skip_policy",name:table,ok:false,
        detail:{unresolvedDynamicSkips:dynamicKeys.length}});
      const reported = ledger.tables?.[table];
      const keyFormat = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?::[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?$/i;
      for (const keys of Object.values(reported?.importerSkips ?? {})) {
        if (!Array.isArray(keys) || keys.some((key) => typeof key !== "string" || !keyFormat.test(key))) {
          throw new Error("Importer skip keys must be UUIDs or org:user UUID pairs");
        }
      }
      findings.push({kind:"ledger",name:table,ok:reported?.candidates === candidates && reported.imported === imported
        && sorted(reported.skipped) === sorted(skipped) && sortedKeys(reported.importerSkips) === sortedKeys(dynamicReasons),
        detail:{observed:{candidates,imported,skipped,importerSkips:dynamicReasons},reported}});
    }
    const expectedOrgs = [...perOrg.keys()].sort();
    findings.push({kind:"ledger",name:"organization_set",ok:JSON.stringify(expectedOrgs) === JSON.stringify(Object.keys(ledger.orgs ?? {}).sort()),detail:{expected:expectedOrgs}});
    for (const [org,expected] of perOrg) {
      const actual = ledger.orgs?.[org];
      findings.push({kind:"ledger_org",name:org,ok:actual?.status === "ok" && ORG_TABLES.every((table) =>
        (expected[table] ?? 0) === (actual.imported[table] ?? 0)),detail:{expected,reported:actual}});
    }
    const tables = comparisons(scope,columns).map((item) => {
      const keys = exclusions.get(item.name)!;
      return keys.length ? {...item,sourceSql:`SELECT p.* FROM (${item.sourceSql}) p WHERE __key::text <> ALL(ARRAY[${keys.map(literal).join(",")}]::text[])`} : item;
    });
    const contract = contractFor(scope,columns,tables);
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
    return {contract,findings};
  }});
}
