import { createHash } from "node:crypto";
import { readFile,readdir } from "node:fs/promises";
import type { Client } from "pg";
import type { Finding } from "./verify.js";

export type SchemaEntry={kind:string;name:string;definition:unknown};
export type SchemaManifest={version:1;baseline:string;migrations:{name:string;sha256:string}[];
  required:SchemaEntry[];optional:Record<string,SchemaEntry[]>;sha256:string};
const digest=(value:unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const canonical=(value:unknown):unknown => Array.isArray(value) ? value.map(canonical)
  : value !== null && typeof value === "object" ? Object.fromEntries(Object.entries(value).sort(([a],[b]) => a < b ? -1 : a > b ? 1 : 0).map(([key,v]) => [key,canonical(v)])) : value;
const key=(entry:SchemaEntry) => `${entry.kind}:${entry.name}`;
const sorted=(entries:SchemaEntry[]) => entries.map((entry) => ({...entry,definition:canonical(entry.definition)}))
  .sort((a,b) => key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0);

export async function migrationFiles() {
  const directory=new URL("../../migrations/",import.meta.url);
  return Promise.all((await readdir(directory)).filter((name) => name.endsWith(".sql")).sort().map(async (name) =>
    ({name,sha256:createHash("sha256").update(await readFile(new URL(name,directory))).digest("hex")})));
}

/** Catalogue definitions only, never table data. Must be called in a read-only
 * transaction by verification; the offline generator uses a fresh local DB. */
export async function schemaCatalog(client:Client,relations:readonly string[]|null=null):Promise<SchemaEntry[]> {
  await client.query("SET LOCAL search_path=pg_catalog,public");
  const tables=await client.query(`SELECT c.oid::text AS oid,c.relname,
    jsonb_build_object('kind',c.relkind,'row_security',c.relrowsecurity,'force_row_security',c.relforcerowsecurity)
      || CASE WHEN c.relkind IN ('v','m') THEN jsonb_build_object('view',pg_get_viewdef(c.oid,false)) ELSE '{}'::jsonb END AS definition
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f')
    AND NOT EXISTS(SELECT 1 FROM pg_depend d WHERE d.classid='pg_class'::regclass AND d.objid=c.oid AND d.deptype='e')
    AND ($1::text[] IS NULL OR c.relname=ANY($1::text[])) ORDER BY c.relname`,[relations]);
  const ids=tables.rows.map((row) => row.oid);
  const entries:SchemaEntry[]=tables.rows.map((row) => ({kind:"table",name:`public.${row.relname}`,definition:row.definition}));
  const columns=await client.query(`SELECT c.relname,a.attname,
    jsonb_build_object('position',a.attnum,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,
      'default',pg_get_expr(d.adbin,d.adrelid,false),'identity',a.attidentity,'generated',a.attgenerated,
      'collation',CASE WHEN coll.oid IS NULL THEN NULL ELSE cn.nspname||'.'||coll.collname END) AS definition
    FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
    LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
    LEFT JOIN pg_collation coll ON coll.oid=a.attcollation LEFT JOIN pg_namespace cn ON cn.oid=coll.collnamespace
    WHERE a.attrelid=ANY($1::oid[]) AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`,[ids]);
  entries.push(...columns.rows.map((row) => ({kind:"column",name:`public.${row.relname}.${row.attname}`,definition:row.definition})));
  const constraints=await client.query(`SELECT r.relname,c.conname,
    jsonb_build_object('type',c.contype,'definition',pg_get_constraintdef(c.oid,false),'validated',c.convalidated,
      'deferrable',c.condeferrable,'deferred',c.condeferred,'no_inherit',c.connoinherit,
      'triggers',COALESCE((SELECT jsonb_agg(jsonb_build_object('table',tn.nspname||'.'||tr.relname,
        'function',pn.nspname||'.'||p.proname,'type',t.tgtype,'enabled',t.tgenabled,
        'deferrable',t.tgdeferrable,'deferred',t.tginitdeferred) ORDER BY tn.nspname,tr.relname,t.tgtype,pn.nspname,p.proname)
        FROM pg_trigger t JOIN pg_class tr ON tr.oid=t.tgrelid JOIN pg_namespace tn ON tn.oid=tr.relnamespace
        JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace pn ON pn.oid=p.pronamespace
        WHERE t.tgconstraint=c.oid),'[]'::jsonb)) AS definition
    FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid WHERE c.conrelid=ANY($1::oid[])
    ORDER BY r.relname,c.conname`,[ids]);
  entries.push(...constraints.rows.map((row) => ({kind:"constraint",name:`public.${row.relname}.${row.conname}`,definition:row.definition})));
  const indexes=await client.query(`SELECT t.relname,i.relname AS index_name,
    jsonb_build_object('definition',pg_get_indexdef(x.indexrelid),'unique',x.indisunique,'primary',x.indisprimary,
      'valid',x.indisvalid,'ready',x.indisready,'live',x.indislive,'nulls_not_distinct',x.indnullsnotdistinct) AS definition
    FROM pg_index x JOIN pg_class t ON t.oid=x.indrelid JOIN pg_class i ON i.oid=x.indexrelid
    WHERE x.indrelid=ANY($1::oid[]) ORDER BY t.relname,i.relname`,[ids]);
  entries.push(...indexes.rows.map((row) => ({kind:"index",name:`public.${row.relname}.${row.index_name}`,definition:row.definition})));
  const triggers=await client.query(`SELECT c.relname,t.tgname,
    jsonb_build_object('definition',pg_get_triggerdef(t.oid,false),'enabled',t.tgenabled) AS definition
    FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
    WHERE t.tgrelid=ANY($1::oid[]) AND NOT t.tgisinternal ORDER BY c.relname,t.tgname`,[ids]);
  entries.push(...triggers.rows.map((row) => ({kind:"trigger",name:`public.${row.relname}.${row.tgname}`,definition:row.definition})));
  // Functions/sequences are migration-owned public objects. Extension functions
  // differ by provider and are not part of the Control migration manifest.
  if (relations === null || !relations.every((name) => name === "staff_read_grants")) {
    const functions=await client.query(`SELECT p.oid::regprocedure::text AS name,CASE WHEN p.prokind <> 'a' THEN to_jsonb(pg_get_functiondef(p.oid))
        ELSE jsonb_build_object('kind',p.prokind,'source',p.prosrc,'config',p.proconfig) END AS definition
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'
      AND NOT EXISTS(SELECT 1 FROM pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e')
      ORDER BY p.oid::regprocedure::text`);
    entries.push(...functions.rows.map((row) => ({kind:"function",name:row.name,definition:row.definition})));
    const sequences=await client.query(`SELECT c.relname,jsonb_build_object('type',format_type(s.seqtypid,NULL),'start',s.seqstart::text,
      'increment',s.seqincrement::text,'minimum',s.seqmin::text,'maximum',s.seqmax::text,'cache',s.seqcache::text,'cycle',s.seqcycle,
      'owner',COALESCE((SELECT tn.nspname||'.'||t.relname||'.'||a.attname FROM pg_depend d JOIN pg_class t ON t.oid=d.refobjid
        JOIN pg_namespace tn ON tn.oid=t.relnamespace JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=d.refobjsubid
        WHERE d.classid='pg_class'::regclass AND d.objid=c.oid AND d.deptype IN ('a','i') LIMIT 1),NULL)) AS definition
      FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' ORDER BY c.relname`);
    entries.push(...sequences.rows.map((row) => ({kind:"sequence",name:`public.${row.relname}`,definition:row.definition})));
  }
  if (relations === null) {
    const types=await client.query(`SELECT t.typname,jsonb_build_object('kind',t.typtype,
      'base',CASE WHEN t.typtype='d' THEN format_type(t.typbasetype,t.typtypmod) ELSE NULL END,
      'not_null',t.typnotnull,'default',t.typdefault,
      'labels',COALESCE((SELECT jsonb_agg(e.enumlabel ORDER BY e.enumsortorder) FROM pg_enum e WHERE e.enumtypid=t.oid),'[]'::jsonb),
      'constraints',COALESCE((SELECT jsonb_agg(pg_get_constraintdef(c.oid,false) ORDER BY c.conname) FROM pg_constraint c WHERE c.contypid=t.oid),'[]'::jsonb)) AS definition
      FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace LEFT JOIN pg_class r ON r.oid=t.typrelid
      WHERE n.nspname='public' AND (t.typtype IN ('d','e') OR (t.typtype='c' AND r.relkind='c'))
      AND NOT EXISTS(SELECT 1 FROM pg_depend d WHERE d.classid='pg_type'::regclass AND d.objid=t.oid AND d.deptype='e') ORDER BY t.typname`);
    entries.push(...types.rows.map((row) => ({kind:"type",name:`public.${row.typname}`,definition:row.definition})));
  }
  return sorted(entries);
}

export function sealManifest(value:Omit<SchemaManifest,"sha256">):SchemaManifest {
  return {...value,sha256:digest(canonical(value))};
}

export async function schemaFindings(client:Client) {
  const expected=JSON.parse(await readFile(new URL("./schema-manifest.json",import.meta.url),"utf8")) as SchemaManifest;
  const {sha256,...content}=expected;
  if (expected.version !== 1 || !expected.required?.some((entry) => entry.kind === "table")
    || sha256 !== digest(canonical(content))) throw new Error("Invalid committed schema manifest");
  const presentOptional:string[]=[];
  for (const relation of Object.keys(expected.optional)) {
    if ((await client.query("SELECT to_regclass($1) IS NOT NULL AS present",[`public.${relation}`])).rows[0].present) presentOptional.push(relation);
  }
  const actual=await schemaCatalog(client);
  const wanted=sorted([...expected.required,...presentOptional.flatMap((name) => expected.optional[name]!)]);
  const actualMap=new Map(actual.map((entry) => [key(entry),digest(entry.definition)]));
  const wantedMap=new Map(wanted.map((entry) => [key(entry),digest(entry.definition)]));
  const missing=wanted.filter((entry) => !actualMap.has(key(entry))).map(key);
  const changed=wanted.filter((entry) => actualMap.has(key(entry)) && actualMap.get(key(entry)) !== wantedMap.get(key(entry))).map(key);
  const unexpected=actual.filter((entry) => !wantedMap.has(key(entry)));
  const migrationsMatch=digest(await migrationFiles()) === digest(expected.migrations);
  const ok=!missing.length && !changed.length && !unexpected.length && migrationsMatch;
  const summary={baseline:expected.baseline,manifestSha256:sha256,expectedSchemaSha256:digest(wanted),actualSchemaSha256:digest(actual),
    profile:presentOptional.length ? "main-plus-proposed-0061" : "main",optionalRelations:presentOptional,
    expectedObjects:wanted.length,actualObjects:actual.length,missing,changed,unexpectedCount:unexpected.length,
    migrationsMatch,ok};
  const finding:Finding={kind:"schema_manifest",name:expected.baseline,ok,detail:summary};
  // Never query row data or read credential objects against an unreviewed or
  // degraded target schema. The metadata failure remains in the bound report.
  return {finding,summary,halt:!ok};
}

/** Stable one-object-per-line serialization keeps the reviewed inventory diffable. */
export function manifestJson(manifest:SchemaManifest):string {
  const lines=["{",`  "version":1,`, `  "baseline":${JSON.stringify(manifest.baseline)},`, `  "migrations":[`];
  lines.push(manifest.migrations.map((entry) => `    ${JSON.stringify(entry)}`).join(",\n"));
  lines.push('  ],','  "required":[');
  lines.push(manifest.required.map((entry) => `    ${JSON.stringify(entry)}`).join(",\n"));
  lines.push('  ],','  "optional":{');
  lines.push(Object.entries(manifest.optional).map(([name,entries]) => `    ${JSON.stringify(name)}:[\n${entries.map((entry) => `      ${JSON.stringify(entry)}`).join(",\n")}\n    ]`).join(",\n"));
  lines.push('  },',`  "sha256":${JSON.stringify(manifest.sha256)}`,'}');return lines.join("\n")+"\n";
}
