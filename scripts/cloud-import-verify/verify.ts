import { createHash } from "node:crypto";
import type { Client } from "pg";
import { decryptSecret, type EncryptionKeyring } from "../../src/crypto.js";

/** SQL is trusted operator configuration, reviewed alongside mapping.ts.
 * Each projection must expose __key (unique, non-null) and __org (nullable).
 * Project only like-for-like values; do not hash randomized ciphertexts.
 */
export interface Comparison {
  name: string;
  sourceSql: string;
  targetSql: string;
  workspaceScoped?: boolean;
}
export interface Contract {
  version: 1;
  mappingRevision: string;
  tables: Comparison[];
  identities: Comparison[];
  targetRelations: string[];
  encryptedSamples: { name: string; sql: string; minimum: number; limit: number }[];
  standaloneSequences?: { name: string; relation: string; sourceBoundsSql: string; targetBoundsSql: string }[];
  pepperChecks?: { name: string; sql: string }[];
}
type OrgSummary = { count: number; checksum: string };
type Snapshot = {
  columns: string[];
  count: number;
  checksum: string;
  invalidKeys: number;
  orgs: Record<string, OrgSummary>;
  workspaces: Record<string, OrgSummary> | null;
  invalidWorkspaceBindings: number;
};
export type Finding = { kind: string; name: string; ok: boolean; detail: unknown };
export type Report = {
  version: 1;
  mappingRevision: string;
  ok: boolean;
  findings: Finding[];
  smoke: { name: string; status: "pending" }[];
};

const quote = (value: string) => `"${value.replaceAll('"', '""')}"`;
const qualified = (schema: string, name: string) => `${quote(schema)}.${quote(name)}`;
function hashRow(hash: ReturnType<typeof createHash>, row: string): void {
  hash.update(`${Buffer.byteLength(row)}:`).update(row);
}

async function snapshot(client: Client, sql: string, workspaceScoped = false): Promise<Snapshot> {
  const shape = await client.query(`SELECT * FROM (${sql}) p LIMIT 0`);
  const columns = shape.fields.map((f) => f.name).sort();
  if (!columns.includes("__key") || !columns.includes("__org")
    || (workspaceScoped && !columns.includes("__workspace")) || new Set(columns).size !== columns.length) {
    throw new Error("Projection requires unique aliases, __key, __org and scoped __workspace");
  }
  const badKeys = await client.query(`SELECT count(*)::text AS n FROM (
    SELECT __key FROM (${sql}) p GROUP BY __key HAVING __key IS NULL OR count(*) > 1
  ) duplicate_keys`);
  const invalidWorkspaceBindings = workspaceScoped
    ? Number((await client.query(`SELECT count(*)::text AS n FROM (${sql}) p WHERE __workspace IS NULL`)).rows[0].n) : 0;
  // PostgreSQL canonicalizes jsonb object keys and preserves numeric precision.
  // Length framing avoids concatenation ambiguities; C order is locale independent.
  await client.query(`DECLARE cloud_verify_cursor NO SCROLL CURSOR FOR
    SELECT to_jsonb(p)::text AS canonical, to_jsonb(p.__org)::text AS org,
      ${workspaceScoped ? "to_jsonb(p.__workspace)::text" : "NULL::text"} AS workspace
    FROM (${sql}) p ORDER BY to_jsonb(p)::text COLLATE "C"`);
  const hash = createHash("sha256");
  const orgs = new Map<string, { count: number; hash: ReturnType<typeof createHash> }>();
  const workspaces: typeof orgs = new Map();
  const accumulate = (groups: typeof orgs, key: string, row: string) => {
    const group = groups.get(key) ?? { count: 0, hash: createHash("sha256") };
    group.count++; hashRow(group.hash,row); groups.set(key,group);
  };
  let count = 0;
  try {
    for (;;) {
      const batch = await client.query("FETCH FORWARD 250 FROM cloud_verify_cursor");
      if (!batch.rows.length) break;
      for (const row of batch.rows as { canonical: string; org: string | null; workspace: string | null }[]) {
        count++;
        hashRow(hash, row.canonical);
        // JSON encoding distinguishes a null org from a literal string "null".
        accumulate(orgs,row.org ?? "null",row.canonical);
        if (workspaceScoped) accumulate(workspaces,row.workspace ?? "null",row.canonical);
      }
    }
  } finally {
    await client.query("CLOSE cloud_verify_cursor");
  }
  const finish = (groups: typeof orgs) => Object.fromEntries([...groups].sort(([a],[b]) => a.localeCompare(b))
    .map(([key,value]) => [key,{count:value.count,checksum:value.hash.digest("hex")} ]));
  return {
    columns, count, checksum: hash.digest("hex"), invalidKeys: Number(badKeys.rows[0].n),
    orgs: finish(orgs), workspaces: workspaceScoped ? finish(workspaces) : null, invalidWorkspaceBindings,
  };
}

async function compare(source: Client, target: Client, item: Comparison, kind: string): Promise<Finding> {
  const left = await snapshot(source, item.sourceSql,item.workspaceScoped);
  const right = await snapshot(target, item.targetSql,item.workspaceScoped);
  return { kind, name: item.name,
    ok: left.invalidKeys === 0 && right.invalidKeys === 0
      && left.invalidWorkspaceBindings === 0 && right.invalidWorkspaceBindings === 0
      && JSON.stringify(left) === JSON.stringify(right),
    detail: { source: left, target: right } };
}

async function standaloneSequence(source: Client,target: Client,item: NonNullable<Contract["standaloneSequences"]>[number]): Promise<Finding> {
  const metadata = await target.query(`SELECT n.nspname AS schema,c.relname AS name,
    s.seqincrement::text AS increment,s.seqmin::text AS minimum,s.seqmax::text AS maximum,s.seqcycle AS cycle
    FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE s.seqrelid=to_regclass($1)`,[item.relation]);
  if (metadata.rowCount !== 1) return {kind:"standalone_sequence",name:item.name,ok:false,detail:"missing_sequence"};
  const seq = metadata.rows[0];
  const state = (await target.query(`SELECT last_value::text,is_called FROM ${qualified(seq.schema,seq.name)}`)).rows[0];
  const next = BigInt(state.last_value) + (state.is_called ? BigInt(seq.increment) : 0n);
  const bounds = [];
  for (const [client,sql] of [[source,item.sourceBoundsSql],[target,item.targetBoundsSql]] as const) {
    const result = await client.query(`SELECT min_value::text,max_value::text FROM (${sql}) b`);
    if (result.rowCount !== 1) throw new Error("Sequence bounds require exactly one row");
    bounds.push(result.rows[0] as {min_value:string|null;max_value:string|null});
  }
  const ahead = bounds.every((b) => BigInt(seq.increment) > 0n
    ? b.max_value === null || next > BigInt(b.max_value) : b.min_value === null || next < BigInt(b.min_value));
  return {kind:"standalone_sequence",name:item.name,
    ok:ahead && !seq.cycle && next >= BigInt(seq.minimum) && next <= BigInt(seq.maximum),
    detail:{next:next.toString(),source:bounds[0],target:bounds[1],cycle:seq.cycle}};
}

async function relationChecks(client: Client, relation: string): Promise<Finding[]> {
  const found = await client.query(`SELECT c.oid::text, n.nspname AS schema, c.relname AS name
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.oid=to_regclass($1) AND c.relkind IN ('r','p')`, [relation]);
  if (found.rowCount !== 1) return [{ kind: "relation", name: relation, ok: false, detail: "missing_table" }];
  const table = found.rows[0];
  const tableSql = qualified(table.schema, table.name);
  const findings: Finding[] = [];
  const unvalidated = await client.query(`SELECT conname,contype FROM pg_constraint
    WHERE conrelid=$1::oid AND NOT convalidated ORDER BY conname`,[table.oid]);
  findings.push({kind:"constraint_validation",name:relation,ok:unvalidated.rows.length === 0,
    detail:{unvalidated:unvalidated.rows}});
  const fks = await client.query(`SELECT con.conname, con.convalidated, con.confmatchtype,
    rn.nspname AS ref_schema, rc.relname AS ref_table,
    ARRAY(SELECT a.attname::text FROM unnest(con.conkey) WITH ORDINALITY k(attnum, ord)
      JOIN pg_attribute a ON a.attrelid=con.conrelid AND a.attnum=k.attnum ORDER BY ord) AS cols,
    ARRAY(SELECT a.attname::text FROM unnest(con.confkey) WITH ORDINALITY k(attnum, ord)
      JOIN pg_attribute a ON a.attrelid=con.confrelid AND a.attnum=k.attnum ORDER BY ord) AS ref_cols
    FROM pg_constraint con JOIN pg_class rc ON rc.oid=con.confrelid
    JOIN pg_namespace rn ON rn.oid=rc.relnamespace
    WHERE con.conrelid=$1::oid AND con.contype='f'`, [table.oid]);
  for (const fk of fks.rows) {
    const cols: string[] = fk.cols;
    const nonNull = cols.map((c) => `t.${quote(c)} IS NOT NULL`).join(" AND ");
    const anyNonNull = cols.map((c) => `t.${quote(c)} IS NOT NULL`).join(" OR ");
    const join = cols.map((c, i) => `r.${quote(fk.ref_cols[i])}=t.${quote(c)}`).join(" AND ");
    const fullPartial = fk.confmatchtype === "f" ? `((${anyNonNull}) AND NOT (${nonNull})) OR ` : "";
    const result = await client.query(`SELECT count(*)::text AS n FROM ${tableSql} t WHERE
      ${fullPartial}((${nonNull}) AND NOT EXISTS
        (SELECT 1 FROM ${qualified(fk.ref_schema, fk.ref_table)} r WHERE ${join}))`);
    const violations = Number(result.rows[0].n);
    findings.push({ kind: "foreign_key", name: `${relation}.${fk.conname}`,
      ok: fk.convalidated && violations === 0, detail: { validated: fk.convalidated, violations } });
  }
  const indexes = await client.query(`SELECT i.indexrelid::text, c.relname AS name,
    i.indisvalid, i.indisready, i.indnullsnotdistinct,
    pg_get_expr(i.indpred,i.indrelid) AS predicate,
    ARRAY(SELECT pg_get_indexdef(i.indexrelid,k,true)
      FROM generate_series(1,i.indnkeyatts) k) AS expressions
    FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
    WHERE i.indrelid=$1::oid AND i.indisunique`, [table.oid]);
  for (const index of indexes.rows) {
    const expressions: string[] = index.expressions;
    const where = [index.predicate,
      ...(index.indnullsnotdistinct ? [] : expressions.map((e) => `(${e}) IS NOT NULL`))]
      .filter(Boolean).map((e) => `(${e})`).join(" AND ");
    const result = await client.query(`SELECT count(*)::text AS n FROM (
      SELECT 1 FROM ${tableSql} ${where ? `WHERE ${where}` : ""}
      GROUP BY ${expressions.join(", ")} HAVING count(*)>1) duplicate_groups`);
    const violations = Number(result.rows[0].n);
    findings.push({ kind: "unique", name: `${relation}.${index.name}`,
      ok: index.indisvalid && index.indisready && violations === 0,
      detail: { valid: index.indisvalid, ready: index.indisready, violations } });
  }
  const sequences = await client.query(`SELECT sn.nspname AS schema, s.relname AS name,
    a.attname AS col, ps.seqincrement::text AS increment, ps.seqmin::text AS minimum,
    ps.seqmax::text AS maximum, ps.seqcycle AS cycle
    FROM pg_depend d JOIN pg_class s ON s.oid=d.objid AND s.relkind='S'
    JOIN pg_namespace sn ON sn.oid=s.relnamespace
    JOIN pg_sequence ps ON ps.seqrelid=s.oid
    JOIN pg_attribute a ON a.attrelid=d.refobjid AND a.attnum=d.refobjsubid
    WHERE d.classid='pg_class'::regclass AND d.refclassid='pg_class'::regclass
      AND d.refobjid=$1::oid AND d.deptype IN ('a','i')`, [table.oid]);
  if (!sequences.rows.length) findings.push({ kind: "sequence", name: relation, ok: true, detail: "not_applicable" });
  for (const seq of sequences.rows) {
    // Reading sequence state does not consume a value. bigint arithmetic remains exact.
    const state = await client.query(`SELECT last_value::text, is_called FROM ${qualified(seq.schema, seq.name)}`);
    const increment = BigInt(seq.increment);
    const last = state.rows[0];
    const next = BigInt(last.last_value) + (last.is_called ? increment : 0n);
    const bounds = await client.query(`SELECT min(${quote(seq.col)})::text AS lo,
      max(${quote(seq.col)})::text AS hi FROM ${tableSql}`);
    const { lo, hi } = bounds.rows[0];
    const inBounds = next >= BigInt(seq.minimum) && next <= BigInt(seq.maximum);
    const ahead = increment > 0n ? hi === null || next > BigInt(hi) : lo === null || next < BigInt(lo);
    findings.push({ kind: "sequence", name: `${relation}.${seq.col}`, ok: inBounds && ahead && !seq.cycle,
      detail: { next: next.toString(), minimum: lo, maximum: hi, cycle: seq.cycle } });
  }
  return findings;
}

export function validateContract(contract: Contract): void {
  if (contract.version !== 1 || !contract.mappingRevision || !contract.tables?.length
    || !Array.isArray(contract.identities) || !contract.targetRelations?.length || !contract.encryptedSamples?.length) {
    throw new Error("Contract must name its mapping revision, tables, identities, target relations and encrypted samples");
  }
  const names = new Set<string>();
  for (const item of [...contract.tables, ...contract.identities]) {
    if (!item.name || !item.sourceSql || !item.targetSql || names.has(item.name)) throw new Error("Invalid or duplicate comparison");
    if (item.workspaceScoped !== undefined && typeof item.workspaceScoped !== "boolean") throw new Error("workspaceScoped must be boolean");
    names.add(item.name);
  }
  for (const sample of contract.encryptedSamples) {
    if (!sample.name || !sample.sql || !Number.isSafeInteger(sample.minimum) || sample.minimum < 1
      || !Number.isSafeInteger(sample.limit) || sample.limit < sample.minimum || sample.limit > 1000) {
      throw new Error("Encrypted sample requires 1 <= minimum <= limit <= 1000");
    }
  }
  for (const item of contract.standaloneSequences ?? []) {
    if (!item.name || !item.relation || !item.sourceBoundsSql || !item.targetBoundsSql) throw new Error("Invalid standalone sequence check");
  }
  for (const item of contract.pepperChecks ?? []) {
    if (!item.name || !item.sql) throw new Error("Invalid pepper check");
  }
}

/** Call with separate connected clients. Never writes or consumes sequences.
 * Freeze importer writes before taking these independent repeatable-read snapshots.
 */
export async function verify(source: Client, target: Client, contract: Contract, keyring: EncryptionKeyring,
  options: {pepperVersions?: readonly number[];
    prepare?: (source:Client,target:Client) => Promise<{contract:Contract;findings:Finding[]}>} = {}): Promise<Report> {
  if (source === target) throw new Error("Separate source and target clients required");
  validateContract(contract);
  const findings: Finding[] = [];
  let active = contract;
  try {
    for (const client of [source, target]) {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      await client.query("SET LOCAL statement_timeout='60s'");
      await client.query("SET LOCAL TIME ZONE 'UTC'");
      await client.query("SET LOCAL DateStyle='ISO, YMD'");
      // A role that silently filters data must not produce a passing checksum.
      await client.query("SET LOCAL row_security=off");
    }
    if (options.prepare) {
      const prepared = await options.prepare(source,target);
      validateContract(prepared.contract); active = prepared.contract; findings.push(...prepared.findings);
    }
    for (const item of active.tables) findings.push(await compare(source, target, item, "table"));
    for (const item of active.identities) findings.push(await compare(source, target, item, "identity"));
    for (const relation of active.targetRelations) findings.push(...await relationChecks(target, relation));
    for (const item of active.standaloneSequences ?? []) findings.push(await standaloneSequence(source,target,item));
    for (const item of active.pepperChecks ?? []) {
      const rows = await target.query(`SELECT DISTINCT pepper_version FROM (${item.sql}) p WHERE pepper_version IS NOT NULL`);
      const versions = rows.rows.map((row) => Number(row.pepper_version)).sort((a,b) => a-b);
      const missing = versions.filter((v) => !Number.isSafeInteger(v) || v < 1 || !options.pepperVersions?.includes(v));
      findings.push({kind:"pepper",name:item.name,ok:missing.length === 0,detail:{versions,missing}});
    }
    for (const sample of active.encryptedSamples) {
      const rows = await target.query(`SELECT ciphertext FROM (${sample.sql}) sample LIMIT $1`, [sample.limit]);
      let failures = 0;
      for (const row of rows.rows) {
        try {
          if (typeof row.ciphertext !== "string") throw new Error("missing_ciphertext");
          decryptSecret(row.ciphertext, keyring);
        } catch { failures++; }
      }
      findings.push({ kind: "decrypt", name: sample.name,
        ok: rows.rows.length >= sample.minimum && failures === 0,
        detail: { sampled: rows.rows.length, minimum: sample.minimum, failures } });
    }
  } finally {
    // Release snapshots even on a failed statement. Never serialize SQL errors:
    // PostgreSQL error details can contain rows and credentials.
    await Promise.allSettled([source.query("ROLLBACK"), target.query("ROLLBACK")]);
  }
  return { version: 1, mappingRevision: active.mappingRevision,
    ok: findings.every((f) => f.ok), findings,
    smoke: ["login", "workspace_list", "relaycast_key_resolve", "flows_run", "integration_token_refresh", "desktop_feed"]
      .map((name) => ({ name, status: "pending" })) };
}
