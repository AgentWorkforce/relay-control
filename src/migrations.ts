import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import {
  assertCurrentSchema,
  forbiddenRoleAttribute,
  ROLE_ATTRIBUTE_COLUMNS,
  type Database,
  type RoleAttributes,
  type SqlExecutor,
} from "./database.js";
import { DEFAULT_DATABASE_SCHEMA, qualifiedName, quoteSchema } from "./db-schema.js";

type AppliedMigration = {
  name: string;
  checksum: string;
};

const MIGRATIONS_TABLE = "selfhost_schema_migrations";

/** The first migration; once the ledger records it, CORE_TABLES must exist. */
export const CORE_MIGRATION = "0001_control_plane.sql";
/** Tables created by CORE_MIGRATION, checked in the configured schema after migrate. */
export const CORE_TABLES = [
  "selfhost_users",
  "selfhost_organizations",
  "selfhost_organization_memberships",
  "selfhost_workspaces",
  "selfhost_token_sessions",
  "selfhost_device_authorizations",
] as const;

/** Schemas every guard query skips: the system namespaces. */
const SYSTEM_SCHEMA_FILTER = `n.nspname <> 'information_schema'
          AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'`;

export function defaultMigrationsDirectory(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "../migrations");
}

function quoteIdentifier(value: string): string {
  if (
    !/^[A-Za-z_][A-Za-z0-9_$]{0,62}$/.test(value) ||
    value.toLowerCase() === "public"
  ) {
    throw new Error("Invalid runtime PostgreSQL role name");
  }
  return `"${value.replaceAll('"', '""')}"`;
}

export type RuntimeGrantOptions = {
  /**
   * Reviewed extension namespaces (SELFHOST_DATABASE_ALLOWED_SCHEMAS) exempt
   * from the foreign-schema checks. Extension namespaces only, never another
   * service's schema: each must be the namespace of an installed extension
   * and every table, sequence, view and function in it must belong to an
   * installed extension, or the grant is refused before anything runs.
   */
  allowedSchemas?: readonly string[];
};

/**
 * SELFHOST_DATABASE_ALLOWED_SCHEMAS may only name extension namespaces: each
 * schema must exist, must be the namespace (pg_extension.extnamespace) of at
 * least one installed extension, and every table, sequence, view, materialized
 * view, foreign table and function in it must be a member of an installed
 * extension (pg_depend deptype 'e'). Another service's schema never
 * qualifies, and neither does an empty schema: the exemption is never vacuous.
 */
async function assertExtensionNamespaces(
  transaction: SqlExecutor,
  allowed: readonly string[],
): Promise<void> {
  if (allowed.length === 0) return;
  const result = await transaction.query<{
    schema_name: string;
    present: boolean;
    extension_namespace: boolean;
    offender: string | null;
  }>(
    `SELECT s.name AS schema_name,
            ns.oid IS NOT NULL AS present,
            EXISTS (SELECT 1 FROM pg_extension e WHERE e.extnamespace = ns.oid) AS extension_namespace,
            (SELECT o.description
               FROM (
                 SELECT CASE WHEN rel.relkind = 'S' THEN 2 ELSE 1 END AS ord, rel.relname::text AS sort_key,
                        CASE rel.relkind
                          WHEN 'S' THEN 'sequence'
                          WHEN 'v' THEN 'view'
                          WHEN 'm' THEN 'materialized view'
                          WHEN 'f' THEN 'foreign table'
                          ELSE 'table'
                        END || ' "' || s.name || '"."' || rel.relname || '"' AS description
                   FROM pg_class rel
                  WHERE rel.relnamespace = ns.oid
                    AND rel.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
                    AND NOT EXISTS (
                      SELECT 1 FROM pg_depend d
                       WHERE d.classid = 'pg_class'::regclass
                         AND d.objid = rel.oid
                         AND d.refclassid = 'pg_extension'::regclass
                         AND d.deptype = 'e')
                 UNION ALL
                 SELECT 3, fn.proname::text,
                        'function "' || s.name || '".' || fn.proname || '(' ||
                          pg_get_function_identity_arguments(fn.oid) || ')'
                   FROM pg_proc fn
                  WHERE fn.pronamespace = ns.oid
                    AND NOT EXISTS (
                      SELECT 1 FROM pg_depend d
                       WHERE d.classid = 'pg_proc'::regclass
                         AND d.objid = fn.oid
                         AND d.refclassid = 'pg_extension'::regclass
                         AND d.deptype = 'e')
               ) o
              ORDER BY o.ord, o.sort_key, o.description
              LIMIT 1) AS offender
       FROM unnest($1::text[]) WITH ORDINALITY AS s(name, position)
       LEFT JOIN pg_namespace ns ON ns.nspname = s.name
      ORDER BY s.position`,
    [allowed],
  );
  for (const row of result.rows) {
    if (row.present !== true) {
      throw new Error(
        `SELFHOST_DATABASE_ALLOWED_SCHEMAS entry "${row.schema_name}" does not exist; ` +
          "list only installed extension namespaces",
      );
    }
    if (row.extension_namespace !== true) {
      throw new Error(
        `SELFHOST_DATABASE_ALLOWED_SCHEMAS entry "${row.schema_name}" is not an installed ` +
          `extension's namespace: no installed extension is in schema "${row.schema_name}"` +
          (row.offender ? ` and ${row.offender} is not owned by an installed extension` : "") +
          ". List only extension namespaces, never another service's schema",
      );
    }
    if (row.offender) {
      throw new Error(
        `SELFHOST_DATABASE_ALLOWED_SCHEMAS entry "${row.schema_name}" is not an extension ` +
          `namespace: ${row.offender} is not owned by an installed extension. ` +
          "List only extension namespaces, never another service's schema",
      );
    }
  }
}

/**
 * Grants the runtime role CRUD on the selfhost_* tables and sequences of
 * `database.schema`, after proving the role is isolated to that schema. The
 * checks are the isolation proof; any failure aborts before a GRANT runs.
 */
export async function grantRuntimeDatabaseRole(
  database: Database,
  runtimeRole: string,
  options: RuntimeGrantOptions = {},
): Promise<void> {
  const role = quoteIdentifier(runtimeRole);
  const schema = database.schema;
  const schemaSql = quoteSchema(schema);
  const ledger = qualifiedName(schema, MIGRATIONS_TABLE);
  // The configured schema plus reviewed extension namespaces.
  const allowed = [...new Set(options.allowedSchemas ?? [])].filter((name) => name !== schema);
  const exempt = [schema, ...allowed];
  await database.transaction(async (transaction) => {
    const current = await transaction.query<{ current_user: string }>(
      "SELECT current_user AS current_user",
    );
    if (current.rows[0]?.current_user === runtimeRole) {
      throw new Error("Migration and runtime database roles must be distinct");
    }

    const attributes = await transaction.query<RoleAttributes>(
      `SELECT ${ROLE_ATTRIBUTE_COLUMNS} FROM pg_roles r WHERE r.rolname = $1`,
      [runtimeRole],
    );
    const attribute = attributes.rows[0] ? forbiddenRoleAttribute(attributes.rows[0]) : null;
    if (attribute) {
      throw new Error(`Runtime database role "${runtimeRole}" must not have ${attribute}`);
    }

    const identity = await transaction.query<{ is_member: boolean; can_create_database: boolean }>(
      `SELECT
         pg_has_role($1, current_user, 'MEMBER') AS is_member,
         has_database_privilege($1, current_database(), 'CREATE') AS can_create_database`,
      [runtimeRole],
    );
    if (identity.rows[0]?.is_member === true) {
      throw new Error(
        `Runtime database role "${runtimeRole}" must not be a member of the migration role`,
      );
    }
    if (identity.rows[0]?.can_create_database === true) {
      throw new Error(
        `Runtime database role "${runtimeRole}" must not have CREATE on the database`,
      );
    }

    const schemaPrivileges = await transaction.query<{ can_create: boolean }>(
      "SELECT has_schema_privilege($1, $2, 'CREATE') AS can_create",
      [runtimeRole, schema],
    );
    if (schemaPrivileges.rows[0]?.can_create === true) {
      throw new Error(
        `Runtime database role must not have schema CREATE privilege on schema "${schema}"`,
      );
    }

    await assertExtensionNamespaces(transaction, allowed);

    // Isolation proof: the runtime role reaches no schema but its own (and
    // reviewed extension namespaces). System schemas (pg_catalog, pg_toast,
    // pg_temp_*, information_schema) are excluded; roles cannot create
    // pg_-prefixed schemas.
    const foreignSchemas = await transaction.query<{ nspname: string }>(
      `SELECT n.nspname
         FROM pg_namespace n
        WHERE n.nspname <> ALL($2::text[])
          AND ${SYSTEM_SCHEMA_FILTER}
          AND has_schema_privilege($1, n.oid, 'USAGE')
        ORDER BY n.nspname`,
      [runtimeRole, exempt],
    );
    if (foreignSchemas.rows.length > 0) {
      // Effective access: USAGE (direct, via membership or via PUBLIC) plus
      // EXECUTE (any source, PUBLIC included) on a function in that schema.
      const reachable = await transaction.query<{ nspname: string; signature: string }>(
        `SELECT n.nspname,
                p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS signature
           FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = ANY($2::text[])
            AND has_function_privilege($1, p.oid, 'EXECUTE')
          ORDER BY n.nspname, p.proname
          LIMIT 1`,
        [runtimeRole, foreignSchemas.rows.map(({ nspname }) => nspname)],
      );
      const reached = reachable.rows[0];
      if (reached) {
        throw new Error(
          `Runtime database role "${runtimeRole}" has effective access to function ` +
            `"${reached.nspname}".${reached.signature} outside schema "${schema}": it has USAGE ` +
            `on schema "${reached.nspname}" and EXECUTE on the function`,
        );
      }
      const names = foreignSchemas.rows.map(({ nspname }) => `"${nspname}"`).join(", ");
      throw new Error(
        `Runtime database role "${runtimeRole}" must not have USAGE on schema ${names}; ` +
          `it may only use schema "${schema}"`,
      );
    }

    // Object grants survive a missing USAGE and become live the moment USAGE
    // is granted, so foreign objects must carry no privilege either.
    const foreignRelations = await transaction.query<{ nspname: string; relname: string; kind: string }>(
      `SELECT n.nspname, c.relname,
              CASE WHEN c.relkind = 'S' THEN 'sequence' ELSE 'table' END AS kind
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname <> ALL($2::text[])
          AND ${SYSTEM_SCHEMA_FILTER}
          AND CASE
                WHEN c.relkind = 'S'
                  THEN has_sequence_privilege($1, c.oid, 'USAGE, SELECT, UPDATE')
                WHEN c.relkind IN ('r', 'p', 'v', 'm', 'f')
                  THEN has_table_privilege(
                    $1, c.oid, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
                ELSE false
              END
        ORDER BY n.nspname, c.relname
        LIMIT 1`,
      [runtimeRole, exempt],
    );
    const relation = foreignRelations.rows[0];
    if (relation) {
      throw new Error(
        `Runtime database role "${runtimeRole}" must not hold privileges on ${relation.kind} ` +
          `"${relation.nspname}"."${relation.relname}" outside schema "${schema}"`,
      );
    }
    // Functions in schemas the role cannot USE (the check above refused any
    // usable one): EXECUTE granted to the runtime role (or owned by it) or to
    // a non-PUBLIC role it belongs to, walked transitively, is grant drift
    // that becomes live if USAGE is ever granted. PUBLIC's default EXECUTE
    // (grantee 0) on such functions is not access and never fails the proof.
    const foreignFunctions = await transaction.query<{
      nspname: string;
      signature: string;
      grantee: string;
    }>(
      `WITH RECURSIVE runtime_roles(oid) AS (
         SELECT r.oid FROM pg_roles r WHERE r.rolname = $1
         UNION
         SELECT m.roleid
           FROM pg_auth_members m
           JOIN runtime_roles rr ON m.member = rr.oid
       )
       SELECT n.nspname,
              p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS signature,
              pg_get_userbyid(a.grantee) AS grantee
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
        WHERE n.nspname <> ALL($2::text[])
          AND ${SYSTEM_SCHEMA_FILTER}
          AND a.privilege_type = 'EXECUTE'
          AND a.grantee <> 0
          AND a.grantee IN (SELECT oid FROM runtime_roles)
        ORDER BY n.nspname, p.proname, 3
        LIMIT 1`,
      [runtimeRole, exempt],
    );
    const fn = foreignFunctions.rows[0];
    if (fn) {
      throw new Error(
        `Runtime database role "${runtimeRole}" has explicit grant drift: EXECUTE on function ` +
          `"${fn.nspname}".${fn.signature} outside schema "${schema}" is granted to role ` +
          `"${fn.grantee}" (the runtime role or a role it is a member of); schema ` +
          `"${fn.nspname}" is not usable by the runtime role`,
      );
    }

    await transaction.exec(`GRANT USAGE ON SCHEMA ${schemaSql} TO ${role}`);

    // Explicit grants filtered to selfhost_*; the migrate command reruns this
    // pass after every migrate, so tables from later migrations are covered.
    const tables = await transaction.query<{ tablename: string }>(
      `SELECT tablename
         FROM pg_tables
        WHERE schemaname = $1
          AND tablename LIKE 'selfhost\\_%' ESCAPE '\\'
          AND tablename <> '${MIGRATIONS_TABLE}'`,
      [schema],
    );
    for (const { tablename } of tables.rows) {
      await transaction.exec(
        `GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ${schemaSql}.${quoteIdentifier(tablename)} TO ${role}`,
      );
    }
    const sequences = await transaction.query<{ sequencename: string }>(
      `SELECT sequencename
         FROM pg_sequences
        WHERE schemaname = $1
          AND sequencename LIKE 'selfhost\\_%' ESCAPE '\\'`,
      [schema],
    );
    for (const { sequencename } of sequences.rows) {
      await transaction.exec(
        `GRANT USAGE, SELECT, UPDATE ON SEQUENCE ${schemaSql}.${quoteIdentifier(sequencename)} TO ${role}`,
      );
    }

    await transaction.exec(`REVOKE ALL PRIVILEGES ON TABLE ${ledger} FROM ${role}`);
    const migrationPrivileges = await transaction.query<{ can_migrate: boolean }>(
      `SELECT
         has_table_privilege($1, $2, 'SELECT')
         OR has_table_privilege($1, $2, 'INSERT')
         OR has_table_privilege($1, $2, 'UPDATE')
         OR has_table_privilege($1, $2, 'DELETE')
         OR has_table_privilege($1, $2, 'TRUNCATE')
         OR has_table_privilege($1, $2, 'REFERENCES')
         OR has_table_privilege($1, $2, 'TRIGGER')
         AS can_migrate`,
      [runtimeRole, ledger],
    );
    if (migrationPrivileges.rows[0]?.can_migrate === true) {
      throw new Error("Runtime database role must not inherit migration table privileges");
    }
  });
}

export type MigrateOptions = {
  /**
   * SELFHOST_DATABASE_SCHEMA_CUTOVER=fresh: install into a brand-new configured
   * schema. Refused unless the configured schema is empty: no relation of any
   * kind, function or user-defined type that is not an installed extension's
   * member (the ledger and selfhost_* tables included); fresh never migrates
   * data and does not unlock coexistence with selfhost_* tables in another
   * schema.
   */
  cutover?: "fresh";
};

/**
 * Refuses a missing schema, or (outside legacy `public`) one the migration
 * role does not own. Migrations never create or adopt a schema.
 */
async function assertSchemaOwnership(transaction: SqlExecutor, schema: string): Promise<void> {
  const result = await transaction.query<{ owner: string; current_user: string }>(
    `SELECT pg_get_userbyid(n.nspowner) AS owner, current_user AS current_user
       FROM pg_namespace n
      WHERE n.nspname = $1`,
    [schema],
  );
  const row = result.rows[0];
  if (!row) {
    throw new Error(
      `Database schema "${schema}" (SELFHOST_DATABASE_SCHEMA) does not exist; ` +
        "the operator must pre-create it, owned by the migration role",
    );
  }
  if (schema !== DEFAULT_DATABASE_SCHEMA && row.owner !== row.current_user) {
    throw new Error(
      `Database schema "${schema}" is owned by "${row.owner}", not by the migration role ` +
        `"${row.current_user}"; the operator must transfer ownership before migrating`,
    );
  }
}

/** selfhost_* tables in other schemas, read from pg_class so it needs no table privilege. */
async function selfhostTablesOutside(
  transaction: SqlExecutor,
  schema: string,
): Promise<Set<string>> {
  const result = await transaction.query<{ nspname: string; relname: string }>(
    `SELECT n.nspname, c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname <> $1
        AND c.relkind IN ('r', 'p')
        AND c.relname LIKE 'selfhost\\_%' ESCAPE '\\'`,
    [schema],
  );
  return new Set(result.rows.map((row) => `${row.nspname}.${row.relname}`));
}

/**
 * The first object in `schema` that is not a member of an installed extension
 * (pg_depend deptype 'e'), described for an error message, or null when the
 * schema is empty. Covers every pg_class relkind, every pg_proc entry and
 * user-defined pg_type entries (enum, domain, range, base, standalone
 * composite). Objects that exist only because of another object (indexes,
 * constraint indexes, owned and identity sequences, relation row types, array
 * and multirange types: pg_depend deptype 'a' or 'i' on a relation,
 * constraint or type) are skipped; the relation or type they hang off is
 * itself checked. Ordered by kind, then name, so the result is
 * deterministic.
 */
async function firstObjectIn(transaction: SqlExecutor, schema: string): Promise<string | null> {
  const result = await transaction.query<{ description: string }>(
    `WITH target AS (SELECT oid FROM pg_namespace WHERE nspname = $1)
     SELECT o.description
       FROM (
         SELECT 1 AS ord, c.relname::text AS sort_key,
                CASE c.relkind
                  WHEN 'r' THEN 'table'
                  WHEN 'p' THEN 'partitioned table'
                  WHEN 'S' THEN 'sequence'
                  WHEN 'v' THEN 'view'
                  WHEN 'm' THEN 'materialized view'
                  WHEN 'f' THEN 'foreign table'
                  WHEN 'c' THEN 'composite type'
                  WHEN 'i' THEN 'index'
                  WHEN 'I' THEN 'partitioned index'
                  ELSE 'relation'
                END || ' "' || $1 || '"."' || c.relname || '"' AS description
           FROM pg_class c
          WHERE c.relnamespace = (SELECT oid FROM target)
            AND NOT EXISTS (
              SELECT 1 FROM pg_depend d
               WHERE d.classid = 'pg_class'::regclass
                 AND d.objid = c.oid
                 AND (d.deptype = 'e' OR (
                   d.deptype IN ('a', 'i')
                   AND d.refclassid IN ('pg_class'::regclass, 'pg_constraint'::regclass))))
         UNION ALL
         SELECT 2, p.proname::text,
                'function "' || $1 || '".' || p.proname || '(' ||
                  pg_get_function_identity_arguments(p.oid) || ')'
           FROM pg_proc p
          WHERE p.pronamespace = (SELECT oid FROM target)
            AND NOT EXISTS (
              SELECT 1 FROM pg_depend d
               WHERE d.classid = 'pg_proc'::regclass
                 AND d.objid = p.oid
                 AND d.deptype = 'e')
         UNION ALL
         SELECT 3, t.typname::text,
                CASE t.typtype
                  WHEN 'e' THEN 'enum type'
                  WHEN 'd' THEN 'domain'
                  WHEN 'r' THEN 'range type'
                  ELSE 'type'
                END || ' "' || $1 || '"."' || t.typname || '"'
           FROM pg_type t
          WHERE t.typnamespace = (SELECT oid FROM target)
            -- Composite types are pg_class rows (relkind 'c' or a relation's
            -- row type) and are covered above.
            AND t.typrelid = 0
            AND NOT EXISTS (
              SELECT 1 FROM pg_depend d
               WHERE d.classid = 'pg_type'::regclass
                 AND d.objid = t.oid
                 AND d.deptype IN ('e', 'i'))
       ) o
      ORDER BY o.ord, o.sort_key, o.description
      LIMIT 1`,
    [schema],
  );
  return result.rows[0]?.description ?? null;
}

/**
 * Cutover safety, checked before the ledger is created or any migration runs.
 *
 * `fresh` is not a bypass: it asserts the configured schema is empty and
 * refuses otherwise, naming the first pre-existing object (the ledger, then
 * selfhost_* tables, then any other relation, function or user-defined type
 * not owned by an installed extension).
 *
 * A non-public target may not coexist with relaycontrol tables in any other
 * schema, fresh or not: migration 0011 looks its constraint up by table name
 * without a schema filter, so a legacy copy elsewhere can break it. A ledger
 * elsewhere with an empty target is an existing install mid-move and gets its
 * own message.
 */
async function assertCutover(
  transaction: SqlExecutor,
  schema: string,
  cutover: MigrateOptions["cutover"],
): Promise<void> {
  const inTarget = await transaction.query<{ relname: string }>(
    `SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1
        AND c.relkind IN ('r', 'p')
        AND c.relname LIKE 'selfhost\\_%' ESCAPE '\\'
      ORDER BY c.relname = '${MIGRATIONS_TABLE}' DESC, c.relname`,
    [schema],
  );
  const targetTables = inTarget.rows.map((row) => row.relname);
  if (cutover === "fresh") {
    const offender = targetTables[0] ?? await firstObjectIn(transaction, schema);
    if (offender) {
      throw new Error(
        `SELFHOST_DATABASE_SCHEMA_CUTOVER=fresh requires an empty target, but schema ` +
          `"${schema}" already holds ${offender}. fresh is only for a brand-new schema and ` +
          "never migrates data; unset SELFHOST_DATABASE_SCHEMA_CUTOVER once the fresh install has run",
      );
    }
  }
  if (schema === DEFAULT_DATABASE_SCHEMA) return;

  const elsewhere = await transaction.query<{ nspname: string; relname: string }>(
    `SELECT n.nspname, c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname <> $1
        AND c.relkind IN ('r', 'p')
        AND c.relname LIKE 'selfhost\\_%' ESCAPE '\\'
      ORDER BY c.relname = '${MIGRATIONS_TABLE}' DESC, n.nspname, c.relname`,
    [schema],
  );
  if (elsewhere.rows.length === 0) return;
  const ledgerSchemas = [...new Set(elsewhere.rows
    .filter((row) => row.relname === MIGRATIONS_TABLE)
    .map((row) => row.nspname))];
  if (ledgerSchemas.length > 0 && !targetTables.includes(MIGRATIONS_TABLE) && cutover !== "fresh") {
    throw new Error(
      `Schema "${schema}" has no ${MIGRATIONS_TABLE} yet, but schema ` +
        `${ledgerSchemas.map((name) => `"${name}"`).join(", ")} holds an existing relaycontrol ` +
        "ledger. Move that install into the configured schema first (README: Moving an existing " +
        "install into a schema). SELFHOST_DATABASE_SCHEMA_CUTOVER=fresh does not unlock " +
        "coexistence with relaycontrol tables in another schema",
    );
  }
  const first = elsewhere.rows[0]!;
  throw new Error(
    `Relaycontrol tables in more than one schema are unsupported: schema "${first.nspname}" ` +
      `holds ${first.relname} while migrating into schema "${schema}". Move every selfhost_* ` +
      `relation and the ledger into "${schema}" (or drop the legacy copies) before migrating, ` +
      "fresh or not. The migrator moves no data and claims no cutover success",
  );
}

/** Applies pending migrations into `database.schema`. */
export async function migrate(
  database: Database,
  directory = defaultMigrationsDirectory(),
  options: MigrateOptions = {},
): Promise<string[]> {
  const schema = database.schema;
  const ledger = qualifiedName(schema, MIGRATIONS_TABLE);
  const files = (await readdir(directory))
    .filter((name) => /^\d+.*\.sql$/.test(name))
    .sort();
  const migrations = await Promise.all(files.map(async (name) => {
    const sql = await readFile(join(directory, name), "utf8");
    return {
      name,
      sql,
      checksum: createHash("sha256").update(sql).digest("hex"),
    };
  }));
  const applied: string[] = [];

  await database.transaction(async (transaction) => {
    await assertSchemaOwnership(transaction, schema);
    // Migration files are unqualified: they land wherever search_path points,
    // so refuse to run unless it resolves to the configured schema.
    await assertCurrentSchema(transaction, schema);
    // Serializes startup jobs without requiring an extension or an external lock.
    await transaction.query("SELECT pg_advisory_xact_lock(1947182641)");
    await assertCutover(transaction, schema, options.cutover);
    const elsewhereBefore = await selfhostTablesOutside(transaction, schema);
    await transaction.query(`
      CREATE TABLE IF NOT EXISTS ${ledger} (
        name text PRIMARY KEY,
        checksum text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    for (const migration of migrations) {
      const existing = await transaction.query<AppliedMigration>(
        `SELECT name, checksum FROM ${ledger} WHERE name = $1`,
        [migration.name],
      );
      if (existing.rows[0]) {
        if (existing.rows[0].checksum !== migration.checksum) {
          throw new Error(`Applied migration ${migration.name} has changed`);
        }
        continue;
      }

      await transaction.exec(migration.sql);
      await transaction.query(
        `INSERT INTO ${ledger} (name, checksum) VALUES ($1, $2)`,
        [migration.name, migration.checksum],
      );
      applied.push(migration.name);
    }

    await assertTablesInSchema(transaction, schema, ledger, elsewhereBefore);
  });

  return applied;
}

/**
 * Proves the migrations landed in the configured schema: the ledger is there,
 * CORE_TABLES are there once the ledger records CORE_MIGRATION, and no
 * selfhost_* table appeared in any other schema during this run.
 */
async function assertTablesInSchema(
  transaction: SqlExecutor,
  schema: string,
  ledger: string,
  elsewhereBefore: Set<string>,
): Promise<void> {
  const core = await transaction.query<{ present: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM ${ledger} WHERE name = $1) AS present`,
    [CORE_MIGRATION],
  );
  const expected: string[] = core.rows[0]?.present === true
    ? [MIGRATIONS_TABLE, ...CORE_TABLES]
    : [MIGRATIONS_TABLE];
  const present = await transaction.query<{ relname: string }>(
    `SELECT c.relname
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1
        AND c.relkind IN ('r', 'p')
        AND c.relname = ANY($2::text[])`,
    [schema, expected],
  );
  const found = new Set(present.rows.map((row) => row.relname));
  const missing = expected.filter((name) => !found.has(name));
  if (missing.length > 0) {
    throw new Error(
      `Migrations did not create ${missing.join(", ")} in schema "${schema}"`,
    );
  }
  const strays = [...await selfhostTablesOutside(transaction, schema)]
    .filter((name) => !elsewhereBefore.has(name));
  if (strays.length > 0) {
    throw new Error(
      `Migrations created tables outside schema "${schema}": ${strays.sort().join(", ")}`,
    );
  }
}
