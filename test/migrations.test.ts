import assert from "node:assert/strict";
import test from "node:test";
import type { Database, SqlExecutor, SqlResult } from "../src/database.js";
import { grantRuntimeDatabaseRole } from "../src/migrations.js";

type Fake = {
  currentUser?: string;
  schema?: string;
  isMember?: boolean;
  canCreateDatabase?: boolean;
  canCreateSchema?: boolean;
  canMigrate?: boolean;
  foreignSchemas?: string[];
  foreignRelation?: { nspname: string; relname: string; kind: string };
  foreignFunction?: { nspname: string; signature: string; grantee: string };
  /** Allowed-schema qualification rows; by default every listed schema qualifies. */
  allowedSchemaRows?: Array<{
    schema_name: string;
    present: boolean;
    extension_namespace: boolean;
    offender: string | null;
  }>;
  /** A pg_roles attribute the runtime role carries. */
  roleAttribute?: "rolsuper" | "rolcreaterole" | "rolcreatedb" | "rolbypassrls" | "rolreplication";
};

/** Records statements and answers the guard's catalog queries from fixed values. */
class RecordingDatabase implements Database {
  readonly statements: string[] = [];
  readonly params: unknown[][] = [];
  readonly schema: string;
  transactions = 0;

  constructor(readonly fake: Fake = {}) {
    this.schema = fake.schema ?? "public";
  }

  async query<T extends Record<string, unknown>>(
    sql: string,
    params: unknown[] = [],
  ): Promise<SqlResult<T>> {
    this.statements.push(sql);
    this.params.push(params);
    const rows = (value: unknown[]) => ({ rows: value as T[] });
    const f = this.fake;
    if (sql.includes("current_user AS current_user")) {
      return rows([{ current_user: f.currentUser ?? "selfhost_migrations" }]);
    }
    if (sql.includes("r.rolsuper")) {
      const attributes: Record<string, boolean> = {
        rolsuper: false,
        rolcreaterole: false,
        rolcreatedb: false,
        rolbypassrls: false,
        rolreplication: false,
      };
      if (f.roleAttribute) attributes[f.roleAttribute] = true;
      return rows([attributes]);
    }
    if (sql.includes("pg_has_role")) {
      return rows([{ is_member: f.isMember ?? false, can_create_database: f.canCreateDatabase ?? false }]);
    }
    if (sql.includes("unnest($1::text[])")) {
      return rows(f.allowedSchemaRows ?? (params[0] as string[]).map((schema_name) => ({
        schema_name,
        present: true,
        extension_namespace: true,
        offender: null,
      })));
    }
    if (sql.includes("FROM pg_namespace n")) {
      return rows((f.foreignSchemas ?? []).map((nspname) => ({ nspname })));
    }
    if (sql.includes("FROM pg_class c")) return rows(f.foreignRelation ? [f.foreignRelation] : []);
    if (sql.includes("FROM pg_proc p")) return rows(f.foreignFunction ? [f.foreignFunction] : []);
    if (sql.includes("has_schema_privilege")) return rows([{ can_create: f.canCreateSchema ?? false }]);
    if (sql.includes("has_table_privilege")) return rows([{ can_migrate: f.canMigrate ?? false }]);
    if (sql.includes("FROM pg_tables")) {
      return rows([{ tablename: "selfhost_users" }, { tablename: "selfhost_token_sessions" }]);
    }
    if (sql.includes("FROM pg_sequences")) return rows([{ sequencename: "selfhost_example_seq" }]);
    return { rows: [] };
  }

  async exec(sql: string): Promise<void> {
    this.statements.push(sql);
    this.params.push([]);
  }

  async transaction<T>(run: (transaction: SqlExecutor) => Promise<T>): Promise<T> {
    this.transactions += 1;
    return run(this);
  }

  async close(): Promise<void> {}

  get writes(): string[] {
    return this.statements.filter((sql) => /^(?:GRANT|REVOKE|ALTER)/.test(sql));
  }
}

test("runtime role grants exclude migration metadata and schema creation", async () => {
  const database = new RecordingDatabase();
  await grantRuntimeDatabaseRole(database, "selfhost_runtime");

  assert.equal(database.transactions, 1);
  const has = (expected: string) =>
    assert(database.statements.includes(expected), `missing statement: ${expected}`);
  has('GRANT USAGE ON SCHEMA "public" TO "selfhost_runtime"');
  has('REVOKE ALL PRIVILEGES ON TABLE "public"."selfhost_schema_migrations" FROM "selfhost_runtime"');
  has('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "public"."selfhost_users" TO "selfhost_runtime"');
  has('GRANT USAGE, SELECT, UPDATE ON SEQUENCE "public"."selfhost_example_seq" TO "selfhost_runtime"');
  assert(!database.statements.some((sql) => /GRANT CREATE/i.test(sql)));
  assert(!database.statements.some((sql) => /GRANT .*selfhost_schema_migrations/i.test(sql)));
  assert(!database.statements.some((sql) => /ALTER DEFAULT PRIVILEGES/i.test(sql)));
});

test("migration owner cannot also be the runtime role", async () => {
  const database = new RecordingDatabase({ currentUser: "selfhost_runtime" });
  await assert.rejects(grantRuntimeDatabaseRole(database, "selfhost_runtime"), /must be distinct/);
  assert.deepEqual(database.writes, []);
});

test("each isolation check fails with its own message before any grant", async () => {
  const cases: Array<[Fake, RegExp]> = [
    [{ roleAttribute: "rolsuper" }, /^Error: Runtime database role "selfhost_runtime" must not have SUPERUSER$/],
    [{ roleAttribute: "rolcreaterole" }, /"selfhost_runtime" must not have CREATEROLE$/],
    [{ roleAttribute: "rolcreatedb" }, /"selfhost_runtime" must not have CREATEDB$/],
    [{ roleAttribute: "rolbypassrls" }, /"selfhost_runtime" must not have BYPASSRLS$/],
    [{ roleAttribute: "rolreplication" }, /"selfhost_runtime" must not have REPLICATION$/],
    [{ isMember: true }, /"selfhost_runtime" must not be a member of the migration role/],
    [{ canCreateDatabase: true }, /"selfhost_runtime" must not have CREATE on the database/],
    [{ canCreateSchema: true }, /schema CREATE privilege on schema "relaycontrol"/],
    [{ foreignSchemas: ["public", "billing"] }, /must not have USAGE on schema "public", "billing"/],
    [
      { foreignRelation: { nspname: "billing", relname: "invoices", kind: "table" } },
      /must not hold privileges on table "billing"."invoices" outside schema "relaycontrol"/,
    ],
    [
      {
        foreignSchemas: ["billing"],
        foreignFunction: { nspname: "billing", signature: "charge(integer)", grantee: "PUBLIC" },
      },
      /has effective access to function "billing".charge\(integer\) outside schema "relaycontrol": it has USAGE on schema "billing" and EXECUTE on the function/,
    ],
    [
      { foreignFunction: { nspname: "billing", signature: "charge(integer)", grantee: "billing_reader" } },
      /has explicit grant drift: EXECUTE on function "billing".charge\(integer\) outside schema "relaycontrol" is granted to role "billing_reader"/,
    ],
  ];
  for (const [fake, message] of cases) {
    const database = new RecordingDatabase({ schema: "relaycontrol", ...fake });
    await assert.rejects(grantRuntimeDatabaseRole(database, "selfhost_runtime"), message);
    assert.deepEqual(database.writes, [], String(message));
  }
  const substituted = new RecordingDatabase({
    schema: "relaycontrol",
    allowedSchemaRows: [{
      schema_name: "relaycast",
      present: true,
      extension_namespace: false,
      offender: 'table "relaycast"."messages"',
    }],
  });
  await assert.rejects(
    grantRuntimeDatabaseRole(substituted, "selfhost_runtime", { allowedSchemas: ["relaycast"] }),
    /entry "relaycast" is not an installed extension's namespace: no installed extension is in schema "relaycast" and table "relaycast"."messages"/,
  );
  assert.deepEqual(substituted.writes, []);
  // An existing schema with no installed extension is refused even when empty.
  const empty = new RecordingDatabase({
    schema: "relaycontrol",
    allowedSchemaRows: [{ schema_name: "relaycast", present: true, extension_namespace: false, offender: null }],
  });
  await assert.rejects(
    grantRuntimeDatabaseRole(empty, "selfhost_runtime", { allowedSchemas: ["relaycast"] }),
    /^Error: SELFHOST_DATABASE_ALLOWED_SCHEMAS entry "relaycast" is not an installed extension's namespace: no installed extension is in schema "relaycast"\. List only/,
  );
  assert.deepEqual(empty.writes, []);
  await assert.rejects(
    grantRuntimeDatabaseRole(new RecordingDatabase({ canMigrate: true }), "selfhost_runtime"),
    /inherit migration table privileges/,
  );
});

test("runtime role identifiers are rejected before database access", async () => {
  const database = new RecordingDatabase();
  for (const role of ["PUBLIC", "runtime-role", 'runtime"; DROP ROLE owner; --']) {
    await assert.rejects(
      grantRuntimeDatabaseRole(database, role),
      /Invalid runtime PostgreSQL role name/,
    );
  }
  assert.equal(database.transactions, 0);
});

test("runtime role grants target database.schema with bound catalog parameters", async () => {
  const database = new RecordingDatabase({ schema: "relaycontrol" });
  await grantRuntimeDatabaseRole(database, "selfhost_runtime", { allowedSchemas: ["extensions"] });

  const has = (expected: string) =>
    assert(database.statements.includes(expected), `missing statement: ${expected}`);
  has('GRANT USAGE ON SCHEMA "relaycontrol" TO "selfhost_runtime"');
  has('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "relaycontrol"."selfhost_users" TO "selfhost_runtime"');
  has('GRANT USAGE, SELECT, UPDATE ON SEQUENCE "relaycontrol"."selfhost_example_seq" TO "selfhost_runtime"');
  has('REVOKE ALL PRIVILEGES ON TABLE "relaycontrol"."selfhost_schema_migrations" FROM "selfhost_runtime"');
  assert(!database.writes.some((sql) => /\bpublic\b/i.test(sql)), "no write names public");
  assert(!database.writes.some((sql) => /extensions/.test(sql)), "allowed schemas are never granted");

  const paramsFor = (fragment: string) =>
    database.params[database.statements.findIndex((sql) => sql.includes(fragment))];
  assert.deepEqual(paramsFor("pg_has_role"), ["selfhost_runtime"]);
  assert.deepEqual(paramsFor("has_schema_privilege($1, $2, 'CREATE')"), ["selfhost_runtime", "relaycontrol"]);
  const exempt = ["selfhost_runtime", ["relaycontrol", "extensions"]];
  assert.deepEqual(paramsFor("FROM pg_namespace n"), exempt);
  assert.deepEqual(paramsFor("FROM pg_class c"), exempt);
  assert.deepEqual(paramsFor("FROM pg_proc p"), exempt);
  assert.deepEqual(paramsFor("FROM pg_tables"), ["relaycontrol"]);
  assert.deepEqual(paramsFor("FROM pg_sequences"), ["relaycontrol"]);
  assert.deepEqual(paramsFor("has_table_privilege($1, $2"), [
    "selfhost_runtime",
    '"relaycontrol"."selfhost_schema_migrations"',
  ]);

  // The ledger revoke and its check are the last steps.
  const revoke = database.statements.findIndex((sql) => sql.startsWith("REVOKE"));
  const lastGrant = Math.max(
    ...database.statements.map((sql, index) => sql.startsWith("GRANT") ? index : -1),
  );
  assert(revoke > lastGrant);
});
