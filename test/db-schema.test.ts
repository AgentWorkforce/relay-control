// PGlite runs one session and has no separate LOGIN connections, so these
// tests switch identities with SET ROLE: the migration owner (control_owner)
// runs migrate and the grant, and the runtime role (control_api_runtime) is
// probed directly. Role names follow the managed profile. SET ROLE in one
// session proves the grant logic only. The server's login binding
// (assertRuntimeLogin) is exercised with SET SESSION AUTHORIZATION, which
// changes session_user; TLS and restart proofs against the target Postgres
// are still required before managed-profile acceptance.
import assert from "node:assert/strict";
import test from "node:test";
import { copyFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { citext } from "@electric-sql/pglite/contrib/citext";
import { assertCurrentSchema, assertRuntimeLogin } from "../src/database.js";
import {
  CORE_MIGRATION,
  CORE_TABLES,
  defaultMigrationsDirectory,
  grantRuntimeDatabaseRole,
  migrate,
} from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { TelemetryStore } from "../src/telemetry/store.js";
import { PGliteDatabase } from "./support/harness.js";

const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const SCHEMA = "relaycontrol";
const OWNER = "control_owner";
const RUNTIME = "control_api_runtime";
const DIR = defaultMigrationsDirectory();

/** A Database over `client` pinned to `schema`, as PostgresDatabase pins every connection. */
async function pinned(client: PGlite, schema = SCHEMA): Promise<PGliteDatabase> {
  const database = new PGliteDatabase(client, schema);
  await database.pinSearchPath();
  return database;
}

/**
 * The infra bootstrap: the schema owned by the migration role, both roles
 * NOLOGIN, PUBLIC's USAGE on public revoked. The session ends as the owner.
 */
async function bootstrap(client = new PGlite()): Promise<PGliteDatabase> {
  await client.exec(`
    CREATE ROLE ${OWNER} NOLOGIN;
    CREATE ROLE ${RUNTIME} NOLOGIN;
    CREATE SCHEMA ${SCHEMA} AUTHORIZATION ${OWNER};
    REVOKE USAGE ON SCHEMA public FROM PUBLIC;
    SET ROLE ${OWNER};
  `);
  return pinned(client);
}

/** Runs `sql` as the superuser standing in for the infra bootstrap, then returns to the owner. */
async function asBootstrap(database: PGliteDatabase, sql: string): Promise<void> {
  await database.exec(`RESET ROLE; ${sql}; SET ROLE ${OWNER}`);
}

async function tablesIn(database: PGliteDatabase, schema: string): Promise<string[]> {
  const result = await database.query<{ relname: string }>(
    `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1 AND c.relkind = 'r' AND c.relname LIKE 'selfhost\\_%' ESCAPE '\\'
      ORDER BY c.relname`,
    [schema],
  );
  return result.rows.map((row) => row.relname);
}

test("migrate lands every table and the ledger in the configured schema", async () => {
  const database = await bootstrap();
  try {
    const applied = await migrate(database, DIR);
    assert(applied.length > 0);

    const tables = await tablesIn(database, SCHEMA);
    for (const name of ["selfhost_schema_migrations", ...CORE_TABLES]) assert(tables.includes(name), name);
    assert.deepEqual(await tablesIn(database, "public"), []);
    const ledger = await database.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM ${SCHEMA}.selfhost_schema_migrations`,
    );
    assert.equal(Number(ledger.rows[0]?.count), applied.length);

    assert.equal(await new ControlPlaneStore(database, KEYRING, 0).ready(), true);
    assert.equal(await new TelemetryStore(database).tableExists("selfhost_workspaces"), true);
  } finally {
    await database.close();
  }
});

test("migrate refuses a missing schema or one owned by another role", async () => {
  const client = new PGlite();
  await client.exec(`CREATE ROLE ${OWNER} NOLOGIN; CREATE ROLE someone_else NOLOGIN`);
  const missing = await pinned(client, "missing_schema");
  await assert.rejects(
    migrate(missing, DIR),
    /Database schema "missing_schema" \(SELFHOST_DATABASE_SCHEMA\) does not exist/,
  );

  await client.exec(`CREATE SCHEMA ${SCHEMA} AUTHORIZATION someone_else; GRANT USAGE, CREATE ON SCHEMA ${SCHEMA} TO ${OWNER}; SET ROLE ${OWNER}`);
  const misowned = await pinned(client);
  await assert.rejects(
    migrate(misowned, DIR),
    /schema "relaycontrol" is owned by "someone_else", not by the migration role "control_owner"/,
  );
  assert.deepEqual(await tablesIn(misowned, SCHEMA), []);
  await client.close();
});

test("migrate refuses when search_path does not resolve to the schema", async () => {
  const database = await bootstrap();
  try {
    await asBootstrap(database, `CREATE SCHEMA other_service; GRANT USAGE, CREATE ON SCHEMA other_service TO ${OWNER}`);
    await database.exec("SET search_path TO other_service");
    await assert.rejects(migrate(database, DIR), /current_schema\(\) is "other_service", expected "relaycontrol"/);
    // With PUBLIC's USAGE on public revoked, a public search_path resolves to nothing.
    await database.exec("SET search_path TO public");
    await assert.rejects(migrate(database, DIR), /current_schema\(\) is null, expected "relaycontrol"/);
    assert.deepEqual(await tablesIn(database, SCHEMA), []);
    assert.deepEqual(await tablesIn(database, "other_service"), []);
  } finally {
    await database.close();
  }
});

test("runtime role guard rejects every escape from the schema", async () => {
  // citext stands in for a reviewed extension installed into a namespace.
  const database = await bootstrap(new PGlite({ extensions: { citext } }));
  const grant = (allowedSchemas: string[] = []) =>
    grantRuntimeDatabaseRole(database, RUNTIME, { allowedSchemas });
  try {
    await migrate(database, DIR);

    await asBootstrap(database, `GRANT ${OWNER} TO ${RUNTIME}`);
    await assert.rejects(grant(), /"control_api_runtime" must not be a member of the migration role/);
    await asBootstrap(database, `REVOKE ${OWNER} FROM ${RUNTIME}`);

    for (const attribute of ["SUPERUSER", "CREATEROLE", "CREATEDB", "BYPASSRLS", "REPLICATION"]) {
      await asBootstrap(database, `ALTER ROLE ${RUNTIME} ${attribute}`);
      await assert.rejects(
        grant(),
        new RegExp(`^Error: Runtime database role "control_api_runtime" must not have ${attribute}$`),
      );
      await asBootstrap(database, `ALTER ROLE ${RUNTIME} NO${attribute}`);
    }

    // PGlite cannot GRANT on its current database (template1), so database
    // ownership, which carries CREATE, stands in for the grant.
    const dbName = (await database.query<{ name: string }>("SELECT current_database() AS name")).rows[0]!.name;
    await asBootstrap(database, `ALTER DATABASE "${dbName}" OWNER TO ${RUNTIME}`);
    await assert.rejects(grant(), /"control_api_runtime" must not have CREATE on the database/);
    await asBootstrap(database, `ALTER DATABASE "${dbName}" OWNER TO postgres`);

    await database.exec(`GRANT CREATE ON SCHEMA ${SCHEMA} TO ${RUNTIME}`);
    await assert.rejects(grant(), /schema CREATE privilege on schema "relaycontrol"/);
    await database.exec(`REVOKE CREATE ON SCHEMA ${SCHEMA} FROM ${RUNTIME}`);

    // (i) USAGE inherited through PUBLIC fails.
    await asBootstrap(database, "GRANT USAGE ON SCHEMA public TO PUBLIC");
    await assert.rejects(grant(), /must not have USAGE on schema "public"; it may only use schema "relaycontrol"/);
    await asBootstrap(database, "REVOKE USAGE ON SCHEMA public FROM PUBLIC");

    // Another service's schema: object grants without USAGE are still refused.
    await asBootstrap(database, `
      CREATE SCHEMA other_service;
      GRANT USAGE ON SCHEMA other_service TO ${RUNTIME}`);
    await assert.rejects(grant(), /must not have USAGE on schema "other_service"/);
    await asBootstrap(database, `
      REVOKE USAGE ON SCHEMA other_service FROM ${RUNTIME};
      CREATE TABLE other_service.invoices (id int);
      GRANT SELECT ON other_service.invoices TO ${RUNTIME}`);
    await assert.rejects(
      grant(),
      /must not hold privileges on table "other_service"."invoices" outside schema "relaycontrol"/,
    );
    await asBootstrap(database, `
      REVOKE SELECT ON other_service.invoices FROM ${RUNTIME};
      CREATE SEQUENCE other_service.invoice_seq;
      GRANT USAGE ON SEQUENCE other_service.invoice_seq TO ${RUNTIME}`);
    await assert.rejects(grant(), /must not hold privileges on sequence "other_service"."invoice_seq"/);
    await asBootstrap(database, `REVOKE USAGE ON SEQUENCE other_service.invoice_seq FROM ${RUNTIME}`);
    const runtimeUsage = async () => (await database.query<{ ok: boolean }>(
      "SELECT has_schema_privilege($1, $2, 'USAGE') AS ok",
      [RUNTIME, SCHEMA],
    )).rows[0]?.ok;

    // Allowed schemas must be extension namespaces: listing another service's
    // schema is refused before anything is granted, as is a missing schema.
    await assert.rejects(
      grant(["other_service"]),
      /^Error: SELFHOST_DATABASE_ALLOWED_SCHEMAS entry "other_service" is not an installed extension's namespace: no installed extension is in schema "other_service" and table "other_service"."invoices" is not owned by an installed extension\. List only extension namespaces, never another service's schema$/,
    );
    // Service-schema substitution: a schema named like a sibling service.
    await asBootstrap(database, `
      CREATE SCHEMA sessions;
      GRANT USAGE ON SCHEMA sessions TO PUBLIC;
      CREATE TABLE sessions.session_rows (id int)`);
    await assert.rejects(
      grant(["sessions"]),
      /^Error: SELFHOST_DATABASE_ALLOWED_SCHEMAS entry "sessions" is not an installed extension's namespace: no installed extension is in schema "sessions" and table "sessions"."session_rows" is not owned by an installed extension/,
    );
    // An existing but empty service schema is refused too: the exemption
    // requires an actual installed extension.
    await asBootstrap(database, "DROP TABLE sessions.session_rows");
    await assert.rejects(
      grant(["sessions"]),
      /^Error: SELFHOST_DATABASE_ALLOWED_SCHEMAS entry "sessions" is not an installed extension's namespace: no installed extension is in schema "sessions"\. List only extension namespaces, never another service's schema$/,
    );
    await asBootstrap(database, "DROP SCHEMA sessions CASCADE");
    await assert.rejects(
      grant(["no_such_schema"]),
      /SELFHOST_DATABASE_ALLOWED_SCHEMAS entry "no_such_schema" does not exist/,
    );
    assert.equal(await runtimeUsage(), false);

    // Functions. (iv) Explicit EXECUTE grants on a function in a schema the
    // runtime role cannot USE are grant drift, whether granted to the role
    // itself or to a non-PUBLIC role it belongs to (walked transitively).
    await asBootstrap(database,
      "CREATE FUNCTION other_service.charge(amount integer) RETURNS integer LANGUAGE sql AS 'SELECT amount'");
    const noAclAdvice = (error: unknown) => {
      assert.doesNotMatch(String(error), /PUBLIC|revoke/i);
      return true;
    };
    await asBootstrap(database, `GRANT EXECUTE ON FUNCTION other_service.charge(integer) TO ${RUNTIME}`);
    await assert.rejects(
      grant(),
      /^Error: Runtime database role "control_api_runtime" has explicit grant drift: EXECUTE on function "other_service".charge\(amount integer\) outside schema "relaycontrol" is granted to role "control_api_runtime" \(the runtime role or a role it is a member of\); schema "other_service" is not usable by the runtime role$/,
    );
    await assert.rejects(grant(), noAclAdvice);
    await asBootstrap(database, `
      REVOKE EXECUTE ON FUNCTION other_service.charge(integer) FROM ${RUNTIME};
      CREATE ROLE billing_team NOLOGIN;
      CREATE ROLE billing_reader NOLOGIN;
      GRANT billing_team TO ${RUNTIME};
      GRANT billing_reader TO billing_team;
      GRANT EXECUTE ON FUNCTION other_service.charge(integer) TO billing_reader`);
    await assert.rejects(
      grant(),
      /has explicit grant drift: EXECUTE on function "other_service".charge\(amount integer\) outside schema "relaycontrol" is granted to role "billing_reader"/,
    );
    await assert.rejects(grant(), noAclAdvice);
    assert.equal(await runtimeUsage(), false);
    await asBootstrap(database, `
      REVOKE EXECUTE ON FUNCTION other_service.charge(integer) FROM billing_reader;
      REVOKE billing_team FROM ${RUNTIME}`);

    // (iii) An accessible foreign function (USAGE on its schema plus EXECUTE,
    // here PUBLIC's default) is effective access, reported distinctly.
    await asBootstrap(database, `GRANT USAGE ON SCHEMA other_service TO ${RUNTIME}`);
    await assert.rejects(
      grant(),
      /^Error: Runtime database role "control_api_runtime" has effective access to function "other_service".charge\(amount integer\) outside schema "relaycontrol": it has USAGE on schema "other_service" and EXECUTE on the function$/,
    );
    await assert.rejects(grant(), noAclAdvice);
    await asBootstrap(database, `REVOKE USAGE ON SCHEMA other_service FROM ${RUNTIME}`);

    // (ii) PUBLIC's default EXECUTE on a function in a schema the runtime role
    // cannot USE is not effective access and passes; it is never revoked.
    const publicExecute = await database.query<{ ok: boolean }>(
      "SELECT has_function_privilege('public', p.oid, 'EXECUTE') AS ok FROM pg_proc p WHERE p.proname = 'charge'",
    );
    assert.equal(publicExecute.rows[0]?.ok, true);
    await grant();
    assert.equal(await runtimeUsage(), true);

    // A reviewed extension namespace is exempt only when listed, and only
    // while it holds nothing but extension objects.
    await asBootstrap(database, `
      CREATE SCHEMA extensions;
      GRANT USAGE ON SCHEMA extensions TO PUBLIC;
      CREATE FUNCTION extensions.gen_id() RETURNS integer LANGUAGE sql AS 'SELECT 1'`);
    await assert.rejects(
      grant(),
      /has effective access to function "extensions".gen_id\(\) outside schema "relaycontrol": it has USAGE on schema "extensions"/,
    );
    await assert.rejects(
      grant(["extensions"]),
      /^Error: SELFHOST_DATABASE_ALLOWED_SCHEMAS entry "extensions" is not an installed extension's namespace: no installed extension is in schema "extensions" and function "extensions".gen_id\(\) is not owned by an installed extension/,
    );
    await asBootstrap(database, "DROP FUNCTION extensions.gen_id()");
    // An existing but empty schema is not an extension namespace: the
    // exemption is never vacuous.
    await assert.rejects(
      grant(["extensions"]),
      /^Error: SELFHOST_DATABASE_ALLOWED_SCHEMAS entry "extensions" is not an installed extension's namespace: no installed extension is in schema "extensions"\. List only extension namespaces, never another service's schema$/,
    );
    await asBootstrap(database, "CREATE EXTENSION citext SCHEMA extensions");
    const extensionFunctions = await database.query<{ count: number }>(
      `SELECT count(*)::int AS count FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'extensions'`,
    );
    assert(extensionFunctions.rows[0]!.count > 0);
    await grant(["extensions"]);
    await grant(["extensions"]); // idempotent
    // An installed extension's namespace still refuses a non-extension object.
    await asBootstrap(database,
      "CREATE FUNCTION extensions.gen_id() RETURNS integer LANGUAGE sql AS 'SELECT 1'");
    await assert.rejects(
      grant(["extensions"]),
      /^Error: SELFHOST_DATABASE_ALLOWED_SCHEMAS entry "extensions" is not an extension namespace: function "extensions".gen_id\(\) is not owned by an installed extension\. List only extension namespaces, never another service's schema$/,
    );
    await asBootstrap(database, "DROP FUNCTION extensions.gen_id()");

    const privileges = await database.query<Record<string, boolean>>(
      `SELECT
         has_schema_privilege($1, $2, 'USAGE') AS usage,
         has_schema_privilege($1, $2, 'CREATE') AS can_create,
         has_table_privilege($1, $3, 'SELECT') AS ledger_select,
         has_table_privilege($1, $4, 'INSERT') AS workspaces_insert`,
      [RUNTIME, SCHEMA, `${SCHEMA}.selfhost_schema_migrations`, `${SCHEMA}.selfhost_workspaces`],
    );
    assert.deepEqual(privileges.rows[0], {
      usage: true,
      can_create: false,
      ledger_select: false,
      workspaces_insert: true,
    });

    // No default privileges: a later table is reachable only after the grant pass reruns.
    await database.exec("CREATE TABLE selfhost_later_migration (id int)");
    const later = () => database.query<{ ok: boolean }>(
      "SELECT has_table_privilege($1, $2, 'SELECT') AS ok",
      [RUNTIME, `${SCHEMA}.selfhost_later_migration`],
    );
    assert.equal((await later()).rows[0]?.ok, false);
    await grant(["extensions"]);
    assert.equal((await later()).rows[0]?.ok, true);

    await database.exec(`SET ROLE ${RUNTIME}`);
    await database.query("SELECT count(*) FROM selfhost_workspaces");
    await assert.rejects(database.query("SELECT count(*) FROM selfhost_schema_migrations"), /permission denied/);
    await assert.rejects(database.query("SELECT count(*) FROM other_service.invoices"), /permission denied/);
    await assert.rejects(database.exec("CREATE TABLE selfhost_sneaky (id int)"), /permission denied/);
    await database.exec(`SET ROLE ${OWNER}`);
  } finally {
    await database.close();
  }
});

test("the API server binds its login to the runtime role and refuses owner/admin logins", async () => {
  // SET SESSION AUTHORIZATION changes session_user in PGlite (the test session
  // is a superuser); RESET SESSION AUTHORIZATION does not restore it there, so
  // the helpers switch back explicitly to postgres.
  const database = await bootstrap();
  const login = (identity: string, then = "") =>
    database.exec(`RESET ROLE; SET SESSION AUTHORIZATION ${identity}; ${then}`);
  const back = () => database.exec(`RESET ROLE; SET SESSION AUTHORIZATION postgres; SET ROLE ${OWNER}`);
  const check = (expected = RUNTIME) => assertRuntimeLogin(database, SCHEMA, expected);
  const refusal = (role: string, property: string, expected = RUNTIME) =>
    new RegExp(
      `^Error: Database login role "${role}" ${property} \\(SELFHOST_RUNTIME_DATABASE_ROLE "${expected}"\\); ` +
        "the API server must connect as the runtime role$",
    );
  try {
    await migrate(database, DIR);
    await grantRuntimeDatabaseRole(database, RUNTIME);

    // Accept: the runtime role logged in as itself.
    await login(RUNTIME);
    await check();
    await database.query("SELECT count(*) FROM selfhost_workspaces");
    // A different expected role name is refused.
    await assert.rejects(
      check("control_api_other"),
      refusal(RUNTIME, 'is not the expected runtime role "control_api_other"', "control_api_other"),
    );
    await back();

    // The schema owner's URL: wrong login, and refused even if named as expected.
    await login(OWNER);
    await assert.rejects(check(), refusal(OWNER, `is not the expected runtime role "${RUNTIME}"`));
    await assert.rejects(check(OWNER), refusal(OWNER, 'must not own schema "relaycontrol"', OWNER));
    await back();

    // The superuser's URL.
    await login("postgres");
    await assert.rejects(check(), refusal("postgres", `is not the expected runtime role "${RUNTIME}"`));
    await assert.rejects(check("postgres"), refusal("postgres", "must not have SUPERUSER", "postgres"));
    await back();

    // A role switched after login (e.g. options=-c role=...): current_user differs.
    await asBootstrap(database, `CREATE ROLE api_helper NOLOGIN; GRANT api_helper TO ${RUNTIME}`);
    await login(RUNTIME, "SET ROLE api_helper");
    await assert.rejects(
      check(),
      refusal(RUNTIME, 'has current_user "api_helper"; the connection must not switch roles'),
    );
    await back();
    await asBootstrap(database, `REVOKE api_helper FROM ${RUNTIME}`);

    // Role attributes.
    for (const attribute of ["SUPERUSER", "CREATEROLE", "CREATEDB", "BYPASSRLS", "REPLICATION"]) {
      await asBootstrap(database, `ALTER ROLE ${RUNTIME} ${attribute}`);
      await login(RUNTIME);
      await assert.rejects(check(), refusal(RUNTIME, `must not have ${attribute}`));
      await back();
      await asBootstrap(database, `ALTER ROLE ${RUNTIME} NO${attribute}`);
    }

    // Membership in the schema owner, walked transitively.
    await asBootstrap(database, `CREATE ROLE owner_group NOLOGIN; GRANT ${OWNER} TO owner_group; GRANT owner_group TO ${RUNTIME}`);
    await login(RUNTIME);
    await assert.rejects(
      check(),
      refusal(RUNTIME, 'must not be a member of role "control_owner", the owner of schema "relaycontrol"'),
    );
    await back();
    await asBootstrap(database, `REVOKE owner_group FROM ${RUNTIME}`);

    // CREATE on the schema.
    await asBootstrap(database, `GRANT CREATE ON SCHEMA ${SCHEMA} TO ${RUNTIME}`);
    await login(RUNTIME);
    await assert.rejects(check(), refusal(RUNTIME, 'must not have CREATE on schema "relaycontrol"'));
    await back();
    await asBootstrap(database, `REVOKE CREATE ON SCHEMA ${SCHEMA} FROM ${RUNTIME}`);

    // CREATE on the database. PGlite cannot GRANT on its current database
    // (template1), so database ownership, which carries CREATE, stands in.
    const dbName = (await database.query<{ name: string }>("SELECT current_database() AS name")).rows[0]!.name;
    await asBootstrap(database, `ALTER DATABASE "${dbName}" OWNER TO ${RUNTIME}`);
    await login(RUNTIME);
    await assert.rejects(check(), refusal(RUNTIME, "must not have CREATE on the database"));
    await back();
    await asBootstrap(database, `ALTER DATABASE "${dbName}" OWNER TO postgres`);

    // Every grant reverted: the runtime login is accepted again.
    await login(RUNTIME);
    await check();
    await back();
  } finally {
    await database.close();
  }
});

test("a hostile search_path cannot redirect qualified reads, and readiness reports it once", async (t) => {
  const database = await bootstrap();
  try {
    await migrate(database, DIR);
    await asBootstrap(database, `
      CREATE SCHEMA other_service;
      GRANT USAGE ON SCHEMA other_service TO ${OWNER};
      CREATE TABLE other_service.selfhost_workspaces (id int);
      CREATE TABLE other_service.selfhost_only_in_other (id int)`);
    const errors: string[] = [];
    t.mock.method(console, "error", (message: string) => { errors.push(message); });

    await database.exec("SET search_path TO other_service");
    const telemetry = new TelemetryStore(database);
    assert.equal(await telemetry.tableExists("selfhost_workspaces"), true);
    assert.equal(await telemetry.tableExists("selfhost_only_in_other"), false);

    const store = new ControlPlaneStore(database, KEYRING, 0);
    assert.equal(await store.ready(), false);
    assert.equal(await store.ready(), false);
    assert.equal(errors.length, 1);
    assert.match(errors[0]!, /current_schema\(\) is "other_service", expected "relaycontrol"/);
    await assert.rejects(
      assertCurrentSchema(database, database.schema),
      /current_schema\(\) is "other_service", expected "relaycontrol"/,
    );

    await database.pinSearchPath();
    assert.equal(await store.ready(), true);
  } finally {
    await database.close();
  }
});

test("a same-named table in another schema never satisfies the configured schema's checks", async () => {
  const database = await bootstrap();
  try {
    await migrate(database, DIR);
    await asBootstrap(database, "CREATE TABLE public.selfhost_workspaces (id int)");
    const store = new ControlPlaneStore(database, KEYRING, 0);
    assert.equal(await store.ready(), true);

    await database.exec(`DROP TABLE ${SCHEMA}.selfhost_workspaces CASCADE`);
    assert.equal(await store.ready(), false);
    // Coexistence across schemas is refused before any migration runs.
    await assert.rejects(
      migrate(database, DIR),
      /Relaycontrol tables in more than one schema are unsupported: schema "public" holds selfhost_workspaces/,
    );
    await asBootstrap(database, "DROP TABLE public.selfhost_workspaces");
    await assert.rejects(
      migrate(database, DIR),
      /Migrations did not create selfhost_workspaces in schema "relaycontrol"/,
    );
  } finally {
    await database.close();
  }
});

test("restart: migrate on a new Database instance applies nothing and the guard is idempotent", async () => {
  const first = await bootstrap();
  try {
    assert((await migrate(first, DIR)).length > 0);
    await grantRuntimeDatabaseRole(first, RUNTIME);

    const second = await pinned(first.client);
    assert.deepEqual(await migrate(second, DIR), []);
    await grantRuntimeDatabaseRole(second, RUNTIME);
    await grantRuntimeDatabaseRole(second, RUNTIME);
    assert.equal(await new ControlPlaneStore(second, KEYRING, 0).ready(), true);
  } finally {
    await first.close();
  }
});

/**
 * A legacy install migrated into public (optionally from a subset of the
 * migrations), then the new schema pre-created.
 */
async function legacyInstall(only?: string[]): Promise<PGlite> {
  const client = new PGlite();
  const legacy = await pinned(client, "public");
  let directory = DIR;
  if (only) {
    directory = await mkdtemp(join(tmpdir(), "rc-legacy-"));
    for (const name of only) await copyFile(join(DIR, name), join(directory, name));
  }
  assert((await migrate(legacy, directory)).length > 0);
  await client.exec(`
    CREATE ROLE ${OWNER} NOLOGIN;
    CREATE SCHEMA ${SCHEMA} AUTHORIZATION ${OWNER};
  `);
  return client;
}

/** Every relation and function in `schema`, for before/after comparisons. */
async function objectsIn(client: PGlite, schema: string): Promise<string[]> {
  const result = await client.query<{ name: string }>(
    `SELECT c.relkind::text || ':' || c.relname AS name
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1
     UNION ALL
     SELECT 'fn:' || p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = $1
     ORDER BY 1`,
    [schema],
  );
  return result.rows.map((row) => row.name);
}

test("cutover: legacy tables in another schema block a new target, fresh or not", async () => {
  const client = await legacyInstall([CORE_MIGRATION]);
  await client.exec(`SET ROLE ${OWNER}`);
  const database = await pinned(client);
  const before = await objectsIn(client, SCHEMA);
  await assert.rejects(
    migrate(database, DIR),
    /^Error: Schema "relaycontrol" has no selfhost_schema_migrations yet, but schema "public" holds an existing relaycontrol ledger\. Move that install into the configured schema first \(README: Moving an existing install into a schema\)\. SELFHOST_DATABASE_SCHEMA_CUTOVER=fresh does not unlock coexistence with relaycontrol tables in another schema$/,
  );
  // Migration 0011 looks its constraint up without a schema filter, so
  // coexistence is refused even under fresh, before any migration runs.
  await assert.rejects(
    migrate(database, DIR, { cutover: "fresh" }),
    /^Error: Relaycontrol tables in more than one schema are unsupported: schema "public" holds selfhost_schema_migrations while migrating into schema "relaycontrol"\. Move every selfhost_\* relation and the ledger into "relaycontrol" \(or drop the legacy copies\) before migrating, fresh or not\. The migrator moves no data and claims no cutover success$/,
  );
  assert.deepEqual(await objectsIn(client, SCHEMA), before);
  assert.deepEqual(await tablesIn(database, SCHEMA), []);
  await client.close();
});

test("cutover: fresh installs only into an empty target and refuses without side effects", async () => {
  // Non-empty target: a pre-existing selfhost_users table.
  const database = await bootstrap();
  await database.exec(`CREATE TABLE ${SCHEMA}.selfhost_users (id int); CREATE TABLE ${SCHEMA}.unrelated (id int)`);
  const before = await objectsIn(database.client, SCHEMA);
  await assert.rejects(
    migrate(database, DIR, { cutover: "fresh" }),
    /^Error: SELFHOST_DATABASE_SCHEMA_CUTOVER=fresh requires an empty target, but schema "relaycontrol" already holds selfhost_users\. fresh is only for a brand-new schema and never migrates data; unset SELFHOST_DATABASE_SCHEMA_CUTOVER once the fresh install has run$/,
  );
  // Rollback proof: the target holds exactly what it held, no ledger and no
  // other selfhost_* table appeared anywhere.
  assert.deepEqual(await objectsIn(database.client, SCHEMA), before);
  assert.deepEqual(await tablesIn(database, SCHEMA), ["selfhost_users"]);
  assert.deepEqual(await tablesIn(database, "public"), []);
  await database.close();

  // Any other pre-existing object also makes fresh refuse: a table with a
  // row, a function, a user-defined type. Each refusal leaves no ledger and
  // the object untouched.
  const occupied: Array<{ create: string; offender: string; check: string }> = [
    {
      create: `CREATE TABLE ${SCHEMA}.notes (id int PRIMARY KEY, body text); INSERT INTO ${SCHEMA}.notes VALUES (1, 'keep')`,
      offender: 'table "relaycontrol"."notes"',
      check: `SELECT body AS value FROM ${SCHEMA}.notes WHERE id = 1`,
    },
    {
      create: `CREATE FUNCTION ${SCHEMA}.helper(x integer) RETURNS integer LANGUAGE sql AS 'SELECT x + 1'`,
      offender: 'function "relaycontrol".helper\\(x integer\\)',
      check: `SELECT ${SCHEMA}.helper(1)::text AS value`,
    },
    {
      create: `CREATE TYPE ${SCHEMA}.mood AS ENUM ('ok')`,
      offender: 'enum type "relaycontrol"."mood"',
      check: `SELECT 'ok'::${SCHEMA}.mood::text AS value`,
    },
  ];
  for (const { create, offender, check } of occupied) {
    const target = await bootstrap();
    await target.exec(create);
    const expected = (await target.query<{ value: string }>(check)).rows[0]?.value;
    const objects = await objectsIn(target.client, SCHEMA);
    await assert.rejects(
      migrate(target, DIR, { cutover: "fresh" }),
      new RegExp(
        `^Error: SELFHOST_DATABASE_SCHEMA_CUTOVER=fresh requires an empty target, but schema "relaycontrol" already holds ${offender}\\. fresh is only for a brand-new schema`,
      ),
    );
    assert.deepEqual(await objectsIn(target.client, SCHEMA), objects);
    assert.deepEqual(await tablesIn(target, SCHEMA), []);
    assert.equal((await target.query<{ value: string }>(check)).rows[0]?.value, expected);
    await target.close();
  }

  // Objects owned by an installed extension do not occupy the target.
  const withExtension = await bootstrap(new PGlite({ extensions: { citext } }));
  await asBootstrap(withExtension, `CREATE EXTENSION citext SCHEMA ${SCHEMA}`);
  assert((await migrate(withExtension, DIR, { cutover: "fresh" })).length > 0);
  await withExtension.close();

  // Empty target in a database with no relaycontrol tables anywhere.
  const empty = await bootstrap();
  assert((await migrate(empty, DIR, { cutover: "fresh" })).length > 0);
  assert((await tablesIn(empty, SCHEMA)).includes("selfhost_workspaces"));
  // A second fresh run finds the ledger and refuses.
  await assert.rejects(
    migrate(empty, DIR, { cutover: "fresh" }),
    /fresh requires an empty target, but schema "relaycontrol" already holds selfhost_schema_migrations/,
  );
  assert.deepEqual(await migrate(empty, DIR), []);
  await empty.close();
});

test("cutover: a manually moved install migrates with nothing to apply", async () => {
  const client = await legacyInstall();
  // The README's reviewed path, run as the owner of both schemas' objects.
  const statements = await client.query<{ sql: string }>(`
    SELECT format('ALTER TABLE public.%I SET SCHEMA ${SCHEMA}', tablename) AS sql
      FROM pg_tables
     WHERE schemaname = 'public' AND tablename LIKE 'selfhost\\_%'
    UNION ALL
    SELECT format('ALTER SEQUENCE public.%I SET SCHEMA ${SCHEMA}', c.relname)
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind = 'S' AND c.relname LIKE 'selfhost\\_%'
       AND NOT EXISTS (
         SELECT 1 FROM pg_depend d
          WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype IN ('a', 'i'))`);
  assert(statements.rows.length > 0);
  for (const { sql } of statements.rows) await client.exec(sql);
  await client.exec(`ALTER SCHEMA ${SCHEMA} OWNER TO CURRENT_USER`);

  const database = await pinned(client);
  assert.deepEqual(await tablesIn(database, "public"), []);
  assert.deepEqual(await migrate(database, DIR), []);
  await client.exec(`CREATE ROLE ${RUNTIME} NOLOGIN; REVOKE USAGE ON SCHEMA public FROM PUBLIC`);
  await grantRuntimeDatabaseRole(database, RUNTIME);
  assert.equal(await new ControlPlaneStore(database, KEYRING, 0).ready(), true);
  await client.close();
});
