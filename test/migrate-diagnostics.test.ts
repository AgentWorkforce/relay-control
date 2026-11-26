import assert from "node:assert/strict";
import test from "node:test";
import {
  connectedAsDatabaseMaster,
  formatMasterLoginWarning,
  formatMissingRoleError,
  missingDatabaseRole,
} from "../src/migrate-diagnostics.js";
import { PGliteDatabase } from "./support/harness.js";

const HELP =
  "Run scripts/selfhost/configure-rds.sh (AgentWorkforce/infra), or see " +
  "https://agentrelay.com/docs/self-hosting/troubleshooting#database-logins";

function pgError(fields: Record<string, unknown>): Error {
  return Object.assign(new Error(String(fields.message ?? "")), fields);
}

test("a missing role (42704 from get_role_oid) prints one AR_DB_LOGIN line and the cause", () => {
  const error = pgError({
    code: "42704",
    routine: "get_role_oid",
    severity: "ERROR",
    message: 'role "control_api_runtime" does not exist',
  });
  assert.equal(missingDatabaseRole(error), "control_api_runtime");
  assert.deepEqual(formatMissingRoleError(error), [
    `AR_DB_LOGIN: role "control_api_runtime" does not exist: the database logins haven't been created. ${HELP}`,
    'cause: 42704 role "control_api_runtime" does not exist',
  ]);
});

test("the message alone identifies a missing role", () => {
  assert.equal(missingDatabaseRole(new Error('role "control_owner" does not exist')), "control_owner");
  // Postgres does not escape quotes inside the name.
  assert.equal(missingDatabaseRole(new Error('role "a"b" does not exist')), 'a"b');
  assert.equal(missingDatabaseRole(new Error('role "a""b" does not exist')), 'a""b');
});

test("a login that does not exist (28000) is a missing role", () => {
  const error = pgError({
    code: "28000",
    severity: "FATAL",
    routine: "InitializeSessionUserId",
    message: 'role "control_owner" does not exist',
  });
  assert.equal(missingDatabaseRole(error), "control_owner");
  assert.equal(formatMissingRoleError(error)![1], 'cause: 28000 role "control_owner" does not exist');
});

test("42704 from get_role_oid with an unexpected message is still a missing role", () => {
  const error = pgError({ code: "42704", routine: "get_role_oid", message: "rolle existiert nicht" });
  assert.equal(missingDatabaseRole(error), "(unknown)");
  assert.match(formatMissingRoleError(error)![0]!, /^AR_DB_LOGIN: role "\(unknown\)" does not exist/);
});

test("other errors are left alone", () => {
  for (const error of [
    pgError({ code: "42P01", routine: "parserOpenTable", message: 'relation "users" does not exist' }),
    pgError({ code: "42704", routine: "LookupTypeName", message: 'type "citext" does not exist' }),
    pgError({ code: "28P01", message: 'password authentication failed for user "postgres"' }),
    pgError({ code: "42501", message: 'permission denied; role "x" does not exist' }),
    new Error("Migration and runtime database roles must be distinct"),
    "role \"x\" does not exist",
    null,
    undefined,
  ]) {
    assert.equal(missingDatabaseRole(error), undefined);
    assert.equal(formatMissingRoleError(error), undefined);
  }
});

test("the formatted lines carry no stack and strip control characters", () => {
  const error = pgError({ code: "42704", message: 'role "evil\nname" does not exist' });
  const lines = formatMissingRoleError(error)!;
  assert.equal(lines.length, 2);
  for (const line of lines) {
    assert.doesNotMatch(line, /\n|\bat /);
  }
  assert.match(lines[0]!, /role "evil name" does not exist/);
});

test("the master login warning uses the shared code and link", () => {
  assert.equal(
    formatMasterLoginWarning(),
    "AR_DB_LOGIN: the migrations URL logs in as the database master (superuser or CREATEROLE); " +
      `each service needs its own login. ${HELP}`,
  );
});

test("a real Postgres missing-role error is detected, and the master login is recognised", async () => {
  const database = new PGliteDatabase();
  try {
    const error = await database
      .exec("GRANT USAGE ON SCHEMA public TO control_api_runtime")
      .then(() => undefined, (caught: unknown) => caught);
    assert.equal(missingDatabaseRole(error), "control_api_runtime");

    // PGlite connects as a superuser, as an RDS master connects with CREATEROLE.
    assert.equal(await connectedAsDatabaseMaster(database), true);
    await database.exec("CREATE ROLE control_owner NOSUPERUSER NOCREATEROLE");
    await database.exec("SET ROLE control_owner");
    assert.equal(await connectedAsDatabaseMaster(database), false);
  } finally {
    await database.close();
  }
});
