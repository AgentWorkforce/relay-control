#!/usr/bin/env node
import {
  loadMigrationsDatabaseUrl,
  loadRuntimeDatabaseRole,
} from "./config.js";
import { PostgresDatabase } from "./database.js";
import {
  connectedAsDatabaseMaster,
  formatMasterLoginWarning,
  formatMissingRoleError,
} from "./migrate-diagnostics.js";
import { grantRuntimeDatabaseRole, migrate } from "./migrations.js";

const databaseUrl = loadMigrationsDatabaseUrl();
const runtimeRole = loadRuntimeDatabaseRole();
const database = new PostgresDatabase(databaseUrl);

try {
  // Best effort: a login that is the database master still migrates, but the
  // per-service logins were most likely never created.
  const master = await connectedAsDatabaseMaster(database).catch(() => false);
  if (master) console.error(formatMasterLoginWarning());

  const applied = await migrate(database);
  await grantRuntimeDatabaseRole(database, runtimeRole);
  console.log(JSON.stringify({ applied }));
} catch (error) {
  const lines = formatMissingRoleError(error);
  if (!lines) throw error;
  for (const line of lines) console.error(line);
  process.exitCode = 1;
} finally {
  await database.close();
}
