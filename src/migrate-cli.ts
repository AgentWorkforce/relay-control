#!/usr/bin/env node
import {
  loadMigrationsDatabaseUrl,
  loadRuntimeDatabaseRole,
} from "./config.js";
import { PostgresDatabase } from "./database.js";
import { grantRuntimeDatabaseRole, migrate } from "./migrations.js";

const databaseUrl = loadMigrationsDatabaseUrl();
const runtimeRole = loadRuntimeDatabaseRole();
const database = new PostgresDatabase(databaseUrl);

try {
  const applied = await migrate(database);
  await grantRuntimeDatabaseRole(database, runtimeRole);
  console.log(JSON.stringify({ applied }));
} finally {
  await database.close();
}
