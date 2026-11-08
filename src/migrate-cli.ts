#!/usr/bin/env node
import {
  loadAllowedDatabaseSchemas,
  loadDatabaseSchema,
  loadDatabaseSchemaCutover,
  loadMigrationsDatabaseUrl,
  loadRuntimeDatabaseRole,
} from "./config.js";
import { PostgresDatabase } from "./database.js";
import { grantRuntimeDatabaseRole, migrate } from "./migrations.js";

const databaseUrl = loadMigrationsDatabaseUrl();
const runtimeRole = loadRuntimeDatabaseRole();
const allowedSchemas = loadAllowedDatabaseSchemas();
const cutover = loadDatabaseSchemaCutover();
const database = new PostgresDatabase(databaseUrl, { schema: loadDatabaseSchema() });

try {
  await database.assertSchema();
  const applied = await migrate(database, undefined, { cutover });
  await grantRuntimeDatabaseRole(database, runtimeRole, { allowedSchemas });
  console.log(JSON.stringify({ applied }));
} finally {
  await database.close();
}
