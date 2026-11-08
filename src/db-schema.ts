/**
 * The Postgres schema relaycontrol lives in. A shared application database can
 * host several services, each in its own schema with its own roles; the
 * default `public` keeps single-service installs unchanged.
 *
 * Names are validated once, where configuration is read (src/config.ts). The
 * helpers below trust a validated name and only add identifier quotes.
 */
export const DEFAULT_DATABASE_SCHEMA = "public";

/** Returns an error message for an unusable schema name, or null when valid. */
export function databaseSchemaError(value: string): string | null {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(value)) {
    return "must be a lower-case PostgreSQL identifier matching ^[a-z_][a-z0-9_]{0,62}$";
  }
  if (value === "information_schema" || value.startsWith("pg_")) {
    return "must not be a PostgreSQL system schema (pg_* or information_schema)";
  }
  return null;
}

export function assertDatabaseSchema(value: string): string {
  const error = databaseSchemaError(value);
  if (error) throw new Error(`Invalid database schema "${value}": ${error}`);
  return value;
}

/** Quotes a validated schema name for interpolation into SQL. */
export function quoteSchema(schema: string): string {
  return `"${schema}"`;
}

/** A schema-qualified, quoted relation name for a validated schema and a fixed selfhost_* name. */
export function qualifiedName(schema: string, name: string): string {
  return `"${schema}"."${name}"`;
}

/** The current_schema() mismatch message shared by startup, migrate and readiness. */
export function currentSchemaMismatch(actual: string | null, expected: string): string {
  return `Database current_schema() is ${actual === null ? "null" : `"${actual}"`}, expected "${expected}"` +
    " (SELFHOST_DATABASE_SCHEMA): the schema must exist, be pre-created by the operator, and grant USAGE to this role";
}
