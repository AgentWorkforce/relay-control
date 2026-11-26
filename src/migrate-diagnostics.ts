import type { SqlExecutor } from "./database.js";

/**
 * Shared error code and help link for database login problems. The same code
 * and URL are printed by relay-control, relaycast and sessions-pipeline, so
 * keep them verbatim.
 */
export const DB_LOGIN_ERROR_CODE = "AR_DB_LOGIN";
export const DB_LOGIN_HELP =
  "Run scripts/selfhost/configure-rds.sh (AgentWorkforce/infra), or see " +
  "https://agentrelay.com/docs/self-hosting/troubleshooting#database-logins";

const UNDEFINED_OBJECT = "42704";
const INVALID_AUTHORIZATION = "28000";
const MISSING_ROLE = /role "((?:[^"]|"")+)" does not exist/;

type PgErrorShape = { code?: unknown; routine?: unknown; message?: unknown };

/**
 * The role name when `error` is Postgres reporting that a role does not exist
 * (SQLSTATE 42704 raised by get_role_oid, or its `role "x" does not exist`
 * message), else undefined.
 */
export function missingDatabaseRole(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const { code, routine, message } = error as PgErrorShape;
  // Another SQLSTATE is another error, whatever its message says. 28000 is
  // the server refusing a login that does not exist (trust or peer auth).
  if (code !== undefined && code !== UNDEFINED_OBJECT && code !== INVALID_AUTHORIZATION) {
    return undefined;
  }
  const match = typeof message === "string" ? MISSING_ROLE.exec(message) : null;
  if (match) return printable(match[1]!.replaceAll('""', '"'));
  // Right SQLSTATE and routine but an unexpected (for example localized) message.
  if (code === UNDEFINED_OBJECT && routine === "get_role_oid") return "(unknown)";
  return undefined;
}

/**
 * The lines the migrate command prints for a missing database role, or
 * undefined when `error` is something else. The second line keeps the
 * original SQLSTATE and message (never a stack, connection URL or password).
 */
export function formatMissingRoleError(error: unknown): string[] | undefined {
  const role = missingDatabaseRole(error);
  if (role === undefined) return undefined;
  const { code, message } = error as PgErrorShape;
  return [
    `${DB_LOGIN_ERROR_CODE}: role "${role}" does not exist: the database logins haven't been created. ${DB_LOGIN_HELP}`,
    `cause: ${typeof code === "string" ? `${code} ` : ""}${printable(String(message))}`,
  ];
}

/** The line printed when the migrations login is the database master. */
export function formatMasterLoginWarning(): string {
  return `${DB_LOGIN_ERROR_CODE}: the migrations URL logs in as the database master ` +
    `(superuser or CREATEROLE); each service needs its own login. ${DB_LOGIN_HELP}`;
}

/**
 * True when the connected login is a superuser or can create roles, which
 * means the migrations URL uses the database master rather than its own
 * owner login. False when the catalog cannot be read.
 */
export async function connectedAsDatabaseMaster(database: SqlExecutor): Promise<boolean> {
  const result = await database.query<{ rolsuper: boolean; rolcreaterole: boolean }>(
    "SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = current_user",
  );
  const row = result.rows[0];
  return row?.rolsuper === true || row?.rolcreaterole === true;
}

function printable(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 200);
}
