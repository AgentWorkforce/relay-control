import pg from "pg";
import { DEFAULT_DATABASE_SCHEMA, currentSchemaMismatch, quoteSchema } from "./db-schema.js";

export type SqlResult<T> = {
  rows: T[];
};

export interface SqlExecutor {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: unknown[],
  ): Promise<SqlResult<T>>;
  exec(sql: string): Promise<void>;
}

export interface Database extends SqlExecutor {
  /**
   * The schema every connection is pinned to (SELFHOST_DATABASE_SCHEMA). Code
   * that names catalog objects reads it from here, so the schema always
   * matches the connection.
   */
  readonly schema: string;
  transaction<T>(run: (transaction: SqlExecutor) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export class PostgresDatabase implements Database {
  readonly #pool: pg.Pool;
  readonly schema: string;

  /**
   * `options.schema` must already be validated (loadDatabaseSchema). An
   * injected pool (tests) is used as-is: its owner is responsible for pinning
   * search_path; only pools built here from a URL get the onConnect pin.
   */
  constructor(databaseUrl: string | pg.Pool, options: { schema?: string } = {}) {
    this.schema = options.schema ?? DEFAULT_DATABASE_SCHEMA;
    const setSearchPath = `SET search_path TO ${quoteSchema(this.schema)}`;
    this.#pool = typeof databaseUrl !== "string" ? databaseUrl : new pg.Pool({
      connectionString: databaseUrl,
      max: 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      // Pins every pooled connection to the configured schema only (no public
      // fallback). pg-pool awaits this before handing the client out and
      // discards the connection if it fails. A session-level SET also wins
      // over any `options=-c search_path=...` carried by the URL.
      onConnect: async (client) => {
        await client.query(setSearchPath);
      },
    });
  }

  /**
   * Fails fast unless connections resolve unqualified names to the configured
   * schema. current_schema() is null when the schema is missing or the role
   * lacks USAGE on it.
   */
  async assertSchema(): Promise<void> {
    await assertCurrentSchema(this, this.schema);
  }

  async query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params: unknown[] = [],
  ): Promise<SqlResult<T>> {
    const result = params.length > 0
      ? await this.#pool.query(sql, params)
      : await this.#pool.query(sql);
    return { rows: result.rows as T[] };
  }

  async transaction<T>(run: (transaction: SqlExecutor) => Promise<T>): Promise<T> {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      const executor: SqlExecutor = {
        query: async <R extends Record<string, unknown>>(sql: string, params: unknown[] = []) => {
          const result = params.length > 0
            ? await client.query(sql, params)
            : await client.query(sql);
          return { rows: result.rows as R[] };
        },
        exec: async (sql: string) => {
          await client.query(sql);
        },
      };
      const result = await run(executor);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      // A failed ROLLBACK (typically a dead connection) must not mask the
      // original error: callers classify COMMIT failures by it.
      try {
        await client.query("ROLLBACK");
      } catch (rollbackError) {
        if (typeof error === "object" && error !== null) {
          try {
            Object.defineProperty(error, "rollbackError", { value: rollbackError, configurable: true });
          } catch {
            // A frozen or non-extensible error keeps its original shape.
          }
        }
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.#pool.end();
  }

  async exec(sql: string): Promise<void> {
    await this.#pool.query(sql);
  }
}

export async function assertCurrentSchema(
  executor: SqlExecutor,
  schema: string,
): Promise<void> {
  const result = await executor.query<{ schema: string | null }>(
    "SELECT current_schema() AS schema",
  );
  const actual = result.rows[0]?.schema ?? null;
  if (actual !== schema) throw new Error(currentSchemaMismatch(actual, schema));
}

/** pg_roles attributes a runtime role must not carry, as selected by ROLE_ATTRIBUTE_COLUMNS. */
export type RoleAttributes = {
  rolsuper: boolean;
  rolcreaterole: boolean;
  rolcreatedb: boolean;
  rolbypassrls: boolean;
  rolreplication: boolean;
};

/** Selects RoleAttributes from `pg_roles r`. */
export const ROLE_ATTRIBUTE_COLUMNS =
  "r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolbypassrls, r.rolreplication";

/** The first forbidden attribute the role carries (e.g. "SUPERUSER"), or null. */
export function forbiddenRoleAttribute(role: RoleAttributes): string | null {
  if (role.rolsuper) return "SUPERUSER";
  if (role.rolcreaterole) return "CREATEROLE";
  if (role.rolcreatedb) return "CREATEDB";
  if (role.rolbypassrls) return "BYPASSRLS";
  if (role.rolreplication) return "REPLICATION";
  return null;
}

type RuntimeLoginRow = RoleAttributes & {
  session_user: string;
  current_user: string;
  schema_present: boolean;
  schema_owner: string | null;
  owns_schema: boolean;
  member_of_owner: boolean;
  can_create_database: boolean;
  can_create_schema: boolean;
};

/**
 * Binds the API server's actual LOGIN to SELFHOST_RUNTIME_DATABASE_ROLE at
 * startup, in one query. Fails unless the session user is `expectedRole`,
 * current_user equals it (no role switched through URL options), it carries
 * none of SUPERUSER, CREATEROLE, CREATEDB, BYPASSRLS or REPLICATION, it
 * neither owns `schema` nor is a (transitive) member of its owner, and it has
 * CREATE on neither the database nor `schema`. Messages name the login role
 * and the failed property, never the connection URL.
 */
export async function assertRuntimeLogin(
  executor: SqlExecutor,
  schema: string,
  expectedRole: string,
): Promise<void> {
  const result = await executor.query<RuntimeLoginRow>(
    `SELECT session_user::text AS session_user,
            current_user::text AS current_user,
            ${ROLE_ATTRIBUTE_COLUMNS},
            n.oid IS NOT NULL AS schema_present,
            pg_get_userbyid(n.nspowner)::text AS schema_owner,
            coalesce(n.nspowner = r.oid, false) AS owns_schema,
            coalesce(pg_has_role(r.oid, n.nspowner, 'MEMBER'), false) AS member_of_owner,
            has_database_privilege(r.oid, current_database(), 'CREATE') AS can_create_database,
            coalesce(has_schema_privilege(r.oid, n.oid, 'CREATE'), false) AS can_create_schema
       FROM pg_roles r
       LEFT JOIN pg_namespace n ON n.nspname = $1
      WHERE r.rolname = session_user`,
    [schema],
  );
  const row = result.rows[0];
  if (!row) throw new Error("Database login role is not visible in pg_roles");
  const login = row.session_user;
  const refuse = (property: string) =>
    new Error(
      `Database login role "${login}" ${property} (SELFHOST_RUNTIME_DATABASE_ROLE ` +
        `"${expectedRole}"); the API server must connect as the runtime role`,
    );
  if (login !== expectedRole) throw refuse(`is not the expected runtime role "${expectedRole}"`);
  if (row.current_user !== login) {
    throw refuse(`has current_user "${row.current_user}"; the connection must not switch roles`);
  }
  const attribute = forbiddenRoleAttribute(row);
  if (attribute) throw refuse(`must not have ${attribute}`);
  if (!row.schema_present) throw refuse(`cannot find schema "${schema}"`);
  if (row.owns_schema) throw refuse(`must not own schema "${schema}"`);
  if (row.member_of_owner) {
    throw refuse(`must not be a member of role "${row.schema_owner}", the owner of schema "${schema}"`);
  }
  if (row.can_create_database) throw refuse("must not have CREATE on the database");
  if (row.can_create_schema) throw refuse(`must not have CREATE on schema "${schema}"`);
}
