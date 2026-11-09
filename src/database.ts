import pg from "pg";

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
  transaction<T>(run: (transaction: SqlExecutor) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export class PostgresDatabase implements Database {
  readonly #pool: pg.Pool;

  constructor(databaseUrl: string | pg.Pool) {
    this.#pool = typeof databaseUrl !== "string" ? databaseUrl : new pg.Pool({
      connectionString: databaseUrl,
      max: 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
    });
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

const UNAVAILABLE_SQLSTATES = new Set(["57P01", "57P02", "57P03", "53300"]);
const UNAVAILABLE_ERRNOS = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ENOTFOUND",
  "EAI_AGAIN",
  "EPIPE",
]);

/**
 * True when `error` means the database could not be reached or dropped the
 * connection (SQLSTATE class 08, admin/crash shutdown, cannot connect now,
 * too many connections, socket errnos, pg-pool connect timeout, pg
 * "Connection terminated"), directly, inside an AggregateError or through
 * `cause`. False for everything else, including query and constraint errors.
 */
export function isDatabaseUnavailable(error: unknown): boolean {
  return unavailable(error, 0);
}

function unavailable(error: unknown, depth: number): boolean {
  if (depth > 8 || typeof error !== "object" || error === null) return false;
  const { code, message, cause } = error as { code?: unknown; message?: unknown; cause?: unknown };
  if (typeof code === "string" && (
    code.startsWith("08") || UNAVAILABLE_SQLSTATES.has(code) || UNAVAILABLE_ERRNOS.has(code)
  )) {
    return true;
  }
  if (typeof message === "string" && (
    /timeout exceeded when trying to connect/i.test(message) || /connection terminated/i.test(message)
  )) {
    return true;
  }
  if (error instanceof AggregateError && Array.isArray(error.errors) &&
    error.errors.some((inner) => unavailable(inner, depth + 1))) {
    return true;
  }
  return cause !== undefined && unavailable(cause, depth + 1);
}

/** The error's `code` (SQLSTATE or errno) for logs, else its constructor name. */
export function databaseErrorCause(error: unknown): string {
  let current = error;
  for (let depth = 0; depth <= 8 && typeof current === "object" && current !== null; depth += 1) {
    const { code, cause } = current as { code?: unknown; cause?: unknown };
    if (typeof code === "string" && code) return code;
    const next = current instanceof AggregateError && Array.isArray(current.errors)
      ? current.errors.find((item) => isDatabaseUnavailable(item))
      : undefined;
    if (next !== undefined) current = next;
    else if (cause !== undefined && isDatabaseUnavailable(cause)) current = cause;
    else return current instanceof Error ? current.name : "unknown";
  }
  return "unknown";
}
