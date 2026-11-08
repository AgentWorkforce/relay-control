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
