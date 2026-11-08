import assert from "node:assert/strict";
import type { Server } from "node:http";
import { PGlite } from "@electric-sql/pglite";
import type { Database, SqlExecutor, SqlResult } from "../../src/database.js";

export class PGliteDatabase implements Database {
  /**
   * `schema` mirrors PostgresDatabase's pinned schema. PGlite is a single
   * session, so call pinSearchPath() once the schema exists.
   */
  constructor(readonly client = new PGlite(), readonly schema = "public") {}

  async pinSearchPath(): Promise<void> {
    await this.client.exec(`SET search_path TO "${this.schema}"`);
  }

  async query<T extends Record<string, unknown>>(
    sql: string,
    params: unknown[] = [],
  ): Promise<SqlResult<T>> {
    const result = params.length > 0
      ? await this.client.query<T>(sql, params)
      : await this.client.query<T>(sql);
    return { rows: result.rows };
  }

  async transaction<T>(run: (transaction: SqlExecutor) => Promise<T>): Promise<T> {
    return this.client.transaction(async (transaction) => run({
      query: async <R extends Record<string, unknown>>(sql: string, params: unknown[] = []) => {
        const result = params.length > 0
          ? await transaction.query<R>(sql, params)
          : await transaction.query<R>(sql);
        return { rows: result.rows };
      },
      exec: async (sql: string) => {
        await transaction.exec(sql);
      },
    }));
  }

  async close(): Promise<void> {
    await this.client.close();
  }

  async exec(sql: string): Promise<void> {
    await this.client.exec(sql);
  }
}

export async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");
  return `http://127.0.0.1:${address.port}`;
}

export async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => error ? reject(error) : resolve()));
}

export type JsonResponse = {
  status: number;
  body: Record<string, any>;
  raw: string;
  headers: Headers;
};

export async function request(
  baseUrl: string,
  path: string,
  options: {
    method?: string;
    token?: string;
    cookie?: string;
    body?: unknown;
    contentType?: string;
    rawBody?: string;
  } = {},
): Promise<JsonResponse> {
  const headers: Record<string, string> = {};
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  if (options.cookie) headers.cookie = options.cookie;
  let body: string | undefined;
  if (options.rawBody !== undefined) {
    body = options.rawBody;
    headers["content-type"] = options.contentType ?? "text/plain";
  } else if (options.body !== undefined) {
    body = JSON.stringify(options.body);
    headers["content-type"] = options.contentType ?? "application/json";
  }
  const response = await fetch(`${baseUrl}${path}`, {
    method: options.method ?? "GET",
    headers,
    body,
    redirect: "manual",
  });
  const raw = response.status === 204 ? "" : await response.text();
  let parsed: Record<string, any> = {};
  try {
    parsed = raw ? JSON.parse(raw) as Record<string, any> : {};
  } catch {
    parsed = {};
  }
  return { status: response.status, body: parsed, raw, headers: response.headers };
}
