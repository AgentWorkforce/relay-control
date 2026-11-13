import assert from "node:assert/strict";
import type { Server } from "node:http";
import { PGlite } from "@electric-sql/pglite";
import type { Database, SqlExecutor, SqlResult } from "../../src/database.js";

/**
 * A PGlite-backed Database for tests. close() also drops the PGlite reference:
 * node:test keeps every finished test's t.after() closure (and so this
 * wrapper) alive until the file ends, and each PGlite pins ~100 MB of WASM
 * memory, so a file with dozens of databases otherwise grows to several GB.
 */
export class PGliteDatabase implements Database {
  // A plain (not #private) field: tests wrap databases with Object.create().
  private open: PGlite | null;

  constructor(client = new PGlite()) {
    this.open = client;
  }

  get client(): PGlite {
    if (!this.open) throw new Error("PGliteDatabase is closed");
    return this.open;
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
    const client = this.open;
    if (!client) return;
    this.open = null;
    await client.close();
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
    /** Extra request headers. */
    headers?: Record<string, string>;
  } = {},
): Promise<JsonResponse> {
  const headers: Record<string, string> = { ...options.headers };
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
