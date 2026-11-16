import assert from "node:assert/strict";
import pg from "pg";

/**
 * Creates every session in a test pool and configures it in-session.
 * Supabase Supavisor session mode drops libpq startup `options`, so test
 * isolation must not rely on `options=-c search_path=...`.
 */
export async function isolatedPostgresPool(
  connectionString: string,
  schema: string,
  max: number,
): Promise<pg.Pool> {
  const pool = new pg.Pool({ connectionString, max });
  const clients: pg.PoolClient[] = [];
  let failure: unknown;
  try {
    for (let index = 0; index < max; index += 1) clients.push(await pool.connect());
    for (const client of clients) {
      await client.query("SELECT set_config('search_path', $1, false)", [`"${schema}", public`]);
      const shown = await client.query<{ search_path: string }>("SHOW search_path");
      assert(shown.rows[0]!.search_path.includes(schema));
      const current = await client.query<{ current_schema: string }>("SELECT current_schema()");
      assert.equal(current.rows[0]!.current_schema, schema);
    }
  } catch (error) {
    failure = error;
  } finally {
    for (const client of clients) client.release();
  }
  if (failure) {
    await pool.end();
    throw failure;
  }
  return pool;
}
