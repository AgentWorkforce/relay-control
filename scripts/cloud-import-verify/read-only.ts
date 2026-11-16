import type { Client } from "pg";

export type ReadOnlySettings={transactionReadOnly:string;isolation:string;statementTimeout:string;lockTimeout:string};

/** In-session SQL only: poolers can silently drop libpq startup options.
 * Caller must roll back in finally, including when a setting check fails. */
export async function beginReadOnlySnapshot(client:Client):Promise<ReadOnlySettings> {
  await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
  await client.query("SET LOCAL statement_timeout='60s'");
  await client.query("SET LOCAL lock_timeout='5s'");
  await client.query("SET LOCAL TIME ZONE 'UTC'");
  await client.query("SET LOCAL DateStyle='ISO, YMD'");
  await client.query("SET LOCAL row_security=off");
  const show=async (name:string):Promise<string> => Object.values((await client.query(`SHOW ${name}`)).rows[0])[0] as string;
  const settings={transactionReadOnly:await show("transaction_read_only"),isolation:await show("transaction_isolation"),
    statementTimeout:await show("statement_timeout"),lockTimeout:await show("lock_timeout")};
  if (settings.transactionReadOnly !== "on" || settings.isolation !== "repeatable read"
    || settings.statementTimeout !== "1min" || settings.lockTimeout !== "5s") throw new Error("Read-only transaction settings not enforced");
  return settings;
}
