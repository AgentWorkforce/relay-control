import { readFile } from "node:fs/promises";
import { Client } from "pg";
import { loadEncryptionKeyring } from "../../src/config.js";
import { validateContract, verify, type Contract } from "./verify.js";

// Synthetic/local use only until remote verification is separately authorized.
function localUrl(value: string | undefined): string {
  if (!value) throw new Error("missing_url");
  const url = new URL(value);
  if (!["postgres:", "postgresql:"].includes(url.protocol)
    || !["127.0.0.1", "[::1]"].includes(url.hostname)
    || [...url.searchParams.keys()].some((key) => !["sslmode"].includes(key))) {
    throw new Error("local_database_required");
  }
  return value;
}

let source: Client | undefined;
let target: Client | undefined;
try {
  const path = process.argv[2];
  if (!path || process.argv.length !== 3) throw new Error("contract_path_required");
  const contract = JSON.parse(await readFile(path, "utf8")) as Contract;
  validateContract(contract);
  const keyring = loadEncryptionKeyring();
  source = new Client({ connectionString: localUrl(process.env.CLOUD_VERIFY_SOURCE_URL) });
  target = new Client({ connectionString: localUrl(process.env.CLOUD_VERIFY_TARGET_URL) });
  await source.connect();
  await target.connect();
  const report = await verify(source, target, contract, keyring);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.ok ? 0 : 1;
} catch {
  // Keep database errors, connection strings and secret values out of reports.
  process.stderr.write("Verification could not complete. Check the local URLs, contract, schema and keyring.\n");
  process.exitCode = 2;
} finally {
  await Promise.allSettled([source?.end(), target?.end()]);
}
