#!/usr/bin/env node
// cloud-import: copy hosted Cloud identity rows into relay-control.
//
//   node --import tsx scripts/cloud-import/cli.ts --mode plan|dry-run|apply
//        [--org <uuid>]... [--report <path>] [--verifier-contract <path>]
//
// Environment (each also accepts NAME_FILE, never a command-line argument):
//   CLOUD_IMPORT_SOURCE_URL           Cloud database, read-only role
//   CLOUD_IMPORT_TARGET_URL           Control database (not needed for plan)
//   CLOUD_CREDENTIAL_ENCRYPTION_KEY   Cloud's 64-hex credential key
//   SELFHOST_ENCRYPTION_KEY_ID / SELFHOST_ENCRYPTION_KEY
//                                     Control's keyring, as the service loads it
//
// Exit 0: done, every organization ok. 1: refused, or an organization failed.
// 2: usage or configuration error. Output is JSON lines without values.
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { loadEncryptionKeyring, readSecret, type Env } from "../../src/config.js";
import { PostgresDatabase } from "../../src/database.js";
import { runImport, type ImportMode } from "./importer.js";
import { encryptedSamples, MAPPING_REVISION, TARGET_RELATIONS, verifierComparisons } from "./mapping.js";

export type CliArgs = {
  mode: ImportMode;
  orgIds: string[] | null;
  report?: string;
  verifierContract?: string;
};

export const USAGE = "usage: cloud-import --mode plan|dry-run|apply [--org <uuid>]... [--report <path>] [--verifier-contract <path>]";

export function parseArgs(argv: readonly string[]): CliArgs {
  let mode: ImportMode | undefined;
  const orgs: string[] = [];
  let report: string | undefined;
  let verifierContract: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) throw new Error(`${flag} needs a value`);
    index += 1;
    if (flag === "--mode") {
      if (value !== "plan" && value !== "dry-run" && value !== "apply") throw new Error("--mode must be plan, dry-run or apply");
      mode = value;
    } else if (flag === "--org") orgs.push(value);
    else if (flag === "--report") report = value;
    else if (flag === "--verifier-contract") verifierContract = value;
    else throw new Error(`unknown flag ${flag}`);
  }
  if (!mode) throw new Error("--mode is required");
  return { mode, orgIds: orgs.length ? orgs : null, ...(report ? { report } : {}), ...(verifierContract ? { verifierContract } : {}) };
}

function required(env: Env, name: string): string {
  const value = readSecret(env, name);
  if (!value) throw new Error(`${name} (or ${name}_FILE) is required`);
  return value;
}

async function main(argv: readonly string[], env: Env): Promise<number> {
  let args: CliArgs;
  let config: { sourceUrl: string; targetUrl?: string; cloudKey?: string; keyring: ReturnType<typeof loadEncryptionKeyring> };
  try {
    args = parseArgs(argv);
    // Plan mode may run without the Cloud key (agent tokens are then not
    // test-decrypted); dry-run and apply need it.
    const cloudKey = args.mode === "plan"
      ? readSecret(env, "CLOUD_CREDENTIAL_ENCRYPTION_KEY")
      : required(env, "CLOUD_CREDENTIAL_ENCRYPTION_KEY");
    if (cloudKey !== undefined && !/^[0-9a-f]{64}$/i.test(cloudKey)) throw new Error("CLOUD_CREDENTIAL_ENCRYPTION_KEY must be 64 hex characters");
    config = {
      sourceUrl: required(env, "CLOUD_IMPORT_SOURCE_URL"),
      ...(args.mode === "plan" ? {} : { targetUrl: required(env, "CLOUD_IMPORT_TARGET_URL") }),
      ...(cloudKey ? { cloudKey } : {}),
      // Plan writes nothing, so without Control's keyring a throwaway key
      // stands in for the re-encryption pass.
      keyring: args.mode === "plan" && !readSecret(env, "SELFHOST_ENCRYPTION_KEY")
        ? { active: { id: "plan-only", key: randomBytes(32) } }
        : loadEncryptionKeyring(env),
    };
  } catch (error) {
    // Usage errors name flags and variables, never values.
    console.error(JSON.stringify({ event: "cloud_import.usage_error", error: error instanceof Error ? error.message : "invalid" }));
    console.error(USAGE);
    return 2;
  }

  const scope = { orgIds: args.orgIds };
  if (args.verifierContract) {
    writeFileSync(args.verifierContract, JSON.stringify({
      version: 1,
      mappingRevision: MAPPING_REVISION,
      tables: verifierComparisons(scope),
      identities: [],
      targetRelations: TARGET_RELATIONS,
      encryptedSamples: encryptedSamples(200, scope),
    }, null, 2), { mode: 0o600 });
  }

  const source = new PostgresDatabase(config.sourceUrl);
  const target = config.targetUrl ? new PostgresDatabase(config.targetUrl) : undefined;
  try {
    const report = await runImport({
      source,
      ...(target ? { target } : {}),
      keyring: config.keyring,
      ...(config.cloudKey ? { cloudKeyHex: config.cloudKey } : {}),
      log: (event, fields) => console.log(JSON.stringify({ event, ...fields })),
    }, scope, args.mode);
    if (args.report) writeFileSync(args.report, JSON.stringify(report, null, 2), { mode: 0o600 });
    return report.ok ? 0 : 1;
  } catch (error) {
    const code = (error as { code?: unknown } | null)?.code;
    console.error(JSON.stringify({
      event: "cloud_import.error",
      ...(typeof code === "string" ? { code } : { error: error instanceof Error ? error.name : "unexpected" }),
    }));
    return 2;
  } finally {
    await source.close();
    await target?.close();
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  process.exitCode = await main(process.argv.slice(2), process.env);
}
