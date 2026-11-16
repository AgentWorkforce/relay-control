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
// --copy-credentials (opt-in, after the identity import) also copies
// coding-agent secrets from Cloud's credential store (Cloudflare R2, S3 API,
// read-only) through Control's own stores. It additionally needs:
//   CLOUD_CREDENTIAL_R2_ENDPOINT, CLOUD_CREDENTIAL_R2_BUCKET,
//   CLOUD_CREDENTIAL_R2_ACCESS_KEY_ID, CLOUD_CREDENTIAL_R2_SECRET_ACCESS_KEY
//   and Control's credential storage settings (SELFHOST_CREDENTIAL_STORAGE...)
//
// Exit 0: done, every organization ok. 1: refused, or an organization failed.
// 2: usage or configuration error. Output is JSON lines without values.
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { loadEncryptionKeyring, readSecret, type Env } from "../../src/config.js";
import { PostgresDatabase } from "../../src/database.js";
import { CodingAgentStore } from "../../src/admin/coding-agents.js";
import { CredentialBlobStore, credentialBackendFromEnv, S3ObjectBackend } from "../../src/admin/credential-blobs.js";
import { SubscriptionLoginStore } from "../../src/admin/subscription-logins.js";
import type { EncryptionKeyring } from "../../src/crypto.js";
import { copyCodingAgentCredentials, type CloudObjectReader } from "./credentials.js";
import { runImport, type ImportMode } from "./importer.js";
import { encryptedSamples, IMPORT_LEDGER_DDL, MAPPING_REVISION, TARGET_RELATIONS, verifierComparisons } from "./mapping.js";

export type CliArgs = {
  mode: ImportMode;
  orgIds: string[] | null;
  report?: string;
  verifierContract?: string;
  copyCredentials: boolean;
  credentialsReport?: string;
  initLedger: boolean;
};

export const USAGE = "usage: cloud-import --mode plan|dry-run|apply [--org <uuid>]... [--report <path>] [--verifier-contract <path>] [--init-ledger] [--copy-credentials [--credentials-report <path>]]";

export function parseArgs(argv: readonly string[]): CliArgs {
  let mode: ImportMode | undefined;
  const orgs: string[] = [];
  let report: string | undefined;
  let verifierContract: string | undefined;
  let copyCredentials = false;
  let credentialsReport: string | undefined;
  let initLedger = false;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--copy-credentials") {
      copyCredentials = true;
      continue;
    }
    if (flag === "--init-ledger") {
      initLedger = true;
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) throw new Error(`${flag} needs a value`);
    index += 1;
    if (flag === "--mode") {
      if (value !== "plan" && value !== "dry-run" && value !== "apply") throw new Error("--mode must be plan, dry-run or apply");
      mode = value;
    } else if (flag === "--org") orgs.push(value);
    else if (flag === "--report") report = value;
    else if (flag === "--verifier-contract") verifierContract = value;
    else if (flag === "--credentials-report") credentialsReport = value;
    else throw new Error(`unknown flag ${flag}`);
  }
  if (!mode) throw new Error("--mode is required");
  if (copyCredentials && mode === "dry-run") throw new Error("--copy-credentials runs with plan or apply only (its stores commit)");
  return {
    mode,
    orgIds: orgs.length ? orgs : null,
    copyCredentials,
    initLedger,
    ...(report ? { report } : {}),
    ...(verifierContract ? { verifierContract } : {}),
    ...(credentialsReport ? { credentialsReport } : {}),
  };
}

const COPY_APPLY_ENV = [
  "CLOUD_IMPORT_TARGET_URL",
  "CLOUD_CREDENTIAL_ENCRYPTION_KEY",
  "CLOUD_CREDENTIAL_R2_ENDPOINT",
  "CLOUD_CREDENTIAL_R2_BUCKET",
  "CLOUD_CREDENTIAL_R2_ACCESS_KEY_ID",
  "CLOUD_CREDENTIAL_R2_SECRET_ACCESS_KEY",
] as const;

/**
 * `--mode apply --copy-credentials` refuses up front, before the identity
 * import writes anything, when any setting it needs is missing. Names only.
 */
export function copyApplyPreflight(args: Pick<CliArgs, "mode" | "copyCredentials">, env: Env): string[] {
  if (!args.copyCredentials || args.mode !== "apply") return [];
  return COPY_APPLY_ENV.filter((name) => !readSecret(env, name));
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
    const missing = copyApplyPreflight(args, env);
    if (missing.length) throw new Error(`--copy-credentials with --mode apply needs ${missing.join(", ")} (or *_FILE)`);
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
    if (args.initLedger && target && args.mode !== "plan") {
      // Until the ledger ships as a Control migration: an explicit operator
      // step that creates only this table, idempotently.
      await target.exec(IMPORT_LEDGER_DDL);
    }
    const report = await runImport({
      source,
      ...(target ? { target } : {}),
      keyring: config.keyring,
      ...(config.cloudKey ? { cloudKeyHex: config.cloudKey } : {}),
      log: (event, fields) => console.log(JSON.stringify({ event, ...fields })),
    }, scope, args.mode);
    if (args.report) writeFileSync(args.report, JSON.stringify(report, null, 2), { mode: 0o600 });
    if (!args.copyCredentials) return report.ok ? 0 : 1;
    if (args.mode === "apply" && !report.ok) return 1;
    const copy = await copyCredentials(args, env, source, target, config.keyring, config.cloudKey);
    if (args.credentialsReport) writeFileSync(args.credentialsReport, JSON.stringify(copy, null, 2), { mode: 0o600 });
    return report.ok && copy.ok ? 0 : 1;
  } catch (error) {
    if (error instanceof CopyRefused) {
      console.error(JSON.stringify({ event: "cloud_import.usage_error", error: error.message }));
      return 2;
    }
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

/** Cloud's credential store, read-only: only GET is reachable from here. */
function cloudReader(env: Env): CloudObjectReader {
  const backend = new S3ObjectBackend({
    bucket: required(env, "CLOUD_CREDENTIAL_R2_BUCKET"),
    region: "auto",
    prefix: "credentials",
    endpoint: required(env, "CLOUD_CREDENTIAL_R2_ENDPOINT"),
    forcePathStyle: true,
    credentials: {
      accessKeyId: required(env, "CLOUD_CREDENTIAL_R2_ACCESS_KEY_ID"),
      secretAccessKey: required(env, "CLOUD_CREDENTIAL_R2_SECRET_ACCESS_KEY"),
    },
  });
  return { get: (key) => backend.get(key) };
}

class CopyRefused extends Error {}

async function copyCredentials(
  args: CliArgs,
  env: Env,
  source: PostgresDatabase,
  target: PostgresDatabase | undefined,
  keyring: EncryptionKeyring,
  cloudKey: string | undefined,
) {
  const scope = { orgIds: args.orgIds };
  if (args.mode === "plan") {
    // Plan: candidates and skip reasons only; the object store is not touched.
    const stub = undefined as unknown as never;
    return copyCodingAgentCredentials({ source, target: stub, reader: { get: async () => null }, cloudKeyHex: "", keyring, codingAgents: stub, logins: stub }, scope, "plan");
  }
  if (!target || !cloudKey) {
    // Never fall back to a silent plan when an apply was asked for.
    throw new CopyRefused("--copy-credentials with --mode apply needs CLOUD_IMPORT_TARGET_URL and CLOUD_CREDENTIAL_ENCRYPTION_KEY");
  }
  const blobs = new CredentialBlobStore(credentialBackendFromEnv(env, target), keyring);
  return copyCodingAgentCredentials({
    source,
    target,
    reader: cloudReader(env),
    cloudKeyHex: cloudKey,
    keyring,
    codingAgents: new CodingAgentStore(target, keyring, undefined, blobs),
    logins: new SubscriptionLoginStore(target, keyring, blobs),
    log: (event, fields) => console.log(JSON.stringify({ event, ...fields })),
  }, scope, "apply");
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  process.exitCode = await main(process.argv.slice(2), process.env);
}
