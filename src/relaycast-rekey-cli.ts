#!/usr/bin/env node
// relaycast-rekey (bin agent-relay-selfhost-relaycast-rekey): replace every
// legacy Relaycast credential this service stores with an ar_ one before
// Relaycast moves to durable actors. Runs as a one-shot Job with the API's
// environment. README, "Re-keying Relaycast credentials".
//
//   relaycast-rekey [--workspace <id>] [--dry-run] [--grace-ms <n>]
//   relaycast-rekey --undo <run-id> [--grace-ms <n>]
//   relaycast-rekey --purge <run-id> [--confirm]
//
// Exit 0: done with no failures. 1: at least one credential failed (the
// others were still processed). 2: usage or configuration error.
import type { Env } from "./config.js";
import { PostgresDatabase } from "./database.js";
import {
  loadRekeyEnv,
  parseRekeyArgs,
  purgeRelaycastRekey,
  rekeyRelaycastCredentials,
  REKEY_USAGE,
  undoRelaycastRekey,
  type RekeyArgs,
  type RekeyDeps,
  type RekeyLogger,
  type RekeyReport,
} from "./relaycast-rekey.js";

const log: RekeyLogger = (event, fields) => {
  console.log(JSON.stringify({ event, ...fields }));
};

function printSummary(report: RekeyReport): void {
  console.log(JSON.stringify({
    event: "relaycast_rekey.summary",
    mode: report.mode,
    run_id: report.runId,
    failed: report.failed,
    by_column: report.summary,
  }));
}

async function main(argv: readonly string[], env: Env): Promise<number> {
  let args: RekeyArgs;
  let config: ReturnType<typeof loadRekeyEnv>;
  try {
    args = parseRekeyArgs(argv);
    if (args.mode === "help") {
      console.log(REKEY_USAGE);
      return 0;
    }
    config = loadRekeyEnv(env, args.mode === "undo" || (args.mode === "rekey" && !args.dryRun));
  } catch (error) {
    // Configuration and usage errors name variables and flags, never values.
    console.error(JSON.stringify({ event: "relaycast_rekey.usage_error", error: error instanceof Error ? error.message : "invalid" }));
    console.error(REKEY_USAGE);
    return 2;
  }

  const { databaseUrl, ...rest } = config;
  const database = new PostgresDatabase(databaseUrl);
  try {
    const deps: RekeyDeps = { ...rest, database, log };
    if (args.mode === "purge") {
      // Without --confirm this is a preview; the counts are already logged.
      await purgeRelaycastRekey(deps, args.runId, { confirm: args.confirm });
      return 0;
    }
    const report = args.mode === "undo"
      ? await undoRelaycastRekey(deps, args.runId, args.graceMs === undefined ? {} : { workspaceKeyGraceMs: args.graceMs })
      : await rekeyRelaycastCredentials(deps, {
        dryRun: args.dryRun,
        ...(args.workspaceId === undefined ? {} : { workspaceId: args.workspaceId }),
        ...(args.graceMs === undefined ? {} : { workspaceKeyGraceMs: args.graceMs }),
      });
    printSummary(report);
    return report.failed > 0 ? 1 : 0;
  } catch (error) {
    // Validation errors are fixed strings; anything else reports its code only.
    const code = (error as { code?: unknown } | null)?.code;
    console.error(JSON.stringify({
      event: "relaycast_rekey.error",
      ...(typeof code === "string" ? { code } : { error: error instanceof Error && error.constructor === Error ? error.message : "unexpected" }),
    }));
    return 2;
  } finally {
    await database.close();
  }
}

process.exitCode = await main(process.argv.slice(2), process.env);
