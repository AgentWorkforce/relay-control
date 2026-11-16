import { open } from "node:fs/promises";
import { Client } from "pg";
import { readSecret } from "../../src/config.js";
import { captureCredentialConvergence } from "./convergence.js";
import { localDatabaseUrl } from "./local.js";

let target:Client|undefined;
try {
  const args=process.argv.slice(2);
  if (args.length !== 2 || args[1] !== "--all-organizations") throw new Error("all_scope_and_output_required");
  target=new Client({connectionString:localDatabaseUrl(readSecret(process.env,"CLOUD_VERIFY_TARGET_URL"))});
  await target.connect();
  const snapshot=await captureCredentialConvergence(target);
  const file=await open(args[0]!,"wx",0o600);
  try {await file.writeFile(`${JSON.stringify(snapshot,null,2)}\n`);} finally {await file.close();}
  process.stdout.write(`${JSON.stringify({ok:true,credentialRows:snapshot.credentials.length,blobRows:snapshot.blobs.length})}\n`);
} catch {
  process.stderr.write("Convergence capture could not complete. Check all-org scope, local target, Postgres blob storage and a fresh private output path.\n");
  process.exitCode=2;
} finally {await target?.end();}
