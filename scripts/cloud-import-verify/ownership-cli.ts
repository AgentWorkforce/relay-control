import { open } from "node:fs/promises";
import { Client } from "pg";
import { readSecret } from "../../src/config.js";
import { assertScope,type ImportScope } from "../cloud-import/mapping.js";
import { captureOwnership } from "./reconciliation.js";
import { localDatabaseUrl } from "./local.js";

let target:Client|undefined;
try {
  const args=process.argv.slice(2);let scope:ImportScope;
  if (args.length === 2 && args[1] === "--all-organizations") scope={orgIds:null};
  else if (args.length === 3 && args[1] === "--org-ids") scope={orgIds:args[2]!.split(",")};
  else throw new Error("explicit_scope_required");
  assertScope(scope);
  target=new Client({connectionString:localDatabaseUrl(readSecret(process.env,"CLOUD_VERIFY_TARGET_URL"))});
  await target.connect();const snapshot=await captureOwnership(target,scope);
  const file=await open(args[0]!,"w",0o600);
  try {await file.chmod(0o600);await file.writeFile(`${JSON.stringify(snapshot,null,2)}\n`);}
  finally {await file.close();}
  process.stdout.write(`${JSON.stringify({ok:true,entries:snapshot.rows.length})}\n`);
} catch {
  process.stderr.write("Ownership capture could not complete. Check the local target, scope, owner role and output path.\n");process.exitCode=2;
} finally {await target?.end();}
