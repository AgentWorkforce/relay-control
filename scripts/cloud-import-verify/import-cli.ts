import { readFile } from "node:fs/promises";
import { Client } from "pg";
import { loadEncryptionKeyring,readSecret } from "../../src/config.js";
import { parsePepperFile,readPepperFile } from "../../src/identity/config.js";
import type { ImportReport } from "../cloud-import/importer.js";
import { assertScope,type ImportScope } from "../cloud-import/mapping.js";
import { localDatabaseUrl } from "./local.js";
import { verifyImport } from "./import-contract.js";

let source:Client|undefined;
let target:Client|undefined;
try {
  const args = process.argv.slice(2);
  const path = args[0];
  let scope:ImportScope;
  if (args.length === 2 && args[1] === "--all-organizations") scope = {orgIds:null};
  else if (args.length === 3 && args[1] === "--org-ids") scope = {orgIds:args[2]!.split(",")};
  else throw new Error("explicit_scope_required");
  assertScope(scope);
  const ledger = JSON.parse(await readFile(path!,"utf8")) as ImportReport;
  const keyring = loadEncryptionKeyring();
  const cloudKeyHex = readSecret(process.env,"CLOUD_IMPORT_CREDENTIAL_ENCRYPTION_KEY") ?? "";
  const pepperPath = process.env.SELFHOST_PASSWORD_PEPPER_FILE?.trim();
  const pepperVersions = pepperPath ? parsePepperFile(readPepperFile(pepperPath)).map((p) => p.version) : [];
  source = new Client({connectionString:localDatabaseUrl(readSecret(process.env,"CLOUD_VERIFY_SOURCE_URL"))});
  target = new Client({connectionString:localDatabaseUrl(readSecret(process.env,"CLOUD_VERIFY_TARGET_URL"))});
  await source.connect();await target.connect();
  const report = await verifyImport(source,target,scope,ledger,keyring,cloudKeyHex,{pepperVersions});
  process.stdout.write(`${JSON.stringify(report,null,2)}\n`);
  process.exitCode = report.ok ? 0 : 1;
} catch {
  process.stderr.write("Import verification could not complete. Check the explicit scope, ledger, local URLs, schema and keys.\n");
  process.exitCode=2;
} finally {await Promise.allSettled([source?.end(),target?.end()]);}
