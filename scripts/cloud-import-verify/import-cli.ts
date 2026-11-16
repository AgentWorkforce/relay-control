import type { CredentialConvergenceSnapshot } from "./convergence.js";
import { readFile,realpath,stat } from "node:fs/promises";
import { resolve,sep } from "node:path";
import { Client } from "pg";
import { loadEncryptionKeyring,readSecret } from "../../src/config.js";
import { parsePepperFile,readPepperFile } from "../../src/identity/config.js";
import type { ImportReport } from "../cloud-import/importer.js";
import { assertScope,type ImportScope } from "../cloud-import/mapping.js";
import { localDatabaseUrl } from "./local.js";
import { verifyImport } from "./import-contract.js";
import { readOnlyPostgresBlobs,type CredentialEvidence,type CredentialTargetSnapshot } from "./credential-copy.js";
import type { CredentialCopyReport } from "../cloud-import/credentials.js";
import type { OwnershipSnapshot } from "./reconciliation.js";

let source:Client|undefined;
let target:Client|undefined;
try {
  const args = process.argv.slice(2);
  const copyAt = args.indexOf("--credential-copy-report");
  let copyPath:string|undefined;
  if (copyAt >= 0) {
    copyPath=args[copyAt+1];
    if (!copyPath || copyPath.startsWith("--")) throw new Error("copy_report_path_required");
    args.splice(copyAt,2);
  }
  const previousAt=args.indexOf("--previous-report");
  let previousPath:string|undefined;
  if (previousAt >= 0) {
    previousPath=args[previousAt+1];
    if (!previousPath || previousPath.startsWith("--")) throw new Error("previous_report_path_required");
    args.splice(previousAt,2);
  }
  const ownershipAt=args.indexOf("--previous-ownership");let ownershipPath:string|undefined;
  if (ownershipAt >= 0) {
    ownershipPath=args[ownershipAt+1];
    if (!ownershipPath || ownershipPath.startsWith("--")) throw new Error("ownership_snapshot_path_required");
    args.splice(ownershipAt,2);
  }
  const credentialBeforeAt=args.indexOf("--previous-credentials");let credentialBeforePath:string|undefined;
  if (credentialBeforeAt >= 0) {
    credentialBeforePath=args[credentialBeforeAt+1];
    if (!credentialBeforePath || credentialBeforePath.startsWith("--")) throw new Error("credential_snapshot_path_required");
    args.splice(credentialBeforeAt,2);
  }
  const convergenceAt=args.indexOf("--convergence-before");let convergencePath:string|undefined;
  if (convergenceAt >= 0) {
    convergencePath=args[convergenceAt+1];
    if (!convergencePath || convergencePath.startsWith("--")) throw new Error("convergence_snapshot_path_required");
    args.splice(convergenceAt,2);
  }
  if ((credentialBeforePath || convergencePath) && !copyPath) throw new Error("credential_copy_report_required");
  const path = args[0];
  let scope:ImportScope;
  if (args.length === 2 && args[1] === "--all-organizations") scope = {orgIds:null};
  else if (args.length === 3 && args[1] === "--org-ids") scope = {orgIds:args[2]!.split(",")};
  else throw new Error("explicit_scope_required");
  assertScope(scope);
  const ledger = JSON.parse(await readFile(path!,"utf8")) as ImportReport;
  const previousReport = previousPath ? JSON.parse(await readFile(previousPath,"utf8")) as ImportReport : undefined;
  const previousOwnership=ownershipPath ? JSON.parse(await readFile(ownershipPath,"utf8")) as OwnershipSnapshot : undefined;
  const keyring = loadEncryptionKeyring();
  const cloudKeyHex = readSecret(process.env,"CLOUD_CREDENTIAL_ENCRYPTION_KEY") ?? "";
  const pepperPath = process.env.SELFHOST_PASSWORD_PEPPER_FILE?.trim();
  const pepperVersions = pepperPath ? parsePepperFile(readPepperFile(pepperPath)).map((p) => p.version) : [];
  source = new Client({connectionString:localDatabaseUrl(readSecret(process.env,"CLOUD_VERIFY_SOURCE_URL"))});
  target = new Client({connectionString:localDatabaseUrl(readSecret(process.env,"CLOUD_VERIFY_TARGET_URL"))});
  await source.connect();await target.connect();
  let credentialCopy:CredentialEvidence|undefined;
  if (copyPath) {
    if (!process.env.CLOUD_VERIFY_CREDENTIAL_OBJECTS_DIR) throw new Error("local_object_directory_required");
    const root = await realpath(process.env.CLOUD_VERIFY_CREDENTIAL_OBJECTS_DIR);
    credentialCopy = {
      convergenceBefore:convergencePath ? JSON.parse(await readFile(convergencePath,"utf8")) as CredentialConvergenceSnapshot : undefined,
      previousTarget:credentialBeforePath ? JSON.parse(await readFile(credentialBeforePath,"utf8")) as CredentialTargetSnapshot : undefined,
      report:JSON.parse(await readFile(copyPath,"utf8")) as CredentialCopyReport,
      targetBlobs:readOnlyPostgresBlobs(target,keyring),
      reader:{get:async (key) => {
        try {
          const path = await realpath(resolve(root,key));
          if (!path.startsWith(root+sep)) throw new Error("object_path_outside_directory");
          const info = await stat(path);
          if (!info.isFile() || (info.mode & 0o077) !== 0
            || (process.getuid && info.uid !== process.getuid())) throw new Error("private_object_file_required");
          return await readFile(path,"utf8");
        } catch (error) {if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;throw error;}
      }},
    };
  }
  const report = await verifyImport(source,target,scope,ledger,keyring,cloudKeyHex,{pepperVersions,credentialCopy,previousReport,previousOwnership});
  process.stdout.write(`${JSON.stringify(report,null,2)}\n`);
  process.exitCode = report.ok ? 0 : 1;
} catch {
  process.stderr.write("Import verification could not complete. Check the explicit scope, ledger, local URLs, schema and keys.\n");
  process.exitCode=2;
} finally {await Promise.allSettled([source?.end(),target?.end()]);}
