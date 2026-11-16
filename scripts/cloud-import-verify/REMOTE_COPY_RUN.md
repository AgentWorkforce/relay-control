# Final identity plus credential-copy qualification

This is the final-run variant when credential copying is in scope. It extends
[REMOTE_IMPORT_RUN.md](REMOTE_IMPORT_RUN.md) with mandatory copier evidence.
An identity-only result with `credentialCopy: "not_requested"` is not sufficient.
The independently authorized rehearsal runner executes it; the verifier author
never receives database, R2 or encryption secrets. This recipe performs no copy,
refresh, mutation, grant or schema change.

Use the exact verifier commit in the handoff, including main's fixed importer
and copier. Preserve the final apply report and separate `CredentialCopyReport`
from the approved `--copy-credentials` run (`--credentials-report` saves it).
Both reports and the target ownership ledger must match the mapping revision.
Keep the source and target stable while verification takes its snapshots.

Use the private URL, CA, Control keyring and Cloud AES-key inputs from the
identity recipe. Also supply the existing approved Cloud object-reader inputs
via environment or `_FILE`: `CLOUD_CREDENTIAL_R2_ENDPOINT`,
`CLOUD_CREDENTIAL_R2_BUCKET`, `CLOUD_CREDENTIAL_R2_ACCESS_KEY_ID` and
`CLOUD_CREDENTIAL_R2_SECRET_ACCESS_KEY`. The reader exposes GET only, refuses
redirects and requires verified HTTPS. It uses explicit R2 inputs, never an
ambient AWS credential chain. No endpoint, key, object body or driver error
should be returned over Relay.

This ready-to-run variant reads target credential blobs from Postgres, the
scratch copier's default. Confirm that this matches the backend actually used
by the copier. A row pointing at another backend fails verification; do not
silently substitute or migrate it. For an approved non-Postgres backend, supply
a reviewed read-only `CredentialBlobStore` reader to the library instead.

If native credentials already exist, capture `captureCredentialTarget(target,
scope)` before the copier and write that metadata snapshot privately (mode 600).
Pass it as `--previous-credentials`. It contains hashed natural keys and flags,
not accounts/fingerprints/secrets. Without a baseline, unmatched target rows
fail. A snapshot taken after copying does not prove a pre-existing native row.
A fresh empty credential target needs no baseline. Positive identity deletion
counts additionally require the actual pre-import ownership snapshot.

Copy the complete block to private mode-600 `run-copy-verify.mjs` and run from
the exact checkout root. All secret inputs remain local to the runner.

```js
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

let source, target;
try {
  const require = createRequire(pathToFileURL(resolve("package.json")));
  const { Client } = require("pg");
  const localImport = (path) => import(pathToFileURL(resolve(path)).href);
  const { verifyImport } = await localImport("scripts/cloud-import-verify/import-contract.ts");
  const { readOnlyCloudCredentials } = await localImport("scripts/cloud-import-verify/credential-readers.ts");
  const { readOnlyPostgresBlobs } = await localImport("scripts/cloud-import-verify/credential-copy.ts");
  const { assertScope, MAPPING_REVISION } = await localImport("scripts/cloud-import/mapping.ts");
  const { loadEncryptionKeyring, readSecret } = await localImport("src/config.ts");
  const { parsePepperFile, readPepperFile } = await localImport("src/identity/config.ts");
  const args = process.argv.slice(2);
  function takePath(flag, required = false) {
    const at = args.indexOf(flag);
    if (at < 0) {
      if (required) throw new Error("required_report_missing");
      return undefined;
    }
    const path = args[at + 1];
    if (!path || path.startsWith("--")) throw new Error("report_path_required");
    args.splice(at, 2);
    return path;
  }
  const copyPath = takePath("--credential-copy-report", true);
  const credentialBeforePath = takePath("--previous-credentials");
  const beforeAt = args.indexOf("--previous-ownership");
  let beforePath;
  if (beforeAt >= 0) {
    beforePath = args[beforeAt + 1];
    if (!beforePath || beforePath.startsWith("--")) throw new Error("ownership_path_required");
    args.splice(beforeAt, 2);
  }
  let scope;
  if (args.length === 2 && args[1] === "--all-organizations") scope = {orgIds: null};
  else if (args.length === 3 && args[1] === "--org-ids") scope = {orgIds: args[2].split(",")};
  else throw new Error("explicit_scope_required");
  assertScope(scope);
  const ledger = JSON.parse(await readFile(args[0], "utf8"));
  if (ledger.version !== 1 || ledger.mappingRevision !== MAPPING_REVISION
    || ledger.mode !== "apply" || ledger.ok !== true) throw new Error("matching_apply_required");
  const cloudKeyHex = readSecret(process.env, "CLOUD_CREDENTIAL_ENCRYPTION_KEY") ?? "";
  if (!/^[0-9a-f]{64}$/i.test(cloudKeyHex)) throw new Error("cloud_key_required");
  const previousOwnership = beforePath ? JSON.parse(await readFile(beforePath, "utf8")) : undefined;
  const copyReport = JSON.parse(await readFile(copyPath, "utf8"));
  if (copyReport.version !== 1 || copyReport.mappingRevision !== MAPPING_REVISION
    || copyReport.mode !== "apply") throw new Error("matching_copy_report_required");
  const previousTarget = credentialBeforePath
    ? JSON.parse(await readFile(credentialBeforePath, "utf8")) : undefined;
  const reader = readOnlyCloudCredentials(process.env);
  async function clientFor(side) {
    const value = readSecret(process.env, `CLOUD_VERIFY_${side}_URL`);
    if (!value) throw new Error("url_required");
    const url = new URL(value);
    const host = url.hostname.replace(/^\[|\]$/g, "");
    if (!["postgres:", "postgresql:"].includes(url.protocol) || !host.includes(".")
      || isIP(host) || host.endsWith(".") || /(^|\.)localhost$/i.test(host)
      || url.hash || !url.username || !url.password || !url.pathname || url.pathname === "/") throw new Error("direct_dns_required");
    for (const [name, option] of url.searchParams) {
      if (name !== "sslmode" || option !== "verify-full") throw new Error("unsupported_connection_option");
    }
    const caPath = process.env[`CLOUD_VERIFY_${side}_CA_FILE`];
    if (!caPath) throw new Error("approved_ca_required");
    const ca = await readFile(caPath, "utf8");
    // Remove URL SSL options so pg cannot replace the explicit TLS object.
    url.search = "";
    url.port = url.port || "5432";
    return new Client({connectionString: url.href, connectionTimeoutMillis: 10000,
      application_name: "cloud-import-readonly-verification",
      options: "-c default_transaction_read_only=on",
      ssl: {ca, rejectUnauthorized: true, servername: host}});
  }
  source = await clientFor("SOURCE");
  target = await clientFor("TARGET");
  const keyring = loadEncryptionKeyring();
  const pepperPath = process.env.SELFHOST_PASSWORD_PEPPER_FILE?.trim();
  const pepperVersions = pepperPath
    ? parsePepperFile(readPepperFile(pepperPath)).map((pepper) => pepper.version) : [];
  await source.connect();
  await target.connect();
  const credentialCopy = {report: copyReport, reader,
    targetBlobs: readOnlyPostgresBlobs(target, keyring), previousTarget};
  const report = await verifyImport(source, target, scope, ledger, keyring, cloudKeyHex,
    {pepperVersions, previousOwnership, credentialCopy});
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.ok ? 0 : 1;
} catch {
  process.stderr.write("Verification could not complete. Check the approved inputs, TLS, apply ledger, schema and keyring locally.\n");
  process.exitCode = 2;
} finally {
  await Promise.allSettled([source?.end(), target?.end()]);
}
```

```sh
umask 077
node --import tsx /path/to/private/run-copy-verify.mjs /path/to/private/final-apply.json --all-organizations --credential-copy-report /path/to/private/final-copy.json > /path/to/private/final-verification.json
```

Use `--org-ids UUID,UUID` instead of `--all-organizations` only for a matching
approved cohort. Append `--previous-credentials /path/to/private/before-copy.json`
when needed, and `--previous-ownership /path/to/private/before-import.json` for
positive declared removals. These are evidence snapshots, never write authority.

Expected successful evidence: exit 0, `ok: true`, `credentialCopy: "verified"`,
all requested checks passing, and the six app smokes still pending. Exit 1 with
`credentialCopy: "failed"` retains missing/decrypt/selection/natural-key/ID-map
failures as unresolved; do not suppress them or relabel a prior result. Exit 2
means the run could not complete and stderr is a fixed redacted message.

Return exact verifier/importer heads, original revisions, exit code, counts and
check summaries, report digest/size and a redacted report. Keep all private
inputs, object bodies and driver logs on the runner. Application smoke proof
and any production action remain separate from this database/copy evidence.
