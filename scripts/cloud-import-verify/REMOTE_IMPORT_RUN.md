# Matching-revision identity qualification on the rehearsal machine

Use this variant for the final identity run, rather than the contract-only
`verify()` recipe. All access is by the independently authorized rehearsal
runner on its approved read-only source branch and temporary target. The
checked-in loopback CLI and its guard remain unchanged.

Use the exact verifier commit in the handoff. Importer report, target ownership
ledger and checked-out mapping must all have the same revision; this driver
rejects an old report before connecting. A `.7` contract/report is not a `.11`
apply report. Keep the importer stopped while the verifier takes its snapshots.

Use the same private URL, approved CA and Control keyring inputs described in
[REMOTE_RUN.md](REMOTE_RUN.md). Also supply the runner's existing
`CLOUD_CREDENTIAL_ENCRYPTION_KEY` or `_FILE` input (64 hex characters), which
allows independent source-envelope/skip verification. Never send that key.
The target reader must already be authorized to SELECT `cloud_import_ledger`;
verification does not grant privileges or mutate anything.

Copy the complete block below to a private mode-600 `run-import.mjs` file.
Run it from the checkout root with the exact final `.11` apply report and
explicit organization scope, keeping every input local to the runner.

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
  const { assertScope, MAPPING_REVISION } = await localImport("scripts/cloud-import/mapping.ts");
  const { requireAllSourceScope, cutoverScopeFinding } = await localImport("scripts/cloud-import-verify/organization-scope.ts");
  const { loadEncryptionKeyring, readSecret } = await localImport("src/config.ts");
  const { parsePepperFile, readPepperFile } = await localImport("src/identity/config.ts");
  const args = process.argv.slice(2);
  const beforeAt = args.indexOf("--previous-ownership");
  let beforePath;
  if (beforeAt >= 0) {
    beforePath = args[beforeAt + 1];
    if (!beforePath || beforePath.startsWith("--")) throw new Error("ownership_path_required");
    args.splice(beforeAt, 2);
  }
  let scope;
  if (args.length === 2 && args[1] === "--all-organizations") scope = {orgIds: null};
  else throw new Error("explicit_scope_required");
  assertScope(scope);
  requireAllSourceScope(scope);
  const ledger = JSON.parse(await readFile(args[0], "utf8"));
  if (ledger.version !== 1 || ledger.mappingRevision !== MAPPING_REVISION
    || ledger.mode !== "apply" || ledger.ok !== true) throw new Error("matching_apply_required");
  const cloudKeyHex = readSecret(process.env, "CLOUD_CREDENTIAL_ENCRYPTION_KEY") ?? "";
  if (!/^[0-9a-f]{64}$/i.test(cloudKeyHex)) throw new Error("cloud_key_required");
  const previousOwnership = beforePath ? JSON.parse(await readFile(beforePath, "utf8")) : undefined;
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
  const report = await verifyImport(source, target, scope, ledger, keyring, cloudKeyHex,
    {pepperVersions, previousOwnership});
  const scopeCheck = cutoverScopeFinding(report);
  report.findings.push(scopeCheck);
  report.ok = report.ok && scopeCheck.ok;
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.ok ? 0 : 1;
} catch {
  process.stderr.write("Verification could not complete. Check the approved inputs, TLS, apply ledger, schema and keyring locally.\n");
  process.exitCode = 2;
} finally {
  await Promise.allSettled([source?.end(), target?.end()]);
}
```

For the full approved cohort:

```sh
umask 077
node --import tsx /path/to/private/run-import.mjs /path/to/private/final-apply.json --all-organizations > /path/to/private/final-verification.json
```

Final qualification requires `--all-organizations`; explicit subsets are rejected
before any report/secret read or connection. Diagnostic subsets use the library
and remain explicitly scope-labeled. With positive
`deleted` totals, append `--previous-ownership /path/to/private/before.json`.
That ownership snapshot must have been captured before the corresponding import
using `captureOwnership(target, scope)`. A snapshot taken afterward cannot prove
old removals. A fresh run or zero-deletion convergence run needs no prior snapshot.

Exit codes remain 0 (all requested database checks passed), 1 (completed with
failed checks), and 2 (could not complete, with fixed redacted stderr). Return the
exact verifier/importer heads, mapping revision, exit code, `ok`, check summaries
and redacted report digest/size. Do not forward private inputs, endpoints or logs.

This identity-only variant must report `credentialCopy: "not_requested"` and all
six application smokes as pending. It reconciles source/target rows, importer
skips and current ownership, checks continuity, constraints/sequences/keyring
samples, and proves declared removals when the prior snapshot exists. It does
not qualify the separate credential copier or provide application smoke proof.
A passing identity-only report is not a completed cutover approval.

When the final scope includes copying credentials, use [REMOTE_COPY_RUN.md](REMOTE_COPY_RUN.md)
instead; this identity-only command cannot sign off the copier.

The result includes normalized `scope`, a streaming all-source organization
census/count/digest and selected census, plus the committed target schema
manifest identity/digests. The cutover guard requires all-source scope, matching
nonempty census and the production `main` schema profile. The synthetic proposed
0061 profile and contract-only/unbound reports cannot satisfy that guard.
