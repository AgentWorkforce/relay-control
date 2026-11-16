# Read-only library integration for the rehearsal runner

This recipe is for the independently authorized runner on the rehearsal machine.
It does not change the checked-in CLI's loopback restriction or authorize access.
Use the approved read-only Cloud child branch and temporary dry-run target only.
Wait for the import to commit and do not run concurrent importer reruns while
verification takes its two snapshots. Run from the root of an isolated checkout of the exact verifier commit supplied
in the handoff, with its own `npm ci --no-audit --no-fund`.

Connect directly to each provider's actual DNS hostname. Do not use loopback
forwarding, routing overrides, `verify-ca`, `require`, or disabled hostname checks.
Both certificate-chain and hostname verification remain enabled. Keep URLs,
passwords, CA bundles and keyring inputs on that machine; never send them in Relay
or put them on the command line.

Use private environment/file inputs:

- `CLOUD_VERIFY_SOURCE_URL_FILE` and `CLOUD_VERIFY_TARGET_URL_FILE`: existing
  mode-600 URL files for the approved readers. The usual environment variables
  without `_FILE` also work. The only supported URL query option is
  `sslmode=verify-full`; no option is required because TLS is explicit below.
- `CLOUD_VERIFY_SOURCE_CA_FILE` and `CLOUD_VERIFY_TARGET_CA_FILE`: local approved
  PEM trust bundles for each provider.
- Control's `SELFHOST_ENCRYPTION_*` environment or `_FILE` inputs, including the
  previous key if needed; optionally `SELFHOST_PASSWORD_PEPPER_FILE`.

Copy the following code into a private directory as `run-contract.mjs` (mode
600). Its library imports resolve from the checkout's current working directory.
It reads only the contract and local configuration before connecting.

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
  const { validateContract, verify } = await localImport("scripts/cloud-import-verify/verify.ts");
  const { loadEncryptionKeyring, readSecret } = await localImport("src/config.ts");
  const { parsePepperFile, readPepperFile } = await localImport("src/identity/config.ts");
  if (process.argv.length !== 3) throw new Error("contract_path_required");
  const contract = JSON.parse(await readFile(process.argv[2], "utf8"));
  validateContract(contract);
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
      ssl: {ca, rejectUnauthorized: true, servername: host}});
  }
  source = await clientFor("SOURCE");
  target = await clientFor("TARGET");
  const keyring = loadEncryptionKeyring();
  const pepperPath = process.env.SELFHOST_PASSWORD_PEPPER_FILE?.trim();
  const pepperVersions = contract.pepperChecks?.length && pepperPath
    ? parsePepperFile(readPepperFile(pepperPath)).map((pepper) => pepper.version) : [];
  await source.connect();
  await target.connect();
  const report = await verify(source, target, contract, keyring, {pepperVersions});
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.ok ? 0 : 1;
} catch {
  process.stderr.write("Verification could not complete. Check the approved inputs, TLS, contract, schema and keyring locally.\n");
  process.exitCode = 2;
} finally {
  await Promise.allSettled([source?.end(), target?.end()]);
}
```

From the checkout root, after local inputs are set and the execution scope is
confirmed, the invocation is:

```sh
umask 077
node --import tsx /path/to/private/run-contract.mjs /path/to/private/contract.json > /path/to/private/verification-report.json
```

Exit 0 means every check requested by that contract passed; exit 1 means at
least one check completed and failed; exit 2 means verification could not
complete. On 0 or 1, stdout is the JSON report. On 2, stderr contains only the
fixed message above; inspect provider/connection errors locally without
forwarding them. Transactions are read-only repeatable-read, with UTC, statement
timeouts, row-security fail-closed behavior and rollback on both connections.

Return the exact verifier commit, importer commit, original contract revision,
exit code and redacted JSON report (counts, checksums, IDs and check statuses).
Do not return local URLs, certificate paths, keyring inputs, raw rows or driver
logs. Preserve a failing report as evidence; do not rewrite skips or revisions.

A `.7` contract stays `.7` and provides lower-level database evidence only.
This API does not reconcile the importer report, dynamic skip keys, ownership
snapshots or all continuity gates. It does not qualify copied credentials or
execute the six application smokes, which remain pending. `verifyImport` requires
matching report, database ledger and mapping revisions; `.7` artifacts cannot be
relabeled as `.11` qualification. Any new import/rerun needs its own approved
scope; this recipe performs no import, grant, refresh or schema mutation.
