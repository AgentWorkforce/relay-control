# Capture evidence before the approved apply and copier

Run this on the independently authorized rehearsal machine before the apply,
with all target writers stopped. It connects only to the approved temporary
target, with the strict TLS/read-only client configuration used by the verifier.
It does not access the source database, R2, Cloud AES key or Control keyring.
The loopback CLI remains unchanged.

Local inputs are `CLOUD_VERIFY_TARGET_URL` or `_FILE`, and
`CLOUD_VERIFY_TARGET_CA_FILE`. The existing reader must already have SELECT
access to both target credential metadata and owner-only `cloud_import_ledger`.
No privilege change or database mutation is part of capture.

Copy the block to a private mode-600 `capture-before.mjs`, then run from the
exact verifier checkout root. Supply two fresh private output paths: first
credential metadata, then ownership. Existing files are never overwritten.

```js
import { readFile, open } from "node:fs/promises";
import { createRequire } from "node:module";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

let target;
try {
  const require = createRequire(pathToFileURL(resolve("package.json")));
  const { Client } = require("pg");
  const localImport = (path) => import(pathToFileURL(resolve(path)).href);
  const { readSecret } = await localImport("src/config.ts");
  const { assertScope } = await localImport("scripts/cloud-import/mapping.ts");
  const { captureCredentialTarget } = await localImport("scripts/cloud-import-verify/credential-copy.ts");
  const { captureOwnership } = await localImport("scripts/cloud-import-verify/reconciliation.ts");
  const args = process.argv.slice(2);
  let scope;
  if (args.length === 3 && args[2] === "--all-organizations") scope = {orgIds: null};
  else if (args.length === 4 && args[2] === "--org-ids") scope = {orgIds: args[3].split(",")};
  else throw new Error("explicit_scope_and_two_output_paths_required");
  assertScope(scope);
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
  target = await clientFor("TARGET");
  await target.connect();
  // Each function manages and rolls back its own read-only transaction.
  const credentials = await captureCredentialTarget(target, scope);
  const ownership = await captureOwnership(target, scope);
  async function saveNew(path, value) {
    const file = await open(path, "wx", 0o600);
    try { await file.writeFile(`${JSON.stringify(value, null, 2)}\n`); }
    finally { await file.close(); }
  }
  await saveNew(args[0], credentials);
  await saveNew(args[1], ownership);
  process.stdout.write(`${JSON.stringify({ok: true, credentialRows: credentials.rows.length,
    ownershipRows: ownership.rows.length})}\n`);
} catch {
  process.stderr.write("Snapshot capture could not complete. Check approved target inputs, TLS, reader privileges, scope and fresh output paths locally.\n");
  process.exitCode = 2;
} finally {
  await Promise.allSettled([target?.end()]);
}

```

```sh
umask 077
node --import tsx /path/to/private/capture-before.mjs /path/to/private/before-copy.json /path/to/private/before-import.json --all-organizations
```

Use `--org-ids UUID,UUID` only for an approved matching subset. Each library
call manages a separate read-only repeatable-read transaction and rollback;
do not wrap the calls in another transaction. Hold the apply until capture
exits 0 and both files are complete. For the fresh empty target, the expected
stdout is `{"ok":true,"credentialRows":0,"ownershipRows":0}`. Exit 2 means
capture failed; file presence alone is insufficient to proceed.

Pass the first file as `--previous-credentials` and the second as
`--previous-ownership` to the copier-enabled [REMOTE_COPY_RUN.md](REMOTE_COPY_RUN.md)
command. The files contain hashed natural keys/selection flags and ownership
IDs only, never secret values. Keep them private (mode 600). They establish
before-state for verification and never authorize writes or deletions.

Read-only and timeout guarantees use in-session `BEGIN ... READ ONLY` and
`SET LOCAL`, followed by `SHOW transaction_read_only`, `SHOW transaction_isolation`,
`SHOW statement_timeout` and `SHOW lock_timeout`. The returned `sessionSafety`
records must show `on`, `repeatable read`, `1min` and `5s`. Libpq startup options
are not used: Supavisor session poolers can silently drop them. A real pooler
run must retain these returned settings as evidence; local tests alone do not
prove pooler behavior. A mismatch aborts before row or credential reads.
