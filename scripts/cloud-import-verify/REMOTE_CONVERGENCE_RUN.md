# Credential convergence qualification

This is a new, separately authorized rerun phase. An initial apply verification
with `credentialConvergence: not_requested` is not convergence evidence. The
already completed historical rerun cannot be retroactively given a baseline.
Preserve its original artifacts; capture a new checkpoint only before a future
approved rerun using the fixed copier.

Use the reviewed exact verifier/importer heads and matching mapping revision.
Quiesce the target. Only Postgres credential blobs are supported. The checkpoint
covers all target credentials (native, relay-managed and copied) and all rows
in `coding_agent_credential_blobs`. It hashes complete row values and MVCC
xmin/ctid locally; checkpoint keys are hashed too. No plaintext is decrypted.
The checkpoint is private mode 600; findings expose counts only. Physical table
rewrites or other credential writers also cause failure.

After the initial apply and verification, and immediately BEFORE the convergence
rerun, copy this complete script to a private mode-600
`capture-credential-convergence.mjs`. Run from the checkout root with the same
approved `CLOUD_VERIFY_TARGET_URL` or `_FILE` and
`CLOUD_VERIFY_TARGET_CA_FILE` inputs as REMOTE_SNAPSHOT_RUN. There is no source,
Cloud key, R2 reader or Control keyring input.

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
  const { captureCredentialConvergence } = await localImport("scripts/cloud-import-verify/convergence.ts");
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[1] !== "--all-organizations") throw new Error("all_scope_and_output_required");
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") throw new Error("verified_tls_required");
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
  const snapshot = await captureCredentialConvergence(target);
  const file = await open(args[0], "wx", 0o600);
  try { await file.writeFile(`${JSON.stringify(snapshot, null, 2)}\n`); }
  finally { await file.close(); }
  process.stdout.write(`${JSON.stringify({ok: true, credentialRows: snapshot.credentials.length, blobRows: snapshot.blobs.length})}\n`);
} catch {
  process.stderr.write("Convergence capture could not complete. Check the approved target TLS inputs, all scope, Postgres blobs and a fresh private output path.\n");
  process.exitCode = 2;
} finally { await target?.end(); }
```

```sh
umask 077
node --import tsx /path/to/private/capture-credential-convergence.mjs /path/to/private/before-convergence.json --all-organizations
```

Require exit 0 and a new checkpoint file before executing the separately
approved copier-enabled rerun. Use fresh rerun apply/copy report paths. Then use
the updated complete runner from [REMOTE_COPY_RUN.md](REMOTE_COPY_RUN.md):

```sh
node --import tsx /path/to/private/run-copy-verify.mjs /path/to/private/rerun-apply.json --all-organizations --credential-copy-report /path/to/private/rerun-copy.json --previous-credentials /path/to/private/before-first-copy.json --previous-ownership /path/to/private/before-first-import.json --convergence-before /path/to/private/before-convergence.json > /path/to/private/rerun-verification.json
```

The original native/ownership baselines and this convergence checkpoint are
separate evidence. Never substitute one for another, relabel a later snapshot,
or regenerate a missing before-state from the current target.

A passing convergence report requires `credentialCopy: verified`,
`credentialConvergence: verified`, all-source scope and the production schema,
plus `ok: true`. Its `credential_convergence` finding must show all five
producer `writes` counters explicitly zero, zero credential/blob inserted,
removed or changed rows, and zero blob-version changes. Missing/invalid or
unknown write counters fail; nonzero reported writes fail even with unchanged
state. Equal row counts alone are insufficient, and same-value UPDATEs are
caught by tuple identity. Actual copied/updated outcome totals and selection
write counters must agree with the write receipt. The existing source/content,
selection, ledger, constraint and keyring checks still apply.

The producer receipt covers its documented statement outcomes; the independent
snapshot covers the two credential relations, not unrelated application writes.
Operator provenance is required: snapshots are evidence files, not signed
attestations. Return only verdict/count summaries and the report digest; retain
private artifacts locally. Application smoke evidence remains separate.
