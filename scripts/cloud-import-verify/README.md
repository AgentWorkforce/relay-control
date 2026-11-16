# Cloud identity import verification (NESN-32)

This directory owns the independent verifier and synthetic dry-run harness.
The importer and authoritative mapping belong in `../cloud-import/`.

**Current scope:** the engine and its reference fixtures work independently of
the importer. `synthetic-reference-v1-NOT-production-mapping` is an explicit
placeholder revision. The importer has not yet published `mapping.ts`; the
production table projections, skip rules and importer invocation must be wired
and reviewed against that contract before this can qualify an import. Passing
these tests proves the verifier's detection behavior, not an actual import.

## Run focused checks

Requires Node >=22, real `npm ci` in this worktree, and PostgreSQL >=15 binaries.
The harness initializes a disposable local cluster, runs one test worker,
stops Postgres in cleanup, and removes the cluster on success. Failed synthetic
clusters are stopped and retained for debugging. It never uses inherited
database URLs or an existing server. PostgreSQL uses 16MB shared buffers,
1MB work memory, ten maximum connections and no parallel workers.

```sh
npm ci --no-audit --no-fund
npm run typecheck
CLOUD_VERIFY_PG_BIN=/opt/homebrew/opt/postgresql@15/bin \
  node --import tsx scripts/cloud-import-verify/dry-run.ts \
  --report /tmp/cloud-import-synthetic-report.json
```

Omit `CLOUD_VERIFY_PG_BIN` when `initdb` and `postgres` are available to Node
through `PATH`. `--report` is optional. Only the synthetic fixtures are seeded;
there is no Neon/Supabase connection and no production importer invocation.
The fixtures include `rw_actual-text-01` and `rw_not_a_uuid_02` Cloud workspace
identifiers alongside their distinct UUID identity column.

The test file is `test/cloud-import-verify.test.ts`. Normal repository test
runs skip its database cases with an explicit reason; only this harness starts
their isolated cluster. Code under `scripts/` and tests under `test/` are both
covered by the root `npm run typecheck`.

The suite covers passing imports, equal-count payload corruption, per-org
counts, missing rows, wrong orgs, wrong `rw_` mappings, FK orphans after trigger
bypass, composite `MATCH FULL`, failed concurrent unique-index builds,
partial/expression/NULLS NOT DISTINCT indexes, stale bigint sequences,
current/previous keyring decryption, insufficient samples, duplicate projection
keys, multiple cursor batches, exact large JSON numbers, timestamp/JSON
normalization, read-only transactions, cleanup and CLI exit/redaction behavior.

## Contract and CLI

`verify.ts` exports `Contract` and `verify(sourceClient, targetClient, contract,
keyring)`. `fixtures.ts:fixtureContract()` is a runnable example of the contract.
Use two separate connected `pg.Client` instances. The CLI accepts a JSON file:

```sh
# Supply both loopback database URLs through the environment, plus Control's
# SELFHOST_ENCRYPTION_KEY_ID / SELFHOST_ENCRYPTION_KEY (or its existing _FILE
# mechanism), and optional SELFHOST_ENCRYPTION_PREVIOUS_KEY_ID / _KEY.
node --import tsx scripts/cloud-import-verify/cli.ts /path/to/contract.json
```

URL variables are `CLOUD_VERIFY_SOURCE_URL` and `CLOUD_VERIFY_TARGET_URL`.
The CLI currently accepts only literal `127.0.0.1` / `::1` hosts and refuses
connection-option overrides that could redirect the connection. Remote
execution requires separate authorization through the lead and a reviewed
change; this tool does not provide a remote opt-in switch.

Exit codes: **0** = all database checks passed; **1** = a completed check failed;
**2** = verification could not complete. Application smoke entries stay pending
even when the database report passes. SQL/driver errors are not serialized
because they can contain credentials or row contents.

Each named table and identity comparison supplies `sourceSql` and `targetSql`.
Both must produce the same named columns, including a unique non-null `__key`
and nullable `__org`. SQL is trusted, reviewed configuration. Projections must:

- Include each mapped row in the source and its corresponding imported target
  scope. Make importer skip reasons explicit; do not hide unexplained drops
  with a target filter. Reconcile skipped rows with the importer JSON ledger.
- Use Cloud `uuid` as `__key` and Control `id` as `__key` for people, orgs and
  workspaces. For workspace identity comparisons, additionally project Cloud
  `id` as `cloud_relay_workspace_id` and the matching Control text column.
- Include the same org identity on both sides. A genuinely global table can
  use `NULL::text AS __org`; membership joins must use a stable composite key.
- Normalize intentional transformations in the reviewed projection, including
  timestamp precision, JSON types, roles and nullable defaults. Use explicit
  aliases and avoid `SELECT *`. Do not put secrets in compared columns.
- Exclude randomized encrypted envelopes from byte checksums; test each mapped
  encrypted column via `encryptedSamples` using Control's real decrypt routine.
  Each sample SQL returns `ciphertext`, with a deterministic `ORDER BY`, a
  positive minimum and a limit of at most 1,000. Empty samples fail.

Checksums are SHA-256 over length-framed, server-canonical JSONB row text, sorted
with the C collation. JSON numeric precision stays on the server; the verifier
never parses compared row values as JavaScript numbers. Rows stream in batches
of 250; one count/hash accumulator is retained per org. Output includes the
source and target total, checksum, invalid-key count and per-org counts/hashes.

`targetRelations` lists every imported target relation, schema qualified.
The verifier scans its actual FK data (including composite keys), constraint
validation flags, unique-index data, validity/readiness and owned sequence
state. It does not advance sequences. UUID-only tables report sequence checks
as `not_applicable`. Sequences must have a next value strictly beyond imported
data in their increment direction, within bounds, and not cycle.

Freeze writes before checking: the source and target use independent
repeatable-read snapshots, not a synchronized cross-database snapshot.
PostgreSQL sequences themselves are not MVCC snapshots. Each query has a
60-second timeout. This is a correctness checker, not a production impact
benchmark. Catalog scans apply to the whole listed target relation; comparisons
apply to the imported scope selected by the contract. Keep both databases on
the same PostgreSQL major version for byte-level JSON rendering comparisons.
Review schema coverage as well: catalog scans cannot infer a dropped constraint
that is absent from the reviewed target schema.

## Application smoke checklist

Record identity/org/workspace IDs, service build, timestamp, outcome and a
sanitized evidence pointer for every smoke. Never retain bearer tokens,
ciphertexts, decrypted credentials or provider response bodies in the receipt.
Use approved staging/local services and synthetic providers until authorized.

| Smoke | Action and required result |
| --- | --- |
| Login | Sign in as a migrated person using the deployed login method. `/cloud/api/auth/session` and `/api/v1/auth/whoami` identify the same Cloud UUID and intended membership. A revoked session is refused. |
| Workspace list | List `/api/v1/organizations/{organizationId}/workspaces` and Desktop's `/api/v1/auth/desktop/workspaces`. Compare IDs/names/roles to the source fixture and verify another org's workspace is inaccessible. |
| Relaycast key resolve | Resolve the migrated workspace using `/api/v1/workspaces/{workspaceId}/resolve`. Verify the UUID and `rw_` binding and use the resolved credential for one approved Relaycast request. Record success only, never the key. |
| Flows run | Through the deployed `relayfile-control` HTTP boundary, run one approved synthetic Flow using the migrated identity and credential broker. Verify workspace/run binding, terminal success and events. Do not read the Flows database. |
| Integration token refresh | With a synthetic provider, refresh one migrated integration credential, verify the next provider call succeeds and org/workspace binding remains correct. Confirm the rotated envelope decrypts with Control's keyring; keep the token out of evidence. |
| Desktop feed | Sign in with Desktop, choose the migrated workspace, and load its session/activity feed. Emit one synthetic event, verify it arrives once, then verify workspace switching cannot expose the other org's feed. |

The verifier emits all six as `pending`. A database `ok:true` is never evidence
that these application smokes ran.
