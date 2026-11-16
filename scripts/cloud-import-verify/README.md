# Cloud identity import verification (NESN-32)

This directory owns the independent verifier and synthetic dry-run harness.
The importer and authoritative mapping belong in `../cloud-import/`.

`import-contract.ts` binds the verifier to the published
`scripts/cloud-import/mapping.ts` from importer PR #155. It uses
`MAPPING_REVISION`, shared comparisons, target specs/relations and encrypted
sample definitions. PR #148 is stacked on the importer branch.

The harness executes the actual importer against its synthetic Cloud fixture
and separate source/target databases. It checks rollback mode, committed apply
and a second apply, reconciles all ten mapped tables and per-org ledgers, preserves
invite hashes and proves sessions/reconnect state stay empty. The checked-in
`import-report.example.json` is that synthetic receipt; application smokes are
pending and no real-data import has run.

The target uses all checked-in Control migrations (through 0051 at the initial
integration) plus test-only models of the optional 0053/0056/0057/0058 shapes
from separate schema PRs. These models exercise the new columns/types; they
do not prove those pending migration files themselves. The shared Cloud fixture
now includes the generation column, so there is no verifier-owned source guard.
The smaller fixtures in `fixtures.ts` independently
stress the engine and are explicitly labeled as reference shapes.

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
through `PATH`. `--report` is optional and writes the actual importer's synthetic
verification receipt. There is no Neon/Supabase connection or production run.
The fixtures follow the plan's identifier shapes: `workspaces.id` is a UUID,
`workspaces.relay_workspace_id` references text `relay_workspaces.id` values
such as `rw_000000a1`, and `relay_workspaces.relaycast_workspace_id` contains a
distinct provider ID. Both the UUID and `rw_` → provider joins are checked.
Users/orgs also have UUID `id` columns; active-only membership filtering and
lowercase email/name fallback are represented. These are reduced synthetic
shapes, not the final importer contract. JSON/precision stress payloads live in
separate `payload_probe` tables and do not imply a production workspace column.

The test files are `test/cloud-import-verify.test.ts` and
`test/cloud-import-verify-integration.test.ts`. Normal repository test
runs skip their database cases with an explicit reason; only this harness starts
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

For an actual importer ledger against local synthetic databases:

```sh
node --import tsx scripts/cloud-import-verify/import-cli.ts /path/to/import-ledger.json --all-organizations
# Or use an explicit UUID cohort:
node --import tsx scripts/cloud-import-verify/import-cli.ts /path/to/import-ledger.json --org-ids UUID,UUID
```

Supply `CLOUD_VERIFY_SOURCE_URL`, `CLOUD_VERIFY_TARGET_URL`,
`CLOUD_CREDENTIAL_ENCRYPTION_KEY` (Cloud's 64-hex AES key, shared with the importer) and Control's
usual keyring variables through the environment or their `_FILE` variants.
Pepper coverage uses `SELFHOST_PASSWORD_PEPPER_FILE`. The explicit scope must
match the ledger; a plan or rollback-mode ledger cannot qualify committed data.

The adapter discovers optional target columns instead of trusting the ledger.
It independently reconstructs source-query skips, decrypt failures and legacy
Desktop source-ID exclusions inside the same read-only snapshots as the
checksums. It checks candidate/import/skip totals and every per-org import
count, and compares the exact `importerSkips` key sets by reason against those
independently derived from source rows. Ledger counts alone never authorize excluding a row. Dynamic exclusions
use independently derived keys and still block qualification as unresolved
data-loss cases. Missing `rw_` storage and legacy `rw_` values normalized away
by the importer also block continuity qualification, even if checksums match.
Dropped History route fields or populated origin/generation metadata omitted
by an older target schema also block qualification; normalization to NULL must
not silently redirect a workspace to the default History service.
Source metadata streams in batches of 250, with a 10,000-key exclusion cap that
refuses excessive unresolved skips. Encrypted samples stay within the cohort;
empty mapped secret tables are explicitly not applicable based on observed
source/import counts.

The shared mapping supplies workspace projections and scoped encrypted samples
directly. Coding-agent `relay_managed` rows are also checked; a target lacking
0058 support accounts for their excluded keys and blocks qualification. No
external coding-agent credential-store secrets are read or copied.

The library entry point is `verifyImport(source, target, scope, ledger, keyring,
cloudKeyHex, {pepperVersions})`. For standalone comparisons without an importer
ledger, the lower-level API remains available:

`verify.ts` exports `Contract` and `verify(sourceClient, targetClient, contract,
keyring, {pepperVersions})`. The final options argument is optional.
`fixtures.ts:fixtureContract()` is a runnable example of the contract.
Use two separate connected `pg.Client` instances. The CLI accepts a JSON file:

```sh
# Supply both loopback database URLs through the environment, plus Control's
# SELFHOST_ENCRYPTION_KEY_ID / SELFHOST_ENCRYPTION_KEY (or its existing _FILE
# mechanism), and optional SELFHOST_ENCRYPTION_PREVIOUS_KEY_ID / _KEY.
node --import tsx scripts/cloud-import-verify/cli.ts /path/to/contract.json
```

The importer's `--verifier-contract` JSON is accepted directly, including its
empty `identities` array: identity keys remain part of the table checksums.
This lower-level command does not reconcile the importer ledger or apply the
additional continuity gates. Use `import-cli.ts` for full import qualification.

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
and nullable `__org`. Workspace-scoped comparisons additionally set
`workspaceScoped: true` and project non-null `__workspace` on both sides.
Their reports contain per-workspace counts and checksums as well as per-org
summaries; other comparisons explicitly report workspace summaries as null.
SQL is trusted, reviewed configuration. Projections must:

- Include each mapped row in the source and its corresponding imported target
  scope. Make importer skip reasons explicit; do not hide unexplained drops
  with a target filter. Reconcile skipped rows with the importer JSON ledger.
- Use Cloud's UUID-valued `id` as `__key` and Control `id` as `__key` for people,
  orgs and workspaces. For workspace identity comparisons, additionally project
  Cloud `workspaces.relay_workspace_id` as `cloud_relay_workspace_id` and the
  matching Control text column. Separately join `relay_workspaces.id` to compare
  the Relaycast provider ID; an `rw_` value must never be used as that provider ID.
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

Sequences without an owned table column, including `desktop_feed_publish_seq`,
must be listed in `standaloneSequences`. Each entry names its target `relation`
and source/target bounds queries that each return one row with `min_value` and
`max_value`. The next sequence value must be beyond both data bounds, using
exact bigint arithmetic. These reads never call `nextval` or `setval`.

`pepperChecks` entries query only `pepper_version` from each relevant credential
table. Every non-null version must exist in the supplied `pepperVersions`.
The CLI obtains these versions through Control's `readPepperFile` and
`parsePepperFile` using `SELFHOST_PASSWORD_PEPPER_FILE`, retaining the existing
ownership and mode-600 permission checks. No hash or pepper value enters a
report; absent files fail coverage when any stored version is non-null.

Freeze writes before checking: the source and target use independent
repeatable-read snapshots, not a synchronized cross-database snapshot.
Use direct or session-mode database connections; transaction poolers cannot
support the cursor/snapshot contract.
PostgreSQL sequences themselves are not MVCC snapshots. Each query has a
60-second timeout. This is a correctness checker, not a production impact
benchmark. Catalog scans apply to the whole listed target relation; comparisons
apply to the imported scope selected by the contract. Keep both databases on
the same PostgreSQL major version for byte-level JSON rendering comparisons.
Review schema coverage as well: catalog scans cannot infer a dropped constraint
that is absent from the reviewed target schema.

## Cohort qualification

The source-verified plan requires a one-time, repeatable import per cohort.
Before a cohort can be marked ready:

1. Pin the importer and verifier to the same `mapping.ts` revision. Reconcile
   raw source counts with imported rows and every skipped row/reason in its
   JSON ledger, including active-only memberships, unresolved users and unbound
   workspaces. A passing projection alone cannot prove skip accounting.
2. Run the actual-importer synthetic harness and repeat against the intended
   target's finalized migrations before a cohort run. It already exercises
   rollback/apply/rerun, open invite deduplication and agent identity uniqueness;
   pending optional migration files still need their own schema proof.
3. Check transformed identity tables: users' deferred `last_*` references,
   refreshed invite hashes, re-encrypted person/Desktop/hosted-participant
   tokens, Desktop `source_id` text-to-UUID handling and derived fleet fields.
   Unsupported inputs must fail or have explicit reviewed skip accounting.
4. On a fresh target, assert that Cloud browser/API sessions, device grants,
   CI/durable tokens, MCP grants and reconnect-only state were not imported.
   Existing target operator sessions require an explicit scoped baseline.
5. Freeze cohort identity writes, including memberships, invites, workspace
   creation and Desktop sync, before the final delta and verifier snapshots.
   Finish the six application smokes below before flipping authenticated routes.
   Database checks do not authorize routing changes or a deployment.
6. Obtain the infrastructure owner's approved restore-proof receipt for the
   destination. The local synthetic harness does not qualify a production
   project restore and never provisions or accesses Supabase.

The synthetic importer integration is exercised locally. Real cohort execution,
application smokes and restore proof remain pending. Rollback keeps the source
intact; writes created in Control after cutover need separate reconciliation.

## Application smoke checklist

Record identity/org/workspace IDs, service build, timestamp, outcome and a
sanitized evidence pointer for every smoke. Never retain bearer tokens,
ciphertexts, decrypted credentials or provider response bodies in the receipt.
Use approved staging/local services and synthetic providers until authorized.

| Smoke | Action and required result |
| --- | --- |
| Login | Force a fresh login with the deployed method. `/cloud/api/auth/session` and `/api/v1/auth/whoami` identify the preserved UUID and membership. Old Cloud cookie/access/refresh credentials must fail Control authentication, introspection and refresh consistently; a revoked new session is refused. Test duplicate Cloud/Control cookies in both header orders and verify the agreed clearing/renaming behavior. |
| Workspace list | List `/api/v1/organizations/{organizationId}/workspaces` and Desktop's `/api/v1/auth/desktop/workspaces`. Compare IDs/names/roles to the source fixture and verify another org's workspace is inaccessible. |
| Relaycast key resolve | Resolve the migrated workspace using `/api/v1/workspaces/{workspaceId}/resolve`. Verify the UUID, preserved `rw_` binding and distinct provider ID, then use the resolved credential for one approved Relaycast request. Confirm a Relayfile lookup still reaches its existing `rw_` namespace. Record success only, never the key. |
| Flows run | Through the deployed `relayfile-control` HTTP boundary, run one approved synthetic Flow using the migrated identity and credential broker. Verify workspace/run binding, terminal success and events. Do not read the Flows database. |
| Integration token refresh | With a synthetic provider, refresh one migrated integration credential, verify the next provider call succeeds and org/workspace binding remains correct. Verify existing Nango connection lookup uses the preserved `rw_` identity where applicable. Confirm the rotated envelope decrypts with Control's keyring; keep the token out of evidence. |
| Desktop feed | Sign in with Desktop, choose the migrated workspace, and load its session/activity feed. Emit one synthetic event, verify it arrives once, then verify workspace switching cannot expose the other org's feed. |

The verifier emits all six as `pending`. A database `ok:true` is never evidence
that these application smokes ran.
