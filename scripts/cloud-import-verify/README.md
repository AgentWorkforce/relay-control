# Cloud identity import verification (NESN-32)

This directory owns the independent verifier and synthetic dry-run harness.
The importer and authoritative mapping belong in `../cloud-import/`.

`import-contract.ts` binds the verifier to the published
`scripts/cloud-import/mapping.ts` from importer PR #155. It uses
`MAPPING_REVISION`, shared comparisons, target specs/relations and encrypted
sample definitions. PR #155 has merged; PR #148 now targets main.

The harness executes the actual importer against its synthetic Cloud fixture
and separate source/target databases. It checks rollback mode, committed apply
and a second apply, reconciles all thirteen mapped tables and per-org ledgers, preserves
invite hashes and proves sessions/reconnect state stay empty.
It then runs the opt-in credential copier against in-memory encrypted Cloud
objects and local encrypted Postgres blobs, including a repeat copy.
`import-report.example.json` is that full synthetic receipt; application smokes are
pending and no real-data import has run.

The target runs all checked-in Control migrations, including the actual
0053/0054/0056/0057/0058/0062 files and the owner-only 0063 ledger migration. Only the pending 0061 staff-grant schema uses a test-only
model; it does not prove that pending migration file. The shared Cloud fixture
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

The database tests are `test/cloud-import-verify.test.ts` and
`test/cloud-import-verify-integration.test.ts`; GET-only reader tests live in
`test/cloud-import-verify-readers.test.ts`. Normal repository test
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
# Capture ownership before the next local import:
node --import tsx scripts/cloud-import-verify/ownership-cli.ts /path/to/before.json --all-organizations
# After the importer commits, verify removals against that database snapshot:
node --import tsx scripts/cloud-import-verify/import-cli.ts /path/to/current-ledger.json --all-organizations \
  --previous-ownership /path/to/before.json
# Capture existing target credentials before the opt-in secret copy:
node --import tsx scripts/cloud-import-verify/credential-snapshot-cli.ts /path/to/credential-baseline.json --all-organizations
# After copying, verify its ledger and local object snapshot:
node --import tsx scripts/cloud-import-verify/import-cli.ts /path/to/import-ledger.json --all-organizations \
  --credential-copy-report /path/to/credential-copy-ledger.json \
  --previous-credentials /path/to/credential-baseline.json
```

Supply `CLOUD_VERIFY_SOURCE_URL`, `CLOUD_VERIFY_TARGET_URL`,
`CLOUD_CREDENTIAL_ENCRYPTION_KEY` (Cloud's 64-hex AES key, shared with the importer) and Control's
usual keyring variables through the environment or their `_FILE` variants.
Pepper coverage uses `SELFHOST_PASSWORD_PEPPER_FILE`. The explicit scope must
match the ledger; a plan or rollback-mode ledger cannot qualify committed data.

The importer reconciles exclusively from its transactional target
`cloud_import_ledger`; report files never authorize deletion. The verifier
checks the actual post-import ledger's keys/revisions against independently
derived source import keys and `OrgLedger.keys`. Before each delta,
`ownership-cli.ts` takes a scoped read-only database snapshot, written to
mode 600 without customer hosts or secrets. The harness captures the same
snapshot through `captureOwnership(target, scope)`.

With `--previous-ownership`, the verifier computes removed owned keys for
`RECONCILED_TABLES`, proves their target absence and reconciles per-org/global
logical `deleted` totals, including cascades. Positive deletion claims without
the pre-import database snapshot fail. An optional `--previous-report` adds an
old-report cross-check; it is not ownership authority. Other tables must report
zero deletions. Tests prove runtime SELECT/DELETE are denied on the ledger and
that reruns preserve unowned Control rows instead of claiming or deleting them.
Revision `.8` onward scopes target comparisons to the ownership ledger, so native
Control organizations, invitations and grants can coexist with imported rows.
Users remain global under the shared mapping contract.

Before the opt-in secret copy, `credential-snapshot-cli.ts` captures existing target credential
natural-key hashes and selection flags in a private mode-600 file. Supply it as
`--previous-credentials` when verifying. The library uses
`captureCredentialTarget(target, scope)` and `credentialCopy.previousTarget`.
The baseline contains no account ids, fingerprints or secret values. Unmatched
target credentials without baseline evidence fail; pre-existing native selections
must survive when this run copied no Cloud-selected row for that selector.

For `--credential-copy-report`, set `CLOUD_VERIFY_CREDENTIAL_OBJECTS_DIR` to a
local encrypted object snapshot using the Cloud-relative object keys. Files
must be owned by the process user and private (mode 600); resolved paths must
stay inside that directory. The CLI only reads local source files and target
Postgres blobs. It never creates a Cloud R2/S3 client, refreshes a token or
loads cloud-provider credentials. Remote object/backend evidence requires a
separately authorized caller supplying read-only readers to the library.

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
refuses excessive unresolved skips. Ownership manifests retain imported IDs
for comparison with the current report and captured database ownership; choose a bounded
cohort when memory is limited. Encrypted samples stay within the cohort; empty
mapped secret tables are explicitly not applicable based on observed counts.

The shared mapping supplies workspace projections and scoped encrypted samples
directly. Coding-agent `relay_managed` rows are also checked; a target lacking
0058 support accounts for their excluded keys and blocks qualification. No
external coding-agent credential store is accessed by the local harness.

`credential-copy.ts` verifies the store-copied rows by workspace, provider,
auth type and keyed fingerprint/account identity, never Cloud row id. It
derives expected keys from independently decrypted objects, reconciles the
copy ledger, checks scope/organization and compares decrypted inline secrets
or raw auth-file contents. Only counts and checksums enter reports. Copies
that deduplicate/reassign row ids are valid; missing copied natural keys,
wrong fingerprints, unreadable blobs and unresolved input failures are not.
Unmatched target credentials must be established by the pre-copy baseline;
copied rows must all match their source-derived natural keys and contents.
Suspended/non-members and unusable Cloud credentials are intentional exclusions.
A shared legacy object is never read when multiple rows could own it; missing
account objects in that case remain unresolved and block qualification.
SQL-imported `relay_managed` rows retain their Cloud ids and are compared
separately so the copier's additional rows cannot spoil those counts.

Selection checks require one model-active row when the group has model-call
credentials, and at most one sandbox selection. With credential-copy evidence,
the verifier independently derives Cloud's selected copied row by latest update
and Cloud id tie-break, checks the exact natural key selected, and reconciles all
six selection-report counters. A saved, unselected copy must stay inactive when
another row carries the selection. Auto-activation fallback conflicts block
qualification until reviewed and resolved. The copier can legitimately demote
SQL-imported relay-managed rows, so in this phase their selection flags are
checked by these group checks rather than the pre-copy SQL checksum shape.

Staff grants are copied as revoked history. Beyond their shared table projection,
the verifier requires revocation, the installation's operator organization, a
fresh-shaped token hash, null use/revocation actor fields and exactly one matching
import audit. Reruns preserve the hash and audit count. Missing source tables are
explicitly reconciled with the importer's warning; missing target support or
operator organization remains an unresolved skip.

The main synthetic fixture uses UTC sessions. A separate audit on PostgreSQL's
Europe/Oslo session timezone found that the importer's `created_at + interval
'90 days'` staff-grant clamp shifts one hour across DST compared with the
verifier's UTC snapshot. The fix merged in #168 at `c13c294`: both importer source transactions use
UTC, the default canonicalizer is Control's, and selection conflicts fail the
copy report. The dedicated PostgreSQL regression switches the source to Oslo,
proves UTC expiry and session restoration, and checks conflict failure.
The verifier retains UTC checks.

The library entry point is `verifyImport(source, target, scope, ledger, keyring,
cloudKeyHex, {pepperVersions, previousOwnership, previousReport, canonicalOrigin,
credentialCopy: {report, reader, targetBlobs, previousTarget}})`.
The copy option is optional: output explicitly marks this phase as
`not_requested`, `verified` or `failed`. Identity-only verification does not
qualify copied secrets. For standalone comparisons without an importer
ledger, the lower-level API remains available.

Revision `.6` deliberately excludes History origins from the shared SQL checksum
shape. A separate check defaults to Control's `canonicalRelayhistoryOrigin` from
`src/relayhistory-origin.ts` and accepts the same `canonicalOrigin` callback as
the importer. It compares stored
values and the private origin inventory, and reports only counts/mismatches.
Customer hosts are never echoed, including a tampered input report's origin list.

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
additional continuity gates. Use `import-cli.ts` for verification of its declared scope. All-source cutover
evidence requires the copier-enabled runner and its scope/schema guard.

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
   the remaining 0058 migration still needs its own schema proof.
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

The independently authorized rehearsal runner can integrate the library with
direct provider DNS and full TLS verification using [REMOTE_RUN.md](REMOTE_RUN.md).
That recipe leaves the loopback CLI unchanged and keeps older contract evidence
distinct from full import qualification.

Use [REMOTE_IMPORT_RUN.md](REMOTE_IMPORT_RUN.md) for matching-revision identity
qualification; the contract-only runner remains lower-level evidence.

The final copier-enabled qualification uses [REMOTE_COPY_RUN.md](REMOTE_COPY_RUN.md)
and must report `credentialCopy: verified`. Its source reader is GET-only; copied
Control IDs are cross-checked against independently derived natural keys.

Current copier reports must include #168's `controlIds` map. Each successful
Cloud row must map to a real Control row with its independently derived natural
key; missing, extra or mismatched links fail. Multiple Cloud rows may deduplicate
to one Control ID when their natural key agrees. The map never authorizes a skip
or excludes an unexplained target row.

Before the approved apply/copy, [REMOTE_SNAPSHOT_RUN.md](REMOTE_SNAPSHOT_RUN.md)
captures private credential and ownership before-state using the same strict
TLS/read-only library connection, without source/R2/keyring inputs.

Schema and scope requirements are documented in [SCHEMA_MANIFEST.md](SCHEMA_MANIFEST.md).
Qualified results always include normalized scope and the all-source org census.
Cutover runners require all-source scope and the reviewed production schema;
subset results and the proposed 0061 fixture profile are diagnostic evidence only.

Verification and pre-import snapshots establish their own in-session repeatable-
read, read-only transactions. They set a 60-second statement timeout and a
5-second lock timeout, then `SHOW` read-only mode, isolation and both timeouts
before reading data. Reports and new snapshots record the observed settings in
`sessionSafety`; a mismatch aborts. Remote recipes do not rely on libpq startup
options, which Supavisor can drop. The local harness proves these checks without
startup options; the authorized remote rehearsal must retain the actual pooler
settings as evidence.

`credential_natural_keys` separates source exclusions/reads from copied-target
checks. `contentFailures` counts copied target rows failing organization, status,
fingerprint, exact plaintext content, blob-backend or read/decrypt checks. Fixed
`contentFailureReasons` counters distinguish those causes without IDs, accounts,
object locations or driver errors. A row may contribute multiple reasons but
counts once in `contentFailures`. Matching natural-key checksums establish the
row identity set; they do not establish matching decrypted content. Source
`credential_not_usable` exclusions never increment `contentFailures`.
