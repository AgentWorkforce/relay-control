# Reviewed target schema and verification scope

`schema-manifest.json` is a committed reference built from all 64 checked-in
Control migrations (main `b79cb5f` plus 0068), in a fresh disposable local PostgreSQL
cluster. It is never generated from the target being qualified. Its seal covers
all expected entries and migration file hashes; verification also checks the
migration files in the verifier checkout still match those hashes.

The mandatory inventory has 99 tables and 1,822 logical catalogue objects.
It covers tables/relation kind and RLS flags, column types/positions/nullability/
defaults/identity/generated/collation, constraints and definitions/validation/
deferral/FK-trigger state, indexes and definitions/predicates/validity/readiness/
NULL semantics, user triggers, migration-owned functions and sequences. OIDs,
row contents and mutable sequence positions are excluded. Actual catalogue reads
also expose unexpected non-extension public relations, functions/sequences and
custom types; unknown object names/bodies are not echoed in reports.

Missing tables, columns, constraints or indexes are failures even when the
source has zero corresponding rows. A same-name weakened index/constraint or
validator function is a definition mismatch. Constraint/index presence cannot
be inferred from the constraints/indexes that happen to remain. A schema
failure stops subsequent data/credential checks; a skipped check cannot mark
the copier verified. Column discovery uses pg_catalog, not privilege-filtered
information_schema gating. Inaccessible data fails closed rather than becoming
an empty target.

The manifest keeps a generic map of separately identified optional inventories;
it is currently empty. The staff-grant table from the checked-in 0061 migration
is part of the required inventory like every other migration. If an optional
inventory is ever present, all of its expected objects must match and the
report profile is `main-plus-optional`, which the cutover guard rejects; the
production profile is `main`.

Qualified reports expose `targetSchema` with the baseline, committed manifest
seal, expected/actual schema digests, object counts and missing/changed expected
names. Unexpected objects contribute a count and digest, never untrusted names
or definitions. Extensions belong to the provider and their member objects are
excluded. This is a logical Control schema check, not a dump of provider roles,
extension implementation or physical storage state.

For a reviewed migration update, generate a candidate only through the isolated
synthetic harness:

```sh
CLOUD_VERIFY_PG_BIN=/opt/homebrew/opt/postgresql@15/bin node --import tsx scripts/cloud-import-verify/dry-run.ts --write-schema-manifest /tmp/candidate-schema-manifest.json
```

Inspect the migration hashes and complete object diff against the committed
manifest and request review before accepting an update. Never regenerate an
expected manifest from a production or rehearsal target to clear a failure.
The compact file has one object per line so a named constraint/index diff is
reviewable. A changed PostgreSQL deparser representation is a failure to
investigate, not an automatic normalization or waiver.

Every `verifyImport` report contains normalized `scope` (lowercase, sorted,
deduplicated UUIDs, or `orgIds:null` for all) and `sourceOrganizationCensus`.
The census streams every source organization independently of the requested
subset, returns all-source and selected counts and length-framed SHA-256 UUID
digests, and rejects unknown requested organizations. A subset result may pass
for its declared subset while another organization is corrupt; it remains
explicitly a subset result.

The final identity/copy runners accept only `--all-organizations`. They call
`requireAllSourceScope` before report/secret reads or connection, then check
`cutoverScopeFinding` on the returned result. That requires identity-import
evidence, all-source scope, a matching nonempty all/selected census and the
production `main` schema profile. The copier runner additionally requires
`credentialCopy:verified`. Contract-only reports are labeled `contract-only`
and cannot pass this guard. Application smoke checks remain separate/pending.

The ordinary offline test suite compares every migration filename/hash against
the committed manifest, so a newly merged or changed migration fails CI until
its inventory update is reviewed. This check does not require PostgreSQL and
cannot silently skip with the integration tests. Baseline b79cb5f adds only the
43 catalogue objects from 0059 relay-node credentials and 0060 relay-launch
credentials; the earlier 1,777 required definitions remain identical. 0068
(users.signup_source) adds exactly 2 more: the nullable text column and the
validated `users_signup_source_known` CHECK; the 1,820 prior definitions are
unchanged.
