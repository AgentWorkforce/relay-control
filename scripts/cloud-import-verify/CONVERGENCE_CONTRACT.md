# Convergence checkpoint and producer receipt contract

Module: `scripts/cloud-import-verify/convergence.ts`.

```ts
computeCredentialCheckpoint(tx: SqlExecutor, scope: ImportScope): Promise<ComputedCredentialCheckpoint>
validateCredentialCheckpoint(value: unknown, scope: ImportScope): CredentialConvergenceSnapshot
credentialCheckpointDigest(state: CredentialCheckpointState): string
```

`SqlExecutor` is the existing interface in `src/database.ts` (`query`, `exec`).
The caller owns the transaction. It must set repeatable-read isolation before
calling compute; the helper checks the actual setting. The helper does not
begin, commit, roll back or write data. It uses in-session statement/lock
limits, UTC/ISO formatting and `row_security=off` for consistent complete reads.
Only `scope.orgIds === null` is currently supported; subset convergence is
refused. Provider OAuth blob storage must be Postgres.

Snapshot version is **2**. Captures have `kind: credential-convergence`,
`phase: before|after`, the mapping revision, all-org scope, observed read-only
session settings, credential/blob/copier-marker hashed state, `digest`, and a
fresh 32-byte random nonce encoded as 64 lowercase hex characters. Before
validation requires nonempty credential state. Version 1 has no binding and
cannot qualify. Read-only capture functions generate a fresh nonce per capture.

`computeCredentialCheckpoint` returns the independently read state plus
`digest`, without a nonce or phase. Digest encoding is lowercase hex SHA-256
of UTF-8 canonical JSON over exactly:

```text
{version:2, mappingRevision, scope, credentials, blobs, markers}
```

Object keys are recursively sorted by JavaScript lexical order; each relation's
row array is sorted by its hashed `key`. Entries contain `key`, `stateSha256`
and `blobVersion`. The per-row state digest covers PostgreSQL `to_jsonb(t)::text`
in UTC plus xmin and ctid. Checkpoint metadata (`kind`, `phase`, `nonce`, session
settings) is excluded from the state digest so a fresh transaction can compute
the same value. The nonce is bound separately in the receipt.

The producer CLI must load and validate `--convergence-checkpoint` BEFORE any
writes. In its own fresh transaction, it computes the actual target state and
refuses without writing if the digest differs. The pattern is:

```ts
const checkpoint = validateCredentialCheckpoint(parsedFile, scope);
const convergence = await target.transaction(async (tx) => {
  await tx.exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
  const current = await computeCredentialCheckpoint(tx, scope);
  if (current.digest !== checkpoint.digest) throw new Error("checkpoint_mismatch");
  return {beforeDigest: current.digest, nonce: checkpoint.nonce};
});
// Only after that succeeds may the separately authorized apply/copy start.
// The actual run receipt carries this value, never a post-hoc reconstruction:
report.convergence = convergence;
```

The writer must keep the target quiescent across that check and its run. Its
receipt still contains all five actual write counters. The verifier compares
`report.convergence.beforeDigest` with the supplied before checkpoint's verified
state digest and requires the receipt nonce to match. Both must be strings of
64 lowercase hex characters; absent, malformed or additional receipt fields
fail. Reports and checkpoints must share the same mapping revision.

A post-rerun capture has a new nonce and current state. Relabelling it `before`
does not recreate the original receipt binding. Even replaying the old nonce
cannot replace the independently computed before digest after tuple changes.
A fabricated all-zero report with an empty checkpoint also fails. None of these
checks treats a manually edited producer receipt as an authenticated signature;
operator-held actual-run artifacts and provenance are still required.
