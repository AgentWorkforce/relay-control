# Selection divergence counters

The verifier emits the separate `selection_diverged` finding. Differences are
visible diagnostics because selection belongs to Control after insertion;
they do not waive failed written-selection, cardinality, content, ownership,
ID-link, write-receipt or convergence checks. Missing/unlinked rows still fail.

Copier follow-up field:

```ts
selectionDiverged: Record<string, { active: number; harness: number }>;
```

Keys are lowercase organization UUIDs, scoped to the run. This is a sparse map:
omit entries where both counts are zero; use `{}` when there are no differences.
Both fields are required nonnegative safe integers, with no extra fields. Never
include credential IDs, provider/account names, secrets or flag values. The
existing report mappingRevision binds the semantics; no separate version is
needed. Unknown organizations and malformed counts fail verification.

The counting unit is **distinct linked Control credential flags**, not groups
or writes. One credential can increment active and harness independently.

1. Metadata: use the effective `sourceQuery("coding_agent_credentials", scope)`
   rows with `skip_reason IS NULL` and `auth_type = 'relay_managed'`. These flags
   include the import mapping's active-row normalization and forced harness-off
   rule. Compare by preserved UUID against the actual target row, including org
   and workspace links. They are deliberately absent from table checksums.
2. Copied credentials: use independently decrypted usable source candidates and
   validated actual Control-ID/natural-key links. Provider-OAuth duplicates use
   the freshest/lowest-ID winner with the group's OR-ed flags. If several other
   source rows link to the same Control credential, OR their flags too and count
   that target ID once. Skip unmapped/excluded source rows in the counts; their
   existing independent failure/exclusion checks remain authoritative.
3. Compare each expected flag with the actual target flag. Increment that org's
   corresponding counter when different, then sum metadata and copied counts.
   Control-native rows with no Cloud counterpart are not counted themselves.
   Demotions caused by resolving Cloud's per-user choices into one Control
   workspace choice are visible differences even when selection is valid.

The verifier recomputes counts inside its read-only source/target snapshots;
the producer field never supplies the expectation. The current `.27` producer
does not yet supply the field, which is explicitly `not_reported` rather than
reported as zero. Once supplied, it must exactly match recomputed counts;
mismatches fail the report and credential-copy qualification. The independent
finding is always emitted, including metadata-only runs (`not_requested` for
the absent copier). This preserves diagnostics while the follow-up lands.

Exports in `selection-divergence.ts` include `SelectionDiverged`,
`reportedSelectionDiverged(value, knownOrganizations)` and
`selectionDivergence(source, target, scope, linkedCopied?, unmappedCopied?, reported?)`.
The read helper requires caller-owned frozen read-only transactions and exposes
fixed counts only. It never mutates rows or reads credential objects.
