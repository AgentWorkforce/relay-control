# Cloud identity import

This is a one-way, re-runnable copy of hosted Cloud identity rows (schema `public`) into relay-control. The verifier lives in `../cloud-import-verify` and binds to the contract in `mapping.ts`.

## Run

```sh
# Plan: reads the source only and prints the ledger. Nothing is written.
node --import tsx scripts/cloud-import/cli.ts --mode plan --report /tmp/plan.json

# Dry run: performs every write inside one transaction, then rolls it back.
node --import tsx scripts/cloud-import/cli.ts --mode dry-run --report /tmp/dry.json

# Apply: users in batches, then one transaction per organization.
node --import tsx scripts/cloud-import/cli.ts --mode apply --org <uuid> --report /tmp/apply.json \
  --verifier-contract /tmp/contract.json
```

The CLI reads its settings from the environment. Each variable also accepts a `NAME_FILE` form, and none is ever passed as an argument:

| Variable | Meaning |
| --- | --- |
| `CLOUD_IMPORT_SOURCE_URL` | The Cloud database. Use a read-only role on a branch or replica. |
| `CLOUD_IMPORT_TARGET_URL` | The Control database. Connect directly or through a session-mode pooler, never transaction mode. Not needed for `plan`. |
| `CLOUD_CREDENTIAL_ENCRYPTION_KEY` | Cloud's 64-hex credential key, used to decrypt agent-token envelopes. |
| `SELFHOST_ENCRYPTION_KEY_ID`, `SELFHOST_ENCRYPTION_KEY` | Control's keyring, read exactly as the service reads it. |

**Exit codes**
- **0:** every organization was imported.
- **1:** the run was refused (see `refused`), or an organization failed (see `orgs[id].error`).
- **2:** usage or configuration error.

**Output**
- Logs and reports carry counts, Cloud UUIDs and SQLSTATE/constraint names only.
- They never carry emails, tokens, ciphertext, keys or driver messages.
- Report files are written with mode 600.

## Guarantees

- **Consistent source read:** the source is read in one `REPEATABLE READ, READ ONLY` transaction.
- **Stable ids, safe re-runs:** ids are the Cloud ids, and every write is an upsert on the primary key, so a re-run converges.
  - Re-encrypted columns get fresh ciphertext on each run.
  - Invite token hashes are written on insert only.
- **Skips are always explained.** Every candidate row is either imported or counted under a stable skip reason:
  - `mapping.ts` defines the SQL-side reasons.
  - `IMPORTER_SKIP_REASONS` lists the importer-side ones, whose ids are listed in `importerSkips`.
- **Optional columns follow the target:** columns from migrations 0053, 0056 and 0057 are written only when the target has them (`optionalColumns` in the report). Before 0057, Desktop identities with a non-UUID `source_id` are skipped, and `node_name` falls back to the node id.
- **Refusals:** the import refuses to run against a target whose migration ledger lacks `0051`, or where an imported email already belongs to a different Control user.

## Deliberately not migrated

| What | Consequence |
| --- | --- |
| Browser and bearer sessions, refresh tokens, device codes, CI tokens | Everyone signs in again. |
| OIDC subjects | Control matches users by email. |
| MCP OAuth grants | Connectors re-authorize. |
| Billing | Stays in Cloud. |

**Invites**
- The Cloud invite token is not carried over. Each open invite gets a new `sh_inv_` hash whose token is discarded.
- Sign-in auto-accepts open invites by email, and an admin's "Copy link"/"Resend" issues a working link.
- Imported invites have no `invitation.create` audit row.

**Coding-agent credentials and GitHub App connections** are follow-ups and are not in this tool yet.

## Target prerequisites

The target must run `SELFHOST_TENANCY=multi`, because Cloud has many organizations.
