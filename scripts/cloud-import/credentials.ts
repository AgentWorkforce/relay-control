// Opt-in copier for coding-agent secrets that Cloud keeps in its credential
// object store (Cloudflare R2, S3 API) rather than in Postgres.
//
// For each secret-bearing Cloud provider_credentials row (mapping.ts
// credentialCopyQuery) it reads the object the Cloud runtime reads, opens
// Cloud's envelope with the Cloud credential key and hands the secret to
// Control's own store seams, so validation, fingerprints, previews, blob
// envelopes and audit rows are exactly what the service writes:
//   byo_api_key    -> CodingAgentStore.putApiKey
//   oauth_token    -> CodingAgentStore.putSetupToken
//   provider_oauth -> SubscriptionLoginStore.storeLogin (raw CLI auth file)
// Those seams dedupe by key fingerprint / provider account, so a re-run
// converges. Control assigns its own row ids; the report maps outcomes by
// Cloud id. Nothing secret is logged or reported.
//
// Cloud object keys (prefix "credentials", see Cloud's credential-store.ts):
//   byo_api_key     {user}/{rowId}/credentials.json.enc
//   oauth_token     {user}/accounts/{rowId}/... then {user}/anthropic/...
//   provider_oauth  {user}/accounts/{rowId}/... when provider_account_id is
//                   set, then {user}/{provider}/credentials.json.enc
import type { EncryptionKeyring } from "../../src/crypto.js";
import type { Database, SqlExecutor } from "../../src/database.js";
import { CodingAgentError, type CodingAgentStore } from "../../src/admin/coding-agents.js";
import { describeAuthFile, type SubscriptionLoginStore, type SubscriptionProvider } from "../../src/admin/subscription-logins.js";
import type { CredentialBlobStore } from "../../src/admin/credential-blobs.js";
import { decryptCloudEnvelope } from "./importer.js";
import { assertScope, credentialCopyQuery, MAPPING_REVISION, type ImportScope } from "./mapping.js";

/**
 * Cloud's status and history on a row the copier just wrote (the store seams
 * reset them: status connected, last_authenticated_at now, no error).
 * Control's status CHECK allows connected|error|refresh_failed.
 */
async function preserveCloudState(target: SqlExecutor, id: string, row: Candidate): Promise<number> {
  const status = row.status === "connected" || row.status === "error" || row.status === "refresh_failed" ? row.status : "error";
  const result = await target.query<{ id: string }>(
    `UPDATE coding_agent_credentials
        SET status = $2, last_error = $3, refresh_attempts = $4,
            last_authenticated_at = $5::timestamptz, last_used_at = $6::timestamptz
      WHERE id = $1
      RETURNING id`,
    [id, status, row.last_error, row.refresh_attempts ?? 0, row.last_authenticated_at, row.last_used_at],
  );
  return result.rows.length;
}

/**
 * The import's own record of the login it last wrote: a cloud_import_ledger
 * row (owner-only, 0063) under table_name copier_login, row_key
 * "<controlId>:<blob_version>". The identity importer's reconcile reads only
 * its own table names, so these never reach it.
 */
const LOGIN_MARKER = "copier_login";

async function loginMarker(target: Database, organizationId: string, controlId: string): Promise<number | null> {
  const rows = (await target.query<{ row_key: string }>(
    "SELECT row_key FROM cloud_import_ledger WHERE organization_id = $1 AND table_name = $2 AND row_key LIKE $3",
    [organizationId, LOGIN_MARKER, `${controlId}:%`],
  )).rows;
  if (rows.length !== 1) return null;
  const version = Number(rows[0]!.row_key.slice(controlId.length + 1));
  return Number.isInteger(version) ? version : null;
}

/**
 * Records, inside storeLogin's own transaction, the version it just wrote:
 * the marker can only ever name the import's own write, never a version a
 * concurrent Control refresh produced (storeLogin and refresh share the
 * per-credential advisory lock).
 */
async function writeLoginMarker(tx: SqlExecutor, organizationId: string, stored: { id: string; version: number }): Promise<void> {
  await tx.query(
    "DELETE FROM cloud_import_ledger WHERE organization_id = $1 AND table_name = $2 AND row_key LIKE $3",
    [organizationId, LOGIN_MARKER, `${stored.id}:%`],
  );
  await tx.query(
    `INSERT INTO cloud_import_ledger (organization_id, table_name, row_key, mapping_revision)
     VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
    [organizationId, LOGIN_MARKER, `${stored.id}:${stored.version}`, MAPPING_REVISION],
  );
}

/** Reads one Cloud credential object; null when it does not exist. */
export interface CloudObjectReader {
  get(key: string): Promise<string | null>;
}

export type CredentialCopyDeps = {
  source: Database;
  /** Control's database, to leave a first-time copy of an unselected row inactive. */
  target: Database;
  reader: CloudObjectReader;
  cloudKeyHex: string;
  codingAgents: CodingAgentStore;
  logins: SubscriptionLoginStore;
  /** Control's credential blobs, to tell an unchanged login from a changed one. */
  blobs: CredentialBlobStore;
  keyring: EncryptionKeyring;
  log?: (event: string, fields: Record<string, unknown>) => void;
};

export type CredentialOutcome =
  | "copied"
  | "updated"
  | "already_present"
  | "control_newer"
  /** Another Cloud row for the same Control login (workspace, provider, account) won. */
  | "duplicate_login"
  | "blob_read_failed"
  | "object_missing"
  | "decrypt_failed"
  | "payload_invalid"
  | `store_rejected:${string}`
  | `skipped:${string}`;

export type CredentialCopyReport = {
  version: 1;
  mappingRevision: string;
  mode: "plan" | "apply";
  ok: boolean;
  candidates: number;
  outcomes: Record<string, number>;
  /** Cloud provider_credentials id -> outcome. Ids only. */
  rows: Record<string, CredentialOutcome>;
  /**
   * Cloud id -> the Control coding_agent_credentials id it was written to
   * (copied or already present). Copier rows are not in the import ledger,
   * so this is what a rollback deletes by.
   */
  controlIds: Record<string, string>;
  /**
   * Writes this run actually made, counted from statement outcomes (store
   * results and UPDATE ... RETURNING row counts), never inferred. A
   * converged re-run reports zero for every field.
   * - inserted: new Control credential rows (copied).
   * - updated: existing login rows rewritten because the Cloud content
   *   changed (updated).
   * - blobWrites: subscription-login blobs written (storeLogin calls).
   * - metadataWrites: rows whose Cloud status/history was written.
   * - selectionWrites: rows whose is_active/harness_active changed.
   */
  writes: { inserted: number; updated: number; blobWrites: number; metadataWrites: number; selectionWrites: number };
  /** How Cloud's selection was applied (see applyCloudSelection). */
  /**
   * selectionConflicts: groups where Cloud selected no copied row, no other
   * Control row was active, and a copy had been auto-activated: it is kept
   * active (never zero) and counted here for review.
   */
  selection?: { groups: number; active: number; harness: number; activeDemoted: number; harnessDemoted: number; selectionConflicts: number; writes: number };
};

/**
 * The store seams auto-activate the first credential per provider, so the
 * copier sets the selection explicitly afterwards, in one transaction, per
 * (workspace, provider) and per flag (is_active = LLM calls, harness_active
 * = sandbox, the latter for setup tokens and logins only):
 * - Cloud's selected row was copied in this run: it gets the flag and every
 *   other row in the group loses it.
 * - Otherwise only this run's copies lose it; Control-native, relay_managed
 *   and earlier rows are untouched. If that would leave no active LLM row
 *   where a copy had been auto-activated and nothing else is active, the
 *   copy keeps it and the group counts as a selection conflict.
 * Cloud selects per user, Control per workspace: the most recently updated
 * Cloud selection wins; the others are counted as demoted.
 */
export async function applyCloudSelection(
  target: Database,
  copied: Array<{ row: Candidate; controlId: string }>,
): Promise<NonNullable<CredentialCopyReport["selection"]>> {
  const summary = { groups: 0, active: 0, harness: 0, activeDemoted: 0, harnessDemoted: 0, selectionConflicts: 0, writes: 0 };
  await target.transaction(async (tx) => {
    const ids = [...new Set(copied.map((entry) => entry.controlId))];
    const control = new Map((await tx.query<{ id: string; workspace_id: string; model_provider: string; auth_type: string }>(
      `SELECT id::text AS id, workspace_id::text AS workspace_id, model_provider, auth_type
         FROM coding_agent_credentials WHERE id::text = ANY($1::text[]) FOR UPDATE`,
      [ids],
    )).rows.map((row) => [row.id, row]));
    const groups = new Map<string, Array<{ row: Candidate; controlId: string; authType: string }>>();
    for (const entry of copied) {
      const target = control.get(entry.controlId);
      if (!target) continue;
      const key = `${target.workspace_id}\0${target.model_provider}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push({ ...entry, authType: target.auth_type });
    }
    const newest = <T extends { row: Candidate }>(entries: T[]) =>
      [...entries].sort((a, b) => new Date(b.row.updated_at).getTime() - new Date(a.row.updated_at).getTime() || a.row.id.localeCompare(b.row.id))[0];
    for (const [key, entries] of groups) {
      const [workspaceId, provider] = key.split("\0") as [string, string];
      const copiedIds = [...new Set(entries.map((entry) => entry.controlId))];
      const llm = entries.filter((entry) => entry.row.is_active);
      const sandbox = entries.filter((entry) =>
        entry.row.harness_active && (entry.authType === "oauth_token" || entry.authType === "provider_oauth"));
      for (const [column, chosen, candidates] of [
        ["is_active", newest(llm), llm],
        ["harness_active", newest(sandbox), sandbox],
      ] as const) {
        if (chosen) {
          // Cloud's selection was copied in this run: it wins the group (the
          // partial unique index allows one), clearing first.
          summary.writes += (await tx.query(
            `UPDATE coding_agent_credentials SET ${column} = false, updated_at = now()
              WHERE workspace_id = $1 AND model_provider = $2 AND id <> $3 AND ${column}
              RETURNING id`,
            [workspaceId, provider, chosen.controlId],
          )).rows.length;
          summary.writes += (await tx.query(
            `UPDATE coding_agent_credentials SET ${column} = true WHERE id = $1 AND NOT ${column} RETURNING id`,
            [chosen.controlId],
          )).rows.length;
          if (column === "is_active") summary.active += 1;
          else summary.harness += 1;
          const demoted = new Set(candidates.map((entry) => entry.controlId)).size - 1;
          if (column === "is_active") summary.activeDemoted += Math.max(0, demoted);
          else summary.harnessDemoted += Math.max(0, demoted);
          continue;
        }
        // Cloud selected nothing this run copied (nothing at all, or a row such
        // as relay_managed that the copier does not write). Only this run's
        // copies are deactivated; Control-native, relay_managed and earlier
        // rows keep their flags. A group is never left with no selection when
        // it had one: then the seam's pick stays and it is a conflict.
        const others = await tx.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM coding_agent_credentials
            WHERE workspace_id = $1 AND model_provider = $2 AND ${column} AND NOT (id::text = ANY($3::text[]))`,
          [workspaceId, provider, copiedIds],
        );
        const flaggedCopies = await tx.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM coding_agent_credentials WHERE id::text = ANY($1::text[]) AND ${column}`,
          [copiedIds],
        );
        if ((flaggedCopies.rows[0]?.n ?? 0) === 0) continue;
        if ((others.rows[0]?.n ?? 0) > 0 || column === "harness_active") {
          // Another row carries the selection, or (sandbox) none is required:
          // an empty sandbox selection is valid. The auto-selected copies go
          // back to inactive.
          summary.writes += (await tx.query(
            `UPDATE coding_agent_credentials SET ${column} = false, updated_at = now()
              WHERE id::text = ANY($1::text[]) AND ${column} RETURNING id`,
            [copiedIds],
          )).rows.length;
        } else {
          summary.selectionConflicts += 1;
        }
      }
      summary.groups += 1;
    }
  });
  return summary;
}

type Candidate = {
  id: string;
  organization_id: string | null;
  workspace_id: string;
  user_id: string | null;
  cloud_user_id: string;
  model_provider: string;
  auth_type: "byo_api_key" | "oauth_token" | "provider_oauth";
  label: string | null;
  account_email: string | null;
  provider_account_id: string | null;
  /** Cloud selected it for LLM calls or the sandbox. */
  selected: boolean;
  status: string;
  last_error: string | null;
  refresh_attempts: number;
  last_authenticated_at: string | null;
  last_used_at: string | null;
  is_active: boolean;
  harness_active: boolean;
  updated_at: Date;
  skip_reason: string | null;
};

// Cloud's cli-credentials.ts aliases: claude -> anthropic, codex -> openai, grok -> xai.
// Cloud's canonicalConnectionProvider (packages/web/lib/billing/connection-provider.ts)
// plus gemini -> google from normalizeModelProvider (packages/web/lib/billing/house-keys.ts).
const CANONICAL: Record<string, string> = {
  claude: "anthropic", codex: "openai", grok: "xai", "cursor-agent": "cursor", agent: "cursor", gemini: "google",
};
export const canonicalProvider = (value: string) => {
  const normalized = value.trim().toLowerCase();
  return CANONICAL[normalized] ?? normalized;
};

/**
 * Object keys to try, in order, relative to the "credentials" prefix: exactly
 * the object(s) Cloud's runtime reads for this row, so Control never receives
 * a secret Cloud would not serve for it (review C2). Cloud trunk call sites:
 * - byo_api_key: the row's own object ({user}/{rowId}), written by
 *   app/api/v1/provider-credentials/byok/route.ts and read by
 *   lib/billing/provider-credential-runtime.ts (and flow-byok-credentials.ts).
 * - oauth_token: the account object, then the provider (legacy) object,
 *   whatever other rows share it: lib/auth/setup-token-credential.ts
 *   readSetupTokenCredential (retrieveAccount, then retrieve).
 * - provider_oauth: the account object iff the row has provider_account_id,
 *   otherwise the provider (legacy) object, never both:
 *   lib/billing/provider-credential-runtime.ts (useAccountObject =
 *   subscriptionMultiAccountEnabled && provider_account_id). The
 *   multi-account flag's database fallback
 *   (lib/auth/credential-store-backend.ts hasAccountScopedSubscriptionCredential)
 *   is true whenever such a row exists, so provider_account_id decides.
 */
/** Winner order for Cloud rows naming one Control login: newest, then lowest id. */
function compareLoginRows(a: Candidate, b: Candidate): number {
  const at = new Date(a.updated_at).getTime();
  const bt = new Date(b.updated_at).getTime();
  if (at !== bt) return bt - at;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

export function cloudObjectKeys(row: Pick<Candidate, "id" | "cloud_user_id" | "auth_type" | "model_provider" | "provider_account_id">): string[] {
  const account = `${row.cloud_user_id}/accounts/${row.id}/credentials.json.enc`;
  const legacy = `${row.cloud_user_id}/${canonicalProvider(row.model_provider)}/credentials.json.enc`;
  switch (row.auth_type) {
    case "byo_api_key":
      return [`${row.cloud_user_id}/${row.id}/credentials.json.enc`];
    case "oauth_token":
      return [account, legacy];
    case "provider_oauth": {
      // subscriptionMultiAccountEnabled is false for any provider other than
      // openai and anthropic (credential-store-backend.ts), so an xai login
      // always reads the legacy object, even with a provider_account_id.
      const provider = canonicalProvider(row.model_provider);
      const multiAccount = (provider === "openai" || provider === "anthropic") && Boolean(row.provider_account_id);
      return multiAccount ? [account] : [legacy];
    }
  }
}

export async function copyCodingAgentCredentials(
  deps: CredentialCopyDeps,
  scope: ImportScope,
  mode: "plan" | "apply",
): Promise<CredentialCopyReport> {
  assertScope(scope);
  const report: CredentialCopyReport = {
    version: 1,
    mappingRevision: MAPPING_REVISION,
    mode,
    ok: true,
    candidates: 0,
    outcomes: {},
    rows: {},
    controlIds: {},
    writes: { inserted: 0, updated: 0, blobWrites: 0, metadataWrites: 0, selectionWrites: 0 },
  };
  const record = (id: string, outcome: CredentialOutcome) => {
    report.rows[id] = outcome;
    report.outcomes[outcome] = (report.outcomes[outcome] ?? 0) + 1;
  };

  const candidates = await deps.source.transaction(async (tx) => {
    await tx.exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
    await tx.exec("SET LOCAL TIME ZONE 'UTC'");
    return (await tx.query<Candidate>(credentialCopyQuery(scope))).rows;
  });
  report.candidates = candidates.length;

  const copied: Array<{ row: Candidate; controlId: string }> = [];
  const ready: Array<{ row: Candidate; plaintext: string }> = [];
  for (const row of candidates) {
    if (row.skip_reason) {
      record(row.id, `skipped:${row.skip_reason}`);
      continue;
    }
    if (mode === "plan") {
      record(row.id, "skipped:plan");
      continue;
    }
    // The importer may have skipped this workspace on this target (an
    // unbound workspace before 0064): never let a store fail on its FK,
    // and never read a secret that cannot land.
    const onTarget = await deps.target.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM workspaces WHERE id = $1", [row.workspace_id]);
    if ((onTarget.rows[0]?.n ?? 0) === 0) {
      record(row.id, "skipped:workspace_not_on_target");
      continue;
    }
    let plaintext: string | null = null;
    try {
      for (const key of cloudObjectKeys(row)) {
        const body = await deps.reader.get(key);
        if (body === null) continue;
        plaintext = decryptCloudEnvelope(JSON.parse(body), deps.cloudKeyHex);
        break;
      }
    } catch {
      record(row.id, "decrypt_failed");
      continue;
    }
    if (plaintext === null) {
      // Not where Cloud's runtime reads it: the credential is broken in
      // Cloud too, and its user must sign in again.
      record(row.id, "object_missing");
      continue;
    }
    ready.push({ row, plaintext });
  }

  // Several Cloud rows can name one Control login (workspace, provider,
  // provider account): writing each would overwrite the others on every run
  // and never converge. One deterministic winner per login, the freshest
  // (most recently updated, then lowest id), carrying the group's Cloud
  // selection so an older selected duplicate never wins over a newer token.
  const loginKey = (row: Candidate, plaintext: string): string | null => {
    if (row.auth_type !== "provider_oauth") return null;
    try {
      const provider = canonicalProvider(row.model_provider) as SubscriptionProvider;
      JSON.parse(plaintext);
      return `${row.workspace_id}|${provider}|${describeAuthFile(provider, plaintext, row.account_email).accountId}`;
    } catch {
      return null; // the write below reports it (payload_invalid / store_rejected)
    }
  };
  const winners = new Map<string, Candidate>();
  for (const { row, plaintext } of ready) {
    const key = loginKey(row, plaintext);
    if (key === null) continue;
    const best = winners.get(key);
    if (!best || compareLoginRows(row, best) < 0) winners.set(key, row);
  }

  const carried = new Map<string, Candidate>();
  for (const { row, plaintext } of ready) {
    const key = loginKey(row, plaintext);
    if (key === null) continue;
    const winner = carried.get(key) ?? { ...winners.get(key)! };
    winner.is_active ||= row.is_active;
    winner.harness_active ||= row.harness_active;
    winner.selected ||= row.selected;
    carried.set(key, winner);
  }

  for (const { row: original, plaintext } of ready) {
    const key = loginKey(original, plaintext);
    if (key !== null && winners.get(key) !== original) {
      record(original.id, "duplicate_login");
      continue;
    }
    const row = key === null ? original : carried.get(key)!;
    const actor = { kind: "user" as const, userId: row.user_id! };
    const base = { workspaceId: row.workspace_id, organizationId: row.organization_id!, actor };
    try {
      if (row.auth_type === "provider_oauth") {
        // The raw CLI auth file, unmodified (#150: email is passed beside it).
        JSON.parse(plaintext);
        // storeLogin always rewrites in place (new blob, version + 1, status
        // reset), so it runs only when Control does not already hold this
        // exact login: a re-run writes nothing and bumps no version.
        const provider = canonicalProvider(row.model_provider) as SubscriptionProvider;
        const cloudFile = describeAuthFile(provider, plaintext, row.account_email);
        const accountId = cloudFile.accountId;
        const existing = (await deps.target.query<{ id: string; blob_location: string | null; blob_version: number | null }>(
          `SELECT id::text AS id, blob_location, blob_version FROM coding_agent_credentials
            WHERE workspace_id = $1 AND model_provider = $2 AND auth_type = 'provider_oauth' AND provider_account_id = $3`,
          [row.workspace_id, provider, accountId],
        )).rows[0];
        if (existing) {
          // Never overwrite on doubt: an unreadable Control blob is an error
          // for this row, not a reason to replace it.
          let stored: string;
          try {
            if (!existing.blob_location || existing.blob_version === null) throw new Error("no blob");
            stored = await deps.blobs.read(existing.blob_location, existing.id, existing.blob_version);
          } catch {
            record(row.id, "blob_read_failed");
            continue;
          }
          report.controlIds[row.id] = existing.id;
          if (stored === plaintext) {
            copied.push({ row, controlId: existing.id });
            record(row.id, "already_present");
            continue;
          }
          // Different content. Overwrite only if Cloud changed AND Control did
          // not: the import's marker must name the row's current blob_version
          // (every Control refresh or rotation bumps it; the selection pass
          // never does). A moved version, or no marker at all (a row Control
          // created), means Control owns newer state: never clobber it.
          const marker = await loginMarker(deps.target, row.organization_id!, existing.id);
          if (marker === null || marker !== existing.blob_version) {
            copied.push({ row, controlId: existing.id });
            record(row.id, "control_newer");
            continue;
          }
        }
        // The decision above was made without locks: storeLogin re-checks the
        // version under the per-credential lock (expectedVersion), and the
        // marker and Cloud's state are written in its transaction, so a
        // Control refresh or first login landing in between is never replaced.
        let metadataWrites = 0;
        let id: string;
        try {
          id = await deps.logins.storeLogin({
            ...base,
            provider,
            authFile: plaintext,
            accountEmail: row.account_email,
            expectedVersion: existing ? existing.blob_version : null,
            onStored: async (tx, stored) => {
              await writeLoginMarker(tx, row.organization_id!, stored);
              metadataWrites = await preserveCloudState(tx, stored.id, row);
            },
          });
        } catch (error) {
          if (error instanceof CodingAgentError && error.code === "login_version_conflict") {
            if (existing) copied.push({ row, controlId: existing.id });
            record(row.id, "control_newer");
            continue;
          }
          throw error;
        }
        report.writes.blobWrites += 1;
        if (existing) report.writes.updated += 1;
        else report.writes.inserted += 1;
        report.writes.metadataWrites += metadataWrites;
        copied.push({ row, controlId: id });
        report.controlIds[row.id] = id;
        record(row.id, existing ? "updated" : "copied");
        continue;
      }
      const payload = JSON.parse(plaintext) as { key?: unknown; token?: unknown };
      const result = row.auth_type === "byo_api_key"
        ? typeof payload.key === "string"
          ? await deps.codingAgents.putApiKey({ ...base, modelProvider: row.model_provider, key: payload.key, label: row.label })
          : null
        : typeof payload.token === "string"
          ? await deps.codingAgents.putSetupToken({ ...base, token: payload.token, accountEmail: row.account_email, label: row.label })
          : null;
      if (!result) {
        record(row.id, "payload_invalid");
        continue;
      }
      // putApiKey/putSetupToken dedupe by fingerprint and write nothing for
      // a key Control already holds; only a fresh row gets Cloud's state.
      if (result.created) {
        report.writes.inserted += 1;
        report.writes.metadataWrites += await preserveCloudState(deps.target, result.record.id, row);
      }
      copied.push({ row, controlId: result.record.id });
      report.controlIds[row.id] = result.record.id;
      record(row.id, result.created ? "copied" : "already_present");
    } catch (error) {
      if (error instanceof SyntaxError) {
        record(row.id, "payload_invalid");
      } else {
        const code = error instanceof CodingAgentError ? error.code : (error as { code?: unknown })?.code;
        record(row.id, `store_rejected:${typeof code === "string" ? code : "unexpected"}`);
      }
    }
  }
  if (mode === "apply" && copied.length > 0) {
    report.selection = await applyCloudSelection(deps.target, copied);
    report.writes.selectionWrites = report.selection.writes;
  }
  // A selection conflict needs a human choice per (workspace, provider)
  // before cutover sign-off, so it is never a clean run.
  report.ok = Object.keys(report.outcomes).every((outcome) =>
    outcome === "copied" || outcome === "updated" || outcome === "already_present" || outcome === "control_newer"
    || outcome === "duplicate_login"
    || outcome.startsWith("skipped:"))
    && (report.selection?.selectionConflicts ?? 0) === 0;
  deps.log?.("cloud_import.credentials", { mode, ok: report.ok, candidates: report.candidates, outcomes: report.outcomes });
  return report;
}
