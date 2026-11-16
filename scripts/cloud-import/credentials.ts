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
import type { Database } from "../../src/database.js";
import { CodingAgentError, type CodingAgentStore } from "../../src/admin/coding-agents.js";
import type { SubscriptionLoginStore, SubscriptionProvider } from "../../src/admin/subscription-logins.js";
import { decryptCloudEnvelope } from "./importer.js";
import { assertScope, credentialCopyQuery, MAPPING_REVISION, type ImportScope } from "./mapping.js";

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
  keyring: EncryptionKeyring;
  log?: (event: string, fields: Record<string, unknown>) => void;
};

export type CredentialOutcome =
  | "copied"
  | "already_present"
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
  /** How Cloud's selection was applied (see applyCloudSelection). */
  /**
   * selectionConflicts: groups where Cloud selected no copied row, no other
   * Control row was active, and a copy had been auto-activated: it is kept
   * active (never zero) and counted here for review.
   */
  selection?: { groups: number; active: number; harness: number; activeDemoted: number; harnessDemoted: number; selectionConflicts: number };
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
  const summary = { groups: 0, active: 0, harness: 0, activeDemoted: 0, harnessDemoted: 0, selectionConflicts: 0 };
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
          await tx.query(
            `UPDATE coding_agent_credentials SET ${column} = false, updated_at = now()
              WHERE workspace_id = $1 AND model_provider = $2 AND id <> $3 AND ${column}`,
            [workspaceId, provider, chosen.controlId],
          );
          await tx.query(`UPDATE coding_agent_credentials SET ${column} = true WHERE id = $1`, [chosen.controlId]);
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
          await tx.query(
            `UPDATE coding_agent_credentials SET ${column} = false, updated_at = now() WHERE id::text = ANY($1::text[])`,
            [copiedIds],
          );
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

    const actor = { kind: "user" as const, userId: row.user_id! };
    const base = { workspaceId: row.workspace_id, organizationId: row.organization_id!, actor };
    try {
      if (row.auth_type === "provider_oauth") {
        // The raw CLI auth file, unmodified (#150: email is passed beside it).
        JSON.parse(plaintext);
        const login: Parameters<SubscriptionLoginStore["storeLogin"]>[0] & { accountEmail?: string | null } = {
          ...base,
          provider: canonicalProvider(row.model_provider) as SubscriptionProvider,
          authFile: plaintext,
          accountEmail: row.account_email,
        };
        const id = await deps.logins.storeLogin(login);
        copied.push({ row, controlId: id });
        report.controlIds[row.id] = id;
        record(row.id, "copied");
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
  }
  // A selection conflict needs a human choice per (workspace, provider)
  // before cutover sign-off, so it is never a clean run.
  report.ok = Object.keys(report.outcomes).every((outcome) =>
    outcome === "copied" || outcome === "already_present" || outcome.startsWith("skipped:"))
    && (report.selection?.selectionConflicts ?? 0) === 0;
  deps.log?.("cloud_import.credentials", { mode, ok: report.ok, candidates: report.candidates, outcomes: report.outcomes });
  return report;
}
