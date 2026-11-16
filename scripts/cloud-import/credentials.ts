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
};

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
  skip_reason: string | null;
};

// Cloud's cli-credentials.ts aliases: claude -> anthropic, codex -> openai, grok -> xai.
const CANONICAL: Record<string, string> = { claude: "anthropic", codex: "openai", grok: "xai" };
export const canonicalProvider = (value: string) => CANONICAL[value] ?? value;

/** Object keys to try, in order, relative to the "credentials" prefix. */
export function cloudObjectKeys(row: Pick<Candidate, "id" | "cloud_user_id" | "auth_type" | "model_provider" | "provider_account_id">): string[] {
  const account = `${row.cloud_user_id}/accounts/${row.id}/credentials.json.enc`;
  const legacy = `${row.cloud_user_id}/${canonicalProvider(row.model_provider)}/credentials.json.enc`;
  switch (row.auth_type) {
    case "byo_api_key":
      return [`${row.cloud_user_id}/${row.id}/credentials.json.enc`];
    case "oauth_token":
      return [account, `${row.cloud_user_id}/anthropic/credentials.json.enc`];
    case "provider_oauth":
      return row.provider_account_id ? [account, legacy] : [legacy];
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
  };
  const record = (id: string, outcome: CredentialOutcome) => {
    report.rows[id] = outcome;
    report.outcomes[outcome] = (report.outcomes[outcome] ?? 0) + 1;
  };

  const candidates = await deps.source.transaction(async (tx) => {
    await tx.exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
    return (await tx.query<Candidate>(credentialCopyQuery(scope))).rows;
  });
  report.candidates = candidates.length;

  for (const row of candidates) {
    if (row.skip_reason) {
      record(row.id, `skipped:${row.skip_reason}`);
      continue;
    }
    if (mode === "plan") {
      record(row.id, "skipped:plan");
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
        await deps.logins.storeLogin(login);
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
  report.ok = Object.keys(report.outcomes).every((outcome) =>
    outcome === "copied" || outcome === "already_present" || outcome.startsWith("skipped:"));
  deps.log?.("cloud_import.credentials", { mode, ok: report.ok, candidates: report.candidates, outcomes: report.outcomes });
  return report;
}
