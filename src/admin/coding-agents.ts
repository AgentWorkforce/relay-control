// Coding agents: model-provider credentials for a workspace, ported from
// the hosted control plane's Settings > Connections > "Coding agents".
//
// Self-host differences, by design:
// - Credentials belong to the workspace (created_by is recorded), not to one
//   member. Owners/admins write; every member sees metadata. Hosted shows an
//   owner every member's rows, so the owner view is the same.
// - No Agent Relay house key ("Agent Relay API key", "OpenCode managed"):
//   self-host has no Agent Relay-paid model access.
// - Secrets are AES-256-GCM ciphertext under SELFHOST_ENCRYPTION_KEY in
//   Postgres instead of hosted's R2 credential store. Plaintext only leaves
//   relaycontrol through the internal runtime environment read.
import { createHmac, randomUUID } from "node:crypto";
import type { Database } from "../database.js";
import {
  decryptSecret,
  EncryptedSecretError,
  encryptSecret,
  type EncryptionKeyring,
} from "../crypto.js";
import { iso, recordAudit, type AuditActor } from "./audit.js";
import type { CredentialBlobStore } from "./credential-blobs.js";

/** byo_api_key = API key; oauth_token = Claude setup token; provider_oauth = Codex/Grok device login. */
export type CodingAgentAuthType = "byo_api_key" | "oauth_token" | "provider_oauth";

export type CodingAgentProvider = {
  id: string;
  displayName: string;
  harness: string;
  /** Env var a flow run receives when this provider's LLM credential is selected. */
  apiKeyEnv: string;
  /** Can hold a subscription login a sandbox CLI mounts ("Sandbox access"). */
  setupToken: boolean;
  /** Has a browser device login (hosted provider_oauth) whose auth file a run's CLI mounts. */
  deviceLogin: boolean;
  keyPlaceholder: string;
  docsUrl: string;
};

/** Env var the Claude CLI reads a `claude setup-token` from. */
export const SETUP_TOKEN_ENV = "CLAUDE_CODE_OAUTH_TOKEN";

export const CODING_AGENT_PROVIDERS: readonly CodingAgentProvider[] = [
  {
    id: "anthropic",
    displayName: "Anthropic",
    harness: "claude",
    apiKeyEnv: "ANTHROPIC_API_KEY",
    setupToken: true,
    deviceLogin: false,
    keyPlaceholder: "sk-ant-api03-…",
    docsUrl: "https://console.anthropic.com/settings/keys",
  },
  {
    id: "openai",
    displayName: "OpenAI",
    harness: "codex",
    apiKeyEnv: "OPENAI_API_KEY",
    setupToken: false,
    deviceLogin: true,
    keyPlaceholder: "sk-…",
    docsUrl: "https://platform.openai.com/api-keys",
  },
  {
    id: "openrouter",
    displayName: "OpenRouter",
    harness: "openrouter",
    apiKeyEnv: "OPENROUTER_API_KEY",
    setupToken: false,
    deviceLogin: false,
    keyPlaceholder: "sk-or-v1-…",
    docsUrl: "https://openrouter.ai/settings/keys",
  },
  {
    id: "xai",
    displayName: "xAI",
    harness: "grok",
    apiKeyEnv: "XAI_API_KEY",
    setupToken: false,
    deviceLogin: true,
    keyPlaceholder: "xai-…",
    docsUrl: "https://console.x.ai",
  },
  {
    id: "google",
    displayName: "Google",
    harness: "gemini",
    apiKeyEnv: "GEMINI_API_KEY",
    setupToken: false,
    deviceLogin: false,
    keyPlaceholder: "AIza…",
    docsUrl: "https://aistudio.google.com/apikey",
  },
];

const PROVIDERS_BY_ID = new Map(CODING_AGENT_PROVIDERS.map((provider) => [provider.id, provider]));

/** Hosted `normalizeModelProvider`, limited to the providers self-host stores. */
export function normalizeCodingAgentProvider(value: unknown): CodingAgentProvider | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  const id = normalized === "claude"
    ? "anthropic"
    : normalized === "codex"
      ? "openai"
      : normalized === "grok"
        ? "xai"
        : normalized === "gemini"
          ? "google"
          : normalized;
  return PROVIDERS_BY_ID.get(id) ?? null;
}

export class CodingAgentError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "CodingAgentError";
  }
}

/** Hosted `CloudAgent` shape. Never carries the secret or its ciphertext. */
export type CodingAgentRecord = {
  id: string;
  displayName: string;
  harness: string;
  modelProvider: string;
  authType: CodingAgentAuthType;
  label: string | null;
  accountEmail: string | null;
  secretPreview: string;
  isActive: boolean;
  harnessActive: boolean;
  defaultModel: null;
  status: "connected" | "error" | "refresh_failed";
  credentialStoredAt: string;
  lastAuthenticatedAt: string | null;
  lastCheckedAt: string | null;
  lastUsedAt: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
  owner: { userId: string; name: string | null; email: string | null; avatarUrl: null } | null;
};

type Row = {
  id: string;
  model_provider: string;
  harness: string;
  auth_type: CodingAgentAuthType;
  display_name: string;
  label: string | null;
  account_email: string | null;
  secret_preview: string;
  is_active: boolean;
  harness_active: boolean;
  status: "connected" | "error" | "refresh_failed";
  last_error: string | null;
  last_checked_at: Date | string | null;
  last_authenticated_at: Date | string | null;
  last_used_at: Date | string | null;
  created_at: Date | string;
  updated_at: Date | string;
  created_by_user_id: string | null;
  owner_name: string | null;
  owner_email: string | null;
};

const COLUMNS = `c.id, c.model_provider, c.harness, c.auth_type, c.display_name, c.label,
  c.account_email, c.secret_preview, c.is_active, c.harness_active, c.status, c.last_error,
  c.last_checked_at, c.last_authenticated_at, c.last_used_at, c.created_at, c.updated_at,
  c.created_by_user_id, u.name AS owner_name, u.email AS owner_email`;
const FROM = `coding_agent_credentials c
  LEFT JOIN users u ON u.id = c.created_by_user_id`;

function maybeIso(value: Date | string | null): string | null {
  return value === null ? null : iso(value);
}

function toRecord(row: Row): CodingAgentRecord {
  return {
    id: row.id,
    displayName: row.display_name,
    harness: row.harness,
    modelProvider: row.model_provider,
    authType: row.auth_type,
    label: row.label,
    accountEmail: row.account_email,
    secretPreview: row.secret_preview,
    isActive: row.is_active,
    harnessActive: row.harness_active,
    defaultModel: null,
    status: row.status,
    credentialStoredAt: iso(row.updated_at),
    lastAuthenticatedAt: maybeIso(row.last_authenticated_at),
    lastCheckedAt: maybeIso(row.last_checked_at),
    lastUsedAt: maybeIso(row.last_used_at),
    lastError: row.last_error,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
    owner: row.created_by_user_id
      ? { userId: row.created_by_user_id, name: row.owner_name, email: row.owner_email, avatarUrl: null }
      : null,
  };
}

/** First 7 and last 4 characters for keys long enough to keep them unguessable. */
export function previewSecret(value: string): string {
  if (value.length < 20) return "••••";
  return `${value.slice(0, 7)}…${value.slice(-4)}`;
}

const SECRET_MAX_BYTES = 8 * 1024;
const LABEL_MAX = 80;
const EMAIL_MAX = 254;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateSecret(value: unknown, field: string): string {
  const secret = typeof value === "string" ? value.trim() : "";
  if (!secret) throw new CodingAgentError(400, "invalid_request", `${field} is required`);
  if (Buffer.byteLength(secret, "utf8") > SECRET_MAX_BYTES || /[\s\u0000-\u001f\u007f]/.test(secret)) {
    throw new CodingAgentError(400, "invalid_request", `${field} must be a single-line token`);
  }
  return secret;
}

function validateLabel(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw new CodingAgentError(400, "invalid_request", "label must be a string");
  const label = value.replace(/[\p{C}]/gu, " ").replace(/\s+/g, " ").trim();
  if (label.length > LABEL_MAX) {
    throw new CodingAgentError(400, "invalid_request", `label must be at most ${LABEL_MAX} characters`);
  }
  return label || null;
}

function validateEmail(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw new CodingAgentError(400, "account_email_invalid", "accountEmail must be an email address");
  }
  const email = value.trim();
  if (!email) return null;
  if (email.length > EMAIL_MAX || !EMAIL_RE.test(email)) {
    throw new CodingAgentError(400, "account_email_invalid", "accountEmail must be an email address");
  }
  return email;
}

export type RuntimeCodingAgentEnvironment = {
  env: Record<string, string>;
  skipped: Array<{ name: string; reason: "undecryptable" }>;
};

export type ProbeResult = {
  status: "available" | "unavailable" | "unsupported" | "error";
  checkedAt: string;
  message: string;
};

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** Hosted `probeProviderCredential`: one cheap authenticated read per provider. */
const PROBES: Record<string, (secret: string) => { url: string; headers: Record<string, string> }> = {
  anthropic: (key) => ({
    url: "https://api.anthropic.com/v1/models?limit=1",
    headers: { "x-api-key": key, "anthropic-version": "2023-06-01" },
  }),
  openai: (key) => ({ url: "https://api.openai.com/v1/models", headers: { authorization: `Bearer ${key}` } }),
  openrouter: (key) => ({ url: "https://openrouter.ai/api/v1/key", headers: { authorization: `Bearer ${key}` } }),
  xai: (key) => ({ url: "https://api.x.ai/v1/models", headers: { authorization: `Bearer ${key}` } }),
  google: (key) => ({
    url: "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1",
    headers: { "x-goog-api-key": key },
  }),
};

export class CodingAgentStore {
  constructor(
    private readonly database: Database,
    private readonly keyring: EncryptionKeyring,
    private readonly fetchImpl: FetchLike = (url, init) => fetch(url, init),
    /** Object storage of subscription-login auth files, removed with their row. */
    private readonly blobs?: CredentialBlobStore,
  ) {}

  private fingerprint(provider: string, authType: string, secret: string): string {
    return createHmac("sha256", this.keyring.active.key)
      .update("selfhost-coding-agent-credential")
      .update("\0")
      .update(provider)
      .update("\0")
      .update(authType)
      .update("\0")
      .update(secret)
      .digest("hex");
  }

  async list(workspaceId: string): Promise<CodingAgentRecord[]> {
    const result = await this.database.query<Row>(
      `SELECT ${COLUMNS} FROM ${FROM}
        WHERE c.workspace_id = $1
        ORDER BY c.updated_at DESC, c.created_at DESC, c.id`,
      [workspaceId],
    );
    return result.rows.map(toRecord);
  }

  async get(workspaceId: string, id: string): Promise<CodingAgentRecord | null> {
    if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
    const result = await this.database.query<Row>(
      `SELECT ${COLUMNS} FROM ${FROM} WHERE c.workspace_id = $1 AND c.id = $2`,
      [workspaceId, id],
    );
    return result.rows[0] ? toRecord(result.rows[0]) : null;
  }

  /**
   * Stores an API key (hosted POST provider-credentials/byok). The same key
   * stored again returns the existing row. The first credential of a provider
   * becomes its LLM-call credential, as hosted `ensureActiveProviderCredential`.
   */
  async putApiKey(input: {
    workspaceId: string;
    organizationId: string;
    modelProvider: unknown;
    key: unknown;
    label: unknown;
    actor: AuditActor & { kind: "user" };
  }): Promise<{ record: CodingAgentRecord; created: boolean }> {
    const provider = normalizeCodingAgentProvider(input.modelProvider);
    if (!provider) {
      throw new CodingAgentError(400, "invalid_request", "modelProvider must be one of anthropic, openai, openrouter, xai, google");
    }
    const key = validateSecret(input.key, "key");
    const label = validateLabel(input.label);
    return this.store({
      workspaceId: input.workspaceId,
      organizationId: input.organizationId,
      provider,
      authType: "byo_api_key",
      secret: key,
      label,
      accountEmail: null,
      displayName: label ?? `${provider.displayName} API key`,
      actor: input.actor,
    });
  }

  /**
   * Stores a `claude setup-token` (hosted POST provider-credentials/setup-token).
   * A token for an account email already stored replaces that account's token;
   * a different email adds another account. The first setup token becomes the
   * sandbox credential, as hosted `ensureActiveSubscriptionHarness`.
   */
  async putSetupToken(input: {
    workspaceId: string;
    organizationId: string;
    token: unknown;
    accountEmail: unknown;
    label: unknown;
    actor: AuditActor & { kind: "user" };
  }): Promise<{ record: CodingAgentRecord; created: boolean }> {
    const provider = PROVIDERS_BY_ID.get("anthropic")!;
    const token = validateSecret(input.token, "token");
    const accountEmail = validateEmail(input.accountEmail);
    const label = validateLabel(input.label);
    return this.store({
      workspaceId: input.workspaceId,
      organizationId: input.organizationId,
      provider,
      authType: "oauth_token",
      secret: token,
      label,
      accountEmail,
      displayName: label ?? "Claude setup token",
      actor: input.actor,
    });
  }

  private async store(input: {
    workspaceId: string;
    organizationId: string;
    provider: CodingAgentProvider;
    authType: CodingAgentAuthType;
    secret: string;
    label: string | null;
    accountEmail: string | null;
    displayName: string;
    actor: AuditActor & { kind: "user" };
  }): Promise<{ record: CodingAgentRecord; created: boolean }> {
    const fingerprint = this.fingerprint(input.provider.id, input.authType, input.secret);
    const ciphertext = encryptSecret(input.secret, this.keyring.active);
    const preview = previewSecret(input.secret);
    const id = await this.database.transaction(async (tx) => {
      // Serialize credential writers per workspace so the selection
      // invariants (first credential becomes active) hold.
      await tx.query("SELECT id FROM workspaces WHERE id = $1 FOR UPDATE", [input.workspaceId]);
      const duplicate = await tx.query<{ id: string }>(
        `SELECT id FROM coding_agent_credentials
          WHERE workspace_id = $1 AND model_provider = $2 AND auth_type = $3 AND key_fingerprint = $4`,
        [input.workspaceId, input.provider.id, input.authType, fingerprint],
      );
      if (duplicate.rows[0]) return { id: duplicate.rows[0].id, created: false };

      if (input.authType === "oauth_token" && input.accountEmail) {
        const sameAccount = await tx.query<{ id: string }>(
          `UPDATE coding_agent_credentials SET
             secret_ciphertext = $3, secret_preview = $4, key_fingerprint = $5,
             label = COALESCE($6, label), display_name = $7, status = 'connected', last_error = NULL,
             last_authenticated_at = now(), updated_at = now()
           WHERE workspace_id = $1 AND auth_type = 'oauth_token' AND lower(account_email) = lower($2)
           RETURNING id`,
          [input.workspaceId, input.accountEmail, ciphertext, preview, fingerprint, input.label, input.displayName],
        );
        if (sameAccount.rows[0]) {
          await recordAudit(tx, {
            organizationId: input.organizationId,
            workspaceId: input.workspaceId,
            actor: input.actor,
            action: "coding_agent.replace",
            target: `${input.provider.id}:${sameAccount.rows[0].id}`,
          });
          return { id: sameAccount.rows[0].id, created: false };
        }
      }

      const hasActive = await tx.query<{ llm: boolean; sandbox: boolean }>(
        `SELECT coalesce(bool_or(is_active), false) AS llm, coalesce(bool_or(harness_active), false) AS sandbox
           FROM coding_agent_credentials WHERE workspace_id = $1 AND model_provider = $2`,
        [input.workspaceId, input.provider.id],
      );
      const id = randomUUID();
      await tx.query(
        `INSERT INTO coding_agent_credentials
           (id, organization_id, workspace_id, created_by_user_id, model_provider, harness, auth_type,
            display_name, label, account_email, secret_ciphertext, secret_preview, key_fingerprint,
            is_active, harness_active, last_authenticated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, now())`,
        [
          id,
          input.organizationId,
          input.workspaceId,
          input.actor.userId,
          input.provider.id,
          input.provider.harness,
          input.authType,
          input.displayName,
          input.label,
          input.accountEmail,
          ciphertext,
          preview,
          fingerprint,
          hasActive.rows[0]?.llm !== true,
          input.authType === "oauth_token" && hasActive.rows[0]?.sandbox !== true,
        ],
      );
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: "coding_agent.create",
        target: `${input.provider.id}:${id}`,
      });
      return { id, created: true };
    });
    const record = await this.get(input.workspaceId, id.id);
    return { record: record!, created: id.created };
  }

  /**
   * Hosted POST /cloud-agents/{id}/activate: `model` selects the provider's
   * LLM-call credential, `harness` its sandbox credential.
   */
  async activate(input: {
    workspaceId: string;
    organizationId: string;
    id: string;
    selection: unknown;
    actor: AuditActor & { kind: "user" };
  }): Promise<CodingAgentRecord> {
    const selection = input.selection === undefined ? "model" : input.selection;
    if (selection !== "model" && selection !== "harness") {
      throw new CodingAgentError(400, "invalid_request", "Invalid selection");
    }
    const existing = await this.get(input.workspaceId, input.id);
    if (!existing) throw new CodingAgentError(404, "credential_not_found", "Credential not found");
    if (existing.status !== "connected") {
      throw new CodingAgentError(409, "credential_not_connected", "Reconnect this credential before selecting it");
    }
    if (selection === "harness" && existing.authType === "byo_api_key") {
      throw new CodingAgentError(409, "sandbox_not_supported", "Only a subscription login can be used for sandbox access");
    }
    if (selection === "model" && existing.authType === "provider_oauth") {
      // A Codex/Grok login is mounted as the CLI's auth file; it is not an API
      // key a flow can call models with.
      throw new CodingAgentError(409, "llm_not_supported", "A subscription login is used for sandbox access only");
    }
    const column = selection === "model" ? "is_active" : "harness_active";
    await this.database.transaction(async (tx) => {
      await tx.query(
        `UPDATE coding_agent_credentials SET ${column} = false, updated_at = now()
          WHERE workspace_id = $1 AND model_provider = $2 AND ${column} AND id <> $3`,
        [input.workspaceId, existing.modelProvider, existing.id],
      );
      await tx.query(
        `UPDATE coding_agent_credentials SET ${column} = true, updated_at = now()
          WHERE workspace_id = $1 AND id = $2`,
        [input.workspaceId, existing.id],
      );
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: selection === "model" ? "coding_agent.select_llm" : "coding_agent.select_sandbox",
        target: `${existing.modelProvider}:${existing.id}`,
      });
    });
    return (await this.get(input.workspaceId, existing.id))!;
  }

  /**
   * Deletes a credential. When it held a selection, the most recent remaining
   * eligible credential of that provider takes it over (hosted promotion).
   */
  async delete(input: {
    workspaceId: string;
    organizationId: string;
    id: string;
    actor: AuditActor & { kind: "user" };
  }): Promise<CodingAgentRecord | null> {
    const existing = await this.get(input.workspaceId, input.id);
    if (!existing) return null;
    const blob = await this.database.query<{ blob_location: string | null }>(
      "SELECT blob_location FROM coding_agent_credentials WHERE workspace_id = $1 AND id = $2",
      [input.workspaceId, existing.id],
    );
    await this.database.transaction(async (tx) => {
      await tx.query("SELECT id FROM workspaces WHERE id = $1 FOR UPDATE", [input.workspaceId]);
      await tx.query(
        "DELETE FROM coding_agent_credentials WHERE workspace_id = $1 AND id = $2",
        [input.workspaceId, existing.id],
      );
      if (existing.isActive) {
        await tx.query(
          `UPDATE coding_agent_credentials SET is_active = true, updated_at = now()
            WHERE id = (SELECT id FROM coding_agent_credentials
                         WHERE workspace_id = $1 AND model_provider = $2 AND status = 'connected'
                           AND auth_type <> 'provider_oauth'
                         ORDER BY updated_at DESC, created_at DESC, id LIMIT 1)`,
          [input.workspaceId, existing.modelProvider],
        );
      }
      if (existing.harnessActive) {
        await tx.query(
          `UPDATE coding_agent_credentials SET harness_active = true, updated_at = now()
            WHERE id = (SELECT id FROM coding_agent_credentials
                         WHERE workspace_id = $1 AND model_provider = $2 AND status = 'connected'
                           AND auth_type IN ('oauth_token', 'provider_oauth')
                         ORDER BY updated_at DESC, created_at DESC, id LIMIT 1)`,
          [input.workspaceId, existing.modelProvider],
        );
      }
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: "coding_agent.delete",
        target: `${existing.modelProvider}:${existing.id}`,
      });
    });
    const location = blob.rows[0]?.blob_location;
    if (location && this.blobs) await this.blobs.remove(location).catch(() => undefined);
    return existing;
  }

  private async secret(workspaceId: string, id: string): Promise<string> {
    const result = await this.database.query<{ secret_ciphertext: string }>(
      "SELECT secret_ciphertext FROM coding_agent_credentials WHERE workspace_id = $1 AND id = $2",
      [workspaceId, id],
    );
    const row = result.rows[0];
    if (!row) throw new CodingAgentError(404, "credential_not_found", "Credential not found");
    try {
      return decryptSecret(row.secret_ciphertext, this.keyring);
    } catch (error) {
      if (error instanceof EncryptedSecretError) {
        throw new CodingAgentError(422, "credential_undecryptable", "Credential cannot be decrypted with the configured keys");
      }
      throw error;
    }
  }

  /** Hosted POST /cloud-agents/{id}/check: one authenticated provider read. */
  async check(input: {
    workspaceId: string;
    id: string;
  }): Promise<ProbeResult> {
    const existing = await this.get(input.workspaceId, input.id);
    if (!existing) throw new CodingAgentError(404, "credential_not_found", "Credential not found");
    const checkedAt = new Date().toISOString();
    const probe = PROBES[existing.modelProvider];
    let result: ProbeResult;
    if (existing.authType === "provider_oauth") {
      return {
        status: "unsupported",
        checkedAt,
        message: "Subscription logins refresh when a run starts. No provider request was made.",
      };
    }
    if (existing.authType === "oauth_token" || !probe) {
      result = {
        status: "unsupported",
        checkedAt,
        message: existing.authType === "oauth_token"
          ? "Setup tokens are checked when a sandbox starts Claude. No provider request was made."
          : "This provider has no credential check. No provider request was made.",
      };
    } else {
      const secret = await this.secret(input.workspaceId, existing.id);
      const request = probe(secret);
      try {
        const response = await this.fetchImpl(request.url, {
          headers: { ...request.headers, accept: "application/json" },
          signal: AbortSignal.timeout(10_000),
        });
        await response.body?.cancel().catch(() => undefined);
        result = response.ok
          ? { status: "available", checkedAt, message: `${existing.displayName} authenticated with the provider.` }
          : response.status === 401 || response.status === 403
            ? { status: "error", checkedAt, message: `The provider rejected this key (${response.status}).` }
            : { status: "unavailable", checkedAt, message: `The provider answered ${response.status}. Try again later.` };
      } catch {
        result = { status: "unavailable", checkedAt, message: "The provider could not be reached from the control plane." };
      }
    }
    if (result.status !== "unsupported") {
      await this.database.query(
        `UPDATE coding_agent_credentials SET
           status = $3, last_error = $4, last_checked_at = $5,
           last_authenticated_at = CASE WHEN $3 = 'connected' THEN $5 ELSE last_authenticated_at END
         WHERE workspace_id = $1 AND id = $2`,
        [
          input.workspaceId,
          existing.id,
          result.status === "error" ? "error" : "connected",
          result.status === "error" ? result.message : null,
          checkedAt,
        ],
      );
    }
    return result;
  }

  /**
   * Internal runtime read: the env a flow run receives for the workspace's
   * selected credentials. LLM-call credentials map to the provider's API-key
   * variable (a selected setup token maps to CLAUDE_CODE_OAUTH_TOKEN); the
   * sandbox credential maps to CLAUDE_CODE_OAUTH_TOKEN.
   */
  async readRuntimeEnvironment(
    workspaceId: string,
    actor: AuditActor,
  ): Promise<RuntimeCodingAgentEnvironment> {
    const result = await this.database.query<{
      id: string;
      model_provider: string;
      auth_type: CodingAgentAuthType;
      is_active: boolean;
      harness_active: boolean;
      secret_ciphertext: string;
    }>(
      `SELECT id, model_provider, auth_type, is_active, harness_active, secret_ciphertext
         FROM coding_agent_credentials
        WHERE workspace_id = $1 AND status = 'connected' AND (is_active OR harness_active)
          AND auth_type <> 'provider_oauth'
        ORDER BY harness_active DESC, model_provider, id`,
      [workspaceId],
    );
    const env: Record<string, string> = Object.create(null) as Record<string, string>;
    const skipped: RuntimeCodingAgentEnvironment["skipped"] = [];
    const used: string[] = [];
    for (const row of result.rows) {
      const provider = PROVIDERS_BY_ID.get(row.model_provider);
      if (!provider) continue;
      const name = row.auth_type === "oauth_token" ? SETUP_TOKEN_ENV : provider.apiKeyEnv;
      // The sandbox selection is read first, so it owns CLAUDE_CODE_OAUTH_TOKEN.
      if (name in env) continue;
      try {
        env[name] = decryptSecret(row.secret_ciphertext, this.keyring);
        used.push(row.id);
      } catch (error) {
        if (!(error instanceof EncryptedSecretError)) throw error;
        console.error("[selfhost-api] undecryptable coding agent credential", {
          workspaceId,
          credentialId: row.id,
          code: error.code,
        });
        skipped.push({ name, reason: "undecryptable" });
      }
    }
    if (used.length) {
      await this.database.query(
        "UPDATE coding_agent_credentials SET last_used_at = now() WHERE id = ANY($1::uuid[])",
        [used],
      );
      await recordAudit(this.database, {
        workspaceId,
        actor,
        action: "coding_agent.runtime_read",
        target: `${used.length} credentials`,
      });
    }
    return { env: { ...env }, skipped };
  }
}
