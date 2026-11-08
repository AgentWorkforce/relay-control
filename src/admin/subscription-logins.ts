// Subscription logins for coding agents: hosted's provider_oauth credentials,
// ported to self-host.
//
//   device login (start/status)  ->  auth file JSON  ->  envelope-encrypted
//   object (CredentialBlobStore)  ->  run-scoped reference in the assignment
//   payload  ->  worker reads it, writes the CLI's auth file 0600 into the
//   run's private dir, and writes refreshed tokens back after the run.
//
// Secrets never appear in API responses, logs, audit targets, or errors.
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";
import { decryptSecret, encryptSecret, opaqueToken, type EncryptionKeyring } from "../crypto.js";
import { recordAudit, type AuditActor } from "./audit.js";
import { CredentialBlobError, type CredentialBlobStore } from "./credential-blobs.js";
import { CodingAgentError } from "./coding-agents.js";
import {
  exchangeOpenAIDeviceAuthorization,
  OPENAI_DEVICE_AUTH_LIFETIME_SECONDS,
  OPENAI_DEVICE_CLIENT_ID,
  OpenAIDeviceAuthError,
  pollOpenAIDeviceAuthorization,
  startOpenAIDeviceAuthorization,
  type CodexAuthJson,
} from "./openai-device-auth.js";
import {
  pollXaiDeviceAuthorization,
  startXaiDeviceAuthorization,
  XAI_DEVICE_CREDENTIAL_SCOPE,
  XaiDeviceAuthError,
} from "./xai-device-auth.js";

export type SubscriptionProvider = "openai" | "xai";

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** Where each CLI reads its login (hosted PROVIDER_PATHS / grokOauthCredentialMountScript). */
export const SUBSCRIPTION_CLI_FILES: Record<SubscriptionProvider, {
  cli: string;
  homeEnv: string;
  directory: string;
  file: string;
  displayName: string;
}> = {
  openai: { cli: "codex", homeEnv: "CODEX_HOME", directory: ".codex", file: "auth.json", displayName: "Codex login" },
  xai: { cli: "grok", homeEnv: "GROK_HOME", directory: ".grok", file: "auth.json", displayName: "Grok login" },
};

/** Device sessions live 15 minutes (hosted OPENAI_DEVICE_AUTH_LIFETIME_SECONDS). */
const STALE_PROCESSING_MS = 30_000;
/** Refresh at run start when the access token expires within this window (hosted: 45 min). */
export const REFRESH_WINDOW_MS = 45 * 60_000;
/** Run references are capped at the longest run the worker allows. */
export const RUN_REFERENCE_TTL_MS = 6 * 60 * 60_000;
const MAX_FAILED_REFRESHES = 3;
const MAX_AUTH_FILE_BYTES = 64 * 1024;

const OPENAI_TOKEN_ENDPOINT = "https://auth.openai.com/oauth/token";
const XAI_TOKEN_ENDPOINT = "https://auth.x.ai/oauth2/token";

export const DEVICE_BINDING_COOKIES: Record<SubscriptionProvider, string> = {
  openai: "agent_relay_openai_device_session",
  xai: "agent_relay_xai_device_session",
};

export type DeviceStart = {
  transactionId: string;
  verificationUri: string;
  userCode: string;
  intervalSeconds: number;
  expiresAt: string;
  /** Set as an httpOnly cookie by the route; never returned in the body. */
  browserBinding: string;
};

export type DeviceStatus =
  | { status: "pending"; retryAfterSeconds: number }
  | { status: "connected"; providerCredentialId: string }
  | { status: "expired" }
  | { status: "failed"; error?: string };

export type RunCredentialFile = {
  credentialId: string;
  provider: SubscriptionProvider;
  cli: string;
  homeEnv: string;
  directory: string;
  file: string;
  /** The CLI's auth file. Only ever sent to the run's authenticated worker. */
  content: string;
};

export type RunCredentialReference = {
  ref: string;
  expiresAt: string;
  credentials: Array<{ credentialId: string; provider: SubscriptionProvider; cli: string }>;
};

function readJwtPayload(token: string | undefined): Record<string, unknown> | null {
  const parts = token?.split(".") ?? [];
  if (parts.length !== 3) return null;
  try {
    const value = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

type GrokEntry = {
  key: string;
  refresh_token: string;
  expires_at?: string;
  email?: string;
  oidc_client_id?: string;
  [key: string]: unknown;
};

/** Identity, expiry and fingerprint input of a stored auth file. */
export function describeAuthFile(provider: SubscriptionProvider, content: string): {
  accountId: string;
  email: string | null;
  expiresAt: Date | null;
  refreshToken: string;
} {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new CodingAgentError(422, "invalid_auth_file", "Auth file is not JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new CodingAgentError(422, "invalid_auth_file", "Auth file is not an object");
  }
  if (provider === "openai") {
    const codex = parsed as Partial<CodexAuthJson>;
    const tokens = codex.tokens;
    if (codex.auth_mode !== "chatgpt" || !tokens?.access_token || !tokens.refresh_token || !tokens.account_id) {
      throw new CodingAgentError(422, "invalid_auth_file", "Not a Codex ChatGPT login");
    }
    const access = readJwtPayload(tokens.access_token);
    const id = readJwtPayload(tokens.id_token);
    const exp = typeof access?.exp === "number" ? new Date(access.exp * 1000) : null;
    const email = typeof id?.email === "string" ? id.email : null;
    return { accountId: tokens.account_id, email, expiresAt: exp, refreshToken: tokens.refresh_token };
  }
  const entry = (parsed as Record<string, GrokEntry>)[XAI_DEVICE_CREDENTIAL_SCOPE];
  if (!entry?.key || !entry.refresh_token) {
    throw new CodingAgentError(422, "invalid_auth_file", "Not a Grok login");
  }
  const expiresAt = entry.expires_at ? new Date(entry.expires_at) : null;
  const email = typeof entry.email === "string" ? entry.email : null;
  const sub = readJwtPayload(entry.key)?.sub;
  return {
    accountId: typeof sub === "string" ? sub : email ?? createHash("sha256").update(entry.refresh_token).digest("hex").slice(0, 32),
    email,
    expiresAt: expiresAt && !Number.isNaN(expiresAt.getTime()) ? expiresAt : null,
    refreshToken: entry.refresh_token,
  };
}

/** Hosted credential-refresher.ts for openai and xai. Error messages never carry token bodies. */
export async function refreshAuthFile(
  provider: SubscriptionProvider,
  content: string,
  fetchImpl: FetchLike,
  now = new Date(),
): Promise<string> {
  const parsed = JSON.parse(content) as Record<string, unknown>;
  if (provider === "openai") {
    const codex = parsed as unknown as CodexAuthJson;
    const response = await fetchImpl(OPENAI_TOKEN_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: codex.tokens.refresh_token,
        client_id: OPENAI_DEVICE_CLIENT_ID,
      }).toString(),
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw new RefreshFailed(provider, response.status);
    const tokens = await response.json() as { access_token?: string; refresh_token?: string; id_token?: string };
    if (!tokens.access_token) throw new RefreshFailed(provider, 502);
    return JSON.stringify({
      ...codex,
      tokens: {
        ...codex.tokens,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token ?? codex.tokens.refresh_token,
        // Hosted keeps the old id_token; take a new one when offered.
        ...(tokens.id_token ? { id_token: tokens.id_token } : {}),
      },
      last_refresh: now.toISOString(),
    });
  }
  const entry = parsed[XAI_DEVICE_CREDENTIAL_SCOPE] as GrokEntry;
  const clientId = entry.oidc_client_id || XAI_DEVICE_CREDENTIAL_SCOPE.split("::")[1]!;
  const response = await fetchImpl(XAI_TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: entry.refresh_token, client_id: clientId }).toString(),
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new RefreshFailed(provider, response.status);
  const tokens = await response.json() as { access_token?: string; refresh_token?: string; expires_in?: number };
  if (!tokens.access_token) throw new RefreshFailed(provider, 502);
  return JSON.stringify({
    ...parsed,
    [XAI_DEVICE_CREDENTIAL_SCOPE]: {
      ...entry,
      key: tokens.access_token,
      // auth.x.ai rotates refresh tokens on every refresh.
      refresh_token: tokens.refresh_token ?? entry.refresh_token,
      create_time: now.toISOString(),
      expires_at: new Date(now.getTime() + (tokens.expires_in ?? 6 * 3600) * 1000).toISOString(),
    },
  });
}

export class RefreshFailed extends Error {
  constructor(readonly provider: SubscriptionProvider, readonly status: number) {
    super(`Token refresh failed for ${provider}: HTTP ${status}`);
    this.name = "RefreshFailed";
  }
}

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

type CredentialRow = {
  id: string;
  model_provider: SubscriptionProvider;
  blob_location: string;
  blob_version: number;
  provider_account_id: string;
  credential_expires_at: Date | string | null;
  status: string;
  refresh_attempts: number;
};

export class SubscriptionLoginStore {
  constructor(
    private readonly database: Database,
    private readonly keyring: EncryptionKeyring,
    private readonly blobs: CredentialBlobStore,
    private readonly fetchImpl: FetchLike = (url, init) => fetch(url, init),
    private readonly now: () => Date = () => new Date(),
  ) {}

  /** The ported device-auth modules take a global-fetch-shaped function. */
  private get deviceFetch(): typeof fetch {
    return ((input: RequestInfo | URL, init?: RequestInit) => this.fetchImpl(String(input), init ?? {})) as typeof fetch;
  }

  private bindingFingerprint(provider: SubscriptionProvider, token: string): string {
    return createHmac("sha256", this.keyring.active.key)
      .update(`${provider}-device-browser-session\0`)
      .update(token)
      .digest("hex");
  }

  private keyFingerprint(provider: SubscriptionProvider, refreshToken: string): string {
    return createHmac("sha256", this.keyring.active.key)
      .update("selfhost-coding-agent-credential\0")
      .update(`${provider}\0provider_oauth\0`)
      .update(refreshToken)
      .digest("hex");
  }

  // --------------------------------------------------------- device login

  async startDevice(input: {
    provider: SubscriptionProvider;
    workspaceId: string;
    organizationId: string;
    userId: string;
  }): Promise<DeviceStart> {
    // Hosted: 5 starts per 5 minutes per user and workspace.
    const recent = await this.database.query<{ count: number }>(
      `SELECT count(*)::int AS count FROM selfhost_coding_agent_device_sessions
        WHERE user_id = $1 AND workspace_id = $2 AND model_provider = $3
          AND created_at > now() - interval '5 minutes'`,
      [input.userId, input.workspaceId, input.provider],
    );
    if ((recent.rows[0]?.count ?? 0) >= 5) {
      throw new CodingAgentError(429, "device_start_rate_limited", "Too many login attempts. Try again in a few minutes.");
    }
    let state: Record<string, string>;
    let verificationUri: string;
    let userCode: string;
    let intervalSeconds: number;
    let lifetimeSeconds: number;
    try {
      if (input.provider === "openai") {
        const started = await startOpenAIDeviceAuthorization(this.deviceFetch);
        state = { deviceAuthId: started.deviceAuthId, userCode: started.userCode };
        ({ verificationUri, userCode, intervalSeconds } = started);
        lifetimeSeconds = OPENAI_DEVICE_AUTH_LIFETIME_SECONDS;
      } else {
        const started = await startXaiDeviceAuthorization(this.deviceFetch);
        state = { deviceCode: started.deviceCode, userCode: started.userCode, codeVerifier: started.codeVerifier };
        ({ verificationUri, userCode, intervalSeconds } = started);
        lifetimeSeconds = started.expiresInSeconds;
      }
    } catch (error) {
      if (error instanceof OpenAIDeviceAuthError || error instanceof XaiDeviceAuthError) {
        throw new CodingAgentError(502, "device_start_failed", "The provider did not start a login. Try again.");
      }
      throw error;
    }
    const browserBinding = randomBytes(32).toString("base64url");
    const id = randomUUID();
    const now = this.now();
    const expiresAt = new Date(now.getTime() + lifetimeSeconds * 1000);
    await this.database.transaction(async (tx) => {
      await tx.query(
        `DELETE FROM selfhost_coding_agent_device_sessions
          WHERE user_id = $1 AND workspace_id = $2 AND model_provider = $3 AND status <> 'processing'
            AND created_at <= now() - interval '5 minutes'`,
        [input.userId, input.workspaceId, input.provider],
      );
      await tx.query(
        `UPDATE selfhost_coding_agent_device_sessions
            SET status = 'expired', encrypted_device_state = NULL, updated_at = now()
          WHERE user_id = $1 AND workspace_id = $2 AND model_provider = $3 AND status = 'pending'`,
        [input.userId, input.workspaceId, input.provider],
      );
      await tx.query(
        `INSERT INTO selfhost_coding_agent_device_sessions
           (id, organization_id, workspace_id, user_id, model_provider, session_fingerprint,
            encrypted_device_state, poll_interval_seconds, next_poll_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          id,
          input.organizationId,
          input.workspaceId,
          input.userId,
          input.provider,
          this.bindingFingerprint(input.provider, browserBinding),
          encryptSecret(JSON.stringify(state), this.keyring.active),
          intervalSeconds,
          new Date(now.getTime() + intervalSeconds * 1000),
          expiresAt,
        ],
      );
    });
    return {
      transactionId: id,
      verificationUri,
      userCode,
      intervalSeconds,
      expiresAt: expiresAt.toISOString(),
      browserBinding,
    };
  }

  async pollDevice(input: {
    provider: SubscriptionProvider;
    transactionId: unknown;
    workspaceId: string;
    organizationId: string;
    userId: string;
    browserBinding: string | null;
  }): Promise<DeviceStatus> {
    if (typeof input.transactionId !== "string" || !/^[0-9a-f-]{36}$/i.test(input.transactionId)) {
      throw new CodingAgentError(400, "invalid_request", "transactionId is required");
    }
    if (!input.browserBinding) throw new CodingAgentError(404, "device_session_not_found", "Login not found. Start again.");
    const fingerprint = this.bindingFingerprint(input.provider, input.browserBinding);
    const find = await this.database.query<{
      id: string; status: string; next_poll_at: Date | string; expires_at: Date | string;
      updated_at: Date | string; provider_credential_id: string | null; poll_interval_seconds: number;
    }>(
      `SELECT id, status, next_poll_at, expires_at, updated_at, provider_credential_id, poll_interval_seconds
         FROM selfhost_coding_agent_device_sessions
        WHERE id = $1 AND user_id = $2 AND workspace_id = $3 AND model_provider = $4 AND session_fingerprint = $5`,
      [input.transactionId, input.userId, input.workspaceId, input.provider, fingerprint],
    );
    const session = find.rows[0];
    if (!session) throw new CodingAgentError(404, "device_session_not_found", "Login not found. Start again.");
    const now = this.now();
    if (session.status === "completed" && session.provider_credential_id) {
      return { status: "connected", providerCredentialId: session.provider_credential_id };
    }
    if (session.status === "failed") return { status: "failed" };
    if (session.status === "expired") return { status: "expired" };
    if (new Date(session.expires_at) <= now) {
      await this.finishSession(session.id, "expired");
      return { status: "expired" };
    }
    if (session.status === "processing") {
      if (now.getTime() - new Date(session.updated_at).getTime() > STALE_PROCESSING_MS) {
        await this.finishSession(session.id, "failed");
        return { status: "failed" };
      }
      return { status: "pending", retryAfterSeconds: 2 };
    }
    const nextPoll = new Date(session.next_poll_at);
    if (nextPoll > now) {
      return { status: "pending", retryAfterSeconds: Math.max(1, Math.ceil((nextPoll.getTime() - now.getTime()) / 1000)) };
    }
    // One poll at a time: claim the row.
    const claimed = await this.database.query<{ encrypted_device_state: string }>(
      `UPDATE selfhost_coding_agent_device_sessions SET status = 'processing', updated_at = now()
        WHERE id = $1 AND status = 'pending' AND next_poll_at <= $2
        RETURNING encrypted_device_state`,
      [session.id, now],
    );
    const stateCiphertext = claimed.rows[0]?.encrypted_device_state;
    if (!stateCiphertext) return { status: "pending", retryAfterSeconds: 2 };
    const state = JSON.parse(decryptSecret(stateCiphertext, this.keyring)) as Record<string, string>;
    const backToPending = async (intervalSeconds: number) => {
      await this.database.query(
        `UPDATE selfhost_coding_agent_device_sessions
            SET status = 'pending', poll_interval_seconds = $2, next_poll_at = $3, updated_at = now()
          WHERE id = $1 AND status = 'processing'`,
        [session.id, intervalSeconds, new Date(now.getTime() + intervalSeconds * 1000)],
      );
      return { status: "pending" as const, retryAfterSeconds: intervalSeconds };
    };
    let authFile: string;
    try {
      if (input.provider === "openai") {
        const polled = await pollOpenAIDeviceAuthorization(
          { deviceAuthId: state.deviceAuthId!, userCode: state.userCode! },
          this.deviceFetch,
        );
        if (polled.status === "pending") return backToPending(session.poll_interval_seconds);
        authFile = JSON.stringify(await exchangeOpenAIDeviceAuthorization(
          { authorizationCode: polled.authorizationCode, codeVerifier: polled.codeVerifier, now },
          this.deviceFetch,
        ));
      } else {
        const polled = await pollXaiDeviceAuthorization(
          { deviceCode: state.deviceCode!, codeVerifier: state.codeVerifier!, now },
          this.deviceFetch,
        );
        if (polled.status === "pending") {
          return backToPending(polled.slowDown ? Math.min(60, session.poll_interval_seconds + 5) : session.poll_interval_seconds);
        }
        if (polled.status === "denied") {
          await this.finishSession(session.id, "failed");
          return { status: "failed", error: "The login was denied." };
        }
        if (polled.status === "expired") {
          await this.finishSession(session.id, "expired");
          return { status: "expired" };
        }
        authFile = JSON.stringify(polled.credential);
      }
    } catch (error) {
      if ((error instanceof OpenAIDeviceAuthError || error instanceof XaiDeviceAuthError) && error.retryable) {
        return backToPending(Math.max(session.poll_interval_seconds, 5));
      }
      await this.finishSession(session.id, "failed");
      return { status: "failed", error: "The provider rejected the login. Start again." };
    }
    const credentialId = await this.storeLogin({
      provider: input.provider,
      workspaceId: input.workspaceId,
      organizationId: input.organizationId,
      actor: { kind: "user", userId: input.userId },
      authFile,
    });
    await this.database.query(
      `UPDATE selfhost_coding_agent_device_sessions
          SET status = 'completed', provider_credential_id = $2, encrypted_device_state = NULL,
              completed_at = now(), updated_at = now()
        WHERE id = $1`,
      [session.id, credentialId],
    );
    return { status: "connected", providerCredentialId: credentialId };
  }

  private async finishSession(id: string, status: "failed" | "expired"): Promise<void> {
    await this.database.query(
      `UPDATE selfhost_coding_agent_device_sessions
          SET status = $2, encrypted_device_state = NULL, updated_at = now()
        WHERE id = $1 AND status IN ('pending', 'processing')`,
      [id, status],
    );
  }

  /**
   * Stores (or replaces, for the same provider account) a subscription login.
   * The first login of a provider takes sandbox access. Exported for tests and
   * for operator imports; the routes only reach it through a completed login.
   */
  async storeLogin(input: {
    provider: SubscriptionProvider;
    workspaceId: string;
    organizationId: string;
    actor: AuditActor & { kind: "user" };
    authFile: string;
  }): Promise<string> {
    if (Buffer.byteLength(input.authFile) > MAX_AUTH_FILE_BYTES) {
      throw new CodingAgentError(422, "invalid_auth_file", "Auth file is too large");
    }
    const described = describeAuthFile(input.provider, input.authFile);
    const files = SUBSCRIPTION_CLI_FILES[input.provider];
    const fingerprint = this.keyFingerprint(input.provider, described.refreshToken);
    let previousLocation: string | null = null;
    const id = await this.database.transaction(async (tx) => {
      await tx.query("SELECT id FROM selfhost_workspaces WHERE id = $1 FOR UPDATE", [input.workspaceId]);
      const existing = await tx.query<{ id: string; blob_version: number; blob_location: string }>(
        `SELECT id, blob_version, blob_location FROM selfhost_coding_agent_credentials
          WHERE workspace_id = $1 AND model_provider = $2 AND auth_type = 'provider_oauth'
            AND provider_account_id = $3
          FOR UPDATE`,
        [input.workspaceId, input.provider, described.accountId],
      );
      const current = existing.rows[0];
      const credentialId = current?.id ?? randomUUID();
      const version = (current?.blob_version ?? 0) + 1;
      const location = await this.blobs.write(input.workspaceId, credentialId, version, input.authFile, tx);
      const preview = described.email ?? files.displayName;
      if (current) {
        previousLocation = current.blob_location;
        await tx.query(
          `UPDATE selfhost_coding_agent_credentials SET
             blob_backend = $2, blob_location = $3, blob_version = $4, key_fingerprint = $5,
             account_email = COALESCE($6, account_email), secret_preview = $7,
             credential_expires_at = $8, status = 'connected', last_error = NULL,
             refresh_attempts = 0, last_authenticated_at = now(), updated_at = now()
           WHERE id = $1`,
          [credentialId, this.blobs.kind, location, version, fingerprint, described.email, preview, described.expiresAt],
        );
      } else {
        const sandbox = await tx.query<{ taken: boolean }>(
          `SELECT coalesce(bool_or(harness_active), false) AS taken FROM selfhost_coding_agent_credentials
            WHERE workspace_id = $1 AND model_provider = $2`,
          [input.workspaceId, input.provider],
        );
        await tx.query(
          `INSERT INTO selfhost_coding_agent_credentials
             (id, organization_id, workspace_id, created_by_user_id, model_provider, harness, auth_type,
              display_name, account_email, secret_ciphertext, secret_preview, key_fingerprint,
              is_active, harness_active, last_authenticated_at, blob_backend, blob_location, blob_version,
              provider_account_id, credential_expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, 'provider_oauth', $7, $8, NULL, $9, $10,
                   false, $11, now(), $12, $13, $14, $15, $16)`,
          [
            credentialId,
            input.organizationId,
            input.workspaceId,
            input.actor.userId,
            input.provider,
            files.cli,
            files.displayName,
            described.email,
            preview,
            fingerprint,
            sandbox.rows[0]?.taken !== true,
            this.blobs.kind,
            location,
            version,
            described.accountId,
            described.expiresAt,
          ],
        );
      }
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: current ? "coding_agent.login_replace" : "coding_agent.login_create",
        target: `${input.provider}:${credentialId}`,
      });
      return credentialId;
    });
    if (previousLocation) await this.blobs.remove(previousLocation).catch(() => undefined);
    return id;
  }

  // ------------------------------------------------------- run delivery

  /**
   * Issues the run-scoped reference put into an assignment payload when the
   * workspace has a selected subscription login. Returns null otherwise.
   */
  async issueRunReference(workspaceId: string, runId: string): Promise<RunCredentialReference | null> {
    const rows = await this.database.query<{ id: string; model_provider: SubscriptionProvider }>(
      `SELECT id, model_provider FROM selfhost_coding_agent_credentials
        WHERE workspace_id = $1 AND auth_type = 'provider_oauth' AND harness_active
          AND status = 'connected'
        ORDER BY model_provider`,
      [workspaceId],
    );
    if (!rows.rows.length) return null;
    const ref = opaqueToken("sh_clicred_");
    const expiresAt = new Date(this.now().getTime() + RUN_REFERENCE_TTL_MS);
    await this.database.query(
      `INSERT INTO selfhost_cli_credential_refs (ref_hash, run_id, workspace_id, credential_ids, expires_at)
       VALUES ($1, $2, $3, $4::uuid[], $5)`,
      [sha256(ref), runId, workspaceId, rows.rows.map((row) => row.id), expiresAt],
    );
    return {
      ref,
      expiresAt: expiresAt.toISOString(),
      credentials: rows.rows.map((row) => ({
        credentialId: row.id,
        provider: row.model_provider,
        cli: SUBSCRIPTION_CLI_FILES[row.model_provider].cli,
      })),
    };
  }

  private async verifyReference(ref: string | null, runId: string): Promise<{ workspaceId: string; credentialIds: string[] }> {
    if (!ref || !ref.startsWith("sh_clicred_")) {
      throw new CodingAgentError(401, "unauthorized", "Credential reference required");
    }
    const result = await this.database.query<{ workspace_id: string; credential_ids: string[] }>(
      `SELECT workspace_id, credential_ids FROM selfhost_cli_credential_refs
        WHERE ref_hash = $1 AND run_id = $2 AND revoked_at IS NULL AND expires_at > now()`,
      [sha256(ref), runId],
    );
    const row = result.rows[0];
    if (!row) throw new CodingAgentError(401, "unauthorized", "Credential reference is invalid or expired");
    return { workspaceId: row.workspace_id, credentialIds: row.credential_ids };
  }

  /** Revokes a run's references (called when the run finishes). */
  async revokeRun(runId: string): Promise<void> {
    await this.database.query(
      "UPDATE selfhost_cli_credential_refs SET revoked_at = now() WHERE run_id = $1 AND revoked_at IS NULL",
      [runId],
    );
  }

  /**
   * The worker's read: each referenced login's auth file, refreshed first when
   * the access token is about to expire. A login that cannot be refreshed and
   * is already expired is skipped (the run proceeds; the row needs attention).
   */
  async readForRun(ref: string | null, runId: string): Promise<{
    files: RunCredentialFile[];
    skipped: Array<{ credentialId: string; reason: string }>;
  }> {
    const { workspaceId, credentialIds } = await this.verifyReference(ref, runId);
    const files: RunCredentialFile[] = [];
    const skipped: Array<{ credentialId: string; reason: string }> = [];
    for (const credentialId of credentialIds) {
      try {
        const content = await this.freshAuthFile(workspaceId, credentialId);
        if (!content) {
          skipped.push({ credentialId, reason: "unavailable" });
          continue;
        }
        const row = await this.row(this.database, workspaceId, credentialId);
        const spec = SUBSCRIPTION_CLI_FILES[row!.model_provider];
        files.push({ credentialId, provider: row!.model_provider, ...spec, content });
      } catch (error) {
        if (!(error instanceof CredentialBlobError)) throw error;
        console.error("[selfhost-api] cli credential unreadable", { credentialId, code: error.code });
        skipped.push({ credentialId, reason: error.code });
      }
    }
    if (files.length) {
      await this.database.query(
        "UPDATE selfhost_coding_agent_credentials SET last_used_at = now() WHERE id = ANY($1::uuid[])",
        [files.map((file) => file.credentialId)],
      );
      await recordAudit(this.database, {
        workspaceId,
        actor: { kind: "service", subject: `run:${runId}` },
        action: "coding_agent.login_materialize",
        target: `${files.length} logins`,
      });
    }
    return { files, skipped };
  }

  private async row(executor: SqlExecutor, workspaceId: string, credentialId: string): Promise<CredentialRow | null> {
    const result = await executor.query<CredentialRow>(
      `SELECT id, model_provider, blob_location, blob_version, provider_account_id,
              credential_expires_at, status, refresh_attempts
         FROM selfhost_coding_agent_credentials
        WHERE workspace_id = $1 AND id = $2 AND auth_type = 'provider_oauth'`,
      [workspaceId, credentialId],
    );
    return result.rows[0] ?? null;
  }

  /**
   * Hosted refreshHarnessCliCredentialIfStale + refreshStoredCredentialSerialized:
   * under a per-credential advisory lock, re-read the row; refresh only when it
   * still expires within REFRESH_WINDOW_MS, so concurrent runs spend one
   * single-use refresh token, not two.
   */
  async freshAuthFile(workspaceId: string, credentialId: string): Promise<string | null> {
    let staleLocation: string | null = null;
    const content = await this.database.transaction(async (tx) => {
      await tx.query("SELECT pg_advisory_xact_lock(hashtext('selfhost-cli-credential-refresh'), hashtext($1))", [credentialId]);
      const row = await this.row(tx, workspaceId, credentialId);
      if (!row || row.status === "refresh_failed") return null;
      const current = await this.blobs.read(row.blob_location, row.id, row.blob_version, tx);
      const expiresAt = row.credential_expires_at ? new Date(row.credential_expires_at) : null;
      const now = this.now();
      if (!expiresAt || expiresAt.getTime() - now.getTime() > REFRESH_WINDOW_MS) return current;
      try {
        const refreshed = await refreshAuthFile(row.model_provider, current, this.fetchImpl, now);
        const described = describeAuthFile(row.model_provider, refreshed);
        const version = row.blob_version + 1;
        const location = await this.blobs.write(workspaceId, row.id, version, refreshed, tx);
        await tx.query(
          `UPDATE selfhost_coding_agent_credentials SET
             blob_location = $2, blob_version = $3, credential_expires_at = $4,
             key_fingerprint = $5, refresh_attempts = 0, last_refreshed_at = now(),
             last_error = NULL, status = 'connected', updated_at = now()
           WHERE id = $1`,
          [row.id, location, version, described.expiresAt, this.keyFingerprint(row.model_provider, described.refreshToken)],
        );
        staleLocation = row.blob_location;
        return refreshed;
      } catch (error) {
        if (!(error instanceof RefreshFailed) && !(error instanceof TypeError) && !(error instanceof SyntaxError)) throw error;
        const attempts = row.refresh_attempts + 1;
        const expired = expiresAt.getTime() <= now.getTime();
        await tx.query(
          `UPDATE selfhost_coding_agent_credentials SET
             refresh_attempts = $2, last_error = $3,
             status = CASE WHEN $4 THEN 'refresh_failed' ELSE status END, updated_at = now()
           WHERE id = $1`,
          [
            row.id,
            attempts,
            error instanceof RefreshFailed
              ? `Token refresh failed (HTTP ${error.status}). Sign in again if this continues.`
              : "Token refresh failed. Sign in again if this continues.",
            attempts >= MAX_FAILED_REFRESHES || expired,
          ],
        );
        return expired ? null : current;
      }
    });
    if (staleLocation) await this.blobs.remove(staleLocation).catch(() => undefined);
    return content;
  }

  /**
   * The worker's write-back after a run: the CLI may have refreshed its own
   * tokens. Accepted only for a login the reference covers, for the same
   * provider account, and only when it differs from what is stored.
   */
  async writeBack(ref: string | null, runId: string, credentialId: string, content: unknown): Promise<{ updated: boolean }> {
    const { workspaceId, credentialIds } = await this.verifyReference(ref, runId);
    if (!credentialIds.includes(credentialId)) {
      throw new CodingAgentError(404, "credential_not_found", "Credential not found");
    }
    if (typeof content !== "string" || Buffer.byteLength(content) > MAX_AUTH_FILE_BYTES) {
      throw new CodingAgentError(400, "invalid_request", "content must be the auth file as a string");
    }
    let staleLocation: string | null = null;
    const updated = await this.database.transaction(async (tx) => {
      await tx.query("SELECT pg_advisory_xact_lock(hashtext('selfhost-cli-credential-refresh'), hashtext($1))", [credentialId]);
      const row = await this.row(tx, workspaceId, credentialId);
      if (!row) throw new CodingAgentError(404, "credential_not_found", "Credential not found");
      const described = describeAuthFile(row.model_provider, content);
      if (described.accountId !== row.provider_account_id) {
        throw new CodingAgentError(409, "account_mismatch", "Auth file belongs to a different account");
      }
      const current = await this.blobs.read(row.blob_location, row.id, row.blob_version, tx);
      if (current === content) return false;
      const currentExpiry = row.credential_expires_at ? new Date(row.credential_expires_at).getTime() : 0;
      // Never replace a newer login (for example one refreshed by another run).
      if (described.expiresAt && described.expiresAt.getTime() < currentExpiry) return false;
      const version = row.blob_version + 1;
      const location = await this.blobs.write(workspaceId, row.id, version, content, tx);
      await tx.query(
        `UPDATE selfhost_coding_agent_credentials SET
           blob_location = $2, blob_version = $3, credential_expires_at = $4, key_fingerprint = $5,
           refresh_attempts = 0, last_refreshed_at = now(), last_error = NULL, status = 'connected',
           updated_at = now()
         WHERE id = $1`,
        [row.id, location, version, described.expiresAt, this.keyFingerprint(row.model_provider, described.refreshToken)],
      );
      await recordAudit(tx, {
        workspaceId,
        actor: { kind: "service", subject: `run:${runId}` },
        action: "coding_agent.login_write_back",
        target: `${row.model_provider}:${row.id}`,
      });
      staleLocation = row.blob_location;
      return true;
    });
    if (staleLocation) await this.blobs.remove(staleLocation).catch(() => undefined);
    return { updated };
  }

  /** Removes a deleted credential's object. */
  async removeBlob(location: string | null): Promise<void> {
    if (location) await this.blobs.remove(location).catch(() => undefined);
  }
}
