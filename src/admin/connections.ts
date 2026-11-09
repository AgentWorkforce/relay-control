import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";
import {
  decryptSecret,
  EncryptedSecretError,
  encryptSecret,
  hashSecret,
  type EncryptionKeyring,
} from "../crypto.js";
import { iso, recordAudit, type AuditActor } from "./audit.js";
import { maskValue } from "./env-policy.js";
import {
  parseStandardTokenResponse,
  ProviderTokenError,
  type ApiKeyProvider,
  type OAuthProvider,
  type ParsedToken,
  type ProviderDefinition,
  type ProviderRegistry,
} from "./providers.js";

const OAUTH_STATE_TTL_MS = 10 * 60 * 1_000;
/** Refresh access tokens this close to expiry before handing them out. */
const REFRESH_SKEW_MS = 2 * 60 * 1_000;
const PROVIDER_TIMEOUT_MS = 15_000;

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export class ConnectionError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "ConnectionError";
  }
}

type UserActor = AuditActor & { kind: "user" };

export type OAuthAppRecord = {
  provider: string;
  clientId: string;
  clientSecretMasked: string;
  scopes: string[];
  scopesOverridden: boolean;
  redirectUri: string;
  createdBy: string | null;
  updatedBy: string | null;
  createdAt: string;
  updatedAt: string;
};

/** Public connection record; never carries tokens or API keys. */
export type ConnectionRecord = {
  connectionId: string;
  provider: string;
  providerConfigKey: string;
  displayName: string;
  authMode: "oauth2" | "api_key";
  status: "ready" | "error";
  ready: boolean;
  scopes: string[];
  accountId: string | null;
  accountLabel: string | null;
  metadata: Record<string, unknown>;
  accessTokenExpiresAt: string | null;
  refreshable: boolean;
  lastRefreshedAt: string | null;
  lastError: string | null;
  connectedBy: string | null;
  updatedBy: string | null;
  connectedAt: string;
  updatedAt: string;
};

export type RuntimeToken = {
  connectionId: string;
  provider: string;
  authMode: "oauth2" | "api_key";
  accessToken: string;
  tokenType: string;
  expiresAt: string | null;
  scopes: string[];
  accountId: string | null;
  metadata: Record<string, unknown>;
  /** Non-secret extra fields of API-key connections (e.g. host). */
  config: Record<string, string>;
};

type StoredCredentials = {
  accessToken?: string;
  refreshToken?: string | null;
  /** API-key provider secret fields, keyed by CredentialField.key. */
  fields?: Record<string, string>;
};

type ConnectionRow = {
  id: string;
  provider: string;
  auth_mode: "oauth2" | "api_key";
  status: "ready" | "error";
  credentials_ciphertext: string;
  token_type: string | null;
  scopes: string[] | null;
  access_token_expires_at: Date | string | null;
  account_id: string | null;
  account_label: string | null;
  metadata: Record<string, unknown> | string | null;
  last_refreshed_at: Date | string | null;
  last_error: string | null;
  created_by_user_id: string | null;
  updated_by_user_id: string | null;
  created_at: Date | string;
  updated_at: Date | string;
};

const CONNECTION_COLUMNS = `id, provider, auth_mode, status, credentials_ciphertext, token_type,
  scopes, access_token_expires_at, account_id, account_label, metadata,
  last_refreshed_at, last_error, created_by_user_id, updated_by_user_id,
  created_at, updated_at`;

function metadataObject(value: ConnectionRow["metadata"]): Record<string, unknown> {
  if (!value) return {};
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as Record<string, unknown>;
    } catch {
      return {};
    }
  }
  return value;
}

function cleanText(value: unknown, field: string, max: number): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new ConnectionError(400, "invalid_request", `${field} must be a non-empty string`);
  }
  const trimmed = value.trim();
  if (trimmed.length > max || /[\u0000-\u001f\u007f]/u.test(trimmed)) {
    throw new ConnectionError(400, "invalid_request", `${field} is invalid`);
  }
  return trimmed;
}

function scopeList(value: unknown): string[] | null {
  if (value === undefined || value === null) return null;
  const items = Array.isArray(value)
    ? value
    : typeof value === "string"
      ? value.split(/[\s,]+/)
      : null;
  if (!items || items.some((item) => typeof item !== "string")) {
    throw new ConnectionError(400, "invalid_request", "scopes must be a list of strings");
  }
  const scopes = (items as string[]).map((item) => item.trim()).filter(Boolean);
  if (scopes.length > 100 || scopes.some((scope) => !/^[A-Za-z0-9_.:/-]{1,200}$/.test(scope))) {
    throw new ConnectionError(400, "invalid_request", "scopes contain an invalid entry");
  }
  return [...new Set(scopes)];
}

function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

function expiryFromNow(seconds: number | null | undefined): Date | null {
  return seconds ? new Date(Date.now() + seconds * 1_000) : null;
}

async function readTokenResponse(response: Response): Promise<Record<string, unknown>> {
  const raw = await response.text();
  const type = response.headers.get("content-type") ?? "";
  if (type.includes("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(raw));
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // fall through
  }
  throw new ProviderTokenError(
    "invalid_token_response",
    `Provider token endpoint returned an unreadable response (HTTP ${response.status})`,
    response.status,
  );
}

export class ConnectionStore {
  constructor(
    private readonly database: Database,
    private readonly keyring: EncryptionKeyring,
    private readonly providers: ProviderRegistry,
    private readonly redirectUri: string,
    private readonly fetchImpl: FetchLike = (input, init) => fetch(input, init),
    /** Installation-wide OAuth apps from the operator's config (chart Secrets). */
    private readonly operatorApps: Record<string, { clientId: string; clientSecret: string; scopes: string[] | null }> = {},
  ) {}

  /** Whether the operator configured this provider's OAuth app (chart values / env). */
  operatorConfigured(providerId: string): boolean {
    return Object.hasOwn(this.operatorApps, providerId);
  }

  provider(id: string): ProviderDefinition {
    const provider = this.providers.get(id);
    if (!provider) {
      throw new ConnectionError(404, "unknown_provider", `Unknown provider ${id}`);
    }
    return provider;
  }

  private oauthProvider(id: string): OAuthProvider {
    const provider = this.provider(id);
    if (provider.authMode !== "oauth2") {
      throw new ConnectionError(400, "not_oauth_provider", `${provider.displayName} uses an API key`);
    }
    return provider;
  }

  // ---------------------------------------------------------------- OAuth apps

  async listOAuthApps(workspaceId: string): Promise<OAuthAppRecord[]> {
    const result = await this.database.query<{
      provider: string;
      client_id: string;
      client_secret_masked: string;
      scopes: string[] | null;
      created_by_user_id: string | null;
      updated_by_user_id: string | null;
      created_at: Date | string;
      updated_at: Date | string;
    }>(
      `SELECT provider, client_id, client_secret_masked, scopes, created_by_user_id,
              updated_by_user_id, created_at, updated_at
         FROM integration_oauth_apps WHERE workspace_id = $1 ORDER BY provider`,
      [workspaceId],
    );
    return result.rows.flatMap((row) => {
      const provider = this.providers.get(row.provider);
      if (!provider || provider.authMode !== "oauth2") return [];
      return [{
        provider: row.provider,
        clientId: row.client_id,
        clientSecretMasked: row.client_secret_masked,
        scopes: row.scopes ?? provider.defaultScopes,
        scopesOverridden: row.scopes !== null,
        redirectUri: this.redirectUri,
        createdBy: row.created_by_user_id,
        updatedBy: row.updated_by_user_id,
        createdAt: iso(row.created_at),
        updatedAt: iso(row.updated_at),
      }];
    });
  }

  async putOAuthApp(input: {
    workspaceId: string;
    organizationId: string;
    provider: string;
    clientId: unknown;
    clientSecret: unknown;
    scopes: unknown;
    actor: UserActor;
  }): Promise<OAuthAppRecord> {
    const provider = this.oauthProvider(input.provider);
    const clientId = cleanText(input.clientId, "clientId", 512);
    const secret = input.clientSecret === undefined || input.clientSecret === ""
      ? null
      : cleanText(input.clientSecret, "clientSecret", 4_096);
    const scopes = scopeList(input.scopes);
    await this.database.transaction(async (tx) => {
      if (secret === null) {
        const updated = await tx.query(
          `UPDATE integration_oauth_apps
              SET client_id = $3, scopes = $4, updated_by_user_id = $5, updated_at = now()
            WHERE workspace_id = $1 AND provider = $2 RETURNING provider`,
          [input.workspaceId, provider.id, clientId, scopes, input.actor.userId],
        );
        if (updated.rows.length === 0) {
          throw new ConnectionError(400, "invalid_request", "clientSecret is required");
        }
      } else {
        await tx.query(
          `INSERT INTO integration_oauth_apps
             (workspace_id, provider, client_id, client_secret_ciphertext, client_secret_masked,
              scopes, created_by_user_id, updated_by_user_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
           ON CONFLICT (workspace_id, provider) DO UPDATE SET
             client_id = EXCLUDED.client_id,
             client_secret_ciphertext = EXCLUDED.client_secret_ciphertext,
             client_secret_masked = EXCLUDED.client_secret_masked,
             scopes = EXCLUDED.scopes,
             updated_by_user_id = EXCLUDED.updated_by_user_id,
             updated_at = now()`,
          [
            input.workspaceId,
            provider.id,
            clientId,
            encryptSecret(secret, this.keyring.active),
            maskValue(secret),
            scopes,
            input.actor.userId,
          ],
        );
      }
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: "integration.oauth_app.put",
        target: provider.id,
      });
    });
    const apps = await this.listOAuthApps(input.workspaceId);
    return apps.find((app) => app.provider === provider.id)!;
  }

  async deleteOAuthApp(input: {
    workspaceId: string;
    organizationId: string;
    provider: string;
    actor: UserActor;
  }): Promise<boolean> {
    const provider = this.oauthProvider(input.provider);
    return this.database.transaction(async (tx) => {
      const deleted = await tx.query(
        `DELETE FROM integration_oauth_apps
          WHERE workspace_id = $1 AND provider = $2 RETURNING provider`,
        [input.workspaceId, provider.id],
      );
      if (deleted.rows.length === 0) return false;
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: "integration.oauth_app.delete",
        target: provider.id,
      });
      return true;
    });
  }

  private async oauthClient(
    executor: SqlExecutor,
    workspaceId: string,
    provider: OAuthProvider,
  ): Promise<{ clientId: string; clientSecret: string; scopes: string[] }> {
    const result = await executor.query<{
      client_id: string;
      client_secret_ciphertext: string;
      scopes: string[] | null;
    }>(
      `SELECT client_id, client_secret_ciphertext, scopes
         FROM integration_oauth_apps WHERE workspace_id = $1 AND provider = $2`,
      [workspaceId, provider.id],
    );
    // The operator's app (chart values backed by a Secret) wins; a
    // per-workspace app stored through the API is the legacy fallback.
    const operator = Object.hasOwn(this.operatorApps, provider.id) ? this.operatorApps[provider.id] : undefined;
    if (operator) {
      return {
        clientId: operator.clientId,
        clientSecret: operator.clientSecret,
        scopes: operator.scopes ?? provider.defaultScopes,
      };
    }
    const row = result.rows[0];
    if (!row) {
      throw new ConnectionError(
        409,
        "oauth_app_not_configured",
        `Your administrator needs to configure the ${provider.displayName} app before it can be connected.`,
      );
    }
    try {
      return {
        clientId: row.client_id,
        clientSecret: decryptSecret(row.client_secret_ciphertext, this.keyring),
        scopes: row.scopes ?? provider.defaultScopes,
      };
    } catch (error) {
      if (error instanceof EncryptedSecretError) {
        throw new ConnectionError(
          422,
          "oauth_app_undecryptable",
          `Re-enter the ${provider.displayName} OAuth client secret`,
        );
      }
      throw error;
    }
  }

  // ---------------------------------------------------------- OAuth flow

  /** Starts the authorization-code flow. Returns the provider URL to open. */
  async startOAuth(input: {
    workspaceId: string;
    provider: string;
    userId: string;
    /** Same-origin dashboard URL the callback page returns to (already validated). */
    returnTo?: string | null;
  }): Promise<{ connectLink: string; expiresAt: string; provider: OAuthProvider }> {
    const provider = this.oauthProvider(input.provider);
    const client = await this.oauthClient(this.database, input.workspaceId, provider);
    const state = randomBytes(32).toString("base64url");
    const pkce = provider.pkce ? pkcePair() : null;
    const expiresAt = new Date(Date.now() + OAUTH_STATE_TTL_MS);
    await this.database.query(
      "DELETE FROM integration_oauth_states WHERE expires_at < now() - interval '1 day'",
    );
    await this.database.query(
      `INSERT INTO integration_oauth_states
         (state_hash, workspace_id, provider, user_id, code_verifier_ciphertext, redirect_uri, expires_at, return_to)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        hashSecret(state),
        input.workspaceId,
        provider.id,
        input.userId,
        pkce ? encryptSecret(pkce.verifier, this.keyring.active) : null,
        this.redirectUri,
        expiresAt.toISOString(),
        input.returnTo ?? null,
      ],
    );
    const url = new URL(provider.authorizeUrl);
    url.searchParams.set("client_id", client.clientId);
    url.searchParams.set("redirect_uri", this.redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("state", state);
    if (client.scopes.length > 0) {
      url.searchParams.set(provider.scopeParam ?? "scope", client.scopes.join(provider.scopeSeparator));
    }
    for (const [key, value] of Object.entries(provider.extraAuthorizeParams ?? {})) {
      url.searchParams.set(key, value);
    }
    if (pkce) {
      url.searchParams.set("code_challenge", pkce.challenge);
      url.searchParams.set("code_challenge_method", "S256");
    }
    return { connectLink: url.toString(), expiresAt: expiresAt.toISOString(), provider };
  }

  /** Handles the provider redirect. State is single-use and expires. */
  async completeOAuth(input: {
    state: string;
    code: string | null;
    error: string | null;
  }): Promise<{ workspaceId: string; connection: ConnectionRecord; returnTo: string | null }> {
    const consumed = await this.database.query<{
      return_to: string | null;
      workspace_id: string;
      provider: string;
      user_id: string;
      code_verifier_ciphertext: string | null;
      redirect_uri: string;
      organization_id: string;
    }>(
      `UPDATE integration_oauth_states s
          SET consumed_at = now()
         FROM workspaces w
        WHERE s.state_hash = $1
          AND s.consumed_at IS NULL
          AND s.expires_at > now()
          AND w.id = s.workspace_id
        RETURNING s.workspace_id, s.provider, s.user_id, s.code_verifier_ciphertext,
                  s.redirect_uri, s.return_to, w.organization_id`,
      [hashSecret(input.state)],
    );
    const state = consumed.rows[0];
    if (!state) {
      throw new ConnectionError(400, "invalid_state", "This connection link is invalid or has expired");
    }
    const provider = this.oauthProvider(state.provider);
    if (input.error) {
      throw new ConnectionError(
        400,
        "authorization_denied",
        `${provider.displayName} did not authorize the connection (${input.error.slice(0, 100)})`,
      );
    }
    if (!input.code) {
      throw new ConnectionError(400, "invalid_request", "Authorization code is missing");
    }
    const client = await this.oauthClient(this.database, state.workspace_id, provider);
    const verifier = state.code_verifier_ciphertext
      ? decryptSecret(state.code_verifier_ciphertext, this.keyring)
      : null;
    const token = await this.tokenRequest(provider, client, {
      grant_type: "authorization_code",
      code: input.code,
      redirect_uri: state.redirect_uri,
      ...(verifier ? { code_verifier: verifier } : {}),
    });
    const connection = await this.saveOAuthConnection({
      workspaceId: state.workspace_id,
      organizationId: state.organization_id,
      provider,
      token,
      actor: { kind: "user", userId: state.user_id },
    });
    return { workspaceId: state.workspace_id, connection, returnTo: state.return_to };
  }

  private async tokenRequest(
    provider: OAuthProvider,
    client: { clientId: string; clientSecret: string },
    params: Record<string, string>,
  ): Promise<ParsedToken> {
    const headers: Record<string, string> = { accept: "application/json" };
    const body: Record<string, string> = { ...params };
    if (provider.clientAuth === "basic") {
      headers.authorization = `Basic ${Buffer.from(
        `${client.clientId}:${client.clientSecret}`,
      ).toString("base64")}`;
    } else {
      body.client_id = client.clientId;
      body.client_secret = client.clientSecret;
    }
    let encoded: string;
    if (provider.tokenBody === "json") {
      headers["content-type"] = "application/json";
      encoded = JSON.stringify(body);
    } else {
      headers["content-type"] = "application/x-www-form-urlencoded";
      encoded = new URLSearchParams(body).toString();
    }
    let response: Response;
    try {
      response = await this.fetchImpl(provider.tokenUrl, {
        method: "POST",
        headers,
        body: encoded,
        redirect: "error",
        signal: AbortSignal.timeout(PROVIDER_TIMEOUT_MS),
      });
    } catch {
      throw new ProviderTokenError(
        "provider_unreachable",
        `${provider.displayName} token endpoint is unreachable`,
      );
    }
    const parsedBody = await readTokenResponse(response);
    if (!response.ok && typeof parsedBody.error !== "string") {
      throw new ProviderTokenError(
        "token_request_failed",
        `${provider.displayName} token endpoint returned HTTP ${response.status}`,
        response.status,
      );
    }
    return provider.parseTokenResponse
      ? provider.parseTokenResponse(parsedBody)
      : parseStandardTokenResponse(parsedBody);
  }

  private async saveOAuthConnection(input: {
    workspaceId: string;
    organizationId: string;
    provider: OAuthProvider;
    token: ParsedToken;
    actor: UserActor;
  }): Promise<ConnectionRecord> {
    const credentials: StoredCredentials = {
      accessToken: input.token.accessToken,
      refreshToken: input.token.refreshToken ?? null,
    };
    return this.upsertConnection({
      workspaceId: input.workspaceId,
      organizationId: input.organizationId,
      provider: input.provider,
      credentials,
      tokenType: input.token.tokenType ?? "bearer",
      scopes: input.token.scopes ?? null,
      expiresAt: expiryFromNow(input.token.expiresIn),
      refreshExpiresAt: expiryFromNow(input.token.refreshTokenExpiresIn),
      accountId: input.token.accountId ?? null,
      accountLabel: input.token.accountLabel ?? null,
      metadata: input.token.metadata ?? {},
      actor: input.actor,
    });
  }

  private async upsertConnection(input: {
    workspaceId: string;
    organizationId: string;
    provider: ProviderDefinition;
    credentials: StoredCredentials;
    tokenType: string | null;
    scopes: string[] | null;
    expiresAt: Date | null;
    refreshExpiresAt: Date | null;
    accountId: string | null;
    accountLabel: string | null;
    metadata: Record<string, unknown>;
    actor: UserActor;
  }): Promise<ConnectionRecord> {
    return this.database.transaction(async (tx) => {
      const result = await tx.query<ConnectionRow>(
        `INSERT INTO integration_connections
           (id, workspace_id, provider, auth_mode, status, credentials_ciphertext, token_type,
            scopes, access_token_expires_at, refresh_token_expires_at, account_id,
            account_label, metadata, created_by_user_id, updated_by_user_id)
         VALUES ($1, $2, $3, $4, 'ready', $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13, $13)
         ON CONFLICT (workspace_id, provider) DO UPDATE SET
           auth_mode = EXCLUDED.auth_mode,
           status = 'ready',
           credentials_ciphertext = EXCLUDED.credentials_ciphertext,
           token_type = EXCLUDED.token_type,
           scopes = EXCLUDED.scopes,
           access_token_expires_at = EXCLUDED.access_token_expires_at,
           refresh_token_expires_at = EXCLUDED.refresh_token_expires_at,
           account_id = EXCLUDED.account_id,
           account_label = EXCLUDED.account_label,
           metadata = EXCLUDED.metadata,
           last_error = NULL,
           last_refreshed_at = NULL,
           updated_by_user_id = EXCLUDED.updated_by_user_id,
           updated_at = now()
         RETURNING ${CONNECTION_COLUMNS}`,
        [
          randomUUID(),
          input.workspaceId,
          input.provider.id,
          input.provider.authMode,
          encryptSecret(JSON.stringify(input.credentials), this.keyring.active),
          input.tokenType,
          input.scopes,
          input.expiresAt?.toISOString() ?? null,
          input.refreshExpiresAt?.toISOString() ?? null,
          input.accountId,
          input.accountLabel,
          JSON.stringify(input.metadata),
          input.actor.userId,
        ],
      );
      const row = result.rows[0]!;
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: "integration.connect",
        target: input.provider.id,
      });
      return this.toRecord(row);
    });
  }

  // ------------------------------------------------------- API-key providers

  async putApiKeyConnection(input: {
    workspaceId: string;
    organizationId: string;
    provider: string;
    credentials: unknown;
    actor: UserActor;
  }): Promise<ConnectionRecord> {
    const provider = this.provider(input.provider);
    if (provider.authMode !== "api_key") {
      throw new ConnectionError(
        400,
        "oauth_provider",
        `${provider.displayName} connects with OAuth; use connect-session`,
      );
    }
    const supplied = input.credentials;
    if (!supplied || typeof supplied !== "object" || Array.isArray(supplied)) {
      throw new ConnectionError(400, "invalid_request", "credentials must be an object");
    }
    const { secrets, config } = this.apiKeyFields(provider, supplied as Record<string, unknown>);
    return this.upsertConnection({
      workspaceId: input.workspaceId,
      organizationId: input.organizationId,
      provider,
      credentials: { fields: secrets },
      tokenType: "api_key",
      scopes: null,
      expiresAt: null,
      refreshExpiresAt: null,
      accountId: null,
      accountLabel: null,
      metadata: { config },
      actor: input.actor,
    });
  }

  private apiKeyFields(
    provider: ApiKeyProvider,
    supplied: Record<string, unknown>,
  ): { secrets: Record<string, string>; config: Record<string, string> } {
    const secrets: Record<string, string> = {};
    const config: Record<string, string> = {};
    const known = new Set(provider.credentialFields.map((field) => field.key));
    for (const key of Object.keys(supplied)) {
      if (!known.has(key)) {
        throw new ConnectionError(400, "invalid_request", `Unknown credential field ${key}`);
      }
    }
    for (const field of provider.credentialFields) {
      const value = supplied[field.key];
      if (value === undefined || value === null || value === "") {
        if (field.required) {
          throw new ConnectionError(400, "invalid_request", `${field.label} is required`);
        }
        continue;
      }
      const cleaned = cleanText(value, field.label, 8_192);
      (field.secret ? secrets : config)[field.key] = cleaned;
    }
    return { secrets, config };
  }

  // ------------------------------------------------------------ connections

  private toRecord(row: ConnectionRow): ConnectionRecord {
    const provider = this.providers.get(row.provider);
    let refreshable = false;
    if (row.auth_mode === "oauth2") {
      try {
        refreshable = Boolean(this.credentials(row).refreshToken);
      } catch {
        refreshable = false;
      }
    }
    return {
      connectionId: row.id,
      provider: row.provider,
      providerConfigKey: provider?.configKey ?? row.provider,
      displayName: provider?.displayName ?? row.provider,
      authMode: row.auth_mode,
      status: row.status,
      ready: row.status === "ready",
      scopes: row.scopes ?? [],
      accountId: row.account_id,
      accountLabel: row.account_label,
      metadata: metadataObject(row.metadata),
      accessTokenExpiresAt: row.access_token_expires_at ? iso(row.access_token_expires_at) : null,
      refreshable,
      lastRefreshedAt: row.last_refreshed_at ? iso(row.last_refreshed_at) : null,
      lastError: row.last_error,
      connectedBy: row.created_by_user_id,
      updatedBy: row.updated_by_user_id,
      connectedAt: iso(row.created_at),
      updatedAt: iso(row.updated_at),
    };
  }

  private credentials(row: Pick<ConnectionRow, "credentials_ciphertext">): StoredCredentials {
    return JSON.parse(decryptSecret(row.credentials_ciphertext, this.keyring)) as StoredCredentials;
  }

  async list(workspaceId: string): Promise<ConnectionRecord[]> {
    const result = await this.database.query<ConnectionRow>(
      `SELECT ${CONNECTION_COLUMNS} FROM integration_connections
        WHERE workspace_id = $1 ORDER BY provider`,
      [workspaceId],
    );
    return result.rows.map((row) => this.toRecord(row));
  }

  async get(workspaceId: string, providerId: string): Promise<ConnectionRecord | null> {
    const provider = this.provider(providerId);
    const result = await this.database.query<ConnectionRow>(
      `SELECT ${CONNECTION_COLUMNS} FROM integration_connections
        WHERE workspace_id = $1 AND provider = $2`,
      [workspaceId, provider.id],
    );
    return result.rows[0] ? this.toRecord(result.rows[0]) : null;
  }

  async disconnect(input: {
    workspaceId: string;
    organizationId: string;
    provider: string;
    actor: AuditActor;
  }): Promise<boolean> {
    const provider = this.provider(input.provider);
    return this.database.transaction(async (tx) => {
      const deleted = await tx.query(
        `DELETE FROM integration_connections
          WHERE workspace_id = $1 AND provider = $2 RETURNING id`,
        [input.workspaceId, provider.id],
      );
      if (deleted.rows.length === 0) return false;
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: "integration.disconnect",
        target: provider.id,
      });
      return true;
    });
  }

  /**
   * Runtime token fetch. Refreshes OAuth tokens that are expired or within
   * REFRESH_SKEW_MS of expiry (or when forced) under a row lock, so
   * concurrent consumers never race a refresh-token rotation.
   */
  async runtimeToken(input: {
    workspaceId: string;
    provider: string;
    forceRefresh?: boolean;
    actor: AuditActor;
  }): Promise<RuntimeToken> {
    const provider = this.provider(input.provider);
    const token = await this.database.transaction(async (tx) => {
      const result = await tx.query<ConnectionRow>(
        `SELECT ${CONNECTION_COLUMNS} FROM integration_connections
          WHERE workspace_id = $1 AND provider = $2 FOR UPDATE`,
        [input.workspaceId, provider.id],
      );
      const row = result.rows[0];
      if (!row) {
        throw new ConnectionError(404, "connection_not_found", `${provider.displayName} is not connected`);
      }
      let credentials: StoredCredentials;
      try {
        credentials = this.credentials(row);
      } catch (error) {
        if (error instanceof EncryptedSecretError) {
          throw new ConnectionError(
            422,
            "connection_undecryptable",
            `Reconnect ${provider.displayName}: stored credentials are unreadable`,
          );
        }
        throw error;
      }
      const config = (metadataObject(row.metadata).config ?? {}) as Record<string, string>;
      if (provider.authMode === "api_key") {
        const primary = provider.credentialFields.find((field) => field.secret)!;
        return this.runtimeResult(row, credentials.fields?.[primary.key] ?? "", "api_key", null, config);
      }

      const expiresAt = row.access_token_expires_at ? new Date(iso(row.access_token_expires_at)) : null;
      const stale = expiresAt !== null && expiresAt.getTime() - Date.now() < REFRESH_SKEW_MS;
      if (!input.forceRefresh && !stale && row.status === "ready") {
        return this.runtimeResult(row, credentials.accessToken!, row.token_type ?? "bearer", expiresAt, config);
      }
      if (!credentials.refreshToken) {
        if (stale) {
          await this.markError(tx, row.id, "token_expired");
          return { error: new ConnectionError(409, "token_expired", `Reconnect ${provider.displayName}: the access token expired and is not refreshable`) };
        }
        if (row.status !== "ready") {
          return { error: new ConnectionError(409, "connection_error", `Reconnect ${provider.displayName}: ${row.last_error ?? "connection error"}`) };
        }
        return this.runtimeResult(row, credentials.accessToken!, row.token_type ?? "bearer", expiresAt, config);
      }
      let refreshed: ParsedToken;
      try {
        const client = await this.oauthClient(tx, input.workspaceId, provider);
        refreshed = await this.tokenRequest(provider, client, {
          grant_type: "refresh_token",
          refresh_token: credentials.refreshToken,
        });
      } catch (error) {
        if (error instanceof ProviderTokenError || error instanceof ConnectionError) {
          await this.markError(tx, row.id, `refresh_failed: ${error.code}`);
          return {
            error: new ConnectionError(
              error instanceof ProviderTokenError && error.code === "provider_unreachable" ? 503 : 409,
              "refresh_failed",
              `${provider.displayName} token refresh failed (${error.code})`,
            ),
          };
        }
        throw error;
      }
      const next: StoredCredentials = {
        accessToken: refreshed.accessToken,
        // Providers that do not rotate refresh tokens omit them on refresh.
        refreshToken: refreshed.refreshToken ?? credentials.refreshToken,
      };
      const nextExpiry = expiryFromNow(refreshed.expiresIn);
      const updated = await tx.query<ConnectionRow>(
        `UPDATE integration_connections SET
           status = 'ready',
           credentials_ciphertext = $2,
           token_type = COALESCE($3, token_type),
           scopes = COALESCE($4, scopes),
           access_token_expires_at = $5,
           refresh_token_expires_at = COALESCE($6, refresh_token_expires_at),
           last_refreshed_at = now(),
           last_error = NULL,
           updated_at = now()
         WHERE id = $1
         RETURNING ${CONNECTION_COLUMNS}`,
        [
          row.id,
          encryptSecret(JSON.stringify(next), this.keyring.active),
          refreshed.tokenType ?? null,
          refreshed.scopes ?? null,
          nextExpiry?.toISOString() ?? null,
          expiryFromNow(refreshed.refreshTokenExpiresIn)?.toISOString() ?? null,
        ],
      );
      await recordAudit(tx, {
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: "integration.refresh",
        target: provider.id,
      });
      return this.runtimeResult(updated.rows[0]!, next.accessToken!, updated.rows[0]!.token_type ?? "bearer", nextExpiry, config);
    });
    // Errors are returned (not thrown) from the transaction so the error
    // status written by markError commits.
    if ("error" in token) throw token.error;
    await recordAudit(this.database, {
      workspaceId: input.workspaceId,
      actor: input.actor,
      action: "integration.token_read",
      target: provider.id,
    });
    return token;
  }

  private runtimeResult(
    row: ConnectionRow,
    accessToken: string,
    tokenType: string,
    expiresAt: Date | null,
    config: Record<string, string>,
  ): RuntimeToken {
    const metadata = { ...metadataObject(row.metadata) };
    delete metadata.config;
    return {
      connectionId: row.id,
      provider: row.provider,
      authMode: row.auth_mode,
      accessToken,
      tokenType,
      expiresAt: expiresAt?.toISOString() ?? null,
      scopes: row.scopes ?? [],
      accountId: row.account_id,
      metadata,
      config,
    };
  }

  private async markError(executor: SqlExecutor, id: string, message: string): Promise<void> {
    await executor.query(
      `UPDATE integration_connections
          SET status = 'error', last_error = $2, updated_at = now() WHERE id = $1`,
      [id, message.slice(0, 500)],
    );
  }

  /**
   * Hosted-compatible env injection (cloud lib/integrations/
   * nango-runtime-credential-env.ts): WORKFORCE_INTEGRATION_<P>_TOKEN plus
   * WORKFORCE_INTEGRATION_<P>_<CONFIG_KEY> for non-secret config. Best effort:
   * a connection that cannot produce a token is reported, never fatal.
   */
  async runtimeIntegrationEnv(
    workspaceId: string,
    actor: AuditActor,
  ): Promise<{ env: Record<string, string>; failed: Array<{ provider: string; error: string }> }> {
    const env: Record<string, string> = {};
    const failed: Array<{ provider: string; error: string }> = [];
    for (const connection of await this.list(workspaceId)) {
      const provider = this.providers.get(connection.provider);
      if (!provider) continue;
      try {
        const token = await this.runtimeToken({ workspaceId, provider: provider.id, actor });
        const prefix = `WORKFORCE_INTEGRATION_${provider.envName}`;
        env[`${prefix}_TOKEN`] = token.accessToken;
        for (const [key, value] of Object.entries(token.config)) {
          const suffix = key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toUpperCase().replace(/[^A-Z0-9_]/g, "_");
          env[`${prefix}_${suffix}`] = value;
        }
      } catch (error) {
        failed.push({
          provider: provider.id,
          error: error instanceof ConnectionError ? error.code : "token_unavailable",
        });
      }
    }
    return { env, failed };
  }
}
