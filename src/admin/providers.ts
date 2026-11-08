// Self-host provider registry. Hosted delegates OAuth, token storage
// and refresh to Nango. Self-host replaces Nango with bring-your-own OAuth
// apps: an admin enters each provider's client id/secret, relaycontrol runs
// the authorization-code flow, and stores tokens encrypted at rest.
//
// Adding a provider is mechanical: add an entry to PROVIDERS. OAuth providers
// need authorize/token URLs, scopes, and (only if the provider deviates from
// RFC 6749) a `parseTokenResponse` or `tokenRequest` override.

export type AuthMode = "oauth2" | "api_key";

export type ParsedToken = {
  accessToken: string;
  refreshToken?: string | null;
  tokenType?: string | null;
  expiresIn?: number | null;
  refreshTokenExpiresIn?: number | null;
  scopes?: string[] | null;
  accountId?: string | null;
  accountLabel?: string | null;
  /** Non-secret provider details exposed to admins and runtime consumers. */
  metadata?: Record<string, unknown>;
};

export class ProviderTokenError extends Error {
  constructor(readonly code: string, message: string, readonly status?: number) {
    super(message);
    this.name = "ProviderTokenError";
  }
}

export type CredentialField = {
  key: string;
  label: string;
  secret: boolean;
  required: boolean;
  placeholder?: string;
};

type BaseProvider = {
  id: string;
  displayName: string;
  description: string;
  /** Hosted Nango config key, kept for catalog/relayfile compatibility. */
  configKey: string;
  vfsRoot: string;
  categories: string[];
  docs: string;
  /** Prefix for runtime env injection: WORKFORCE_INTEGRATION_<ENV_NAME>_TOKEN. */
  envName: string;
};

export type OAuthProvider = BaseProvider & {
  authMode: "oauth2";
  authorizeUrl: string;
  tokenUrl: string;
  defaultScopes: string[];
  scopeSeparator: " " | ",";
  /** Query parameter carrying scopes; Slack bot scopes use `scope`. */
  scopeParam?: string;
  extraAuthorizeParams?: Record<string, string>;
  /** How the client authenticates at the token endpoint. */
  clientAuth: "body" | "basic";
  /** Token endpoint body encoding. */
  tokenBody: "form" | "json";
  pkce: boolean;
  /** Where admins create the OAuth app. */
  appSetupUrl: string;
  parseTokenResponse?: (body: Record<string, unknown>) => ParsedToken;
};

export type ApiKeyProvider = BaseProvider & {
  authMode: "api_key";
  credentialFields: CredentialField[];
};

export type ProviderDefinition = OAuthProvider | ApiKeyProvider;

function str(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function num(value: unknown): number | null {
  const parsed = typeof value === "string" ? Number(value) : value;
  return typeof parsed === "number" && Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

/** RFC 6749 section 5.1 token response, with a section 5.2 error check. */
export function parseStandardTokenResponse(body: Record<string, unknown>): ParsedToken {
  if (typeof body.error === "string") {
    throw new ProviderTokenError(
      body.error,
      str(body.error_description) ?? `Provider returned ${body.error}`,
    );
  }
  const accessToken = str(body.access_token);
  if (!accessToken) {
    throw new ProviderTokenError("invalid_token_response", "Provider response had no access_token");
  }
  const scope = str(body.scope);
  return {
    accessToken,
    refreshToken: str(body.refresh_token),
    tokenType: str(body.token_type),
    expiresIn: num(body.expires_in),
    refreshTokenExpiresIn: num(body.refresh_token_expires_in),
    scopes: scope ? scope.split(/[ ,]+/).filter(Boolean) : null,
  };
}

const github: OAuthProvider = {
  id: "github",
  displayName: "GitHub",
  description: "Repositories, issues, and pull requests.",
  configKey: "github-relay",
  vfsRoot: "/github",
  categories: ["dev-tools"],
  docs: "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps",
  envName: "GITHUB",
  authMode: "oauth2",
  authorizeUrl: "https://github.com/login/oauth/authorize",
  tokenUrl: "https://github.com/login/oauth/access_token",
  defaultScopes: ["repo", "read:org", "read:user"],
  scopeSeparator: " ",
  clientAuth: "body",
  tokenBody: "form",
  pkce: true,
  appSetupUrl: "https://github.com/settings/applications/new",
};

const slack: OAuthProvider = {
  id: "slack",
  displayName: "Slack",
  description: "Channels, messages, and reactions.",
  configKey: "slack-relay",
  vfsRoot: "/slack",
  categories: ["communication"],
  docs: "https://api.slack.com/authentication/oauth-v2",
  envName: "SLACK",
  authMode: "oauth2",
  authorizeUrl: "https://slack.com/oauth/v2/authorize",
  tokenUrl: "https://slack.com/api/oauth.v2.access",
  // Hosted slack-relay bot scopes (cloud nango-integrations/INTEGRATION_SCOPES.md).
  defaultScopes: [
    "app_mentions:read", "channels:history", "channels:join", "channels:read",
    "chat:write", "chat:write.public", "groups:history", "groups:read",
    "reactions:read", "reactions:write", "users:read", "users:read.email",
  ],
  scopeSeparator: ",",
  clientAuth: "body",
  tokenBody: "form",
  pkce: false,
  appSetupUrl: "https://api.slack.com/apps",
  parseTokenResponse(body) {
    if (body.ok !== true) {
      throw new ProviderTokenError(
        str(body.error) ?? "slack_oauth_failed",
        `Slack returned ${str(body.error) ?? "an error"}`,
      );
    }
    const parsed = parseStandardTokenResponse(body);
    const team = (body.team ?? {}) as Record<string, unknown>;
    return {
      ...parsed,
      accountId: str(team.id),
      accountLabel: str(team.name),
      metadata: {
        teamId: str(team.id),
        teamName: str(team.name),
        botUserId: str(body.bot_user_id),
        appId: str(body.app_id),
      },
    };
  },
};

const linear: OAuthProvider = {
  id: "linear",
  displayName: "Linear",
  description: "Issues, projects, and comments.",
  configKey: "linear-relay",
  vfsRoot: "/linear",
  categories: ["productivity"],
  docs: "https://developers.linear.app/docs/oauth/authentication",
  envName: "LINEAR",
  authMode: "oauth2",
  authorizeUrl: "https://linear.app/oauth/authorize",
  tokenUrl: "https://api.linear.app/oauth/token",
  defaultScopes: ["read", "write", "app:assignable", "app:mentionable"],
  scopeSeparator: ",",
  // Hosted forces actor=app for linear-relay.
  extraAuthorizeParams: { actor: "app", prompt: "consent" },
  clientAuth: "body",
  tokenBody: "form",
  pkce: true,
  appSetupUrl: "https://linear.app/settings/api/applications/new",
};

const notion: OAuthProvider = {
  id: "notion",
  displayName: "Notion",
  description: "Pages, databases, and comments.",
  configKey: "notion-relay",
  vfsRoot: "/notion",
  categories: ["knowledge-base"],
  docs: "https://developers.notion.com/docs/authorization",
  envName: "NOTION",
  authMode: "oauth2",
  authorizeUrl: "https://api.notion.com/v1/oauth/authorize",
  tokenUrl: "https://api.notion.com/v1/oauth/token",
  // Notion uses integration capabilities configured on the app, not scopes.
  defaultScopes: [],
  scopeSeparator: " ",
  extraAuthorizeParams: { owner: "user" },
  clientAuth: "basic",
  tokenBody: "json",
  pkce: false,
  appSetupUrl: "https://www.notion.so/profile/integrations",
  parseTokenResponse(body) {
    const parsed = parseStandardTokenResponse(body);
    return {
      ...parsed,
      accountId: str(body.workspace_id),
      accountLabel: str(body.workspace_name),
      metadata: {
        workspaceId: str(body.workspace_id),
        workspaceName: str(body.workspace_name),
        botId: str(body.bot_id),
      },
    };
  },
};

const apiKey = (label: string, placeholder?: string): CredentialField => ({
  key: "apiKey",
  label,
  secret: true,
  required: true,
  ...(placeholder ? { placeholder } : {}),
});

const API_KEY_PROVIDERS: ApiKeyProvider[] = [
  {
    id: "posthog",
    displayName: "PostHog",
    description: "Product analytics via a personal or project API key.",
    configKey: "posthog",
    vfsRoot: "/posthog",
    categories: ["analytics"],
    docs: "https://posthog.com/docs/api",
    envName: "POSTHOG",
    authMode: "api_key",
    credentialFields: [
      apiKey("Personal API key", "phx_..."),
      { key: "host", label: "API host", secret: false, required: false, placeholder: "https://us.posthog.com" },
    ],
  },
  {
    id: "shortcut",
    displayName: "Shortcut",
    description: "Stories and epics. Use a token from a non-Observer member.",
    configKey: "shortcut",
    vfsRoot: "/shortcut",
    categories: ["productivity"],
    docs: "https://developer.shortcut.com/api/rest/v3#Authentication",
    envName: "SHORTCUT",
    authMode: "api_key",
    credentialFields: [apiKey("API token")],
  },
  {
    id: "telegram",
    displayName: "Telegram",
    description: "Bot messages via a BotFather bot token.",
    configKey: "telegram",
    vfsRoot: "/telegram",
    categories: ["communication"],
    docs: "https://core.telegram.org/bots#how-do-i-create-a-bot",
    envName: "TELEGRAM",
    authMode: "api_key",
    credentialFields: [apiKey("Bot token", "123456:ABC-...")],
  },
  {
    id: "cloudflare",
    displayName: "Cloudflare",
    description: "Cloudflare account resources via an API token.",
    configKey: "cloudflare",
    vfsRoot: "/cloudflare",
    categories: ["infrastructure"],
    docs: "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
    envName: "CLOUDFLARE",
    authMode: "api_key",
    credentialFields: [
      apiKey("API token"),
      { key: "accountId", label: "Account ID", secret: false, required: false },
    ],
  },
  {
    id: "neon",
    displayName: "Neon",
    description: "Neon Postgres projects via an API key.",
    configKey: "neon-relay",
    vfsRoot: "/neon",
    categories: ["infrastructure"],
    docs: "https://neon.tech/docs/manage/api-keys",
    envName: "NEON",
    authMode: "api_key",
    credentialFields: [apiKey("API key")],
  },
];

export const DEFAULT_PROVIDERS: readonly ProviderDefinition[] = [
  github,
  slack,
  linear,
  notion,
  ...API_KEY_PROVIDERS,
];

export class ProviderRegistry {
  readonly #providers = new Map<string, ProviderDefinition>();

  constructor(providers: readonly ProviderDefinition[] = DEFAULT_PROVIDERS) {
    for (const provider of providers) {
      if (!/^[a-z][a-z0-9-]{0,63}$/.test(provider.id)) {
        throw new Error(`Invalid provider id ${provider.id}`);
      }
      if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(provider.envName)) {
        throw new Error(`Invalid provider envName ${provider.envName}`);
      }
      this.#providers.set(provider.id, provider);
    }
  }

  list(): ProviderDefinition[] {
    return [...this.#providers.values()];
  }

  /** Resolves a provider id or hosted config key (e.g. `slack-relay`). */
  get(idOrConfigKey: string): ProviderDefinition | null {
    const key = idOrConfigKey.trim().toLowerCase();
    return this.#providers.get(key)
      ?? this.list().find((provider) => provider.configKey === key)
      ?? null;
  }
}

export function catalogEntry(provider: ProviderDefinition): Record<string, unknown> {
  return {
    id: provider.id,
    displayName: provider.displayName,
    description: provider.description,
    configKey: provider.configKey,
    vfsRoot: provider.vfsRoot,
    deprecated: false,
    backend: "selfhost",
    backends: ["selfhost"],
    sources: ["selfhost"],
    authMode: provider.authMode === "oauth2" ? "OAUTH2" : "API_KEY",
    categories: provider.categories,
    docs: provider.docs,
    ...(provider.authMode === "oauth2"
      ? {
          defaultScopes: provider.defaultScopes,
          appSetupUrl: provider.appSetupUrl,
        }
      : {
          credentialFields: provider.credentialFields,
        }),
  };
}
