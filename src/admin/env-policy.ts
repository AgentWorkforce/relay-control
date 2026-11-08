// Ported from the hosted control plane (workspace environment variables). Self-host difference: hosted routes model-provider
// keys (ANTHROPIC_API_KEY, OPENAI_API_KEY, ...) through a separate credential
// proxy and never delivers a workspace variable under those names. Self-host
// has no credential proxy, so model-provider keys saved here ARE delivered to
// runtime consumers.

export const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

/** Names that alter process startup or platform trust; refused at save. */
export const UNSAFE_DELIVERED_ENV_KEYS: ReadonlySet<string> = new Set([
  "PATH", "HOME", "SHELL", "USER", "LOGNAME", "TMPDIR",
  "NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS",
  "SSL_CERT_FILE", "SSL_CERT_DIR",
  "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
  "BASH_ENV", "ENV", "PROMPT_COMMAND",
  "PYTHONPATH", "PYTHONSTARTUP", "PERL5OPT", "RUBYOPT",
  "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
  "GCONV_PATH", "NODE_TLS_REJECT_UNAUTHORIZED",
  "GIT_ASKPASS", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR",
  "GIT_PROXY_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_EDITOR",
  "GIT_SEQUENCE_EDITOR", "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR",
  "GIT_SSL_NO_VERIFY",
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
  "http_proxy", "https_proxy", "all_proxy", "no_proxy",
  "__proto__",
]);
export const UNSAFE_DELIVERED_ENV_PREFIXES: readonly string[] = [
  "LD_", "DYLD_", "GIT_CONFIG", "GIT_TRACE",
];

/** Sandbox-provider credential families; refused at save. */
export const SANDBOX_PROVIDER_CREDENTIAL_ENV_PREFIXES: readonly string[] = [
  "E2B_", "DAYTONA_", "FREESTYLE_", "AGENT37_",
];

/** Namespaces the run launcher writes itself; saved but never delivered. */
export const LAUNCHER_OWNED_ENV_PREFIXES: readonly string[] = [
  "RELAY_", "RELAYFLOW_", "RELAYFILE_", "RELAYAUTH_", "RELAYHISTORY_",
  "RELAYCONTROL_", "WORKFLOW_", "CLOUD_API_", "S3_", "SANDBOX_",
  "LOCAL_SANDBOX_", "CALLBACK_", "CREDENTIAL_PROXY_", "HOUSE_PROXY_",
  "LAUNCH_MEMBER_", "COLD_START_", "WORKFORCE_SANDBOX_", "SELFHOST_",
];
export const LAUNCHER_OWNED_ENV_KEYS: ReadonlySet<string> = new Set([
  "RUN_ID", "USER_ID", "INTERACTIVE", "START_FROM", "RESUME_RUN_ID",
  "PREVIOUS_RUN_ID", "CLI_CREDENTIALS", "CLI_CREDENTIAL_SOURCE",
  "AWS_REGION", "AWS_DEFAULT_REGION",
]);

export const MAX_DELIVERED_ENV_VALUE_BYTES = 32 * 1024;
export const MAX_DELIVERED_ENV_TOTAL_BYTES = 256 * 1024;
export const MAX_DELIVERED_ENV_COUNT = 200;

const utf8 = new TextEncoder();

export function deliveredEnvEntryBytes(name: string, value: string): number {
  return utf8.encode(name).length + utf8.encode(value).length + 2;
}

export function isUnsafeDeliveredEnvKey(key: string): boolean {
  return UNSAFE_DELIVERED_ENV_KEYS.has(key)
    || UNSAFE_DELIVERED_ENV_PREFIXES.some((prefix) => key.startsWith(prefix));
}

export function isSandboxProviderCredentialEnvKey(key: string): boolean {
  return SANDBOX_PROVIDER_CREDENTIAL_ENV_PREFIXES.some((prefix) => key.startsWith(prefix));
}

export function isLauncherOwnedEnvKey(key: string): boolean {
  return LAUNCHER_OWNED_ENV_KEYS.has(key)
    || LAUNCHER_OWNED_ENV_PREFIXES.some((prefix) => key.startsWith(prefix));
}

/** Whether a saved workspace variable reaches flow runs / runtime consumers. */
export function envKeyReachesRuntime(key: string): boolean {
  return ENV_NAME_PATTERN.test(key)
    && !isUnsafeDeliveredEnvKey(key)
    && !isSandboxProviderCredentialEnvKey(key)
    && !isLauncherOwnedEnvKey(key);
}

export class EnvVarValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvVarValidationError";
  }
}

export function validateEnvName(name: unknown): string {
  if (typeof name !== "string" || !ENV_NAME_PATTERN.test(name)) {
    throw new EnvVarValidationError(
      "name must start with a letter or underscore and contain only letters, digits, and underscores (max 128)",
    );
  }
  if (isUnsafeDeliveredEnvKey(name)) {
    throw new EnvVarValidationError(`${name} is reserved: it alters process startup`);
  }
  if (isSandboxProviderCredentialEnvKey(name)) {
    throw new EnvVarValidationError(`${name} is reserved for sandbox provider credentials`);
  }
  return name;
}

export function validateEnvValue(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new EnvVarValidationError("value must be a non-empty string");
  }
  if (value.includes("\u0000")) {
    throw new EnvVarValidationError("value must not contain NUL bytes");
  }
  if (utf8.encode(value).length > MAX_DELIVERED_ENV_VALUE_BYTES) {
    throw new EnvVarValidationError(
      `value exceeds ${MAX_DELIVERED_ENV_VALUE_BYTES} bytes`,
    );
  }
  return value;
}

/** Hosted masking: first 2 + stars + last 2; short values are fully starred. */
export function maskValue(value: string): string {
  if (value.length <= 8) return "*".repeat(Math.max(4, value.length));
  return `${value.slice(0, 2)}${"*".repeat(Math.max(4, value.length - 4))}${value.slice(-2)}`;
}
