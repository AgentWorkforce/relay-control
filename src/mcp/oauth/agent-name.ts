/**
 * Relay agent-name rules, shared by server validation and client forms.
 * Must stay free of server-only imports: the OAuth consent form bundles it.
 */
export const AGENT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
export const AGENT_NAME_MAX_LENGTH = 128;

// Names reserved for internal trust-bearing minters. Any agent the cloud
// uses to short-circuit per-request gates (writeback queueing, auth bypass,
// etc.) MUST live here so the same name can't be obtained by an external
// caller through /join or /provision and impersonate the internal flow.
//
// Keep in sync with `PROVIDER_SYNC_AGENT_NAMES` in `relayfile-cloud`'s auth
// middleware.
export const RESERVED_AGENT_NAMES: ReadonlySet<string> = new Set([
  "cloud-github",
  "github-clone-worker",
  "nango-sync-worker",
  "nango-sync-workflow",
]);

export function isValidAgentName(value: string): boolean {
  return agentNameError(value) === null;
}

/** A short, user-facing reason the name is invalid, or null when it is valid. */
export function agentNameError(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return "Enter a name.";
  if (trimmed.length > AGENT_NAME_MAX_LENGTH) return `Use at most ${AGENT_NAME_MAX_LENGTH} characters.`;
  if (!/^[A-Za-z0-9]/u.test(trimmed)) return "Start with a letter or digit.";
  if (!AGENT_NAME_PATTERN.test(trimmed)) return "Use only letters, digits, dots, dashes or underscores.";
  // Reject names reserved for internal trust-bearing minters so external
  // callers can't mint a token whose claims would short-circuit
  // server-side gates (e.g. `isProviderSyncWriter` in `relayfile-cloud`'s
  // auth middleware).
  if (RESERVED_AGENT_NAMES.has(trimmed)) return "That name is reserved. Pick another.";
  return null;
}
