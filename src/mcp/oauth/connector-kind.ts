// Which MCP client an OAuth grant belongs to, from its registered redirect
// URIs. A leaf (no imports) so the request-auth path can classify a grant
// without loading the connectors dashboard module.

export type ConnectorKind = "chatgpt" | "grok-bot" | "muse" | "mcp";

export function hostOf(uri: string): { scheme: string; host: string; displayHost: string; path: string } | null {
  try {
    const url = new URL(uri);
    return {
      scheme: url.protocol.replace(/:$/, ""),
      host: url.hostname.toLowerCase(),
      displayHost: url.host.toLowerCase(),
      path: url.pathname,
    };
  } catch {
    return null;
  }
}

const under = (host: string, domain: string) => host === domain || host.endsWith(`.${domain}`);

/**
 * Which client a grant belongs to, from what it registered. Grok Bot runs on
 * Cursor's cloud-agent backend and registers its
 * https://www.cursor.com/agents/... callback (plus cursor:// and localhost);
 * the Cursor IDE registers cursor:// too, so cursor:// alone is not Grok Bot.
 * ChatGPT registers chatgpt.com / openai.com callbacks. The client name is
 * self-reported, so it never decides the kind; a grant with a routine is Grok
 * Bot unless its registered callback identifies Muse, whose polling uses
 * the same ingest infrastructure.
 */
export function connectorKind(client: { clientName: string | null; redirectUris: string[] }): ConnectorKind {
  // Mixed registrations retain the established Grok, then ChatGPT, then Muse
  // precedence. This is provider presentation, never additional OAuth authority.
  const hosts = client.redirectUris.map(hostOf).filter((value) => value !== null);
  if (hosts.some(({ host, path }) => (under(host, "cursor.com") && path.startsWith("/agents/")) || under(host, "x.ai"))) return "grok-bot";
  if (hosts.some(({ host }) => under(host, "chatgpt.com") || under(host, "openai.com"))) return "chatgpt";
  if (hosts.some(({ scheme, host }) => scheme === "https" && (under(host, "muse.ai") || under(host, "agent.meta.ai")))) return "muse";
  return "mcp";
}
