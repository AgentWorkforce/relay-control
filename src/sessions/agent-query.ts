/**
 * `@name` tokens in a session search query (docs in openapi.yaml). A token is a
 * whitespace-separated word starting with `@`: a name of letters, digits, `-`,
 * `_` or `.`, an optional `@node` suffix, and an optional trailing `*` for a
 * prefix match. Anything else, such as an email address or `@foo!`, stays free
 * text so ordinary searches keep working.
 */
const AGENT_TOKEN = /^@([a-z0-9._-]+(?:@[a-z0-9._-]+)?\*?)$/i;

export type AgentQuery = {
  /** The query with agent tokens removed, whitespace collapsed. */
  text: string;
  /** Lowercased and de-duplicated, in first-seen order. A trailing `*` means prefix. */
  agents: string[];
};

/** An explicit `agent` parameter: a token without its leading `@`. */
export const AGENT_VALUE = /^[a-z0-9._-]+(?:@[a-z0-9._-]+)?\*?$/i;

export type AgentSelection = {
  /** The one agent sent to the backend, which serves a single agent per request. */
  agent?: string;
  /** Further agents named in the query, reported rather than silently dropped. */
  ignored: string[];
  text?: string;
};

/**
 * Picks the agent for one request. `parseTokens` is off until an installation
 * enables `@name` parsing, so existing free-text searches are unchanged.
 */
export function selectAgent(
  explicit: string | undefined,
  query: string | undefined,
  parseTokens: boolean,
): AgentSelection {
  const parsed = parseTokens && query ? parseAgentQuery(query) : { text: query ?? "", agents: [] };
  const [agent, ...ignored] = [...new Set([...(explicit ? [explicit.toLowerCase()] : []), ...parsed.agents])];
  return { ...(agent ? { agent } : {}), ignored, ...(parsed.text ? { text: parsed.text } : {}) };
}

/** A `*` value needs enough of a name for the prefix index to be selective. */
export function agentPrefixTooShort(agent: string): boolean {
  return agent.endsWith("*") && agent.slice(0, -1).replace(/[^a-z0-9]/gi, "").length < 3;
}

export function parseAgentQuery(query: string): AgentQuery {
  const agents = new Set<string>();
  const text: string[] = [];
  for (const word of query.split(/\s+/u).filter(Boolean)) {
    const token = AGENT_TOKEN.exec(word);
    if (token) agents.add(token[1]!.toLowerCase());
    else text.push(word);
  }
  return { text: text.join(" "), agents: [...agents] };
}
