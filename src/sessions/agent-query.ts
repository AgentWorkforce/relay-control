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
