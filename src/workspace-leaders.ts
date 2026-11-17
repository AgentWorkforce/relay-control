/**
 * Workspace leaders (docs/workspace-leaders.md): agent-name patterns stored
 * by the Relaycast engine, not here. This module only validates a PUT body
 * with the engine's rules, so a bad request is refused before the workspace
 * key is spent:
 *
 * - at most MAX_LEADER_PATTERNS patterns;
 * - each pattern is trimmed and must then be 1..MAX_LEADER_PATTERN_LENGTH
 *   characters with no control characters;
 * - duplicates collapse, keeping the first occurrence's order;
 * - `*` and `?` are the only wildcards, everything else is literal, and a
 *   pattern matches the whole agent name, case-sensitively (the engine does
 *   the matching).
 */

export const MAX_LEADER_PATTERNS = 64;
export const MAX_LEADER_PATTERN_LENGTH = 128;

export class LeaderPatternsError extends Error {
  readonly status = 400;
  readonly code = "invalid_request";
  constructor(message: string) {
    super(message);
    this.name = "LeaderPatternsError";
  }
}

/** The normalised `patterns` of a `{ patterns: string[] }` body; `[]` clears. */
export function parseLeaderPatterns(body: unknown): string[] {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new LeaderPatternsError("Body must be a JSON object");
  }
  const extra = Object.keys(body).filter((key) => key !== "patterns");
  if (extra.length > 0) throw new LeaderPatternsError(`Unknown field: ${extra[0]!.slice(0, 64)}`);
  const given = (body as Record<string, unknown>).patterns;
  if (!Array.isArray(given)) throw new LeaderPatternsError("patterns must be an array of strings");
  if (given.length > MAX_LEADER_PATTERNS) {
    throw new LeaderPatternsError(`patterns may hold at most ${MAX_LEADER_PATTERNS} entries`);
  }
  const patterns: string[] = [];
  for (const entry of given) {
    if (typeof entry !== "string") throw new LeaderPatternsError("patterns must be an array of strings");
    const pattern = entry.trim();
    if (pattern.length < 1 || pattern.length > MAX_LEADER_PATTERN_LENGTH) {
      throw new LeaderPatternsError(`Each pattern must be 1 to ${MAX_LEADER_PATTERN_LENGTH} characters after trimming`);
    }
    if (/\p{Cc}/u.test(pattern)) throw new LeaderPatternsError("Patterns may not contain control characters");
    if (!patterns.includes(pattern)) patterns.push(pattern);
  }
  return patterns;
}
