// telemetry lane: identifier hashing, error fingerprints, route templates.
import { createHash, createHmac } from "node:crypto";

/**
 * Hash an identifier (workspace id, agent name...) with the per-install salt.
 * The salt is generated locally and never sent, so the hosted side cannot
 * reverse or correlate the hashes across installs.
 */
export function hashIdentifier(salt: string, value: string): string {
  return `h_${createHmac("sha256", salt).update(value).digest("hex").slice(0, 20)}`;
}

/** Literal path words kept in a route template; everything else becomes :id. */
const ID_PARENTS = new Set([
  "organizations", "workspaces", "memberships", "sessions", "events", "flows", "runs",
  "workers", "connections", "integrations", "tokens", "env", "environment", "secrets",
  "issues", "reports", "agents", "channels", "steps", "objects", "deployment-api-tokens",
]);

export function routeTemplate(rawPath: string): string {
  const path = rawPath.split("?")[0]!.replace(/\/+$/, "") || "/";
  const segments = path.split("/");
  const output: string[] = [];
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index]!;
    if (index === 0) {
      output.push("");
      continue;
    }
    const previous = segments[index - 1] ?? "";
    const literal = /^(?:v\d{1,2}|[a-z][a-z-]{0,39})$/.test(segment);
    output.push(literal && !ID_PARENTS.has(previous) ? segment : ":id");
  }
  return output.slice(0, 12).join("/") || "/";
}

/**
 * Stable fingerprint for an error: its class, code, component, and the top
 * stack frames reduced to `function@file` (no absolute paths, line numbers,
 * or message text, so the same bug fingerprints the same across releases).
 */
export function errorFingerprint(input: {
  component: string;
  errorClass: string;
  code?: string | null;
  stack?: string | null;
}): string {
  const frames = (input.stack ?? "")
    .split("\n")
    .slice(1)
    .map((line) => {
      const match = /at\s+(?:(\S+)\s+\()?(?:.*[\\/])?([^\\/():]+)(?::\d+){0,2}\)?\s*$/.exec(line.trim());
      return match ? `${match[1] ?? "<anon>"}@${match[2]}` : null;
    })
    .filter((frame): frame is string => Boolean(frame) && !frame!.includes("node:internal"))
    .slice(0, 6);
  return `fp_${createHash("sha256")
    .update([input.component, input.errorClass, input.code ?? "", ...frames].join("|"))
    .digest("hex")
    .slice(0, 16)}`;
}
