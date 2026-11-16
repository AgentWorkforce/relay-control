import type { IncomingMessage } from "node:http";

/** The request's Authorization bearer token, or null when there is none. */
export function bearer(request: IncomingMessage): string | null {
  const header = request.headers.authorization;
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match?.[1]?.trim() || null;
}
