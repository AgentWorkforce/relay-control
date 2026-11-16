/**
 * Cloud owns agent_relay_session on Path=/ while Control historically uses
 * the same name on Path=/cloud. Browsers may send both values, in either
 * order, so select the value that has Control's access-token prefix.
 */
export const SESSION_COOKIE = "agent_relay_session";
export const CONTROL_ACCESS_TOKEN_PREFIX = "sh_at_";

export function controlSessionToken(cookieHeader: string | null | undefined): string | null {
  for (const part of (cookieHeader ?? "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0 || part.slice(0, separator).trim() !== SESSION_COOKIE) continue;
    try {
      const value = decodeURIComponent(part.slice(separator + 1).trim());
      if (value.startsWith(CONTROL_ACCESS_TOKEN_PREFIX)) return value;
    } catch {
      // A malformed Cloud cookie must not hide a later valid Control cookie.
    }
  }
  return null;
}
