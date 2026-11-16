const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Canonical customer History origin stored by the Cloud importer.
 *
 * URL performs IDN-to-punycode, IP literal, host-case, port and default-port
 * normalization. DNS's trailing dot is stripped so equivalent hostnames have
 * one database identity. Plain HTTP is development-only loopback.
 */
export function canonicalRelayhistoryOrigin(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    return null;
  }
  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username || url.password || url.search || url.hash ||
    (url.pathname !== "" && url.pathname !== "/")
  ) {
    return null;
  }
  if (url.hostname.endsWith(".")) url.hostname = url.hostname.slice(0, -1);
  // PostgreSQL inet and WHATWG URL spell IPv4-mapped IPv6 differently. They
  // are unnecessary for customer History and would create two DB identities
  // for one routed destination, so both layers reject them.
  if (url.hostname.startsWith("[::ffff:")) return null;
  if (url.protocol === "http:" && !LOOPBACK_HOSTS.has(url.hostname)) return null;
  return url.origin;
}
