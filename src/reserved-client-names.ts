/**
 * Client names that only first-party flows may present. One list, shared by
 * the device-code sign-in and hosted MCP dynamic client registration.
 */

/**
 * The client name GET /login starts its device-code sign-in with. Only that
 * flow, redeemed by POST /login/poll as the browser cookie, is a browser
 * sign-in (scope "account"); POST /api/v1/auth/device/start refuses the name.
 */
export const DASHBOARD_DEVICE_CLIENT = "relay-dashboard";

/**
 * Names reserved for this product's own apps. The device flow refuses them to
 * any caller but its own; anonymous MCP client registration refuses them
 * outright, as well as any name that starts with the product brand.
 */
export const RESERVED_CLIENT_NAMES: readonly string[] = [
  DASHBOARD_DEVICE_CLIENT,
  "Agent Relay",
  "Agent Relay Desktop",
  "Agent Relay Dashboard",
  "Agent Relay Cloud",
  "Relay Dashboard",
  "Relay Control",
];
const RESERVED_BRAND_PREFIX = "agentrelay";

/** Case-insensitive comparison key that ignores spaces, hyphens and underscores. */
export function clientNameKey(name: string): string {
  return name.normalize("NFKC").toLowerCase().replace(/[\s\-_]+/gu, "");
}

const RESERVED_KEYS = new Set(RESERVED_CLIENT_NAMES.map(clientNameKey));

/** Exact match on the device flow's reserved name (its existing rule). */
export function isDeviceReservedClientName(name: string): boolean {
  return name === DASHBOARD_DEVICE_CLIENT;
}

/** Whether a self-reported client name would impersonate a first-party app. */
export function isReservedClientName(name: string): boolean {
  const key = clientNameKey(name);
  return RESERVED_KEYS.has(key) || key.startsWith(RESERVED_BRAND_PREFIX);
}
