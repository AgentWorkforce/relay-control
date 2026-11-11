// Agent Relay Desktop opens browser links as `<its site>` plus a Cloud-shaped
// dashboard path (`/cloud/dashboard/...`, `/dashboard/...`). Its site is the
// public API origin, so on an install whose dashboard (relay-webapp) has its
// own host those links reach this service. Installed Desktop builds cannot be
// changed quickly, so a browser GET/HEAD here is sent to the matching
// relay-webapp route on SELFHOST_DASHBOARD_URL.
//
// Only that configured origin is ever named, never a host from the request.
// When the dashboard shares this service's origin (single-host), or the request
// already arrived on the dashboard host, nothing is redirected.

const DASHBOARD_PATH = /^\/(cloud\/)?dashboard(?:\/(.*))?$/;
/** History sources are harness names (`claude`, `codex`, ...). */
const SOURCE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_SESSION_ID = 256;

export type DashboardLinkInput = {
  method: string;
  /** The request target as received (`request.url`): raw path plus query. */
  target: string;
  host: string | undefined;
  publicBaseUrl: string;
  dashboardUrl: string;
};

/** The absolute dashboard URL to send this request to, or null to leave it alone. */
export function dashboardLinkRedirect(input: DashboardLinkInput): string | null {
  if (input.method !== "GET" && input.method !== "HEAD") return null;
  const dashboard = new URL(input.dashboardUrl);
  if (dashboard.origin === new URL(input.publicBaseUrl).origin) return null;
  if ((input.host ?? "").trim().toLowerCase() === dashboard.host.toLowerCase()) return null;

  let target: URL;
  try {
    target = new URL(input.target, "http://request.invalid");
  } catch {
    return null;
  }
  const match = DASHBOARD_PATH.exec(target.pathname.replace(/\/+$/, ""));
  if (!match) return null;
  const cloudPrefix = Boolean(match[1]);
  const segments = (match[2] ?? "").split("/").filter(Boolean);

  dashboard.search = "";
  dashboard.hash = "";
  if (!dashboard.pathname.endsWith("/")) dashboard.pathname += "/";
  const root = dashboard.toString();

  const [section, ...rest] = segments;
  if (section === "sessions" && rest.length === 1) {
    const sessionId = sessionIdFrom(rest[0]!);
    if (!sessionId) return root;
    // relay-webapp's sessionHref: `<base>?session=<id>&source=<source>`. A
    // Desktop link carries no source; the webapp then opens the session list.
    const params = new URLSearchParams({ session: sessionId });
    const source = target.searchParams.get("source");
    if (source && SOURCE.test(source)) params.set("source", source);
    return `${root}?${params}`;
  }
  if (section === "settings") {
    // The fragment Desktop adds (#workspace, #connections, #billing) never
    // reaches the server. Only Amp's link uses `/dashboard/settings`
    // (#connections); every `/cloud/dashboard/settings` link opens Workspace.
    return `${root}#/settings/${cloudPrefix ? "workspace" : "connections"}`;
  }
  if (section === "downloads" && rest.length === 0) return new URL("downloads", root).toString();
  return root;
}

function sessionIdFrom(segment: string): string | null {
  let value: string;
  try {
    value = decodeURIComponent(segment);
  } catch {
    return null;
  }
  if (!value || value.length > MAX_SESSION_ID || /[\p{C}]/u.test(value)) return null;
  return value;
}
