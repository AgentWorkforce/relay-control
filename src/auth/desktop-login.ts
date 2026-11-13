import { createHash, timingSafeEqual } from "node:crypto";
import { safeNextPath } from "./device-approval.js";

/**
 * desktop-auth lane, browser flow. Agent Relay Desktop's welcome screen
 * (desktop-core browser_login.rs) opens
 * `<site>/cloud/api/v1/cli/login?redirect_uri=http://127.0.0.1:<port>/callback/<state>
 * &state=<state>&client=desktop&workspace_selection=desktop&code_challenge=<S256>
 * &code_challenge_method=S256[&desktop_host_name=<host>][&workspace=<id>]`
 * and waits on the loopback port for `access_token`, `access_token_expires_at`
 * and `api_url`. The handoff's bearer is then redeemed with the verifier at
 * `POST /api/v1/auth/desktop/session`. Shapes follow hosted Cloud
 * (packages/web/app/api/v1/cli/login and auth/desktop/session).
 */

/** Hosted Cloud's S256 challenge and verifier shapes. */
export const DESKTOP_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
export const DESKTOP_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;
/** Hosted Cloud's handoff lifetime; the loopback URL lands in browser history. */
export const DESKTOP_HANDOFF_TTL_MS = 15 * 60 * 1_000;
export const DESKTOP_SESSION_LABEL = "Agent Relay Desktop";
export const DESKTOP_LOGIN_RATE_LIMITS = {
  /** Per client IP, GET and consent POST together (hosted: 30 per minute). */
  login: { limit: 30, windowMs: 60_000 },
  /** Per client IP (hosted: 30 per minute). */
  exchange: { limit: 30, windowMs: 60_000 },
  /** Per user (hosted: 20 per hour). */
  claim: { limit: 20, windowMs: 60 * 60_000 },
} as const;

function base64Url(bytes: Buffer): string {
  return bytes.toString("base64url");
}

export function s256Challenge(verifier: string): string {
  return base64Url(createHash("sha256").update(verifier, "utf8").digest());
}

export function challengeMatches(expected: string, verifier: string): boolean {
  if (!DESKTOP_VERIFIER_PATTERN.test(verifier)) return false;
  const actual = Buffer.from(s256Challenge(verifier));
  const wanted = Buffer.from(expected);
  return actual.length === wanted.length && timingSafeEqual(actual, wanted);
}

/** `redirect_uri` must be the loopback listener of the app on this computer. */
export function isLoopbackRedirectUri(value: string | null | undefined): value is string {
  if (!value || value.length > 2_048) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password) return false;
  return url.hostname === "127.0.0.1" || url.hostname === "localhost";
}

export type DesktopLogin = {
  redirectUri: string;
  state: string;
  /** Present with client=desktop and a valid S256 challenge. */
  codeChallenge: string | null;
  /** The computer asking to be approved as Agent Relay Desktop; display data. */
  desktopHostName: string | null;
  /** Requested workspace id, when the app named one. */
  workspace: string | null;
};

export type DesktopLoginError = { error: string };

/**
 * Every check that needs no session, shared by the GET and the consent POST.
 * Mirrors hosted Cloud's validateLogin: a loopback redirect, and for
 * client=desktop an S256 challenge; desktop_host_name needs both.
 */
export function validateDesktopLogin(params: URLSearchParams): DesktopLogin | DesktopLoginError {
  const redirectUri = params.get("redirect_uri");
  if (!isLoopbackRedirectUri(redirectUri)) {
    return { error: "redirect_uri must point to localhost or 127.0.0.1" };
  }
  const desktopClient = params.get("client") === "desktop";
  const challenge = params.get("code_challenge");
  const method = params.get("code_challenge_method");
  let codeChallenge: string | null = null;
  if (desktopClient && (challenge !== null || method !== null)) {
    if (method !== "S256" || !challenge || !DESKTOP_CHALLENGE_PATTERN.test(challenge)) {
      return {
        error: "code_challenge must be a 43-character base64url S256 challenge with code_challenge_method=S256",
      };
    }
    codeChallenge = challenge;
  }
  const rawHost = params.get("desktop_host_name");
  let desktopHostName: string | null = null;
  if (rawHost !== null) {
    const cleaned = rawHost.replace(/[\p{C}]/gu, " ").trim();
    if (!desktopClient || !codeChallenge || !cleaned || cleaned.length > 80) {
      return {
        error: "desktop_host_name must be 1-80 characters and needs client=desktop with an S256 code_challenge",
      };
    }
    desktopHostName = cleaned;
  }
  const state = params.get("state") ?? "";
  if (state.length > 512) return { error: "state is too long" };
  const workspace = params.get("workspace");
  return {
    redirectUri,
    state,
    codeChallenge,
    desktopHostName,
    workspace: workspace && workspace.trim() ? workspace.trim() : null,
  };
}

/** The fields the consent form posts back; everything else is ignored. */
export const DESKTOP_CONSENT_FIELDS = [
  "redirect_uri",
  "state",
  "client",
  "workspace_selection",
  "code_challenge",
  "code_challenge_method",
  "desktop_host_name",
  "workspace",
] as const;

export type ConsentAttempt = {
  userId: string;
  codeChallenge: string;
  hostName: string;
  workspaceId: string;
  redirectUri: string;
};

/**
 * The sign-in attempt a consent token is bound to: one person, one code
 * challenge, host, workspace and loopback redirect. The token itself is a
 * shared single-use database row (ControlPlaneStore.issueDesktopConsentToken),
 * so any Control replica may receive the approve/deny form post.
 */
export function consentAttemptKey(attempt: ConsentAttempt): string {
  return JSON.stringify([
    attempt.userId,
    attempt.codeChallenge,
    attempt.hostName,
    attempt.workspaceId,
    attempt.redirectUri,
  ]);
}

function escape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// Hosted Cloud's Desktop sign-in pages (packages/web/app/api/v1/cli/login/
// desktop-consent.ts and workspace-picker.ts): same markup and styles.
const CLOUD_STYLE = "body{margin:0;background:#10171d;color:#edf3f7;font:16px system-ui,sans-serif;display:grid;min-height:100vh;place-items:center}main{max-width:460px;padding:40px}h1{font-size:28px;letter-spacing:-.5px}p{color:#b6c6d0;line-height:1.6}strong{color:#edf3f7;overflow-wrap:anywhere}.actions{display:flex;gap:12px;margin-top:28px}button{box-sizing:border-box;flex:1;font:inherit;border-radius:8px;padding:12px;cursor:pointer}button[value=approve]{background:#78bce0;color:#10171d;border:0;font-weight:600}button[value=deny]{background:transparent;color:#edf3f7;border:1px solid #526470}";
const CLOUD_PICKER_STYLE = "body{margin:0;background:#10171d;color:#edf3f7;font:16px system-ui,sans-serif;display:grid;min-height:100vh;place-items:center}main{max-width:420px;padding:40px}h1{font-size:28px;letter-spacing:-.5px}p{color:#b6c6d0;line-height:1.6}label{display:block;margin-top:28px}select,button{box-sizing:border-box;width:100%;font:inherit;border-radius:8px;padding:12px;margin-top:10px}select{background:#1b2832;color:#edf3f7;border:1px solid #526470}button{background:#78bce0;color:#10171d;border:0;font-weight:600;cursor:pointer}small{display:block;color:#b6c6d0;line-height:1.6;margin-top:20px}";

function cloudPage(title: string, body: string, style = CLOUD_STYLE): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${escape(title)} · Agent Relay</title>
<style>${style}</style></head><body><main>${body}</main></body></html>`;
}

/**
 * The consent screen for a desktop sign-in that names its host. Approve posts
 * the same parameters back with the consent token; nothing is issued by
 * rendering this page.
 */
export function desktopConsentPage(input: {
  action: string;
  params: URLSearchParams;
  hostName: string;
  workspaceName: string | null;
  consentToken: string;
}): string {
  const hidden = DESKTOP_CONSENT_FIELDS
    .filter((field) => input.params.has(field))
    .map((field) =>
      `<input type="hidden" name="${field}" value="${escape(input.params.get(field)!)}">`)
    .join("\n");
  const name = `Agent Relay Desktop on ${input.hostName}`;
  const workspace = input.workspaceName ? ` <strong>${escape(input.workspaceName)}</strong>` : "";
  return cloudPage("Authorize a device", `<p>Requesting app or device</p><h1>${escape(name)}</h1>
<p>Approving authorizes ${escape(name)} to access your workspace${workspace}. Check that this is the computer where you started sign-in; otherwise, deny it.</p>
<form method="post" action="${escape(input.action)}">
${hidden}
<input type="hidden" name="consent_token" value="${escape(input.consentToken)}">
<div class="actions">
<button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="deny">Deny</button></div></form>`);
}

export function desktopConsentDeniedPage(): string {
  return cloudPage("Device denied", `<p>Agent Relay</p><h1>Device denied</h1>
<p>No credentials were issued. You can close this tab.</p>`);
}

/** Where the browser is sent with the handoff (hosted Cloud's issueHandoff). */
export function handoffCallbackUrl(
  login: DesktopLogin,
  issued: { accessToken: string; accessTokenExpiresAt: string },
  apiUrl: string,
): string {
  const callback = new URL(login.redirectUri);
  callback.searchParams.set("state", login.state);
  callback.searchParams.set("access_token", issued.accessToken);
  callback.searchParams.set("access_token_expires_at", issued.accessTokenExpiresAt);
  callback.searchParams.set("api_url", apiUrl);
  return callback.toString();
}

/**
 * Hosted Cloud's provider sign-in (`/cloud/api/auth/google/start?next=`)
 * returns to a path under its app origin; the Desktop sends
 * `next=/api/v1/cli/login?...`. Self-host has no provider login, so the same
 * `next` is mapped onto the `/cloud` mount (where the session cookie lives)
 * and handed to `/login`.
 */
export function cloudPathForNext(value: string | null): string {
  const next = safeNextPath(value);
  if (next === "/api/v1" || next.startsWith("/api/v1/") || next.startsWith("/api/v1?")) {
    return `/cloud${next}`;
  }
  return next;
}

/**
 * Multi-workspace desktop sign-in (Cloud's cli/login picker): choosing re-opens
 * the same sign-in with ?workspace=<id>. Choosing issues nothing by itself;
 * the GET that follows runs the usual consent or handoff.
 */
export function desktopWorkspacePickerPage(input: {
  action: string;
  params: URLSearchParams;
  workspaces: ReadonlyArray<{ id: string; name: string; organizationName: string }>;
}): string {
  const hidden = [...input.params]
    .filter(([key]) => key !== "workspace")
    .map(([key, value]) => `<input type="hidden" name="${escape(key)}" value="${escape(value)}">`)
    .join("");
  const options = input.workspaces.map((workspace) => {
    const label = workspace.organizationName && workspace.organizationName !== workspace.name
      ? `${workspace.organizationName} / ${workspace.name}` : workspace.name;
    return `<option value="${escape(workspace.id)}">${escape(label)}</option>`;
  }).join("");
  return cloudPage("Choose your workspace", `<p>Agent Relay</p><h1>Choose your workspace</h1><p>This computer will connect to the workspace you choose.</p>
<form method="get" action="${escape(input.action)}">${hidden}<label for="workspace">Workspace</label>
<select id="workspace" name="workspace" required>${options}</select><button type="submit">Continue to Agent Relay</button></form>
<small>Sign out of the desktop app to switch workspaces.</small>`, CLOUD_PICKER_STYLE);
}
