import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
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
 * Single-use consent tokens for the "approve Agent Relay Desktop on <host>"
 * screen. Per process (the API runs one replica): a token is bound to one
 * person and one sign-in attempt and expires with the screen.
 */
export class ConsentTokens {
  private readonly entries = new Map<string, { attempt: string; expiresAt: number }>();

  constructor(
    private readonly clock: () => number = Date.now,
    private readonly ttlMs = 10 * 60_000,
  ) {}

  private key(attempt: ConsentAttempt): string {
    return JSON.stringify([
      attempt.userId,
      attempt.codeChallenge,
      attempt.hostName,
      attempt.workspaceId,
      attempt.redirectUri,
    ]);
  }

  issue(attempt: ConsentAttempt): string {
    const now = this.clock();
    for (const [token, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(token);
    }
    const token = base64Url(randomBytes(32));
    this.entries.set(token, { attempt: this.key(attempt), expiresAt: now + this.ttlMs });
    return token;
  }

  /** True once, for the matching attempt; the token is consumed either way. */
  consume(token: unknown, attempt: ConsentAttempt): boolean {
    if (typeof token !== "string" || !token) return false;
    const entry = this.entries.get(token);
    this.entries.delete(token);
    if (!entry || entry.expiresAt <= this.clock()) return false;
    const expected = Buffer.from(entry.attempt);
    const actual = Buffer.from(this.key(attempt));
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  }
}

function escape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const PAGE_CSS =
  "body{font:16px system-ui;max-width:34rem;margin:10vh auto;padding:1.5rem;color:#171717}" +
  "button{font:inherit;padding:.6rem 1.2rem;margin-right:.75rem;border-radius:.4rem;border:1px solid #888;background:#fff;cursor:pointer}" +
  "button.primary{background:#171717;color:#fff;border-color:#171717}p.muted{color:#555}";

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
  const where = input.workspaceName
    ? `<p>It will use the workspace <strong>${escape(input.workspaceName)}</strong>.</p>`
    : "";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Approve Agent Relay Desktop</title><style>${PAGE_CSS}</style></head>
<body><main><h1>Sign in Agent Relay Desktop?</h1>
<p>Agent Relay Desktop on <strong>${escape(input.hostName)}</strong> is asking to sign in as you.</p>
${where}
<p class="muted">Only approve a sign-in you started on that computer.</p>
<form method="post" action="${escape(input.action)}">
${hidden}
<input type="hidden" name="consent_token" value="${escape(input.consentToken)}">
<button class="primary" type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form></main></body></html>`;
}

export function desktopConsentDeniedPage(): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Sign-in denied</title><style>${PAGE_CSS}</style></head>
<body><main><h1>Sign-in denied</h1>
<p>Agent Relay Desktop was not signed in. You can close this tab.</p></main></body></html>`;
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
 * Multi-workspace desktop sign-in (Cloud cli/login picker): each choice
 * re-opens the same sign-in with ?workspace=<id>. Choosing issues nothing by
 * itself; the GET that follows runs the usual consent or handoff.
 */
export function desktopWorkspacePickerPage(input: {
  action: string;
  params: URLSearchParams;
  workspaces: ReadonlyArray<{ id: string; name: string; organizationName: string }>;
}): string {
  const items = input.workspaces.map((workspace) => {
    const params = new URLSearchParams(input.params);
    params.set("workspace", workspace.id);
    return `<li><a href="${escape(`${input.action}?${params.toString()}`)}">${escape(workspace.name)}</a> <span class="muted">${escape(workspace.organizationName)}</span></li>`;
  }).join("\n");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Choose a workspace</title><style>${PAGE_CSS}li{margin:.5rem 0}span.muted{color:#555}</style></head>
<body><main><h1>Choose a workspace</h1>
<p>Pick the workspace Agent Relay Desktop should use.</p>
<ul>
${items}
</ul></main></body></html>`;
}
