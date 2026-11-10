import { AGENT_RELAY_MARK, AGENT_RELAY_WORDMARK } from "./brand-svg.js";

/** Server-rendered sign-in pages (served at /login on the dashboard origin). */

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// Agent Relay brand tokens, matching the dashboard's sign-in page
// (relay-dashboard src/sign-in/SignInPage.tsx and src/styles.css).
const STYLE = `:root{color-scheme:light dark;--mark:#4a90c2;--bg:#f9fafb;--card:#fff;--fg:#111827;--muted:#4b5563;--border:#d7e0e8;--field:#b6c4d0;--field-bg:#fff;--link:#2f6f9f;--focus:#2f6f9f;--accent:#2d6a9c;--accent-hover:#234969;--accent-border:#234969;--accent-fg:#fff;--secondary-hover:#eef2f6;--danger:#b91c1c;--danger-soft:#fef2f2;--ok-soft:#f0fdf4}
@media (prefers-color-scheme:dark){:root{--mark:#74b8e2;--bg:#101c29;--card:#182838;--fg:#e8f0f7;--muted:#a9bdce;--border:#30485e;--field:#30485e;--field-bg:#101c29;--link:#80bfe5;--focus:#80bfe5;--secondary-hover:#24394b;--danger:#f87171;--danger-soft:#2a1212;--ok-soft:#0f2417}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:28rem;margin:10vh auto;padding:0 24px}.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:28px}
h1{font-size:1.35rem;font-weight:600;letter-spacing:-.01em;margin:0 0 6px}p{margin:0 0 14px}.muted{color:var(--muted);font-size:.9rem}
a{color:var(--link);text-underline-offset:2px;text-decoration:none}a:hover{text-decoration:underline}a:visited{color:var(--link)}
a:focus-visible,.btn:focus-visible,summary:focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:4px}
.btn{display:block;width:100%;text-align:center;min-height:40px;padding:9px 16px;border-radius:6px;border:1px solid var(--accent-border);background:var(--accent);color:var(--accent-fg);font:inherit;font-size:.92rem;font-weight:500;text-decoration:none;cursor:pointer;transition:background-color .15s}
.btn:hover{background:var(--accent-hover);text-decoration:none}.btn:visited{color:var(--accent-fg)}
.btn.secondary{background:transparent;color:var(--fg);border-color:var(--field)}.btn.secondary:hover{background:var(--secondary-hover)}.btn.secondary:visited{color:var(--fg)}
input[type=email],input[type=password]{width:100%;padding:10px 14px;border-radius:6px;border:1px solid var(--field);background:var(--field-bg);color:var(--fg);font:inherit;font-size:.92rem;margin:0 0 10px;outline:none}
input[type=email]:focus,input[type=password]:focus{border-color:var(--focus);box-shadow:0 0 0 3px color-mix(in srgb,var(--focus) 30%,transparent)}@media (forced-colors:active){input[type=email]:focus,input[type=password]:focus{outline:2px solid CanvasText;outline-offset:1px}}
.or{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:.8rem;margin:18px 0}.or:before,.or:after{content:"";flex:1;border-top:1px solid var(--border)}
.notice{border:1px solid var(--border);border-radius:10px;padding:12px 14px;margin:0 0 16px;font-size:.92rem}.notice.error{border-color:var(--danger);background:var(--danger-soft);color:var(--danger)}.notice.ok{background:var(--ok-soft)}
dl{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;margin:0 0 16px;font-size:.92rem}dt{color:var(--muted)}dd{margin:0;word-break:break-all}
.brand{display:flex;flex-direction:column;align-items:flex-start;margin:0 0 24px}.brand .lockup{display:inline-flex;align-items:center;gap:10px}.brand .mark{height:24px;width:auto;color:var(--mark)}.brand .wordmark{height:20px;width:auto;color:var(--fg)}
.brand hr{align-self:flex-start;width:150px;max-width:100%;margin:14px 0;border:0;border-top:1px solid var(--border)}.cobrand{display:flex;align-items:center;gap:10px;min-width:0;max-width:100%}.cobrand img{height:22px;width:auto;max-width:160px;object-fit:contain;object-position:left;flex:none}.cobrand strong{font-size:16px;font-weight:700;letter-spacing:-.01em;min-width:0;overflow-wrap:anywhere}
details{margin-top:18px;font-size:.9rem}summary{cursor:pointer;color:var(--muted)}code{font-size:1.6rem;letter-spacing:.12em}`;

export const PAGE_CSP =
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

export function page(title: string, body: string, script = "", header = ""): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title><style>${STYLE}</style></head>
<body><main>${header}<div class="card">${body}</div></main>${script ? `<script>${script}</script>` : ""}</body></html>`;
}

export type InviteBanner =
  | { kind: "valid"; organizationName: string; inviterName: string | null; role: string; email: string }
  | { kind: "invalid"; message: string };

function roleText(role: string): string {
  return role === "admin" ? "an admin" : role === "owner" ? "an owner" : "a member";
}

/** A customer logo beside the Agent Relay lockup (SELFHOST_LOGIN_LOGO_URL). */
export type CoBrand = { logoUrl: string; orgName: string | null };

/**
 * The lockup above the card: the Agent Relay lockup, a rule and the customer
 * lockup stacked flush left in one column (co-brand option A, stacked). An
 * `<img>` never runs script inside an SVG, and the CSS caps how large the logo
 * can draw.
 */
function brandHeader(coBrand: CoBrand | null): string {
  const customer = coBrand
    ? `<hr><div class="cobrand"><img src="${escapeHtml(coBrand.logoUrl)}" alt="${coBrand.orgName ? "" : "Organization logo"}" referrerpolicy="no-referrer">${coBrand.orgName ? `<strong>${escapeHtml(coBrand.orgName)}</strong>` : ""}</div>`
    : "";
  return `<header class="brand"><span class="lockup">${AGENT_RELAY_MARK}${AGENT_RELAY_WORDMARK}</span>${customer}</header>`;
}

export function loginPage(input: {
  next: string;
  invite: string | null;
  banner: InviteBanner | null;
  oidc: { displayName: string } | null;
  emailLogin: boolean;
  /** SELFHOST_SIGNIN_METHODS includes password: a same-origin form to POST /login/password. */
  password?: boolean;
  coBrand?: CoBrand | null;
  /** Dashboard pages for people without a working password. Only with `password`. */
  passwordLinks?: { forgot: string; register: string } | null;
  userCode: string;
  pollIntervalMs: number;
  notice?: { kind: "error" | "ok"; text: string } | null;
}): string {
  const query = new URLSearchParams({ next: input.next });
  if (input.invite) query.set("invite", input.invite);
  const parts: string[] = [];
  if (input.banner?.kind === "valid") {
    parts.push(`<h1>Join ${escapeHtml(input.banner.organizationName)}</h1>
<p class="muted">${escapeHtml(input.banner.inviterName || "Someone")} invited you to join as ${roleText(input.banner.role)}. Sign in with your invited email to continue.</p>
<dl><dt>Invited email</dt><dd>${escapeHtml(input.banner.email)}</dd><dt>Role</dt><dd>${escapeHtml(input.banner.role)}</dd></dl>`);
  } else {
    parts.push(`<h1>Sign in to Agent Relay</h1>`);
    if (input.banner?.kind === "invalid") {
      parts.push(`<div class="notice error"><strong>Invite unavailable.</strong> ${escapeHtml(input.banner.message)}</div>`);
    }
  }
  if (input.notice) parts.push(`<div class="notice ${input.notice.kind}">${escapeHtml(input.notice.text)}</div>`);
  const methods: string[] = [];
  if (input.oidc) {
    methods.push(`<a class="btn" href="/login/oidc/start?${escapeHtml(query.toString())}">Continue with ${escapeHtml(input.oidc.displayName)}</a>`);
  }
  const invitedEmail = input.banner?.kind === "valid" ? ` value="${escapeHtml(input.banner.email)}"` : "";
  const hidden = `<input type="hidden" name="next" value="${escapeHtml(input.next)}">${input.invite ? `<input type="hidden" name="invite" value="${escapeHtml(input.invite)}">` : ""}`;
  if (input.password) {
    methods.push(`<form method="post" action="/login/password">
${hidden}
<input type="email" name="email" required autocomplete="username" placeholder="you@company.com" aria-label="Email address"${invitedEmail}>
<input type="password" name="password" required autocomplete="current-password" placeholder="Password" aria-label="Password" maxlength="1024">
<button class="btn${input.oidc ? " secondary" : ""}" type="submit">Sign in with password</button></form>${input.passwordLinks ? `
<p class="muted"><a href="${escapeHtml(input.passwordLinks.forgot)}">Forgot password?</a> · <a href="${escapeHtml(input.passwordLinks.register)}">Create an account</a></p>` : ""}`);
  }
  if (input.emailLogin) {
    methods.push(`<form method="post" action="/login/email">
<input type="hidden" name="next" value="${escapeHtml(input.next)}">${input.invite ? `<input type="hidden" name="invite" value="${escapeHtml(input.invite)}">` : ""}
<input type="email" name="email" required autocomplete="email" placeholder="you@company.com" aria-label="Email address"${input.banner?.kind === "valid" ? ` value="${escapeHtml(input.banner.email)}"` : ""}>
<button class="btn${input.oidc || input.password ? " secondary" : ""}" type="submit">Email me a sign-in link</button></form>`);
  }
  parts.push(methods.join(`<div class="or">or</div>`));
  const hasMethod = methods.length > 0;
  if (!hasMethod) {
    parts.push(`<p class="muted">No sign-in method is configured for this installation yet. Ask your administrator to set up single sign-on (OIDC), email links or passwords.</p>`);
  }
  parts.push(`<details${hasMethod ? "" : " open"}><summary>Operator sign-in</summary>
<p class="muted">An administrator or a signed-in Agent Relay client can approve this code:</p>
<p><code>${escapeHtml(input.userCode)}</code></p><p class="muted" id="status">Waiting for approval…</p></details>`);
  const script = `const status=document.getElementById("status");const next=${JSON.stringify(input.next).replaceAll("<", "\\u003c")};
async function poll(){try{const r=await fetch("/login/poll",{method:"POST",credentials:"same-origin",headers:{accept:"application/json"}});
if(r.status===202){const p=await r.json();setTimeout(poll,Math.max(1,Number(p.interval)||5)*1000);return}
if(r.ok){location.replace(next);return}status.textContent="Code expired. Reload to get a new one."}catch{setTimeout(poll,5000)}}
setTimeout(poll,${input.pollIntervalMs});`;
  return page("Sign in to Agent Relay", parts.join("\n"), script, brandHeader(input.coBrand ?? null));
}

export function messagePage(input: { title: string; message: string; kind?: "error" | "ok"; back?: string | null }): string {
  return page(input.title, `<h1>${escapeHtml(input.title)}</h1>
<div class="notice ${input.kind ?? "error"}">${escapeHtml(input.message)}</div>
${input.back === null ? "" : `<a class="btn secondary" href="${escapeHtml(input.back ?? "/login")}">Back to sign in</a>`}`);
}

export function confirmEmailPage(input: { email: string; token: string }): string {
  return page("Sign in to Agent Relay", `<h1>Sign in to Agent Relay</h1>
<p class="muted">Continue as <strong>${escapeHtml(input.email)}</strong>.</p>
<form method="post" action="/login/email/verify"><input type="hidden" name="token" value="${escapeHtml(input.token)}">
<button class="btn" type="submit">Continue</button></form>`);
}

/**
 * The page an emailed password link opens: /login/password/verify (first
 * password) or /login/password/reset (new password, or ask for a link).
 * The link carries its token in the URL fragment, which browsers never send
 * to a server, so it stays out of access logs and Referer headers; the
 * inline script copies it into the form, drops it from the address bar, and
 * the form POSTs it back to this origin. After a rejected password the server
 * renders the token into the form itself (`token`).
 */
export function passwordLinkPage(input: {
  kind: "verify" | "reset";
  token?: string | null;
  notice?: { kind: "error" | "ok"; text: string } | null;
  minLength: number;
}): string {
  const verify = input.kind === "verify";
  const title = verify ? "Set your password" : "Reset your password";
  const action = verify ? "/login/password/verify" : "/login/password/reset";
  const token = input.token ?? "";
  const notice = input.notice ? `<div class="notice ${input.notice.kind}">${escapeHtml(input.notice.text)}</div>` : "";
  const setForm = `<form id="set" method="post" action="${action}"${token ? "" : " hidden"}>
<input type="hidden" name="token" id="token" value="${escapeHtml(token)}">
<input type="password" name="password" required autocomplete="new-password" placeholder="New password" aria-label="New password" minlength="${input.minLength}" maxlength="1024">
<button class="btn" type="submit">${verify ? "Set password and sign in" : "Change password"}</button>
${verify ? "" : `<p class="muted">Changing the password signs you out everywhere.</p>`}</form>`;
  const fallback = verify
    ? `<div id="none"${token ? " hidden" : ""}><p class="muted">Open the link from your confirmation email to set a password.</p><a class="btn secondary" href="/login">Back to sign in</a></div>`
    : `<form id="none" method="post" action="/login/password/reset"${token ? " hidden" : ""}>
<p class="muted">Enter your email and we'll send you a reset link.</p>
<input type="email" name="email" required autocomplete="email" placeholder="you@company.com" aria-label="Email address">
<button class="btn" type="submit">Email me a reset link</button></form>`;
  const script = `const m=/^#token=([^&]*)/.exec(location.hash);
if(m){document.getElementById("token").value=decodeURIComponent(m[1]);document.getElementById("set").hidden=false;document.getElementById("none").hidden=true}
if(location.hash)history.replaceState(null,"",location.pathname);`;
  return page(title, `<h1>${title}</h1>
${notice}
${setForm}
${fallback}`, script);
}
