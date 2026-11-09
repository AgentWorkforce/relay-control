/** Server-rendered sign-in pages (served at /login on the dashboard origin). */

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const STYLE = `:root{color-scheme:light dark;--bg:#fafaf9;--card:#fff;--fg:#171717;--muted:#57534e;--border:#e7e5e4;--accent:#171717;--accent-fg:#fff;--danger:#b91c1c;--danger-soft:#fef2f2;--ok-soft:#f0fdf4}
@media (prefers-color-scheme:dark){:root{--bg:#0c0a09;--card:#1c1917;--fg:#f5f5f4;--muted:#a8a29e;--border:#292524;--accent:#f5f5f4;--accent-fg:#0c0a09;--danger:#f87171;--danger-soft:#2a1212;--ok-soft:#0f2417}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:26rem;margin:10vh auto;padding:0 16px}.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:28px}
h1{font-size:1.35rem;margin:0 0 6px}p{margin:0 0 14px}.muted{color:var(--muted);font-size:.9rem}
.btn{display:block;width:100%;text-align:center;padding:10px 16px;border-radius:999px;border:1px solid var(--accent);background:var(--accent);color:var(--accent-fg);font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
.btn.secondary{background:transparent;color:var(--fg);border-color:var(--border)}
input[type=email],input[type=password]{width:100%;padding:9px 14px;border-radius:999px;border:1px solid var(--border);background:transparent;color:var(--fg);font:inherit;margin:0 0 10px}
.or{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:.8rem;margin:18px 0}.or:before,.or:after{content:"";flex:1;border-top:1px solid var(--border)}
.notice{border:1px solid var(--border);border-radius:10px;padding:12px 14px;margin:0 0 16px;font-size:.92rem}.notice.error{border-color:var(--danger);background:var(--danger-soft);color:var(--danger)}.notice.ok{background:var(--ok-soft)}
dl{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;margin:0 0 16px;font-size:.92rem}dt{color:var(--muted)}dd{margin:0;word-break:break-all}
details{margin-top:18px;font-size:.9rem}summary{cursor:pointer;color:var(--muted)}code{font-size:1.6rem;letter-spacing:.12em}`;

export const PAGE_CSP =
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

export function page(title: string, body: string, script = ""): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title><style>${STYLE}</style></head>
<body><main><div class="card">${body}</div></main>${script ? `<script>${script}</script>` : ""}</body></html>`;
}

export type InviteBanner =
  | { kind: "valid"; organizationName: string; inviterName: string | null; role: string; email: string }
  | { kind: "invalid"; message: string };

function roleText(role: string): string {
  return role === "admin" ? "an admin" : role === "owner" ? "an owner" : "a member";
}

export function loginPage(input: {
  next: string;
  invite: string | null;
  banner: InviteBanner | null;
  oidc: { displayName: string } | null;
  emailLogin: boolean;
  /** SELFHOST_SIGNIN_METHODS includes password: a same-origin form to POST /login/password. */
  password?: boolean;
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
<button class="btn${input.oidc ? " secondary" : ""}" type="submit">Sign in with password</button></form>`);
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
  return page("Sign in to Agent Relay", parts.join("\n"), script);
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
