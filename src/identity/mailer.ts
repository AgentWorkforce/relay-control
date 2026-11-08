import nodemailer from "nodemailer";
import type { SmtpConfig } from "./config.js";

export type OutgoingEmail = { to: string; subject: string; text: string; html: string };

export interface Mailer {
  send(message: OutgoingEmail): Promise<void>;
}

/** SMTP delivery for invites and sign-in links (SELFHOST_SMTP_*). */
export function smtpMailer(config: SmtpConfig): Mailer {
  const transport = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.security === "tls",
    requireTLS: config.security === "starttls",
    ignoreTLS: config.security === "none",
    ...(config.username && config.password ? { auth: { user: config.username, pass: config.password } } : {}),
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
  });
  return {
    async send(message) {
      await transport.sendMail({ from: config.from, ...message });
    },
  };
}

function escape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function layout(heading: string, intro: string, button: string, url: string, footer: string): string {
  return `<!doctype html><html><body style="margin:0;padding:24px;background:#f5f5f4;font:15px/1.5 system-ui,sans-serif;color:#171717">
<table role="presentation" width="100%" style="max-width:520px;margin:0 auto;background:#fff;border:1px solid #e5e5e5;border-radius:12px"><tr><td style="padding:28px">
<h1 style="margin:0 0 12px;font-size:20px">${escape(heading)}</h1>
<p style="margin:0 0 20px">${escape(intro)}</p>
<p style="margin:0 0 20px"><a href="${escape(url)}" style="display:inline-block;padding:10px 18px;border-radius:999px;background:#171717;color:#fff;text-decoration:none">${escape(button)}</a></p>
<p style="margin:0 0 6px;color:#525252;font-size:13px">If the button doesn't work, copy and paste this link into your browser:</p>
<p style="margin:0 0 20px;word-break:break-all;font-size:13px"><a href="${escape(url)}">${escape(url)}</a></p>
<p style="margin:0;color:#737373;font-size:12px">${escape(footer)}</p>
</td></tr></table></body></html>`;
}

/** Hosted Cloud's invite email (lib/invites/invite-email-template.ts), self-host wording. */
export function inviteEmail(input: {
  to: string;
  organizationName: string;
  inviterName: string | null;
  role: string;
  url: string;
  expiresInText: string;
}): OutgoingEmail {
  const who = input.inviterName || "Someone";
  const intro = `${who} invited you to join "${input.organizationName}" on Agent Relay as ${input.role === "admin" ? "an admin" : `a ${input.role}`}.`;
  return {
    to: input.to,
    subject: `You've been invited to join ${input.organizationName} on Agent Relay`,
    text: `${intro}\n\nAccept the invitation: ${input.url}\n\nThis invite expires in ${input.expiresInText}.\n`,
    html: layout(
      "You're invited",
      intro,
      "Accept invitation",
      input.url,
      `This invite expires in ${input.expiresInText}. If you didn't expect this email, you can ignore it.`,
    ),
  };
}

export function signInEmail(input: { to: string; url: string; siteName: string }): OutgoingEmail {
  const intro = `Use this link to sign in to Agent Relay (${input.siteName}). It works once and expires in 15 minutes.`;
  return {
    to: input.to,
    subject: "Your Agent Relay sign-in link",
    text: `${intro}\n\nSign in: ${input.url}\n\nIf you didn't ask to sign in, you can ignore this email.\n`,
    html: layout("Sign in to Agent Relay", intro, "Sign in", input.url, "If you didn't ask to sign in, you can ignore this email."),
  };
}
