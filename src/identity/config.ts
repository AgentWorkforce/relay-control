import { readFileSync, statSync } from "node:fs";
import { domainToASCII } from "node:url";
import { loadTenancyConfig, type TenancyConfig } from "../tenancy.js";

/**
 * bootstrap-signup lane: first-boot bootstrap, sign-in methods and invites,
 * all from environment (the chart renders these from values and Secrets).
 */
export type BootstrapConfig = {
  organizationName: string;
  /**
   * SELFHOST_BOOTSTRAP_ADMIN_EMAIL: made owner at first boot, before any
   * sign-in (the original behaviour). Null when only SELFHOST_ADMIN_EMAILS
   * is set.
   */
  adminEmail: string | null;
  /**
   * Every admin email (SELFHOST_BOOTSTRAP_ADMIN_EMAIL first, then
   * SELFHOST_ADMIN_EMAILS), normalized and de-duplicated. On a verified
   * sign-in the first of them to arrive becomes owner when the bootstrap
   * organization has none; the rest become admin, once each.
   */
  adminEmails: string[];
  adminName: string;
  workspaceName: string;
};

export type SigninMethod = "email_link" | "password";
export const SIGNIN_METHODS: readonly SigninMethod[] = ["email_link", "password"];

/** OWASP Password Storage Cheat Sheet argon2id baseline; env may only raise it. */
export const ARGON2_BASELINE = { memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;

export type Argon2Params = { memoryCost: number; timeCost: number; parallelism: number };

export type PasswordPepper = { version: number; secret: Buffer };

export type PasswordConfig = {
  argon2: Argon2Params;
  /** Every pepper in SELFHOST_PASSWORD_PEPPER_FILE, highest version first. */
  peppers: PasswordPepper[];
  /** The version new hashes use (the highest), or null without a pepper file. */
  currentPepperVersion: number | null;
  /** SELFHOST_PASSWORD_HIBP=on: k-anonymity range check (fails open). */
  hibp: boolean;
};

export type OidcConfig = {
  issuer: string;
  clientId: string;
  clientSecret: string;
  scopes: string[];
  /** Lower-case email domains allowed to sign in; empty allows any. */
  allowedDomains: string[];
  /** Button label: "Continue with <displayName>". */
  displayName: string;
  /** Registered with the IdP; empty derives <dashboard origin>/login/oidc/callback. */
  redirectUrl: string | null;
  /** Test-only: allow an http:// issuer (e.g. an in-cluster Dex). */
  allowHttpIssuer: boolean;
};

export type SmtpConfig = {
  host: string;
  port: number;
  /** "tls" = implicit TLS (465), "starttls" = upgrade (587), "none" = plain (tests/relays only). */
  security: "tls" | "starttls" | "none";
  username: string | null;
  password: string | null;
  from: string;
};

export type IdentityConfig = {
  bootstrap: BootstrapConfig | null;
  /** Relaycast's internal admin secret, for provisioning the default workspace. */
  relaycastInternalSecret: string | null;
  oidc: OidcConfig | null;
  smtp: SmtpConfig | null;
  /** Email sign-in links (needs smtp). */
  emailLogin: boolean;
  /** Verified emails in these domains join as member on first sign-in. */
  autoJoinDomains: string[];
  inviteTtlMs: number;
  /** SELFHOST_TENANCY and its multi-mode flags (src/tenancy.ts). */
  tenancy: TenancyConfig;
  /** SELFHOST_SIGNIN_METHODS (OIDC is configured separately). */
  signinMethods: SigninMethod[];
  /** SELFHOST_LOGIN_LOGO_URL, an https URL shown on the sign-in page. */
  logoUrl: string | null;
  /** Password sign-in settings, or null when "password" is not enabled. */
  password: PasswordConfig | null;
};

type Env = Record<string, string | undefined>;

function readSecret(env: Env, name: string): string | undefined {
  const direct = env[name]?.trim();
  const file = env[`${name}_FILE`]?.trim();
  if (direct && file) throw new Error(`${name} and ${name}_FILE are mutually exclusive`);
  if (direct) return direct;
  if (!file) return undefined;
  const value = readFileSync(file, "utf8").trim();
  return value || undefined;
}

function flag(env: Env, name: string): boolean {
  const value = env[name]?.trim().toLowerCase();
  if (!value) return false;
  if (value === "true" || value === "1" || value === "yes") return true;
  if (value === "false" || value === "0" || value === "no") return false;
  throw new Error(`${name} must be true or false`);
}

export function normalizeEmailAddress(value: string): string | null {
  const email = value.trim().toLowerCase();
  if (email.length > 320 || !/^[^@\s<>()",;:]+@[^@\s<>()",;:]+\.[^@\s<>()",;:]+$/.test(email)) return null;
  return email;
}

const DOMAIN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;

function domains(env: Env, name: string): string[] {
  const raw = env[name]?.trim();
  if (!raw) return [];
  const list = raw.split(/[\s,]+/).filter(Boolean).map((item) => {
    const ascii = asciiDomain(item);
    if (!ascii) throw new Error(`${name} must list email domains (e.g. example.com), got ${JSON.stringify(item)}`);
    return ascii;
  });
  return [...new Set(list)];
}

/**
 * Lowercase IDNA-ascii form of an email domain (a leading "@" is dropped), or
 * null when it is not a valid domain. Auto-join matching compares only this
 * form on both sides.
 */
export function asciiDomain(value: string): string | null {
  const trimmed = value.trim().replace(/^@/, "").replace(/\.$/, "");
  if (!trimmed) return null;
  const ascii = domainToASCII(trimmed).toLowerCase();
  return ascii && DOMAIN.test(ascii) ? ascii : null;
}

export function emailDomain(email: string): string {
  return email.slice(email.lastIndexOf("@") + 1);
}

function cleanLabel(value: string): string {
  return value.replace(/[\p{C}]/gu, " ").trim().slice(0, 120);
}

function adminEmailList(env: Env): string[] {
  const raw = env.SELFHOST_ADMIN_EMAILS?.trim();
  if (!raw) return [];
  return [...new Set(raw.split(/[\s,]+/).filter(Boolean).map((item) => {
    const email = normalizeEmailAddress(item);
    if (!email) throw new Error(`SELFHOST_ADMIN_EMAILS must list email addresses, got ${JSON.stringify(item)}`);
    return email;
  }))];
}

function loadBootstrap(env: Env): BootstrapConfig | null {
  const organizationName = cleanLabel(env.SELFHOST_BOOTSTRAP_ORG_NAME ?? "");
  const rawEmail = env.SELFHOST_BOOTSTRAP_ADMIN_EMAIL?.trim() ?? "";
  const listed = adminEmailList(env);
  if (!organizationName && !rawEmail && listed.length === 0) return null;
  if (!organizationName || (!rawEmail && listed.length === 0)) {
    throw new Error(
      "SELFHOST_BOOTSTRAP_ORG_NAME must be set together with SELFHOST_BOOTSTRAP_ADMIN_EMAIL or SELFHOST_ADMIN_EMAILS",
    );
  }
  const adminEmail = rawEmail ? normalizeEmailAddress(rawEmail) : null;
  if (rawEmail && !adminEmail) throw new Error("SELFHOST_BOOTSTRAP_ADMIN_EMAIL must be an email address");
  const adminEmails = [...new Set([...(adminEmail ? [adminEmail] : []), ...listed])];
  const first = adminEmails[0]!;
  const adminName = cleanLabel(env.SELFHOST_BOOTSTRAP_ADMIN_NAME ?? "") || first.slice(0, first.indexOf("@"));
  const workspaceName = cleanLabel(env.SELFHOST_BOOTSTRAP_WORKSPACE_NAME ?? "") || "Default";
  return { organizationName, adminEmail, adminEmails, adminName, workspaceName };
}

function loadSigninMethods(env: Env, emailLoginFlag: boolean): SigninMethod[] {
  const raw = env.SELFHOST_SIGNIN_METHODS?.trim();
  if (!raw) return emailLoginFlag ? ["email_link"] : [];
  const methods = [...new Set(raw.split(/[\s,]+/).filter(Boolean).map((item) => item.toLowerCase()))];
  for (const method of methods) {
    if (!(SIGNIN_METHODS as readonly string[]).includes(method)) {
      throw new Error(`SELFHOST_SIGNIN_METHODS must list ${SIGNIN_METHODS.join(" and/or ")}, got ${JSON.stringify(method)}`);
    }
  }
  if (emailLoginFlag && !methods.includes("email_link")) {
    throw new Error("SELFHOST_EMAIL_LOGIN=true conflicts with SELFHOST_SIGNIN_METHODS without email_link");
  }
  return methods as SigninMethod[];
}

function loadLogoUrl(env: Env): string | null {
  const raw = env.SELFHOST_LOGIN_LOGO_URL?.trim();
  if (!raw) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("SELFHOST_LOGIN_LOGO_URL must be an absolute https URL");
  }
  if (url.protocol !== "https:") throw new Error("SELFHOST_LOGIN_LOGO_URL must use https");
  if (url.username || url.password) throw new Error("SELFHOST_LOGIN_LOGO_URL must not contain credentials");
  if (raw.length > 2_048 || /[\p{C}\s"'<>\\]/u.test(raw)) {
    throw new Error("SELFHOST_LOGIN_LOGO_URL must be at most 2048 characters without spaces, quotes or angle brackets");
  }
  return url.toString();
}

function raisedInteger(env: Env, name: string, baseline: number, max: number): number {
  const raw = env[name]?.trim();
  if (!raw) return baseline;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < baseline || value > max) {
    throw new Error(`${name} must be an integer from ${baseline} (the OWASP baseline; it can only be raised) to ${max}`);
  }
  return value;
}

/**
 * SELFHOST_PASSWORD_PEPPER_FILE: one pepper per line as `<version>:<secret>`
 * (a single line without a version is version 1). The highest version hashes
 * new passwords; older lines stay so existing hashes still verify and are
 * re-hashed on the next sign-in. Blank lines and `#` comments are ignored.
 */
export function parsePepperFile(text: string): PasswordPepper[] {
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
  if (lines.length === 0) throw new Error("SELFHOST_PASSWORD_PEPPER_FILE is empty");
  const peppers = new Map<number, Buffer>();
  for (const line of lines) {
    // Every line names its version, so a secret that happens to start with
    // digits and a colon is never misread as a versioned one.
    const match = /^v(\d{1,6}):(.+)$/.exec(line);
    if (!match) throw new Error("SELFHOST_PASSWORD_PEPPER_FILE lines must be v<version>:<secret>");
    const version = Number(match[1]);
    const secret = Buffer.from(match[2]!.trim(), "utf8");
    if (version < 1) throw new Error("SELFHOST_PASSWORD_PEPPER_FILE versions start at 1");
    if (secret.length < 32) throw new Error("SELFHOST_PASSWORD_PEPPER_FILE secrets must be at least 32 bytes");
    if (peppers.has(version)) throw new Error(`SELFHOST_PASSWORD_PEPPER_FILE repeats version ${version}`);
    peppers.set(version, secret);
  }
  return [...peppers].sort((a, b) => b[0] - a[0]).map(([version, secret]) => ({ version, secret }));
}

/**
 * Reads the pepper file only if no other user can: owned by this process's
 * uid and no group or world permission bits (mode & 0o077 === 0).
 */
export function readPepperFile(path: string): string {
  const stats = statSync(path);
  if (!stats.isFile()) throw new Error("SELFHOST_PASSWORD_PEPPER_FILE must be a regular file");
  if ((stats.mode & 0o077) !== 0) {
    throw new Error(`SELFHOST_PASSWORD_PEPPER_FILE must not be readable by group or others (mode ${(stats.mode & 0o777).toString(8)}; use chmod 600)`);
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (uid !== null && stats.uid !== uid) {
    throw new Error("SELFHOST_PASSWORD_PEPPER_FILE must be owned by the user the server runs as");
  }
  return readFileSync(path, "utf8");
}

function loadPassword(env: Env): PasswordConfig {
  const argon2 = {
    memoryCost: raisedInteger(env, "SELFHOST_PASSWORD_ARGON2_MEMORY_KIB", ARGON2_BASELINE.memoryCost, 1_048_576),
    timeCost: raisedInteger(env, "SELFHOST_PASSWORD_ARGON2_TIME_COST", ARGON2_BASELINE.timeCost, 10),
    parallelism: raisedInteger(env, "SELFHOST_PASSWORD_ARGON2_PARALLELISM", ARGON2_BASELINE.parallelism, 16),
  };
  const pepperFile = env.SELFHOST_PASSWORD_PEPPER_FILE?.trim();
  const peppers = pepperFile ? parsePepperFile(readPepperFile(pepperFile)) : [];
  const hibpRaw = env.SELFHOST_PASSWORD_HIBP?.trim().toLowerCase() || "off";
  if (hibpRaw !== "on" && hibpRaw !== "off") throw new Error("SELFHOST_PASSWORD_HIBP must be on or off");
  return { argon2, peppers, currentPepperVersion: peppers[0]?.version ?? null, hibp: hibpRaw === "on" };
}

function loadOidc(env: Env): OidcConfig | null {
  const issuer = env.SELFHOST_OIDC_ISSUER?.trim();
  const clientId = env.SELFHOST_OIDC_CLIENT_ID?.trim();
  if (!issuer && !clientId) return null;
  if (!issuer || !clientId) throw new Error("SELFHOST_OIDC_ISSUER and SELFHOST_OIDC_CLIENT_ID must be set together");
  const clientSecret = readSecret(env, "SELFHOST_OIDC_CLIENT_SECRET");
  if (!clientSecret) throw new Error("SELFHOST_OIDC_CLIENT_SECRET (or _FILE) is required with SELFHOST_OIDC_ISSUER");
  const allowHttpIssuer = flag(env, "SELFHOST_OIDC_ALLOW_HTTP_ISSUER");
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    throw new Error("SELFHOST_OIDC_ISSUER must be an absolute URL");
  }
  if (issuerUrl.protocol !== "https:" && !(allowHttpIssuer && issuerUrl.protocol === "http:")) {
    throw new Error("SELFHOST_OIDC_ISSUER must use https");
  }
  if (issuerUrl.username || issuerUrl.password || issuerUrl.search || issuerUrl.hash) {
    throw new Error("SELFHOST_OIDC_ISSUER must not contain credentials, a query or a fragment");
  }
  const redirect = env.SELFHOST_OIDC_REDIRECT_URL?.trim() || null;
  if (redirect) {
    let url: URL;
    try {
      url = new URL(redirect);
    } catch {
      throw new Error("SELFHOST_OIDC_REDIRECT_URL must be an absolute URL");
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("SELFHOST_OIDC_REDIRECT_URL must use http or https");
    if (url.pathname !== "/login/oidc/callback" || url.search || url.hash || url.username || url.password) {
      throw new Error("SELFHOST_OIDC_REDIRECT_URL must be <origin>/login/oidc/callback");
    }
  }
  const scopes = (env.SELFHOST_OIDC_SCOPES?.trim() || "openid email profile").split(/[\s,]+/).filter(Boolean);
  if (!scopes.includes("openid")) scopes.unshift("openid");
  if (!scopes.includes("email")) scopes.push("email");
  return {
    // Kept byte-for-byte: the id_token `iss` must equal the discovery issuer.
    issuer: issuer.replace(/\/+$/, ""),
    clientId,
    clientSecret,
    scopes,
    allowedDomains: domains(env, "SELFHOST_OIDC_ALLOWED_DOMAINS"),
    displayName: cleanLabel(env.SELFHOST_OIDC_DISPLAY_NAME ?? "") || "single sign-on",
    redirectUrl: redirect,
    allowHttpIssuer,
  };
}

function loadSmtp(env: Env): SmtpConfig | null {
  const host = env.SELFHOST_SMTP_HOST?.trim();
  if (!host) return null;
  const port = Number(env.SELFHOST_SMTP_PORT?.trim() || "587");
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("SELFHOST_SMTP_PORT must be 1-65535");
  const security = (env.SELFHOST_SMTP_SECURITY?.trim().toLowerCase() || (port === 465 ? "tls" : "starttls"));
  if (security !== "tls" && security !== "starttls" && security !== "none") {
    throw new Error("SELFHOST_SMTP_SECURITY must be tls, starttls or none");
  }
  const username = env.SELFHOST_SMTP_USERNAME?.trim() || null;
  const password = readSecret(env, "SELFHOST_SMTP_PASSWORD") ?? null;
  if (Boolean(username) !== Boolean(password)) {
    throw new Error("SELFHOST_SMTP_USERNAME and SELFHOST_SMTP_PASSWORD (or _FILE) must be set together");
  }
  const from = env.SELFHOST_EMAIL_FROM?.trim();
  if (!from || /[\r\n]/.test(from) || !/@/.test(from)) {
    throw new Error("SELFHOST_EMAIL_FROM is required with SELFHOST_SMTP_HOST (e.g. Agent Relay <relay@example.com>)");
  }
  return { host, port, security, username, password, from };
}

export function loadIdentityConfig(env: Env = process.env): IdentityConfig {
  const smtp = loadSmtp(env);
  const emailLoginFlag = flag(env, "SELFHOST_EMAIL_LOGIN");
  if (emailLoginFlag && !smtp) throw new Error("SELFHOST_EMAIL_LOGIN=true requires SELFHOST_SMTP_HOST");
  const signinMethods = loadSigninMethods(env, emailLoginFlag);
  if (signinMethods.length > 0 && !smtp) {
    throw new Error("SELFHOST_SIGNIN_METHODS (email_link and password both send email) requires SELFHOST_SMTP_HOST");
  }
  const emailLogin = signinMethods.includes("email_link");
  const ttlHours = Number(env.SELFHOST_INVITE_TTL_HOURS?.trim() || "168");
  if (!Number.isInteger(ttlHours) || ttlHours < 1 || ttlHours > 720) {
    throw new Error("SELFHOST_INVITE_TTL_HOURS must be an integer from 1 to 720");
  }
  const relaycastInternalSecret = readSecret(env, "RELAYCAST_INTERNAL_SECRET") ?? null;
  if (relaycastInternalSecret !== null && Buffer.byteLength(relaycastInternalSecret) < 32) {
    throw new Error("RELAYCAST_INTERNAL_SECRET must be at least 32 bytes");
  }
  const tenancy = loadTenancyConfig(env);
  const bootstrap = loadBootstrap(env);
  const autoJoinDomains = domains(env, "SELFHOST_AUTO_JOIN_DOMAINS");
  if (tenancy.mode === "multi") {
    if (autoJoinDomains.length > 0) {
      throw new Error(
        "SELFHOST_AUTO_JOIN_DOMAINS is not supported with SELFHOST_TENANCY=multi; " +
        "the operator assigns domains per organization with PUT /api/v1/organizations/{id}/domains/{domain}",
      );
    }
    if (!bootstrap) {
      throw new Error(
        "SELFHOST_TENANCY=multi requires SELFHOST_BOOTSTRAP_ORG_NAME and SELFHOST_BOOTSTRAP_ADMIN_EMAIL (the operator organization)",
      );
    }
  }
  return {
    bootstrap,
    relaycastInternalSecret,
    oidc: loadOidc(env),
    smtp,
    emailLogin,
    autoJoinDomains,
    inviteTtlMs: ttlHours * 60 * 60 * 1_000,
    tenancy,
    signinMethods,
    logoUrl: loadLogoUrl(env),
    password: signinMethods.includes("password") ? loadPassword(env) : null,
  };
}
