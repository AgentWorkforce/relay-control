import { createHash } from "node:crypto";
import { COMMON_PASSWORDS_TEXT } from "./common-passwords.js";

/**
 * Password policy (NIST SP 800-63B style): 12 to 128 characters, no
 * composition rules, not a common password, not containing the email's local
 * part, and optionally not in a known breach (HIBP range API).
 */

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;
/** A trailing run of at most this many digits/symbols is stripped before the list lookup. */
const STRIPPED_SUFFIX_MAX = 6;

let commonPasswords: Set<string> | null = null;

export function commonPasswordSet(): Set<string> {
  commonPasswords ??= new Set(COMMON_PASSWORDS_TEXT.split("\n"));
  return commonPasswords;
}

export type PolicyViolation =
  | "password_too_short"
  | "password_too_long"
  | "password_common"
  | "password_contains_email"
  | "password_breached";

export const POLICY_MESSAGES: Record<PolicyViolation, string> = {
  password_too_short: `Use at least ${PASSWORD_MIN_LENGTH} characters.`,
  password_too_long: `Use at most ${PASSWORD_MAX_LENGTH} characters.`,
  password_common: "That password is too common. Choose a less predictable one.",
  password_contains_email: "The password must not contain your email address or its name part.",
  password_breached: "That password has appeared in a known data breach. Choose a different one.",
};

/** Length in characters (code points), after NFC normalization. */
export function passwordLength(password: string): number {
  return [...password.normalize("NFC")].length;
}

export function isCommonPassword(password: string): boolean {
  const lower = password.normalize("NFC").toLowerCase();
  const list = commonPasswordSet();
  if (list.has(lower)) return true;
  const suffix = /[^\p{L}]+$/u.exec(lower);
  if (suffix && [...suffix[0]].length <= STRIPPED_SUFFIX_MAX) {
    const base = lower.slice(0, lower.length - suffix[0].length);
    if (base && list.has(base)) return true;
  }
  return false;
}

/** The local-check violation, or null when the password passes. */
export function checkPasswordPolicy(password: string, email: string): PolicyViolation | null {
  const length = passwordLength(password);
  if (length < PASSWORD_MIN_LENGTH) return "password_too_short";
  if (length > PASSWORD_MAX_LENGTH) return "password_too_long";
  const lower = password.normalize("NFC").toLowerCase();
  const local = email.slice(0, email.lastIndexOf("@")).toLowerCase();
  // Very short local parts ("a@", "jo@") would reject unrelated passwords.
  if (local.length >= 3 && lower.includes(local)) return "password_contains_email";
  if (isCommonPassword(password)) return "password_common";
  return null;
}

export type HibpFetch = (url: string, init: { signal: AbortSignal; headers: Record<string, string> }) =>
  Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

export type HibpResult = "breached" | "clean" | "unavailable";

/**
 * Have I Been Pwned range check (k-anonymity): only the first five hex
 * characters of the SHA-1 leave the server; the suffix is matched locally.
 * Add-Padding asks for decoy rows so the response size reveals nothing.
 */
export async function hibpCheck(
  password: string,
  options: { fetch?: HibpFetch; timeoutMs?: number; baseUrl?: string } = {},
): Promise<HibpResult> {
  const digest = createHash("sha1").update(password.normalize("NFC"), "utf8").digest("hex").toUpperCase();
  const prefix = digest.slice(0, 5);
  const suffix = digest.slice(5);
  const doFetch = options.fetch ?? (fetch as unknown as HibpFetch);
  try {
    const response = await doFetch(`${options.baseUrl ?? "https://api.pwnedpasswords.com"}/range/${prefix}`, {
      signal: AbortSignal.timeout(options.timeoutMs ?? 3_000),
      headers: { "add-padding": "true", "user-agent": "relay-control" },
    });
    if (!response.ok) return "unavailable";
    for (const line of (await response.text()).split(/\r?\n/)) {
      const [candidate, count] = line.trim().split(":");
      if (candidate?.toUpperCase() === suffix && Number(count) > 0) return "breached";
    }
    return "clean";
  } catch {
    return "unavailable";
  }
}
