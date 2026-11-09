import type { IncomingMessage } from "node:http";
import { normalizeUserCode } from "../crypto.js";

/**
 * desktop-auth lane: helpers for the human half of the device flow (RFC 8628
 * §3.3) and the abuse limits hosted Cloud applies to the device routes.
 */

/** Hosted Cloud's limits (cloud packages/web app/api/v1/auth/device/*). */
export const DEVICE_RATE_LIMITS = {
  /** Per client IP; a device start is unauthenticated. */
  start: { limit: 10, windowMs: 5 * 60_000 },
  /** Per client IP; generous next to a 5 s interval. */
  token: { limit: 120, windowMs: 60_000 },
  /** Per approver; bounds guessing of the low-entropy user code. */
  approve: { limit: 30, windowMs: 5 * 60_000 },
} as const;

type Hits = { timestamps: number[]; expiresAt: number };

/** Sliding-window limiter. Per process, like hosted Cloud's. */
export class RateLimiter {
  private readonly entries = new Map<string, Hits>();
  private lastPrunedAt = -Infinity;

  constructor(private readonly clock: () => number = Date.now) {}

  consume(key: string, limit: number, windowMs: number): { allowed: boolean; retryAfterSeconds: number } {
    const now = this.clock();
    if (now - this.lastPrunedAt >= 60_000) {
      for (const [stored, entry] of this.entries) {
        if (entry.expiresAt <= now) this.entries.delete(stored);
      }
      this.lastPrunedAt = now;
    }
    const entry = this.entries.get(key) ?? { timestamps: [], expiresAt: now + windowMs };
    entry.timestamps = entry.timestamps.filter((timestamp) => timestamp > now - windowMs);
    if (entry.timestamps.length >= limit) {
      this.entries.set(key, entry);
      const retryAfterMs = Math.max(0, windowMs - (now - entry.timestamps[0]!));
      return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil(retryAfterMs / 1_000)) };
    }
    entry.timestamps.push(now);
    entry.expiresAt = now + windowMs;
    this.entries.set(key, entry);
    return { allowed: true, retryAfterSeconds: 0 };
  }
}

/**
 * How many reverse proxies in front of the server append to X-Forwarded-For
 * (SELFHOST_TRUSTED_PROXIES, a non-negative integer, default 0). Read per
 * call so tests and operators see one source of truth.
 */
export function trustedProxyHops(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.SELFHOST_TRUSTED_PROXIES?.trim();
  if (!raw) return 0;
  if (!/^\d{1,2}$/.test(raw)) throw new Error("SELFHOST_TRUSTED_PROXIES must be an integer from 0 to 99");
  return Number(raw);
}

/**
 * The client address for rate limits, lockouts and audit. With 0 trusted
 * proxies (the default) it is the socket peer and X-Forwarded-For /
 * X-Real-IP are ignored, since any client can send them. With N trusted
 * proxies it is the Nth address from the right of X-Forwarded-For, the
 * last one a trusted proxy appended; entries further left are client
 * supplied. A shorter header than N falls back to its leftmost entry.
 */
export function clientIp(request: IncomingMessage, hops = trustedProxyHops()): string {
  const socket = request.socket?.remoteAddress || "unknown";
  if (hops <= 0) return socket;
  const header = request.headers["x-forwarded-for"];
  const entries = (Array.isArray(header) ? header.join(",") : header ?? "")
    .split(",").map((entry) => entry.trim()).filter(Boolean);
  if (entries.length === 0) return socket;
  return entries[Math.max(0, entries.length - hops)]!;
}

/**
 * The machine name Agent Relay Desktop sends (`desktop_host_name`). Display
 * data only: control characters become spaces so a caller cannot forge lines
 * on the approval page; empty or over 80 characters is dropped.
 */
export function sanitizeDesktopHostName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const cleaned = value.replace(/[\p{C}]/gu, " ").trim();
  return cleaned && cleaned.length <= 80 ? cleaned : null;
}

/** The dashboard approval route for a code (`<dashboard>#/device?user_code=`). */
export function deviceApprovalPageUrl(dashboardUrl: string, rawUserCode: string | null): string {
  const url = new URL(dashboardUrl);
  url.search = "";
  const userCode = rawUserCode ? normalizeUserCode(rawUserCode) : null;
  const query = userCode ? `?${new URLSearchParams({ user_code: userCode })}` : "";
  url.hash = `/device${query}`;
  return url.toString();
}

/**
 * Where /login may send the browser after sign-in: a same-origin absolute path
 * only (no scheme, no `//host`, no backslash tricks, no control characters).
 */
export function safeNextPath(value: string | null): string {
  if (!value || value.length > 2_048) return "/";
  if (!value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return "/";
  if (/[\p{C}]/u.test(value)) return "/";
  try {
    const base = new URL("https://next.invalid");
    const resolved = new URL(value, base);
    if (resolved.origin !== base.origin) return "/";
    return `${resolved.pathname}${resolved.search}${resolved.hash}`;
  } catch {
    return "/";
  }
}

/**
 * CSRF guard for a cookie-authenticated state change. The session cookie is
 * SameSite=Lax, which already keeps it off cross-site POSTs; this also
 * refuses same-site (sibling subdomain) and form posts: the request must be
 * JSON and come from the dashboard or API origin. Bearer requests are not
 * ambient and skip this.
 */
export function cookieRequestAllowed(
  request: IncomingMessage,
  allowedOrigins: readonly string[],
): boolean {
  const contentType = request.headers["content-type"]?.split(";")[0]?.trim().toLowerCase();
  if (contentType !== "application/json") return false;
  const origin = request.headers.origin;
  if (typeof origin === "string" && origin) {
    return origin !== "null" && allowedOrigins.includes(origin);
  }
  return request.headers["sec-fetch-site"] === "same-origin";
}
