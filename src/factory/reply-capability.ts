/**
 * Per-delivery reply capability (design §6.4). The bearer is minted in the
 * claim transaction, shown to the Droid once inside the injected text, and
 * stored only as its sha256 hash. It is pinned to one (binding, delivery,
 * sender), expires after 24h, and dies with the binding (retire clears it).
 */
import { createHash } from "node:crypto";
import { hashSecret, opaqueToken } from "../crypto.js";

export const REPLY_BEARER = /^factory_reply_[A-Za-z0-9_-]{43}$/;
export const REPLY_LIFETIME_MS = 24 * 60 * 60 * 1000;
/** Relay message text bound (Cloud delivery.ts). */
export const MAX_RELAY_TEXT_CHARS = 20_000;
/** Request body bound for the public reply route. */
export const MAX_REPLY_BODY_BYTES = 64 * 1024;

export function mintReplyBearer(): { bearer: string; hash: string } {
  const bearer = opaqueToken("factory_reply_");
  return { bearer, hash: hashSecret(bearer) };
}

/** The bearer from `Authorization: Bearer ...`, or null when absent or malformed. */
export function replyBearer(header: string | string[] | undefined): string | null {
  if (typeof header !== "string") return null;
  const match = /^Bearer ([^\s]+)$/.exec(header.trim());
  return match && REPLY_BEARER.test(match[1]!) ? match[1]! : null;
}

/** One Relaycast idempotency key per (binding, Relay message). */
export function replyIdempotencyKey(bindingId: string, messageId: string): string {
  return `factory-${createHash("sha256").update(`${bindingId}:${messageId}`).digest("hex")}`;
}

export function replyBodyHash(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/** Strict `{text}`, 1..20,000 characters. Anything else is null (400). */
export function parseReplyBody(raw: unknown): string | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const keys = Object.keys(raw);
  if (keys.length !== 1 || keys[0] !== "text") return null;
  const text = (raw as { text: unknown }).text;
  if (typeof text !== "string" || text.length < 1 || text.length > MAX_RELAY_TEXT_CHARS) return null;
  return text;
}
