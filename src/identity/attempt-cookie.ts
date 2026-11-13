import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Chunked transport for the encrypted provider sign-in attempt. A long `next`
 * (an MCP authorize URL with a 4096-character state) makes the blob larger
 * than one browser cookie (~4096 bytes), so it is split across `name.0` ...
 * `name.(n-1)` and the base cookie carries a digest-checked manifest.
 */

/** Cookie value characters per chunk; the blob is base64url + dots, so encodeURIComponent keeps it as is. */
export const ATTEMPT_CHUNK_SIZE = 2800;
/** Node's default 16 KiB request-header limit bounds the callback's cookie header; 5 x 2800 plus the manifest stays under it. */
export const ATTEMPT_MAX_CHUNKS = 5;

const MANIFEST_PREFIX = "chunked.";

function setCookie(name: string, value: string, path: string, maxAge: number): string {
  return `${name}=${encodeURIComponent(value)}; Path=${path}; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;
}

function clearCookie(name: string, path: string): string {
  return `${name}=; Path=${path}; Max-Age=0; Secure; HttpOnly; SameSite=Lax`;
}

function digest(blob: string): string {
  return createHash("sha256").update(blob, "utf8").digest("base64url");
}

function chunkName(name: string, index: number): string {
  return `${name}.${index}`;
}

/** Set-Cookie strings for the attempt blob, or null when it needs more than ATTEMPT_MAX_CHUNKS chunks. */
export function attemptSetCookies(blob: string, name: string, path: string, maxAge: number): string[] | null {
  if (blob.length <= ATTEMPT_CHUNK_SIZE) {
    const cookies = [setCookie(name, blob, path, maxAge)];
    for (let index = 0; index < ATTEMPT_MAX_CHUNKS; index += 1) cookies.push(clearCookie(chunkName(name, index), path));
    return cookies;
  }
  const count = Math.ceil(blob.length / ATTEMPT_CHUNK_SIZE);
  if (count > ATTEMPT_MAX_CHUNKS) return null;
  const cookies = [setCookie(name, `${MANIFEST_PREFIX}${count}.${digest(blob)}`, path, maxAge)];
  for (let index = 0; index < count; index += 1) {
    cookies.push(setCookie(chunkName(name, index), blob.slice(index * ATTEMPT_CHUNK_SIZE, (index + 1) * ATTEMPT_CHUNK_SIZE), path, maxAge));
  }
  for (let index = count; index < ATTEMPT_MAX_CHUNKS; index += 1) cookies.push(clearCookie(chunkName(name, index), path));
  return cookies;
}

/** Clear strings for the base cookie and every chunk slot. */
export function attemptClearCookies(name: string, path: string): string[] {
  const cookies = [clearCookie(name, path)];
  for (let index = 0; index < ATTEMPT_MAX_CHUNKS; index += 1) cookies.push(clearCookie(chunkName(name, index), path));
  return cookies;
}

/** The attempt blob from a manifest + chunks (digest-checked), or the legacy single value. */
export function readAttemptCookie(lookup: (name: string) => string | null, name: string): string | null {
  const base = lookup(name);
  if (!base) return null;
  if (!base.startsWith(MANIFEST_PREFIX)) return base;
  const match = /^chunked\.([1-9]\d*)\.([A-Za-z0-9_-]+)$/.exec(base);
  if (!match) return null;
  const count = Number(match[1]);
  if (!Number.isSafeInteger(count) || count < 1 || count > ATTEMPT_MAX_CHUNKS) return null;
  const parts: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const part = lookup(chunkName(name, index));
    if (!part) return null;
    parts.push(part);
  }
  const blob = parts.join("");
  const expected = Buffer.from(match[2]!, "utf8");
  const actual = Buffer.from(digest(blob), "utf8");
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return null;
  return blob;
}
