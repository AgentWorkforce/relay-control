import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { ATTEMPT_CHUNK_SIZE, ATTEMPT_MAX_CHUNKS, attemptClearCookies, attemptSetCookies, readAttemptCookie } from "../src/identity/attempt-cookie.js";

const NAME = "agent_relay_oidc";
const PATH = "/login/oidc";

function blob(length: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";
  return Array.from({ length }, (_, index) => alphabet[(index * 7) % alphabet.length]).join("");
}

/** name -> value of the cookies a browser keeps (Max-Age=0 deletes). */
function jar(setCookies: string[]): Map<string, string> {
  const kept = new Map<string, string>();
  for (const line of setCookies) {
    const [pair] = line.split(";");
    const index = pair!.indexOf("=");
    const name = pair!.slice(0, index);
    if (/Max-Age=0(;|$)/.test(line)) kept.delete(name);
    else kept.set(name, decodeURIComponent(pair!.slice(index + 1)));
  }
  return kept;
}

function lookup(cookies: Map<string, string>) {
  return (name: string) => cookies.get(name) ?? null;
}

function sha(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

test("attempt cookie: budget constants", () => {
  assert.equal(ATTEMPT_CHUNK_SIZE, 2800);
  assert.equal(ATTEMPT_MAX_CHUNKS, 5);
});

test("attempt cookie: a 2800-character blob is one legacy cookie plus five chunk clears", () => {
  const value = blob(2800);
  const cookies = attemptSetCookies(value, NAME, PATH, 600)!;
  assert.equal(cookies.length, 6);
  assert.equal(cookies[0], `${NAME}=${value}; Path=${PATH}; Max-Age=600; Secure; HttpOnly; SameSite=Lax`);
  for (let index = 0; index < 5; index += 1) {
    assert.equal(cookies[index + 1], `${NAME}.${index}=; Path=${PATH}; Max-Age=0; Secure; HttpOnly; SameSite=Lax`);
  }
  assert.equal(readAttemptCookie(lookup(jar(cookies)), NAME), value);
});

test("attempt cookie: a 2801-character blob is a manifest, two chunks and three clears", () => {
  const value = blob(2801);
  const cookies = attemptSetCookies(value, NAME, PATH, 600)!;
  assert.equal(cookies.length, 6);
  assert.equal(cookies[0], `${NAME}=chunked.2.${sha(value)}; Path=${PATH}; Max-Age=600; Secure; HttpOnly; SameSite=Lax`);
  assert.equal(cookies[1], `${NAME}.0=${value.slice(0, 2800)}; Path=${PATH}; Max-Age=600; Secure; HttpOnly; SameSite=Lax`);
  assert.equal(cookies[2], `${NAME}.1=${value.slice(2800)}; Path=${PATH}; Max-Age=600; Secure; HttpOnly; SameSite=Lax`);
  for (let index = 2; index < 5; index += 1) {
    assert.equal(cookies[index + 1], `${NAME}.${index}=; Path=${PATH}; Max-Age=0; Secure; HttpOnly; SameSite=Lax`);
  }
  assert.equal(readAttemptCookie(lookup(jar(cookies)), NAME), value);
});

test("attempt cookie: 14000 characters fit in five chunks, 14001 are refused", () => {
  const value = blob(14_000);
  const cookies = attemptSetCookies(value, NAME, PATH, 600)!;
  assert.equal(cookies.length, 6);
  assert.match(cookies[0]!, /^agent_relay_oidc=chunked\.5\./);
  for (const line of cookies) assert(line.length <= 4096, `${line.length} bytes`);
  assert.equal(readAttemptCookie(lookup(jar(cookies)), NAME), value);
  assert.equal(attemptSetCookies(blob(14_001), NAME, PATH, 600), null);
});

test("attempt cookie: the clear set covers the base cookie and every chunk slot", () => {
  assert.deepEqual(attemptClearCookies(NAME, PATH), [
    `${NAME}=; Path=${PATH}; Max-Age=0; Secure; HttpOnly; SameSite=Lax`,
    ...[0, 1, 2, 3, 4].map((index) => `${NAME}.${index}=; Path=${PATH}; Max-Age=0; Secure; HttpOnly; SameSite=Lax`),
  ]);
});

test("attempt cookie: tampered, incomplete or malformed manifests are refused", () => {
  const value = blob(9000);
  const cookies = jar(attemptSetCookies(value, NAME, PATH, 600)!);
  assert.equal(readAttemptCookie(lookup(cookies), NAME), value);

  const flipped = new Map(cookies);
  const chunk = flipped.get(`${NAME}.1`)!;
  flipped.set(`${NAME}.1`, `${chunk[0] === "A" ? "B" : "A"}${chunk.slice(1)}`);
  assert.equal(readAttemptCookie(lookup(flipped), NAME), null, "digest mismatch");

  const missing = new Map(cookies);
  missing.delete(`${NAME}.3`);
  assert.equal(readAttemptCookie(lookup(missing), NAME), null, "missing chunk");

  const empty = new Map(cookies);
  empty.set(`${NAME}.0`, "");
  assert.equal(readAttemptCookie(lookup(empty), NAME), null, "empty chunk");

  const digest = sha(value);
  for (const manifest of [`chunked.0.${digest}`, `chunked.6.${digest}`, `chunked.1.5.${digest}`, `chunked.x.${digest}`, `chunked.04.${digest}`, "chunked.4", "chunked."]) {
    const forged = new Map(cookies);
    forged.set(NAME, manifest);
    assert.equal(readAttemptCookie(lookup(forged), NAME), null, manifest);
  }
});

test("attempt cookie: a value without the manifest prefix is the legacy blob", () => {
  assert.equal(readAttemptCookie(lookup(new Map([[NAME, "v1.key.iv.tag.ct"]])), NAME), "v1.key.iv.tag.ct");
  assert.equal(readAttemptCookie(lookup(new Map()), NAME), null);
});
