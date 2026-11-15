import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FileDesktopFeedSigner, SignerUnavailableError, verifyEd25519 } from "../src/desktop-feed/signer.js";
import { loadDesktopFeedConfig } from "../src/config.js";

function secret(t: test.TestContext, type: "ed25519" | "rsa" = "ed25519") {
  const dir = mkdtempSync(join(tmpdir(), "feed-signer-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, "key.pem");
  const pair = type === "rsa" ? generateKeyPairSync("rsa", { modulusLength: 2048 }) : generateKeyPairSync("ed25519");
  writeFileSync(path, pair.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  return { path, dir };
}

test("persistent feed signer signs full multi-platform manifests across restarts with an enforced 64KiB bound", async t => {
  const { path, dir } = secret(t);
  const projected = join(dir, "projected-secret"); symlinkSync(path, projected);
  const options = { label: "k1", keyFiles: { profile1: projected } };
  const first = new FileDesktopFeedSigner(options), restarted = new FileDesktopFeedSigner(options);
  chmodSync(path, 0o440);
  assert.equal(await new FileDesktopFeedSigner(options).publicKey("profile1"), await first.publicKey("profile1"));
  const bytes = Buffer.alloc(5000, 32); // More than the 4096-byte KMS limit.
  const signed = await first.sign("profile1", bytes);
  assert.equal(signed.keyId, "fk_profile1_k1");
  assert.equal(await first.publicKey("profile1"), await restarted.publicKey("profile1"));
  assert.equal(verifyEd25519(await restarted.publicKey("profile1"), bytes, signed.signature), true);
  assert.equal(restarted.maxCanonicalBytes(), 65536);
  assert.equal(restarted.hasProfile("other"), false);
  await restarted.sign("profile1", Buffer.alloc(65536));
  await assert.rejects(restarted.sign("profile1", Buffer.alloc(65537)), SignerUnavailableError);
  await assert.rejects(restarted.sign("other", bytes), SignerUnavailableError);
});

test("persistent feed signer refuses readable, malformed and wrong-type secrets without echoing content or paths", t => {
  const { path } = secret(t);
  const create = () => new FileDesktopFeedSigner({ label: "k1", keyFiles: { profile1: path } });
  chmodSync(path, 0o644);
  assert.throws(create, /Cannot load a private Ed25519/);
  chmodSync(path, 0o600); writeFileSync(path, "PRIVATE_SENTINEL_CONTENT");
  try { create(); assert.fail("malformed key accepted"); } catch (error) {
    assert.equal(String(error).includes("PRIVATE_SENTINEL_CONTENT"), false);
    assert.equal(String(error).includes(path), false);
  }
  const wrong = secret(t, "rsa");
  assert.throws(() => new FileDesktopFeedSigner({ label: "k1", keyFiles: { profile1: wrong.path } }), /Cannot load a private Ed25519/);
});

test("file signer config validates a profile-to-absolute-file map without accepting key contents", () => {
  const base = { SELFHOST_DESKTOP_FEED_SIGNER: "file", SELFHOST_DESKTOP_FEED_STORAGE: "memory" };
  assert.deepEqual(loadDesktopFeedConfig({ ...base, SELFHOST_DESKTOP_FEED_KEY_FILES: '{"profile1":"/run/secrets/feed.pem"}' })?.signer,
    { kind: "file", label: "f1", keyFiles: { profile1: "/run/secrets/feed.pem" } });
  for (const map of ['{}', '{"profile1":"relative.pem"}', '{"profile1":true}', '{"bad/profile":"/secret"}']) {
    assert.throws(() => loadDesktopFeedConfig({ ...base, SELFHOST_DESKTOP_FEED_KEY_FILES: map }), /SELFHOST_DESKTOP_FEED_KEY_FILES/);
  }
});
