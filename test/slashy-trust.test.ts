import assert from "node:assert/strict";
import { test } from "node:test";
import { issueSlashyTrustToken, SLASHY_TRUST_TOKEN_TTL_SECONDS, slashyTrustKey, verifySlashyTrustToken } from "../src/mcp/slashy-trust.js";

const key = slashyTrustKey(Buffer.alloc(32, 7));
const binding = { grantId: "grant-1", workspaceId: "ws-1", userId: "user-1" };
const NOW = Date.UTC(2026, 10, 27, 12, 0, 0);

test("a Slashy trust token round-trips its agent ids for the connection it was issued to", () => {
  const { token, expiresAt } = issueSlashyTrustToken(key, binding, ["42", "7", "42"], NOW);
  assert.match(token, /^srt1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
  assert.equal(expiresAt, new Date(NOW + SLASHY_TRUST_TOKEN_TTL_SECONDS * 1000).toISOString());
  const verdict = verifySlashyTrustToken(key, token, binding, NOW + 1000);
  assert.equal(verdict.status, "ok");
  assert.deepEqual(verdict.status === "ok" ? [...verdict.agentIds].sort() : [], ["42", "7"]);
});

test("an edited payload, a swapped signature or another key is invalid", () => {
  const { token } = issueSlashyTrustToken(key, binding, ["42"], NOW);
  const [prefix, payload, signature] = token.split(".");
  const forged = JSON.parse(Buffer.from(payload!, "base64url").toString("utf8"));
  forged.a = ["42", "666"];
  assert.deepEqual(verifySlashyTrustToken(key, `${prefix}.${Buffer.from(JSON.stringify(forged)).toString("base64url")}.${signature}`, binding, NOW), { status: "invalid" });
  const other = issueSlashyTrustToken(key, binding, ["666"], NOW).token.split(".")[2];
  assert.deepEqual(verifySlashyTrustToken(key, `${prefix}.${payload}.${other}`, binding, NOW), { status: "invalid" });
  const foreign = issueSlashyTrustToken(slashyTrustKey(Buffer.alloc(32, 9)), binding, ["42"], NOW).token;
  assert.deepEqual(verifySlashyTrustToken(key, foreign, binding, NOW), { status: "invalid" });
});

test("a token for another connection, an expired token and junk widen nothing", () => {
  const { token } = issueSlashyTrustToken(key, binding, ["42"], NOW);
  assert.deepEqual(verifySlashyTrustToken(key, token, { ...binding, grantId: "grant-2" }, NOW), { status: "other_connection" });
  assert.deepEqual(verifySlashyTrustToken(key, token, { ...binding, userId: "user-2" }, NOW), { status: "other_connection" });
  assert.deepEqual(verifySlashyTrustToken(key, token, binding, NOW + SLASHY_TRUST_TOKEN_TTL_SECONDS * 1000), { status: "expired" });
  for (const junk of [undefined, 42, "", "srt1..", "srt2.abc.def", `${token}x`]) {
    assert.deepEqual(verifySlashyTrustToken(key, junk, binding, NOW), { status: "invalid" });
  }
});
