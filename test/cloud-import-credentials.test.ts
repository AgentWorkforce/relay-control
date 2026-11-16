import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { CodingAgentStore } from "../src/admin/coding-agents.js";
import { CredentialBlobStore, PostgresObjectBackend } from "../src/admin/credential-blobs.js";
import { SubscriptionLoginStore } from "../src/admin/subscription-logins.js";
import { decryptSecret, type EncryptionKeyring } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import { CLOUD_FIXTURE_DDL, cloudEnvelope, cloudFixtureSeed, id } from "../scripts/cloud-import/cloud-fixture.js";
import { cloudObjectKeys, copyCodingAgentCredentials } from "../scripts/cloud-import/credentials.js";
import { runImport } from "../scripts/cloud-import/importer.js";
import { PGliteDatabase } from "./support/harness.js";

const CLOUD_KEY = randomBytes(32).toString("hex");
const KEYRING: EncryptionKeyring = { active: { id: "copy-test", key: randomBytes(32) } };
const jwt = (payload: Record<string, unknown>) =>
  `e30.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.sig`;

test("cloud object keys follow Cloud's runtime read order", () => {
  const base = { id: id(9), cloud_user_id: id(1), model_provider: "codex", provider_account_id: null };
  assert.deepEqual(cloudObjectKeys({ ...base, auth_type: "byo_api_key" }), [`${id(1)}/${id(9)}/credentials.json.enc`]);
  assert.deepEqual(cloudObjectKeys({ ...base, auth_type: "provider_oauth" }), [`${id(1)}/openai/credentials.json.enc`]);
  assert.deepEqual(cloudObjectKeys({ ...base, auth_type: "provider_oauth", provider_account_id: "a" }), [
    `${id(1)}/accounts/${id(9)}/credentials.json.enc`,
    `${id(1)}/openai/credentials.json.enc`,
  ]);
  assert.deepEqual(cloudObjectKeys({ ...base, model_provider: "anthropic", auth_type: "oauth_token" }), [
    `${id(1)}/accounts/${id(9)}/credentials.json.enc`,
    `${id(1)}/anthropic/credentials.json.enc`,
  ]);
});

test("credential copier: store seams, fallbacks, missing objects and re-run", async (t) => {
  const source = new PGliteDatabase();
  const target = new PGliteDatabase();
  t.after(async () => {
    await source.close();
    await target.close();
  });
  await source.exec(CLOUD_FIXTURE_DDL);
  await source.exec(cloudFixtureSeed(CLOUD_KEY));
  await migrate(target);
  const identity = await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply");
  assert.equal(identity.ok, true);

  const codexAuth = JSON.stringify({
    auth_mode: "chatgpt",
    tokens: {
      access_token: jwt({ exp: Math.floor(Date.now() / 1000) + 3600 }),
      id_token: jwt({ email: "alice@example.test" }),
      refresh_token: "rt-synthetic",
      account_id: "acct-synthetic-1",
    },
  });
  const objects = new Map<string, string>([
    [`${id(1)}/${id(0x803)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(JSON.stringify({ type: "api_key", modelProvider: "openai", key: "sk-synthetic-openai-key-0000000000" }), CLOUD_KEY))],
    // oauth_token: no account object, so the legacy provider key is used.
    [`${id(2)}/anthropic/credentials.json.enc`, JSON.stringify(cloudEnvelope(JSON.stringify({ type: "oauth_token", modelProvider: "anthropic", token: "sk-ant-oat01-synthetic-token-00000000000" }), CLOUD_KEY))],
    [`${id(1)}/accounts/${id(0x806)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(codexAuth, CLOUD_KEY))],
  ]);
  const reads: string[] = [];
  const reader = { get: async (key: string) => { reads.push(key); return objects.get(key) ?? null; } };
  const blobs = new CredentialBlobStore(new PostgresObjectBackend(target), KEYRING);
  const deps = {
    source,
    reader,
    cloudKeyHex: CLOUD_KEY,
    keyring: KEYRING,
    codingAgents: new CodingAgentStore(target, KEYRING, undefined, blobs),
    logins: new SubscriptionLoginStore(target, KEYRING, blobs),
  };

  const plan = await copyCodingAgentCredentials(deps, { orgIds: null }, "plan");
  assert.equal(reads.length, 0, "plan never reads the object store");
  assert.equal(plan.candidates, 5);

  const report = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.deepEqual(report.rows, {
    [id(0x803)]: "copied",
    [id(0x805)]: "copied",
    [id(0x806)]: "copied",
    [id(0x807)]: "skipped:anthropic_login_without_account_email",
    [id(0x808)]: "object_missing",
  });
  assert.equal(report.ok, false, "a missing object is not a clean copy");
  assert.doesNotMatch(JSON.stringify(report), /sk-|rt-synthetic|example\.test/);

  const rows = (await target.query<{ auth_type: string; model_provider: string; secret_ciphertext: string | null; blob_location: string | null; workspace_id: string }>(
    "SELECT auth_type, model_provider, secret_ciphertext, blob_location, workspace_id FROM coding_agent_credentials ORDER BY auth_type")).rows;
  assert.deepEqual(rows.map((row) => [row.auth_type, row.model_provider, row.workspace_id]), [
    ["byo_api_key", "openai", id(0x201)],
    ["oauth_token", "anthropic", id(0x205)],
    ["provider_oauth", "openai", id(0x201)],
  ]);
  assert.equal(decryptSecret(rows[0]!.secret_ciphertext!, KEYRING), "sk-synthetic-openai-key-0000000000");
  assert.equal(decryptSecret(rows[1]!.secret_ciphertext!, KEYRING), "sk-ant-oat01-synthetic-token-00000000000");
  assert.ok(rows[2]!.blob_location);
  assert.equal(await deps.logins.freshAuthFile(id(0x201), (await target.query<{ id: string }>(
    "SELECT id FROM coding_agent_credentials WHERE auth_type = 'provider_oauth'")).rows[0]!.id), codexAuth);

  // Re-run converges on Control's own dedupe keys.
  const again = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.equal(again.rows[id(0x803)], "already_present");
  assert.equal(again.rows[id(0x805)], "already_present");
  const count = (await target.query<{ n: number }>("SELECT count(*)::int AS n FROM coding_agent_credentials")).rows[0]!.n;
  assert.equal(count, 3);
});
