import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { CodingAgentStore } from "../src/admin/coding-agents.js";
import { CredentialBlobStore, PostgresObjectBackend } from "../src/admin/credential-blobs.js";
import { SubscriptionLoginStore } from "../src/admin/subscription-logins.js";
import { decryptSecret, type EncryptionKeyring } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import { CLOUD_FIXTURE_DDL, cloudEnvelope, cloudFixtureSeed, id, ORG_A } from "../scripts/cloud-import/cloud-fixture.js";
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
  // provider_oauth: the account object iff provider_account_id, else the
  // legacy object, never both (Cloud provider-credential-runtime.ts).
  assert.deepEqual(cloudObjectKeys({ ...base, auth_type: "provider_oauth", provider_account_id: "a" }), [
    `${id(1)}/accounts/${id(9)}/credentials.json.enc`,
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
  await migrate(target); // includes 0063 cloud_import_ledger
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
  const legacyCodexAuth = JSON.stringify({
    auth_mode: "chatgpt",
    tokens: {
      access_token: jwt({ exp: Math.floor(Date.now() / 1000) + 3600 }),
      id_token: jwt({ email: "alice.legacy@example.test" }),
      refresh_token: "rt-synthetic-legacy",
      account_id: "acct-synthetic-legacy",
    },
  });
  const objects = new Map<string, string>([
    [`${id(1)}/${id(0x803)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(JSON.stringify({ type: "api_key", modelProvider: "openai", key: "sk-synthetic-openai-key-0000000000" }), CLOUD_KEY))],
    // oauth_token: no account object, so the legacy provider key is used.
    [`${id(2)}/anthropic/credentials.json.enc`, JSON.stringify(cloudEnvelope(JSON.stringify({ type: "oauth_token", modelProvider: "anthropic", token: "sk-ant-oat01-synthetic-token-00000000000" }), CLOUD_KEY))],
    [`${id(1)}/accounts/${id(0x806)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(codexAuth, CLOUD_KEY))],
    [`${id(1)}/${id(0x80d)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(JSON.stringify({ type: "api_key", modelProvider: "anthropic", key: "sk-ant-api03-synthetic-selected-0000" }), CLOUD_KEY))],
    [`${id(1)}/${id(0x80e)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(JSON.stringify({ type: "api_key", modelProvider: "google", key: "AIza-synthetic-cloud-google-key-000000" }), CLOUD_KEY))],
    [`${id(2)}/${id(0x80f)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(JSON.stringify({ type: "api_key", modelProvider: "openrouter", key: "sk-or-v1-synthetic-cloud-openrouter-0" }), CLOUD_KEY))],
    // 0x810 has no provider_account_id: Cloud reads Alice's legacy openai object.
    [`${id(1)}/openai/credentials.json.enc`, JSON.stringify(cloudEnvelope(legacyCodexAuth, CLOUD_KEY))],
    // 0x80c HAS a provider_account_id: Cloud reads only its account object,
    // which does not exist. A decoy account-less read must never happen.
    // Saved but unselected in Cloud: copied, left inactive.
    [`${id(2)}/${id(0x80b)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(JSON.stringify({ type: "api_key", modelProvider: "anthropic", key: "sk-ant-api03-synthetic-unselected-000" }), CLOUD_KEY))],
  ]);
  const reads: string[] = [];
  const reader = { get: async (key: string) => { reads.push(key); return objects.get(key) ?? null; } };
  const blobs = new CredentialBlobStore(new PostgresObjectBackend(target), KEYRING);
  const deps = {
    source,
    target,
    reader,
    cloudKeyHex: CLOUD_KEY,
    keyring: KEYRING,
    codingAgents: new CodingAgentStore(target, KEYRING, undefined, blobs),
    logins: new SubscriptionLoginStore(target, KEYRING, blobs),
  };

  // S1 probe: Control already has a native, active Google key in workspace A.
  const native = await deps.codingAgents.putApiKey({
    workspaceId: id(0x201), organizationId: ORG_A,
    modelProvider: "google", key: "AIza-synthetic-native-google-key-00000", label: "Native", actor: { kind: "user", userId: id(1) },
  });
  assert.equal(native.record.isActive, true);
  const plan = await copyCodingAgentCredentials(deps, { orgIds: null }, "plan");
  assert.equal(reads.length, 0, "plan never reads the object store");
  assert.equal(plan.candidates, 16);

  const report = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.deepEqual(report.rows, {
    [id(0x803)]: "copied",
    [id(0x805)]: "copied",
    [id(0x806)]: "copied",
    [id(0x807)]: "skipped:anthropic_login_without_account_email",
    [id(0x808)]: "object_missing",
    // C1
    [id(0x809)]: "skipped:not_a_member",
    [id(0x80a)]: "skipped:credential_not_usable",
    [id(0x80b)]: "copied",
    [id(0x80d)]: "copied",
    [id(0x80e)]: "copied",
    [id(0x80f)]: "copied",
    // C2, Cloud-exact: 0x80c has a provider_account_id, so only its (missing)
    // account object is read; it is broken in Cloud as well.
    [id(0x80c)]: "object_missing",
    // 0x810 has none: Cloud reads the legacy object, and so does the copier.
    [id(0x810)]: "copied",
    [id(0x811)]: "skipped:dead_login",
    // Its workspace (a2, unbound) is not on this pre-0064 target.
    [id(0x812)]: "skipped:workspace_not_on_target",
    // Khaliq: "drop" (no OpenRouter/Daytona login in Control).
    [id(0x813)]: "skipped:unsupported_dropped",
  });
  // Control receives only what Cloud's runtime reads for each row.
  assert.ok(!reads.includes(`${id(1)}/accounts/${id(0x810)}/credentials.json.enc`), "no account read for an account-less login");
  assert.equal(reads.filter((key) => key === `${id(1)}/openai/credentials.json.enc`).length, 1, "legacy read only for 0x810");
  assert.equal(report.ok, false, "a missing object is not a clean copy");
  // Rollback handle: every written Cloud row maps to its Control row.
  assert.equal(Object.keys(report.controlIds).length, 8); // 0x808 object missing
  const mapped = (await target.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM coding_agent_credentials WHERE id::text = ANY($1::text[])", [Object.values(report.controlIds)])).rows[0]!.n;
  assert.equal(mapped, 8);
  assert.doesNotMatch(JSON.stringify(report), /sk-|rt-synthetic|example\.test/);

  const rows = (await target.query<{ auth_type: string; model_provider: string; secret_ciphertext: string | null; blob_location: string | null; workspace_id: string }>(
    "SELECT auth_type, model_provider, secret_ciphertext, blob_location, workspace_id FROM coding_agent_credentials WHERE auth_type <> 'relay_managed' ORDER BY auth_type")).rows;
  assert.deepEqual(rows.map((row) => `${row.auth_type} ${row.model_provider} ${row.workspace_id}`).sort(), [
    `byo_api_key anthropic ${id(0x201)}`,
    `byo_api_key anthropic ${id(0x201)}`,
    `byo_api_key google ${id(0x201)}`,
    `byo_api_key google ${id(0x201)}`,
    `byo_api_key openai ${id(0x201)}`,
    `byo_api_key openrouter ${id(0x205)}`,
    `oauth_token anthropic ${id(0x205)}`,
    `provider_oauth openai ${id(0x201)}`,
    `provider_oauth openai ${id(0x201)}`,
  ]);
  const byProvider = (auth: string, provider: string) => rows.find((row) => row.auth_type === auth && row.model_provider === provider)!;
  assert.equal(decryptSecret(byProvider("byo_api_key", "openai").secret_ciphertext!, KEYRING), "sk-synthetic-openai-key-0000000000");
  assert.equal(decryptSecret(byProvider("oauth_token", "anthropic").secret_ciphertext!, KEYRING), "sk-ant-oat01-synthetic-token-00000000000");
  assert.ok(byProvider("provider_oauth", "openai").blob_location);
  // Explicit selection contract: per (workspace, provider) Control's active
  // and sandbox rows are exactly Cloud's, whatever the seams auto-activated.
  const flags = (await target.query<{ workspace_id: string; model_provider: string; auth_type: string; is_active: boolean; harness_active: boolean; secret_ciphertext: string | null }>(
    "SELECT workspace_id::text AS workspace_id, model_provider, auth_type, is_active, harness_active, secret_ciphertext FROM coding_agent_credentials")).rows;
  // flags includes the identity import's relay_managed rows (0058): the
  // invariants below hold across them too.
  const plain = (row: { secret_ciphertext: string | null }) => row.secret_ciphertext ? decryptSecret(row.secret_ciphertext, KEYRING) : null;
  const anthropicA = flags.filter((row) => row.workspace_id === id(0x201) && row.model_provider === "anthropic");
  assert.deepEqual(anthropicA.filter((row) => row.is_active).map(plain), ["sk-ant-api03-synthetic-selected-0000"],
    "Cloud's selected key is active although the unselected key has the lower id");
  assert.ok(anthropicA.every((row) => !row.harness_active));
  const openaiA = flags.filter((row) => row.workspace_id === id(0x201) && row.model_provider === "openai");
  assert.deepEqual(openaiA.filter((row) => row.is_active).map((row) => row.auth_type), ["byo_api_key"]);
  assert.deepEqual(openaiA.filter((row) => row.harness_active).map((row) => row.auth_type), ["provider_oauth"]);
  const anthropicB = flags.filter((row) => row.workspace_id === id(0x205) && row.model_provider === "anthropic");
  assert.deepEqual(anthropicB.map((row) => [row.is_active, row.harness_active]), [[true, true]]);
  // Invariant: at most one active and one sandbox row per (workspace, provider).
  for (const group of new Set(flags.map((row) => `${row.workspace_id} ${row.model_provider}`))) {
    const rowsInGroup = flags.filter((row) => `${row.workspace_id} ${row.model_provider}` === group);
    assert.ok(rowsInGroup.filter((row) => row.is_active).length <= 1, group);
    assert.ok(rowsInGroup.filter((row) => row.harness_active).length <= 1, group);
  }
  // S1: the native Google key stays active; the unselected Cloud copy is inactive.
  const google = flags.filter((row) => row.workspace_id === id(0x201) && row.model_provider === "google");
  assert.deepEqual(google.filter((row) => row.is_active).map(plain), ["AIza-synthetic-native-google-key-00000"]);
  // A group with no Cloud selection and nothing else active keeps the copy
  // active (never zero) and is reported as a conflict.
  const openrouter = flags.filter((row) => row.model_provider === "openrouter");
  assert.deepEqual(openrouter.map((row) => row.is_active), [true]);
  assert.deepEqual(report.selection, { groups: 5, active: 3, harness: 2, activeDemoted: 0, harnessDemoted: 0, selectionConflicts: 1 });
  assert.equal(await deps.logins.freshAuthFile(id(0x201), (await target.query<{ id: string }>(
    "SELECT id FROM coding_agent_credentials WHERE auth_type = 'provider_oauth'")).rows[0]!.id), codexAuth);

  // Re-run converges on Control's own dedupe keys. The lost key is found
  // this time, so the only remaining problem is the selection conflict.
  objects.set(`${id(2)}/${id(0x808)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(JSON.stringify({ type: "api_key", modelProvider: "openai", key: "sk-synthetic-openai-found-0000000000" }), CLOUD_KEY)));
  const again = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.equal(again.rows[id(0x808)], "copied");
  assert.equal(again.selection?.selectionConflicts, 1);
  assert.equal(again.ok, false, "a selection conflict is never a clean run");
  // Org A alone has no conflict (its Google group has a native active key).
  const orgA = await copyCodingAgentCredentials(deps, { orgIds: [ORG_A] }, "apply");
  assert.equal(orgA.selection?.selectionConflicts, 0);
  assert.equal(orgA.ok, true);
  assert.equal(again.rows[id(0x803)], "already_present");
  assert.equal(again.rows[id(0x805)], "already_present");
  assert.equal(again.rows[id(0x80b)], "already_present");
  const count = (await target.query<{ n: number }>("SELECT count(*)::int AS n FROM coding_agent_credentials WHERE auth_type <> 'relay_managed'")).rows[0]!.n;
  assert.equal(count, 10);
  // The re-run re-applies the same selection.
  const activeAfter = (await target.query<{ secret_ciphertext: string }>(
    "SELECT secret_ciphertext FROM coding_agent_credentials WHERE workspace_id = $1 AND model_provider = 'anthropic' AND is_active", [id(0x201)])).rows;
  assert.deepEqual(activeAfter.map((row) => decryptSecret(row.secret_ciphertext, KEYRING)), ["sk-ant-api03-synthetic-selected-0000"]);
});

test("credential copier CLI: apply refuses up front when copy settings are missing", async () => {
  const { copyApplyPreflight } = await import("../scripts/cloud-import/cli.js");
  assert.deepEqual(copyApplyPreflight({ mode: "plan", copyCredentials: true }, {}), []);
  assert.deepEqual(copyApplyPreflight({ mode: "apply", copyCredentials: false }, {}), []);
  assert.deepEqual(copyApplyPreflight({ mode: "apply", copyCredentials: true }, { CLOUD_IMPORT_TARGET_URL: "postgres://x" }), [
    "CLOUD_CREDENTIAL_ENCRYPTION_KEY",
    "CLOUD_CREDENTIAL_R2_ENDPOINT",
    "CLOUD_CREDENTIAL_R2_BUCKET",
    "CLOUD_CREDENTIAL_R2_ACCESS_KEY_ID",
    "CLOUD_CREDENTIAL_R2_SECRET_ACCESS_KEY",
  ]);
});
