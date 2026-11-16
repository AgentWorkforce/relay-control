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
  // xai: Cloud's multi-account flag is false for xai, so even with a
  // provider_account_id only the legacy object is read.
  assert.deepEqual(cloudObjectKeys({ ...base, model_provider: "xai", auth_type: "provider_oauth", provider_account_id: "a" }), [
    `${id(1)}/xai/credentials.json.enc`,
  ]);
  // Aliases normalise exactly like Cloud's canonicalConnectionProvider.
  assert.deepEqual(cloudObjectKeys({ ...base, model_provider: " Codex ", auth_type: "provider_oauth" }), [
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
    [`${id(2)}/${id(0x817)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(JSON.stringify({ type: "api_key", modelProvider: "gemini", key: "AIza-synthetic-gemini-alias-key-000000" }), CLOUD_KEY))],
    [`${id(1)}/${id(0x812)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(JSON.stringify({ type: "api_key", modelProvider: "openai", key: "sk-synthetic-openai-unbound-a2-000000" }), CLOUD_KEY))],
    [`${id(2)}/${id(0x814)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(JSON.stringify({ type: "api_key", modelProvider: "claude", key: "sk-ant-api03-synthetic-alias-0000000" }), CLOUD_KEY))],
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
    blobs,
  };

  // S1 probe: Control already has a native, active Google key in workspace A.
  const native = await deps.codingAgents.putApiKey({
    workspaceId: id(0x201), organizationId: ORG_A,
    modelProvider: "google", key: "AIza-synthetic-native-google-key-00000", label: "Native", actor: { kind: "user", userId: id(1) },
  });
  assert.equal(native.record.isActive, true);
  const plan = await copyCodingAgentCredentials(deps, { orgIds: null }, "plan");
  assert.equal(reads.length, 0, "plan never reads the object store");
  assert.equal(plan.candidates, 18);

  const report = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  // A dropped login is classified in SQL before any object is read: none of
  // the keys Cloud would read for it is fetched.
  const droppedKeys = cloudObjectKeys({ id: id(0x813), cloud_user_id: id(1), auth_type: "provider_oauth", model_provider: "openrouter", provider_account_id: null });
  assert.ok(droppedKeys.length > 0);
  for (const key of droppedKeys) assert.ok(!reads.includes(key), `no object-store read for a dropped login (${key})`);
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
    // On unbound a2, which imports on a 0064 target and binds lazily later.
    [id(0x812)]: "copied",
    // Khaliq: "drop" (no OpenRouter/Daytona login in Control).
    [id(0x813)]: "skipped:unsupported_dropped",
    // Stored as " Claude ": Cloud serves it as anthropic, and so does Control.
    [id(0x814)]: "copied",
    // Stored as "Gemini": Cloud serves it as google.
    [id(0x817)]: "copied",
  });
  // Control receives only what Cloud's runtime reads for each row.
  assert.ok(!reads.includes(`${id(1)}/accounts/${id(0x810)}/credentials.json.enc`), "no account read for an account-less login");
  assert.equal(reads.filter((key) => key === `${id(1)}/openai/credentials.json.enc`).length, 1, "legacy read only for 0x810");
  assert.equal(report.ok, false, "a missing object is not a clean copy");
  // Rollback handle: every written Cloud row maps to its Control row.
  assert.equal(Object.keys(report.controlIds).length, 11); // 0x808 object missing
  const mapped = (await target.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM coding_agent_credentials WHERE id::text = ANY($1::text[])", [Object.values(report.controlIds)])).rows[0]!.n;
  assert.equal(mapped, 11);
  assert.doesNotMatch(JSON.stringify(report), /sk-|rt-synthetic|example\.test/);

  const rows = (await target.query<{ auth_type: string; model_provider: string; secret_ciphertext: string | null; blob_location: string | null; workspace_id: string }>(
    "SELECT auth_type, model_provider, secret_ciphertext, blob_location, workspace_id FROM coding_agent_credentials WHERE auth_type <> 'relay_managed' ORDER BY auth_type")).rows;
  assert.deepEqual(rows.map((row) => `${row.auth_type} ${row.model_provider} ${row.workspace_id}`).sort(), [
    `byo_api_key anthropic ${id(0x201)}`,
    `byo_api_key anthropic ${id(0x201)}`,
    `byo_api_key anthropic ${id(0x205)}`,
    `byo_api_key google ${id(0x201)}`,
    `byo_api_key google ${id(0x201)}`,
    `byo_api_key google ${id(0x205)}`,
    `byo_api_key openai ${id(0x201)}`,
    `byo_api_key openai ${id(0x202)}`,
    `byo_api_key openrouter ${id(0x205)}`,
    `oauth_token anthropic ${id(0x205)}`,
    `provider_oauth openai ${id(0x201)}`,
    `provider_oauth openai ${id(0x201)}`,
  ]);
  const byProvider = (auth: string, provider: string) => rows.find((row) => row.auth_type === auth && row.model_provider === provider && row.workspace_id === id(0x201))
    ?? rows.find((row) => row.auth_type === auth && row.model_provider === provider)!;
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
  // b1 anthropic: Cloud selected both the setup token and the alias key for
  // LLM calls; Control keeps one (the newest, ties by id) and demotes the other.
  assert.deepEqual(anthropicB.filter((row) => row.auth_type !== "relay_managed")
    .map((row) => [row.auth_type, row.is_active, row.harness_active]).sort(),
    [["byo_api_key", false, false], ["oauth_token", true, true]]);
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
  assert.deepEqual(report.selection, { groups: 7, active: 5, harness: 2, activeDemoted: 1, harnessDemoted: 0, selectionConflicts: 1, writes: report.selection!.writes });
  assert.equal(await deps.logins.freshAuthFile(id(0x201), (await target.query<{ id: string }>(
    "SELECT id FROM coding_agent_credentials WHERE auth_type = 'provider_oauth'")).rows[0]!.id), codexAuth);

  // Cloud's status and history survive on the rows the copier wrote.
  const history = async (cloudId: string) => (await target.query<{ status: string; last_error: string | null; refresh_attempts: number; la: string | null; lu: string | null }>(
    `SELECT status, last_error, refresh_attempts,
            to_char(last_authenticated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') AS la,
            to_char(last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') AS lu
       FROM coding_agent_credentials WHERE id = $1`, [report.controlIds[cloudId]])).rows[0]!;
  assert.deepEqual(await history(id(0x806)), { status: "connected", last_error: "transient refresh error", refresh_attempts: 2, la: "2026-01-05T10:00:00.123456", lu: "2026-01-06T11:00:00.654321" });
  assert.deepEqual(await history(id(0x803)), { status: "connected", last_error: null, refresh_attempts: 0, la: "2026-01-07T09:00:00.000001", lu: "2026-01-08T09:30:00.500000" });

  // A re-run writes nothing to rows Control already holds: no blob version,
  // no updated_at, no status moves (storeLogin would rewrite every login).
  const snapshot = async () => (await target.query<{ id: string; v: number | null; u: string; status: string }>(
    "SELECT id::text AS id, blob_version AS v, updated_at::text AS u, status FROM coding_agent_credentials WHERE auth_type <> 'relay_managed' ORDER BY id")).rows;
  // The identity import re-runs after the copy (every convergence rerun
  // does): it must not re-impose Cloud's flags on the relay_managed rows the
  // copier's selection demoted (one active LLM credential per workspace and
  // provider, coding_agent_one_llm), and it must write no credential row.
  const flagsOf = async () => (await target.query<{ id: string; a: boolean; h: boolean }>(
    "SELECT id::text AS id, is_active AS a, harness_active AS h FROM coding_agent_credentials ORDER BY id")).rows;
  const flagsBefore = await flagsOf();
  const xminBefore = (await target.query<{ x: string }>("SELECT string_agg(xmin::text, ',' ORDER BY id) AS x FROM coding_agent_credentials")).rows[0]!.x;
  const identityAgain = await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply");
  assert.equal(identityAgain.ok, true, JSON.stringify(identityAgain.orgs));
  assert.deepEqual(await flagsOf(), flagsBefore, "the identity re-run keeps Control's selection");
  assert.equal((await target.query<{ x: string }>("SELECT string_agg(xmin::text, ',' ORDER BY id) AS x FROM coding_agent_credentials")).rows[0]!.x,
    xminBefore, "and writes no credential row");
  // A relay_managed credential NEW to Control, active in Cloud, for a group
  // where Control already has an active key: it enters inactive, counted,
  // instead of failing the org on coding_agent_one_llm.
  await source.exec(`INSERT INTO provider_credentials (id, organization_id, workspace_id, user_id, harness, model_provider, auth_type, display_name, is_active, harness_active, status, created_at, updated_at)
    VALUES ('${id(0x8f1)}', '${ORG_A}', '${id(0x201)}', '${id(1)}', 'claude', 'anthropic', 'relay_managed', 'Relay Claude (new)', true, false, 'connected', '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z')`);
  const newRelay = await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply");
  assert.equal(newRelay.ok, true, JSON.stringify(newRelay.orgs));
  assert.equal(newRelay.warnings.coding_agent_credentials_control_active_kept, 1);
  const anthropicActive = (await target.query<{ id: string }>(
    "SELECT id::text AS id FROM coding_agent_credentials WHERE workspace_id = $1 AND model_provider = 'anthropic' AND is_active", [id(0x201)])).rows;
  assert.equal(anthropicActive.length, 1);
  assert.notEqual(anthropicActive[0]!.id, id(0x8f1), "Control's selected key stays the active one");
  assert.equal((await target.query<{ a: boolean }>("SELECT is_active AS a FROM coding_agent_credentials WHERE id = $1", [id(0x8f1)])).rows[0]!.a, false);
  await source.exec(`DELETE FROM provider_credentials WHERE id = '${id(0x8f1)}'`);
  const before = await snapshot();
  // Re-run converges on Control's own dedupe keys. The lost key is found
  // this time, so the only remaining problem is the selection conflict.
  objects.set(`${id(2)}/${id(0x808)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(JSON.stringify({ type: "api_key", modelProvider: "openai", key: "sk-synthetic-openai-found-0000000000" }), CLOUD_KEY)));
  const again = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.equal(again.rows[id(0x808)], "copied");
  // Unchanged logins are already_present, never a blanket "copied".
  assert.equal(again.rows[id(0x806)], "already_present");
  assert.equal(again.rows[id(0x810)], "already_present");
  assert.ok(!Object.values(again.rows).includes("updated"));
  const after = new Map((await snapshot()).map((row) => [row.id, row]));
  for (const row of before) assert.deepEqual(after.get(row.id), row, `row ${row.id} unchanged by the re-run`);
  // The report proves it: only the newly found 0x808 key was written.
  assert.deepEqual(again.writes, { inserted: 1, updated: 0, blobWrites: 0, metadataWrites: 1, selectionWrites: again.writes.selectionWrites });
  // A third run with nothing new writes nothing at all.
  const third = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.deepEqual(third.writes, { inserted: 0, updated: 0, blobWrites: 0, metadataWrites: 0, selectionWrites: 0 });
  // Cloud's selection is applied only to rows a run writes: the first run
  // reported the conflict, and rows Control already holds keep Control's
  // own choice (the operator resolves the conflict there), so the re-run
  // re-evaluates only the newly written 0x808.
  assert.deepEqual(again.selection, { groups: 1, active: 1, harness: 0, activeDemoted: 0, harnessDemoted: 0, selectionConflicts: 0, writes: 0 });
  assert.equal(again.ok, false, "0x80c's object is still missing");
  // Org A alone has no conflict (its Google group has a native active key).
  const orgA = await copyCodingAgentCredentials(deps, { orgIds: [ORG_A] }, "apply");
  assert.equal(orgA.selection, undefined, "nothing written, so no selection pass");
  assert.equal(orgA.ok, true);
  // A login Control turned off stays off: a re-run never re-activates it.
  const login806 = again.controlIds[id(0x806)]!;
  const harness = async () => (await target.query<{ h: boolean }>("SELECT harness_active AS h FROM coding_agent_credentials WHERE id = $1", [login806])).rows[0]!.h;
  assert.equal(await harness(), true);
  // selectionDiverged: a sparse per-org count; before the deselection it is
  // whatever the copier's own resolution produced (stable across re-runs).
  const settled = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  const divergence = settled.selectionDiverged!;
  assert.ok(divergence && typeof divergence === "object");
  for (const [org, counts] of Object.entries(divergence)) {
    assert.match(org, /^[0-9a-f-]{36}$/);
    assert.deepEqual(Object.keys(counts).sort(), ["active", "harness"]);
    assert.ok(counts.active + counts.harness > 0, "sparse: no zero entries");
  }
  assert.doesNotMatch(JSON.stringify(divergence), /sk-|rt-|@example/);
  await target.query("UPDATE coding_agent_credentials SET harness_active = false WHERE id = $1", [login806]);
  const deactivated = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  // Control's deselection of Cloud's sandbox login is one more harness difference in org A.
  const orgABefore = divergence[ORG_A] ?? { active: 0, harness: 0 };
  // relay_managed 0x801 is Cloud-active, but the copier's selection made the
  // copied 0x80d key a1's active anthropic credential: a metadata difference.
  const relay801 = (await target.query<{ a: boolean }>("SELECT is_active AS a FROM coding_agent_credentials WHERE id = $1", [id(0x801)])).rows[0]!.a;
  assert.equal(relay801, false);
  assert.ok(orgABefore.active >= 1, "the demoted relay_managed row is counted");
  assert.deepEqual(deactivated.selectionDiverged![ORG_A], { active: orgABefore.active, harness: orgABefore.harness + 1 });
  assert.equal(deactivated.rows[id(0x806)], "already_present");
  assert.equal(await harness(), false, "Control's deselection survives a re-run");
  assert.equal(deactivated.writes.selectionWrites, 0);
  await target.query("UPDATE coding_agent_credentials SET harness_active = true WHERE id = $1", [login806]);
  assert.equal(again.rows[id(0x803)], "already_present");
  assert.equal(again.rows[id(0x805)], "already_present");
  assert.equal(again.rows[id(0x80b)], "already_present");
  const count = (await target.query<{ n: number }>("SELECT count(*)::int AS n FROM coding_agent_credentials WHERE auth_type <> 'relay_managed'")).rows[0]!.n;
  assert.equal(count, 13);
  // The re-run re-applies the same selection.
  const activeAfter = (await target.query<{ secret_ciphertext: string }>(
    "SELECT secret_ciphertext FROM coding_agent_credentials WHERE workspace_id = $1 AND model_provider = 'anthropic' AND is_active", [id(0x201)])).rows;
  assert.deepEqual(activeAfter.map((row) => decryptSecret(row.secret_ciphertext, KEYRING)), ["sk-ant-api03-synthetic-selected-0000"]);
  // Re-import must never clobber Control-owned state. Control rotates
  // 0x806's login (a refresh), and Cloud's copy also changed: Control wins.
  const loginId = report.controlIds[id(0x806)]!;
  const version = async (controlId: string) => (await target.query<{ v: number }>(
    "SELECT blob_version AS v FROM coding_agent_credentials WHERE id = $1", [controlId])).rows[0]!.v;
  const rotated = JSON.stringify({ ...JSON.parse(codexAuth), tokens: { ...JSON.parse(codexAuth).tokens, refresh_token: "rt-rotated-by-control" } });
  await deps.logins.storeLogin({ provider: "openai", workspaceId: id(0x201), organizationId: ORG_A, actor: { kind: "user", userId: id(1) }, authFile: rotated });
  const rotatedVersion = await version(loginId);
  const cloudChanged = JSON.stringify({ ...JSON.parse(codexAuth), tokens: { ...JSON.parse(codexAuth).tokens, refresh_token: "rt-cloud-changed" } });
  objects.set(`${id(1)}/accounts/${id(0x806)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(cloudChanged, CLOUD_KEY)));
  const afterRotation = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.equal(afterRotation.rows[id(0x806)], "control_newer");
  assert.equal(await version(loginId), rotatedVersion, "no write over Control's rotated login");
  assert.equal(await deps.logins.freshAuthFile(id(0x201), loginId), rotated, "Control's rotated token survives");
  assert.equal(afterRotation.writes.blobWrites, 0);

  // Cloud changed and Control did not: the import updates it and moves its marker.
  const legacyId = report.controlIds[id(0x810)]!;
  const legacyBefore = await version(legacyId);
  const legacyChanged = JSON.stringify({ ...JSON.parse(legacyCodexAuth), tokens: { ...JSON.parse(legacyCodexAuth).tokens, refresh_token: "rt-legacy-cloud-v2" } });
  objects.set(`${id(1)}/openai/credentials.json.enc`, JSON.stringify(cloudEnvelope(legacyChanged, CLOUD_KEY)));
  const cloudNewer = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.equal(cloudNewer.rows[id(0x810)], "updated");
  assert.equal(await version(legacyId), legacyBefore + 1);
  assert.equal(await deps.logins.freshAuthFile(id(0x201), legacyId), legacyChanged);
  assert.equal(cloudNewer.writes.updated, 1);
  assert.equal(cloudNewer.writes.blobWrites, 1);
  // ...and the next run sees it unchanged.
  assert.equal((await copyCodingAgentCredentials(deps, { orgIds: null }, "apply")).rows[id(0x810)], "already_present");

  // An unreadable Control blob is a row error, never an overwrite.
  await target.query("UPDATE coding_agent_credentials SET blob_location = 'missing/blob' WHERE id = $1", [loginId]);
  const unreadable = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.equal(unreadable.rows[id(0x806)], "blob_read_failed");
  assert.equal(await version(loginId), rotatedVersion);
  assert.equal(unreadable.ok, false);

  // storeLogin reports, inside its own transaction, exactly the version it wrote.
  let seen: { id: string; version: number } | null = null;
  const storedId = await deps.logins.storeLogin({
    provider: "openai", workspaceId: id(0x201), organizationId: ORG_A, actor: { kind: "user", userId: id(1) },
    authFile: codexAuth, onStored: async (_tx, stored) => { seen = stored; },
  });
  const seenVersion = (seen as { id: string; version: number } | null)!;
  assert.equal(seenVersion.id, storedId);
  assert.equal(seenVersion.version, await version(storedId));
});

test("credential copier: a marker only ever names the import's own write, even racing a Control rotation", async (t) => {
  const source = new PGliteDatabase();
  const target = new PGliteDatabase();
  t.after(async () => {
    await source.close();
    await target.close();
  });
  await source.exec(CLOUD_FIXTURE_DDL);
  await source.exec(cloudFixtureSeed(CLOUD_KEY));
  await migrate(target);
  assert.equal((await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply")).ok, true);
  const auth = (refresh: string) => JSON.stringify({
    auth_mode: "chatgpt",
    tokens: { access_token: jwt({ exp: Math.floor(Date.now() / 1000) + 3600 }), id_token: jwt({ email: "alice@example.test" }), refresh_token: refresh, account_id: "acct-synthetic-1" },
  });
  const objects = new Map([[`${id(1)}/accounts/${id(0x806)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(auth("rt-cloud"), CLOUD_KEY))]]);
  const blobs = new CredentialBlobStore(new PostgresObjectBackend(target), KEYRING);
  const deps = {
    source, target, reader: { get: async (key: string) => objects.get(key) ?? null }, cloudKeyHex: CLOUD_KEY, keyring: KEYRING,
    codingAgents: new CodingAgentStore(target, KEYRING, undefined, blobs),
    logins: new SubscriptionLoginStore(target, KEYRING, blobs), blobs,
  };
  for (let round = 0; round < 4; round += 1) {
    objects.set(`${id(1)}/accounts/${id(0x806)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(auth(`rt-cloud-${round}`), CLOUD_KEY)));
    await Promise.all([
      copyCodingAgentCredentials(deps, { orgIds: null }, "apply"),
      deps.logins.storeLogin({ provider: "openai", workspaceId: id(0x201), organizationId: ORG_A, actor: { kind: "user", userId: id(1) }, authFile: auth(`rt-control-${round}`) }),
    ]);
    const markers = (await target.query<{ row_key: string }>(
      "SELECT row_key FROM cloud_import_ledger WHERE table_name = 'copier_login'")).rows;
    for (const { row_key } of markers) {
      const [controlId, markedVersion] = row_key.split(":") as [string, string];
      const row = (await target.query<{ blob_location: string }>("SELECT blob_location FROM coding_agent_credentials WHERE id = $1", [controlId])).rows[0];
      if (!row) continue;
      // Whatever interleaving happened, a marker names a version the import wrote.
      const atMarker = await blobs.read(`workspaces/${id(0x201)}/accounts/${controlId}/v${markedVersion}.json.enc`, controlId, Number(markedVersion)).catch(() => null);
      if (atMarker !== null) assert.match(atMarker, /rt-cloud-/, `marker ${row_key} names the import's own write`);
    }
  }
});

test("credential copier: a workspace the target does not have is skipped without reading Cloud", async (t) => {
  const source = new PGliteDatabase();
  const target = new PGliteDatabase();
  t.after(async () => {
    await source.close();
    await target.close();
  });
  await source.exec(CLOUD_FIXTURE_DDL);
  await source.exec(cloudFixtureSeed(CLOUD_KEY));
  await migrate(target);
  assert.equal((await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply")).ok, true);
  // As on a pre-0064 target, where the unbound a2 is skipped by the importer.
  await target.query("DELETE FROM workspaces WHERE id = $1", [id(0x202)]);
  const reads: string[] = [];
  const blobs = new CredentialBlobStore(new PostgresObjectBackend(target), KEYRING);
  const report = await copyCodingAgentCredentials({
    source, target, reader: { get: async (key: string) => { reads.push(key); return null; } }, cloudKeyHex: CLOUD_KEY, keyring: KEYRING,
    codingAgents: new CodingAgentStore(target, KEYRING, undefined, blobs), logins: new SubscriptionLoginStore(target, KEYRING, blobs), blobs,
  }, { orgIds: null }, "apply");
  assert.equal(report.rows[id(0x812)], "skipped:workspace_not_on_target");
  assert.ok(!reads.some((key) => key.includes(id(0x812))), "no Cloud read for a row that cannot land");
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
