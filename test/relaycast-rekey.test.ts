import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { randomUUID } from "node:crypto";
import { decryptSecret, encryptSecret, type EncryptionKeyring } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import {
  loadRekeyEnv,
  parseRekeyArgs,
  purgeRelaycastRekey,
  rekeyRelaycastCredentials,
  TOKEN_SOURCES,
  undoRelaycastRekey,
  type RekeyDeps,
} from "../src/relaycast-rekey.js";
import { PGliteDatabase } from "./support/harness.js";

const RELAYCAST_URL = "http://relaycast.internal:8080";
const PUBLIC_URL = "https://cast.example.test";
const INTERNAL_SECRET = "internal-secret-".padEnd(48, "s");
const RC_WS = "7300000000000000001";
const RC_WS_OTHER = "7300000000000000002";

/**
 * A Relaycast that speaks the two routes the re-key uses, with the engine's
 * semantics: server-minted ar_ws_ rotation fenced at stored + 1, and an
 * idempotent legacy -> ar_ upgrade (the same legacy token always yields the
 * same ar_ credential).
 */
function fakeRelaycast() {
  const generations = new Map<string, number>();
  const currentKeys = new Map<string, string>();
  const upgrades = new Map<string, string>();
  const calls: { path: string; bearer: string; body: Record<string, unknown> }[] = [];
  const failUpgrade = new Map<string, { status: number; code: string }>();
  const failRotation = new Map<string, { status: number; code: string }>();
  let beforeUpgrade: ((legacy: string) => Promise<void>) | undefined;
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const fetch = async (input: string, init: RequestInit): Promise<Response> => {
    const url = new URL(input);
    assert.equal(url.origin, RELAYCAST_URL);
    const bearer = String((init.headers as Record<string, string>).authorization ?? "").replace(/^Bearer /, "");
    const body = JSON.parse(String(init.body ?? "{}")) as Record<string, unknown>;
    calls.push({ path: url.pathname, bearer, body });
    const rotate = /^\/internal\/workspaces\/([^/]+)\/api-key$/.exec(url.pathname);
    if (rotate) {
      if (bearer !== INTERNAL_SECRET) return json(401, { ok: false, error: { code: "unauthorized", message: "Invalid internal token" } });
      const id = decodeURIComponent(rotate[1]!);
      const failure = failRotation.get(id);
      if (failure) return json(failure.status, { ok: false, error: { code: failure.code, message: `secret detail ${INTERNAL_SECRET}` } });
      const stored = generations.get(id) ?? 0;
      if (body.api_key === undefined) {
        const apiKey = `ar_ws_${id}_${randomUUID().replaceAll("-", "")}`;
        generations.set(id, stored + 1);
        currentKeys.set(id, apiKey);
        return json(200, { ok: true, data: { workspace_id: id, api_key_generation: stored + 1, api_key: apiKey } });
      }
      if (typeof body.key_generation !== "number" || body.key_generation <= stored) {
        return json(409, { ok: false, error: { code: "stale_key_generation", message: "stale" } });
      }
      generations.set(id, body.key_generation);
      currentKeys.set(id, String(body.api_key));
      return json(200, { ok: true, data: { workspace_id: id, api_key_generation: body.key_generation } });
    }
    if (url.pathname === "/v1/credentials/upgrade") {
      if (bearer.startsWith("ar_")) {
        return json(409, { ok: false, error: { code: "credential_not_legacy", message: "already ar" } });
      }
      const failure = failUpgrade.get(bearer);
      if (failure) return json(failure.status, { ok: false, error: { code: failure.code, message: `bad ${bearer}` } });
      await beforeUpgrade?.(bearer);
      const kind = bearer.startsWith("wh_live_") ? "wh" : "ag";
      const credential = upgrades.get(bearer) ?? `ar_${kind}_${randomUUID().replaceAll("-", "")}`;
      upgrades.set(bearer, credential);
      return json(200, { ok: true, data: { credential, kind: kind === "wh" ? "webhook" : "agent", legacy_expires_at: "2027-01-01T00:00:00.000Z" } });
    }
    return json(404, { ok: false, error: { code: "not_found", message: "Route not found" } });
  };
  return {
    fetch, calls, upgrades, currentKeys, generations, failUpgrade, failRotation,
    setBeforeUpgrade(hook: (legacy: string) => Promise<void>) { beforeUpgrade = hook; },
  };
}

type Fixture = Awaited<ReturnType<typeof fixture>>;

async function fixture(t: TestContext) {
  const database = new PGliteDatabase();
  t.after(() => database.close());
  await migrate(database);
  const keyring: EncryptionKeyring = { active: { id: "k1", key: Buffer.alloc(32, 9) } };
  const enc = (value: string) => encryptSecret(value, keyring.active);
  const dec = (value: string) => decryptSecret(value, keyring);
  const relaycast = fakeRelaycast();
  const logs: string[] = [];
  const deps: RekeyDeps = {
    database,
    keyring,
    relaycastUrl: RELAYCAST_URL,
    relaycastOrigins: [RELAYCAST_URL, PUBLIC_URL],
    internalSecret: INTERNAL_SECRET,
    fetch: relaycast.fetch,
    log: (event, fields) => logs.push(JSON.stringify({ event, ...fields })),
  };

  const org = randomUUID(), otherOrg = randomUUID(), user = randomUUID();
  const workspace = randomUUID(), sharedWorkspace = randomUUID(), otherWorkspace = randomUUID();
  const secrets: string[] = [INTERNAL_SECRET];
  const secret = (value: string) => {
    secrets.push(value);
    return value;
  };
  for (const id of [org, otherOrg]) await database.query("INSERT INTO organizations(id,name) VALUES ($1,'Org')", [id]);
  await database.query("INSERT INTO users(id,email,name) VALUES ($1,$2,'User')", [user, `${user}@example.test`]);
  for (const id of [org, otherOrg]) {
    await database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'owner')", [id, user]);
  }
  const legacyKey = secret(`rk_live_${"a".repeat(32)}`);
  const otherKey = secret(`rk_live_${"b".repeat(32)}`);
  const insertWorkspace = async (id: string, organization: string, relaycastId: string, key: string) =>
    database.query(
      "INSERT INTO workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext) VALUES ($1,$2,'W',$3,$4)",
      [id, organization, relaycastId, enc(key)],
    );
  await insertWorkspace(workspace, org, RC_WS, legacyKey);
  // Another organization bound to the same Relaycast workspace and key.
  await insertWorkspace(sharedWorkspace, otherOrg, RC_WS, legacyKey);
  await insertWorkspace(otherWorkspace, org, RC_WS_OTHER, otherKey);

  const tokens: Record<string, string> = {};
  const ids: Record<string, string> = {};
  const add = async (name: string, sql: string, params: (token: string, id: string) => unknown[], token = `at_live_${name}_${"x".repeat(24)}`) => {
    const id = randomUUID();
    tokens[name] = secret(token);
    ids[name] = id;
    await database.query(sql, params(token, id));
  };
  await add("person", `INSERT INTO person_identities(id,workspace_id,user_id,agent_name,agent_remote_id,token_ciphertext,relaycast_workspace_id)
    VALUES ($1,$2,$3,'person','ag_person',$4,$5)`, (token, id) => [id, workspace, user, enc(token), RC_WS]);
  await add("hosted", `INSERT INTO hosted_relay_participants(id,workspace_id,user_id,relaycast_workspace_id,agent_name,agent_remote_id,token_ciphertext)
    VALUES ($1,$2,$3,$4,'hosted','ag_hosted',$5)`, (token, id) => [id, workspace, user, RC_WS, enc(token)]);
  await add("desktop", `INSERT INTO desktop_relay_identities(id,workspace_id,organization_id,user_id,relaycast_workspace_id,source_id,agent_name,agent_remote_id,address,token_ciphertext)
    VALUES ($1,$2,$3,$4,$5,$6,'desk','ag_desk','desk@host',$7)`, (token, id) => [id, workspace, org, user, RC_WS, randomUUID(), enc(token)]);
  await add("amp", `INSERT INTO amp_bindings(id,workspace_id,organization_id,user_id,thread_id,state,relaycast_workspace_id,agent_name,agent_remote_id,token_ciphertext)
    VALUES ($1,$2,$3,$4,'T-1','bound',$5,'amp','ag_amp',$6)`, (token, id) => [id, workspace, org, user, RC_WS, enc(token)]);
  await add("factory", `INSERT INTO factory_bindings(id,workspace_id,organization_id,user_id,session_id,computer_id,state,relay_agent_name,relay_agent_id,hosted_token_envelope)
    VALUES ($1,$2,$3,$4,'s-1','c-1','bound','factory','ag_factory',$5)`, (token, id) => [id, workspace, org, user, enc(token)]);
  await add("capy", `INSERT INTO capy_bindings(id,workspace_id,organization_id,user_id,thread_id,state,connection_digest,relaycast_workspace_id,agent_name,agent_remote_id,token_ciphertext)
    VALUES ($1,$2,$3,$4,'jam_1','bound','d',$5,'capy','ag_capy',$6)`, (token, id) => [id, workspace, org, user, RC_WS, enc(token)]);
  // Agent in the other workspace, for --workspace filtering.
  await add("otherPerson", `INSERT INTO person_identities(id,workspace_id,user_id,agent_name,agent_remote_id,token_ciphertext,relaycast_workspace_id)
    VALUES ($1,$2,$3,'other','ag_other',$4,$5)`, (token, id) => [id, otherWorkspace, user, enc(token), RC_WS_OTHER]);
  const shim = (url: string) => (token: string, id: string) => [
    id, randomUUID(), randomUUID(), randomUUID(), enc("hook-token"), url, enc(token), workspace, user,
  ];
  const shimSql = `INSERT INTO events_shims(id,mcp_token_hash,hook_token_hash,manage_token_hash,hook_token_ciphertext,wake_url,wake_secret_ciphertext,created_at,last_used_at,workspace_id,user_id)
    VALUES ($1,$2,$3,$4,$5,$6,$7,now(),now(),$8,$9)`;
  await add("wake", shimSql, shim(`${PUBLIC_URL}/v1/hooks/wh_1`), `wh_live_${"w".repeat(32)}`);
  await add("foreignWake", shimSql, shim("https://cast.elsewhere.test/v1/hooks/wh_2"), `wh_live_${"f".repeat(32)}`);

  const read = async (table: string, column: string, id: string) => {
    const { rows } = await database.query<{ value: string }>(`SELECT ${column} AS value FROM ${table} WHERE id = $1`, [id]);
    return rows[0]!.value;
  };
  const workspaceKey = (id: string) => read("workspaces", "relaycast_api_key_ciphertext", id);
  const snapshot = async () => {
    const out: Record<string, string> = {};
    for (const id of [workspace, sharedWorkspace, otherWorkspace]) out[`ws:${id}`] = await workspaceKey(id);
    const where: Record<string, [string, string]> = {
      person: ["person_identities", "token_ciphertext"],
      otherPerson: ["person_identities", "token_ciphertext"],
      hosted: ["hosted_relay_participants", "token_ciphertext"],
      desktop: ["desktop_relay_identities", "token_ciphertext"],
      amp: ["amp_bindings", "token_ciphertext"],
      factory: ["factory_bindings", "hosted_token_envelope"],
      capy: ["capy_bindings", "token_ciphertext"],
      wake: ["events_shims", "wake_secret_ciphertext"],
      foreignWake: ["events_shims", "wake_secret_ciphertext"],
    };
    for (const [name, [table, column]] of Object.entries(where)) out[name] = await read(table, column, ids[name]!);
    return out;
  };
  return {
    database, keyring, enc, dec, relaycast, deps, logs, secrets, tokens, ids, read, workspaceKey, snapshot,
    workspace, sharedWorkspace, otherWorkspace, legacyKey, otherKey,
  };
}

const agentTables = (f: Fixture) => ({
  person: ["person_identities", "token_ciphertext"],
  hosted: ["hosted_relay_participants", "token_ciphertext"],
  desktop: ["desktop_relay_identities", "token_ciphertext"],
  amp: ["amp_bindings", "token_ciphertext"],
  factory: ["factory_bindings", "hosted_token_envelope"],
  capy: ["capy_bindings", "token_ciphertext"],
  otherPerson: ["person_identities", "token_ciphertext"],
  wake: ["events_shims", "wake_secret_ciphertext"],
} satisfies Record<string, [string, string]> as Record<string, [string, string]>);

test("covers every Relaycast credential column", () => {
  assert.deepEqual(
    TOKEN_SOURCES.map((source) => `${source.table}.${source.column}`),
    [
      "person_identities.token_ciphertext",
      "hosted_relay_participants.token_ciphertext",
      "desktop_relay_identities.token_ciphertext",
      "amp_bindings.token_ciphertext",
      "factory_bindings.hosted_token_envelope",
      "capy_bindings.token_ciphertext",
      "events_shims.wake_secret_ciphertext",
    ],
  );
});

test("rotates each Relaycast workspace key once and stores it in every bound row", async (t) => {
  const f = await fixture(t);
  const report = await rekeyRelaycastCredentials(f.deps);
  assert.equal(report.failed, 0);

  const rotations = f.relaycast.calls.filter((call) => call.path.startsWith("/internal/"));
  assert.deepEqual(rotations.map((call) => call.path).sort(), [
    `/internal/workspaces/${RC_WS}/api-key`,
    `/internal/workspaces/${RC_WS_OTHER}/api-key`,
  ]);
  for (const call of rotations) {
    assert.equal(call.bearer, INTERNAL_SECRET);
    assert.deepEqual(call.body, { grace_ms: 3_600_000 });
  }
  const primary = f.dec(await f.workspaceKey(f.workspace));
  assert.equal(primary, f.relaycast.currentKeys.get(RC_WS));
  assert.match(primary, /^ar_ws_/);
  // The other organization's row bound to the same Relaycast workspace follows.
  assert.equal(f.dec(await f.workspaceKey(f.sharedWorkspace)), primary);
  assert.equal(f.dec(await f.workspaceKey(f.otherWorkspace)), f.relaycast.currentKeys.get(RC_WS_OTHER));

  const { rows } = await f.database.query<{ row_id: string; old_ciphertext: string; key_generation: string; kind: string }>(
    "SELECT row_id, old_ciphertext, key_generation::text, kind FROM relaycast_rekey_backups WHERE run_id = $1 AND table_name = 'workspaces' ORDER BY row_id",
    [report.runId],
  );
  assert.equal(rows.length, 3);
  for (const row of rows) {
    assert.equal(row.kind, "workspace");
    assert.equal(row.key_generation, "1");
    assert.equal(f.dec(row.old_ciphertext), row.row_id === f.otherWorkspace ? f.otherKey : f.legacyKey);
  }
});

test("upgrades every stored agent and wake token, leaving another Relaycast's wake alone", async (t) => {
  const f = await fixture(t);
  const before = await f.snapshot();
  const report = await rekeyRelaycastCredentials(f.deps);
  assert.equal(report.failed, 0);
  for (const [name, [table, column]] of Object.entries(agentTables(f))) {
    const stored = f.dec(await f.read(table, column, f.ids[name]!));
    assert.equal(stored, f.relaycast.upgrades.get(f.tokens[name]!), name);
    assert.match(stored, name === "wake" ? /^ar_wh_/ : /^ar_ag_/);
  }
  assert.equal(await f.read("events_shims", "wake_secret_ciphertext", f.ids.foreignWake!), before.foreignWake);
  assert.equal(report.summary["events_shims.wake_secret_ciphertext"]?.foreign, 1);
  const upgradeCalls = f.relaycast.calls.filter((call) => call.path === "/v1/credentials/upgrade");
  assert.equal(upgradeCalls.length, 8);
  for (const call of upgradeCalls) assert.deepEqual(call.body, {});
  const { rows } = await f.database.query<{ count: number }>(
    "SELECT count(*)::int AS count FROM relaycast_rekey_backups WHERE run_id = $1",
    [report.runId],
  );
  assert.equal(rows[0]!.count, 3 + 8);
});

test("a rerun skips credentials already ar_ without calling Relaycast", async (t) => {
  const f = await fixture(t);
  await rekeyRelaycastCredentials(f.deps);
  const after = await f.snapshot();
  f.relaycast.calls.length = 0;
  const report = await rekeyRelaycastCredentials(f.deps);
  assert.equal(report.failed, 0);
  assert.equal(f.relaycast.calls.length, 0);
  assert.equal(report.items.filter((item) => item.outcome === "upgraded").length, 0);
  assert.equal(report.items.filter((item) => item.outcome === "already_ar").length, 3 + 8);
  assert.deepEqual(await f.snapshot(), after);
  const { rows } = await f.database.query<{ count: number }>(
    "SELECT count(*)::int AS count FROM relaycast_rekey_backups WHERE run_id = $1",
    [report.runId],
  );
  assert.equal(rows[0]!.count, 0);
});

test("409 credential_not_legacy counts as done and writes nothing", async (t) => {
  const f = await fixture(t);
  f.relaycast.failUpgrade.set(f.tokens.amp!, { status: 409, code: "credential_not_legacy" });
  const before = await f.snapshot();
  const report = await rekeyRelaycastCredentials(f.deps);
  assert.equal(report.failed, 0);
  const amp = report.items.find((item) => item.rowId === f.ids.amp);
  assert.deepEqual(amp && { outcome: amp.outcome, code: amp.code }, { outcome: "already_ar", code: "credential_not_legacy" });
  assert.equal(await f.read("amp_bindings", "token_ciphertext", f.ids.amp!), before.amp);
});

test("a failed credential is reported and the rest still upgrade", async (t) => {
  const f = await fixture(t);
  f.relaycast.failUpgrade.set(f.tokens.hosted!, { status: 409, code: "credential_superseded" });
  f.relaycast.failRotation.set(RC_WS_OTHER, { status: 500, code: "internal_error" });
  // Undecryptable ciphertext (a key this keyring does not hold).
  await f.database.query("UPDATE capy_bindings SET token_ciphertext = $2 WHERE id = $1", [
    f.ids.capy,
    encryptSecret(f.tokens.capy!, { id: "gone", key: Buffer.alloc(32, 1) }),
  ]);
  // A writer replaces the token while its upgrade is in flight.
  f.relaycast.setBeforeUpgrade(async (legacy) => {
    if (legacy === f.tokens.desktop) {
      await f.database.query("UPDATE desktop_relay_identities SET token_ciphertext = $2 WHERE id = $1", [f.ids.desktop, f.enc("at_live_resynced")]);
    }
  });
  const before = await f.snapshot();
  const report = await rekeyRelaycastCredentials(f.deps);

  const failures = Object.fromEntries(report.items.filter((item) => item.outcome === "failed").map((item) => [item.rowId, item.code]));
  assert.deepEqual(failures, {
    [f.otherWorkspace]: "internal_error",
    [f.ids.hosted!]: "credential_superseded",
    [f.ids.capy!]: "ciphertext_unknown_key",
    [f.ids.desktop!]: "concurrent_change",
  });
  assert.equal(report.failed, 4);
  assert.equal(await f.workspaceKey(f.otherWorkspace), before[`ws:${f.otherWorkspace}`]);
  assert.equal(await f.read("hosted_relay_participants", "token_ciphertext", f.ids.hosted!), before.hosted);
  assert.equal(f.dec(await f.read("desktop_relay_identities", "token_ciphertext", f.ids.desktop!)), "at_live_resynced");
  // Everything else went through.
  assert.match(f.dec(await f.workspaceKey(f.workspace)), /^ar_ws_/);
  for (const name of ["person", "amp", "factory", "otherPerson", "wake"]) {
    const [table, column] = agentTables(f)[name]!;
    assert.match(f.dec(await f.read(table, column, f.ids[name]!)), /^ar_/, name);
  }
  // No backup is left for a credential that was not replaced.
  const { rows } = await f.database.query<{ row_id: string }>("SELECT row_id FROM relaycast_rekey_backups WHERE run_id = $1", [report.runId]);
  const backedUp = new Set(rows.map((row) => row.row_id));
  for (const id of [f.otherWorkspace, f.ids.hosted!, f.ids.capy!, f.ids.desktop!]) assert.ok(!backedUp.has(id));
});

test("--workspace limits the run to one workspace and its Relaycast binding", async (t) => {
  const f = await fixture(t);
  const before = await f.snapshot();
  const report = await rekeyRelaycastCredentials(f.deps, { workspaceId: f.workspace });
  assert.equal(report.failed, 0);
  // The shared Relaycast workspace's other row is rotated with it.
  assert.match(f.dec(await f.workspaceKey(f.sharedWorkspace)), /^ar_ws_/);
  assert.equal(await f.workspaceKey(f.otherWorkspace), before[`ws:${f.otherWorkspace}`]);
  assert.equal(await f.read("person_identities", "token_ciphertext", f.ids.otherPerson!), before.otherPerson);
  assert.match(f.dec(await f.read("person_identities", "token_ciphertext", f.ids.person!)), /^ar_ag_/);
});

test("dry run reports by table and kind without calling Relaycast or writing", async (t) => {
  const f = await fixture(t);
  const before = await f.snapshot();
  const report = await rekeyRelaycastCredentials({ ...f.deps, internalSecret: null }, { dryRun: true });
  assert.equal(report.runId, null);
  assert.equal(report.mode, "dry-run");
  assert.equal(f.relaycast.calls.length, 0);
  assert.deepEqual(await f.snapshot(), before);
  assert.deepEqual(report.summary["workspaces.relaycast_api_key_ciphertext"], { would_upgrade: 3 });
  assert.deepEqual(report.summary["person_identities.token_ciphertext"], { would_upgrade: 2 });
  assert.deepEqual(report.summary["events_shims.wake_secret_ciphertext"], { would_upgrade: 1, foreign: 1 });
  const { rows } = await f.database.query<{ count: number }>("SELECT count(*)::int AS count FROM relaycast_rekey_backups");
  assert.equal(rows[0]!.count, 0);
});

test("undo restores every replaced ciphertext and pushes the old workspace key back", async (t) => {
  const f = await fixture(t);
  const before = await f.snapshot();
  const run = await rekeyRelaycastCredentials(f.deps);
  assert.equal(run.failed, 0);
  f.relaycast.calls.length = 0;

  const undo = await undoRelaycastRekey(f.deps, run.runId!);
  assert.equal(undo.failed, 0);
  assert.equal(undo.items.filter((item) => item.outcome === "restored").length, 3 + 8);
  assert.deepEqual(await f.snapshot(), before);
  const pushes = f.relaycast.calls.filter((call) => call.path.startsWith("/internal/"));
  assert.equal(pushes.length, 2);
  const primary = pushes.find((call) => call.path.includes(RC_WS + "/"))!;
  assert.deepEqual(primary.body, { api_key: f.legacyKey, key_generation: 2, grace_ms: 3_600_000 });
  assert.equal(f.relaycast.currentKeys.get(RC_WS), f.legacyKey);
  assert.equal(f.relaycast.calls.filter((call) => call.path === "/v1/credentials/upgrade").length, 0);

  // A second undo has nothing left to restore.
  const again = await undoRelaycastRekey(f.deps, run.runId!);
  assert.equal(again.items.length, 0);
  // And a rekey after the undo upgrades the same principals to the same ar_ credentials.
  const rerun = await rekeyRelaycastCredentials(f.deps);
  assert.equal(rerun.failed, 0);
  assert.equal(f.dec(await f.read("amp_bindings", "token_ciphertext", f.ids.amp!)), f.relaycast.upgrades.get(f.tokens.amp!));
});

test("undo leaves a row changed since the run and reports it", async (t) => {
  const f = await fixture(t);
  const run = await rekeyRelaycastCredentials(f.deps);
  const changed = f.enc("ar_ag_written_later");
  await f.database.query("UPDATE amp_bindings SET token_ciphertext = $2 WHERE id = $1", [f.ids.amp, changed]);
  const undo = await undoRelaycastRekey(f.deps, run.runId!);
  assert.equal(undo.failed, 1);
  assert.deepEqual(undo.items.find((item) => item.outcome === "failed"), {
    table: "amp_bindings", column: "token_ciphertext", rowId: f.ids.amp, kind: "agent", outcome: "failed", code: "concurrent_change",
  });
  assert.equal(await f.read("amp_bindings", "token_ciphertext", f.ids.amp!), changed);
  await assert.rejects(undoRelaycastRekey(f.deps, randomUUID()), /No relaycast rekey backups/);
});

test("nothing secret reaches the log or the report", async (t) => {
  const f = await fixture(t);
  f.relaycast.failUpgrade.set(f.tokens.hosted!, { status: 500, code: "internal_error" });
  f.relaycast.failRotation.set(RC_WS_OTHER, { status: 409, code: "key_write_conflict" });
  const before = await f.snapshot();
  const run = await rekeyRelaycastCredentials(f.deps);
  await rekeyRelaycastCredentials(f.deps, { dryRun: true });
  const undo = await undoRelaycastRekey(f.deps, run.runId!);

  const { rows } = await f.database.query<{ old_ciphertext: string; new_ciphertext: string }>("SELECT old_ciphertext, new_ciphertext FROM relaycast_rekey_backups");
  const forbidden = [
    ...f.secrets,
    ...f.relaycast.upgrades.values(),
    ...f.relaycast.currentKeys.values(),
    ...Object.values(before),
    ...rows.flatMap((row) => [row.old_ciphertext, row.new_ciphertext]),
    f.keyring.active.key.toString("base64"),
  ];
  const output = [...f.logs, JSON.stringify(run), JSON.stringify(undo)].join("\n");
  assert.ok(f.logs.length > 10);
  for (const value of forbidden) assert.ok(!output.includes(value), "a secret or ciphertext was logged");
  for (const line of f.logs) {
    const event = JSON.parse(line) as Record<string, unknown>;
    for (const value of Object.values(event)) assert.ok(value === null || ["string", "number", "boolean"].includes(typeof value));
  }
});

test("CLI arguments carry no secret and environment errors name variables only", () => {
  assert.deepEqual(parseRekeyArgs([]), { mode: "rekey", dryRun: false });
  assert.deepEqual(parseRekeyArgs(["--workspace", "w", "--dry-run", "--grace-ms", "0"]), { mode: "rekey", dryRun: true, workspaceId: "w", graceMs: 0 });
  assert.deepEqual(parseRekeyArgs(["--undo", "r"]), { mode: "undo", runId: "r" });
  assert.throws(() => parseRekeyArgs(["--internal-secret", "x"]), /unknown argument --internal-secret/);
  assert.throws(() => parseRekeyArgs(["rk_live_pasted"]), (error: Error) => !error.message.includes("rk_live_pasted"));
  assert.throws(() => parseRekeyArgs(["--undo", "r", "--dry-run"]), /--undo takes no/);
  assert.deepEqual(parseRekeyArgs(["--purge", "r"]), { mode: "purge", runId: "r", confirm: false });
  assert.deepEqual(parseRekeyArgs(["--purge", "r", "--confirm"]), { mode: "purge", runId: "r", confirm: true });
  assert.throws(() => parseRekeyArgs(["--purge", "r", "--undo", "r"]), /--purge takes only --confirm/);
  assert.throws(() => parseRekeyArgs(["--confirm"]), /--confirm applies only to --purge/);
  assert.throws(() => parseRekeyArgs(["--grace-ms", "-1"]), /needs a value|non-negative/);

  const env = {
    DATABASE_URL: "postgres://u:dbpass@db/control",
    RELAYCAST_URL: RELAYCAST_URL,
    RELAYCAST_PUBLIC_URL: PUBLIC_URL,
    SELFHOST_ENCRYPTION_KEY_ID: "k1",
    SELFHOST_ENCRYPTION_KEY: Buffer.alloc(32, 3).toString("base64"),
  };
  assert.throws(() => loadRekeyEnv(env, true), (error: Error) =>
    /RELAYCAST_INTERNAL_SECRET is required/.test(error.message) && !error.message.includes("dbpass"));
  const loaded = loadRekeyEnv({ ...env, RELAYCAST_INTERNAL_SECRET: INTERNAL_SECRET }, true);
  assert.equal(loaded.internalSecret, INTERNAL_SECRET);
  assert.deepEqual(loaded.relaycastOrigins, [RELAYCAST_URL, PUBLIC_URL]);
  assert.equal(loadRekeyEnv(env, false).internalSecret, null);
});

test("purge without --confirm only reports; with it the run's backups are deleted", async (t) => {
  const f = await fixture(t);
  const run = await rekeyRelaycastCredentials(f.deps);
  // One row rewritten since the run, one row gone.
  await f.database.query("UPDATE amp_bindings SET token_ciphertext = $2 WHERE id = $1", [f.ids.amp, f.enc("ar_ag_later")]);
  await f.database.query("DELETE FROM factory_bindings WHERE id = $1", [f.ids.factory]);
  const count = async () => (await f.database.query<{ count: number }>(
    "SELECT count(*)::int AS count FROM relaycast_rekey_backups WHERE run_id = $1", [run.runId],
  )).rows[0]!.count;

  const preview = await purgeRelaycastRekey(f.deps, run.runId!);
  assert.deepEqual(preview, {
    runId: run.runId, confirmed: false, backups: 11, live: 9, changed: 1, gone: 1, restored: 0, purged: 0,
  });
  assert.equal(await count(), 11);

  const purged = await purgeRelaycastRekey(f.deps, run.runId!, { confirm: true });
  assert.equal(purged.purged, 11);
  assert.equal(await count(), 0);
  await assert.rejects(undoRelaycastRekey(f.deps, run.runId!), /No relaycast rekey backups/);
  await assert.rejects(purgeRelaycastRekey(f.deps, run.runId!, { confirm: true }), /No relaycast rekey backups/);
  await assert.rejects(purgeRelaycastRekey(f.deps, "not-a-uuid"), /--purge must be a run id/);

  // Counts only: the purge log carries no ciphertext or credential.
  const purgeLines = f.logs.filter((line) => line.includes("relaycast_rekey.purge"));
  assert.equal(purgeLines.length, 2);
  for (const line of purgeLines) {
    for (const value of [...f.secrets, ...f.relaycast.upgrades.values()]) assert.ok(!line.includes(value));
    assert.ok(!/v2\.k1\./.test(line));
  }
});

test("purge counts rows restored by undo", async (t) => {
  const f = await fixture(t);
  const run = await rekeyRelaycastCredentials(f.deps);
  await undoRelaycastRekey(f.deps, run.runId!);
  const report = await purgeRelaycastRekey(f.deps, run.runId!, { confirm: true });
  assert.equal(report.restored, 11);
  assert.equal(report.purged, 11);
});
