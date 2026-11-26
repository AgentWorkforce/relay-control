import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import type { SelfhostConfig } from "../src/config.js";
import type { Database } from "../src/database.js";
import { grokRoutinesOptions } from "../src/mcp/grok-routines.js";
import { createRelaycastClient } from "../src/messaging/relaycast.js";

const KEYRING = { active: { id: "fake-key", key: Buffer.alloc(32, 7) } };
const database = {} as Database;
const client = createRelaycastClient({ internalOrigin: "https://relaycast.example.test" });

function configWith(extra: Record<string, unknown>): SelfhostConfig {
  return { dashboardUrl: "https://dashboard.example.test/site", publicBaseUrl: "https://relay.example.test/dashboard", encryptionKeyring: KEYRING, ...extra } as unknown as SelfhostConfig;
}
const build = (config: SelfhostConfig, now?: () => Date) =>
  grokRoutinesOptions(config, { database, tenancyMode: "multi", client, ...(now ? { now } : {}) });

test("a relaygate public URL gives the routines a gate client", () => {
  const options = build(configWith({ relaygatePublicUrl: "https://gate.example.test" }));
  assert.ok(options.gate);
  assert.notEqual(options.gate, client);
});

test("without a relaygate public URL there is no gate client", () => {
  assert.equal("gate" in build(configWith({})), false);
});

test("a required cursor cloud run identity sets cursorRunIdentityRequired", () => {
  const options = build(configWith({ cursorCloud: { enabled: true, runIdentity: "required", trustedTeams: [], allowSelfHosted: false } }));
  assert.equal(options.cursorRunIdentityRequired, true);
});

test("cursorRunIdentityRequired is false when optional, disabled or unconfigured", () => {
  const optional = { enabled: true, runIdentity: "optional", trustedTeams: [], allowSelfHosted: false };
  assert.equal(build(configWith({ cursorCloud: optional })).cursorRunIdentityRequired, false);
  assert.equal(build(configWith({ cursorCloud: { ...optional, enabled: false, runIdentity: "required" } })).cursorRunIdentityRequired, false);
  assert.equal(build(configWith({})).cursorRunIdentityRequired, false);
});

test("options carry the keyring, public origin, tenancy mode, client and clock", () => {
  const now = () => new Date(0);
  const options = build(configWith({}), now);
  assert.equal(options.keyring, KEYRING);
  assert.equal(options.dashboardOrigin, "https://dashboard.example.test");
  assert.equal(options.publicOrigin, "https://relay.example.test");
  assert.equal(options.tenancyMode, "multi");
  assert.equal(options.client, client);
  assert.equal(options.database, database);
  assert.equal(options.now, now);
});

// The defect this guards: one of the two construction sites built its own options object and drifted from the other.
test("the server and createApp build GrokRoutines only through grokRoutinesOptions", async () => {
  for (const file of ["../src/server.ts", "../src/app.ts"]) {
    const source = await readFile(new URL(file, import.meta.url), "utf8");
    assert.equal((source.match(/new GrokRoutines\(/g) ?? []).length, 1, file);
    assert.match(source, /new GrokRoutines\(grokRoutinesOptions\(config,/, file);
  }
});
