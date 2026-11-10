import assert from "node:assert/strict";
import test from "node:test";
import type { AmpModule } from "../src/amp/module.js";
import type { SelfhostConfig } from "../src/config.js";
import type { FactoryModule } from "../src/factory/routes.js";
import { buildProviderProbes } from "../src/providers/probes.js";
import { providerStatuses } from "../src/providers/registry.js";

const factoryModule = (enabled: boolean) => ({ enabled }) as unknown as FactoryModule;
const ampModule = (enabled: boolean, transport: object | null) =>
  ({ config: { enabled, transport } }) as unknown as AmpModule;
const config = (factory?: object) => ({ factory }) as unknown as SelfhostConfig;

async function statusOf(probes: ReturnType<typeof buildProviderProbes>, id: string) {
  const status = (await providerStatuses(probes)).find(entry => entry.id === id);
  assert.ok(status);
  return status;
}

test("factory enabled flag is reflected", async () => {
  const on = buildProviderProbes({ factory: factoryModule(true), amp: ampModule(false, null), config: config({ enabled: true }) });
  const off = buildProviderProbes({ factory: factoryModule(false), amp: ampModule(false, null), config: config({ enabled: false }) });
  const enabled = await statusOf(on, "factory");
  assert.deepEqual([enabled.implemented, enabled.configured, enabled.enabled], [true, true, true]);
  const disabled = await statusOf(off, "factory");
  assert.deepEqual([disabled.implemented, disabled.configured, disabled.enabled], [true, true, false]);
});

test("factory is not configured without a loaded config", async () => {
  const probes = buildProviderProbes({ factory: factoryModule(false), amp: ampModule(false, null), config: config() });
  assert.equal((await statusOf(probes, "factory")).configured, false);
});

test("amp configured follows the transport, enabled follows the flag", async () => {
  const none = buildProviderProbes({ factory: factoryModule(false), amp: ampModule(false, null), config: config({}) });
  const noneStatus = await statusOf(none, "amp");
  assert.deepEqual([noneStatus.implemented, noneStatus.configured, noneStatus.enabled], [true, false, false]);
  const set = buildProviderProbes({ factory: factoryModule(false), amp: ampModule(true, {}), config: config({}) });
  const setStatus = await statusOf(set, "amp");
  assert.deepEqual([setStatus.implemented, setStatus.configured, setStatus.enabled], [true, true, true]);
});

test("copilot is reported as unconditionally mounted", async () => {
  const probes = buildProviderProbes({ factory: factoryModule(false), amp: ampModule(false, null), config: config({}) });
  const status = await statusOf(probes, "copilot");
  assert.deepEqual([status.implemented, status.configured, status.enabled], [true, true, true]);
});

test("providers without a module are absent and report all false", async () => {
  const probes = buildProviderProbes({ factory: factoryModule(true), amp: ampModule(true, {}), config: config({}) });
  assert.deepEqual(Object.keys(probes).sort(), ["amp", "copilot", "factory"]);
  for (const id of ["capy", "replicas", "dot", "grok-bot"]) {
    const status = await statusOf(probes, id);
    assert.deepEqual([status.implemented, status.configured, status.enabled], [false, false, false]);
  }
});
