import assert from "node:assert/strict";
import test from "node:test";
import { agentNameFor } from "../src/factory/service.js";
import { bindingRow, connectAndBind, FACTORY_KEY, factoryPath, startFactoryEnv } from "./factory-helpers.js";

const bind = (env: Awaited<ReturnType<typeof startFactoryEnv>>, body: Record<string, unknown>, token = env.ownerToken, workspaceId = env.workspaceId) =>
  env.api(factoryPath(workspaceId, "/bindings"), { method: "POST", token, body });

test("factory bind validates the session against Factory and pins its computer", async (t) => {
  const env = await startFactoryEnv(t);
  await env.api(factoryPath(env.workspaceId, "/connection"), { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY } });
  assert.equal((await bind(env, { session_id: "sess a", computer_id: "cmp-1" })).status, 422);
  assert.equal((await bind(env, { session_id: "sess-a" })).status, 422);
  assert.equal((await bind(env, { session_id: "sess-a", computer_id: "cmp-404" })).status, 422);
  assert.equal((await bind(env, { session_id: "sess-missing", computer_id: "cmp-1" })).status, 422);
  assert.equal(env.relay.registered, 0);

  const bound = await bind(env, { session_id: "sess-a", computer_id: "cmp-1" });
  assert.equal(bound.status, 201);
  // The same session presented on another computer is a move, not a second binding.
  const moved = await bind(env, { session_id: "sess-a", computer_id: "cmp-2" });
  assert.equal(moved.status, 409);
  assert.equal(moved.body.error, "factory_session_moved");
  assert.equal(env.relay.registered, 1);
});

test("factory bind refuses a session already bound in another workspace", async (t) => {
  const env = await startFactoryEnv(t);
  await connectAndBind(env, { token: env.ownerOtherToken, workspaceId: env.otherWorkspaceId, sessionId: "sess-a" });
  await env.api(factoryPath(env.workspaceId, "/connection"), { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY } });
  const refused = await bind(env, { session_id: "sess-a", computer_id: "cmp-1" });
  assert.equal(refused.status, 409);
  assert.deepEqual(refused.body, { error: "factory_session_other_workspace", message: "Factory session is bound in another workspace" });
  assert.equal(env.relay.registered, 1);
});

test("factory bind recovers its own registration after a crash between Relay register and the final write", async (t) => {
  let crash = true;
  const env = await startFactoryEnv(t, {
    hooks: {
      beforeFinalWrite: async (operation) => {
        if (operation === "bind" && crash) {
          crash = false;
          throw new Error("simulated crash");
        }
      },
    },
  });
  await env.api(factoryPath(env.workspaceId, "/connection"), { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY } });
  const crashed = await bind(env, { session_id: "sess-a", computer_id: "cmp-1" });
  assert.equal(crashed.status, 500);
  const agentName = agentNameFor("sess-a");
  const orphan = env.relay.agents.get(agentName)!;
  assert.ok(orphan);
  const preparing = await env.database.query<{ id: string; state: string }>("SELECT id, state FROM factory_bindings");
  assert.deepEqual(preparing.rows.map((row) => row.state), ["preparing"]);

  const retried = await bind(env, { session_id: "sess-a", computer_id: "cmp-1" });
  assert.equal(retried.status, 201, JSON.stringify(retried.body));
  assert.equal(retried.body.binding_id, preparing.rows[0]!.id);
  assert.equal(retried.body.agent.id, orphan.id);
  assert.equal(env.relay.registered, 1);
  assert.equal(env.relay.recovered, 1);
  assert.equal((await bindingRow(env, retried.body.binding_id)).state, "bound");
});

test("factory bind: two attempts sharing one preparing row and recovering the same agent never release the winner's agent", async (t) => {
  let calls = 0;
  let secondArrived!: () => void;
  const secondAtFinal = new Promise<void>((resolve) => { secondArrived = resolve; });
  let firstFinished!: () => void;
  const firstDone = new Promise<void>((resolve) => { firstFinished = resolve; });
  const env = await startFactoryEnv(t, {
    hooks: {
      beforeFinalWrite: async (operation) => {
        if (operation !== "bind") return;
        const call = ++calls;
        if (call === 1) throw new Error("simulated crash");
        // The first attempt to arrive waits until the other has also
        // recovered the same agent from the same preparing row; the other
        // then writes only after the first has bound and answered.
        if (call === 2) await secondAtFinal;
        if (call === 3) { secondArrived(); await firstDone; }
      },
    },
  });
  await env.api(factoryPath(env.workspaceId, "/connection"), { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY } });
  assert.equal((await bind(env, { session_id: "sess-a", computer_id: "cmp-1" })).status, 500);
  const agentName = agentNameFor("sess-a");
  const agent = env.relay.agents.get(agentName)!;
  const [row] = (await env.database.query<{ id: string }>("SELECT id FROM factory_bindings")).rows;

  const attempt = () => bind(env, { session_id: "sess-a", computer_id: "cmp-1" }).finally(() => firstFinished());
  const results = await Promise.all([attempt(), attempt()]);
  assert.equal(env.relay.recovered, 2, "both attempts recovered the same agent");
  for (const result of results) {
    assert.equal(result.status, 201, JSON.stringify(result.body));
    assert.equal(result.body.binding_id, row!.id);
    assert.equal(result.body.agent.id, agent.id);
  }
  assert.deepEqual(env.relay.releaseRequests, [], "the winner's agent is never released");
  assert.equal(env.relay.agents.get(agentName)?.id, agent.id);
  const stored = await bindingRow(env, row!.id);
  assert.equal(stored.state, "bound");
  assert.equal(stored.relay_agent_id, agent.id);
});

test("factory bind refuses a Relay agent name held by something that is not ours", async (t) => {
  const env = await startFactoryEnv(t);
  await env.api(factoryPath(env.workspaceId, "/connection"), { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY } });
  const agentName = agentNameFor("sess-a");
  env.relay.agents.set(agentName, { id: "ag-foreign", name: agentName, token: "at_foreign", key: "rk_live_primary", metadata: { source: "someone-else" } });
  const refused = await bind(env, { session_id: "sess-a", computer_id: "cmp-1" });
  assert.equal(refused.status, 409);
  assert.equal(refused.body.error, "factory_agent_conflict");
  assert.equal(env.relay.agents.get(agentName)!.id, "ag-foreign");
});

test("factory rebind after a failed remote release waits for cleanup, then reuses the name", async (t) => {
  const env = await startFactoryEnv(t);
  const first = await connectAndBind(env);
  env.relay.failRelease = true;
  assert.equal((await env.api(factoryPath(env.workspaceId, `/bindings/${first.binding_id}`), { method: "DELETE", token: env.ownerToken })).status, 204);
  const tombstone = await bindingRow(env, first.binding_id);
  assert.equal(tombstone.state, "retired");
  assert.equal(tombstone.relay_agent_id, first.agent.id);
  assert.equal(tombstone.remote_cleanup_code, "release_failed");

  const blocked = await bind(env, { session_id: "sess-a", computer_id: "cmp-1" });
  assert.equal(blocked.status, 409);
  assert.equal(blocked.body.error, "factory_cleanup_pending");

  env.relay.failRelease = false;
  const rebound = await bind(env, { session_id: "sess-a", computer_id: "cmp-1" });
  assert.equal(rebound.status, 201);
  assert.notEqual(rebound.body.binding_id, first.binding_id);
  assert.deepEqual(env.relay.released, [first.agent.id]);
  assert.equal((await bindingRow(env, first.binding_id)).relay_agent_id, null);
});
