import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { decryptSecret, encryptSecret } from "../src/crypto.js";
import { ProvisionError, relaycastProvisioner, type RelaycastProvisioner } from "../src/identity/bootstrap.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore, RelaycastBindingUnavailableError } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

const KEYRING = { active: { id: "lazy-binding", key: Buffer.alloc(32, 23) } };

async function fixture(t: test.TestContext, provisioner: RelaycastProvisioner | null) {
  const database = new PGliteDatabase();
  t.after(() => database.close());
  await migrate(database);
  const store = new ControlPlaneStore(database, KEYRING, 0, { relaycastProvisioner: provisioner });
  const organization = await store.createOrganization({
    name: "Imported Cloud",
    ownerEmail: "owner@lazy.test",
    ownerName: "Owner",
  });
  const workspaceId = "00000000-0000-4000-8000-000000000064";
  await database.query(
    "INSERT INTO workspaces (id, organization_id, name) VALUES ($1, $2, 'Imported workspace')",
    [workspaceId, organization.id],
  );
  return { database, store, organization, workspaceId };
}

test("an unbound workspace is readable without Relaycast and binds once on concurrent first use", async (t) => {
  const created: string[] = [];
  const provisioner: RelaycastProvisioner = {
    async create() {
      const id = `rw_lazy_${created.length + 1}`;
      created.push(id);
      return { id, apiKey: `rk_lazy_${created.length}` };
    },
    async remove() {},
  };
  const { database, store, organization, workspaceId } = await fixture(t, provisioner);

  // Listing and membership discovery do not need a Relaycast credential and
  // preserve the imported NULL binding until a Relaycast-capable path uses it.
  assert.deepEqual((await store.memberWorkspaces(organization.owner.id)).map(({ id }) => id), [workspaceId]);
  assert.equal((await store.workspaceMembershipForUser(workspaceId, organization.owner.id))?.name, "Imported workspace");
  const listed = await store.listWorkspaces(organization.id);
  assert.equal(listed[0]!.relaycastWorkspaceId, null);
  assert.equal(created.length, 0);

  const [first, second] = await Promise.all([
    store.workspaceForUser(workspaceId, organization.owner.id),
    store.relaycastBinding(workspaceId),
  ]);
  assert.equal(created.length, 1);
  assert.equal(first!.relaycastWorkspaceId, "rw_lazy_1");
  assert.equal(first!.relaycastApiKey, "rk_lazy_1");
  assert.equal(second!.relaycastWorkspaceId, "rw_lazy_1");
  assert.equal(second!.relaycastApiKey, "rk_lazy_1");
  assert.equal(Number(first!.relaycastProvisioned) + Number(second!.provisioned), 1);

  const stored = (await database.query<{
    relaycast_workspace_id: string;
    relaycast_api_key_ciphertext: string;
  }>(
    "SELECT relaycast_workspace_id, relaycast_api_key_ciphertext FROM workspaces WHERE id = $1",
    [workspaceId],
  )).rows[0]!;
  assert.equal(stored.relaycast_workspace_id, "rw_lazy_1");
  assert.notEqual(stored.relaycast_api_key_ciphertext, "rk_lazy_1");
  assert.equal(decryptSecret(stored.relaycast_api_key_ciphertext, KEYRING), "rk_lazy_1");
});

test("an existing binding is returned unchanged and never reprovisioned", async (t) => {
  let creates = 0;
  const provisioner: RelaycastProvisioner = {
    async create() {
      creates += 1;
      throw new Error("must not provision an existing binding");
    },
    async remove() {},
  };
  const { database, store, organization, workspaceId } = await fixture(t, provisioner);
  await database.query(
    `UPDATE workspaces
        SET relaycast_workspace_id = 'rw_existing', relaycast_api_key_ciphertext = $2
      WHERE id = $1`,
    [workspaceId, encryptSecret("rk_existing", KEYRING.active)],
  );

  const workspace = await store.workspaceForUser(workspaceId, organization.owner.id);
  assert.equal(creates, 0);
  assert.equal(workspace!.relaycastWorkspaceId, "rw_existing");
  assert.equal(workspace!.relaycastApiKey, "rk_existing");
  assert.equal(workspace!.relaycastProvisioned, false);
});

test("a concurrent waiter gets retryable not-ready without holding a transaction open", async (t) => {
  let releaseCreate!: () => void;
  let enteredCreate!: () => void;
  const entered = new Promise<void>((resolve) => { enteredCreate = resolve; });
  const release = new Promise<void>((resolve) => { releaseCreate = resolve; });
  const idempotencyKeys: Array<string | undefined> = [];
  const provisioner: RelaycastProvisioner = {
    async create(_name, idempotencyKey) {
      idempotencyKeys.push(idempotencyKey);
      enteredCreate();
      await release;
      return { id: "rw_waiter", apiKey: "rk_waiter" };
    },
    async remove() {},
  };
  const { database, store, organization, workspaceId } = await fixture(t, provisioner);
  const first = store.workspaceForUser(workspaceId, organization.owner.id);
  await entered;

  await assert.rejects(store.relaycastBinding(workspaceId), (error: unknown) => {
    assert(error instanceof RelaycastBindingUnavailableError);
    assert.equal(error.retryAfterSeconds, 5);
    return true;
  });
  releaseCreate();
  assert.equal((await first)!.relaycastWorkspaceId, "rw_waiter");
  assert.deepEqual(idempotencyKeys, [`relay-control-${workspaceId}`]);
  const claim = (await database.query<{
    relaycast_binding_claim_id: string | null;
    relaycast_binding_claimed_at: Date | null;
  }>("SELECT relaycast_binding_claim_id, relaycast_binding_claimed_at FROM workspaces WHERE id = $1", [workspaceId])).rows[0]!;
  assert.deepEqual(claim, { relaycast_binding_claim_id: null, relaycast_binding_claimed_at: null });
});

test("a stale durable claim is reclaimed with the stable workspace idempotency key", async (t) => {
  const keys: Array<string | undefined> = [];
  const provisioner: RelaycastProvisioner = {
    async create(_name, idempotencyKey) {
      keys.push(idempotencyKey);
      return { id: "rw_reconciled", apiKey: "rk_reconciled" };
    },
    async remove() {},
  };
  const { database, store, workspaceId } = await fixture(t, provisioner);
  await database.query(
    `UPDATE workspaces
        SET relaycast_binding_claim_id = '00000000-0000-4000-8000-000000000001',
            relaycast_binding_claimed_at = now() - interval '10 minutes',
            relaycast_binding_claim_name = name
      WHERE id = $1`,
    [workspaceId],
  );
  assert.equal((await store.relaycastBinding(workspaceId))!.relaycastWorkspaceId, "rw_reconciled");
  assert.deepEqual(keys, [`relay-control-${workspaceId}`]);
});

test("an explicit operator pair installs directly on an unbound row without provisioning an orphan", async (t) => {
  let creates = 0;
  const provisioner: RelaycastProvisioner = {
    async create() {
      creates += 1;
      return { id: "rw_orphan", apiKey: "rk_orphan" };
    },
    async remove() {},
  };
  const { store, organization, workspaceId } = await fixture(t, provisioner);
  const updated = await store.updateWorkspace({
    organizationId: organization.id,
    workspaceId,
    name: "Operator bound",
    relaycastWorkspaceId: "rw_operator",
    relaycastApiKey: "rk_operator",
  });
  assert.equal(creates, 0);
  assert.equal(updated!.relaycastWorkspaceId, "rw_operator");
  assert.equal((await store.relaycastBinding(workspaceId))!.relaycastApiKey, "rk_operator");
});

test("an explicit operator pair wins an in-flight create and the unused remote is removed", async (t) => {
  let enteredCreate!: () => void;
  let releaseCreate!: () => void;
  const entered = new Promise<void>((resolve) => { enteredCreate = resolve; });
  const release = new Promise<void>((resolve) => { releaseCreate = resolve; });
  const removed: string[] = [];
  const provisioner: RelaycastProvisioner = {
    async create() {
      enteredCreate();
      await release;
      return { id: "rw_lost_create", apiKey: "rk_lost_create" };
    },
    async remove(id) { removed.push(id); },
  };
  const { store, organization, workspaceId } = await fixture(t, provisioner);
  const lazy = store.relaycastBinding(workspaceId);
  await entered;
  await store.updateWorkspace({
    organizationId: organization.id,
    workspaceId,
    relaycastWorkspaceId: "rw_operator_wins",
    relaycastApiKey: "rk_operator_wins",
  });
  releaseCreate();
  assert.equal((await lazy)!.relaycastWorkspaceId, "rw_operator_wins");
  assert.deepEqual(removed, ["rw_lost_create"]);
});

test("a lost create response retains its durable claim and reconciles with the same key", async (t) => {
  let attempt = 0;
  const keys: Array<string | undefined> = [];
  const names: string[] = [];
  const provisioner: RelaycastProvisioner = {
    async create(name, idempotencyKey) {
      attempt += 1;
      keys.push(idempotencyKey);
      names.push(name);
      if (attempt === 1) throw new ProvisionError("Relaycast is unreachable", true, true);
      return { id: "rw_after_lost_response", apiKey: "rk_after_lost_response" };
    },
    async remove() {},
  };
  const { database, store, workspaceId } = await fixture(t, provisioner);
  await assert.rejects(store.relaycastBinding(workspaceId), RelaycastBindingUnavailableError);
  const retained = (await database.query<{ relaycast_binding_claim_id: string | null }>(
    "SELECT relaycast_binding_claim_id FROM workspaces WHERE id = $1", [workspaceId],
  )).rows[0]!;
  assert(retained.relaycast_binding_claim_id);
  await assert.rejects(store.relaycastBinding(workspaceId), RelaycastBindingUnavailableError);
  assert.equal(attempt, 1, "a fresh claim prevents an immediate duplicate create");
  await database.query(
    `UPDATE workspaces
        SET name = 'Renamed after uncertain create',
            relaycast_binding_claimed_at = now() - interval '10 minutes'
      WHERE id = $1`,
    [workspaceId],
  );
  assert.equal((await store.relaycastBinding(workspaceId))!.relaycastWorkspaceId, "rw_after_lost_response");
  assert.deepEqual(keys, [`relay-control-${workspaceId}`, `relay-control-${workspaceId}`]);
  assert.deepEqual(names, ["Imported workspace", "Imported workspace"], "the retried request digest is stable across a rename");
});

test("the Relaycast client forwards create idempotency and surfaces cleanup failures", async () => {
  let createHeaders: HeadersInit | undefined;
  const provisioner = relaycastProvisioner("https://relaycast.test", "internal-secret", async (_input, init) => {
    if (init?.method === "POST") {
      createHeaders = init.headers;
      return new Response(JSON.stringify({ data: { workspace_id: "rw_http", api_key: "rk_http" } }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(null, { status: 503 });
  });
  assert.deepEqual(await provisioner.create("Imported workspace", "relay-control-stable-key"), {
    id: "rw_http",
    apiKey: "rk_http",
  });
  assert.equal(new Headers(createHeaders).get("idempotency-key"), "relay-control-stable-key");
  await assert.rejects(provisioner.remove("rw_http"), (error: unknown) => {
    assert(error instanceof ProvisionError);
    assert.equal(error.outcomeUnknown, true);
    return true;
  });
});

test("GET /resolve lazily binds once and reports only the creating response as provisioned", async (t) => {
  let creates = 0;
  const provisioner: RelaycastProvisioner = {
    async create() {
      creates += 1;
      return { id: "rw_resolved", apiKey: "rk_resolved" };
    },
    async remove() {},
  };
  const { database, store, organization, workspaceId } = await fixture(t, provisioner);
  const tokens = await database.transaction((tx) => store.issueBrowserSession(tx, {
    userId: organization.owner.id,
    organizationId: organization.id,
    workspaceId,
    label: "resolve test",
  }));
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: "https://control.lazy.test",
    relaycastUrl: "http://relaycast.internal",
    relaycastPublicUrl: "https://relay.lazy.test",
    relayhistoryUrl: "",
    relayhistoryPublicUrl: "",
    sessionReadApi: { url: "http://history.internal", publicUrl: "https://history.lazy.test", secret: "test-secret" },
    bootstrapToken: "bootstrap-token-that-is-at-least-32-bytes",
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: "https://control.lazy.test/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.lazy.test/",
    imageVersion: "lazy-test",
    port: 3000,
    host: "127.0.0.1",
  };
  const server = createServer(createApp({ config, store }));
  t.after(() => close(server));
  const origin = await listen(server);

  const first = await request(origin, `/api/v1/workspaces/${workspaceId}/resolve`, { token: tokens.accessToken });
  assert.equal(first.status, 200);
  assert.equal(first.body.relaycastWorkspaceId, "rw_resolved");
  assert.equal(first.body.relaycastApiKey, "rk_resolved");
  assert.equal(first.body.provisioned, true);

  const second = await request(origin, `/api/v1/workspaces/${workspaceId}/resolve`, { token: tokens.accessToken });
  assert.equal(second.status, 200);
  assert.equal(second.body.relaycastWorkspaceId, "rw_resolved");
  assert.equal(second.body.provisioned, false);
  assert.equal(creates, 1);
});

test("an unbound first use fails closed without a provisioner and leaves both columns NULL", async (t) => {
  const { database, store, organization, workspaceId } = await fixture(t, null);
  await assert.rejects(
    store.workspaceForUser(workspaceId, organization.owner.id),
    RelaycastBindingUnavailableError,
  );
  const row = (await database.query<{
    relaycast_workspace_id: string | null;
    relaycast_api_key_ciphertext: string | null;
  }>("SELECT relaycast_workspace_id, relaycast_api_key_ciphertext FROM workspaces WHERE id = $1", [workspaceId])).rows[0]!;
  assert.deepEqual(row, { relaycast_workspace_id: null, relaycast_api_key_ciphertext: null });
});

test("migration 0064 permits only complete or empty Relaycast binding pairs", async (t) => {
  const { database, organization } = await fixture(t, null);
  await assert.rejects(
    database.query(
      `INSERT INTO workspaces
         (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
       VALUES ('00000000-0000-4000-8000-000000000065', $1, 'Half bound', 'rw_half', NULL)`,
      [organization.id],
    ),
    /workspaces_relaycast_binding_pair/,
  );
  await assert.rejects(
    database.query(
      `UPDATE workspaces
          SET relaycast_binding_claim_id = '00000000-0000-4000-8000-000000000066',
              relaycast_binding_claim_name = 'half claim'
        WHERE id = '00000000-0000-4000-8000-000000000064'`,
    ),
    /workspaces_relaycast_binding_claim_pair/,
  );
});
