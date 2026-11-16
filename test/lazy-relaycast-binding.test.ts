import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { decryptSecret, encryptSecret } from "../src/crypto.js";
import type { RelaycastProvisioner } from "../src/identity/bootstrap.js";
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
});
