import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { copyFile, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hashSecret } from "../src/crypto.js";
import { defaultMigrationsDirectory, migrate } from "../src/migrations.js";
import { createMcpOAuthProtocol, pkceS256, type AuthorizationRequest } from "../src/mcp/oauth/protocol.js";
import { McpOAuthStore, McpOAuthAgentNameTakenError, McpOAuthContinuationError } from "../src/mcp/oauth/store.js";
import { MCP_OAUTH_CLIENT_TTL_MS, McpOAuthTeardown, pruneMcpOAuthClients } from "../src/mcp/oauth/teardown.js";
import type { RelaycastClient } from "../src/messaging/relaycast.js";
import { PGliteDatabase } from "./support/harness.js";

const ORIGIN = "https://relay.example.test";
const SHARED = "/api/v1/mcp/shared-sessions";
const EVENTS = "/api/v1/mcp/relay-events";
const NOW = new Date("2026-01-01T00:00:00Z");

async function fixture(t: test.TestContext, mode: "single" | "multi" = "multi") {
  const database = new PGliteDatabase();
  t.after(() => database.close());
  await migrate(database);
  const userId = randomUUID(), organizationId = randomUUID(), workspaceId = randomUUID();
  await database.query("INSERT INTO selfhost_users(id,email,name) VALUES ($1,'fake@example.test','Fake User')", [userId]);
  async function tenant() {
    const organizationId = randomUUID(), workspaceId = randomUUID();
    await addTenant(organizationId, workspaceId);
    return { organizationId, workspaceId, userId, agentName: "fake-agent" };
  }
  async function addTenant(org: string, workspace: string) {
    await database.query("INSERT INTO selfhost_organizations(id,name) VALUES ($1,'Fake Organization')", [org]);
    await database.query("INSERT INTO selfhost_organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')", [org,userId]);
    await database.query(`INSERT INTO selfhost_workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
      VALUES ($1,$2,'Fake Workspace',$3,'fake-envelope')`, [workspace,org,`fake-relay-${workspace}`]);
  }
  await addTenant(organizationId, workspaceId);
  const owner = { userId, organizationId, workspaceId, agentName: "fake-agent" };
  const protocol = createMcpOAuthProtocol({ publicOrigin: ORIGIN, enabledResources: [SHARED,EVENTS] });
  const store = new McpOAuthStore(database, { protocol, tenancyMode: mode, now: () => new Date(NOW),
    isGrokRoutine: request => request.resourcePath === EVENTS && new URL(request.redirectUri).hostname === "x.ai" });
  const client = await store.registerMcpOAuthClient({ clientName: "fake-client", redirectUris: ["https://client.example.test/cb","https://x.ai/callback"] });
  function authorization(overrides: Record<string,string> = {}): AuthorizationRequest {
    const result = protocol.validateAuthorizationRequest({ client_id: client.clientId, response_type: "code",
      redirect_uri: client.redirectUris[0]!, code_challenge: pkceS256("fake-verifier"), code_challenge_method: "S256",
      resource: `${ORIGIN}/cloud${SHARED}`, ...overrides }, client);
    assert.ok(result.ok);
    return result.value;
  }
  async function grant(request = authorization(), context = owner) {
    const id = randomUUID();
    await database.query(`INSERT INTO selfhost_mcp_oauth_grants
      (id,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,token_family_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [id,request.clientId,context.userId,context.organizationId,context.workspaceId,context.agentName,
      request.scopes,request.resource,randomUUID()]);
    return id;
  }
  async function codeCount() {
    return (await database.query<{ count: number }>("SELECT count(*)::int AS count FROM selfhost_mcp_oauth_authorization_codes")).rows[0]!.count;
  }
  return { database,store,protocol,owner,client,tenant,authorization,grant,codeCount };
}

test("OAuth clients/codes retain source IDs, exact redirect arrays, one-way code and 120s expiry", async t => {
  const f = await fixture(t);
  assert.match(f.client.clientId, /^mcpc_[A-Za-z0-9_-]{24}$/);
  assert.deepEqual(await f.store.getMcpOAuthClient(f.client.clientId), f.client);
  assert.equal(await f.store.getMcpOAuthClient("x".repeat(129)), null);
  const request = f.authorization();
  const code = await f.store.createMcpOAuthAuthorizationCode(request, f.owner);
  const row = (await f.database.query("SELECT * FROM selfhost_mcp_oauth_authorization_codes")).rows[0]!;
  assert.match(code, /^mcpac_[A-Za-z0-9_-]{43}$/);
  assert.equal(row.code_hash, hashSecret(code));
  assert.ok(!JSON.stringify(row).includes(code));
  assert.equal(new Date(row.expires_at as string).getTime() - new Date(row.created_at as string).getTime(), 120_000);
  assert.equal(row.organization_id, f.owner.organizationId);
  assert.equal(row.workspace_id, f.owner.workspaceId);
  assert.equal(row.redirect_uri, request.redirectUri);
  assert.equal(row.code_challenge, request.codeChallenge);
  assert.deepEqual(row.scopes, ["relay:mcp"]);
  assert.equal((await f.database.query("SELECT id FROM selfhost_token_sessions")).rows.length, 0);
});

test("unused registered clients are pruned after a day while clients with a grant or code are kept", async t => {
  const f = await fixture(t);
  const register = async (name: string, at: Date) => {
    const client = await f.store.registerMcpOAuthClient({ clientName: name, redirectUris: ["https://client.example.test/cb"] });
    await f.database.query("UPDATE selfhost_mcp_oauth_clients SET created_at=$2 WHERE client_id=$1", [client.clientId, at]);
    return client.clientId;
  };
  const old = new Date(NOW.getTime() - MCP_OAUTH_CLIENT_TTL_MS - 1000), recent = new Date(NOW.getTime() - 60_000);
  const unused = await register("fake-unused", old), fresh = await register("fake-fresh", recent);
  const granted = await register("fake-granted", old), coded = await register("fake-coded", old);
  await f.grant({ ...f.authorization(), clientId: granted });
  await f.store.createMcpOAuthAuthorizationCode({ ...f.authorization(), clientId: coded }, f.owner);
  const extra = await Promise.all(Array.from({ length: 3 }, (_, index) => register("fake-extra-" + index, old)));
  const cutoff = new Date(NOW.getTime() - MCP_OAUTH_CLIENT_TTL_MS);
  assert.equal(await pruneMcpOAuthClients(f.database, cutoff, 2), 2);
  assert.equal(await pruneMcpOAuthClients(f.database, cutoff), 2);
  assert.equal(await pruneMcpOAuthClients(f.database, cutoff), 0);
  const left = (await f.database.query<{ client_id: string }>("SELECT client_id FROM selfhost_mcp_oauth_clients")).rows.map(row => row.client_id);
  for (const id of [unused, ...extra]) assert.equal(left.includes(id), false);
  for (const id of [fresh, granted, coded]) assert.equal(left.includes(id), true);
  // The teardown pass runs the prune on its own clock.
  const doomed = await register("fake-doomed", old);
  const relaycast = {} as RelaycastClient;
  const worker = new McpOAuthTeardown({ database: f.database, keyring: { active: { id: "fake-key", key: Buffer.alloc(32, 7) } },
    client: relaycast, now: () => new Date(NOW) });
  t.after(() => worker.stop());
  assert.deepEqual(await worker.drain(), { completed: 0, kept: 0, pending: 0 });
  assert.equal((await f.database.query("SELECT 1 FROM selfhost_mcp_oauth_clients WHERE client_id=$1", [doomed])).rows.length, 0);
  assert.equal((await f.database.query("SELECT 1 FROM selfhost_mcp_oauth_clients WHERE client_id=$1", [fresh])).rows.length, 1);
});

test("one user in two organizations gets explicitly bound codes; mismatched workspace/org is refused", async t => {
  const f = await fixture(t);
  const other = await f.tenant();
  await f.store.createMcpOAuthAuthorizationCode(f.authorization(), other);
  const row = (await f.database.query("SELECT * FROM selfhost_mcp_oauth_authorization_codes")).rows[0]!;
  assert.equal(row.organization_id, other.organizationId);
  assert.equal(row.workspace_id, other.workspaceId);
  await assert.rejects(f.store.createMcpOAuthAuthorizationCode(f.authorization(), { ...f.owner, workspaceId: other.workspaceId }), McpOAuthContinuationError);
  assert.equal(await f.codeCount(), 1);
});

test("single-mode request gate fails closed over a database with multiple organizations", async t => {
  const f = await fixture(t,"single");
  await f.store.createMcpOAuthAuthorizationCode(f.authorization(), f.owner);
  await f.tenant();
  await assert.rejects(f.store.createMcpOAuthAuthorizationCode(f.authorization(), f.owner), McpOAuthContinuationError);
  assert.equal(await f.codeCount(), 1);
});

test("revoked live membership refuses code issuance and hides connection names without deleting lineage", async t => {
  const f = await fixture(t);
  await f.grant();
  assert.deepEqual(await f.store.listConnectedAgentNames(f.owner), [{ workspaceId: f.owner.workspaceId, agentName: "fake-agent" }]);
  await f.database.query("DELETE FROM selfhost_organization_memberships WHERE organization_id=$1 AND user_id=$2", [f.owner.organizationId,f.owner.userId]);
  await assert.rejects(f.store.createMcpOAuthAuthorizationCode(f.authorization(), f.owner), McpOAuthContinuationError);
  assert.deepEqual(await f.store.listConnectedAgentNames(f.owner), []);
  assert.equal((await f.database.query("SELECT id FROM selfhost_mcp_oauth_grants")).rows.length, 1);
  assert.equal(await f.codeCount(), 0);
});

test("Events continuation must select the exact live owner/client/resource and retain prior scopes", async t => {
  const f = await fixture(t);
  const request = f.authorization({ resource: `${ORIGIN}/cloud${EVENTS}`, scope: "relay:events relay:mcp relay:agents" });
  const id = await f.grant(request);
  await assert.rejects(f.store.createMcpOAuthAuthorizationCode(request,f.owner), McpOAuthContinuationError);
  await assert.rejects(f.store.createMcpOAuthAuthorizationCode(request,f.owner,randomUUID()), McpOAuthContinuationError);
  await f.store.createMcpOAuthAuthorizationCode(request,f.owner,id);
  const row = (await f.database.query("SELECT grant_id FROM selfhost_mcp_oauth_authorization_codes")).rows[0]!;
  assert.equal(row.grant_id,id);
  const narrowed = f.authorization({ resource: `${ORIGIN}/cloud${EVENTS}`, scope: "relay:events", redirect_uri: "https://x.ai/callback" });
  await assert.rejects(f.store.createMcpOAuthAuthorizationCode(narrowed,f.owner,id), McpOAuthContinuationError);
  const other = await f.tenant();
  await assert.rejects(f.store.createMcpOAuthAuthorizationCode(request,other,id), McpOAuthContinuationError);
  const otherClient = await f.store.registerMcpOAuthClient({ clientName: "fake-other-client", redirectUris: f.client.redirectUris });
  await assert.rejects(f.store.createMcpOAuthAuthorizationCode({ ...request, clientId: otherClient.clientId },f.owner,id), McpOAuthContinuationError);
  await assert.rejects(f.store.createMcpOAuthAuthorizationCode(f.authorization(),f.owner,id), McpOAuthContinuationError);
  await f.database.query("UPDATE selfhost_mcp_oauth_grants SET revoked_at=now() WHERE id=$1", [id]);
  await assert.rejects(f.store.createMcpOAuthAuthorizationCode(request,f.owner,id), McpOAuthContinuationError);
  assert.equal(await f.codeCount(), 1);
});

test("Grok name check runs inside the owner transaction and returns a typed409; explicit continuation keeps identity", async t => {
  const f = await fixture(t);
  const request = f.authorization({ resource: `${ORIGIN}/cloud${EVENTS}`, scope: "relay:events", redirect_uri: "https://x.ai/callback" });
  const id = await f.grant(request);
  await assert.rejects(f.store.createMcpOAuthAuthorizationCode(request,f.owner), (error: unknown) =>
    error instanceof McpOAuthAgentNameTakenError && error.status === 409 && error.code === "agent_name_taken");
  assert.equal(await f.codeCount(), 0);
  await f.store.createMcpOAuthAuthorizationCode(request,f.owner,id);
  assert.equal(await f.codeCount(), 1);
});

test("tenant composite foreign keys and scope constraints reject malformed stored authority", async t => {
  const f = await fixture(t);
  const other = await f.tenant();
  await assert.rejects(f.grant(f.authorization(), { ...f.owner, workspaceId: other.workspaceId }), /foreign key/);
  const invalid = { ...f.authorization(), scopes: ["relay:mcp","account"] } as unknown as AuthorizationRequest;
  await assert.rejects(f.store.createMcpOAuthAuthorizationCode(invalid,f.owner), /check constraint/);
  assert.equal(await f.codeCount(), 0);
});

test("OAuth migrations upgrade an existing database idempotently", async t => {
  const directory = await mkdtemp(join(tmpdir(),"mcp-oauth-upgrade-"));
  t.after(() => rm(directory,{ recursive: true, force: true }));
  const database = new PGliteDatabase();
  t.after(() => database.close());
  const source = defaultMigrationsDirectory();
  const oauthMigrations=new Set(["0015_mcp_oauth.sql","0028_mcp_oauth_sessions.sql","0030_mcp_oauth_revocations.sql","0032_mcp_oauth_revocation_attempts.sql"]);
  for (const name of await readdir(source)) if (name.endsWith(".sql") && !oauthMigrations.has(name)) await copyFile(join(source,name),join(directory,name));
  await migrate(database,directory);
  assert.deepEqual(await migrate(database),[...oauthMigrations]);
  assert.deepEqual(await migrate(database),[]);
});

test("0028/0030/0032 apply after the OAuth foundation without changing its checksum",async t=>{
  const directory=await mkdtemp(join(tmpdir(),"mcp-oauth-foundation-upgrade-"));
  t.after(()=>rm(directory,{ recursive:true,force:true }));
  const database=new PGliteDatabase(); t.after(()=>database.close());
  const source=defaultMigrationsDirectory();
  const later=["0028_mcp_oauth_sessions.sql","0030_mcp_oauth_revocations.sql","0032_mcp_oauth_revocation_attempts.sql"];
  for(const name of await readdir(source)) if(name.endsWith(".sql") && !later.includes(name)) {
    await copyFile(join(source,name),join(directory,name));
  }
  await migrate(database,directory);
  const before=(await database.query<{ checksum:string }>("SELECT checksum FROM selfhost_schema_migrations WHERE name='0015_mcp_oauth.sql'")).rows[0]!.checksum;
  assert.deepEqual(await migrate(database),later);
  const after=(await database.query<{ checksum:string }>("SELECT checksum FROM selfhost_schema_migrations WHERE name='0015_mcp_oauth.sql'")).rows[0]!.checksum;
  assert.equal(after,before);
  assert.deepEqual(await migrate(database),[]);
});
