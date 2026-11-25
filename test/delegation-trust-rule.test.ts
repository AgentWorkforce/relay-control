import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import { encryptSecret } from "../src/crypto.js";
import { delegateStillBound, grantFitsPolicy, type DelegationDeps, type GrantRow } from "../src/delegation/service.js";
import {
  launcherName, MAX_TRUST_DEPTH, resolveTrustPath, trustRelation, trustRelationAllowed, type TrustPath, type TrustReader,
} from "../src/delegation/trust.js";
import { backfillConnectorRoots } from "../src/delegation/trust-backfill.js";
import { copilotDesktopSetup } from "./support/copilot-desktop.js";
import { request } from "./support/harness.js";

const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const INTERNAL = "internal-service-token-".padEnd(48, "x");
const sha = (value: string) => createHash("sha256").update(value).digest("hex");
const MERGE = [{ class: "merge", target: "AgentWorkforce/relay#2250" }];

async function setup(t: TestContext) {
  const env = await copilotDesktopSetup(t, {}, undefined,
    { delegationSigning: { kid: "dlg-test", seed: randomBytes(32), previous: [] }, internalServiceToken: INTERNAL });
  const desktop = await env.desktopSignIn({ hostName: "owner-box" });
  const base = `/api/v1/workspaces/${env.workspaceId}`;
  const browser = (path: string, method: string, body?: unknown, cookie = desktop.session) =>
    request(env.origin, `/cloud${base}${path}`, { method, cookie, ...(method === "GET" ? {} : { body: body ?? {} }),
      headers: { origin: env.origin } });
  const bearer = (path: string, method = "GET", body?: unknown, token = desktop.accessToken) =>
    request(env.origin, `${base}${path}`, { method, token, ...(body === undefined ? {} : { body }) });
  const enable = async (body: Record<string, unknown> = {}) =>
    assert.equal((await browser("/delegates/policy", "PUT", { delegation_enabled: true, ...body })).status, 200);
  async function desktopIdentity(name: string, userId = env.ownerId) {
    const agent = env.world.addAgent(name);
    await env.database.query(
      `INSERT INTO desktop_relay_identities
         (id, workspace_id, organization_id, user_id, relaycast_workspace_id, source_id, agent_name, agent_remote_id, address, token_ciphertext)
       VALUES ($1, $2, $3, $4, 'rw_primary', $5, $6, $7, $8, $9)`,
      [randomUUID(), env.workspaceId, env.orgId, userId, randomUUID(), name, agent.id, `${name}@cloud-${agent.id}`,
        encryptSecret(agent.token, KEYRING.active)]);
    return agent;
  }
  async function claim(name: string) {
    const agent = env.world.addAgent(name);
    const started = await browser("/delegates/claims", "POST");
    assert.equal(started.status, 201, started.raw);
    const done = await request(env.origin, `${base}/delegates/claims/complete`, {
      method: "POST", body: { code: started.body.code, agent_id: agent.id, agent_token: agent.token } });
    assert.equal(done.status, 200, done.raw);
    return { ...agent, claimId: started.body.claim_id as string };
  }
  /** An assistant the owner connected through MCP OAuth: a live grant pinned to its id, and the owner's hosted participant. */
  async function connector(name: string, options: { userId?: string; redirect?: string; participantAt?: string;
    grantAt?: string; pinned?: boolean } = {}) {
    const userId = options.userId ?? env.ownerId;
    const agent = env.world.addAgent(name, { source: "cloud-hosted-mcp", owner_hash: sha(userId), cloud_workspace_id: env.workspaceId });
    const clientId = `client-${randomUUID()}`;
    const grantId = randomUUID();
    const family = randomUUID();
    await env.database.query("INSERT INTO mcp_oauth_clients (client_id, client_name, redirect_uris) VALUES ($1, 'ChatGPT', $2)",
      [clientId, [options.redirect ?? "https://chatgpt.com/connector_platform_oauth_redirect"]]);
    await env.database.query(
      `INSERT INTO mcp_oauth_grants (id, client_id, client_name, user_id, organization_id, workspace_id, agent_name, agent_remote_id,
         scopes, resource, token_family_id, created_at)
       VALUES ($1, $2, 'ChatGPT', $3, $4, $5, $6, $7, ARRAY['relay:mcp'], 'https://control.test/mcp', $8, COALESCE($9::timestamptz, now()))`,
      [grantId, clientId, userId, env.orgId, env.workspaceId, name, options.pinned === false ? null : agent.id, family,
        options.grantAt ?? null]);
    await env.database.query(
      `INSERT INTO mcp_oauth_sessions (id, grant_id, token_family_id, user_id, organization_id, workspace_id, scopes,
         access_token_hash, refresh_token_hash, access_token_expires_at, refresh_token_expires_at, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, ARRAY['relay:mcp'], $7, $8, now() + interval '1 hour', now() + interval '30 days', now(), now())`,
      [randomUUID(), grantId, family, userId, env.orgId, env.workspaceId, sha(randomUUID()), sha(randomUUID())]);
    await env.database.query(
      `INSERT INTO hosted_relay_participants (id, workspace_id, user_id, relaycast_workspace_id, agent_name, agent_remote_id,
         token_ciphertext, created_at)
       VALUES ($1, $2, $3, 'rw_primary', $4, $5, $6, COALESCE($7::timestamptz, now()))`,
      [randomUUID(), env.workspaceId, userId, name, agent.id, encryptSecret(agent.token, KEYRING.active), options.participantAt ?? null]);
    return { ...agent, grantId };
  }
  /** A Control launch by `actorId` of the owner (or `userId`), journaled in relay_spawns. */
  async function spawn(actorId: string, name: string, state = "ready", userId = env.ownerId) {
    const agent = env.world.addAgent(name);
    const id = randomUUID();
    await env.database.query(
      `INSERT INTO relay_spawns (id, workspace_id, user_id, authority_hash, relaycast_workspace_id, actor_id, idempotency_hash,
         request_hash, agent_name, cli, node_id, state, worker_id, worker_address, audit)
       VALUES ($1, $2, $3, $4, 'rw_primary', $5, $6, $7, $8, 'claude', 'node-1', $9, $10, $11, '[]'::jsonb)`,
      [id, env.workspaceId, userId, sha(id), actorId, sha(`i${id}`), sha(`r${id}`), name, state, agent.id, `${name}@node-1`]);
    return { ...agent, spawnId: id };
  }
  const send = (from: { name: string }, to: { name: string }, actions: unknown = MERGE, options: { createdAt?: string } = {}) =>
    env.world.sendApprovalAs(from.name, to.name, "ok", { v: 1, owner_id: env.ownerId, actions, quote: "ship it" }, options).message.id;
  const attest = (recipient: { id: string; token: string }, messageId: string, token = desktop.accessToken) =>
    request(env.origin, `${base}/messaging/delegation`, { method: "POST", token,
      body: { recipient_agent_id: recipient.id, recipient_token: recipient.token, message_id: messageId } });
  const redeem = (recipient: { id: string; token: string }, approvalId: string, action: unknown) =>
    request(env.origin, `${base}/messaging/delegation/redeem`, { method: "POST", token: desktop.accessToken,
      body: { recipient_agent_id: recipient.id, recipient_token: recipient.token, approval_id: approvalId, action } });
  const verdict = async (recipient: { id: string; token: string }, messageId: string) => {
    const result = await attest(recipient, messageId);
    assert.equal(result.status, 200, result.raw);
    return result.body as { verdict: string; reason?: string; claims?: Record<string, any> };
  };
  const grants = async (agentId: string) => (await env.database.query<GrantRow & { created_auth_method: string }>(
    "SELECT * FROM delegation_grants WHERE delegate_agent_id = $1 ORDER BY created_at, id", [agentId])).rows;
  const events = async (event: string) => (await env.database.query<{ reason: string | null; data: Record<string, any>;
    actor_user_id: string | null; auth_method: string | null; grant_id: string | null }>(
    "SELECT reason, data, actor_user_id, auth_method, grant_id FROM delegation_audit_events WHERE event = $1 ORDER BY id", [event])).rows;
  return { ...env, desktop, base, browser, bearer, enable, desktopIdentity, claim, connector, spawn, send, attest, redeem,
    verdict, grants, events };
}

/** Delegation on, the owner's coding agent (recipient), and a claimed assistant with no grant. */
async function ready(t: TestContext) {
  const env = await setup(t);
  await env.enable();
  const recipient = await env.desktopIdentity("relay-coder");
  const bot = await env.claim("assistant");
  return { env, recipient, bot };
}

async function turnOn(env: Awaited<ReturnType<typeof setup>>, body: Record<string, unknown> = {}) {
  const put = await env.browser("/delegates/trust-rule", "PUT", body);
  assert.ok([200, 201].includes(put.status), put.raw);
  return put.body.rule as { trust_rule_id: string; require_tier_o: string[] };
}

// ---------------------------------------------------------------------------
// The chain walk and the relation predicate

/** An in-memory TrustReader: tests name the rows. */
function fakeReader(rows: Partial<{ [K in keyof TrustReader]: (agentId: string) => Awaited<ReturnType<TrustReader[K]>> }>): TrustReader {
  return {
    claims: async (_w, _r, id) => rows.claims?.(id) ?? [],
    connectors: async (_w, _r, _o, id) => rows.connectors?.(id) ?? [],
    participants: async (_w, _r, id) => rows.participants?.(id) ?? [],
    spawns: async (_w, _r, id) => rows.spawns?.(id) ?? [],
    otherBindings: async (_w, _r, id) => rows.otherBindings?.(id) ?? 0,
  };
}

test("chain walk: S1 a connector root needs exactly one participant and no claim; S2 proven no earlier than its OAuth grant", async () => {
  const input = { workspaceId: "ws", relaycastWorkspaceId: "rw", ownerUserId: "owner", agentId: "ag_bot" };
  const connectorRow = { grantId: "g1", clientName: "ChatGPT", redirectUris: ["https://chatgpt.com/cb"], participantName: "bot",
    createdAt: new Date("2026-11-01T00:00:00Z"), grantCreatedAt: new Date("2026-11-20T00:00:00Z") };
  const one = await resolveTrustPath(fakeReader({ connectors: () => [connectorRow],
    participants: () => [{ userId: "owner", workspaceId: "ws" }] }), input);
  assert.equal(one?.path.root.kind, "connector");
  assert.equal(one?.path.root.kind === "connector" && one.path.root.connector, "chatgpt");
  // S2: the reconnect (a newer grant) is when coverage starts, not the older participant.
  assert.equal(one?.path.root.created_at, "2026-11-20T00:00:00.000Z");
  // S1: two participants hold the id (two owners, or one owner twice): ambiguous, never decided by row order.
  for (const second of [{ userId: "owner", workspaceId: "ws" }, { userId: "other", workspaceId: "ws" }]) {
    assert.equal(await resolveTrustPath(fakeReader({ connectors: () => [connectorRow],
      participants: () => [{ userId: "owner", workspaceId: "ws" }, second] }), input), null);
  }
  // A claim and a participant for one id: ambiguous too.
  assert.equal(await resolveTrustPath(fakeReader({ connectors: () => [connectorRow],
    participants: () => [{ userId: "owner", workspaceId: "ws" }],
    claims: () => [{ id: "clm_1", ownerUserId: "owner", workspaceId: "ws", completedAt: new Date(), agentName: "bot" }] }), input), null);
  // The owner's internal launcher is never a root.
  assert.equal(await resolveTrustPath(fakeReader({ connectors: () => [{ ...connectorRow, participantName: launcherName("owner") }],
    participants: () => [{ userId: "owner", workspaceId: "ws" }] }), input), null);
  // Another binding (desktop, person identity) makes the agent ambiguous for the rule.
  assert.equal(await resolveTrustPath(fakeReader({ connectors: () => [connectorRow],
    participants: () => [{ userId: "owner", workspaceId: "ws" }], otherBindings: () => 1 }), input), null);
});

test("chain walk: launches are hops; a cycle and a chain deeper than MAX_TRUST_DEPTH are not covered", async () => {
  const spawnRow = (worker: string, actor: string) => ({ id: `s-${worker}`, userId: "owner", workspaceId: "ws", actorId: actor,
    workerId: worker, agentName: worker, state: "ready", createdAt: new Date("2026-11-21T00:00:00Z") });
  const root = { claims: (id: string) => id === "root" ? [{ id: "clm_1", ownerUserId: "owner", workspaceId: "ws",
    completedAt: new Date("2026-11-01T00:00:00Z"), agentName: "root" }] : [] };
  const chain = (length: number) => fakeReader({ ...root, spawns: (id: string) => {
    const n = Number(id.replace("w", ""));
    return id.startsWith("w") ? [spawnRow(id, n === 1 ? "root" : `w${n - 1}`)] : [];
  } });
  const input = (agentId: string) => ({ workspaceId: "ws", relaycastWorkspaceId: "rw", ownerUserId: "owner", agentId });
  const two = await resolveTrustPath(chain(2), input("w2"));
  assert.deepEqual(two?.path.hops.map(hop => hop.worker_id), ["w1", "w2"]);
  assert.equal(two?.name, "w2");
  assert.ok(await resolveTrustPath(chain(MAX_TRUST_DEPTH), input(`w${MAX_TRUST_DEPTH}`)));
  assert.equal(await resolveTrustPath(chain(MAX_TRUST_DEPTH + 1), input(`w${MAX_TRUST_DEPTH + 1}`)), null);
  // A cycle: a launched by b, b launched by a.
  assert.equal(await resolveTrustPath(fakeReader({ spawns: (id: string) => [spawnRow(id, id === "a" ? "b" : "a")] }), input("a")), null);
  // A launch by someone else, or one not ready, is not a hop.
  assert.equal(await resolveTrustPath(fakeReader({ ...root, spawns: id => id === "w1" ? [{ ...spawnRow("w1", "root"), userId: "bob" }] : [] }),
    input("w1")), null);
  assert.equal(await resolveTrustPath(fakeReader({ ...root, spawns: id => id === "w1" ? [{ ...spawnRow("w1", "root"), state: "accepted" }] : [] }),
    input("w1")), null);
});

test("trust relation: one isolated predicate; allow_all (the owner's answer) and down_tree_only", () => {
  const path = (hops: string[]): TrustPath => ({ root: { kind: "claim", claim_id: "c", agent_id: "root", created_at: "2026-11-01T00:00:00Z" },
    hops: hops.map((worker, index) => ({ spawn_id: `s${index}`, actor_id: index ? hops[index - 1]! : "root", worker_id: worker,
      created_at: "2026-11-02T00:00:00Z" })) });
  assert.equal(trustRelation(path(["a"]), "a", path(["a"])), "self");
  assert.equal(trustRelation(path(["a", "b"]), "a", path(["a"])), "descendant");
  assert.equal(trustRelation(path(["a"]), "b", path(["a", "b"])), "ancestor");
  assert.equal(trustRelation(path(["a"]), "c", path(["c"])), "sibling");
  assert.equal(trustRelation(path(["a"]), "x", null), "unrelated");
  const all = ["self", "ancestor", "descendant", "sibling", "unrelated"] as const;
  assert.deepEqual(all.filter(relation => trustRelationAllowed(relation)), all);
  assert.deepEqual(all.filter(relation => trustRelationAllowed(relation, "allow_all")), all);
  assert.deepEqual(all.filter(relation => trustRelationAllowed(relation, "down_tree_only")), ["ancestor", "unrelated"]);
});

test("the 90-day cap exemption is keyed on the rule link, never on the date", () => {
  const policy = { delegation_enabled: true, max_expiry_days: 7, allowed_classes: null, require_tier_o: [], code_owner_match: "any_path" as const };
  const far = { scopes: [], created_at: new Date(), expires_at: new Date("9999-12-31T00:00:00Z") };
  assert.equal(grantFitsPolicy({ ...far, trust_rule_id: null }, policy), false);
  assert.equal(grantFitsPolicy({ ...far, trust_rule_id: "dtr_x" }, policy), true);
});

// ---------------------------------------------------------------------------
// Routes

test("trust-rule routes: people only, idempotent PUT, not while off, admins act on another owner, one-click DELETE", async (t) => {
  const env = await setup(t);
  assert.deepEqual((await env.bearer("/delegates/trust-rule")).body, { rule: null, covered: [], shadowed: [] });
  const off = await env.browser("/delegates/trust-rule", "PUT", {});
  assert.deepEqual([off.status, off.body.code], [403, "not_enabled"]);
  await env.enable();
  const agent = env.world.addAgent("some-agent");
  // An agent's own Relaycast token is never a person.
  assert.equal((await env.bearer("/delegates/trust-rule", "PUT", {}, agent.token)).status, 401);
  const first = await env.browser("/delegates/trust-rule", "PUT", {});
  assert.equal(first.status, 201, first.raw);
  assert.match(first.body.rule.trust_rule_id, /^dtr_/);
  assert.deepEqual(first.body.rule.require_tier_o, []);
  const again = await env.browser("/delegates/trust-rule", "PUT", {});
  assert.equal(again.status, 200, again.raw);
  assert.equal(again.body.rule.trust_rule_id, first.body.rule.trust_rule_id);
  assert.equal((await env.events("trust_rule.created")).length, 1);
  assert.equal((await env.browser("/delegates/trust-rule", "PUT", { require_tier_o: ["ship_it"] })).status, 400);

  const bobId = await env.addMember("bob@acme.test");
  const bob = await env.desktopSignIn({ hostName: "bob-box", userId: bobId });
  assert.equal((await env.bearer("/delegates/trust-rule", "PUT", {}, bob.accessToken)).status, 201);
  // A member never reads or revokes another owner's rule; an admin may.
  assert.equal((await env.bearer(`/delegates/trust-rule?owner=${env.ownerId}`, "GET", undefined, bob.accessToken)).status, 403);
  assert.equal((await env.bearer(`/delegates/trust-rule?owner=${env.ownerId}`, "DELETE", undefined, bob.accessToken)).status, 403);
  assert.equal((await env.bearer(`/delegates/trust-rule?owner=${bobId}`)).body.rule.owner_id, bobId);
  const adminRevoke = await env.bearer(`/delegates/trust-rule?owner=${bobId}`, "DELETE");
  assert.equal(adminRevoke.status, 200, adminRevoke.raw);
  assert.equal((await env.events("trust_rule.revoked")).at(-1)!.reason, "admin_revoked");
  assert.equal((await env.bearer(`/delegates/trust-rule?owner=${bobId}`, "DELETE")).status, 404);

  // DELETE is allowed while delegation is off.
  await env.enable({ delegation_enabled: false });
  const own = await env.browser("/delegates/trust-rule", "DELETE");
  assert.equal(own.status, 200, own.raw);
  assert.deepEqual([own.body.revoked, own.body.revoked_grants], [first.body.rule.trust_rule_id, 0]);
  assert.equal((await env.browser("/delegates/trust-rule", "DELETE")).status, 404);
  assert.deepEqual((await env.bearer("/delegates/trust-rule")).body.rule, null);
});

test("trusted agents can never register, own or delete release gates", async (t) => {
  const { env, bot } = await ready(t);
  await turnOn(env);
  const body = { repo: "AgentWorkforce/relay-app", workflow_ref: "AgentWorkforce/relay-app/.github/workflows/p.yml@refs/heads/main",
    ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: "AgentWorkforce/relay-app:" };
  // A covered agent's own token is no person's credential: the gate registry refuses it before anything else.
  assert.equal((await env.bearer("/delegates/gates", "POST", body, bot.token)).status, 401);
  assert.equal((await env.bearer("/delegates/gates", "GET", undefined, bot.token)).status, 401);
  assert.equal((await env.bearer("/delegates/gates?gate_id=gate_abcdefgh1", "DELETE", undefined, bot.token)).status, 401);
  assert.equal((await env.database.query("SELECT 1 FROM delegation_gates")).rows.length, 0);
});

// ---------------------------------------------------------------------------
// Coverage through system grants

test("a claimed assistant is covered through a system grant: every allowed class, no expiry, no Tier O by default, audited", async (t) => {
  const { env, recipient, bot } = await ready(t);
  const before = env.send(bot, recipient);
  assert.equal((await env.verdict(recipient, before)).reason, "not_delegate");
  const rule = await turnOn(env);
  // A message sent before the rule (before the agent was covered) predates its grant.
  const old = env.send(bot, recipient, MERGE, { createdAt: new Date(Date.now() - 3_600_000).toISOString() });
  assert.equal((await env.verdict(recipient, old)).reason, "predates_grant");

  const merged = await env.verdict(recipient, env.send(bot, recipient));
  assert.equal(merged.verdict, "delegate", JSON.stringify(merged));
  const [grant] = await env.grants(bot.id);
  assert.equal(grant!.trust_rule_id, rule.trust_rule_id);
  assert.equal(merged.claims!.grant_id, grant!.id);
  assert.equal(grant!.created_auth_method, "system");
  assert.deepEqual(grant!.scopes, []);
  assert.equal(new Date(grant!.expires_at).toISOString(), "9999-12-31T00:00:00.000Z");
  assert.deepEqual(grant!.trust_path, { root: { kind: "claim", claim_id: bot.claimId, agent_id: bot.id,
    created_at: (grant!.trust_path as TrustPath).root.created_at }, hops: [] });
  const [created] = await env.events("grant.created");
  assert.deepEqual([created!.reason, created!.auth_method, created!.actor_user_id, created!.grant_id], ["trust_rule", "system", null, grant!.id]);
  assert.equal(created!.data.trust_rule_id, rule.trust_rule_id);
  assert.deepEqual(created!.data.trust_path, grant!.trust_path);
  assert.equal((await env.events("approval.attested"))[0]!.data.trust_rule_id, rule.trust_rule_id);

  // Every class the policy allows, one grant; the protocol's Tier O defaults still apply.
  const deploy = await env.verdict(recipient, env.send(bot, recipient, [{ class: "deploy", target: "web:prod" }]));
  assert.equal(deploy.verdict, "delegate");
  assert.equal(deploy.claims!.grant_id, grant!.id);
  // No Tier O by default (relay-control has no protocol-default Tier O classes); the policy's list still applies.
  assert.equal((await env.verdict(recipient, env.send(bot, recipient, [{ class: "deploy", target: "web:staging" }]))).verdict, "delegate");
  await env.enable({ require_tier_o: ["deploy"] });
  assert.equal((await env.verdict(recipient, env.send(bot, recipient, [{ class: "deploy", target: "web:staging" }]))).reason, "tier_o_required");
  await env.enable({ require_tier_o: [] });
  assert.equal((await env.grants(bot.id)).length, 1);
  // Redeem under the system grant.
  assert.deepEqual((await env.redeem(recipient, merged.claims!.approval_id, MERGE[0])).body, { ok: true, consumed: false });
  // The workspace policy still narrows it, and a tighter expiry cap never revokes it.
  await env.enable({ allowed_classes: ["merge"], max_expiry_days: 7 });
  assert.equal((await env.verdict(recipient, env.send(bot, recipient, [{ class: "deploy", target: "web:prod" }]))).reason, "out_of_scope");
  assert.equal((await env.grants(bot.id))[0]!.status, "active");
  await env.enable({ delegation_enabled: false });
  assert.equal((await env.verdict(recipient, env.send(bot, recipient))).reason, "not_enabled");
  await env.enable({ delegation_enabled: true });

  const listed = await env.bearer("/delegates/trust-rule");
  assert.deepEqual(listed.body.covered, [{ grant_id: grant!.id, chain: "proven", delegate_agent_id: bot.id,
    created_at: new Date(grant!.created_at).toISOString(), root_kind: "claim", connector: null, root_agent_id: bot.id,
    launched_by: null, hops: 0 }]);
  // A system grant is not edited: it is revoked to exclude the agent.
  const patched = await env.browser(`/delegates/${grant!.id}`, "PATCH", { require_tier_o: ["merge"] });
  assert.deepEqual([patched.status, patched.body.code], [409, "trust_rule_grant"]);
  // Under the rule, a bot may approve its own requests too (allow_all).
  const self = await env.verdict(bot, env.send(bot, bot));
  assert.equal(self.verdict, "delegate", JSON.stringify(self));
});

test("precedence: a live owner-made grant wins, a lapsed one never shadows the rule, a new one supersedes; exclusion sticks", async (t) => {
  const { env, recipient, bot } = await ready(t);
  await turnOn(env);
  assert.equal((await env.verdict(recipient, env.send(bot, recipient))).verdict, "delegate");
  const [system] = await env.grants(bot.id);

  // The owner's own grant supersedes the active system grant.
  const own = await env.browser("/delegates", "POST", { delegate_agent_id: bot.id, scopes: [{ class: "merge", targets: ["AgentWorkforce/*"] }] });
  assert.equal(own.status, 201, own.raw);
  const superseded = (await env.grants(bot.id)).find(row => row.id === system!.id)!;
  assert.deepEqual([superseded.status, superseded.revoked_reason], ["revoked", "superseded_by_grant"]);
  // It wins: its scopes decide, not the rule's every class.
  assert.equal((await env.verdict(recipient, env.send(bot, recipient))).claims!.grant_id, own.body.grant_id);
  assert.equal((await env.verdict(recipient, env.send(bot, recipient, [{ class: "deploy", target: "web:prod" }]))).reason, "out_of_scope");
  assert.deepEqual((await env.bearer("/delegates/trust-rule")).body.shadowed.map((row: { grant_id: string }) => row.grant_id),
    [own.body.grant_id]);

  // R1: once it lapses it is expired first and the rule covers the agent again.
  await env.database.query("UPDATE delegation_grants SET expires_at = now() - interval '1 second' WHERE id = $1", [own.body.grant_id]);
  const back = await env.verdict(recipient, env.send(bot, recipient, [{ class: "deploy", target: "web:prod" }]));
  assert.equal(back.verdict, "delegate", JSON.stringify(back));
  const rows = await env.grants(bot.id);
  assert.equal(rows.find(row => row.id === own.body.grant_id)!.status, "expired");
  const renewed = rows.find(row => row.status === "active")!;
  assert.ok(renewed.trust_rule_id);
  assert.equal(back.claims!.grant_id, renewed.id);

  // Exclusion: a person revoking one system grant keeps that agent out of the same rule for good.
  const removed = await env.browser(`/delegates/${renewed.id}`, "DELETE");
  assert.equal(removed.status, 200, removed.raw);
  assert.equal(removed.body.revoked_reason, "owner_excluded");
  assert.equal((await env.verdict(recipient, env.send(bot, recipient))).verdict, "none");
  assert.equal((await env.grants(bot.id)).filter(row => row.status === "active").length, 0);
});

test("Tier O on the rule reaches its system grants in the same transaction; revoke-all revokes rules first", async (t) => {
  const { env, recipient, bot } = await ready(t);
  await turnOn(env);
  const first = await env.verdict(recipient, env.send(bot, recipient));
  assert.equal(first.verdict, "delegate");
  const updated = await env.browser("/delegates/trust-rule", "PUT", { require_tier_o: ["merge"] });
  assert.equal(updated.status, 200, updated.raw);
  assert.deepEqual(updated.body.rule.require_tier_o, ["merge"]);
  assert.deepEqual((await env.grants(bot.id))[0]!.require_tier_o, ["merge"]);
  assert.deepEqual((await env.events("trust_rule.updated"))[0]!.data.require_tier_o, { before: [], after: ["merge"] });
  assert.equal((await env.verdict(recipient, env.send(bot, recipient))).reason, "tier_o_required");
  await env.browser("/delegates/trust-rule", "PUT", { require_tier_o: [] });

  const revoked = await env.bearer("/delegates/revoke-all", "POST", {});
  assert.equal(revoked.status, 200, revoked.raw);
  const [grant] = await env.grants(bot.id);
  assert.deepEqual(revoked.body.revoked, [grant!.id]);
  // Revoke-all revokes system grants with every other grant of its scope, under its own reason.
  assert.deepEqual([grant!.status, grant!.revoked_reason], ["revoked", "owner_revoke_all"]);
  const [ruleEvent] = await env.events("trust_rule.revoked");
  assert.deepEqual([ruleEvent!.reason, ruleEvent!.data.revoked_grants], ["owner_revoke_all", [grant!.id]]);
  assert.equal((await env.bearer("/delegates/trust-rule")).body.rule, null);
  // The approval attested under it is revoked too.
  assert.equal((await env.redeem(recipient, first.claims!.approval_id, MERGE[0])).body.reason, "revoked");
  assert.equal((await env.verdict(recipient, env.send(bot, recipient))).verdict, "none");
});

test("launch hops: a worker the covered assistant launched is covered; a broken chain revokes durably; S2 a re-created grant starts after the gap", async (t) => {
  const { env, recipient, bot } = await ready(t);
  await turnOn(env);
  const worker = await env.spawn(bot.id, "worker-1");
  const covered = await env.verdict(recipient, env.send(worker, recipient));
  assert.equal(covered.verdict, "delegate", JSON.stringify(covered));
  const listed = (await env.bearer("/delegates/trust-rule")).body.covered;
  assert.deepEqual(listed.map((row: { delegate_agent_id: string; hops: number; launched_by: string }) =>
    [row.delegate_agent_id, row.hops, row.launched_by]), [[worker.id, 1, bot.id]]);

  // A launch by someone else, or one not ready, is never covered.
  const bobId = await env.addMember("bob@acme.test");
  const bobs = await env.spawn(bot.id, "bobs-worker", "ready", bobId);
  assert.equal((await env.verdict(recipient, env.send(bobs, recipient))).reason, "not_delegate");
  const pending = await env.spawn(bot.id, "pending-worker", "accepted");
  assert.equal((await env.verdict(recipient, env.send(pending, recipient))).reason, "not_delegate");

  // Every record of the chain is a day old (as for a long-running assistant).
  await env.database.query("UPDATE relay_spawns SET created_at = now() - interval '1 day' WHERE id = $1", [worker.spawnId]);
  await env.database.query("UPDATE delegation_claims SET consumed_at = now() - interval '1 day' WHERE id = $1", [bot.claimId]);
  await env.database.query("UPDATE delegation_trust_rules SET created_at = now() - interval '1 day'");

  // The hop drops: a message the worker sends now is sent while it is uncovered.
  await env.database.query("UPDATE relay_spawns SET state = 'released' WHERE id = $1", [worker.spawnId]);
  const inGap = env.send(worker, recipient, MERGE, { createdAt: new Date(Date.now() - 600_000).toISOString() });
  // The next use revokes the system grant durably; the rule stays.
  assert.equal((await env.verdict(recipient, env.send(worker, recipient))).reason, "revoked");
  const [gone] = await env.grants(worker.id);
  assert.deepEqual([gone!.status, gone!.revoked_reason], ["revoked", "binding_changed"]);
  assert.ok((await env.bearer("/delegates/trust-rule")).body.rule);

  // S2: the chain proves out again from the same day-old records. The new
  // grant starts no earlier than the end of the rule's earlier coverage, so the
  // message sent in the gap predates it, while a fresh one is covered.
  await env.database.query("UPDATE relay_spawns SET state = 'ready' WHERE id = $1", [worker.spawnId]);
  assert.equal((await env.verdict(recipient, inGap)).reason, "predates_grant");
  const recreated = (await env.grants(worker.id)).find(row => row.status === "active")!;
  assert.ok(new Date(recreated.created_at).getTime() >= new Date(gone!.revoked_at!).getTime());
  assert.equal((await env.verdict(recipient, env.send(worker, recipient))).verdict, "delegate");

  // Releasing the root claim ends the whole tree's coverage.
  assert.equal((await env.browser(`/delegates/claims/${bot.claimId}`, "DELETE")).status, 200);
  assert.equal((await env.verdict(recipient, env.send(bot, recipient))).verdict, "none");
  assert.equal((await env.verdict(recipient, env.send(worker, recipient))).verdict, "none");
  assert.ok((await env.bearer("/delegates/trust-rule")).body.rule);
});

test("connector roots: a live OAuth grant pinned to the agent's id, joined to the owner's participant, marked live", async (t) => {
  const { env, recipient } = await ready(t);
  await turnOn(env);
  const gpt = await env.connector("chatgpt-assistant", { participantAt: new Date(Date.now() - 86_400_000).toISOString() });
  const covered = await env.verdict(recipient, env.send(gpt, recipient));
  assert.equal(covered.verdict, "delegate", JSON.stringify(covered));
  const [grant] = await env.grants(gpt.id);
  const root = (grant!.trust_path as TrustPath).root;
  assert.deepEqual([root.kind, root.kind === "connector" && root.connector, root.kind === "connector" && root.oauth_grant_id],
    ["connector", "chatgpt", gpt.grantId]);
  // S2: proven at the (newer) OAuth grant, not the older participant.
  const oauthAt = (await env.database.query<{ created_at: Date }>("SELECT created_at FROM mcp_oauth_grants WHERE id = $1", [gpt.grantId])).rows[0]!;
  assert.equal(root.created_at, new Date(oauthAt.created_at).toISOString());
  assert.equal((await env.bearer("/delegates/trust-rule")).body.covered[0].connector, "chatgpt");

  // The live agent must still carry Control's hosted marker for this owner.
  env.world.agents.get("chatgpt-assistant")!.metadata = { source: "cloud-hosted-mcp", owner_hash: sha(randomUUID()) };
  assert.equal((await env.verdict(recipient, env.send(gpt, recipient))).reason, "revoked");
  assert.equal((await env.grants(gpt.id))[0]!.revoked_reason, "delegate_released");

  // A revoked OAuth grant is no root.
  const other = await env.connector("grok-assistant", { redirect: "https://x.ai/cb" });
  await env.database.query("UPDATE mcp_oauth_grants SET revoked_at = now() WHERE id = $1", [other.grantId]);
  assert.equal((await env.verdict(recipient, env.send(other, recipient))).reason, "not_delegate");
  // Another owner's connector is not this owner's root; an unpinned grant is no root either.
  const bobId = await env.addMember("bob@acme.test");
  const bobs = await env.connector("bobs-assistant", { userId: bobId });
  assert.equal((await env.verdict(recipient, env.send(bobs, recipient))).reason, "not_delegate");
  const unpinned = await env.connector("unpinned-assistant", { pinned: false });
  assert.equal((await env.verdict(recipient, env.send(unpinned, recipient))).reason, "not_delegate");
  // The owner's launcher is never a root.
  const launcher = await env.connector(launcherName(env.ownerId));
  assert.equal((await env.verdict(recipient, env.send(launcher, recipient))).reason, "not_delegate");
});

test("prompt delegates: with the rule live, each proven root gets its system grant first; workers are not listed", async (t) => {
  const { env, recipient, bot } = await ready(t);
  const worker = await env.spawn(bot.id, "worker-1");
  const list = async () => {
    const listed = await request(env.origin, `${env.base}/messaging/delegation/prompt-delegates`, {
      method: "POST", token: env.desktop.accessToken, body: { session_agent_id: recipient.id, session_token: recipient.token } });
    assert.equal(listed.status, 200, listed.raw);
    return listed.body.delegates.map((row: { agent_id: string }) => row.agent_id) as string[];
  };
  assert.deepEqual(await list(), []);
  await turnOn(env);
  const gpt = await env.connector("chatgpt-assistant");
  assert.deepEqual((await list()).sort(), [bot.id, gpt.id].sort());
  assert.ok(!(await list()).includes(worker.id));
  assert.equal((await env.grants(bot.id))[0]!.trust_rule_id !== null, true);
});

test("C1: delegateStillBound with durable false refuses an unbound delegate without revoking it, rule-backed or owner-made", async (t) => {
  const { env, recipient, bot } = await ready(t);
  await turnOn(env);
  assert.equal((await env.verdict(recipient, env.send(bot, recipient))).verdict, "delegate");
  const workspace = { id: env.workspaceId, organizationId: env.orgId, relaycastWorkspaceId: "rw_primary", relaycastApiKey: "rk_primary" };
  const deps = { database: env.database, now: () => new Date() } as unknown as DelegationDeps;
  // The chain breaks: a second binding for the bot's id.
  await env.database.query(
    `INSERT INTO person_identities (id, workspace_id, organization_id, user_id, relaycast_workspace_id, agent_name, agent_remote_id, token_ciphertext)
     VALUES ($1, $2, $3, $4, 'rw_primary', 'shadow', $5, 'envelope')`,
    [randomUUID(), env.workspaceId, env.orgId, env.ownerId, bot.id]).catch(() => env.database.query(
    `INSERT INTO desktop_relay_identities (id, workspace_id, organization_id, user_id, relaycast_workspace_id, source_id, agent_name,
       agent_remote_id, address, token_ciphertext) VALUES ($1, $2, $3, $4, 'rw_primary', $5, 'shadow', $6, 'shadow@x', 'envelope')`,
    [randomUUID(), env.workspaceId, env.orgId, env.ownerId, randomUUID(), bot.id]));
  const [system] = await env.grants(bot.id);
  assert.equal(await delegateStillBound(deps, workspace, system!, false, { durable: false }), "revoked");
  assert.equal((await env.grants(bot.id))[0]!.status, "active");
  assert.equal(await delegateStillBound(deps, workspace, system!, false), "revoked");
  assert.deepEqual([(await env.grants(bot.id))[0]!.status, (await env.grants(bot.id))[0]!.revoked_reason], ["revoked", "binding_changed"]);

  // Owner-made: a grant whose delegate is now bound to someone else is refused without a durable revoke on a dry run.
  const bobId = await env.addMember("bob@acme.test");
  const bobAgent = await env.desktopIdentity("bob-agent", bobId);
  await env.database.query(
    `INSERT INTO delegation_grants (id, workspace_id, organization_id, owner_user_id, delegate_agent_id, delegate_agent_name, scopes,
       expires_at, created_auth_method) VALUES ('grt_ownerMade01', $1, $2, $3, $4, 'bob-agent', '[]'::jsonb, now() + interval '1 day', 'session')`,
    [env.workspaceId, env.orgId, env.ownerId, bobAgent.id]);
  const [ownerMade] = await env.grants(bobAgent.id);
  assert.equal(await delegateStillBound(deps, workspace, ownerMade!, false, { durable: false }), "revoked");
  assert.equal((await env.grants(bobAgent.id))[0]!.status, "active");
  assert.equal(await delegateStillBound(deps, workspace, ownerMade!, false), "revoked");
  assert.equal((await env.grants(bobAgent.id))[0]!.revoked_reason, "binding_changed");
});

test("P1: an owner-made grant to a connected assistant re-proves its connector; a revoked connector refuses and revokes it", async (t) => {
  const { env, recipient } = await ready(t);
  const gpt = await env.connector("chatgpt-assistant");
  const grant = (scopes: unknown) => request(env.origin, `${env.base}/delegates`, { method: "POST", token: env.desktop.accessToken,
    body: { delegate_agent_id: gpt.id, scopes } });
  const created = await grant([{ class: "merge", targets: ["AgentWorkforce/*"] }]);
  assert.equal(created.status, 201, created.raw);
  assert.equal((await env.verdict(recipient, env.send(gpt, recipient))).verdict, "delegate");
  // The connector is revoked: the participant row and the live agent remain, the owner's grant does not.
  await env.database.query("UPDATE mcp_oauth_grants SET revoked_at = now() WHERE id = $1", [gpt.grantId]);
  assert.equal((await env.verdict(recipient, env.send(gpt, recipient))).reason, "revoked");
  const [owned] = await env.grants(gpt.id);
  assert.deepEqual([owned!.status, owned!.revoked_reason, owned!.trust_rule_id], ["revoked", "binding_changed", null]);
  // A new owner-made grant needs a proven connector too.
  const refused = await grant([{ class: "merge", targets: ["AgentWorkforce/*"] }]);
  assert.equal(refused.status, 403, refused.raw);
  const unpinned = await env.connector("unpinned-assistant", { pinned: false });
  const unproven = await request(env.origin, `${env.base}/delegates`, { method: "POST", token: env.desktop.accessToken,
    body: { delegate_agent_id: unpinned.id, scopes: [{ class: "merge", targets: ["AgentWorkforce/*"] }] } });
  assert.equal(unproven.status, 403, unproven.raw);
});

test("the DB refuses an owner-made grant past the 90-day cap and admits a rule-backed one", async (t) => {
  const { env, bot } = await ready(t);
  const rule = await turnOn(env);
  const insert = (id: string, ruleId: string | null, method: string) => env.database.query(
    `INSERT INTO delegation_grants (id, workspace_id, organization_id, owner_user_id, delegate_agent_id, delegate_agent_name, scopes,
       expires_at, created_auth_method, trust_rule_id)
     VALUES ($1, $2, $3, $4, $5, 'assistant', '[]'::jsonb, now() + interval '91 days', $6, $7)`,
    [id, env.workspaceId, env.orgId, env.ownerId, bot.id, method, ruleId]);
  await assert.rejects(insert("grt_ownerPast01", null, "session"), /delegation_grants_expiry_cap/);
  // Only a rule-backed grant may be created by the system.
  await assert.rejects(insert("grt_ownerSys001", null, "system"), /delegation_grants_auth_method/);
  await insert("grt_ruleBack001", rule.trust_rule_id, "system");
});

test("backfill: service-authenticated, dry run by default, pins only provable connections, idempotent, paged", async (t) => {
  const { env } = await ready(t);
  const call = (body: unknown, token: string | null = INTERNAL) => request(env.origin, "/internal/v1/delegation/trust-backfill", {
    method: "POST", ...(token ? { token } : {}), body });
  assert.equal((await call({}, null)).status, 401);
  assert.equal((await call({}, env.desktop.accessToken)).status, 401);
  const provable = await env.connector("old-assistant", { pinned: false });
  const launcher = await env.connector(launcherName(env.ownerId), { pinned: false });
  void launcher;
  const dry = await call({});
  assert.equal(dry.status, 200, dry.raw);
  assert.deepEqual([dry.body.dry_run, dry.body.provable, dry.body.pinned, dry.body.skipped.launcher], [true, 1, 0, 1]);
  assert.deepEqual(dry.body.pins.map((pin: { agent_id: string }) => pin.agent_id), [provable.id]);
  assert.equal((await env.database.query("SELECT agent_remote_id FROM mcp_oauth_grants WHERE id = $1", [provable.grantId])).rows[0]!
    .agent_remote_id, null);
  assert.equal((await env.events("trust_root.backfilled")).length, 0);

  // Paged by id with an `after` cursor.
  const page = await backfillConnectorRoots(env.database, { apply: false, limit: 1 });
  assert.equal(page.scanned, 1);
  assert.ok(page.next_cursor);
  const rest = await backfillConnectorRoots(env.database, { apply: false, limit: 1, after: page.next_cursor! });
  assert.equal(rest.scanned, 1);
  assert.equal((await backfillConnectorRoots(env.database, { apply: false, limit: 1, after: rest.next_cursor! })).scanned, 0);

  const applied = await call({ apply: true });
  assert.deepEqual([applied.body.dry_run, applied.body.pinned], [false, 1]);
  assert.equal((await env.database.query("SELECT agent_remote_id FROM mcp_oauth_grants WHERE id = $1", [provable.grantId])).rows[0]!
    .agent_remote_id, provable.id);
  const [event] = await env.events("trust_root.backfilled");
  assert.deepEqual([event!.reason, event!.auth_method, event!.actor_user_id, event!.data.oauth_grant_id], ["backfill", "system", null,
    provable.grantId]);
  // No rule and no grant are created; a rerun pins nothing again.
  assert.equal((await env.database.query("SELECT 1 FROM delegation_trust_rules")).rows.length, 0);
  assert.equal((await env.database.query("SELECT 1 FROM delegation_grants")).rows.length, 0);
  assert.equal((await call({ apply: true })).body.pinned, 0);
  assert.equal((await env.events("trust_root.backfilled")).length, 1);
});

/** The owner reconnects a connected assistant: the old OAuth grant is revoked and a new one (with a live session) is pinned to the same id. */
async function reconnect(env: Awaited<ReturnType<typeof setup>>, agent: { id: string; name: string; grantId: string }, at?: string) {
  await env.database.query("UPDATE mcp_oauth_grants SET revoked_at = now() WHERE id = $1", [agent.grantId]);
  const client = (await env.database.query<{ client_id: string }>("SELECT client_id FROM mcp_oauth_grants WHERE id = $1",
    [agent.grantId])).rows[0]!.client_id;
  const grantId = randomUUID();
  const family = randomUUID();
  await env.database.query(
    `INSERT INTO mcp_oauth_grants (id, client_id, client_name, user_id, organization_id, workspace_id, agent_name, agent_remote_id,
       scopes, resource, token_family_id, created_at)
     VALUES ($1, $2, 'ChatGPT', $3, $4, $5, $6, $7, ARRAY['relay:mcp'], 'https://control.test/mcp', $8, COALESCE($9::timestamptz, now()))`,
    [grantId, client, env.ownerId, env.orgId, env.workspaceId, agent.name, agent.id, family, at ?? null]);
  await env.database.query(
    `INSERT INTO mcp_oauth_sessions (id, grant_id, token_family_id, user_id, organization_id, workspace_id, scopes,
       access_token_hash, refresh_token_hash, access_token_expires_at, refresh_token_expires_at, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, ARRAY['relay:mcp'], $7, $8, now() + interval '1 hour', now() + interval '30 days', now(), now())`,
    [randomUUID(), grantId, family, env.ownerId, env.orgId, env.workspaceId, sha(randomUUID()), sha(randomUUID())]);
  return grantId;
}

test("round 3 (1): a system grant covers only the chain it was created on; a reconnected root ends it with its approvals", async (t) => {
  const { env, recipient } = await ready(t);
  await turnOn(env);
  const gpt = await env.connector("chatgpt-assistant");
  const first = await env.verdict(recipient, env.send(gpt, recipient));
  assert.equal(first.verdict, "delegate", JSON.stringify(first));
  const [old] = await env.grants(gpt.id);
  // Revoked and reconnected without any use in between: the chain proves out again, through a new OAuth grant.
  const beforeReconnect = env.send(gpt, recipient, MERGE, { createdAt: new Date(Date.now() - 60_000).toISOString() });
  await reconnect(env, gpt);
  // A message sent before the reconnect: the old grant ends (a hand-over), and the new one never covers it.
  const stale = await env.verdict(recipient, beforeReconnect);
  assert.equal(stale.reason, "predates_grant", JSON.stringify(stale));
  const ended = (await env.grants(gpt.id)).find(row => row.id === old!.id)!;
  assert.deepEqual([ended.status, ended.revoked_reason], ["revoked", "chain_changed"]);
  // The old coverage's approval never redeems again.
  assert.equal((await env.redeem(recipient, first.claims!.approval_id, MERGE[0])).body.reason, "revoked");
  // A message sent after the reconnect is covered by a fresh system grant dated
  // from the new OAuth grant, not from when the change was noticed (Devin on cloud train #6652).
  const fresh = await env.verdict(recipient, env.send(gpt, recipient, MERGE));
  assert.equal(fresh.verdict, "delegate", JSON.stringify(fresh));
  const renewed = (await env.grants(gpt.id)).find(row => row.status === "active")!;
  assert.notEqual(renewed.id, old!.id);
  assert.ok(new Date(renewed.created_at).getTime() <= new Date(ended.revoked_at!).getTime());
});

test("a reclaim noticed late: an approval sent after the new claim but attested later is covered, in the same call", async (t) => {
  const { env, recipient, bot } = await ready(t);
  await turnOn(env);
  const worker = await env.spawn(bot.id, "worker-1");
  assert.equal((await env.verdict(recipient, env.send(worker, recipient))).verdict, "delegate");
  const [old] = await env.grants(worker.id);
  // The owner releases and reclaims the worker's root; nothing the worker sends is attested until later.
  assert.equal((await env.browser(`/delegates/claims/${bot.claimId}`, "DELETE")).status, 200);
  const started = await env.browser("/delegates/claims", "POST");
  assert.equal((await request(env.origin, `${env.base}/delegates/claims/complete`, {
    method: "POST", body: { code: started.body.code, agent_id: bot.id, agent_token: bot.token } })).status, 200);
  const sent = env.send(worker, recipient, MERGE);
  await new Promise(resolve => setTimeout(resolve, 2_500));
  const late = await env.verdict(recipient, sent);
  assert.equal(late.verdict, "delegate", JSON.stringify(late));
  const ended = (await env.grants(worker.id)).find(row => row.id === old!.id)!;
  assert.deepEqual([ended.status, ended.revoked_reason], ["revoked", "chain_changed"]);
});

// d5 B1 (Devin on #340): a connector root's pin has no time, so a hand-over to
// another connector grant is not dated by its records: the cutoff stays at the retirement.
test("a hand-over to another connector grant keeps the cutoff at the retirement", async (t) => {
  const { env, recipient } = await ready(t);
  await turnOn(env);
  const gpt = await env.connector("chatgpt-assistant");
  assert.equal((await env.verdict(recipient, env.send(gpt, recipient))).verdict, "delegate");
  // Reconnected through an OAuth grant created a day ago (as a backfill re-pin of an older grant would look).
  await reconnect(env, gpt, new Date(Date.now() - 86_400_000).toISOString());
  const sent = env.send(gpt, recipient, MERGE);
  await new Promise(resolve => setTimeout(resolve, 2_500));
  assert.equal((await env.verdict(recipient, sent)).reason, "predates_grant");
  // A message sent after the hand-over was noticed is covered.
  assert.equal((await env.verdict(recipient, env.send(gpt, recipient, MERGE))).verdict, "delegate");
});

// d5 B2 (Devin on cloud#6654): the exclusion is of the agent, not the row the person saw.
test("revoking a system grant the rule already replaced excludes the agent; a retired one is recorded as the exclusion", async (t) => {
  const { env, recipient } = await ready(t);
  await turnOn(env);
  const gpt = await env.connector("chatgpt-assistant");
  assert.equal((await env.verdict(recipient, env.send(gpt, recipient))).verdict, "delegate");
  const [shown] = await env.grants(gpt.id);
  await reconnect(env, gpt);
  // The hand-over retires the shown grant and the rule covers the agent through a new one.
  assert.equal((await env.verdict(recipient, env.send(gpt, recipient, MERGE))).verdict, "delegate");
  const replacement = (await env.grants(gpt.id)).find(row => row.status === "active")!;
  assert.notEqual(replacement.id, shown!.id);
  assert.equal((await env.browser(`/delegates/${shown!.id}`, "DELETE")).status, 200);
  const after = await env.grants(gpt.id);
  assert.deepEqual([after.find(row => row.id === replacement.id)!.status, after.find(row => row.id === replacement.id)!.revoked_reason],
    ["revoked", "owner_excluded"]);
  assert.equal((await env.verdict(recipient, env.send(gpt, recipient, MERGE))).verdict, "none");
  assert.equal((await env.grants(gpt.id)).filter(row => row.status === "active").length, 0);

  // Nothing active any more: the retired grant itself is re-recorded as the exclusion.
  const other = await env.connector("other-assistant");
  assert.equal((await env.verdict(recipient, env.send(other, recipient))).verdict, "delegate");
  const [retired] = await env.grants(other.id);
  await env.database.query("UPDATE delegation_grants SET status = 'revoked', revoked_at = now(), revoked_reason = 'chain_changed' WHERE id = $1",
    [retired!.id]);
  assert.equal((await env.browser(`/delegates/${retired!.id}`, "DELETE")).status, 200);
  assert.equal((await env.grants(other.id))[0]!.revoked_reason, "owner_excluded");
  assert.equal((await env.verdict(recipient, env.send(other, recipient, MERGE))).verdict, "none");
  assert.equal((await env.events("grant.revoked")).at(-1)!.data.already_ended, true);
});

test("round 3 (2): a grant that stands on a proof covers messages only from the proof's records on", async (t) => {
  const { env, recipient } = await ready(t);
  const gpt = await env.connector("chatgpt-assistant", { grantAt: new Date(Date.now() - 3_600_000).toISOString(),
    participantAt: new Date(Date.now() - 3_600_000).toISOString() });
  // An owner-made grant to the connected assistant.
  const created = await env.browser("/delegates", "POST", { delegate_agent_id: gpt.id, scopes: [{ class: "merge", targets: ["AgentWorkforce/*"] }] });
  assert.equal(created.status, 201, created.raw);
  const sentBefore = env.send(gpt, recipient, MERGE, { createdAt: new Date(Date.now() + 5_000).toISOString() });
  // The connector is reconnected later: the new OAuth grant is the proof's record now.
  await reconnect(env, gpt, new Date(Date.now() + 60_000).toISOString());
  // Under the existing owner-made grant, a message sent before the reconnect predates it.
  assert.equal((await env.verdict(recipient, sentBefore)).reason, "predates_grant");
  const sentAfter = env.send(gpt, recipient, MERGE, { createdAt: new Date(Date.now() + 61_000).toISOString() });
  assert.equal((await env.verdict(recipient, sentAfter)).verdict, "delegate");
});

test("round 3 (6, 7): workers with a system grant are never prompt delegates; GET reports each chain without writing", async (t) => {
  const { env, recipient, bot } = await ready(t);
  await turnOn(env);
  const worker = await env.spawn(bot.id, "worker-1");
  // The worker carries an approval, so it has a materialized system grant.
  assert.equal((await env.verdict(recipient, env.send(worker, recipient))).verdict, "delegate");
  assert.equal((await env.grants(worker.id))[0]!.status, "active");
  const listed = await request(env.origin, `${env.base}/messaging/delegation/prompt-delegates`, {
    method: "POST", token: env.desktop.accessToken, body: { session_agent_id: recipient.id, session_token: recipient.token } });
  assert.deepEqual(listed.body.delegates.map((row: { agent_id: string }) => row.agent_id), [bot.id]);

  const chains = async () => Object.fromEntries((await env.bearer("/delegates/trust-rule")).body.covered
    .map((row: { delegate_agent_id: string; chain: string }) => [row.delegate_agent_id, row.chain]));
  assert.deepEqual(await chains(), { [bot.id]: "proven", [worker.id]: "proven" });
  await env.database.query("UPDATE relay_spawns SET state = 'released' WHERE id = $1", [worker.spawnId]);
  assert.deepEqual(await chains(), { [bot.id]: "proven", [worker.id]: "broken" });
  // Reading wrote nothing: the worker's grant is still active until its next use revokes it.
  assert.equal((await env.grants(worker.id))[0]!.status, "active");
  assert.equal((await env.verdict(recipient, env.send(worker, recipient))).reason, "revoked");
});

test("round 3 (9): the backfill skips and counts connector grants with no live session", async (t) => {
  const { env } = await ready(t);
  const revoked = await env.connector("revoked-session", { pinned: false });
  const expired = await env.connector("expired-session", { pinned: false });
  const live = await env.connector("live-session", { pinned: false });
  await env.database.query("UPDATE mcp_oauth_sessions SET revoked_at = now() WHERE grant_id = $1", [revoked.grantId]);
  await env.database.query("UPDATE mcp_oauth_sessions SET refresh_token_expires_at = now() - interval '1 second' WHERE grant_id = $1",
    [expired.grantId]);
  const report = await backfillConnectorRoots(env.database, { apply: true });
  assert.equal(report.skipped.no_live_session, 2);
  assert.deepEqual(report.pins.map(pin => pin.agent_id), [live.id]);
  const pinned = async (grantId: string) => (await env.database.query<{ agent_remote_id: string | null }>(
    "SELECT agent_remote_id FROM mcp_oauth_grants WHERE id = $1", [grantId])).rows[0]!.agent_remote_id;
  assert.equal(await pinned(revoked.grantId), null);
  assert.equal(await pinned(expired.grantId), null);
  assert.equal(await pinned(live.grantId), live.id);
});
