import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import { loadDelegationSigning } from "../src/config.js";
import { encryptSecret } from "../src/crypto.js";
import { verifyDelegationJws } from "../src/delegation/jws.js";
import {
  actionsCovered,
  base62,
  highRisk,
  ownerDisplay,
  targetCovered,
  tierDApprovalId,
  validTargetPattern,
} from "../src/delegation/scope.js";
import { copilotDesktopSetup } from "./support/copilot-desktop.js";
import { request } from "./support/harness.js";
import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";

const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const KID = "dlg-2026q4";

type Env = Awaited<ReturnType<typeof setup>>;

async function setup(t: TestContext, options: { signing?: boolean } = {}) {
  const seed = randomBytes(32);
  const env = await copilotDesktopSetup(t, {}, undefined,
    options.signing === false ? {} : { delegationSigning: { kid: KID, seed, previous: [] } });
  const desktop = await env.desktopSignIn({ hostName: "khaliq-box" });
  const base = `/api/v1/workspaces/${env.workspaceId}`;

  /** A browser (cookie) write: JSON with the API origin. */
  const browser = (path: string, method: string, body?: unknown, cookie = desktop.session) =>
    request(env.origin, `/cloud${base}${path}`, {
      method, cookie, body: body ?? {}, headers: { origin: env.origin },
    });
  /** The owner's Desktop-verified bearer. */
  const bearer = (path: string, method = "GET", body?: unknown, token = desktop.accessToken) =>
    request(env.origin, `${base}${path}`, { method, token, ...(body === undefined ? {} : { body }) });

  /** Binds an agent to a person as a synced Desktop identity. */
  async function desktopIdentity(name: string, userId = env.ownerId) {
    const agent = env.world.addAgent(name);
    await env.database.query(
      `INSERT INTO desktop_relay_identities
         (id, workspace_id, organization_id, user_id, relaycast_workspace_id, source_id, agent_name,
          agent_remote_id, address, token_ciphertext)
       VALUES ($1, $2, $3, $4, 'rw_primary', $5, $6, $7, $8, $9)`,
      [randomUUID(), env.workspaceId, env.orgId, userId, randomUUID(), name, agent.id,
        `${name}@cloud-${agent.id}`, encryptSecret(agent.token, KEYRING.active)],
    );
    return agent;
  }

  async function enable(body: Record<string, unknown> = {}) {
    const put = await browser("/delegates/policy", "PUT", { delegation_enabled: true, ...body });
    assert.equal(put.status, 200, put.raw);
    return put;
  }

  /** The claim flow: the owner starts it, the bot completes it with its own token. */
  async function claim(name: string) {
    const agent = env.world.addAgent(name);
    const started = await browser("/delegates/claims", "POST");
    assert.equal(started.status, 201, started.raw);
    const done = await request(env.origin, `${base}/delegates/claims/complete`, {
      method: "POST", body: { code: started.body.code, agent_id: agent.id, agent_token: agent.token },
    });
    assert.equal(done.status, 200, done.raw);
    return agent;
  }

  async function grant(agentId: string, scopes: unknown, extra: Record<string, unknown> = {}) {
    const created = await browser("/delegates", "POST", { delegate_agent_id: agentId, scopes, ...extra });
    assert.equal(created.status, 201, created.raw);
    return created.body;
  }

  function approval(actions: unknown, extra: Record<string, unknown> = {}) {
    return { v: 1, owner_id: env.ownerId, actions, quote: "yes merge 2250 when green", quote_source: "chat:dm", ...extra };
  }

  async function attest(recipient: { id: string; token: string }, messageId: string,
    accept: "own_owner" | "code_owners" = "code_owners", token = desktop.accessToken) {
    return request(env.origin, `${base}/messaging/delegation`, {
      method: "POST", token,
      body: { recipient_agent_id: recipient.id, recipient_token: recipient.token, message_id: messageId, accept },
    });
  }

  async function redeem(recipient: { id: string; token: string }, approvalId: string, action: unknown,
    token = desktop.accessToken) {
    return request(env.origin, `${base}/messaging/delegation/redeem`, {
      method: "POST", token,
      body: { recipient_agent_id: recipient.id, recipient_token: recipient.token, approval_id: approvalId, action },
    });
  }

  async function jwks() {
    const response = await request(env.origin, "/.well-known/relay-delegation-keys.json");
    assert.equal(response.status, 200, response.raw);
    return response.body as { keys: Array<Record<string, string>> };
  }

  async function events(event?: string) {
    return (await env.database.query<{ event: string; reason: string | null; grant_id: string | null; quote: string | null;
      quote_hash: string | null; jti: string | null; approval_id: string | null }>(
      `SELECT event, reason, grant_id, quote, quote_hash, data->>'jti' AS jti, approval_id FROM delegation_audit_events
        WHERE ($1::text IS NULL OR event = $1) ORDER BY id`,
      [event ?? null],
    )).rows;
  }

  return { ...env, seed, desktop, base, browser, bearer, desktopIdentity, enable, claim, grant, approval, attest, redeem, jwks, events };
}

/** Owner's coding agent (recipient), owner's claimed bot (delegate), delegation on, one merge grant. */
async function ready(t: TestContext) {
  const env = await setup(t);
  await env.enable();
  const recipient = await env.desktopIdentity("relay-coder");
  const bot = await env.claim("assistant");
  const created = await env.grant(bot.id, [
    { class: "merge", targets: ["AgentWorkforce/*"] },
    { class: "deploy", targets: ["*:staging", "relay:prod"] },
    { class: "release", targets: ["AgentWorkforce/relay"] },
  ]);
  return { env, recipient, bot, grantId: created.grant_id as string };
}

function send(env: Env, bot: { name: string }, recipient: { name: string }, ownerApproval: unknown) {
  return env.world.sendApprovalAs(bot.name, recipient.name, "Khaliq approved: merge #2250 once CI is green.", ownerApproval).message.id;
}

// ---------------------------------------------------------------------------
// Pure contract rules

test("scope matching follows §16.1", () => {
  assert.ok(targetCovered("owner/*", "owner/x"));
  assert.ok(targetCovered("owner/*", "owner/x#12"));
  assert.ok(targetCovered("owner/repo", "owner/repo"));
  assert.ok(targetCovered("owner/repo", "owner/repo#2250"));
  assert.ok(!targetCovered("owner/repo", "owner/repo2"));
  assert.ok(!targetCovered("owner/repo", "owner/other#1"));
  assert.ok(!targetCovered("owner/repo#1", "owner/repo#12"));
  assert.ok(targetCovered("*:staging", "web:staging"));
  assert.ok(!targetCovered("*:staging", "web:prod"));
  assert.ok(!targetCovered("*:staging", "web:staging:x"));
  assert.ok(!targetCovered("owner/*", "other/x"));
  // An action may not itself be a wildcard, and `*` is never part of a segment.
  assert.ok(!targetCovered("owner/*", "owner/*"));
  assert.ok(!validTargetPattern("relay-*"));
  assert.ok(!validTargetPattern("owner//x"));
  assert.ok(!validTargetPattern("a".repeat(257)));
  // Subsumption (PATCH narrowing).
  assert.ok(targetCovered("owner/*", "owner/repo", true));
  assert.ok(targetCovered("owner/repo", "owner/repo#*", true));
  assert.ok(!targetCovered("owner/repo", "owner/*", true));
  // The whole set is judged.
  const scopes = [{ class: "merge" as const, targets: ["owner/*"] }];
  assert.ok(actionsCovered(scopes, [{ class: "merge", target: "owner/a#1" }]));
  assert.ok(!actionsCovered(scopes, [{ class: "merge", target: "owner/a#1" }, { class: "merge", target: "x/y" }]));
  assert.ok(!actionsCovered(scopes, [{ class: "pr_ops", target: "owner/a" }]));
});

test("high-risk classes and approval ids follow §16.1 and §16.4", () => {
  for (const cls of ["release", "secret_change", "destructive", "spend"] as const) assert.ok(highRisk({ class: cls, target: "x" }));
  assert.ok(highRisk({ class: "deploy", target: "web:prod" }));
  assert.ok(highRisk({ class: "deploy", target: "web:production" }));
  assert.ok(!highRisk({ class: "deploy", target: "web:staging" }));
  assert.ok(!highRisk({ class: "merge", target: "a/b#1" }));
  const ws = "8d7c0a4e-0000-4000-8000-000000000001";
  const digest = createHash("sha256").update(`${ws}|233`).digest().subarray(0, 16);
  assert.equal(tierDApprovalId(ws, "233"), `apv_${base62(digest)}`);
  assert.match(tierDApprovalId(ws, "233"), /^apv_[A-Za-z0-9]{8,64}$/);
  assert.equal(base62(Uint8Array.from([0, 61])), "z");
  assert.equal(base62(Uint8Array.from([1, 0])), "48");
  assert.equal(ownerDisplay("Khaliq Gant"), "Khaliq Gant");
  assert.equal(ownerDisplay("  Khaliq\n Gant "), "Khaliq Gant");
  assert.equal(ownerDisplay("k@example.com"), "the owner");
  assert.equal(ownerDisplay(""), "the owner");
  assert.equal([...ownerDisplay("x".repeat(200))].length, 80);
  // Cut at 80 UTF-16 units on a character boundary: an emoji (a surrogate
  // pair) straddling the boundary is dropped whole, never split.
  const straddling = ownerDisplay(`${"a".repeat(79)}\u{1F600}tail`);
  assert.equal(straddling, "a".repeat(79));
  assert.equal(straddling.length, 79);
  const fits = ownerDisplay(`${"a".repeat(78)}\u{1F600}tail`);
  assert.equal(fits, `${"a".repeat(78)}\u{1F600}`);
  assert.equal(fits.length, 80);
  assert.ok(!/[\uD800-\uDBFF]$/.test(ownerDisplay(`${"b".repeat(79)}\u{1F680}\u{1F680}`)));
});

test("signing key config: seed and kid together, previous keys validated", () => {
  assert.equal(loadDelegationSigning({}), null);
  const seed = randomBytes(32).toString("base64url");
  const loaded = loadDelegationSigning({ SELFHOST_DELEGATION_SIGNING_KEY: seed, SELFHOST_DELEGATION_SIGNING_KID: "k1" });
  assert.equal(loaded?.kid, "k1");
  assert.equal(loaded?.seed.byteLength, 32);
  assert.throws(() => loadDelegationSigning({ SELFHOST_DELEGATION_SIGNING_KEY: seed }), /required together/);
  assert.throws(() => loadDelegationSigning({ SELFHOST_DELEGATION_SIGNING_KEY: "short", SELFHOST_DELEGATION_SIGNING_KID: "k1" }), /32-byte/);
  assert.throws(() => loadDelegationSigning({
    SELFHOST_DELEGATION_SIGNING_KEY: seed, SELFHOST_DELEGATION_SIGNING_KID: "k1",
    SELFHOST_DELEGATION_PREVIOUS_KEYS: JSON.stringify([{ kid: "k1", x: seed }]),
  }), /distinct kids/);
  const rotated = loadDelegationSigning({
    SELFHOST_DELEGATION_SIGNING_KEY: seed, SELFHOST_DELEGATION_SIGNING_KID: "k2",
    SELFHOST_DELEGATION_PREVIOUS_KEYS: JSON.stringify([{ kid: "k1", x: randomBytes(32).toString("base64url") }]),
  });
  assert.equal(rotated?.previous.length, 1);
});

// ---------------------------------------------------------------------------
// Human-only enforcement and grant lifecycle

test("human-only routes refuse agent, CLI and enrollment credentials; off by default", async (t) => {
  const env = await setup(t);
  const recipient = await env.desktopIdentity("relay-coder");

  // Default: delegation_enabled is off. GET works and says so; writes are refused.
  const listed = await env.bearer("/delegates");
  assert.equal(listed.status, 200, listed.raw);
  assert.deepEqual(listed.body, { grants: [] });
  const refusedOff = await env.browser("/delegates", "POST", { delegate_agent_id: recipient.id, scopes: [{ class: "merge", targets: ["a/b"] }] });
  assert.equal(refusedOff.status, 403, refusedOff.raw);
  assert.equal(refusedOff.body.code, "not_enabled");
  assert.equal((await env.browser("/delegates/claims", "POST")).body.code, "not_enabled");
  assert.equal((await env.browser("/delegates/approvals", "POST", { actions: [{ class: "merge", target: "a/b" }] })).body.code, "not_enabled");

  // A plain device-flow CLI login is not a human session for this surface.
  const cli = await env.deviceLogin();
  const cliRead = await env.bearer("/delegates", "GET", undefined, cli);
  assert.equal(cliRead.status, 403, cliRead.raw);
  assert.equal(cliRead.body.code, "forbidden");
  // An agent's Relaycast token and the unexchanged handoff are not Control sessions at all.
  assert.equal((await env.bearer("/delegates", "GET", undefined, recipient.token)).status, 401);
  assert.ok([401, 403].includes((await env.bearer("/delegates", "GET", undefined, env.desktop.handoffToken)).status));
  // The bootstrap operator bearer is not a person.
  assert.equal((await env.bearer("/delegates", "GET", undefined, "bootstrap-token-that-is-at-least-32-bytes")).status, 401);
  // No credential.
  assert.equal((await request(env.origin, `${env.base}/delegates`)).status, 401);

  // Only an admin writes the policy.
  const memberId = await env.addMember("member@acme.test");
  const memberDesktop = await env.desktopSignIn({ hostName: "member-box", userId: memberId });
  const memberPolicy = await env.browser("/delegates/policy", "PUT", { delegation_enabled: true }, memberDesktop.session);
  assert.equal(memberPolicy.status, 403, memberPolicy.raw);
  assert.equal(memberPolicy.body.code, "forbidden");

  // Cookie writes need an allowed origin.
  const crossSite = await request(env.origin, `/cloud${env.base}/delegates/policy`, {
    method: "PUT", cookie: env.desktop.session, body: { delegation_enabled: true }, headers: { origin: "https://evil.example" },
  });
  assert.equal(crossSite.status, 403, crossSite.raw);
  assert.equal(crossSite.body.code, "csrf_rejected");

  // No step-up (§4.1): an old browser session still changes delegates, and so
  // does a verified Desktop sign-in.
  await env.database.query("UPDATE token_sessions SET created_at = now() - interval '20 days'");
  const old = await env.browser("/delegates/policy", "PUT", { delegation_enabled: true });
  assert.equal(old.status, 200, old.raw);
  const viaDesktop = await env.bearer("/delegates/policy", "PUT", { delegation_enabled: true });
  assert.equal(viaDesktop.status, 200, viaDesktop.raw);
  assert.equal(viaDesktop.body.delegation_enabled, true);
});

test("grants: create, narrow, refuse widening, revoke, revoke-all, policy limits, audit", async (t) => {
  const env = await setup(t);
  await env.enable({ max_expiry_days: 60 });
  const bot = await env.claim("assistant");
  const other = await env.desktopIdentity("not-mine", await env.addMember("bob@acme.test"));

  // The delegate must be bound to the caller.
  const foreign = await env.browser("/delegates", "POST", { delegate_agent_id: other.id, scopes: [{ class: "merge", targets: ["a/b"] }] });
  assert.equal(foreign.status, 403, foreign.raw);
  assert.equal(foreign.body.code, "not_delegate");
  const unknown = await env.browser("/delegates", "POST", { delegate_agent_id: "ag_nobody", scopes: [{ class: "merge", targets: ["a/b"] }] });
  assert.equal(unknown.body.code, "not_delegate");

  // Shape: closed classes, whole-segment wildcards, one scope per class, expiry caps.
  for (const scopes of [
    [{ class: "prompt_approval", targets: ["x"] }],
    [{ class: "merge", targets: ["relay-*"] }],
    [{ class: "merge", targets: [] }],
    [{ class: "merge", targets: ["a/b"] }, { class: "merge", targets: ["c/d"] }],
  ]) {
    const bad = await env.browser("/delegates", "POST", { delegate_agent_id: bot.id, scopes });
    assert.equal(bad.status, 400, `${JSON.stringify(scopes)} ${bad.raw}`);
  }
  const tooLong = await env.browser("/delegates", "POST", {
    delegate_agent_id: bot.id, scopes: [{ class: "merge", targets: ["a/b"] }],
    expires_at: new Date(Date.now() + 61 * 86_400_000).toISOString(),
  });
  assert.equal(tooLong.status, 400, tooLong.raw);
  assert.equal(tooLong.body.code, "invalid_expiry");

  const created = await env.grant(bot.id, [{ class: "merge", targets: ["AgentWorkforce/*"] }, { class: "pr_ops", targets: ["AgentWorkforce/relay"] }]);
  assert.match(created.grant_id, /^grt_/);
  assert.equal(created.status, "active");
  assert.deepEqual(Object.keys(created).sort(), ["created_at", "delegate_agent_id", "expires_at", "grant_id", "owner_id",
    "require_tier_o", "revoked_at", "revoked_reason", "scopes", "status", "updated_at"]);
  // One active grant per (owner, delegate): widening is a new grant after revoking.
  const twice = await env.browser("/delegates", "POST", { delegate_agent_id: bot.id, scopes: [{ class: "merge", targets: ["a/b"] }] });
  assert.equal(twice.status, 409, twice.raw);
  assert.equal(twice.body.code, "grant_exists");
  // Default expiry: 30 days.
  const days = (Date.parse(created.expires_at) - Date.now()) / 86_400_000;
  assert.ok(days > 29.9 && days <= 30, String(days));

  // Narrowing works; widening is a new grant.
  const narrowed = await env.browser(`/delegates/${created.grant_id}`, "PATCH", {
    scopes: [{ class: "merge", targets: ["AgentWorkforce/relay"] }],
    expires_at: new Date(Date.now() + 7 * 86_400_000).toISOString(),
  });
  assert.equal(narrowed.status, 200, narrowed.raw);
  assert.deepEqual(narrowed.body.scopes, [{ class: "merge", targets: ["AgentWorkforce/relay"] }]);
  for (const patch of [
    { scopes: [{ class: "merge", targets: ["AgentWorkforce/*"] }] },
    { scopes: [{ class: "deploy", targets: ["*:staging"] }] },
    { expires_at: new Date(Date.now() + 20 * 86_400_000).toISOString() },
  ]) {
    const widened = await env.browser(`/delegates/${created.grant_id}`, "PATCH", patch);
    assert.equal(widened.status, 400, `${JSON.stringify(patch)} ${widened.raw}`);
    assert.equal(widened.body.code, "widening_not_allowed");
  }

  // A second delegate's grant, then the owner's panic button.
  const bot2 = await env.claim("assistant-2");
  const second = await env.grant(bot2.id, [{ class: "external_comms", targets: ["slack:*"] }]);
  const list = await env.bearer("/delegates");
  assert.equal(list.body.grants.length, 2);
  const revokedOne = await request(env.origin, `/cloud${env.base}/delegates/${second.grant_id}`, {
    method: "DELETE", cookie: env.desktop.session, headers: { origin: env.origin, "content-type": "application/json" },
  });
  assert.equal(revokedOne.status, 200, revokedOne.raw);
  assert.equal(revokedOne.body.status, "revoked");
  assert.equal(revokedOne.body.revoked_reason, "owner_revoked");
  const all = await env.browser("/delegates/revoke-all", "POST", {});
  assert.equal(all.status, 200, all.raw);
  assert.deepEqual(all.body, { revoked: [created.grant_id] });
  // A member cannot revoke the whole workspace.
  const memberId = await env.addMember("carol@acme.test");
  const carol = await env.desktopSignIn({ hostName: "carol-box", userId: memberId });
  const notAdmin = await env.browser("/delegates/revoke-all", "POST", { all: true }, carol.session);
  assert.equal(notAdmin.status, 403, notAdmin.raw);
  // Carol cannot see Bob's or the owner's grants, or delete them.
  assert.deepEqual((await env.bearer("/delegates", "GET", undefined, carol.accessToken)).body.grants, []);
  const carolDelete = await env.bearer(`/delegates/${created.grant_id}`, "DELETE", undefined, carol.accessToken);
  assert.equal(carolDelete.status, 404, carolDelete.raw);

  // Revocation stays allowed while delegation is off; creation does not.
  await env.enable({ delegation_enabled: false });
  const third = await env.browser("/delegates", "POST", { delegate_agent_id: bot.id, scopes: [{ class: "merge", targets: ["a/b"] }] });
  assert.equal(third.body.code, "not_enabled");
  assert.equal((await env.browser("/delegates/revoke-all", "POST", {})).status, 200);

  const audit = await env.bearer("/delegates/audit");
  assert.equal(audit.status, 200, audit.raw);
  const names = audit.body.events.map((event: { event: string }) => event.event);
  for (const name of ["policy.updated", "delegate.claimed", "grant.created", "grant.updated", "grant.revoked"]) {
    assert.ok(names.includes(name), `${name} in ${names}`);
  }
  const jsonl = await fetch(`${env.origin}${env.base}/delegates/audit?format=jsonl&grant_id=${created.grant_id}`, {
    headers: { authorization: `Bearer ${env.desktop.accessToken}` },
  });
  assert.equal(jsonl.headers.get("content-type"), "application/x-ndjson; charset=utf-8");
  const lines = (await jsonl.text()).trim().split("\n").map(line => JSON.parse(line) as { grant_id: string });
  assert.ok(lines.length >= 3);
  assert.ok(lines.every(line => line.grant_id === created.grant_id));
});

test("policy change revokes grants that no longer fit", async (t) => {
  const env = await setup(t);
  await env.enable();
  const bot = await env.claim("assistant");
  const bot2 = await env.claim("assistant-2");
  const merge = await env.grant(bot.id, [{ class: "merge", targets: ["a/*"] }]);
  const comms = await env.grant(bot2.id, [{ class: "external_comms", targets: ["slack:*"] }]);
  const put = await env.enable({ allowed_classes: ["merge", "pr_ops"] });
  assert.deepEqual(put.body, { delegation_enabled: true, max_expiry_days: 90, allowed_classes: ["merge", "pr_ops"],
    require_tier_o: [], code_owner_match: "any_path", revoked_grants: [comms.grant_id] });
  const listed = (await env.bearer("/delegates")).body.grants as Array<{ grant_id: string; status: string; revoked_reason: string }>;
  assert.equal(listed.find(row => row.grant_id === merge.grant_id)!.status, "active");
  assert.equal(listed.find(row => row.grant_id === comms.grant_id)!.revoked_reason, "policy_changed");
  await env.bearer("/delegates/revoke-all", "POST", {});
  const refused = await env.browser("/delegates", "POST", { delegate_agent_id: bot.id, scopes: [{ class: "deploy", targets: ["*:staging"] }] });
  assert.equal(refused.status, 403, refused.raw);
  assert.equal(refused.body.code, "out_of_scope");
});

test("claims: single use, owner-bound, need the agent's own token", async (t) => {
  const env = await setup(t);
  await env.enable();
  const bot = env.world.addAgent("chat-assistant");
  const started = await env.browser("/delegates/claims", "POST");
  assert.equal(started.status, 201, started.raw);
  assert.match(started.body.code, /^dlg_[A-Za-z0-9_-]{32}$/);
  assert.match(started.body.claim_id, /^clm_[A-Za-z0-9]+$/);
  const complete = (body: Record<string, unknown>) =>
    request(env.origin, `${env.base}/delegates/claims/complete`, { method: "POST", body });

  const wrongToken = await complete({ code: started.body.code, agent_id: bot.id, agent_token: "at_not_a_real_token" });
  assert.equal(wrongToken.status, 403, wrongToken.raw);
  assert.equal(wrongToken.body.code, "invalid_agent");
  assert.equal(typeof wrongToken.body.error, "string");
  const otherAgent = env.world.addAgent("impostor");
  const mismatch = await complete({ code: started.body.code, agent_id: bot.id, agent_token: otherAgent.token });
  assert.equal(mismatch.body.code, "invalid_agent");
  const badCode = await complete({ code: "dlg_AAAABBBBCCCCDDDDEEEEFFFF", agent_id: bot.id, agent_token: bot.token });
  assert.equal(badCode.status, 404, badCode.raw);
  assert.equal(badCode.body.code, "invalid_code");

  const done = await complete({ code: started.body.code, agent_id: bot.id, agent_token: bot.token });
  assert.equal(done.status, 200, done.raw);
  assert.deepEqual(done.body, { claim_id: started.body.claim_id, agent_id: bot.id, owner_id: env.ownerId });
  const replay = await complete({ code: started.body.code, agent_id: otherAgent.id, agent_token: otherAgent.token });
  assert.equal(replay.status, 404, replay.raw);

  // An agent that already has an owner cannot be claimed again.
  const second = await env.browser("/delegates/claims", "POST");
  const again = await complete({ code: second.body.code, agent_id: bot.id, agent_token: bot.token });
  assert.equal(again.status, 409, again.raw);
  assert.equal(again.body.code, "already_bound");

  // Expired codes are refused.
  const third = await env.browser("/delegates/claims", "POST");
  await env.database.query("UPDATE delegation_claims SET expires_at = now() - interval '1 second' WHERE id = $1", [third.body.claim_id]);
  const fresh = env.world.addAgent("late-bot");
  assert.equal((await complete({ code: third.body.code, agent_id: fresh.id, agent_token: fresh.token })).status, 404);
});

// ---------------------------------------------------------------------------
// Attestation

test("attestation: a live delegate's in-scope approval is signed and verifies against the JWKS", async (t) => {
  const { env, recipient, bot, grantId } = await ready(t);
  const messageId = send(env, bot, recipient, env.approval([{ class: "merge", target: "AgentWorkforce/relay#2250" }],
    { quoted_at: "2026-11-23T07:49:00Z" }));
  const attested = await env.attest(recipient, messageId);
  assert.equal(attested.status, 200, attested.raw);
  assert.equal(attested.headers.get("cache-control"), "no-store");
  assert.equal(attested.body.verdict, "delegate", attested.raw);
  const claims = attested.body.claims;
  assert.deepEqual(Object.keys(claims).sort(), ["actions", "approval_id", "delegate_agent_id", "exp", "grant_id", "iat", "jti",
    "message_id", "owner_display", "owner_id", "recipient_agent_id", "single_use", "standing", "tier", "v", "ws"]);
  assert.equal(claims.standing, "own_owner");
  assert.equal(claims.v, 1);
  assert.equal(claims.ws, env.workspaceId);
  assert.equal(claims.owner_id, env.ownerId);
  assert.equal(claims.owner_display, "Owner");
  assert.equal(claims.delegate_agent_id, bot.id);
  assert.equal(claims.grant_id, grantId);
  assert.equal(claims.message_id, messageId);
  assert.equal(claims.recipient_agent_id, recipient.id);
  assert.equal(claims.approval_id, tierDApprovalId(env.workspaceId, messageId));
  assert.equal(claims.tier, "D");
  assert.deepEqual(claims.actions, [{ class: "merge", target: "AgentWorkforce/relay#2250" }]);
  assert.equal(claims.single_use, false);
  assert.equal(claims.exp - claims.iat, 300);

  // The compact JWS: header exactly as §16.4, signature verifies against the served JWKS.
  const [header] = (attested.body.attestation as string).split(".");
  assert.deepEqual(JSON.parse(Buffer.from(header!, "base64url").toString()), { alg: "EdDSA", typ: "relay-delegation+jws", kid: KID });
  const keys = await env.jwks();
  assert.equal(keys.keys.length, 1);
  assert.deepEqual(Object.keys(keys.keys[0]!).sort(), ["alg", "crv", "kid", "kty", "use", "x"]);
  assert.equal(keys.keys[0]!.kty, "OKP");
  assert.equal(keys.keys[0]!.crv, "Ed25519");
  assert.deepEqual(verifyDelegationJws(attested.body.attestation, keys), claims);
  // Tampering breaks it; another key does not verify it.
  const [h, p, s] = (attested.body.attestation as string).split(".");
  const forged = Buffer.from(JSON.stringify({ ...claims, actions: [{ class: "merge", target: "AgentWorkforce/*" }] })).toString("base64url");
  assert.equal(verifyDelegationJws(`${h}.${forged}.${s}`, keys), null);
  assert.equal(verifyDelegationJws(`${h}.${p}.${s}`, { keys: [{ ...keys.keys[0]!, x: randomBytes(32).toString("base64url") }] }), null);
  // Also served under the /cloud alias.
  assert.equal((await request(env.origin, "/cloud/.well-known/relay-delegation-keys.json")).status, 200);

  // Audit: the attestation with quote and its hash, and the jti.
  const [event] = await env.events("approval.attested");
  assert.equal(event!.jti, claims.jti);
  assert.equal(event!.quote, "yes merge 2250 when green");
  assert.equal(event!.quote_hash, createHash("sha256").update("yes merge 2250 when green").digest("hex"));

  // Positive verdicts are not cached: a second ask issues a fresh jti.
  const again = await env.attest(recipient, messageId);
  assert.equal(again.body.verdict, "delegate");
  assert.notEqual(again.body.claims.jti, claims.jti);
});

test("attestation refusal reasons", async (t) => {
  const { env, recipient, bot, grantId } = await ready(t);
  const merge = [{ class: "merge", target: "AgentWorkforce/relay#2250" }];
  const reason = async (messageId: string, accept?: "own_owner" | "code_owners", who = recipient) => {
    const result = await env.attest(who, messageId, accept);
    assert.equal(result.status, 200, result.raw);
    assert.equal(result.body.verdict, "none", result.raw);
    return result.body.reason as string;
  };

  // no_approval: an ordinary message, or a malformed stored approval.
  const plain = env.world.sendAs(bot.name, recipient.name, "hi").message.id;
  assert.equal(await reason(plain), "no_approval");
  assert.equal(await reason(send(env, bot, recipient, { v: 2, owner_id: env.ownerId, actions: merge })), "no_approval");
  assert.equal(await reason(send(env, bot, recipient, env.approval([{ class: "ship_it", target: "x" }]))), "no_approval");
  // Conditions are a closed set, at most 5, and GitHub ones only on a PR target.
  assert.equal(await reason(send(env, bot, recipient, env.approval([{ ...merge[0], conditions: [{ type: "weather_ok" }] }]))), "no_approval");
  assert.equal(await reason(send(env, bot, recipient, env.approval([{ class: "deploy", target: "web:staging", conditions: [{ type: "ci_green" }] }]))),
    "no_approval");
  assert.equal(await reason(send(env, bot, recipient, env.approval([{ ...merge[0],
    conditions: Array.from({ length: 6 }, () => ({ type: "mergeable" })) }]))), "no_approval");

  // not_delegate: a peer quoting the owner, or an approval naming another owner.
  const peer = env.world.addAgent("random-peer");
  assert.equal(await reason(send(env, peer, recipient, env.approval(merge))), "not_delegate");
  assert.equal(await reason(send(env, bot, recipient, env.approval(merge, { owner_id: randomUUID() }))), "not_delegate");

  // out_of_scope: the whole approval is refused when one action is outside the grant.
  assert.equal(await reason(send(env, bot, recipient, env.approval([...merge, { class: "merge", target: "Other/repo#1" }]))), "out_of_scope");
  assert.equal(await reason(send(env, bot, recipient, env.approval([{ class: "pr_ops", target: "AgentWorkforce/relay" }]))), "out_of_scope");
  // A wildcard action target is not a concrete action: the approval is malformed (as in Cloud).
  assert.equal(await reason(send(env, bot, recipient, env.approval([{ class: "merge", target: "AgentWorkforce/*" }]))), "no_approval");

  // expired: the approval's own expires_at has passed.
  assert.equal(await reason(send(env, bot, recipient, env.approval(merge, { expires_at: "2020-01-01T00:00:00Z" }))), "expired");

  // not_pending: a message for someone else, an acked delivery, a wrong token, another person's recipient.
  const elsewhere = env.world.addAgent("other-recipient");
  const forOther = send(env, bot, elsewhere, env.approval(merge));
  assert.equal(await reason(forOther), "not_pending");
  assert.equal(await reason("999999"), "not_pending");
  const acked = send(env, bot, recipient, env.approval(merge));
  env.world.deliveries.find(row => row.message.id === acked)!.acked = true;
  assert.equal(await reason(acked), "not_pending");
  const live = send(env, bot, recipient, env.approval(merge));
  assert.equal(await reason(live, "own_owner", { ...recipient, token: "at_wrong_token_value" }), "not_pending");
  const bobId = await env.addMember("bob@acme.test");
  const bobsAgent = await env.desktopIdentity("bob-coder", bobId);
  assert.equal(await reason(send(env, bot, bobsAgent, env.approval(merge)), "own_owner", bobsAgent), "not_pending");

  // tier_o_required: a default tier O class, granted, but sent as tier D.
  await env.browser(`/delegates/${grantId}`, "PATCH", { require_tier_o: ["merge"] });
  assert.equal(await reason(send(env, bot, recipient, env.approval(merge))), "tier_o_required");

  // recipient_policy: Bob's own agent (Bob's Desktop) and the owner's delegate.
  const bobDesktop = await env.desktopSignIn({ hostName: "bob-box", userId: bobId });
  const forBob = send(env, bot, bobsAgent, env.approval([{ class: "deploy", target: "web:staging" }]));
  const bobOwn = await env.attest(bobsAgent, forBob, "own_owner", bobDesktop.accessToken);
  assert.equal(bobOwn.body.reason, "recipient_policy", bobOwn.raw);
  // code_owners with no target-owners entry: only Bob's own owner counts.
  const bobNoEntry = await env.attest(bobsAgent, forBob, "code_owners", bobDesktop.accessToken);
  assert.equal(bobNoEntry.body.reason, "recipient_policy", bobNoEntry.raw);

  // revoked: after the owner revokes the grant.
  const deploy = [{ class: "deploy", target: "web:staging" }];
  const beforeRevoke = send(env, bot, recipient, env.approval(deploy));
  assert.equal((await env.attest(recipient, beforeRevoke)).body.verdict, "delegate");
  await env.bearer("/delegates/revoke-all", "POST", {});
  assert.equal(await reason(beforeRevoke), "revoked");
  assert.equal(await reason(send(env, bot, recipient, env.approval(deploy))), "revoked");

  // not_enabled: the workspace switch is off.
  await env.enable({ delegation_enabled: false });
  assert.equal(await reason(send(env, bot, recipient, env.approval(deploy))), "not_enabled");
  await env.enable();

  // expired: the grant itself has expired.
  const fresh = await env.grant(bot.id, [{ class: "deploy", targets: ["*:staging"] }]);
  await env.database.query("UPDATE delegation_grants SET expires_at = now() - interval '1 second' WHERE id = $1", [fresh.grant_id]);
  assert.equal(await reason(send(env, bot, recipient, env.approval(deploy))), "expired");

  // Every refusal is audited with its reason.
  const refused = new Set((await env.events("approval.refused")).map(row => row.reason));
  for (const code of ["no_approval", "not_delegate", "out_of_scope", "expired", "not_pending", "tier_o_required",
    "recipient_policy", "revoked", "not_enabled"]) {
    assert.ok(refused.has(code), `${code} audited`);
  }
});

test("attestation: expired grant, relay outage, wrong credentials and a released delegate fail closed", async (t) => {
  const { env, recipient, bot, grantId } = await ready(t);
  const merge = [{ class: "merge", target: "AgentWorkforce/relay#1" }];
  await env.database.query("UPDATE delegation_grants SET expires_at = now() - interval '1 second' WHERE id = $1", [grantId]);
  assert.equal((await env.attest(recipient, send(env, bot, recipient, env.approval(merge)))).body.reason, "expired");
  await env.database.query("UPDATE delegation_grants SET expires_at = now() + interval '1 day' WHERE id = $1", [grantId]);

  // A Relaycast outage on the by-message proof is `unavailable`, never a verdict.
  const messageId = send(env, bot, recipient, env.approval(merge));
  env.world.failNext("GET", `/v1/deliveries/by-message/${messageId}`, 503);
  assert.equal((await env.attest(recipient, messageId)).body.reason, "unavailable");
  assert.equal((await env.attest(recipient, messageId)).body.verdict, "delegate");

  // The attest route takes only a verified Desktop bearer.
  const cli = await env.deviceLogin();
  assert.equal((await env.attest(recipient, messageId, "own_owner", cli)).status, 403);
  assert.equal((await env.attest(recipient, messageId, "own_owner", recipient.token)).status, 401);
  const bad = await request(env.origin, `${env.base}/messaging/delegation`, {
    method: "POST", token: env.desktop.accessToken, body: { recipient_agent_id: recipient.id, recipient_token: recipient.token },
  });
  assert.equal(bad.status, 400, bad.raw);
  assert.deepEqual(bad.body, { error: "Invalid request", code: "invalid_request" });
  const extra = await request(env.origin, `${env.base}/messaging/delegation`, {
    method: "POST", token: env.desktop.accessToken,
    body: { recipient_agent_id: recipient.id, recipient_token: recipient.token, message_id: messageId, accept: "own_owner", owner_approval: {} },
  });
  assert.equal(extra.status, 400, extra.raw);

  // A released delegate revokes its grants.
  env.world.agents.get("assistant")!.status = "released";
  assert.equal((await env.attest(recipient, send(env, bot, recipient, env.approval(merge)))).body.reason, "revoked");
  const grant = (await env.bearer("/delegates")).body.grants[0];
  assert.equal(grant.revoked_reason, "agent_released");
});

test("attestation without a signing key is unavailable and the JWKS is empty", async (t) => {
  const env = await setup(t, { signing: false });
  await env.enable();
  const recipient = await env.desktopIdentity("relay-coder");
  const bot = await env.claim("assistant");
  await env.grant(bot.id, [{ class: "merge", targets: ["a/*"] }]);
  const messageId = send(env, bot, recipient, env.approval([{ class: "merge", target: "a/b" }]));
  assert.equal((await env.attest(recipient, messageId)).body.reason, "unavailable");
  assert.deepEqual(await env.jwks(), { keys: [] });
});

// ---------------------------------------------------------------------------
// Redeem, replay and revocation

test("redeem: single-use approvals are consumed once; replay and other recipients are refused", async (t) => {
  const { env, recipient, bot } = await ready(t);
  const prod = { class: "deploy", target: "relay:prod" };
  const messageId = send(env, bot, recipient, env.approval([prod]));
  const attested = await env.attest(recipient, messageId);
  assert.equal(attested.body.verdict, "delegate", attested.raw);
  assert.equal(attested.body.claims.single_use, true);
  const approvalId = attested.body.claims.approval_id as string;

  // Out-of-approval action.
  const wrong = await env.redeem(recipient, approvalId, { class: "deploy", target: "web:prod" });
  assert.deepEqual(wrong.body, { ok: false, reason: "out_of_scope" });
  // A recipient that never had it attested.
  const other = await env.desktopIdentity("second-coder");
  assert.deepEqual((await env.redeem(other, approvalId, prod)).body, { ok: false, reason: "no_approval" });
  // Unknown approval.
  assert.deepEqual((await env.redeem(recipient, "apv_unknown123", prod)).body, { ok: false, reason: "no_approval" });

  // Concurrent redeems: exactly one wins.
  const results = await Promise.all([1, 2, 3, 4].map(() => env.redeem(recipient, approvalId, prod)));
  assert.equal(results.filter(result => result.body.ok === true).length, 1, JSON.stringify(results.map(r => r.body)));
  assert.ok(results.filter(result => result.body.ok === false).every(result => result.body.reason === "consumed"));
  // Replay after consumption: refused, and re-attestation says consumed.
  assert.deepEqual((await env.redeem(recipient, approvalId, prod)).body, { ok: false, reason: "consumed" });
  assert.equal((await env.attest(recipient, messageId)).body.reason, "consumed");

  const redeemed = await env.events("approval.redeemed");
  assert.equal(redeemed.length, 1);
  const refused = new Set((await env.events("redeem.refused")).map(row => row.reason));
  for (const code of ["out_of_scope", "no_approval", "consumed"]) assert.ok(refused.has(code), code);
});

test("redeem: revocation invalidates unredeemed approvals at once", async (t) => {
  const { env, recipient, bot, grantId } = await ready(t);
  const release = { class: "release", target: "AgentWorkforce/relay" };
  const messageId = send(env, bot, recipient, env.approval([release]));
  const attested = await env.attest(recipient, messageId);
  assert.equal(attested.body.verdict, "delegate", attested.raw);
  const revoked = await env.bearer(`/delegates/${grantId}`, "DELETE");
  assert.equal(revoked.status, 200, revoked.raw);
  // The attestation is still inside its 5 minutes, but redeem re-checks.
  assert.deepEqual((await env.redeem(recipient, attested.body.claims.approval_id, release)).body, { ok: false, reason: "revoked" });
  const row = (await env.database.query<{ invalidated_at: Date | null }>(
    "SELECT invalidated_at FROM delegation_approvals WHERE id = $1", [attested.body.claims.approval_id],
  )).rows[0];
  assert.ok(row?.invalidated_at);
});

test("redeem: multi-use tier D approvals re-check without consuming; expiry is enforced", async (t) => {
  const { env, recipient, bot } = await ready(t);
  const merge = { class: "merge", target: "AgentWorkforce/relay#7" };
  const attested = await env.attest(recipient, send(env, bot, recipient, env.approval([merge])));
  const approvalId = attested.body.claims.approval_id as string;
  assert.deepEqual((await env.redeem(recipient, approvalId, merge)).body, { ok: true, consumed: false });
  assert.deepEqual((await env.redeem(recipient, approvalId, merge)).body, { ok: true, consumed: false });
  await env.database.query("UPDATE delegation_approvals SET expires_at = now() - interval '1 second' WHERE id = $1", [approvalId]);
  assert.deepEqual((await env.redeem(recipient, approvalId, merge)).body, { ok: false, reason: "expired" });
  // The redeem route is the same Desktop-bearer route.
  assert.equal((await env.redeem(recipient, approvalId, merge, await env.deviceLogin())).status, 403);
});

test("tier O: owner-minted approvals carry the delegate's message and are single-use", async (t) => {
  const { env, recipient, bot } = await ready(t);
  const secret = { class: "secret_change", target: "prod/stripe" };
  // One active grant per pair: re-grant the delegate with secret_change added.
  await env.bearer("/delegates/revoke-all", "POST", {});
  const tierD = await env.grant(bot.id, [{ class: "secret_change", targets: ["prod/*"] }]);
  assert.ok(tierD.grant_id);
  // As tier D, a default tier O class is refused.
  assert.equal((await env.attest(recipient, send(env, bot, recipient, env.approval([secret])))).body.reason, "tier_o_required");

  const minted = await env.browser("/delegates/approvals", "POST", { actions: [secret] });
  assert.equal(minted.status, 201, minted.raw);
  assert.deepEqual(Object.keys(minted.body), ["approval_id"]);
  assert.match(minted.body.approval_id, /^apv_/);
  const ref = minted.body.approval_id as string;
  // Actions must equal the minted object's.
  const mismatch = send(env, bot, recipient, env.approval([{ class: "secret_change", target: "prod/other" }], { approval_ref: ref }));
  assert.equal((await env.attest(recipient, mismatch)).body.reason, "out_of_scope");
  const messageId = send(env, bot, recipient, env.approval([secret], { approval_ref: ref }));
  const attested = await env.attest(recipient, messageId);
  assert.equal(attested.body.verdict, "delegate", attested.raw);
  assert.equal(attested.body.claims.tier, "O");
  assert.equal(attested.body.claims.approval_id, ref);
  assert.equal(attested.body.claims.single_use, true);
  assert.deepEqual((await env.redeem(recipient, ref, secret)).body, { ok: true, consumed: true });
  assert.deepEqual((await env.redeem(recipient, ref, secret)).body, { ok: false, reason: "consumed" });
  assert.equal((await env.attest(recipient, messageId)).body.reason, "consumed");
  // An unknown reference is no approval.
  assert.equal((await env.attest(recipient, send(env, bot, recipient, env.approval([secret], { approval_ref: "apv_doesnotexist" })))).body.reason,
    "no_approval");
  // Minting is human-only and bounded to 24 hours.
  const tooLong = await env.browser("/delegates/approvals", "POST", {
    actions: [secret], expires_at: new Date(Date.now() + 25 * 3_600_000).toISOString(),
  });
  assert.equal(tooLong.status, 400, tooLong.raw);
  assert.equal((await env.bearer("/delegates/approvals", "POST", { actions: [secret] }, await env.deviceLogin())).status, 403);
});

test("quote text is redacted to its hash after 90 days", async (t) => {
  const { env, recipient, bot } = await ready(t);
  await env.attest(recipient, send(env, bot, recipient, env.approval([{ class: "merge", target: "AgentWorkforce/relay#3" }])));
  await env.database.query("UPDATE delegation_audit_events SET created_at = now() - interval '91 days' WHERE event = 'approval.attested'");
  const audit = await env.bearer("/delegates/audit");
  const attested = audit.body.events.find((event: { event: string }) => event.event === "approval.attested");
  assert.equal(attested.quote, null);
  assert.match(attested.quote_hash, /^[0-9a-f]{64}$/);
  assert.ok(attested.quote_redacted_at);
  assert.deepEqual(Object.keys(attested).sort(), ["actor_agent_id", "actor_user_id", "approval_id", "auth_method", "created_at",
    "data", "event", "grant_id", "id", "message_id", "owner_id", "quote", "quote_hash", "quote_redacted_at", "reason",
    "recipient_agent_id"]);
  assert.equal(attested.auth_method, "desktop_bearer");
  assert.equal(attested.data.jti.length, 36);
});

// ---------------------------------------------------------------------------
// Standing (§5.4), prompt_approval (§9.3) and conditions (§5.5)

test("standing: code_owners accepts another person's delegate only through target-owners; repo targets fail closed", async (t) => {
  const { env, bot } = await ready(t);
  const bobId = await env.addMember("bob@acme.test");
  const bobsAgent = await env.desktopIdentity("bob-coder", bobId);
  const bobDesktop = await env.desktopSignIn({ hostName: "bob-box", userId: bobId });
  const staging = { class: "deploy", target: "web:staging" };

  // Admin-only list; members are refused; bodies are validated.
  const memberRead = await env.bearer("/delegates/target-owners", "GET", undefined, bobDesktop.accessToken);
  assert.equal(memberRead.status, 403, memberRead.raw);
  for (const bad of [[{ pattern: "*:staging" }], [{ pattern: "*:staging", repo: "not a repo" }],
    [{ pattern: "relay-*", owner_ids: [env.ownerId] }], [{ pattern: "*:staging", owner_ids: ["not-a-uuid"] }]]) {
    const refused = await env.browser("/delegates/target-owners", "PUT", bad);
    assert.equal(refused.status, 400, `${JSON.stringify(bad)} ${refused.raw}`);
  }
  const put = await env.browser("/delegates/target-owners", "PUT", [
    { pattern: "*:staging", owner_ids: [env.ownerId] },
    { pattern: "docs:*", repo: "AgentWorkforce/docs" },
  ]);
  assert.equal(put.status, 200, put.raw);
  assert.deepEqual(put.body, [{ pattern: "*:staging", owner_ids: [env.ownerId] }, { pattern: "docs:*", repo: "AgentWorkforce/docs" }]);
  assert.deepEqual((await env.bearer("/delegates/target-owners")).body, put.body);

  // The owner is a target owner of *:staging: Bob's code_owners agent accepts.
  const forBob = send(env, bot, bobsAgent, env.approval([staging]));
  const accepted = await env.attest(bobsAgent, forBob, "code_owners", bobDesktop.accessToken);
  assert.equal(accepted.body.verdict, "delegate", accepted.raw);
  assert.equal(accepted.body.claims.standing, "code_owner");
  // own_owner does not.
  assert.equal((await env.attest(bobsAgent, forBob, "own_owner", bobDesktop.accessToken)).body.reason, "recipient_policy");
  // A repo target needs CODEOWNERS through a verified GitHub link, which relay-control lacks: fail closed.
  const merge = send(env, bot, bobsAgent, env.approval([{ class: "merge", target: "AgentWorkforce/relay#2250" }]));
  assert.equal((await env.attest(bobsAgent, merge, "code_owners", bobDesktop.accessToken)).body.reason, "recipient_policy");
  // A target-owners entry that points at a repo also needs CODEOWNERS: fail closed.
  const docsBot = await env.claim("docs-bot");
  await env.grant(docsBot.id, [{ class: "deploy", targets: ["docs:*"] }]);
  const docs = send(env, docsBot, bobsAgent, env.approval([{ class: "deploy", target: "docs:staging2" }]));
  assert.equal((await env.attest(bobsAgent, docs, "code_owners", bobDesktop.accessToken)).body.reason, "recipient_policy");
  // Standing is per action: one action without it refuses the whole approval.
  const mixed = send(env, bot, bobsAgent, env.approval([staging, { class: "merge", target: "AgentWorkforce/relay#1" }]));
  assert.equal((await env.attest(bobsAgent, mixed, "code_owners", bobDesktop.accessToken)).body.reason, "recipient_policy");
});

test("prompt_approval: grant patterns, this session only, machine owner only, prompt-delegates", async (t) => {
  const env = await setup(t);
  await env.enable();
  const session = await env.desktopIdentity("relay-coder");
  const bot = await env.claim("assistant");
  // Grant targets are `*` or `<agent id>:*`.
  for (const targets of [["relay-coder"], ["ag_1:ref"], ["a/b"]]) {
    const bad = await env.browser("/delegates", "POST", { delegate_agent_id: bot.id, scopes: [{ class: "prompt_approval", targets }] });
    assert.equal(bad.status, 400, `${targets} ${bad.raw}`);
  }
  const created = await env.grant(bot.id, [{ class: "prompt_approval", targets: [`${session.id}:*`] }]);

  const ok = send(env, bot, session, env.approval([{ class: "prompt_approval", target: `${session.id}:req_42` }]));
  const attested = await env.attest(session, ok);
  assert.equal(attested.body.verdict, "delegate", attested.raw);
  assert.equal(attested.body.claims.standing, "own_owner");
  assert.deepEqual(attested.body.claims.actions, [{ class: "prompt_approval", target: `${session.id}:req_42` }]);
  // It must name this session.
  const other = await env.desktopIdentity("other-session");
  const wrongSession = send(env, bot, session, env.approval([{ class: "prompt_approval", target: `${other.id}:req_1` }]));
  assert.equal((await env.attest(session, wrongSession)).body.reason, "out_of_scope");
  // Only not_before may condition a prompt_approval.
  const badCondition = send(env, bot, session, env.approval([{ class: "prompt_approval", target: `${session.id}:r`,
    conditions: [{ type: "mergeable" }] }]));
  assert.equal((await env.attest(session, badCondition)).body.reason, "no_approval");
  // Never through code owners: Bob's session refuses even with a target-owners entry.
  const bobId = await env.addMember("bob@acme.test");
  const bobsSession = await env.desktopIdentity("bob-session", bobId);
  const bobDesktop = await env.desktopSignIn({ hostName: "bob-box", userId: bobId });
  await env.browser("/delegates/target-owners", "PUT", [{ pattern: "*", owner_ids: [env.ownerId] }]);
  const wideBot = await env.claim("wide-bot");
  await env.grant(wideBot.id, [{ class: "prompt_approval", targets: ["*"] }]);
  const forBob = send(env, wideBot, bobsSession, env.approval([{ class: "prompt_approval", target: `${bobsSession.id}:r9` }]));
  assert.equal((await env.attest(bobsSession, forBob, "code_owners", bobDesktop.accessToken)).body.reason, "recipient_policy");

  // prompt-delegates: the machine owner's delegates whose grants cover the session.
  const delegates = (token: string, who: { id: string; token: string }) => request(env.origin, `${env.base}/messaging/delegation/prompt-delegates`, {
    method: "POST", token, body: { session_agent_id: who.id, session_token: who.token },
  });
  const listed = await delegates(env.desktop.accessToken, session);
  assert.equal(listed.status, 200, listed.raw);
  assert.deepEqual(listed.body.delegates.map((row: { agent_id: string }) => row.agent_id).sort(), [bot.id, wideBot.id].sort());
  assert.ok(listed.body.delegates.some((row: { grant_id: string }) => row.grant_id === created.grant_id));
  // Another session of the owner is covered by the `*` grant only.
  const otherList = await delegates(env.desktop.accessToken, other);
  assert.deepEqual(otherList.body.delegates.map((row: { agent_id: string }) => row.agent_id), [wideBot.id]);
  // A session that is not the caller's, or a wrong token, is 403.
  const notMine = await delegates(env.desktop.accessToken, bobsSession);
  assert.equal(notMine.status, 403, notMine.raw);
  assert.deepEqual(notMine.body, { error: "The session is not yours", code: "forbidden" });
  assert.equal((await delegates(env.desktop.accessToken, { ...session, token: "at_wrong_token_value" })).status, 403);
  // Bob's own session: the owner's bot is not Bob's delegate.
  assert.deepEqual((await delegates(bobDesktop.accessToken, bobsSession)).body, { delegates: [] });
  // A plain CLI token is refused.
  assert.equal((await delegates(await env.deviceLogin(), session)).status, 403);
  // Revoked: gone.
  await env.bearer("/delegates/revoke-all", "POST", {});
  assert.deepEqual((await delegates(env.desktop.accessToken, session)).body, { delegates: [] });
});

test("conditions: not_before is checked at redeem without consuming; GitHub conditions are unavailable", async (t) => {
  const { env, recipient, bot } = await ready(t);
  const future = new Date(Date.now() + 3_600_000).toISOString();
  const release = { class: "release", target: "AgentWorkforce/relay", conditions: [{ type: "not_before", at: future }] };
  const attested = await env.attest(recipient, send(env, bot, recipient, env.approval([release])));
  assert.equal(attested.body.verdict, "delegate", attested.raw);
  assert.deepEqual(attested.body.claims.actions, [release]);
  const approvalId = attested.body.claims.approval_id as string;
  const action = { class: "release", target: "AgentWorkforce/relay" };
  const unmet = await env.redeem(recipient, approvalId, action);
  assert.deepEqual(unmet.body, { ok: false, reason: "condition_unmet", unmet: [{ type: "not_before", at: future }] });
  // Not consumed: once the time has come, the same approval redeems once.
  await env.database.query(
    `UPDATE delegation_approvals SET actions = jsonb_set(actions, '{0,conditions,0,at}', to_jsonb($2::text)) WHERE id = $1`,
    [approvalId, new Date(Date.now() - 1000).toISOString()],
  );
  assert.deepEqual((await env.redeem(recipient, approvalId, action)).body, { ok: true, consumed: true });
  assert.deepEqual((await env.redeem(recipient, approvalId, action)).body, { ok: false, reason: "consumed" });

  // GitHub conditions cannot be evaluated by relay-control: fail closed, not consumed.
  const merge = { class: "merge", target: "AgentWorkforce/relay#2250",
    conditions: [{ type: "ci_green" }, { type: "head_sha", sha: "3f2a1c9e".padEnd(40, "0") }] };
  const gh = await env.attest(recipient, send(env, bot, recipient, env.approval([merge])));
  assert.equal(gh.body.verdict, "delegate", gh.raw);
  const ghRedeem = await env.redeem(recipient, gh.body.claims.approval_id, { class: "merge", target: merge.target });
  assert.deepEqual(ghRedeem.body, { ok: false, reason: "condition_unavailable" });
  const refused = new Set((await env.events("redeem.refused")).map(row => row.reason));
  assert.ok(refused.has("condition_unmet") && refused.has("condition_unavailable"));

  // Tier O: minted conditions must equal the message's.
  const minted = await env.browser("/delegates/approvals", "POST", { actions: [release] });
  assert.equal(minted.status, 201, minted.raw);
  const differs = send(env, bot, recipient, env.approval([{ class: "release", target: "AgentWorkforce/relay" }],
    { approval_ref: minted.body.approval_id }));
  assert.equal((await env.attest(recipient, differs)).body.reason, "out_of_scope");
});

test("every delegation route is documented in openapi.yaml", () => {
  const spec = parseYaml(readFileSync(new URL("../openapi.yaml", import.meta.url), "utf8")) as { paths: Record<string, Record<string, unknown>> };
  const expected: Record<string, string[]> = {
    "/.well-known/relay-delegation-keys.json": ["get"],
    "/api/v1/workspaces/{workspaceId}/delegates": ["get", "post"],
    "/api/v1/workspaces/{workspaceId}/delegates/{grantId}": ["patch", "delete"],
    "/api/v1/workspaces/{workspaceId}/delegates/revoke-all": ["post"],
    "/api/v1/workspaces/{workspaceId}/delegates/claims": ["post"],
    "/api/v1/workspaces/{workspaceId}/delegates/claims/complete": ["post"],
    "/api/v1/workspaces/{workspaceId}/delegates/approvals": ["post"],
    "/api/v1/workspaces/{workspaceId}/delegates/audit": ["get"],
    "/api/v1/workspaces/{workspaceId}/delegates/policy": ["put"],
    "/api/v1/workspaces/{workspaceId}/delegates/target-owners": ["get", "put"],
    "/api/v1/workspaces/{workspaceId}/messaging/delegation": ["post"],
    "/api/v1/workspaces/{workspaceId}/messaging/delegation/redeem": ["post"],
    "/api/v1/workspaces/{workspaceId}/messaging/delegation/prompt-delegates": ["post"],
    "/api/v1/orgs/{organizationId}/delegation-policy": ["get", "put"],
  };
  for (const [path, methods] of Object.entries(expected)) {
    for (const method of methods) assert.ok(spec.paths[path]?.[method], `${method.toUpperCase()} ${path}`);
  }
});

test("quote_retention_days is an org setting (1–3650, default 90) that every workspace in the org follows", async (t) => {
  const { env, recipient, bot } = await ready(t);
  const orgPath = `/api/v1/orgs/${env.orgId}/delegation-policy`;
  const orgBrowser = (method: string, body?: unknown, cookie = env.desktop.session) =>
    request(env.origin, `/cloud${orgPath}`, { method, cookie, ...(method === "GET" ? {} : { body: body ?? {} }),
      headers: { origin: env.origin } });

  // Default 90 with no row; the Desktop bearer and the browser session both read it.
  assert.deepEqual((await request(env.origin, orgPath, { token: env.desktop.accessToken })).body, { quote_retention_days: 90 });
  assert.deepEqual((await orgBrowser("GET")).body, { quote_retention_days: 90 });

  // Validation: an integer from 1 to 3650, required, nothing else.
  for (const bad of [0, 3651, 1.5, "90", -1, null]) {
    const refused = await orgBrowser("PUT", { quote_retention_days: bad });
    assert.equal(refused.status, 400, `${JSON.stringify(bad)} ${refused.raw}`);
    assert.deepEqual(refused.body, { error: "quote_retention_days must be an integer from 1 to 3650", code: "invalid_request" });
  }
  assert.equal((await orgBrowser("PUT", {})).status, 400);
  assert.equal((await orgBrowser("PUT", { quote_retention_days: 30, extra: 1 })).status, 400);
  for (const days of [1, 3650, 30]) {
    const put = await orgBrowser("PUT", { quote_retention_days: days });
    assert.equal(put.status, 200, put.raw);
    assert.deepEqual(put.body, { quote_retention_days: days });
  }
  assert.deepEqual((await request(env.origin, orgPath, { token: env.desktop.accessToken })).body, { quote_retention_days: 30 });

  // Org owners and admins only; never a plain CLI token or an agent token; an unknown org id is 404.
  const memberId = await env.addMember("member@acme.test");
  const member = await env.desktopSignIn({ hostName: "member-box", userId: memberId });
  const memberPut = await orgBrowser("PUT", { quote_retention_days: 5 }, member.session);
  assert.equal(memberPut.status, 403, memberPut.raw);
  assert.equal(memberPut.body.code, "forbidden");
  assert.equal((await request(env.origin, orgPath, { token: member.accessToken })).status, 403);
  assert.equal((await request(env.origin, orgPath, { token: await env.deviceLogin() })).status, 403);
  assert.equal((await request(env.origin, orgPath, { token: recipient.token })).status, 401);
  assert.equal((await request(env.origin, `/api/v1/orgs/not-a-uuid/delegation-policy`, { token: env.desktop.accessToken })).status, 404);
  assert.equal((await request(env.origin, `/api/v1/orgs/${randomUUID()}/delegation-policy`, { token: env.desktop.accessToken })).status, 403);

  // A workspace cannot override it: the workspace policy has no such field.
  const workspaceField = await env.browser("/delegates/policy", "PUT", { delegation_enabled: true, quote_retention_days: 5 });
  assert.equal(workspaceField.status, 400, workspaceField.raw);
  assert.equal("quote_retention_days" in (await env.enable()).body, false);

  // Audited as org_policy.updated in each of the org's workspaces.
  const orgEvents = await env.database.query<{ workspace_id: string }>(
    "SELECT DISTINCT workspace_id::text FROM delegation_audit_events WHERE event = 'org_policy.updated'");
  assert.deepEqual(orgEvents.rows.map(row => row.workspace_id).sort(), [env.workspaceId, env.otherWorkspaceId].sort());

  // A 30-day window: a 31-day-old quote is redacted, a 29-day-old one is kept.
  const quoted = async (target: string) => {
    const attested = await env.attest(recipient, send(env, bot, recipient, env.approval([{ class: "merge", target }])));
    assert.equal(attested.body.verdict, "delegate", attested.raw);
    return attested.body.claims.jti as string;
  };
  const old = await quoted("AgentWorkforce/relay#31");
  const recent = await quoted("AgentWorkforce/relay#29");
  await env.database.query(
    "UPDATE delegation_audit_events SET created_at = now() - interval '31 days' WHERE data->>'jti' = $1", [old]);
  await env.database.query(
    "UPDATE delegation_audit_events SET created_at = now() - interval '29 days' WHERE data->>'jti' = $1", [recent]);
  type Event = { data: { jti?: string }; quote: string | null; quote_hash: string | null; quote_redacted_at: string | null };
  const audit = async () => (await env.bearer("/delegates/audit")).body.events as Event[];
  const byJti = (events: Event[], jti: string) => events.find(event => event.data.jti === jti)!;
  let events = await audit();
  assert.equal(byJti(events, old).quote, null);
  assert.ok(byJti(events, old).quote_redacted_at);
  assert.equal(byJti(events, old).quote_hash, createHash("sha256").update("yes merge 2250 when green").digest("hex"));
  assert.equal(byJti(events, recent).quote, "yes merge 2250 when green");
  assert.equal(byJti(events, recent).quote_redacted_at, null);

  // Shortening applies to existing quotes at the next sweep; lengthening restores nothing.
  await orgBrowser("PUT", { quote_retention_days: 5 });
  events = await audit();
  assert.equal(byJti(events, recent).quote, null);
  await orgBrowser("PUT", { quote_retention_days: 3650 });
  events = await audit();
  assert.equal(byJti(events, old).quote, null);
  assert.equal(byJti(events, recent).quote, null);
});
