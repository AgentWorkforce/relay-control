import assert from "node:assert/strict";
import test from "node:test";
import {
  CONNECTOR_KINDS, PRESETS, actionRepo, bindingFields, isValidBindingTarget, type BindingFields, coversNothing, decide, readOnlyAuthority, requiredConditionsOf, strictest,
  systemScopes, systemScopesCover, type Authority, type BindingView,
} from "../src/delegation/roles.js";
import { CLASS_DESCRIPTIONS } from "../src/delegation/scope.js";
import { attestDelegation, grantView, redeemApproval } from "../src/delegation/service.js";
import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { TrustPath } from "../src/delegation/trust.js";
import type { ActionClass } from "../src/delegation/scope.js";

// Role bindings, pure: the self-hosted twin of Cloud's lib/delegation/roles.test.ts (cloud#6665).

const NOW = new Date("2026-11-26T00:00:00Z");
const grokRoot: TrustPath = { root: { kind: "connector", oauth_grant_id: "oauth-1", connector: "grok-bot", agent_id: "grok-1",
  created_at: "2026-11-20T00:00:00.000Z" }, hops: [] };
const claimRoot: TrustPath = { root: { kind: "claim", claim_id: "clm_1", agent_id: "relay-1", created_at: "2026-11-20T00:00:00.000Z" },
  hops: [] };
const spawned: TrustPath = { ...grokRoot, hops: [{ spawn_id: "s1", actor_id: "grok-1", worker_id: "worker-1",
  created_at: "2026-11-21T00:00:00.000Z" }] };

function preset(role: "trusted" | "standard" | "read_only", over: Partial<BindingView> & Pick<BindingView, "id" | "principalKind">):
  BindingView {
  return { principalRef: null, role, classes: [...PRESETS[role].classes], requireTierO: [...PRESETS[role].requireTierO],
    prOpsLimit: PRESETS[role].prOpsLimit, requiredConditions: PRESETS[role].requiredConditions, targets: null, expiresAt: null, ...over };
}

test("parity: the preset table, class descriptions and connector kinds pin Cloud's values (cloud#6665)", () => {
  assert.deepEqual(PRESETS, {
    trusted: {
      role: "trusted", label: "Trusted",
      description: "Merges green PRs, replies and does routine PR work. Asks you before deploys, releases, deletes, secrets and spending.",
      classes: ["merge", "pr_ops", "external_comms", "deploy", "release", "destructive", "secret_change", "spend"],
      requireTierO: ["deploy", "release", "destructive", "secret_change", "spend"],
      prOpsLimit: null,
      requiredConditions: { merge: [{ type: "ci_green" }, { type: "mergeable" }] },
    },
    standard: {
      role: "standard", label: "Standard",
      description: "Does routine PR work. Asks you before merges, deploys, deletes and secrets.",
      classes: ["pr_ops", "merge", "deploy", "destructive", "secret_change"],
      requireTierO: ["merge", "deploy", "destructive", "secret_change"],
      prOpsLimit: null,
      requiredConditions: {},
    },
    read_only: {
      role: "read_only", label: "Read-only",
      description: "Reads and reports. May comment on PRs, nothing else.",
      classes: ["pr_ops"],
      requireTierO: [],
      prOpsLimit: ["comment"],
      requiredConditions: {},
    },
  });
  assert.deepEqual(CLASS_DESCRIPTIONS, {
    merge: "Merge a pull request.",
    pr_ops: "Routine pull request work: comment, label, request a review, re-run CI, close or reopen.",
    deploy: "Deploy to an environment.",
    release: "Publish a release, or land a branch for one.",
    secret_change: "Change secrets, credentials or access.",
    destructive: "Delete, or change something that cannot be undone.",
    spend: "Spend money or buy resources.",
    external_comms: "Send messages outside the workspace, such as Slack or email.",
    prompt_approval: "Answer permission prompts in your own sessions.",
    config_change: "Change one setting of your own agent session.",
  });
  // relay-control's connector classifier also knows cursor-cloud, which Cloud's does not.
  assert.deepEqual([...CONNECTOR_KINDS], ["grok-bot", "chatgpt", "cursor-cloud", "muse", "mcp"]);
});

test("no preset opens a delegated path for deploys, releases, deletes, secrets or spend", () => {
  for (const role of ["trusted", "standard", "read_only"] as const) {
    for (const item of ["deploy", "release", "destructive", "secret_change", "spend"] as const) {
      if (PRESETS[role].classes.includes(item)) assert.ok(PRESETS[role].requireTierO.includes(item), `${role} ${item}`);
    }
  }
});

test("decide: the most specific binding wins, with no union; an exclusion never falls through", () => {
  const relay = preset("standard", { id: "dtr_a_relay", principalKind: "relay_agents" });
  const grok = preset("trusted", { id: "dtr_b_grok", principalKind: "connector_kind", principalRef: "grok-bot" });
  const group = preset("read_only", { id: "dtr_c_group", principalKind: "group", principalRef: "grp_x" });
  const agent = preset("trusted", { id: "dtr_d_agent", principalKind: "agent", principalRef: "grok-1" });
  assert.equal((decide([relay, grok], { agentId: "grok-1", path: grokRoot, groupIds: [] }, NOW) as { binding: BindingView }).binding.id, grok.id);
  assert.equal((decide([relay, grok], { agentId: "relay-1", path: claimRoot, groupIds: [] }, NOW) as { binding: BindingView }).binding.id,
    relay.id);
  assert.equal((decide([relay, grok, group], { agentId: "grok-1", path: grokRoot, groupIds: ["grp_x"] }, NOW) as { source: string }).source,
    "group");
  assert.equal((decide([relay, grok, group, agent], { agentId: "grok-1", path: grokRoot, groupIds: ["grp_x"] }, NOW) as
    { source: string }).source, "agent");
  const excluded: BindingView = { ...agent, id: "dtr_e_excl", role: "excluded", classes: [], requireTierO: [], requiredConditions: {} };
  assert.deepEqual(decide([relay, grok, group, excluded], { agentId: "grok-1", path: grokRoot, groupIds: ["grp_x"] }, NOW),
    { kind: "excluded", binding: excluded });
});

test("decide: a launched agent never inherits its spawner's role; the legacy rule keeps the spawn tree", () => {
  const relay = preset("trusted", { id: "dtr_a_relay", principalKind: "relay_agents" });
  const decision = decide([relay], { agentId: "worker-1", path: spawned, groupIds: [] }, NOW);
  assert.equal(decision.kind === "covered" && decision.source, "spawn_default");
  assert.deepEqual(decision.kind === "covered" && decision.authority, readOnlyAuthority());
  const legacy: BindingView = { id: "dtr_z_legacy", principalKind: "all_agents", principalRef: null, role: null, classes: null,
    requireTierO: [], prOpsLimit: null, requiredConditions: {}, targets: null, expiresAt: null };
  assert.equal((decide([legacy], { agentId: "worker-1", path: spawned, groupIds: [] }, NOW) as { source: string }).source, "legacy");
  assert.equal((decide([legacy, relay], { agentId: "worker-1", path: spawned, groupIds: [] }, NOW) as { source: string }).source,
    "spawn_default");
});

test("review B1: two groups whose repo targets do not overlap cover nothing, never every repo", () => {
  const a = preset("trusted", { id: "dtr_g_a", principalKind: "group", principalRef: "grp_a", targets: ["acme/*"] });
  const b = preset("trusted", { id: "dtr_g_b", principalKind: "group", principalRef: "grp_b", targets: ["other/*"] });
  const none = strictest(authorityOf(a), authorityOf(b));
  assert.deepEqual(none.targets, []);
  assert.equal(coversNothing(none), true);
  assert.throws(() => systemScopes(none));
  const decision = decide([a, b], { agentId: "grok-1", path: grokRoot, groupIds: ["grp_a", "grp_b"] }, NOW);
  assert.equal(decision.kind === "covered" && coversNothing(decision.authority), true);
  // An overlap covers only the overlap.
  const narrow = preset("trusted", { id: "dtr_g_c", principalKind: "group", principalRef: "grp_c", targets: ["acme/web"] });
  const overlap = strictest(authorityOf(a), authorityOf(narrow));
  assert.deepEqual(overlap.targets, ["acme/web"]);
  const scopes = systemScopes(overlap);
  assert.equal(systemScopesCover(scopes, { class: "merge", target: "acme/web#3" }), true);
  assert.equal(systemScopesCover(scopes, { class: "merge", target: "acme/api#3" }), false);
  // A legacy authority always grants.
  assert.equal(coversNothing({ classes: null, requireTierO: [], prOpsLimit: null, requiredConditions: {}, targets: null,
    expiresAt: null }), false);
  // An empty pr_ops limit intersection refuses every op.
  const base: Authority = { classes: ["pr_ops"], requireTierO: [], prOpsLimit: ["comment"], requiredConditions: {}, targets: null,
    expiresAt: null };
  const noOps = strictest(base, { ...base, prOpsLimit: ["label"] });
  assert.deepEqual(noOps.prOpsLimit, []);
  for (const op of ["comment", "label=bug", "close"]) {
    assert.equal(systemScopesCover(systemScopes(noOps), { class: "pr_ops", target: `acme/web#7:${op}` }), false, op);
  }
});

function authorityOf(binding: BindingView): Authority {
  return { classes: binding.classes, requireTierO: binding.requireTierO, prOpsLimit: binding.prOpsLimit,
    requiredConditions: binding.requiredConditions, targets: binding.targets, expiresAt: binding.expiresAt };
}

test("system scopes: Read-only is PR comments only; repo targets limit repo-shaped classes and fail closed without a repo", () => {
  const readOnly = systemScopes(readOnlyAuthority());
  assert.equal(systemScopesCover(readOnly, { class: "pr_ops", target: "acme/web#12:comment" }), true);
  for (const op of ["close", "reopen", "rerun_ci", "label=bug", "unlabel=bug", "request_review=octocat"]) {
    assert.equal(systemScopesCover(readOnly, { class: "pr_ops", target: `acme/web#12:${op}` }), false, op);
  }
  assert.equal(systemScopesCover(readOnly, { class: "merge", target: "acme/web#12" }), false);
  const scoped = systemScopes({ classes: ["merge", "pr_ops", "external_comms", "prompt_approval"], requireTierO: [], prOpsLimit: null,
    requiredConditions: {}, targets: ["acme/*"], expiresAt: null });
  assert.equal(systemScopesCover(scoped, { class: "merge", target: "acme/web#3" }), true);
  assert.equal(systemScopesCover(scoped, { class: "merge", target: "other/web#3" }), false);
  assert.equal(systemScopesCover(scoped, { class: "pr_ops", target: "acme/web#3:close" }), true);
  assert.equal(systemScopesCover(scoped, { class: "external_comms", target: "slack:#general" }), false);
  assert.equal(systemScopesCover(scoped, { class: "prompt_approval", target: "agent-1:req-1:approve" }), true);
  assert.equal(systemScopesCover([], { class: "deploy", target: "anything" }), true);
  assert.equal(actionRepo({ class: "deploy", target: "acme/web:prod" }), "acme/web");
  const trusted = systemScopes({ classes: [...PRESETS.trusted.classes], requireTierO: [], prOpsLimit: null,
    requiredConditions: PRESETS.trusted.requiredConditions, targets: null, expiresAt: null });
  assert.deepEqual(requiredConditionsOf(trusted, "merge"), [{ type: "ci_green" }, { type: "mergeable" }]);
});

test("bindingFields: presets resolve once; custom roles are checked; only an agent can be excluded", () => {
  assert.equal((bindingFields({ role: "trusted" }, "relay_agents", null, NOW) as { role: string }).role, "trusted");
  assert.equal(typeof bindingFields({ role: "trusted", classes: ["merge"] }, "relay_agents", null, NOW), "string");
  assert.equal(typeof bindingFields({ role: "custom", classes: ["merge"], require_tier_o: ["deploy"] }, "agent", null, NOW), "string");
  assert.equal(typeof bindingFields({ role: "custom", classes: ["merge"], pr_ops_limit: ["comment"] }, "agent", null, NOW), "string");
  assert.equal(typeof bindingFields({ role: "excluded" }, "group", null, NOW), "string");
  assert.equal((bindingFields({ role: "excluded" }, "agent", null, NOW) as { classes: string[] }).classes.length, 0);
  assert.equal(typeof bindingFields({ role: "trusted", expires_at: "2026-01-01T00:00:00Z" }, "relay_agents", null, NOW), "string");
});

test("parity c1de4d1f1: the spawn default keeps the root binding's repos and expiry; conditions only on merge and pr_ops", () => {
  const until = new Date("2027-01-01T00:00:00Z");
  const relay = preset("trusted", { id: "dtr_a_relay", principalKind: "relay_agents", targets: ["acme/*"], expiresAt: until });
  const decision = decide([relay], { agentId: "worker-1", path: spawned, groupIds: [] }, NOW);
  assert.ok(decision.kind === "covered");
  assert.deepEqual([decision.authority.targets, decision.authority.expiresAt], [["acme/*"], until]);
  const scopes = systemScopes(decision.authority);
  assert.equal(systemScopesCover(scopes, { class: "pr_ops", target: "acme/web#7:comment" }), true);
  assert.equal(systemScopesCover(scopes, { class: "pr_ops", target: "other/web#7:comment" }), false);
  assert.equal(typeof bindingFields({ role: "custom", classes: ["deploy"], required_conditions: { deploy: [{ type: "ci_green" }] } },
    "agent", null, NOW), "string");
  assert.deepEqual((bindingFields({ role: "custom", classes: ["merge", "deploy"], required_conditions: { merge: [{ type: "mergeable" }] } },
    "agent", null, NOW) as { requiredConditions: unknown }).requiredConditions, { merge: [{ type: "mergeable" }] });
});

test("review N1: a thrown error, a 40P01 deadlock included, answers `unavailable` at attest and redeem, never a 500", async () => {
  const deadlock = Object.assign(new Error("deadlock detected"), { code: "40P01" });
  const database = {
    query: async () => { throw deadlock; },
    exec: async () => { throw deadlock; },
    transaction: async () => { throw deadlock; },
    close: async () => {},
  };
  const deps = { database, relaycast: {}, signer: null, gateOnly: false, quoteKey: Buffer.alloc(32), now: () => new Date() } as never;
  const workspace = { id: "00000000-0000-4000-8000-000000000001", organizationId: "org", relaycastWorkspaceId: "rw", relaycastApiKey: "rk" };
  const common = { workspace, callerUserId: "00000000-0000-4000-8000-000000000002", recipientAgentId: "ag_r", recipientToken: "t" };
  assert.deepEqual(await attestDelegation(deps, { ...common, messageId: "m1", accept: "code_owners", authMethod: "desktop_bearer" }),
    { verdict: "none", reason: "unavailable" });
  assert.deepEqual(await redeemApproval(deps, { ...common, approvalId: "apv_abcdefgh", action: { class: "merge", target: "a/b#1" },
    authMethod: "desktop_bearer" }), { ok: false, reason: "unavailable" });
});

test("review: a role binding's system grant validates against the published grant response schema", () => {
  const spec = parseYaml(readFileSync(new URL("../openapi.yaml", import.meta.url), "utf8"));
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  ajv.addSchema({ $id: "openapi", components: spec.components });
  const validate = ajv.compile({ $ref: "openapi#/components/schemas/DelegateGrant" });
  const now = new Date("2026-11-26T00:00:00Z");
  const row = (scopes: unknown) => ({ id: "grt_x", workspace_id: "ws", organization_id: "org", owner_user_id: "owner",
    delegate_agent_id: "grok-1", delegate_agent_name: "grok", scopes, require_tier_o: [], status: "active",
    expires_at: "9999-12-31T00:00:00.000Z", created_auth_method: "system", created_at: now, updated_at: now, revoked_at: null,
    revoked_by: null, revoked_reason: null, trust_rule_id: "dtr_x", trust_path: null });
  const scopes = [
    ...systemScopes(readOnlyAuthority()),
    ...systemScopes({ classes: [...PRESETS.trusted.classes], requireTierO: [], prOpsLimit: null,
      requiredConditions: PRESETS.trusted.requiredConditions, targets: ["acme/*"], expiresAt: null }),
  ];
  const view = grantView(row(scopes) as never, now);
  assert.equal(validate(view), true, JSON.stringify(validate.errors));
  assert.ok(scopes.some(scope => scope.targets.length === 0 && scope.ops) && scopes.some(scope => scope.conditions));
});

test("review: a binding target needs a concrete owner; a PATCH that keeps the role keeps the authority saved with it", () => {
  for (const ok of ["acme/web", "acme/*", "Acme-1/web.app"]) assert.equal(isValidBindingTarget(ok), true, ok);
  for (const bad of ["*/web", "*/*", "acme", "acme/web#1", "acme/web:x", "acme/we*"]) assert.equal(isValidBindingTarget(bad), false, bad);
  // A binding saved under an older Trusted preset (here: deploy not asked first) keeps that authority on a
  // targets-only PATCH; choosing the role again resolves today's preset.
  const saved = { role: "trusted" as const, classes: ["merge", "pr_ops", "deploy"] as ActionClass[], requireTierO: [] as ActionClass[],
    prOpsLimit: null, requiredConditions: {}, targets: null, expiresAt: null };
  const kept = bindingFields({ targets: ["acme/*"] }, "relay_agents", saved, NOW) as BindingFields;
  assert.deepEqual([kept.classes, kept.requireTierO, kept.targets], [saved.classes, [], ["acme/*"]]);
  const chosen = bindingFields({ role: "trusted" }, "relay_agents", saved, NOW) as BindingFields;
  assert.deepEqual(chosen.classes, PRESETS.trusted.classes);
});
