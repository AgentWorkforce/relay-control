import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, randomUUID, sign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import test, { type TestContext } from "node:test";
import { parse as parseYaml } from "yaml";
import { loadDelegationOidcIssuers } from "../src/config.js";
import { encryptSecret } from "../src/crypto.js";
import { validReleaseTarget } from "../src/delegation/scope.js";
import { copilotDesktopSetup } from "./support/copilot-desktop.js";
import { request } from "./support/harness.js";

const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const GITHUB = "https://token.actions.githubusercontent.com";
const GHES = "https://ghe.example.test/_services/token";
const SHA = "3f2a1c9e".padEnd(40, "0");
const REPO = "AgentWorkforce/relay-app";
const WORKFLOW = `${REPO}/.github/workflows/desktop-promote.yml@refs/heads/main`;
const STABLE = `${REPO}:stable:v2026.11.7:${SHA}:123456789`;
const BETA = `${REPO}:beta:v2026.11.7:${SHA}:123456789`;

type Issuer = { iss: string; kid: string; privateKey: KeyObject; jwk: Record<string, unknown> };

function issuer(iss: string, kid = `k-${randomBytes(4).toString("hex")}`): Issuer {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return { iss, kid, privateKey, jwk: { ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" } };
}

/** OpenID discovery and JWKS for the given issuers, as GitHub serves them. */
function oidcFetch(issuers: Issuer[]): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input instanceof Request ? input.url : input);
    for (const item of issuers) {
      if (url === `${item.iss}/.well-known/openid-configuration`) {
        return Response.json({ issuer: item.iss, jwks_uri: `${item.iss}/.well-known/jwks` });
      }
      if (url === `${item.iss}/.well-known/jwks`) return Response.json({ keys: [item.jwk] });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
}

function mint(by: Issuer, claims: Record<string, unknown>, signer: KeyObject = by.privateKey): string {
  const head = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: by.kid })).toString("base64url");
  const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return `${head}.${body}.${sign("sha256", Buffer.from(`${head}.${body}`), signer).toString("base64url")}`;
}

async function setup(t: TestContext) {
  const github = issuer(GITHUB);
  const ghes = issuer(GHES);
  const seed = randomBytes(32);
  const env = await copilotDesktopSetup(t, { delegationOidcFetch: oidcFetch([github, ghes]) }, undefined,
    { delegationSigning: { kid: "dlg-test", seed, previous: [] }, delegationOidcIssuers: [GHES] });
  const desktop = await env.desktopSignIn({ hostName: "owner-box" });
  const base = `/api/v1/workspaces/${env.workspaceId}`;
  const browser = (path: string, method: string, body?: unknown, cookie = desktop.session) =>
    request(env.origin, `/cloud${base}${path}`, { method, cookie, ...(method === "GET" ? {} : { body: body ?? {} }),
      headers: { origin: env.origin } });
  const bearer = (path: string, method = "GET", body?: unknown, token = desktop.accessToken) =>
    request(env.origin, `${base}${path}`, { method, token, ...(body === undefined ? {} : { body }) });

  assert.equal((await browser("/delegates/policy", "PUT", { delegation_enabled: true })).status, 200);
  // The owner's coding agent (recipient) and their claimed assistant (delegate).
  const recipient = env.world.addAgent("relay-coder");
  await env.database.query(
    `INSERT INTO desktop_relay_identities
       (id, workspace_id, organization_id, user_id, relaycast_workspace_id, source_id, agent_name,
        agent_remote_id, address, token_ciphertext)
     VALUES ($1, $2, $3, $4, 'rw_primary', $5, 'relay-coder', $6, $7, $8)`,
    [randomUUID(), env.workspaceId, env.orgId, env.ownerId, randomUUID(), recipient.id,
      `relay-coder@cloud-${recipient.id}`, encryptSecret(recipient.token, KEYRING.active)],
  );
  const assistant = env.world.addAgent("assistant");
  const claim = await browser("/delegates/claims", "POST");
  assert.equal((await request(env.origin, `${base}/delegates/claims/complete`, {
    method: "POST", body: { code: claim.body.code, agent_id: assistant.id, agent_token: assistant.token },
  })).status, 200);
  const grant = await browser("/delegates", "POST", {
    delegate_agent_id: assistant.id, scopes: [{ class: "release", targets: [`${REPO}:*:*:*:*`, REPO] }],
  });
  assert.equal(grant.status, 201, grant.raw);

  /** A delegate's tier D approval for `targets`, attested to the recipient so Control records it. */
  async function approval(targets: string[]) {
    const messageId = env.world.sendApprovalAs("assistant", "relay-coder", "ship it", {
      v: 1, owner_id: env.ownerId, actions: targets.map(target => ({ class: "release", target })),
    }).message.id;
    const attested = await request(env.origin, `${base}/messaging/delegation`, {
      method: "POST", token: desktop.accessToken,
      body: { recipient_agent_id: recipient.id, recipient_token: recipient.token, message_id: messageId },
    });
    assert.equal(attested.body.verdict, "delegate", attested.raw);
    return attested.body.claims.approval_id as string;
  }

  const workflowClaims = (extra: Record<string, unknown> = {}) => {
    const now = Math.floor(Date.now() / 1000);
    return { iss: GITHUB, aud: env.origin, sub: `repo:${REPO}:ref:refs/heads/main`, repository: REPO,
      job_workflow_ref: WORKFLOW, ref: "refs/heads/main", event_name: "workflow_dispatch", run_id: "777000111",
      run_attempt: "1", iat: now - 5, nbf: now - 5, exp: now + 300, ...extra };
  };
  const redeem = (token: string | null, approvalId: string, target = STABLE, extra: Record<string, unknown> = {}) =>
    request(env.origin, `${base}/delegates/gates/redeem`, {
      method: "POST", ...(token ? { token } : {}),
      body: { approval_id: approvalId, action: { class: "release", target }, ...extra },
    });
  async function gate(extra: Record<string, unknown> = {}) {
    const created = await browser("/delegates/gates", "POST", { repo: REPO, job_workflow_ref: WORKFLOW,
      ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:`, ...extra });
    assert.equal(created.status, 201, created.raw);
    return created.body;
  }
  async function events(event: string) {
    return (await env.database.query<{ reason: string | null; data: Record<string, unknown> }>(
      "SELECT reason, data FROM delegation_audit_events WHERE event = $1 ORDER BY id", [event])).rows;
  }
  return { ...env, github, ghes, desktop, base, browser, bearer, approval, workflowClaims, redeem, gate, events };
}

test("release target grammar (§11a.2)", () => {
  assert.ok(validReleaseTarget(STABLE));
  assert.ok(validReleaseTarget(`${STABLE}:mac-universal`));
  assert.ok(validReleaseTarget(`${REPO}:land:main:${SHA}`));
  assert.ok(validReleaseTarget(`${REPO}:land:feature/x:${SHA}`));
  assert.ok(validReleaseTarget(`${REPO}:ios:testflight:2026.11.7.3:${SHA}`));
  for (const bad of [
    REPO, `${REPO}:*`, `${REPO}:stable`, `${REPO}:stable:2026.11.7:${SHA}:1`, `${REPO}:stable:v1:${SHA.slice(0, 39)}:1`,
    `${REPO}:stable:v1:${SHA.toUpperCase()}:1`, `${REPO}:stable:v1:${SHA}:0`, `${REPO}:stable:v1:${SHA}`,
    `${REPO}:land:main`, `${REPO}:ios:testflight:12`, `${REPO}:land:v1:${SHA}:12`, "everything", `${REPO}:stable:v1:${SHA}:1:a:b`,
  ]) assert.equal(validReleaseTarget(bad), false, bad);
});

test("OIDC issuer config: https only, at most 8, GitHub is built in", () => {
  assert.deepEqual(loadDelegationOidcIssuers({}), []);
  assert.deepEqual(loadDelegationOidcIssuers({ SELFHOST_DELEGATION_OIDC_ISSUERS: `${GHES}/, ${GHES}` }), [GHES]);
  assert.throws(() => loadDelegationOidcIssuers({ SELFHOST_DELEGATION_OIDC_ISSUERS: "http://ghe.example" }), /https/);
  assert.throws(() => loadDelegationOidcIssuers({ SELFHOST_DELEGATION_OIDC_ISSUERS: "https://x.example/?q=1" }), /https/);
  assert.throws(() => loadDelegationOidcIssuers({
    SELFHOST_DELEGATION_OIDC_ISSUERS: Array.from({ length: 9 }, (_, i) => `https://i${i}.example`).join(","),
  }), /at most 8/);
});

test("gate registry: owner session or verified Desktop sign-in, validated, listed and deleted", async (t) => {
  const env = await setup(t);
  for (const bad of [
    { repo: REPO, job_workflow_ref: "desktop-promote.yml", ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:` },
    { repo: REPO, job_workflow_ref: WORKFLOW, ref: "main", event: "workflow_dispatch", target_prefix: `${REPO}:` },
    { repo: REPO, job_workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "Workflow Dispatch", target_prefix: `${REPO}:` },
    { repo: REPO, job_workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: "Other/repo:" },
    { repo: REPO, job_workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:`, extra: 1 },
  ]) {
    const refused = await env.browser("/delegates/gates", "POST", bad);
    assert.equal(refused.status, 400, `${JSON.stringify(bad)} ${refused.raw}`);
  }
  // A plain CLI token and an agent token cannot register a gate.
  const body = { repo: REPO, job_workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:` };
  assert.equal((await env.bearer("/delegates/gates", "POST", body, await env.deviceLogin())).status, 403);
  // The verified Desktop sign-in may (§4.1: no step-up, no browser confirmation).
  const viaDesktop = await env.bearer("/delegates/gates", "POST", body);
  assert.equal(viaDesktop.status, 201, viaDesktop.raw);
  assert.match(viaDesktop.body.gate_id, /^gate_[A-Za-z0-9]+$/);
  assert.deepEqual(Object.keys(viaDesktop.body).sort(),
    ["created_at", "event", "gate_id", "job_workflow_ref", "owner_id", "ref", "ref_pattern", "repo", "target_prefix"]);
  assert.equal(viaDesktop.body.ref_pattern, null);
  const duplicate = await env.browser("/delegates/gates", "POST", body);
  assert.equal(duplicate.status, 409, duplicate.raw);
  assert.equal(duplicate.body.code, "gate_exists");
  const listed = await env.bearer("/delegates/gates");
  assert.deepEqual(listed.body.gates.map((gate: { gate_id: string }) => gate.gate_id), [viaDesktop.body.gate_id]);
  // Another member neither sees nor deletes it.
  const memberId = await env.addMember("member@acme.test");
  const member = await env.desktopSignIn({ hostName: "member-box", userId: memberId });
  assert.deepEqual((await env.bearer("/delegates/gates", "GET", undefined, member.accessToken)).body.gates, []);
  assert.equal((await env.bearer(`/delegates/gates/${viaDesktop.body.gate_id}`, "DELETE", undefined, member.accessToken)).status, 404);
  const deleted = await env.bearer(`/delegates/gates/${viaDesktop.body.gate_id}`, "DELETE");
  assert.equal(deleted.status, 200, deleted.raw);
  assert.deepEqual((await env.bearer("/delegates/gates")).body.gates, []);
  // Registering needs delegation on.
  await env.browser("/delegates/policy", "PUT", { delegation_enabled: false });
  assert.equal((await env.browser("/delegates/gates", "POST", body)).body.code, "not_enabled");
  const audited = (await env.database.query<{ event: string }>(
    "SELECT event FROM delegation_audit_events WHERE event LIKE 'gate.%' ORDER BY id")).rows.map(row => row.event);
  assert.deepEqual(audited, ["gate.registered", "gate.deleted"]);
});

test("gate redeem: OIDC must verify (forged, expired, wrong audience or issuer are oidc_invalid)", async (t) => {
  const env = await setup(t);
  await env.gate();
  const approvalId = await env.approval([STABLE]);
  const forger = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  const stranger = issuer("https://token.evil.example");
  const now = Math.floor(Date.now() / 1000);
  const cases: Array<[string, string]> = [
    ["forged signature", mint(env.github, env.workflowClaims(), forger)],
    ["expired", mint(env.github, env.workflowClaims({ iat: now - 900, nbf: now - 900, exp: now - 120 }))],
    ["wrong audience", mint(env.github, env.workflowClaims({ aud: "https://cloud.example.com" }))],
    ["unlisted issuer", mint(stranger, env.workflowClaims({ iss: stranger.iss }))],
    ["not yet valid", mint(env.github, env.workflowClaims({ nbf: now + 600, iat: now + 600, exp: now + 900 }))],
    ["garbage", "not.a.jwt"],
  ];
  for (const [name, token] of cases) {
    const refused = await env.redeem(token, approvalId);
    assert.equal(refused.status, 200, `${name} ${refused.raw}`);
    assert.deepEqual(refused.body, { ok: false, reason: "oidc_invalid" }, name);
  }
  // No bearer at all is 401, before anything is read.
  const missing = await env.redeem(null, approvalId);
  assert.equal(missing.status, 401, missing.raw);
  assert.equal(missing.body.code, "unauthorized");
  // Still unconsumed: the real workflow redeems it.
  assert.deepEqual((await env.redeem(mint(env.github, env.workflowClaims()), approvalId)).body, { ok: true, consumed: true });
  // A self-host's configured issuer is accepted the same way.
  const second = await env.approval([BETA]);
  const ghesToken = mint(env.ghes, env.workflowClaims({ iss: GHES, run_id: "42" }));
  assert.deepEqual((await env.redeem(ghesToken, second, BETA)).body, { ok: true, consumed: true });
  const refused = await env.events("gate.refused");
  assert.equal(refused.filter(row => row.reason === "oidc_invalid").length, cases.length);
  // An unverified token's claims are never logged.
  assert.ok(refused.every(row => row.data.repository === undefined));
});

test("gate redeem: repository, job_workflow_ref, ref and event must all match a registered gate", async (t) => {
  const env = await setup(t);
  const approvalId = await env.approval([STABLE]);
  const token = (extra: Record<string, unknown> = {}) => mint(env.github, env.workflowClaims(extra));
  // No gate for the repository at all.
  assert.deepEqual((await env.redeem(token(), approvalId)).body, { ok: false, reason: "gate_unknown" });
  await env.gate();
  // The same repository's workflow edited on another branch also gets a token: refused.
  const otherBranch = token({ job_workflow_ref: `${REPO}/.github/workflows/desktop-promote.yml@refs/heads/attacker`,
    ref: "refs/heads/attacker" });
  assert.deepEqual((await env.redeem(otherBranch, approvalId)).body, { ok: false, reason: "gate_mismatch" });
  const otherWorkflow = token({ job_workflow_ref: `${REPO}/.github/workflows/ci.yml@refs/heads/main` });
  assert.deepEqual((await env.redeem(otherWorkflow, approvalId)).body, { ok: false, reason: "gate_mismatch" });
  assert.deepEqual((await env.redeem(token({ event_name: "push" }), approvalId)).body, { ok: false, reason: "gate_mismatch" });
  assert.deepEqual((await env.redeem(token({ ref: "refs/heads/release" }), approvalId)).body, { ok: false, reason: "gate_mismatch" });
  assert.deepEqual((await env.redeem(token({ repository: "AgentWorkforce/relay" }), approvalId)).body,
    { ok: false, reason: "gate_unknown" });
  // Exact match redeems.
  assert.deepEqual((await env.redeem(token(), approvalId)).body, { ok: true, consumed: true });
  const redeemed = await env.events("gate.redeemed");
  assert.equal(redeemed.length, 1);
  assert.equal(redeemed[0]!.data.run_id, "777000111");
  assert.equal(redeemed[0]!.data.job_workflow_ref, WORKFLOW);
});

test("gate redeem: single use bound to run_id; any later redeem in the same run is same_run, another run is consumed", async (t) => {
  const env = await setup(t);
  await env.gate();
  // A second job of the same release run (for example promote, then bridge) has its own gate.
  const bridge = `${REPO}/.github/workflows/desktop-bridge.yml@refs/heads/main`;
  await env.gate({ job_workflow_ref: bridge });
  const approvalId = await env.approval([STABLE]);
  const run = (runId: string, attempt: string, extra: Record<string, unknown> = {}) =>
    mint(env.github, env.workflowClaims({ run_id: runId, run_attempt: attempt, ...extra }));
  assert.deepEqual((await env.redeem(run("900", "1"), approvalId)).body, { ok: true, consumed: true });
  // The same run again: the same attempt, a later attempt, or another job of it.
  const sameRun = { ok: true, consumed: true, same_run: true };
  assert.deepEqual((await env.redeem(run("900", "1"), approvalId)).body, sameRun);
  assert.deepEqual((await env.redeem(run("900", "2"), approvalId)).body, sameRun);
  assert.deepEqual((await env.redeem(run("900", "1", { job_workflow_ref: bridge }), approvalId)).body, sameRun);
  // Any other run is consumed, whatever its attempt.
  assert.deepEqual((await env.redeem(run("901", "1"), approvalId)).body, { ok: false, reason: "consumed" });
  assert.deepEqual((await env.redeem(run("901", "2"), approvalId)).body, { ok: false, reason: "consumed" });
  // Concurrent first redeems by different runs: exactly one wins.
  const fresh = await env.approval([BETA]);
  const results = await Promise.all(["31", "32", "33", "34"].map(id => env.redeem(run(id, "1"), fresh, BETA)));
  assert.equal(results.filter(result => result.body.ok === true).length, 1);
  const bound = await env.database.query<{ run_id: string }>(
    "SELECT run_id FROM delegation_gate_redemptions WHERE approval_id = $1", [approvalId]);
  assert.deepEqual(bound.rows.map(row => row.run_id), ["900"]);
  const redeemed = await env.events("gate.redeemed");
  assert.deepEqual(redeemed.map(row => row.data.same_run), [false, true, true, true, false]);
});

test("gate redeem: dry_run runs every check, never consumes, and is audited as dry_run", async (t) => {
  const env = await setup(t);
  await env.gate({ target_prefix: `${REPO}:stable:` });
  const token = (runId = "500") => mint(env.github, env.workflowClaims({ run_id: runId }));
  const approvalId = await env.approval([STABLE]);
  const dry = { dry_run: true };
  assert.deepEqual((await env.redeem(token(), approvalId, STABLE, dry)).body, { ok: true, dry_run: true });
  assert.deepEqual((await env.redeem(token(), approvalId, STABLE, dry)).body, { ok: true, dry_run: true });
  // Nothing was consumed: a real redeem by any run still succeeds.
  const row = await env.database.query<{ consumed_at: Date | null }>(
    "SELECT consumed_at FROM delegation_approvals WHERE id = $1", [approvalId]);
  assert.equal(row.rows[0]!.consumed_at, null);
  // Every refusal is reported with dry_run.
  const beta = await env.approval([BETA]);
  assert.deepEqual((await env.redeem(token(), beta, BETA, dry)).body, { ok: false, reason: "target_prefix", dry_run: true });
  assert.deepEqual((await env.redeem("not.a.jwt", approvalId, STABLE, dry)).body, { ok: false, reason: "oidc_invalid", dry_run: true });
  assert.deepEqual((await env.redeem(mint(env.github, env.workflowClaims({ event_name: "push" })), approvalId, STABLE, dry)).body,
    { ok: false, reason: "gate_mismatch", dry_run: true });
  // After the real redeem, a dry run from the same run is ok and from another run is consumed.
  assert.deepEqual((await env.redeem(token("600"), approvalId)).body, { ok: true, consumed: true });
  assert.deepEqual((await env.redeem(token("600"), approvalId, STABLE, dry)).body, { ok: true, dry_run: true });
  assert.deepEqual((await env.redeem(token("601"), approvalId, STABLE, dry)).body, { ok: false, reason: "consumed", dry_run: true });
  const dryEvents = await env.events("gate.dry_run");
  assert.deepEqual(dryEvents.map(event => event.reason), [null, null, "target_prefix", "oidc_invalid", "gate_mismatch", null, "consumed"]);
  assert.ok(dryEvents.every(event => event.data.dry_run === true));
  assert.equal((await env.events("gate.redeemed")).length, 1);
  assert.equal((await env.events("gate.refused")).length, 0);
});

test("gate ref_pattern: refs/tags/<literal prefix>* only, matched against the token's ref; event still exact", async (t) => {
  const env = await setup(t);
  const body = { repo: REPO, job_workflow_ref: `${REPO}/.github/workflows/release.yml@refs/tags/v2026.11.7`,
    event: "push", target_prefix: `${REPO}:` };
  for (const bad of [
    { ...body, ref_pattern: "refs/heads/*" },
    { ...body, ref_pattern: "refs/tags/*v" },
    { ...body, ref_pattern: "refs/tags/v*.*" },
    { ...body, ref_pattern: "refs/tags/v" },
    { ...body, ref_pattern: "refs/tags/*" },
    { ...body, ref_pattern: "refs/tags/v*", ref: "refs/tags/v1" },
    { ...body },
  ]) {
    const refused = await env.browser("/delegates/gates", "POST", bad);
    assert.equal(refused.status, 400, `${JSON.stringify(bad)} ${refused.raw}`);
  }
  const created = await env.browser("/delegates/gates", "POST", { ...body, ref_pattern: "refs/tags/v2026." });
  assert.equal(created.status, 400, created.raw);
  const gate = await env.browser("/delegates/gates", "POST", { ...body, ref_pattern: "refs/tags/v2026.*" });
  assert.equal(gate.status, 201, gate.raw);
  assert.equal(gate.body.ref, null);
  assert.equal(gate.body.ref_pattern, "refs/tags/v2026.*");
  const tag = (ref: string, extra: Record<string, unknown> = {}) => mint(env.github, env.workflowClaims({
    job_workflow_ref: body.job_workflow_ref, ref, event_name: "push", run_id: `${Math.floor(Math.random() * 1e9) + 1}`, ...extra }));
  const approvalId = await env.approval([STABLE]);
  const dry = { dry_run: true };
  assert.deepEqual((await env.redeem(tag("refs/tags/v2026.11.7"), approvalId, STABLE, dry)).body, { ok: true, dry_run: true });
  // Another prefix, a branch with the same name, or another event: gate_mismatch.
  for (const [ref, extra] of [["refs/tags/v2025.1.0", {}], ["refs/heads/v2026.11.7", {}], ["refs/tags/x/v2026.1", {}],
    ["refs/tags/v2026.11.7", { event_name: "workflow_dispatch" }]] as Array<[string, Record<string, unknown>]>) {
    assert.deepEqual((await env.redeem(tag(ref, extra), approvalId, STABLE, dry)).body,
      { ok: false, reason: "gate_mismatch", dry_run: true }, `${ref} ${JSON.stringify(extra)}`);
  }
  assert.deepEqual((await env.redeem(tag("refs/tags/v2026.11.7"), approvalId)).body, { ok: true, consumed: true });
});

test("gate redeem: target prefix, release grammar, normal checks and tier O through the gate", async (t) => {
  const env = await setup(t);
  await env.gate({ target_prefix: `${REPO}:stable:` });
  const token = (runId: string) => mint(env.github, env.workflowClaims({ run_id: runId }));
  // A beta release through a stable-only gate.
  const beta = await env.approval([BETA]);
  assert.deepEqual((await env.redeem(token("1"), beta, BETA)).body, { ok: false, reason: "target_prefix" });
  // The action must be one the approval names.
  const stable = await env.approval([STABLE]);
  assert.deepEqual((await env.redeem(token("2"), stable, `${STABLE}:other`)).body, { ok: false, reason: "out_of_scope" });
  // A release target that names no single release (§11a.2) is refused.
  const vague = await env.approval([REPO]);
  assert.deepEqual((await env.redeem(token("3"), vague, REPO)).body, { ok: false, reason: "out_of_scope" });
  // Unknown approval.
  assert.deepEqual((await env.redeem(token("4"), "apv_doesnotexist0", STABLE)).body, { ok: false, reason: "no_approval" });
  // Revocation is re-checked.
  const revoked = await env.approval([`${REPO}:stable:v2026.11.8:${SHA}:123456790`]);
  await env.browser("/delegates/revoke-all", "POST", {});
  assert.deepEqual((await env.redeem(token("5"), revoked, `${REPO}:stable:v2026.11.8:${SHA}:123456790`)).body,
    { ok: false, reason: "revoked" });
  assert.deepEqual((await env.redeem(token("6"), stable)).body, { ok: false, reason: "revoked" });

  // Tier O: the owner's own minted approval, redeemed the same way (no delegate, no grant).
  const target = `${REPO}:stable:v2026.11.9:${SHA}:123456791`;
  const minted = await env.browser("/delegates/approvals", "POST", { actions: [{ class: "release", target }] });
  assert.equal(minted.status, 201, minted.raw);
  assert.deepEqual((await env.redeem(token("7"), minted.body.approval_id, target)).body, { ok: true, consumed: true });
  assert.deepEqual((await env.redeem(token("8"), minted.body.approval_id, target)).body, { ok: false, reason: "consumed" });
  // Delegation off: not_enabled.
  await env.browser("/delegates/policy", "PUT", { delegation_enabled: false });
  assert.deepEqual((await env.redeem(token("9"), minted.body.approval_id, target)).body, { ok: false, reason: "not_enabled" });
  const reasons = new Set((await env.events("gate.refused")).map(row => row.reason));
  for (const reason of ["target_prefix", "out_of_scope", "no_approval", "revoked", "consumed", "not_enabled"]) {
    assert.ok(reasons.has(reason), reason);
  }
});

test("every gate route is documented in openapi.yaml", () => {
  const spec = parseYaml(readFileSync(new URL("../openapi.yaml", import.meta.url), "utf8")) as { paths: Record<string, Record<string, unknown>> };
  const expected: Record<string, string[]> = {
    "/api/v1/workspaces/{workspaceId}/delegates/gates": ["get", "post"],
    "/api/v1/workspaces/{workspaceId}/delegates/gates/{gateId}": ["delete"],
    "/api/v1/workspaces/{workspaceId}/delegates/gates/redeem": ["post"],
  };
  for (const [path, methods] of Object.entries(expected)) {
    for (const method of methods) assert.ok(spec.paths[path]?.[method], `${method.toUpperCase()} ${path}`);
  }
});
