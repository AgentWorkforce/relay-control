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
        // The self-host issuer publishes its identifier with a trailing slash.
        return Response.json({ issuer: item.iss === GHES ? `${item.iss}/` : item.iss, jwks_uri: `${item.iss}/.well-known/jwks` });
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
  /** GitHub's REST API: the gated repository resolves to stable ids; anything else is 404. Tests change `github.repos`. */
  const githubApi = { repos: new Map<string, { id: number; owner: number; full_name: string; default_branch?: string } | "down" |
    "moved">([
    [REPO.toLowerCase(), { id: 70151234, owner: 90122, full_name: REPO, default_branch: "main" }],
  ]), calls: [] as Array<{ url: string; authorization: string | null }> };
  const githubFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    githubApi.calls.push({ url, authorization: new Headers(init?.headers).get("authorization") });
    const match = /^https:\/\/api\.github\.com\/repos\/([^/]+)\/([^/]+)$/.exec(url);
    const repo = match ? githubApi.repos.get(`${decodeURIComponent(match[1]!)}/${decodeURIComponent(match[2]!)}`.toLowerCase()) : undefined;
    if (repo === "down") return new Response("unavailable", { status: 503 });
    if (repo === "moved") return new Response(null, { status: 301, headers: { location: "https://api.github.com/repositories/1" } });
    if (!repo) return Response.json({ message: "Not Found" }, { status: 404 });
    return Response.json({ id: repo.id, full_name: repo.full_name, owner: { id: repo.owner },
      ...(repo.default_branch !== undefined ? { default_branch: repo.default_branch } : {}) });
  }) as typeof fetch;
  const env = await copilotDesktopSetup(t, { delegationOidcFetch: oidcFetch([github, ghes]), delegationGithubFetch: githubFetch }, undefined,
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
      workflow_ref: WORKFLOW, job_workflow_ref: WORKFLOW, ref: "refs/heads/main", event_name: "workflow_dispatch", run_id: "777000111",
      run_attempt: "1", repository_id: "70151234", repository_owner_id: "90122", sha: SHA, iat: now - 5, nbf: now - 5, exp: now + 300,
      ...extra };
  };
  const redeem = (token: string | null, approvalId: string, target = STABLE, extra: Record<string, unknown> = {}) =>
    request(env.origin, `${base}/delegates/gates/redeem`, {
      method: "POST", ...(token ? { token } : {}),
      body: { approval_id: approvalId, action: { class: "release", target }, ...extra },
    });
  async function gate(extra: Record<string, unknown> = {}) {
    const created = await browser("/delegates/gates", "POST", { repo: REPO, workflow_ref: WORKFLOW,
      ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:`, ...extra });
    assert.equal(created.status, 201, created.raw);
    return created.body;
  }
  async function events(event: string) {
    return (await env.database.query<{ reason: string | null; data: Record<string, unknown> }>(
      "SELECT reason, data FROM delegation_audit_events WHERE event = $1 ORDER BY id", [event])).rows;
  }
  return { ...env, github, ghes, githubApi, desktop, base, browser, bearer, approval, workflowClaims, redeem, gate, events };
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
    { repo: REPO, workflow_ref: "desktop-promote.yml", ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:` },
    { repo: REPO, workflow_ref: "Other/repo/.github/workflows/x.yml@refs/heads/main", ref: "refs/heads/main",
      event: "workflow_dispatch", target_prefix: `${REPO}:` },
    { repo: REPO, workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:*` },
    { repo: REPO, workflow_ref: WORKFLOW, ref: "main", event: "workflow_dispatch", target_prefix: `${REPO}:` },
    { repo: REPO, workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "Workflow Dispatch", target_prefix: `${REPO}:` },
    { repo: REPO, workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: "Other/repo:" },
    { repo: REPO, workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:`, extra: 1 },
  ]) {
    const refused = await env.browser("/delegates/gates", "POST", bad);
    assert.equal(refused.status, 400, `${JSON.stringify(bad)} ${refused.raw}`);
  }
  // A plain CLI token and an agent token cannot register a gate.
  const body = { repo: REPO, workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:` };
  assert.equal((await env.bearer("/delegates/gates", "POST", body, await env.deviceLogin())).status, 403);
  // The verified Desktop sign-in may (§4.1: no step-up, no browser confirmation).
  const viaDesktop = await env.bearer("/delegates/gates", "POST", body);
  assert.equal(viaDesktop.status, 201, viaDesktop.raw);
  assert.match(viaDesktop.body.gate_id, /^gate_[A-Za-z0-9]+$/);
  assert.deepEqual(Object.keys(viaDesktop.body).sort(),
    ["created_at", "default_branch", "event", "gate_id", "owner_id", "ref", "repo", "repository_id", "repository_owner_id",
      "target_prefix", "workflow_ref"]);
  const listed = await env.bearer("/delegates/gates");
  assert.deepEqual(listed.body.gates.map((gate: { gate_id: string }) => gate.gate_id), [viaDesktop.body.gate_id]);
  // Another member neither sees nor deletes it.
  const memberId = await env.addMember("member@acme.test");
  const member = await env.desktopSignIn({ hostName: "member-box", userId: memberId });
  assert.deepEqual((await env.bearer("/delegates/gates", "GET", undefined, member.accessToken)).body.gates, []);
  assert.equal((await env.bearer(`/delegates/gates?gate_id=${viaDesktop.body.gate_id}`, "DELETE", undefined,
    member.accessToken)).status, 404);
  // DELETE takes `?gate_id=` or `{gate_id}`, as Cloud.
  const deleted = await env.bearer("/delegates/gates", "DELETE", { gate_id: viaDesktop.body.gate_id });
  assert.equal(deleted.status, 200, deleted.raw);
  assert.deepEqual(deleted.body, { gate_id: viaDesktop.body.gate_id, deleted: true });
  assert.equal((await env.bearer(`/delegates/gates?gate_id=${viaDesktop.body.gate_id}`, "DELETE")).status, 404);
  assert.deepEqual((await env.bearer("/delegates/gates")).body.gates, []);
  // Registering needs delegation on.
  await env.browser("/delegates/policy", "PUT", { delegation_enabled: false });
  assert.equal((await env.browser("/delegates/gates", "POST", body)).body.code, "not_enabled");
  const audited = (await env.database.query<{ event: string }>(
    "SELECT event FROM delegation_audit_events WHERE event LIKE 'gate.%' ORDER BY id")).rows.map(row => row.event);
  assert.deepEqual(audited, ["gate.registered", "gate.pinned", "gate.deleted"]);
  // The deletion audits the whole gate, so the log alone shows what stopped serving.
  const deletedEvent = (await env.database.query<{ reason: string; data: Record<string, unknown> }>(
    "SELECT reason, data FROM delegation_audit_events WHERE event = 'gate.deleted'")).rows[0]!;
  assert.equal(deletedEvent.reason, "deleted");
  assert.deepEqual(Object.keys(deletedEvent.data).sort(), ["event", "gate_id", "ref", "repo", "repository_id", "target_prefix", "workflow_ref"]);
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
    assert.equal(refused.status, 401, `${name} ${refused.raw}`);
    assert.deepEqual(refused.body, { ok: false, reason: "oidc_invalid" }, name);
  }
  // No bearer at all is 401, before anything is read.
  const missing = await env.redeem(null, approvalId);
  assert.equal(missing.status, 401, missing.raw);
  assert.equal(missing.body.code, "unauthorized");
  // Still unconsumed: the real workflow redeems it.
  assert.deepEqual((await env.redeem(mint(env.github, env.workflowClaims()), approvalId)).body, { ok: true, consumed: true });
  // A self-host's configured issuer (whose discovery issuer has a trailing
  // slash) is accepted, through a gate registered for that issuer.
  const second = await env.approval([BETA]);
  const ghesToken = mint(env.ghes, env.workflowClaims({ iss: GHES, run_id: "42" }));
  // A same-named repository on another issuer is another repository: the GitHub gate does not match it.
  assert.deepEqual((await env.redeem(ghesToken, second, BETA)).body, { ok: false, reason: "gate_mismatch" });
  // A self-host issuer's repository is not on github.com: its owner names the ids.
  const ghesGate = await env.gate({ issuer: GHES, repository_id: "70151234", repository_owner_id: "90122", default_branch: "main" });
  assert.equal(ghesGate.issuer, GHES);
  assert.deepEqual((await env.redeem(ghesToken, second, BETA)).body, { ok: true, consumed: true });
  assert.equal((await env.browser("/delegates/gates", "POST", { repo: REPO, workflow_ref: WORKFLOW, ref: "refs/heads/main",
    event: "workflow_dispatch", target_prefix: `${REPO}:`, issuer: "https://token.evil.example" })).status, 400);
  // As Cloud: a caller no gate matched is nobody in particular, so an
  // unverified or unmatched token writes nothing to the workspace's log.
  const refused = await env.events("gate.refused");
  assert.equal(refused.filter(row => row.reason === "oidc_invalid" || row.reason === "gate_mismatch").length, 0);
});

test("gate redeem: repository, workflow_ref, ref and event must all match a registered gate", async (t) => {
  const env = await setup(t);
  const approvalId = await env.approval([STABLE]);
  const token = (extra: Record<string, unknown> = {}) => mint(env.github, env.workflowClaims(extra));
  // No gate for the repository at all.
  assert.deepEqual((await env.redeem(token(), approvalId)).body, { ok: false, reason: "gate_unknown" });
  await env.gate();
  // The same repository's workflow edited on another branch also gets a token: refused.
  const otherBranch = token({ workflow_ref: `${REPO}/.github/workflows/desktop-promote.yml@refs/heads/attacker`,
    ref: "refs/heads/attacker" });
  assert.deepEqual((await env.redeem(otherBranch, approvalId)).body, { ok: false, reason: "gate_mismatch" });
  const otherWorkflow = token({ workflow_ref: `${REPO}/.github/workflows/ci.yml@refs/heads/main` });
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
  assert.equal(redeemed[0]!.data.workflow_ref, WORKFLOW);
});

test("gate redeem: single use bound to run_id; any later redeem in the same run is same_run, another run is consumed", async (t) => {
  const env = await setup(t);
  await env.gate();
  // A second job of the same release run (for example promote, then bridge)
  // runs in the same workflow, so the same gate matches it.
  const bridge = `${REPO}/.github/workflows/desktop-promote.yml@refs/heads/main`;
  const approvalId = await env.approval([STABLE]);
  const run = (runId: string, attempt: string, extra: Record<string, unknown> = {}) =>
    mint(env.github, env.workflowClaims({ run_id: runId, run_attempt: attempt, ...extra }));
  assert.deepEqual((await env.redeem(run("900", "1"), approvalId)).body, { ok: true, consumed: true });
  // The same run again: the same attempt, a later attempt, or another job of it.
  const sameRun = { ok: true, consumed: true, same_run: true };
  assert.deepEqual((await env.redeem(run("900", "1"), approvalId)).body, sameRun);
  assert.deepEqual((await env.redeem(run("900", "2"), approvalId)).body, sameRun);
  assert.deepEqual((await env.redeem(run("900", "1", { job_workflow_ref: bridge, job: "bridge" }), approvalId)).body, sameRun);
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
  assert.deepEqual((await env.redeem(token(), approvalId, STABLE, dry)).body, { ok: true, consumed: false, dry_run: true });
  assert.deepEqual((await env.redeem(token(), approvalId, STABLE, dry)).body, { ok: true, consumed: false, dry_run: true });
  // Nothing was consumed: a real redeem by any run still succeeds.
  assert.equal((await env.database.query("SELECT 1 FROM delegation_action_consumptions WHERE approval_id = $1",
    [approvalId])).rows.length, 0);
  // Every refusal is reported with dry_run.
  const beta = await env.approval([BETA]);
  assert.deepEqual((await env.redeem(token(), beta, BETA, dry)).body, { ok: false, reason: "target_prefix", dry_run: true });
  assert.deepEqual((await env.redeem("not.a.jwt", approvalId, STABLE, dry)).body, { ok: false, reason: "oidc_invalid", dry_run: true });
  assert.deepEqual((await env.redeem(mint(env.github, env.workflowClaims({ event_name: "push" })), approvalId, STABLE, dry)).body,
    { ok: false, reason: "gate_mismatch", dry_run: true });
  // After the real redeem, a dry run from the same run is ok and from another run is consumed.
  assert.deepEqual((await env.redeem(token("600"), approvalId)).body, { ok: true, consumed: true });
  assert.deepEqual((await env.redeem(token("600"), approvalId, STABLE, dry)).body, { ok: true, consumed: false, dry_run: true });
  assert.deepEqual((await env.redeem(token("601"), approvalId, STABLE, dry)).body, { ok: false, reason: "consumed", dry_run: true });
  // Dry runs are audited with `dry_run: true` in the event data; a passing one
  // is `gate.checked`, so `gate.redeemed` counts real uses only, as Cloud.
  const all = (await env.database.query<{ event: string; reason: string | null; data: Record<string, unknown> }>(
    `SELECT event, reason, data FROM delegation_audit_events
      WHERE event IN ('gate.redeemed', 'gate.refused', 'gate.checked') ORDER BY id`)).rows;
  const dryEvents = all.filter(event => event.data.dry_run === true);
  assert.deepEqual(dryEvents.map(event => [event.event, event.reason]), [["gate.checked", null], ["gate.checked", null],
    ["gate.refused", "target_prefix"],
    ["gate.checked", null], ["gate.refused", "consumed"]]);
  assert.deepEqual(all.filter(event => event.data.dry_run !== true).map(event => event.event), ["gate.redeemed"]);
});

test("gate ref_pattern: refs/tags/<literal prefix>* only, matched against the token's ref; event still exact", async (t) => {
  const env = await setup(t);
  const tagWorkflow = (ref: string) => `${REPO}/.github/workflows/release.yml@${ref}`;
  const body = { repo: REPO, workflow_ref: tagWorkflow("refs/tags/v2026.*"), event: "push", target_prefix: `${REPO}:` };
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
  assert.equal(gate.body.ref, undefined);
  assert.equal(gate.body.ref_pattern, "refs/tags/v2026.*");
  const tag = (ref: string, extra: Record<string, unknown> = {}) => mint(env.github, env.workflowClaims({
    workflow_ref: tagWorkflow(ref), job_workflow_ref: tagWorkflow(ref), ref, event_name: "push", run_id: `${Math.floor(Math.random() * 1e9) + 1}`, ...extra }));
  const approvalId = await env.approval([STABLE]);
  const dry = { dry_run: true };
  assert.deepEqual((await env.redeem(tag("refs/tags/v2026.11.7"), approvalId, STABLE, dry)).body, { ok: true, consumed: false, dry_run: true });
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
  // A release target that names no single release (§11a.2) is not an approval at all.
  const vagueMessage = env.world.sendApprovalAs("assistant", "relay-coder", "ship everything", {
    v: 1, owner_id: env.ownerId, actions: [{ class: "release", target: REPO }] }).message.id;
  const vague = await request(env.origin, `${env.base}/messaging/delegation`, { method: "POST", token: env.desktop.accessToken,
    body: { recipient_agent_id: env.world.agents.get("relay-coder")!.id, recipient_token: env.world.agents.get("relay-coder")!.token,
      message_id: vagueMessage } });
  assert.equal(vague.body.reason, "no_approval", vague.raw);
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
    "/api/v1/workspaces/{workspaceId}/delegates/gates": ["get", "post", "delete"],
    "/api/v1/workspaces/{workspaceId}/delegates/gates/redeem": ["post"],
  };
  for (const [path, methods] of Object.entries(expected)) {
    for (const method of methods) assert.ok(spec.paths[path]?.[method], `${method.toUpperCase()} ${path}`);
  }
});

test("gate redeem: a gate for a reusable workflow also requires job_workflow_ref", async (t) => {
  const env = await setup(t);
  const reusable = `AgentWorkforce/release-workflows/.github/workflows/publish.yml@${SHA}`;
  await env.gate({ job_workflow_ref: reusable });
  const approvalId = await env.approval([STABLE]);
  const dry = { dry_run: true };
  // The caller workflow matches, but the job ran in another reusable workflow: refused.
  const other = mint(env.github, env.workflowClaims({ job_workflow_ref: "AgentWorkforce/release-workflows/.github/workflows/x.yml@refs/heads/main" }));
  assert.deepEqual((await env.redeem(other, approvalId, STABLE, dry)).body, { ok: false, reason: "gate_mismatch", dry_run: true });
  const inline = mint(env.github, env.workflowClaims());
  assert.deepEqual((await env.redeem(inline, approvalId, STABLE, dry)).body, { ok: false, reason: "gate_mismatch", dry_run: true });
  // Both refs match: redeemed.
  const ok = mint(env.github, env.workflowClaims({ job_workflow_ref: reusable }));
  assert.deepEqual((await env.redeem(ok, approvalId)).body, { ok: true, consumed: true });
  const gates = (await env.bearer("/delegates/gates")).body.gates;
  assert.equal(gates[0].job_workflow_ref, reusable);
  assert.equal(gates[0].workflow_ref, WORKFLOW);
});

test("gate redeem: single use is per action; another action of the same approval is unaffected", async (t) => {
  const env = await setup(t);
  await env.gate();
  const approvalId = await env.approval([STABLE, BETA]);
  const run = (runId: string) => mint(env.github, env.workflowClaims({ run_id: runId }));
  assert.deepEqual((await env.redeem(run("10"), approvalId, BETA)).body, { ok: true, consumed: true });
  // The stable action is still unused: a later run redeems it.
  assert.deepEqual((await env.redeem(run("11"), approvalId, STABLE)).body, { ok: true, consumed: true });
  assert.deepEqual((await env.redeem(run("12"), approvalId, BETA)).body, { ok: false, reason: "consumed" });
  assert.deepEqual((await env.redeem(run("10"), approvalId, BETA)).body, { ok: true, consumed: true, same_run: true });
  // Withdrawn by the delegate: the next redeem is revoked.
  const fresh = await env.approval([`${REPO}:stable:v2026.11.8:${SHA}:123456790`]);
  const assistant = env.world.agents.get("assistant")!;
  const withdrawn = await request(env.origin, `${env.base}/messaging/delegation/withdraw`, { method: "POST",
    body: { delegate_agent_id: assistant.id, delegate_token: assistant.token, approval_id: fresh } });
  assert.equal(withdrawn.status, 200, withdrawn.raw);
  assert.deepEqual((await env.redeem(run("13"), fresh, `${REPO}:stable:v2026.11.8:${SHA}:123456790`)).body,
    { ok: false, reason: "revoked" });
});

test("gate redeem: another member's matching gate never blocks the approval owner's own gate", async (t) => {
  const env = await setup(t);
  // Bob registers the same workflow first; the owner registers it too.
  const bobId = await env.addMember("bob@acme.test");
  const bob = await env.desktopSignIn({ hostName: "bob-box", userId: bobId });
  const body = { repo: REPO, workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:` };
  // A plain member may not own a gate (pending D5, option b): org owners and admins only.
  const refused = await env.bearer("/delegates/gates", "POST", body, bob.accessToken);
  assert.equal(refused.status, 403, refused.raw);
  assert.equal(refused.body.code, "gate_owner_unqualified");
  await env.database.query("UPDATE organization_memberships SET role = 'admin' WHERE user_id = $1", [bobId]);
  assert.equal((await env.bearer("/delegates/gates", "POST", body, bob.accessToken)).status, 201);
  const own = await env.gate();
  const approvalId = await env.approval([STABLE]);
  assert.deepEqual((await env.redeem(mint(env.github, env.workflowClaims()), approvalId)).body, { ok: true, consumed: true });
  const redeemed = await env.events("gate.redeemed");
  assert.equal(redeemed[0]!.data.gate_id, own.gate_id);
});

test("gate redeem: a gate deleted, an approval revoked or a grant narrowed during the checks is decided at commit", async (t) => {
  const env = await setup(t);
  const gate = await env.gate();
  const handle = env.world.handle;
  let during: (() => Promise<void>) | null = null;
  env.world.handle = (async (...args: Parameters<typeof handle>) => {
    if (during && args[0] === "GET" && args[1] === "/v1/agents/assistant") {
      const run = during;
      during = null;
      await run();
    }
    return handle(...args);
  }) as typeof handle;
  const token = (runId: string) => mint(env.github, env.workflowClaims({ run_id: runId }));
  // The gate is deleted while the delegate's binding is re-checked.
  const first = await env.approval([STABLE]);
  during = async () => { await env.database.query("UPDATE delegation_gates SET deleted_at = now() WHERE id = $1", [gate.gate_id]); };
  assert.deepEqual((await env.redeem(token("1"), first)).body, { ok: false, reason: "gate_unknown" });
  await env.gate();
  // The approval expires meanwhile.
  during = async () => { await env.database.query("UPDATE delegation_approvals SET expires_at = now() WHERE id = $1", [first]); };
  assert.deepEqual((await env.redeem(token("2"), first)).body, { ok: false, reason: "expired" });
  // The grant is narrowed meanwhile.
  const second = await env.approval([BETA]);
  during = async () => {
    await env.database.query(`UPDATE delegation_grants SET scopes = '[{"class":"release","targets":["${REPO}"]}]'::jsonb`);
  };
  assert.deepEqual((await env.redeem(token("3"), second, BETA)).body, { ok: false, reason: "out_of_scope" });
  // Nothing was consumed by any of these.
  assert.equal((await env.database.query("SELECT 1 FROM delegation_action_consumptions")).rows.length, 0);
  env.world.handle = handle;
});

test("gates: allowed events, one live gate per workflow identity, pinned repository ids, case-insensitive repo", async (t) => {
  const env = await setup(t);
  const body = { repo: REPO, workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:` };
  // Only events that run the gated ref's own workflow code.
  for (const event of ["pull_request", "pull_request_target", "workflow_run", "issue_comment"]) {
    assert.equal((await env.browser("/delegates/gates", "POST", { ...body, event })).status, 400, event);
  }
  const gate = await env.gate();
  // The same live gate twice is 409 gate_exists; another reusable workflow behind it is a distinct gate.
  const again = await env.browser("/delegates/gates", "POST", body);
  assert.equal(again.status, 409, again.raw);
  assert.deepEqual(again.body, { error: "You already registered this gate", code: "gate_exists" });
  const reusable = `AgentWorkforce/workflows/.github/workflows/publish.yml@${SHA}`;
  await env.gate({ job_workflow_ref: reusable });
  assert.equal((await env.browser("/delegates/gates", "POST", { ...body, job_workflow_ref: reusable })).status, 409);
  // Deleting it frees the identity.
  assert.equal((await env.bearer(`/delegates/gates?gate_id=${gate.gate_id}`, "DELETE")).status, 200);
  const pinned = await env.gate();

  // The repository name matches case-insensitively, the workflow file exactly.
  const approvalId = await env.approval([STABLE]);
  const lower = REPO.toLowerCase();
  const dry = { dry_run: true };
  const ids = { repository_id: "70151234", repository_owner_id: "90122" };
  const caseToken = mint(env.github, env.workflowClaims({ repository: lower,
    workflow_ref: WORKFLOW.replace(REPO, lower), job_workflow_ref: WORKFLOW.replace(REPO, lower), ...ids }));
  assert.deepEqual((await env.redeem(caseToken, approvalId, STABLE, dry)).body, { ok: true, consumed: false, dry_run: true });
  const fileCase = mint(env.github, env.workflowClaims({ workflow_ref: WORKFLOW.replace("desktop-promote", "Desktop-Promote"),
    job_workflow_ref: WORKFLOW.replace("desktop-promote", "Desktop-Promote"), ...ids }));
  assert.deepEqual((await env.redeem(fileCase, approvalId, STABLE, dry)).body, { ok: false, reason: "gate_mismatch", dry_run: true });
  // The gate was pinned at registration to GitHub's ids: a repository that reuses the name is
  // repository_mismatch (logged and audited for the gate's owner, also on a dry run).
  const listed = (await env.bearer("/delegates/gates")).body.gates as Array<Record<string, unknown>>;
  const view = listed.find(item => item.gate_id === pinned.gate_id)!;
  assert.equal(view.repository_id, ids.repository_id);
  assert.equal(view.repository_owner_id, ids.repository_owner_id);
  const pinEvent = (await env.events("gate.pinned")).find(row => row.data.gate_id === pinned.gate_id)!;
  assert.deepEqual(pinEvent.data, { gate_id: pinned.gate_id, repo: REPO, repository_id: ids.repository_id,
    repository_owner_id: ids.repository_owner_id, source: "registration" });
  const reused = mint(env.github, env.workflowClaims({ repository_id: "99999999", repository_owner_id: "90122" }));
  assert.deepEqual((await env.redeem(reused, approvalId, STABLE, dry)).body, { ok: false, reason: "repository_mismatch", dry_run: true });
  const mismatch = (await env.events("gate.refused")).filter(row => row.reason === "repository_mismatch");
  assert.equal(mismatch.length, 1);
  // A token without the ids never matches a pinned gate either.
  const idless = mint(env.github, env.workflowClaims({ repository_id: undefined, repository_owner_id: undefined }));
  assert.deepEqual((await env.redeem(idless, approvalId, STABLE, dry)).body, { ok: false, reason: "repository_mismatch", dry_run: true });
  assert.deepEqual((await env.redeem(mint(env.github, env.workflowClaims(ids)), approvalId)).body, { ok: true, consumed: true });

});

test("gates: a gate serves only while its owner is a member; policy at the commit decides", async (t) => {
  const env = await setup(t);
  await env.gate();
  const handle = env.world.handle;
  let during: (() => Promise<void>) | null = null;
  env.world.handle = (async (...args: Parameters<typeof handle>) => {
    if (during && args[0] === "GET" && args[1] === "/v1/agents/assistant") {
      const run = during;
      during = null;
      await run();
    }
    return handle(...args);
  }) as typeof handle;
  const token = (runId: string) => mint(env.github, env.workflowClaims({ run_id: runId }));
  // Delegation turned off while the checks waited.
  const first = await env.approval([STABLE]);
  during = async () => {
    await env.database.query("UPDATE delegation_policies SET delegation_enabled = false WHERE workspace_id = $1", [env.workspaceId]);
  };
  assert.deepEqual((await env.redeem(token("11"), first)).body, { ok: false, reason: "not_enabled" });
  await env.database.query("UPDATE delegation_policies SET delegation_enabled = true WHERE workspace_id = $1", [env.workspaceId]);
  // A tier O requirement added meanwhile.
  during = async () => {
    await env.database.query("UPDATE delegation_policies SET require_tier_o = ARRAY['release'] WHERE workspace_id = $1",
      [env.workspaceId]);
  };
  assert.deepEqual((await env.redeem(token("12"), first)).body, { ok: false, reason: "tier_o_required" });
  await env.database.query("UPDATE delegation_policies SET require_tier_o = '{}' WHERE workspace_id = $1", [env.workspaceId]);
  // The gate's owner leaves meanwhile: the gate no longer serves.
  during = async () => {
    await env.database.query("DELETE FROM organization_memberships WHERE user_id = $1", [env.ownerId]);
  };
  const left = await env.redeem(token("13"), first);
  assert.equal(left.body.ok, false, left.raw);
  assert.equal((await env.database.query("SELECT 1 FROM delegation_action_consumptions")).rows.length, 0);
  env.world.handle = handle;
});

test("gate redeem: a dry run answers from a fresh re-read; gate.redeemed commits with the consumption", async (t) => {
  const env = await setup(t);
  await env.gate();
  const handle = env.world.handle;
  let during: (() => Promise<void>) | null = null;
  env.world.handle = (async (...args: Parameters<typeof handle>) => {
    if (during && args[0] === "GET" && args[1] === "/v1/agents/assistant") {
      const run = during;
      during = null;
      await run();
    }
    return handle(...args);
  }) as typeof handle;
  t.after(() => { env.world.handle = handle; });
  const token = (runId: string) => mint(env.github, env.workflowClaims({ run_id: runId }));
  const approvalId = await env.approval([STABLE]);
  // Delegation turned off while the delegate's binding is re-checked: the dry run sees it.
  during = async () => {
    assert.equal((await env.browser("/delegates/policy", "PUT", { delegation_enabled: false })).status, 200);
  };
  assert.deepEqual((await env.redeem(token("700"), approvalId, STABLE, { dry_run: true })).body,
    { ok: false, reason: "not_enabled", dry_run: true });
  assert.equal((await env.browser("/delegates/policy", "PUT", { delegation_enabled: true })).status, 200);
  // A failed gate.redeemed write rolls the consumption back: the answer is unavailable and nothing is spent.
  await env.database.query(`CREATE FUNCTION refuse_gate_redeemed() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN IF NEW.event = 'gate.redeemed' THEN RAISE EXCEPTION 'audit down'; END IF; RETURN NEW; END; $$`);
  await env.database.query(`CREATE TRIGGER refuse_gate_redeemed BEFORE INSERT ON delegation_audit_events
    FOR EACH ROW EXECUTE FUNCTION refuse_gate_redeemed()`);
  assert.deepEqual((await env.redeem(token("701"), approvalId)).body, { ok: false, reason: "unavailable" });
  assert.equal((await env.database.query("SELECT 1 FROM delegation_action_consumptions")).rows.length, 0);
  assert.equal((await env.database.query("SELECT 1 FROM delegation_gate_redemptions")).rows.length, 0);
  await env.database.query("DROP TRIGGER refuse_gate_redeemed ON delegation_audit_events");
  assert.deepEqual((await env.redeem(token("702"), approvalId)).body, { ok: true, consumed: true });
  assert.equal((await env.events("gate.redeemed")).length, 1);
});

test("gates: workflow_ref is at the gate's ref; a reusable workflow may be pinned to a commit SHA, matched exactly", async (t) => {
  const env = await setup(t);
  const body = { repo: REPO, workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:` };
  // The run's own workflow must be at the gate's ref.
  const otherRef = await env.browser("/delegates/gates", "POST", { ...body, workflow_ref: WORKFLOW.replace("refs/heads/main", "refs/heads/dev") });
  assert.equal(otherRef.status, 400, otherRef.raw);
  const sha = "0123456789abcdef0123456789abcdef01234567";
  const reusable = `AgentWorkforce/workflows/.github/workflows/publish.yml@${sha}`;
  for (const bad of [sha.toUpperCase(), sha.slice(1)]) {
    const refused = await env.browser("/delegates/gates", "POST", { ...body, job_workflow_ref: reusable.replace(sha, bad) });
    assert.equal(refused.status, 400, refused.raw);
  }
  await env.gate({ job_workflow_ref: reusable });
  const approvalId = await env.approval([STABLE]);
  const dry = { dry_run: true };
  assert.deepEqual((await env.redeem(mint(env.github, env.workflowClaims({ job_workflow_ref: reusable })), approvalId, STABLE, dry)).body,
    { ok: true, consumed: false, dry_run: true });
  const otherSha = reusable.replace(sha, "f".repeat(40));
  assert.deepEqual((await env.redeem(mint(env.github, env.workflowClaims({ job_workflow_ref: otherSha })), approvalId, STABLE, dry)).body,
    { ok: false, reason: "gate_mismatch", dry_run: true });
});

test("OIDC keys: a failed fetch backs off 30 s, serves the last good keys (or fails fast), and is logged", async (t) => {
  const { workflowOidcVerifier, OidcKeysUnavailable } = await import("../src/delegation/oidc.js");
  const { setDelegationLogSinkForTesting } = await import("../src/delegation/observe.js");
  const lines: string[] = [];
  setDelegationLogSinkForTesting((_level, line) => { lines.push(line); });
  t.after(() => setDelegationLogSinkForTesting(null));
  const github = issuer(GITHUB);
  const serve = oidcFetch([github]);
  let down = true;
  let fetches = 0;
  const clock = { ms: Date.now() };
  const verify = workflowOidcVerifier({ issuers: [GITHUB], audience: "https://control.example.test", now: () => new Date(clock.ms),
    fetchImpl: (async (input: string | URL | Request, init?: RequestInit) => {
      fetches += 1;
      return down ? new Response("busy", { status: 503 }) : serve(input, init);
    }) as typeof fetch });
  const seconds = Math.floor(clock.ms / 1000);
  const token = (kid = github.kid) => mint({ ...github, kid }, { iss: GITHUB, aud: "https://control.example.test", sub: "repo:x",
    repository: REPO, workflow_ref: WORKFLOW, job_workflow_ref: WORKFLOW, ref: "refs/heads/main", event_name: "push",
    run_id: "1", run_attempt: "1", sha: SHA, iat: seconds, nbf: seconds, exp: seconds + 600 });
  // No keys yet and the issuer is down: an outage, not a forged token.
  await assert.rejects(verify(token()), OidcKeysUnavailable);
  const afterFirst = fetches;
  // Within the backoff, no fetch starts: it fails fast.
  await assert.rejects(verify(token()), OidcKeysUnavailable);
  assert.equal(fetches, afterFirst);
  const failed = lines.map(line => JSON.parse(line) as Record<string, unknown>).filter(line => line.message === "delegation.dependency_failed");
  assert.equal(failed.length, 1);
  assert.equal(failed[0]!.op, "github_oidc_jwks");
  assert.equal(failed[0]!.stale_cache_served, false);
  assert.equal(failed[0]!.status, 503);
  // After 30 s it fetches again; the issuer is back.
  clock.ms += 31_000;
  down = false;
  assert.equal((await verify(token())).repository, REPO);
  // An unknown kid within the 60 s refresh cooldown is not refetched: unavailable, not oidc_invalid.
  const coolFetches = fetches;
  await assert.rejects(verify(token("too-soon")), OidcKeysUnavailable);
  assert.equal(fetches, coolFetches);
  // The issuer goes down again: an unknown kid refetches (after the cooldown), fails, and the last good keys still serve.
  down = true;
  clock.ms += 61_000;
  // An unknown kid while only stale keys can be served may be a key just rotated in: unavailable, not oidc_invalid.
  await assert.rejects(verify(token("rotated-kid")), OidcKeysUnavailable);
  assert.equal((await verify(token())).repository, REPO);
  const stale = lines.map(line => JSON.parse(line) as Record<string, unknown>).filter(line => line.message === "delegation.dependency_failed").at(-1)!;
  assert.equal(stale.stale_cache_served, true);
  // On a fresh answer an unknown kid is a forged token: oidc_invalid.
  down = false;
  clock.ms += 61_000;
  await assert.rejects(verify(token("forged-kid")), /oidc_invalid: unknown_key/);
});

test("gate redeem: releases only; a gate without job_workflow_ref covers its own file's jobs; same_run by repository id", async (t) => {
  const env = await setup(t);
  // A deploy approval whose target happens to start with the gate's prefix is never spent through a gate.
  await env.bearer("/delegates/revoke-all", "POST", {});
  const assistant = (await env.database.query<{ agent_id: string }>(
    "SELECT agent_id FROM delegation_agent_bindings LIMIT 1")).rows[0]!.agent_id;
  const grant = await env.browser("/delegates", "POST", { delegate_agent_id: assistant, scopes: [
    { class: "release", targets: [`${REPO}:*:*:*:*`, REPO] }, { class: "deploy", targets: [`${REPO}:*`] }] });
  assert.equal(grant.status, 201, grant.raw);
  await env.gate();
  const deployTarget = `${REPO}:prod`;
  const messageId = env.world.sendApprovalAs("assistant", "relay-coder", "ship it",
    { v: 1, owner_id: env.ownerId, actions: [{ class: "deploy", target: deployTarget }] }).message.id;
  const recipient = (await env.database.query<{ agent_remote_id: string }>(
    "SELECT agent_remote_id FROM desktop_relay_identities LIMIT 1")).rows[0]!.agent_remote_id;
  const coder = env.world.agents.get("relay-coder")!;
  const attested = await request(env.origin, `${env.base}/messaging/delegation`, { method: "POST", token: env.desktop.accessToken,
    body: { recipient_agent_id: recipient, recipient_token: coder.token, message_id: messageId } });
  assert.equal(attested.body.verdict, "delegate", attested.raw);
  const deploy = await env.redeem(mint(env.github, env.workflowClaims({ run_id: "950" })), attested.body.claims.approval_id, deployTarget);
  assert.equal(deploy.status, 403, deploy.raw);
  assert.deepEqual(deploy.body, { ok: false, reason: "out_of_scope" });
  // A job inside a reusable workflow the gate does not name: gate_mismatch.
  const approvalId = await env.approval([STABLE]);
  const reusable = "AgentWorkforce/workflows/.github/workflows/publish.yml@refs/heads/main";
  assert.deepEqual((await env.redeem(mint(env.github, env.workflowClaims({ run_id: "951", job_workflow_ref: reusable })),
    approvalId, STABLE, { dry_run: true })).body, { ok: false, reason: "gate_mismatch", dry_run: true });
  // same_run compares GitHub's repository id: a renamed repository (same id) is still the same run.
  assert.deepEqual((await env.redeem(mint(env.github, env.workflowClaims({ run_id: "952" })), approvalId)).body, { ok: true, consumed: true });
  const stored = (await env.database.query<{ repository_id: string }>(
    "SELECT repository_id FROM delegation_gate_redemptions WHERE approval_id = $1", [approvalId])).rows[0]!;
  assert.equal(stored.repository_id, "70151234");
  // The opt-out needs an exact branch ref: an exact tag is refused.
  const tag = await env.browser("/delegates/gates", "POST", { repo: REPO, workflow_ref: `${REPO}/.github/workflows/release.yml@refs/tags/v1`,
    ref: "refs/tags/v1", event: "push", target_prefix: `${REPO}:`, allow_source_sha_mismatch: true });
  assert.equal(tag.status, 400, tag.raw);
});

test("gate redeem: a release is bound to the run's commit (sha claim); status codes fail closed", async (t) => {
  const env = await setup(t);
  await env.gate();
  const approvalId = await env.approval([STABLE]);
  const token = (extra: Record<string, unknown> = {}) => mint(env.github, env.workflowClaims({ run_id: "900", ...extra }));
  const dry = { dry_run: true };
  // The sha claim is required: missing or malformed is oidc_invalid (401).
  for (const sha of [undefined, "abc", "z".repeat(40)]) {
    const refused = await env.redeem(token({ sha }), approvalId);
    assert.equal(refused.status, 401, refused.raw);
    assert.deepEqual(refused.body, { ok: false, reason: "oidc_invalid" });
  }
  // Upper-case hex is accepted and compared lower-cased.
  assert.deepEqual((await env.redeem(token({ sha: SHA.toUpperCase() }), approvalId, STABLE, dry)).body,
    { ok: true, consumed: false, dry_run: true });
  // A run on another commit: sha_mismatch (403), unless the gate opted out for candidate targets.
  const other = "b".repeat(40);
  const mismatch = await env.redeem(token({ sha: other }), approvalId);
  assert.equal(mismatch.status, 403, mismatch.raw);
  assert.deepEqual(mismatch.body, { ok: false, reason: "sha_mismatch" });
  // A SHA-256 repository's 64-hex sha never matches a 40-hex target.
  assert.deepEqual((await env.redeem(token({ sha: SHA + "0".repeat(24) }), approvalId)).body, { ok: false, reason: "sha_mismatch" });
  // A dry run always answers 200 with its verdict.
  const dryMismatch = await env.redeem(token({ sha: other }), approvalId, STABLE, dry);
  assert.equal(dryMismatch.status, 200, dryMismatch.raw);
  assert.deepEqual(dryMismatch.body, { ok: false, reason: "sha_mismatch", dry_run: true });
  const refusedEvent = (await env.events("gate.refused")).find(row => row.reason === "sha_mismatch")!;
  assert.equal(refusedEvent.data.sha, other);
  // A gate that opts out (shown on the gate only when true) serves a candidate target from another commit.
  const optOut = await env.gate({ target_prefix: `${REPO}:stable:`, allow_source_sha_mismatch: true });
  assert.equal(optOut.allow_source_sha_mismatch, true);
  assert.equal((await env.bearer("/delegates/gates")).body.gates.filter((gate: Record<string, unknown>) =>
    gate.allow_source_sha_mismatch === true).length, 1);
  const served = await env.redeem(token({ sha: other }), approvalId);
  assert.equal(served.status, 200, served.raw);
  assert.deepEqual(served.body, { ok: true, consumed: true });
  assert.equal((await env.events("gate.redeemed")).at(-1)!.data.sha, other);
  // A tag gate never serves off-commit, even with the flag set behind registration's back.
  const tagWorkflow = `${REPO}/.github/workflows/release.yml@refs/tags/v*`;
  const tagGate = await env.gate({ workflow_ref: tagWorkflow, ref: undefined, ref_pattern: "refs/tags/v*", event: "push",
    target_prefix: `${REPO}:stable:` });
  await env.database.query("UPDATE delegation_gates SET allow_source_sha_mismatch = true WHERE id = $1", [tagGate.gate_id]);
  const tagApproval = await env.approval([STABLE.replace(":123456789", ":123456790")]);
  const tagToken = mint(env.github, env.workflowClaims({ run_id: "902", sha: other, ref: "refs/tags/v2026.11.7", event_name: "push",
    workflow_ref: `${REPO}/.github/workflows/release.yml@refs/tags/v2026.11.7`,
    job_workflow_ref: `${REPO}/.github/workflows/release.yml@refs/tags/v2026.11.7` }));
  assert.deepEqual((await env.redeem(tagToken, tagApproval, STABLE.replace(":123456789", ":123456790"))).body,
    { ok: false, reason: "sha_mismatch" });
  // Land and iOS targets are always bound, even through an opted-out gate.
  const ios = `${REPO}:ios:testflight:42:${SHA}`;
  const iosApproval = await env.approval([ios]);
  await env.gate({ target_prefix: `${REPO}:ios:`, allow_source_sha_mismatch: true });
  assert.deepEqual((await env.redeem(token({ sha: other, run_id: "901" }), iosApproval, ios)).body,
    { ok: false, reason: "sha_mismatch" });
  assert.deepEqual((await env.redeem(token({ run_id: "901" }), iosApproval, ios)).body, { ok: true, consumed: true });
  // Other refusals are 403; a gate_unknown from a stranger repository too.
  const unknown = await env.redeem(token({ repository: "someone/else" }), approvalId);
  assert.equal(unknown.status, 403, unknown.raw);
});

test("gates: registration pins the repository on GitHub; tag gates cannot opt out of the sha binding", async (t) => {
  const env = await setup(t);
  const body = { repo: REPO, workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "workflow_dispatch" };
  // target_prefix ends at a segment boundary.
  const open = await env.browser("/delegates/gates", "POST", { ...body, target_prefix: `${REPO}:stable` });
  assert.equal(open.status, 400, open.raw);
  // GitHub knows no such repository: 422 repository_unresolved, and no gate is created.
  const ghost = "AgentWorkforce/ghost";
  const unresolved = await env.browser("/delegates/gates", "POST", { repo: ghost,
    workflow_ref: `${ghost}/.github/workflows/release.yml@refs/heads/main`, ref: "refs/heads/main", event: "push", target_prefix: `${ghost}:` });
  assert.equal(unresolved.status, 422, unresolved.raw);
  assert.equal(unresolved.body.code, "repository_unresolved");
  // A renamed repository (canonical name differs) is unresolved too.
  env.githubApi.repos.set(ghost.toLowerCase(), { id: 1, owner: 2, full_name: "AgentWorkforce/renamed", default_branch: "main" });
  assert.equal((await env.browser("/delegates/gates", "POST", { repo: ghost,
    workflow_ref: `${ghost}/.github/workflows/release.yml@refs/heads/main`, ref: "refs/heads/main", event: "push",
    target_prefix: `${ghost}:` })).status, 422);
  // GitHub down: 503 unavailable.
  env.githubApi.repos.set(ghost.toLowerCase(), "down");
  const down = await env.browser("/delegates/gates", "POST", { repo: ghost,
    workflow_ref: `${ghost}/.github/workflows/release.yml@refs/heads/main`, ref: "refs/heads/main", event: "push", target_prefix: `${ghost}:` });
  assert.equal(down.status, 503, down.raw);
  assert.equal((await env.bearer("/delegates/gates")).body.gates.length, 0);
  // A name that moved (GitHub answers a redirect, never followed) is unresolved.
  env.githubApi.repos.set(ghost.toLowerCase(), "moved");
  assert.equal((await env.browser("/delegates/gates", "POST", { repo: ghost,
    workflow_ref: `${ghost}/.github/workflows/release.yml@refs/heads/main`, ref: "refs/heads/main", event: "push",
    target_prefix: `${ghost}:` })).status, 422);
  // GitHub omitting the default branch is an outage.
  env.githubApi.repos.set(ghost.toLowerCase(), { id: 1, owner: 2, full_name: ghost });
  assert.equal((await env.browser("/delegates/gates", "POST", { repo: ghost,
    workflow_ref: `${ghost}/.github/workflows/release.yml@refs/heads/main`, ref: "refs/heads/main", event: "push",
    target_prefix: `${ghost}:` })).status, 503);
  // The source-sha opt-out needs a gate on the default branch (main here).
  const devBranch = await env.browser("/delegates/gates", "POST", { repo: REPO, workflow_ref: WORKFLOW.replace("refs/heads/main", "refs/heads/dev"),
    ref: "refs/heads/dev", event: "workflow_dispatch", target_prefix: `${REPO}:`, allow_source_sha_mismatch: true });
  assert.equal(devBranch.status, 400, devBranch.raw);
  // A GitHub Actions gate cannot name its own ids.
  assert.equal((await env.browser("/delegates/gates", "POST", { ...body, target_prefix: `${REPO}:`,
    repository_id: "1", repository_owner_id: "2" })).status, 400);
  // A tag gate cannot opt out of binding the release to the run's commit.
  const tag = await env.browser("/delegates/gates", "POST", { repo: REPO, workflow_ref: `${REPO}/.github/workflows/release.yml@refs/tags/v*`,
    ref_pattern: "refs/tags/v*", event: "push", target_prefix: `${REPO}:`, allow_source_sha_mismatch: true });
  assert.equal(tag.status, 400, tag.raw);
  // The exact same live gate twice is 409.
  await env.gate({ target_prefix: `${REPO}:stable:` });
  const duplicate = await env.browser("/delegates/gates", "POST", { ...body, target_prefix: `${REPO}:stable:` });
  assert.equal(duplicate.status, 409, duplicate.raw);
  assert.equal(duplicate.body.code, "gate_exists");
});

test("gate repository resolution: a connection's 404 or redirect is unresolved without asking the public API", async () => {
  const { resolveGateRepository, GithubUnavailable } = await import("../src/delegation/gates.js");
  const calls: Array<string | null> = [];
  const answer = (status: number, body?: unknown) => (async (_url: string | URL | Request, init?: RequestInit) => {
    calls.push(new Headers(init?.headers).get("authorization"));
    return body === undefined ? new Response(null, { status, headers: status >= 300 && status < 400 ? { location: "x" } : {} })
      : Response.json(body, { status });
  }) as typeof fetch;
  assert.equal(await resolveGateRepository({ repo: REPO, token: "ghs_x", fetchImpl: answer(404, { message: "Not Found" }) }), null);
  assert.deepEqual(calls, ["Bearer ghs_x"]);
  calls.length = 0;
  assert.equal(await resolveGateRepository({ repo: REPO, token: "ghs_x", fetchImpl: answer(302) }), null);
  assert.equal(calls.length, 1);
  // A full answer resolves with the default branch; a server error is an outage.
  assert.deepEqual(await resolveGateRepository({ repo: REPO, token: null,
    fetchImpl: answer(200, { id: 5, owner: { id: 6 }, full_name: REPO, default_branch: "trunk" }) }),
  { repositoryId: "5", repositoryOwnerId: "6", fullName: REPO, defaultBranch: "trunk" });
  await assert.rejects(resolveGateRepository({ repo: REPO, token: null, fetchImpl: answer(502, {}) }), GithubUnavailable);
});

test("gate redeem: the opt-out re-reads the default branch live; a cross-repo reusable workflow must be SHA-pinned", async (t) => {
  const env = await setup(t);
  // A reusable workflow in another repository pinned to a branch: 400.
  const crossBranch = await env.browser("/delegates/gates", "POST", { repo: REPO, workflow_ref: WORKFLOW, ref: "refs/heads/main",
    event: "workflow_dispatch", target_prefix: `${REPO}:`,
    job_workflow_ref: "AgentWorkforce/workflows/.github/workflows/publish.yml@refs/heads/main" });
  assert.equal(crossBranch.status, 400, crossBranch.raw);
  // An opt-out gate on the default branch (main) serves a candidate target from another commit.
  await env.gate({ allow_source_sha_mismatch: true });
  const other = "c".repeat(40);
  const token = (runId: string) => mint(env.github, env.workflowClaims({ run_id: runId, sha: other }));
  const dry = { dry_run: true };
  const approvalId = await env.approval([STABLE]);
  const before = env.githubApi.calls.length;
  assert.deepEqual((await env.redeem(token("960"), approvalId, STABLE, dry)).body, { ok: true, consumed: false, dry_run: true });
  assert.equal(env.githubApi.calls.length, before + 1, "the default branch is read live");
  // On-commit redeems never ask GitHub.
  const onCommit = env.githubApi.calls.length;
  assert.deepEqual((await env.redeem(mint(env.github, env.workflowClaims({ run_id: "961" })), approvalId, STABLE, dry)).body,
    { ok: true, consumed: false, dry_run: true });
  assert.equal(env.githubApi.calls.length, onCommit);
  // The public-API answer is cached per repository id: a second off-commit redeem asks nothing.
  const cachedCalls = env.githubApi.calls.length;
  assert.deepEqual((await env.redeem(token("962"), approvalId, STABLE, dry)).body, { ok: true, consumed: false, dry_run: true });
  assert.equal(env.githubApi.calls.length, cachedCalls);

});

test("live default branch: connection uncached, public branch answers cached 5 min per repository id, id and name checked, rate limits unavailable", async () => {
  const { liveDefaultBranchReader, GithubRateLimited, GithubUnavailable } = await import("../src/delegation/gates.js");
  let answer: { status: number; body?: unknown } = { status: 200, body: { id: 70151234, owner: { id: 90122 }, full_name: REPO, default_branch: "main" } };
  let calls = 0;
  const fetchImpl = (async () => {
    calls += 1;
    return answer.body === undefined ? new Response(null, { status: answer.status }) : Response.json(answer.body, { status: answer.status });
  }) as typeof fetch;
  const clock = { ms: Date.now() };
  let token: string | null = null;
  const read = liveDefaultBranchReader({ fetchImpl, now: () => new Date(clock.ms), connectionToken: async () => token });
  // Public API: cached for 5 minutes per repository id, branch and null alike.
  assert.equal(await read(REPO, "70151234"), "main");
  assert.equal(await read(REPO, "70151234"), "main");
  assert.equal(calls, 1);
  answer = { status: 200, body: { id: 70151234, owner: { id: 90122 }, full_name: REPO, default_branch: "trunk" } };
  clock.ms += 301_000;
  assert.equal(await read(REPO, "70151234"), "trunk");
  // Another repository id (a recreated repo) or another name: null, never cached.
  const beforeNull = calls;
  assert.equal(await read(REPO, "99999999"), null);
  assert.equal(await read(REPO, "99999999"), null);
  assert.equal(calls, beforeNull + 2);
  answer = { status: 200, body: { id: 70151234, owner: { id: 90122 }, full_name: "Other/name", default_branch: "main" } };
  clock.ms += 301_000;
  assert.equal(await read(REPO, "70151234"), null);
  // Moved (a redirect) or gone (404): null.
  answer = { status: 301 };
  clock.ms += 301_000;
  assert.equal(await read(REPO, "70151234"), null);
  // Rate limits are unavailable, never cached; other failures too.
  answer = { status: 429 };
  clock.ms += 301_000;
  await assert.rejects(read(REPO, "70151234"), GithubRateLimited);
  answer = { status: 403, body: { message: "API rate limit exceeded" } };
  await assert.rejects(read(REPO, "70151234"), GithubRateLimited);
  answer = { status: 502 };
  await assert.rejects(read(REPO, "70151234"), GithubUnavailable);
  // Through the workspace's connection: never cached.
  token = "ghs_x";
  answer = { status: 200, body: { id: 70151234, owner: { id: 90122 }, full_name: REPO, default_branch: "main" } };
  const before = calls;
  assert.equal(await read(REPO, "70151234"), "main");
  assert.equal(await read(REPO, "70151234"), "main");
  assert.equal(calls, before + 2);
});

test("gates: a job_workflow_ref other than workflow_ref is SHA-pinned, except in the gate's own repo at its ref (no opt-out)", async (t) => {
  const env = await setup(t);
  const body = { repo: REPO, workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:` };
  // Decided 2026-11-23 (D2): the gate's own repository at exactly the gate's ref needs no pin...
  const sameRepoAtRef = await env.browser("/delegates/gates", "POST", { ...body, target_prefix: `${REPO}:beta:`,
    job_workflow_ref: `${REPO}/.github/workflows/publish.yml@refs/heads/main` });
  assert.equal(sameRepoAtRef.status, 201, sameRepoAtRef.raw);
  // ...but another ref of the same repository does, and so does an opt-out gate.
  const sameRepoOtherRef = await env.browser("/delegates/gates", "POST", { ...body, target_prefix: `${REPO}:nightly:`,
    job_workflow_ref: `${REPO}/.github/workflows/publish.yml@refs/heads/dev` });
  assert.equal(sameRepoOtherRef.status, 400, sameRepoOtherRef.raw);
  const optOut = await env.browser("/delegates/gates", "POST", { ...body, target_prefix: `${REPO}:canary:`, allow_source_sha_mismatch: true,
    job_workflow_ref: `${REPO}/.github/workflows/publish.yml@refs/heads/main` });
  assert.equal(optOut.status, 400, optOut.raw);
  const equal = await env.browser("/delegates/gates", "POST", { ...body, job_workflow_ref: WORKFLOW });
  assert.equal(equal.status, 201, equal.raw);
  const sameRepoSha = await env.browser("/delegates/gates", "POST", { ...body, target_prefix: `${REPO}:stable:`,
    job_workflow_ref: `${REPO}/.github/workflows/publish.yml@${SHA}` });
  assert.equal(sameRepoSha.status, 201, sameRepoSha.raw);
});

test("gates: only an org owner or admin's gate serves (pending D5); at most 10 live gates per repository and workflow", async (t) => {
  const env = await setup(t);
  const bobId = await env.addMember("admin-bob@acme.test");
  await env.database.query("UPDATE organization_memberships SET role = 'admin' WHERE user_id = $1", [bobId]);
  const bob = await env.desktopSignIn({ hostName: "admin-bob-box", userId: bobId });
  const body = { repo: REPO, workflow_ref: WORKFLOW, ref: "refs/heads/main", event: "workflow_dispatch", target_prefix: `${REPO}:` };
  assert.equal((await env.bearer("/delegates/gates", "POST", body, bob.accessToken)).status, 201);
  // Bob is demoted: his gate no longer serves, and with no qualified gate the answer is gate_owner_unqualified.
  await env.database.query("UPDATE organization_memberships SET role = 'member' WHERE user_id = $1", [bobId]);
  const approvalId = await env.approval([STABLE]);
  const refused = await env.redeem(mint(env.github, env.workflowClaims({ run_id: "990" })), approvalId);
  assert.equal(refused.status, 403, refused.raw);
  assert.deepEqual(refused.body, { ok: false, reason: "gate_owner_unqualified" });
  // At most 10 live gates per (repository, workflow_ref), Bob's included: the 11th is 409 gate_limit.
  for (let index = 0; index < 9; index += 1) await env.gate({ target_prefix: `${REPO}:c${index}:` });
  const eleventh = await env.browser("/delegates/gates", "POST", { ...body, target_prefix: `${REPO}:c10:` });
  assert.equal(eleventh.status, 409, eleventh.raw);
  assert.equal(eleventh.body.code, "gate_limit");
});
