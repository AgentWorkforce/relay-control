# Owner-named trusted delegates

A person names which of their agents may relay their approval ("Khaliq says:
merge #2250 when green"), for which action classes and targets, until when.
Control checks each such approval and signs an attestation. The recipient's
relay-node verifies that attestation and writes a delegate line that only
Relay can write. This is the self-hosted twin of Agent Relay Cloud's surface.
The wire contract is AgentWorkforce/relay
`docs/design/owner-trusted-delegates.md` §16. Paths, request bodies, status
codes, response shapes, reason codes, JWS claims and the JWKS path match
Cloud's implementation (cloud#6501), so a relay-node or dashboard works against
either.

**Error body.** Unlike the rest of this API, every refusal on these routes
uses Cloud's delegation error body, `{"error": "<message>", "code": "<code>"}`,
with `Cache-Control: no-store`. An unexpected failure is `503 unavailable`.

**Off by default.** Nothing changes until a workspace owner or admin sets
`delegation_enabled` with `PUT /api/v1/workspaces/{ws}/delegates/policy`.
Attestation also needs a signing key (below).

## Configuration

| Variable | Meaning |
| --- | --- |
| `SELFHOST_DELEGATION_SIGNING_KEY` (or `_FILE`) | The Ed25519 signing key: a PKCS#8 PEM, or Cloud's keyring JSON (below). A base64url 32-byte seed (the earlier form) is still read. |
| `SELFHOST_DELEGATION_SIGNING_KID` | Optional. The key id, 1–64 of `A-Za-z0-9._-`. Default: the RFC 7638 thumbprint of the public key, as Cloud. |
| `SELFHOST_DELEGATION_PREVIOUS_KEYS` | Optional JSON array of up to 3 public keys `{kid?, x}` (or OKP JWKs) kept in the JWKS: retired keys, or a key published before it signs. Not together with a keyring's `previousPublicJwks`. |

Not configured (empty, `unset`, or a `*-disabled` placeholder, as Cloud):
attestation answers `{"verdict":"none","reason":"unavailable"}` and the JWKS
is `{"keys":[]}`. A value that is set but malformed stops startup, as every
other relay-control secret does, rather than running with attestation silently
off.

The kid defaults to the RFC 7638 thumbprint, as Cloud's. An explicit kid
(`SELFHOST_DELEGATION_SIGNING_KID` or the keyring's `kid`) is kept as given
and not checked against the thumbprint: verifiers match a kid exactly, so an
install that already published one keeps it. Every published kid must be
distinct.

### Generating and rotating the key

Generate a key and point the server at it (the file stays mode 0600):

```sh
openssl genpkey -algorithm ed25519 -out delegation-signing.pem
chmod 600 delegation-signing.pem
SELFHOST_DELEGATION_SIGNING_KEY_FILE=/path/to/delegation-signing.pem
```

Its kid is shown in `GET /.well-known/relay-delegation-keys.json`, which is
cached for 5 minutes (`public, max-age=300`) when it holds keys and `no-store`
when it is empty, so verifiers pick up a first key at once.

Rotate (quarterly, or at once if the key leaked) with Cloud's keyring JSON,
which keeps up to 3 retired public keys in the JWKS so that attestations they
signed keep verifying for their 300-second life and beyond:

1. Read the current public key from the JWKS:
   `curl -s https://<origin>/.well-known/relay-delegation-keys.json`.
2. Generate a new key as above, and write the keyring:

   ```json
   {"currentPrivateKeyPem": "<new PEM, newlines as \n>",
    "previousPublicJwks": [{"kty": "OKP", "crv": "Ed25519", "x": "<old x>", "kid": "<old kid>"}]}
   ```

   Keep at most 3 previous keys; drop the oldest.
3. Set `SELFHOST_DELEGATION_SIGNING_KEY_FILE` to the keyring file and restart.

Relay-nodes cache the JWKS for up to an hour and refetch on an unknown kid.
To avoid even one refetch, publish the new public key first: add it to
`SELFHOST_DELEGATION_PREVIOUS_KEYS`, wait an hour, then switch the signing
key and move the old public key into the previous list.

## Enablement checklist

Delegation is off by default. Before a workspace turns `delegation_enabled`
on in production, check each of these (decided 2026-11-23):

- [ ] The real-Postgres delegation tests run in CI, not only locally (#286):
      they prove commit-safe audit paging, serialized consumption and the
      sweep's lock behaviour.
- [ ] A signing key is configured and published (`GET
      /.well-known/relay-delegation-keys.json` lists it), with a rotation plan
      (above).
- [ ] `RELAYCAST_INTERNAL_SECRET` is set if quotes must be redacted in
      Relaycast too, and the redaction backlog is watched
      (`docs/delegation-quote-redaction-runbook.md`).
- [ ] Alerts exist for `delegation.unavailable` and `delegation.revoke_failed`
      (#289).
- [ ] Verifier UIs label `claims.quote` as delegate-asserted text, not the
      owner's words (#312).
- [ ] Release gates: decide who may register a gate for a repository
      (installation coverage, code ownership or admin) before relying on
      gates for another code owner's approvals (#313). D5 is recorded
      (#owner-decisions 250887862744305664): relay-control lets only org
      owners and admins own gates.

## Who may call what

**Human-only routes** (`/delegates`, `/delegates/{grant_id}`, `revoke-all`,
`claims`, `approvals`, `audit`, `policy`, `target-owners`) take one of two
credentials:

- the browser account session (the `/cloud` cookie with scope `account`).
  Cookie writes need JSON from an allowed Origin, as on every cookie route.
- a verified Agent Relay Desktop bearer: a session redeemed with S256 from a
  browser-consent handoff that named the Desktop host
  (`token_sessions.desktop_verified_at`). This is relay-control's equivalent
  of Cloud's `isVerifiedDesktopSignInBearer`. Enrollment-key sessions are
  machine credentials and are refused here.

A device-flow CLI login, an unexchanged handoff, a workspace API token, the
bootstrap bearer and any Relaycast agent token are refused (`401
unauthorized`, or `403 forbidden`). A caller who is not a current member of
the workspace's organization is `403 forbidden`. Audit records the method as
`session` or `desktop_bearer`, as in Cloud. While delegation is off, everything except `GET`
and revocation answers `403 not_enabled`. `PUT /delegates/policy` is exempt,
because it is how delegation is turned on.

Either credential is enough for every owner action: creating or changing a
grant, minting a tier O approval, setting policy or target owners, and starting
a claim. There is no recent-sign-in requirement and no browser confirmation
step (§4.1, Khaliq's decision). Every owner action is audited.

**Agent routes**:

- `POST /messaging/delegation`, `/messaging/delegation/redeem` and
  `/messaging/delegation/prompt-delegates` take the recipient owner's verified
  Desktop bearer (enrollment-key Desktop sessions are allowed here, as for a
  relay-node). The recipient or session must be bound in Control to that person
  by exactly one binding, and must be proven by its own Relaycast token
  (`GET /v1/agent` matches id, name and address). This is the same as Cloud's
  native-authority route (#4987).
- `POST /delegates/claims/complete` takes no Control credential. The proof is
  the one-time code plus the agent's own Relaycast token for exactly
  `agent_id`.

## Bindings

A delegate must be bound to its owner by exactly one Control record across
`desktop_relay_identities`, `hosted_relay_participants`, `relay_spawns`
(`ready` only; other states still count toward ambiguity), `person_identities`
and `delegation_agent_bindings` (a completed claim). This is Cloud's
binding-uniqueness rule, with relay-control's own tables. Any duplicate means
no binding. A claim is refused for an agent that already has any binding
(`409 already_bound`).

Claims: `POST /delegates/claims` returns `{claim_id, code, expires_at}`. The
code is `dlg_` followed by 24 random bytes in base64url. It is valid for 10
minutes and stored only as its SHA-256. `claims/complete` answers
`{claim_id, agent_id, owner_id}`. It refuses with:

- `404 invalid_code` for an unknown, used or expired code;
- `403 invalid_agent` when the token does not prove `agent_id`;
- `409 already_bound`.

## Grants

There is one active grant per (owner, delegate), as in Cloud. A second grant
answers `409 grant_exists`. A grant that has lapsed is marked `expired`
(audited `grant.expired`) when the pair gets a new grant.

`PATCH` only narrows, and works while delegation is off (as Cloud). Anything wider is `400 widening_not_allowed`: revoke
the grant and create a new one.

Grant JSON is `grant_id, owner_id, delegate_agent_id, scopes, require_tier_o,
expires_at, status, created_at, updated_at, revoked_at, revoked_reason`.

`PUT /delegates/policy` sets the fields it names and keeps every other field at
its stored value (the defaults when no policy exists yet), as Cloud: a PUT
that only flips `delegation_enabled` never resets `require_tier_o` or
`allowed_classes`. `allowed_classes: null` means every class. The answer is the policy plus `revoked_grants` (the ids of
grants revoked because they no longer fit).

`GET /delegates/policy` is read-only and open to any member of the workspace
(a browser session or a Desktop-verified bearer, as the other workspace
reads): it answers the stored policy, or the defaults when none is stored yet
(`delegation_enabled` false, `max_expiry_days` 90, `allowed_classes` null,
`require_tier_o` [], `code_owner_match` any_path). A caller of another
workspace gets 403 `forbidden`. It works while delegation is off, is not
audited, and reads membership without provisioning a Relaycast binding, so a
workspace that has none yet answers too and stays unbound.

`DELETE /delegates/claims/{claim_id}` releases a claimed agent, or cancels a
pending claim code. Its owner, or an org owner or admin, may, also while
delegation is off. A completed claim's binding ends and the owner's active
grants to that agent are revoked (`delegate_released`); a pending code can no
longer be completed. It is audited as `delegate.released` (reason
`delegate_released` or `claim_cancelled`, data `{claim_id, agent_id,
revoked_grants}`) and answers `{claim_id, released: true, revoked_grants}`; an
unknown, already released or another person's claim is 404 `not_found`.

A `merge` action names exactly one PR (`owner/repo#N`); a grant may still
name `owner/repo` or `owner/*`. A `config_change` setting is undelegable when
its name, trimmed, lowercased and with `-` and `.` read as `_`, is
`delegated_approvals_from` or `spawn_delegate_approvals` (or starts with one of
them and `_`), or mentions delegation at all.

## Attestation

The relay-node asks only for deliveries that carry `has_owner_approval`.
Control then:

1. proves the recipient (above);
2. reads the sender id and the immutable `owner_approval` from Relaycast's
   `GET /v1/deliveries/by-message/:id` for the recipient's token, never from
   the caller;
3. re-validates the approval (§16.2); anything malformed is `no_approval`;
4. finds the live grants of (`owner_id`, sender), checks that the owner is
   still a member and that the sender is still bound to the owner and live in
   Relaycast. If not, those grants are revoked (`owner_left`,
   `binding_changed`, `agent_released`);
5. for tier O (`approval_ref`), loads the owner-minted approval, whose actions
   (with conditions) must equal the message's;
6. checks expiry, then that the grant still fits the policy, policy classes
   and grant scope for every action (the whole approval or nothing). Next it
   checks tier O requirements: the policy's and the grant's
   `require_tier_o` (no class needs tier O by default, §15). Last, standing (§5.4) for
   every action under `accept` (default `code_owners`);
7. reads a tier D message's send time, as Cloud: Relaycast's `created_at`
   when it reports one, else the time in its snowflake id (top 42 bits:
   milliseconds since 2025-01-01T00:00:00Z; at most 5 minutes in the future).
   An unknown send time is `unavailable`. A message sent before the grant was
   created (before a revoke and re-grant, or before any grant) was never
   authorized by it: `predates_grant` (2 seconds of clock skew allowed). Then it fixes the approval's expiry at its
   first attestation, as Cloud's `approvalExpiry` does. The base time is the
   send time. The expiry is the approval's `expires_at`
   (default base + 1 hour), capped at base + 24 hours and at the grant's
   expiry. Later attestations keep the stored value;
8. at the commit point, in one transaction after every Relaycast lookup,
   re-reads what steps 4 to 6 used instead of trusting the earlier copies
   (see "Commit-point checks"), then signs, records the `jti`, and writes
   `approval.attested` with the quote and its keyed digest. The route then
   re-checks the bearer.

Once the request is authenticated and well formed, every failure, including
an outage, is HTTP 200 `{"verdict":"none","reason":…}`, and an
`approval.refused` event is written on a best-effort basis. Credential and
body errors come earlier, as HTTP errors without an audit event: `401`
without a credential, `403` for a plain CLI token or another workspace's
token, and `400` for a malformed body. Positive verdicts are never cached.

The JWS header is `{"alg":"EdDSA","typ":"relay-delegation+jws","kid":…}`. The
claims are exactly `v, ws, owner_id, owner_display, delegate_agent_id,
grant_id, message_id, recipient_agent_id, approval_id, tier, actions (with
conditions), standing, single_use, iat, exp, jti`. `exp` is `iat + 300`, or
the approval's expiry when that comes sooner. `jti` is a UUID. `ws` is the
Control workspace id. A tier D `approval_id` is `apv_` followed by base62 (alphabet
`0-9A-Za-z`, big-endian, no padding) of `SHA-256(ws|message_id)[0..16]`.
`owner_display` is the person's name on one line, at most 80 characters, or
"the owner" when it is empty or looks like an email address. Brackets are
stripped. The cut is at 80 characters on a code point boundary, so an emoji is never split. The result is trimmed after the cut, as in Cloud.

### Standing (§5.4)

- `own_owner`: the approval's owner is the recipient's owner.
- `code_owners` (the relay-node default): additionally a code owner of each
  action's target.
  - **Repo targets** (`owner/repo`, `owner/repo#N`) need CODEOWNERS from
    GitHub, read through a verified, linked GitHub account. relay-control has
    no verified person-to-GitHub link, so these **fail closed** with
    `recipient_policy`. When they are supported, the rules are Cloud's: a
    PR's author never has code-owner standing on their own PR (checked
    against every linked login), and for a high-risk class on a repo-level
    target only the owners of the last whole-repo rule (`*`, `**` or `/**`;
    `/*` matches root files only) count.
  - **Other targets** use the admin table `GET/PUT /delegates/target-owners`
    (`[{pattern, repo?, owner_ids?}]`). An entry that names the person by
    member id grants standing. An entry that points at a repo needs CODEOWNERS
    and fails closed. A target with no entry accepts only the recipient's own
    owner.
  - `prompt_approval` never uses code owners.
  - `code_owner_match` (`any_path` / `all_paths`) is stored in the policy for
    parity with Cloud. It has no effect until CODEOWNERS resolution exists here.

The attestation's `standing` is `own_owner` when every action held by own
owner, otherwise `code_owner`.

### pr_ops (§5.1)

An approval names one operation on one PR: `owner/repo#N:<op>`, where `<op>`
is `close`, `reopen`, `label=<name>`, `unlabel=<name>`,
`request_review=<login>`, `rerun_ci` or `comment`. There is no `open`, as
Cloud: a PR's number exists only once it is opened, so such a target could
never be redeemed; it is refused at validation. A grant of `owner/repo`,
`owner/repo#N` or `owner/*` covers every op on a covered PR. PR conditions and
CODEOWNERS standing use the PR part.

### config_change (§5.1, §5.3)

A session's own permissions, sandbox and configuration are delegable (§15,
Khaliq's decision).

- **Approval target:** `<agent id>:<setting>=<value>`. It names exactly one
  setting (at most 100 characters) and its new value (which may be empty), has
  no `*`, and is at most 256 characters. The
  agent id must be the recipient itself.
- **Grant target:** `<agent id>:*` for one agent, or `*` for any of the owner's agents (as Cloud).
- **Limits:**
  - Always single-use.
  - Only `not_before` conditions.
  - Only the recipient's own owner has standing; code owners never apply.
- **Never delegable:** a `config_change` of `delegated_approvals_from` or
  `spawn_delegate_approvals` (the recipient's own delegation settings) is
  `out_of_scope`, including in a tier O mint.

### prompt_approval (§9.3)

A grant target is `*` or `<agent id>:*`. An approval target is
`<session agent id>:<request ref>:approve` or `:deny`, so the decision is
bound in the target, and it must name the recipient itself. It takes no
conditions; the node applies it directly, without a redeem. Only
the machine owner's delegates count. `prompt-delegates` lists the machine
owner's delegates whose live grants cover the session (excluding the session
itself). It returns an empty list when delegation is off or the class is not
allowed by policy. A session that is not the caller's, or a failed token
proof, is `403 forbidden`.

## Redeem

The receiving agent redeems right before **every** action (§6.3), and every
redeem is audited (`approval.redeemed`). Single use is **per action** (§5.1):
each action of a single-use approval redeems once, and redeeming one never
consumes another. Single-use classes are `release`, every `deploy`,
`secret_change`, `destructive`, `spend` and `config_change`: each such action
is single use on its own, and never makes the rest of its approval single use.
Only an owner-minted approval with an explicit `single_use: true` is single
use as a whole, and only that choice sets the claims' `single_use` (a
delegate's approval always has `single_use: false`). A multi-use action is
re-checked on every redeem and never consumed. Control:

- requires an earlier attestation of that approval to this recipient
  (otherwise `no_approval`), and re-checks standing under that attestation's
  `accept`;
- re-checks revocation, the delegate's binding, scope, policy and expiry;
- evaluates conditions:
  - `not_before` is checked here.
  - `ci_green`, `head_sha`, `reviews_approved` and `mergeable` need the PR's
    GitHub state, which relay-control does not read, so they **fail closed**
    with `condition_unavailable`. (Cloud's `ci_green`, for reference: each
    required check name needs at least one result, and every check run and
    commit status under that name must pass.)
  - An unmet condition answers `condition_unmet` with `unmet` and does not
    consume the approval.

The commit-point checks below run again before consuming, and a single-use
action is consumed by one atomic insert in the same transaction, so a replay
or a race with a revocation, a narrowing or a policy change is refused. The answer is
`{ok:true, consumed}` or `{ok:false, reason, unmet?}`. Cloud also returns
`checked.head_sha` for PR targets; relay-control never does, because it does
not read GitHub (PR conditions are `condition_unavailable`).

### Commit-point checks

Attestation (before signing) and redeem (before consuming) end in one
transaction, as Cloud's `decideUnderLocks`. It share-locks, in this order,
the caller's membership row, the workspace policy row, the grant row, the
approval row and then (re-proving the bearer) the session row, and decides on
that state rather than on anything read before the slow Relaycast lookups:

1. membership gone: `not_pending`;
2. delegation off: `not_enabled`;
3. the approval revoked, withdrawn or invalidated: `revoked`;
4. the grant revoked: `revoked`; the grant or the approval expired: `expired`;
5. any action outside the current grant and policy (allowed classes, the
   grant's fit, scope coverage, the recipient's own target): `out_of_scope`;
6. for tier D, any action in the union of the protocol, policy and grant
   Tier O lists: `tier_o_required`;
7. `code_owner_match` changed since standing was resolved: `unavailable` (retry);
8. the bearer revoked: `not_pending`;
9. standing against the target owners as committed now: `recipient_policy`
   (relay-control reads them locally).

The attestation (or, for redeem, the consumption and the `approval.redeemed`
event) is written in the same transaction, and the attestation is signed
last, so a refusal signs nothing. If the `approval.redeemed` write fails, the
consumption rolls back and the answer is `unavailable`: no use goes
unrecorded. Refusal events (`approval.refused`, `redeem.refused`) are
written only once the recipient is proven; a refusal before that (delegation
off, no key, a bad token) is logged as `delegation.refused`, never audited.
A redeem refusal is audited only once the approval is known to have been
attested to that caller; before that (an unknown approval, or one never
attested to it) it is logged only, so another member's agent cannot write rows
into the approval owner's view.
An identical `approval.refused` (message, recipient, reason), or
`redeem.refused` (approval, recipient, action, reason), is written once per 10
minutes; repeats are still logged. A refusal row keeps the sender's quote and its
keyed digest like any other row, as Cloud, so it ages out on the org window,
can be redacted, and its redaction queues the Relaycast copy's removal.
They stay best-effort; a failed write is logged
(`delegation.audit_write_failed`), as is every `unavailable` caused by an
exception (`delegation.unavailable`). See
`docs/delegation-quote-redaction-runbook.md` for the log lines.

An approval is spent only when EVERY action is single use and every one has
been consumed; it is then stamped `consumed_at` in the consuming transaction.
A spent approval is no longer unredeemed: grant revocation and `revoke-all`
leave it alone, unless a release gate redeemed it. The run that consumed a
gate-redeemed action may redeem it again (`same_run`), so revocation reaches
such an approval too. One that still has a reusable action (a merge next to a
release, say) is never spent: attest still delegates it, and a revocation
still reaches it. Redeem reads the clock again after the bearer check (which
can wait on a session lock) and re-checks expiry right before consuming.
Grant creation locks the owner's active grants to the agent (by id), then the
agent's claim rows, the order claim release and revocation use, and re-proves
the binding under those locks; a release that waited re-reads the grants once
it holds the claim and revokes one created meanwhile. Creation and release for
one agent first take a per-agent advisory lock, so a second creation can never
hold a new grant's row lock while a release re-reads the grants. A stamp left
by the earlier spent rule on a mixed approval does not keep it from being
revoked: revocation skips only approvals spent under the current rule. The
current rule never stamps a mixed approval, so such a stamp was left by the
earlier rule, whose revoke-all could have skipped the approval: attest, redeem
and gate redeem refuse it as `revoked` (fail closed; its owner approves again). Its `exp` is the
least of 300 seconds after issue, the approval window found earlier, and the
grant's and approval's expiry as read under the locks. Policy `PUT` (policy,
then grants, then approvals) and revocation (grants, then approvals) take
these rows in the same order. A consuming call (redeem, gate redeem) locks the
approval `FOR NO KEY UPDATE` instead of `FOR SHARE`, so consumers of one
approval run one at a time: insert the consumption, stamp `consumed_at`,
write the event, commit. Attestation keeps `FOR SHARE`. A gate dry run takes
no lock at all: it answers from plain reads, the last of them just before it
answers, so a change committing after that is not reflected.

### Revoking or withdrawing one approval

- `DELETE /delegates/approvals/{approval_id}`: the approval's owner (or an
  admin) revokes one approval, tier D or tier O. It is allowed while
  delegation is off, answers `{approval_id, status: "revoked"}`, and is
  audited as `approval.revoked`.
- `POST /messaging/delegation/withdraw` takes `{delegate_agent_id,
  delegate_token, approval_id}`. The delegate that sent an approval
  withdraws it, for example when the owner later says no. The proof is the
  delegate's own Relaycast token: it must name an agent in this workspace's
  relay, and the approval must be one this delegate sent (minted under its
  grant, or attested from it). It works while delegation is off, like every
  other revocation. No person's credential is needed, because withdrawing only
  narrows. An unknown approval is 404 before any Relaycast call, and a token
  that does not prove the agent (or an agent not in this relay, or an
  approval it did not send) is the same 404. It is audited as
  `approval.withdrawn`.

After either, the next attest or redeem of that approval is `revoked`.

## Release gates (§11a)

The job that publishes redeems the approval itself, under its own short-lived
workflow OIDC token, right before its first publish step. Whatever starts the
job therefore cannot skip the check. No stored secret is involved.

**Registering a gate.** `GET`/`POST`/`DELETE /delegates/gates` are for the
owner, by browser session or verified Desktop bearer. **Gate-owner
qualification is Khaliq's decision D5, option (b) (#owner-decisions
250887862744305664):** only an org owner or admin may register a gate (403 `gate_owner_unqualified` otherwise), and a
gate serves only while its owner still is one. relay-control reads no
CODEOWNERS, so this is stricter than Cloud's code-owner-or-admin rule. At
most 10 live gates may share a repository and workflow file (the
`workflow_ref` path without its `@ref`, so every ref and tag pattern of one
file shares the cap) in a workspace (409 `gate_limit`), and one redeem
evaluates at most 10 candidate gates, oldest first. `DELETE` names the gate
with `?gate_id=` or `{gate_id}` and answers `{gate_id, deleted:true}`. A gate is `{gate_id, repo, workflow_ref, job_workflow_ref?, ref,
ref_pattern, event, target_prefix}`. For example:

- `repo`: `AgentWorkforce/relay-app`
- `workflow_ref`: `AgentWorkforce/relay-app/.github/workflows/desktop-promote.yml@refs/heads/main`
- `ref`: `refs/heads/main`
- `event`: `workflow_dispatch`
- `target_prefix`: `AgentWorkforce/relay-app:`

A gate sets exactly one of `ref` (exact, `refs/heads/...` or `refs/tags/...`)
and `ref_pattern`. A `ref_pattern` is `refs/tags/<literal prefix>*`, with one
trailing `*` and nothing else wild, and it is matched against the token's `ref`.
A gate trusts one OIDC issuer: GitHub Actions by default, or a self-host
issuer from `SELFHOST_DELEGATION_OIDC_ISSUERS` named in `issuer` (shown on the
gate only when it is not GitHub). A same-named repository on another issuer is
a different repository. When several members register the same workflow with
overlapping prefixes, the first (oldest) matching gate whose owner is still a
member and has standing serves.

`workflow_ref` must be a workflow in the gate's repo at the gate's own `ref`,
or, for a tag gate, at its `ref_pattern` (`…/release.yml@refs/tags/v*`): each
tag run's token names its own tag, and the gate matches `<file>@<that tag>`
for a tag the pattern covers. When the publishing job runs inside a reusable
workflow, the gate also sets `job_workflow_ref` (that workflow's file and a
full ref, the gate's `ref_pattern`, or a 40-hex lowercase commit SHA, which
may be in another repo), and the token's `job_workflow_ref` must match it
exactly too. A gate without `job_workflow_ref` covers only the jobs defined
in its own file: the token's `job_workflow_ref` must be absent or equal its
`workflow_ref` (a job inside a reusable workflow must be named on the gate).
A `job_workflow_ref` other than the gate's own `workflow_ref` must be pinned
to a 40-hex commit SHA (400 otherwise): it is matched by name only, and a
branch or tag can be moved to an edited workflow. The one exception (decided
2026-11-23): a reusable workflow in the gate's own repository at exactly the
gate's `ref`, when the gate does not set `allow_source_sha_mismatch`. GitHub
reports a local `uses: ./…` call and a `uses: <repo>/…@<branch>` call with the
same `job_workflow_ref`, and the second reads the workflow at the branch's head
when the run starts, so a redeem through such a gate also needs the token's
`job_workflow_sha` to equal its `sha` (the reusable workflow was read at the
run's own, approved commit), and a commit-pinned one needs `job_workflow_sha`
to be that commit; otherwise it answers `gate_mismatch`.
`target_prefix` must start with `<repo>:`, end with `:` (a segment
boundary, so `repo:stable:` never covers `repo:stable-canary:…`) and contain
no `*`. `allow_source_sha_mismatch` (default false, shown on the gate only when
true) lets candidate-run release targets name a source commit the run is not
on (see step 5). Only a gate on the repository's default branch
(`ref` = `refs/heads/<default_branch>`) can set it (400 otherwise): a tag,
exact or pattern, or any other branch can carry an edited workflow.

**Pinned at registration, as Cloud.** Registering resolves the repository's
GitHub ids through the workspace's GitHub connection (App installation or
OAuth) when it has one, else GitHub's public API. GitHub's canonical
`full_name` must equal the registered `repo` (case-insensitive). The gate
stores `repository_id`, `repository_owner_id` and `default_branch` (shown on
the gate), and `gate.pinned`
(`{gate_id, repo, repository_id, repository_owner_id, source: "registration"}`)
is audited after `gate.registered`. A repository GitHub doesn't know (or
can't show this workspace, or that was renamed) is 422 `repository_unresolved`;
a GitHub outage is 503 `unavailable`. A 404 or redirect (never followed)
through the workspace's connection is 422 without asking the public API; no
connection falls back to the public API, but a connection that fails is 503
with no fallback. GitHub omitting `default_branch` is 503. relay-control only: a gate on a self-host
issuer names `repository_id`, `repository_owner_id` and `default_branch` itself, because Control
cannot look those repositories up on github.com; a GitHub Actions gate cannot. `event` is one
of `push`, `workflow_dispatch`, `release` and `schedule`: only events that run
the gated ref's own workflow code (never `pull_request*` or `workflow_run`).
Registering needs delegation on and a current member (the membership is
held until the insert commits). The same live gate (owner, repo,
`workflow_ref`, `job_workflow_ref`, event, `target_prefix`) cannot be
registered twice (the repository in any letter case): 409 `gate_exists`. A registry outage is
logged as `delegation.unavailable` (op `gate_registry`). Each change is audited
(`gate.registered`, `gate.pinned`, and `gate.deleted` with the whole gate and
reason `deleted`).

**Redeeming.** The job calls `POST /delegates/gates/redeem` with
`Authorization: Bearer <workflow OIDC token>` and `{approval_id, action,
dry_run?}`. Control checks, in order:

1. **The token** (before anything about the workspace is read).
   - Its signature verifies against the issuer's JWKS, found by OpenID
     discovery, cached for 10 minutes and refetched for an unknown `kid`.
   - The issuer is GitHub Actions (`https://token.actions.githubusercontent.com`)
     or one listed in `SELFHOST_DELEGATION_OIDC_ISSUERS` (comma-separated https
     URLs, at most 8; for example a GitHub Enterprise Server issuer).
   - The audience is this deployment's origin (`SELFHOST_PUBLIC_URL`).
   - The token is within its validity window, with 60 seconds of clock skew.
   - Its `sha` (the commit the run is on) is 40 or 64 hex digits, any case,
     kept lower-cased.
   - Failing any of these is `oidc_invalid`. When the issuer's keys cannot be
     read and none are cached, the answer is `unavailable` (an outage, not a
     forged token), and so is a `kid` the cached keys don't know while the
     issuer can't be reached, or within the 60-second refresh cooldown (it
     may be a key just rotated in); on a fresh answer an unknown `kid` is
     `oidc_invalid`. After a failed key fetch no
     refetch starts for 30 seconds; meanwhile the last good keys serve, or
     the call fails fast.
     Each failure is logged (`delegation.dependency_failed`, op
     `github_oidc_jwks`, with `stale_cache_served` and `status`).
2. **The gate**, matched against the token:
   - No gate for the token's `repository` is `gate_unknown`.
   - A gate's `workflow_ref`, `ref` (or `ref_pattern`) and `event` must
     match the token's `workflow_ref`, `ref` and `event_name` exactly, and
     its `job_workflow_ref` too when set; otherwise `gate_mismatch`. Matching the repository alone is not enough.
     Repository names (also the `owner/repo/` part of a workflow ref) match
     case-insensitively, as on GitHub; the workflow file and ref exactly.
   - Redeem never pins. A gate serves only a token carrying its stored
     `repository_id` and `repository_owner_id`, so a repository that later
     reuses the name never does. No gate matching by name is `gate_mismatch`.
     A gate that matches by name but holds other ids is `repository_mismatch`:
     audited as `gate.refused` for that gate's owner and logged as
     `delegation.repository_mismatch` (warn), also on a dry run.
   - Until a gate matches and is pinned, the caller is nobody in particular:
     `oidc_invalid`, `gate_unknown` and `gate_mismatch` write nothing to the
     workspace's audit log.
3. **Delegation on**, otherwise `not_enabled`.
4. **The target prefix**: the action's target must start with a matching
   gate's `target_prefix`, otherwise `target_prefix`.
5. **The approval.** Release gates redeem releases only: an action of any
   other class is `out_of_scope`, before the commit check, standing and
   conditions. Then the normal redeem checks run:
   - the approval exists, and the action is one it names;
   - revocation;
   - for a delegate's (tier D) approval: its grant, the delegate's binding,
     scope and tier O requirements;
   - for an owner-minted (tier O) approval: the owner's membership and
     policy classes;
   - expiry;
   - the gate owner's standing (§5.4; the gate's owner stands where a
     recipient's owner would);
   - conditions (`not_before`; GitHub conditions are `condition_unavailable`).

   Right after the action is found, a `release` is bound to the run's commit,
   as Cloud: the target's sha (the last segment for land and iOS, the source
   sha for a candidate) must equal the token's `sha` (a 64-hex sha never equals
   a 40-hex target). On a mismatch only gates on the default branch with
   `allow_source_sha_mismatch` keep serving a candidate target, land and
   iOS targets keep none, and with none left the answer is `sha_mismatch`.
   For a GitHub Actions gate the default branch is then read live from
   GitHub (never on an on-commit redeem): through the workspace's connection
   when it has one (not cached), else the public API, whose branch answers are
   cached per repository id for 5 minutes (a null answer never is). GitHub's id must equal the gate's
   repository id and its `full_name` the repo. If the branch moved, or GitHub
   no longer resolves the repository (404 or redirect), the opt-out does not
   apply; a rate limit (403/429) or any other failure is `unavailable`, never
   cached.
   A self-host issuer gate keeps the default branch its owner named.
   Other classes are not sha-bound. Every gate event carries the run's `sha`.

   A `release` action must name exactly one release (§11a.2), or the
   approval is malformed (`no_approval` at attestation, `out_of_scope` here):
   - `<repo>:<channel>:v<version>:<source sha>:<candidate run id>[:<profile id>]`
   - `<repo>:land:<branch>:<head sha>`
   - `<repo>:ios:<distribution>:<build number>:<sha>` (the build number is
     dot-separated digit groups, at most 32 characters)

   The land `<branch>` is letters, digits, `.`, `_`, `/` and `-`, and only a
   name `git check-ref-format --branch` accepts (no `..`, no leading `-`,
   `.` or `/`, no component starting with `.` or ending in `.lock`, no `//`,
   no trailing `/` or `.`).

   A `release` grant pattern matches like every other pattern: `*` stands
   for exactly one segment between `/`, `:` or `#`. So
   `owner/repo:land:*:*` covers `main` but not `feature/x`, and
   `owner/repo:land:feature/*:*` covers `feature/x`; a stored grant covers
   exactly what it covered before. A pattern is accepted when a grant is
   created or patched only if replacing each `*` with a valid value gives a
   real release target within 256 characters, so `owner/repo`, `owner/*`,
   `*`, `owner/repo:land:bad..branch:*` and `owner/repo:stable:*:main:*`
   are refused (`400`). A grant stored with such a pattern before this rule
   still covers no release.

   Rollout: a `release` approval minted before this grammar with a bare
   `owner/repo` (or any other non-release) target is deliberately not
   migrated and has no legacy exception. It is never redeemable: it answers
   `out_of_scope`, fails closed, and lapses at its own expiry. Ask for a new
   approval that names the release. Nothing is consumed or invalidated by
   the rollout itself.
6. **A fresh re-read** of what the redeem rests on (delegation on, the
   approval unrevoked and unexpired, its tier D grant live and in scope and
   the class not newly tier O, its tier O owner and the gate's owner still
   members, the class still allowed). A dry run answers from it.
7. **Single use per run, per action** (§5.1), decided under locks as at
   redeem (`decideUnderLocks`: the gate owner's and, for tier O, the approval
   owner's membership, the policy, the tier D grant, the approval, then the
   gate row). Expiry of the approval and of a tier D grant is judged on a
   clock read once the gate and approval locks are held, so waiting on a
   concurrent gate delete that rolls back cannot consume an approval that
   expired during the wait (`expired`). A departed gate owner is `recipient_policy` for tier D and a
   departed approval owner `revoked` for tier O.
   - The first redeem of an action consumes that action and binds it to the
     token's `run_id`, GitHub repository id (so a rename changes nothing)
     and issuer. Other actions of the same approval are unaffected. Once every
     single-use action is spent the approval is stamped `consumed_at`.
   - Any later redeem in the same run, by another job or a later attempt,
     answers `{ok:true, consumed:true, same_run:true}`.
   - Any other run gets `consumed`.

`dry_run: true` runs every check and never consumes. It answers
`{ok:true, consumed:false, dry_run:true}` or `{ok:false, reason, dry_run:true}`.

HTTP status, as Cloud: 200 for a redeem or any dry run; otherwise 401
(`oidc_invalid`), 503 (`unavailable`, `condition_unavailable`: retry) or 403
(every other reason: final). The body is the same either way. A consuming
redeem locks the approval `FOR NO KEY UPDATE`, so redeems of one approval run
one at a time; a dry run takes no locks (it answers from the fresh re-read). `gate_unknown`, like `oidc_invalid`,
is not counted as `delegation.refused`.
`gate.redeemed` (with the run, attempt, repository, workflow refs, ref,
event, action and `same_run`, auth method `github_oidc`) is written in the
consuming transaction: if the write fails, the consumption and run binding
roll back and the job is answered `unavailable`. `gate.refused` and a passing
dry run's `gate.checked` are best-effort (a failed write is logged), so
`gate.redeemed` counts real uses only. A dry run carries `dry_run: true` in
the event data, as in Cloud. An exception is logged as
`delegation.unavailable` (op `gate_redeem`), and each refusal but
`oidc_invalid` as `delegation.refused`.

Migration `0089_delegation_release_gates.sql` adds `delegation_gates` and
`delegation_gate_redemptions`.

## Trust rule

The owner's set-once trust rule, the self-hosted twin of Cloud's
(cloud#6635). One live rule per owner per workspace
(`delegation_trust_rules`) trusts every agent the owner connected, and every
agent those launch through Control, for every class the workspace policy
allows, with no expiry and no Tier O by default, until revoked.

Routes (people only, as the other human routes; an org owner or admin may
read or revoke another owner's rule with `?owner=<user id>`):

| Route | Behavior |
| --- | --- |
| `GET /delegates/trust-rule` | `{rule \| null, covered, shadowed}`: the agents covered now (one system grant each, with `root_kind`, `connector`, `root_agent_id`, `launched_by`, `hops`) and the agents an unexpired owner-made grant shadows. |
| `PUT /delegates/trust-rule` | Body `{require_tier_o?}`. Idempotent: 201 the first time, 200 after. 403 `not_enabled` while delegation is off. A Tier O change reaches every system grant of the rule in the same transaction. |
| `DELETE /delegates/trust-rule` | One-click revoke of the rule, its system grants and their unredeemed and gate-spent approvals, in one transaction. Allowed while delegation is off. 404 when no rule is on. |

Coverage is proven by stored ownership records, never by a name:

- **Roots:** a completed, unreleased claim of the owner, or a live MCP OAuth
  grant of the owner (unrevoked, with a live session) pinned to the agent's
  immutable id (`mcp_oauth_grants.agent_remote_id`) and joined to the owner's
  hosted participant for that id. The owner's internal launcher is never a
  root. A connector root is proven no earlier than its OAuth grant.
- **Hops:** a `relay_spawns` launch of the owner, in state `ready`, whose
  launching actor is itself covered. relay-control records no owner-verified
  ready audit like Cloud's; a launch reaches `ready` only after its
  invocation's caller and node match the journaled actor and node.
- Every node has exactly one Control binding; the walk is cycle-safe and at
  most 8 deep. It is walked again at every attest, redeem, gate redeem and
  gate dry run (once per attest or redeem call). A chain that no longer
  proves out revokes the system grant durably (`binding_changed` or
  `delegate_released`); a gate dry run refuses without revoking. The rule stays.

The rule acts through system grants (`delegation_grants.trust_rule_id`,
`trust_path`, `created_auth_method = 'system'`): attest creates one when the
sender has no live owner-made grant and its chain proves out
(`grant.created`, reason `trust_rule`). An unexpired owner-made grant wins; a
lapsed one is expired first. Creating an owner-made grant supersedes the
pair's system grant (`superseded_by_grant`). A person revoking one system
grant records `owner_excluded`, and the same rule never covers that agent
again. A system grant cannot be PATCHed (409 `trust_rule_grant`). A
re-created system grant starts no earlier than the end of the rule's
earlier coverage of the pair, so a message sent in the gap predates it.
`revoke-all` revokes the scope's live rules first. With the rule live,
prompt-delegates proves each root (never their workers) and creates its
system grant before listing.

Any relation between sender and recipient is allowed under the rule,
including a bot approving its own requests (`TRUST_RELATION_MODE =
"allow_all"` in `src/delegation/trust.ts`; `down_tree_only` allows only
ancestor-to-descendant or outside the tree). A bot with its own owner-made
grant may approve its own requests too. Trusted agents never register, own
or edit release gates: those routes take a person's credential and an org
owner or admin.

A system grant covers only the chain it was created on (its fingerprint: the
root's claim or OAuth grant id, the agent ids and the launch ids). A chain
that now proves through other records (a claim released and reclaimed, a
connector revoked and reconnected, a relaunch) revokes the grant
(`binding_changed`) with its approvals, and the rule creates a fresh one
dated no earlier than the end of any earlier grant of the pair (owner-made
included). A grant that stands on a proof (rule-backed, or owner-made to a
connected assistant) covers messages only from the proof's records on
(`predates_grant` otherwise). `GET /delegates/trust-rule` reports each
covered agent's `chain` as `proven`, `broken` or `unknown`, read without
writing. Launched workers are never prompt delegates.

Lock order, for every writer and decision: the workspace row (decisions take
FOR KEY SHARE, so a workspace deletion queues behind them), memberships (the
caller's and the grant owner's, sorted), policy, rule, grants by id, the
delegate's chain rows (re-read under share locks, after the grant and before
the approval), approvals. Revoke-all locks the scope's rules, then every grant
of the scope by id, owner-made included, before any approval.

`POST /internal/v1/delegation/trust-backfill` (SELFHOST_INTERNAL_TOKEN; 404
without it) pins existing unpinned MCP OAuth grants to their agent ids where
stored rows prove it (exactly one hosted participant of the same owner holds
the consented name, no other binding, no retirement in flight, and a live
session; grants without one are skipped and counted as `no_live_session`). It is a dry
run unless `{"apply": true}`, idempotent, pages by grant id (`after`,
`next_cursor`), creates no rule or grant, and audits each pin as
`trust_root.backfilled` (actor system, reason backfill).

## Role bindings

The self-hosted twin of Cloud's role bindings (cloud#6665; #owner-decisions
251526750352171008). A trust rule becomes a **binding**. A binding has:
- a principal: one agent, a custom group, a connector kind, or every Relay agent;
- a role: Trusted, Standard, Read-only, a custom role, or `excluded`;
- an optional repo scope (`owner/repo`, `owner/*`);
- an optional expiry.
A binding acts through system grants, exactly like the legacy rule did.

| Preset | Classes | Ask me first | Limits |
|---|---|---|---|
| Trusted | merge, pr_ops, external_comms, deploy, release, destructive, secret_change, spend | deploy, release, destructive, secret_change, spend | merge requires `ci_green` and `mergeable` |
| Standard | pr_ops, merge, deploy, destructive, secret_change | merge, deploy, destructive, secret_change | none |
| Read-only | pr_ops | none | pr_ops `comment` only |

**Required conditions fail closed here.** relay-control reads no GitHub
state, so `ci_green` and `mergeable` answer `condition_unavailable` at
redeem. A Trusted merge therefore cannot be redeemed through relay-control.

**Precedence.** The most specific binding wins, and nothing is unioned:
1. an explicit grant;
2. an `agent` binding (`excluded` gives nothing and never falls through);
3. a custom `group` binding (the strictest of two, and nothing when their
   classes or repos do not overlap);
4. the root's `connector_kind` binding, then `relay_agents`.

A launched agent never inherits its spawner's role. It gets Read-only within
its root binding's repos and expiry, unless its own group or binding says
otherwise. A legacy rule (no role) keeps its old meaning, every class across
the whole spawn tree, until the role seed or a PATCH converts it. A legacy
rule and a Relay agents binding never stand together; each refuses the other
with 409 `binding_exists`.

**Locks.** Every binding, group or exclusion write takes the owner's binding
lock exclusively. That is a transaction advisory lock, taken after the
owner's membership lock. The write then re-resolves the owner's active system
grants from stored rows:
- a narrowed grant is revoked as `superseded_by_rule`;
- an excluded agent's grant is revoked as `owner_excluded`.

A materialization takes the same lock shared. Its order is:
1. membership;
2. the binding lock;
3. the policy;
4. the owner's bindings (share);
5. the delegate's creation lock;
6. the pair's grants;
7. a claim root's claim.

A new system grant is dated no earlier than:
- every contributing binding's creation and change;
- a group member's joining;
- any earlier grant's end.

**Answer 3.** An acting agent whose own grant or binding asks first for a
class takes a Tier D approval of that class only from a grant of its own
owner. This is checked before the deciding transaction and again inside it,
under the acting owner's binding lock. `approval.redeemed` records `tier` and
`minter {grant_id, delegate_agent_id, owner_id, binding_id?}`.

**Admins.** An admin acting for another owner (`?owner=`) may only:
- exclude one agent (POST or PATCH with exactly `{"role": "excluded"}`);
- revoke one grant;
- revoke all.
Deleting a binding or a group, and every group change, is refused with 403.
Removing one can widen an agent's authority through precedence.

Routes are under `/api/v1/workspaces/{workspaceId}/delegates/`:
- `roles`
- `bindings`, `bindings/{id}`
- `groups`, `groups/{id}`
- `agents`

The service-token `POST /internal/v1/delegation/role-seed` turns each live
legacy rule into a Relay agents Trusted binding. It is a dry run unless
`{"apply": true}`, and it is idempotent. It carries each rule's exclusions
into `excluded` agent bindings, and it skips an owner who already has a Relay
agents binding.

### Rolling out role bindings

A build from before role bindings reads any live row of
`delegation_trust_rules` as the owner's legacy every-class rule. Create no
binding, and do not apply the role seed, until every instance runs a build
with role bindings. During a rolling deploy, an older instance could serve a
delegation request from a binding row as if it were a legacy rule. Until a
person creates a binding, nothing is written: the migration itself changes
no data.

### Rolling back role bindings

A build from before role bindings reads every live row of
`delegation_trust_rules` as a legacy every-class rule, and every system grant
as covering every class. That includes an exclusion or a Read-only binding.
Never roll back below the build that added roles while a role binding is live.
The runbook:

1. **Stop writes first.** Turn delegation off for the affected workspaces
   (`PUT /delegates/policy {"delegation_enabled": false}`), or hold a
   read-only window. A binding written after the quiesce survives it, and the
   old build reads it as a legacy every-class rule.
2. **Apply the quiesce.** `POST /internal/v1/delegation/role-quiesce` with
   the service token and `{"apply": true}`, with the operator's go. A dry run
   (`{}`) first lists every rule an apply would end. Every owner who has a
   live role binding loses ALL their live rules, the legacy rule included,
   with their system grants and approvals, in one transaction under the
   owner's binding lock, with reason `role_bindings_quiesced`. A legacy rule
   left live under a revoked exclusion, Read-only group or connector binding
   would be what those agents fall through to: every class. An owner with
   only a plain legacy rule is untouched.
3. **Rerun until a dry run lists nothing.** One call handles at most `limit`
   owners (default 1000), and the report does not say whether more remain.
4. **Dry-run again right before cutover, and require an empty list.** Any row
   written in between survives and reads as a legacy every-class rule on the
   old build.
5. Roll back. Any owner who had a role binding has no rule at all now; their
   agents lost the authority their bindings and their legacy rule gave them.

**Exclusions do not survive a rollback.** The old build checks
`owner_excluded` grant rows only for the rule's own id. An exclusion made
since roles may have no grant row at all. An owner who turns the legacy rule
on again after the rollback gets a new rule id, so none of those exclusions
apply to it. That owner must revoke the excluded agents' grants again (`DELETE
/delegates/{grant_id}`) once they reappear under the new rule.

## Revocation

Revocation happens in these cases:

- `DELETE /delegates/{id}` (the owner or an admin);
- `revoke-all` (own grants, or `{all:true}` for admins);
- a policy change that a grant no longer fits (reason `policy_changed`);
- automatically at use time (see Attestation step 4).

Revoking invalidates every unredeemed approval under the grant at once.
`revoke-all` also invalidates the owner's (or, with `all`, the workspace's)
unredeemed approvals, writes one `approval.revoked` event for them with data
`{scope: "revoke_all", count, approval_ids}`, and answers
`{revoked: [grant ids]}`.
Turning `delegation_enabled` off makes every attestation and redeem
`not_enabled` without deleting grants.

## Audit

`delegation_audit_events` is append-only per workspace. Events:

- `grant.created`, `grant.updated`, `grant.revoked`
- `delegate.claimed`
- `approval.minted`, `approval.attested`, `approval.refused`
- `approval.redeemed`, `redeem.refused`
- `policy.updated`, `target_owners.updated`
- `approval.revoked`, `approval.withdrawn`, `quote.redacted`

`GET /delegates/audit?since=&grant_id=&format=jsonl&limit=&after_id=` shows an
admin every event. A member sees, as Cloud, the events filed under them as
owner (their grants and approvals) and the events they caused that are filed
under no owner (a policy change, a refusal before any grant from the claimed
owner exists); on those ownerless rows `quote` and `quote_hash` are null. As a
recipient's owner they do not see another owner's attestations, refusals or
redeems. A refusal that names an owner with no grant to that sender is filed
under no owner, with `data.claimed_owner_id`. The answer is `{events,
next_after_id, complete}` (JSONL: the `X-Audit-Next-After-Id` and
`X-Audit-Complete` headers). Paging is commit-safe, as Cloud: each event
records the id of the transaction that wrote it (`xact_id`, never returned),
and events come in `(xact_id, id)` order. The fence is the statement's
snapshot xmin, read with the rows: events of transactions below it are final.

- The first page (no `after_id`, or `0`) lists every committed event.
  `next_after_id` is the last listed event below the fence.
- To page, pass `after_id=<next_after_id>`, not the last event's id. A cursor
  page lists only events after that event's `(xact_id, id)` and below the
  fence, so it never skips an event whose transaction committed late. Events
  held back are counted (logged as `delegation.audit_fenced`) and make
  `complete` false; `next_after_id` is the last listed event, or the cursor
  itself when none is.
- `complete` is true when the page is not full and nothing was held back.
  Events after the cursor may repeat; none is ever skipped.
- An id that names no event of this workspace, or one this viewer cannot list,
  is 400 `invalid_request`.

The log is append-only (a trigger refuses every change but a
quote redaction, and deletes outside a workspace deletion). Each event is `id, event,
created_at, actor_user_id, actor_agent_id, auth_method, owner_id, grant_id,
approval_id, message_id, recipient_agent_id, reason, data, quote, quote_hash,
quote_redacted_at`, as in Cloud. The attestation's `jti` and `kid` are in
`data`. `quote_hash` is a keyed digest (§8), `hmac-sha256:v1:<64 hex>` (the version names the key derivation): an
HMAC-SHA256 under a per-workspace key (HKDF-SHA256, salt
`relay-delegation-quote-digest-v1`, info `workspace:<id>`, as Cloud) derived
from a server-held secret, so a reader of the log
cannot test guessed quotes against it. The key is `SELFHOST_DELEGATION_QUOTE_KEY`
(at least 32 bytes) or, when unset, the active encryption key;
set it to keep digests stable across encryption key rotations. The quote
itself is also in the signed claims (`quote`). Quote text is redacted to `quote_hash` (with
`quote_redacted_at` set) once it is older than the org's
`quote_retention_days`. An hourly sweep (started with the server) also runs the
redaction and marks lapsed grants `expired`, so a quiet workspace does not keep
quote text past its window. Each run handles at most 500 grants and 500
quotes (read per workspace as one index range up to its org's cutoff), then tries the due Relaycast redactions and reports the queue's
backlog (see `docs/delegation-quote-redaction-runbook.md`).

- This is §15.9, Khaliq's decision: an org setting from 1 to 3650 days,
  default 90. It is set with `GET`/`PUT /api/v1/orgs/{org}/delegation-policy`
  `{quote_retention_days}`.
- Only org owners and admins can call that route, by browser session or
  verified Desktop bearer.
- It applies to every workspace in the org, and no workspace policy overrides
  it. A change is audited as `org_policy.updated` in each workspace of the
  org.
- A shorter window redacts existing older quotes at the next sweep. A longer
  one restores nothing.
- The redaction runs hourly from the server, and also on every audit read.
  The hash and the event itself are kept. Nulling the quotes and queueing
  their Relaycast redaction are one statement.
- Redaction is per message. Every quote write and every redaction of a
  message take the same transaction-scoped advisory lock
  (`delegation-quote:<workspace>:<message>`). Under it, a message with a
  redaction requested (queued or done) is attested with `quote: null` and its
  event stores only the digest, with `quote_redacted_at` set. The sweep and
  audit reads also redact any event still quoting such a message. Each
  redacted message is queued for redaction in Relaycast (see below).

### Redacting one message's quote

`POST /delegates/quotes/redact {message_id}` lets the owner redact the quote
of one delegate message at any time (§8, §15.9), along with the ownerless
rows they caused (a refusal before any grant from the claimed owner); an org
owner or admin may redact any. The audit copies become null (their digests stay), one
`quote.redacted` event is written, and Relaycast is asked to redact the
quote in its stored `owner_approval`:
`POST {relaycast}/internal/workspaces/{relay workspace}/messages/{message}/owner-approval/redact-quote`
with `RELAYCAST_INTERNAL_SECRET` and no body. The answer is `{message_id,
redacted_events, relaycast: "redacted" | "queued"}`. With no quote of the
caller's for that message it is 404 `not_found`. Expired quotes redacted by
retention are queued the same way. Each Relaycast try is recorded as Cloud
records it (`relaycast_outcome`, `relaycast_status`):

- 2xx: `redacted`, done;
- 404 `owner_approval_not_found`: `absent`, done;
- 5xx, 429, a network error or timeout, or a 404 without that code: retried
  by the hourly sweep once due: `last_attempt_at` at least
  `min(2^min(attempts, 9), 360)` minutes ago, with no attempt cap;
- any other answer (400, 401, 403, a redirect): `rejected`, parked for an
  operator (clear `relaycast_outcome` to retry it) and still counted as
  unfinished.

## Migration

`0088_owner_delegates.sql` adds these tables:

- `delegation_policies`
- `delegation_org_policies`
- `delegation_target_owners`
- `delegation_claims`
- `delegation_agent_bindings`
- `delegation_grants`
- `delegation_approvals`
- `delegation_attestations`
- `delegation_audit_events`

All of them are workspace-scoped and cascade on workspace delete.

`0098_delegation_trust_rules.sql` (additive) adds `delegation_trust_rules`,
`delegation_grants.trust_rule_id` and `trust_path`, widens
`delegation_grants_auth_method` to admit `system` for rule-backed rows only,
and adds `delegation_grants_expiry_cap`: only a row with `trust_rule_id` may
expire more than 2160 hours (90 days of 24 hours, counted in hours so a DST
change never refuses a full-length grant) and 60 s after it was created.

`0099_delegation_role_bindings.sql` (additive) adds the binding columns to
`delegation_trust_rules` (`principal_kind` default `all_agents`, `principal_ref`,
`role`, `classes`, `pr_ops_limit`, `required_conditions`, `targets`,
`expires_at`). It adds `delegation_groups` and `delegation_group_members`. It
replaces the one-live-rule-per-owner index with one live binding per
(owner, principal), a superset for legacy rows.

## Not on relay-control yet

- **Gate-only installs:** attest, redeem and claims answer `unavailable`, and
  prompt-delegates returns an empty list. Desktop identities there carry
  relaygate ids.
- **No GitHub reads:** CODEOWNERS standing and GitHub conditions fail closed
  (see above).
- **Not built yet:**
  - owner notices for each use;
  - grant expiry reminders;
  - per-grant attestation rate limits and anomaly-triggered tier O;
  - admin co-approval;
  - SIEM webhooks;
  - the delegate-requested tier O one-tap flow (`approvals/request`).
