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

| Variable                                                 | Meaning                                                                                                  |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `SELFHOST_DELEGATION_SIGNING_KEY` (or `_FILE`)           | base64url 32-byte Ed25519 seed. Generate: `node -e "console.log(crypto.randomBytes(32).toString('base64url'))"` |
| `SELFHOST_DELEGATION_SIGNING_KID`                        | key id published in the JWKS and the JWS header (1–64 of `A-Za-z0-9._-`)                                 |
| `SELFHOST_DELEGATION_PREVIOUS_KEYS`                      | optional JSON array of up to 8 `{kid, x}` retired public keys kept in the JWKS during rotation           |

The first two are required together. Without them, attestation answers
`{"verdict":"none","reason":"unavailable"}` and the JWKS is `{"keys":[]}`.
Rotate quarterly. Start signing with a new seed and kid, and move the old
public `x` (from the JWKS) into `SELFHOST_DELEGATION_PREVIOUS_KEYS` for at
least the attestation TTL plus the relay-node JWKS cache hour. A KMS-held key is
a follow-up (§15.4).

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

`PATCH` only narrows. Anything wider is `400 widening_not_allowed`: revoke
the grant and create a new one.

Grant JSON is `grant_id, owner_id, delegate_agent_id, scopes, require_tier_o,
expires_at, status, created_at, updated_at, revoked_at, revoked_reason`.

`PUT /delegates/policy` replaces the whole policy. Omitted optional fields take
their defaults. The answer is the policy plus `revoked_grants` (the ids of
grants revoked because they no longer fit).

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
   checks tier O requirements (defaults `secret_change`, `destructive`,
   `spend`, plus the policy's and the grant's). Last, standing (§5.4) for
   every action under `accept` (default `code_owners`);
7. fixes a tier D approval's expiry at its first attestation, as Cloud's
   `approvalExpiry` does. The base time is Relaycast's `created_at` when it
   reports one, otherwise now. The expiry is the approval's `expires_at`
   (default base + 1 hour), capped at base + 24 hours and at the grant's
   expiry. Later attestations keep the stored value;
8. re-checks the caller's membership, signs, records the `jti`, and writes
   `approval.attested` with the quote and its SHA-256. The route then
   re-checks the bearer.

Every failure, including an outage, is HTTP 200
`{"verdict":"none","reason":…}` plus an `approval.refused` event. Positive
verdicts are never cached.

The JWS header is `{"alg":"EdDSA","typ":"relay-delegation+jws","kid":…}`. The
claims are exactly `v, ws, owner_id, owner_display, delegate_agent_id,
grant_id, message_id, recipient_agent_id, approval_id, tier, actions (with
conditions), standing, single_use, iat, exp, jti`. `exp` is `iat + 300`, or
the approval's expiry when that comes sooner. `jti` is a UUID. `ws` is the
Control workspace id. A tier D `approval_id` is `apv_` followed by base62 (alphabet
`0-9A-Za-z`, big-endian, no padding) of `SHA-256(ws|message_id)[0..16]`.
`owner_display` is the person's name on one line, at most 80 characters, or
"the owner" when it is empty or looks like an email address. Brackets are
stripped. The cut is at 80 UTF-16 units on a character boundary, so an emoji is never split. The result is trimmed after the cut, as in Cloud.

### Standing (§5.4)

- `own_owner`: the approval's owner is the recipient's owner.
- `code_owners` (the relay-node default): additionally a code owner of each
  action's target.
  - **Repo targets** (`owner/repo`, `owner/repo#N`) need CODEOWNERS from
    GitHub, read through a verified, linked GitHub account. relay-control has
    no verified person-to-GitHub link, so these **fail closed** with
    `recipient_policy`.
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

### prompt_approval (§9.3)

A grant target is `*` or `<agent id>:*`. An approval target is
`<session agent id>:<request ref>` and must name the recipient itself. Only
the machine owner's delegates count. `prompt-delegates` lists the machine
owner's delegates whose live grants cover the session (excluding the session
itself). It returns an empty list when delegation is off or the class is not
allowed by policy. A session that is not the caller's, or a failed token
proof, is `403 forbidden`.

## Redeem

Redeem is required right before acting when the approval is single-use (any
high-risk action: `release`, `secret_change`, `destructive`, `spend`, or
`deploy` to `:prod`/`:production`) or when the action has conditions.
Control:

- requires an earlier attestation of that approval to this recipient
  (otherwise `no_approval`), and re-checks standing under that attestation's
  `accept`;
- re-checks revocation, the delegate's binding, scope, policy and expiry;
- evaluates conditions:
  - `not_before` is checked here.
  - `ci_green`, `head_sha`, `reviews_approved` and `mergeable` need the PR's
    GitHub state, which relay-control does not read, so they **fail closed**
    with `condition_unavailable`.
  - An unmet condition answers `condition_unmet` with `unmet` and does not
    consume the approval.

A single-use approval is consumed by one conditional `UPDATE` (not consumed,
not invalidated, not expired, grant still live), so a replay or a race with a
revocation is refused. The answer is `{ok:true, consumed}` or
`{ok:false, reason, unmet?}`.

## Revocation

Revocation happens in these cases:

- `DELETE /delegates/{id}` (the owner or an admin);
- `revoke-all` (own grants, or `{all:true}` for admins);
- a policy change that a grant no longer fits (reason `policy_changed`);
- automatically at use time (see Attestation step 4).

Revoking invalidates every unredeemed approval under the grant at once.
`revoke-all` also invalidates the owner's (or, with `all`, the workspace's)
unredeemed tier O approvals, and answers `{revoked: [grant ids]}`.
Turning `delegation_enabled` off makes every attestation and redeem
`not_enabled` without deleting grants.

## Audit

`delegation_audit_events` is append-only per workspace. Events:

- `grant.created`, `grant.updated`, `grant.revoked`
- `delegate.claimed`
- `approval.minted`, `approval.attested`, `approval.refused`
- `approval.redeemed`, `redeem.refused`
- `policy.updated`, `target_owners.updated`

`GET /delegates/audit?since=&grant_id=&format=jsonl&limit=` shows a member
their own events and an admin all of them. Each event is `id, event,
created_at, actor_user_id, actor_agent_id, auth_method, owner_id, grant_id,
approval_id, message_id, recipient_agent_id, reason, data, quote, quote_hash,
quote_redacted_at`, as in Cloud. The attestation's `jti` and `kid` are in
`data`. Quote text is redacted to `quote_hash` (with
`quote_redacted_at` set) once it is older than the org's
`quote_retention_days`.

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
- relay-control has no cron, so the sweep runs on every attestation and every
  audit read. The hash and the event itself are kept.

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
  - owner-initiated quote redaction;
  - SIEM webhooks;
  - the delegate-requested tier O one-tap flow (`approvals/request`).
