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
Rotate quarterly, publishing the new key before signing with it, so that
relay-nodes with a cached JWKS (an hour) already know the new `kid`:

1. Generate a new seed and kid. Add the new public `{kid, x}` to
   `SELFHOST_DELEGATION_PREVIOUS_KEYS` (which publishes any extra keys) and
   redeploy. Wait at least one JWKS cache hour.
2. Switch `SELFHOST_DELEGATION_SIGNING_KEY`/`_KID` to the new key, and replace
   its entry in `SELFHOST_DELEGATION_PREVIOUS_KEYS` with the old key's public
   `{kid, x}` (from the JWKS).
3. After the attestation TTL plus a cache hour, drop the old key.

Every published kid must be distinct.

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
   checks tier O requirements: the policy's and the grant's
   `require_tier_o` (no class needs tier O by default, §15). Last, standing (§5.4) for
   every action under `accept` (default `code_owners`);
7. fixes a tier D approval's expiry at its first attestation, as Cloud's
   `approvalExpiry` does. The base time is Relaycast's `created_at` when it
   reports one, otherwise now. The expiry is the approval's `expires_at`
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

### pr_ops (§5.1)

An approval names one operation on one PR: `owner/repo#N:<op>`, where `<op>`
is `open`, `close`, `reopen`, `label=<name>`, `unlabel=<name>`,
`request_review=<login>`, `rerun_ci` or `comment`. A grant of `owner/repo`,
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
`secret_change`, `destructive`, `spend` and `config_change`; an owner-minted
approval can also be single-use as a whole. A multi-use action is re-checked
on every redeem and never consumed. Control:

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

The commit-point checks below run again before consuming, and a single-use
action is consumed by one atomic insert in the same transaction, so a replay
or a race with a revocation, a narrowing or a policy change is refused. The answer is
`{ok:true, consumed}` or `{ok:false, reason, unmet?}`. Cloud also returns
`checked.head_sha` for PR targets; relay-control never does, because it does
not read GitHub (PR conditions are `condition_unavailable`).

### Commit-point checks

Attestation (before signing) and redeem (before consuming) end in one
transaction that re-reads, from committed state, everything the earlier
checks read before the slow Relaycast lookups:

1. the workspace policy, share-locked (a policy `PUT` locks it for update):
   delegation off is `not_enabled`;
2. the grant, locked for update (revocation and `PATCH` take the same lock):
   `revoked` or `expired`;
3. every action against the current grant and policy (allowed classes, the
   grant's fit, scope coverage, the recipient's own target): `out_of_scope`;
4. for tier D, the current policy's and grant's `require_tier_o`:
   `tier_o_required`;
5. the caller's membership and bearer, share-locked: `not_pending`;
6. the approval row, locked: revoked, withdrawn or invalidated is `revoked`;
7. standing against the target owners as committed now: `recipient_policy`.

The reason codes are the same as the early checks'. Locks are taken policy,
then grant, then membership, session and approval; a policy `PUT` (policy,
then grants, then approvals) and revocation (grants, then approvals) take
them in the same order. Attestation signs last, inside the transaction, so a
refusal at the commit point signs nothing.

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
  grant, or attested from it). With delegation off it answers 404. No person's
  credential is needed, because withdrawing only narrows. It is audited as
  `approval.withdrawn`.

After either, the next attest or redeem of that approval is `revoked`.

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
- `approval.revoked`, `approval.withdrawn`, `quote.redacted`

`GET /delegates/audit?since=&grant_id=&format=jsonl&limit=&after_id=` shows a member
their own events and an admin all of them. Events come in id order; resume
with `after_id=<last id>`. Ids come from a sequence at insert, but a row only
becomes visible when its transaction commits, so a later id can be visible
before an earlier one. A page therefore stops before the first event (of any
viewer or filter) that could still be committing: one inserted at or after
the start of a transaction still in flight on the database (read from
`pg_stat_activity` before the page's snapshot; a five-minute lag if activity
tracking is off). A page can be short or empty while writes are in flight;
the next read with the same `after_id` returns the rest, and nothing is ever
skipped. As Cloud, a paged read (`after_id`; start a follow at
`after_id=0`) also leaves out events from the last 30 seconds. Each event is `id, event,
created_at, actor_user_id, actor_agent_id, auth_method, owner_id, grant_id,
approval_id, message_id, recipient_agent_id, reason, data, quote, quote_hash,
quote_redacted_at`, as in Cloud. The attestation's `jti` and `kid` are in
`data`. `quote_hash` is a keyed digest (§8), `hmac-sha256:<hex>`: an
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
quote text past its window.

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
- The redaction runs hourly from the server, and also on every attestation
  and every audit read. The hash and the event itself are kept.
- Redaction is per message. Once any event's quote for a message is
  redacted, attesting that message again signs `quote: null` and stores only
  the digest (with `quote_redacted_at` set), and the next sweep or audit read
  redacts any other event still quoting it (one written concurrently with the
  redaction). Each redacted message is also queued for redaction in
  Relaycast (see below).

### Redacting one message's quote

`POST /delegates/quotes/redact {message_id}` lets the owner redact the quote
of one delegate message at any time (§8, §15.9); an org owner or admin may
redact any. The audit copies become null (their digests stay), one
`quote.redacted` event is written, and Relaycast is asked to redact the
quote in its stored `owner_approval` through its internal route (with
`RELAYCAST_INTERNAL_SECRET`). The answer is `{message_id, redacted_events,
relaycast: "redacted" | "queued"}`; a Relaycast failure, or no internal
secret, leaves it queued (`delegation_quote_redactions`) for the hourly
sweep, which retries with back-off. With no quote of the caller's for that
message the answer is 404 `not_found`. Expired quotes redacted by retention
are queued for Relaycast the same way.

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
  - SIEM webhooks;
  - the delegate-requested tier O one-tap flow (`approvals/request`).
