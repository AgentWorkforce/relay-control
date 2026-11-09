# Amp control

Amp control connects an Amp (ampcode.com) thread to Agent Relay: a person
connects their Amp API key, picks one of their threads, and the thread gets a
Relaycast identity. Messages to that identity are injected into the thread as
prompts, and the thread can answer through a scoped reply capability.

It is a port of the hosted control plane's Amp integration onto the control
plane's Postgres, Relaycast client and encryption keyring. The code is in `src/amp`.

## What ships and what is deferred

| Area | Status |
| --- | --- |
| Connect, discover, bind, unbind, disconnect (owner/admin, workspace routes) | Ships |
| Relay events webhook with Standard Webhooks verification | Ships; bind creates the Relaycast subscriptions (below) |
| Postgres outbox, in-process worker, internal job route | Ships |
| Reply capability `POST /api/v1/amp/agents/{bindingId}/messages` | Ships |
| `check_delivery` route = Cloud `reconcileDelivery` (read-only marker reconciliation) | Ships |
| MCP tools `list_amp_threads`, `bind_amp_thread`, `unbind_amp_thread` | Ships, only when the feature is on |
| Member-removal purge and `cleanupWorkspaceAmp` | Ships; no route calls `cleanupWorkspaceAmp` yet because self-host has no workspace deletion |
| Thread history upload to RelayHistory | Implemented up to the upload; inactive until a push-only History session can be issued (below) |
| Automatic Relaycast subscriptions at bind, deleted at unbind | Ships |
| Inbox recovery (each bound agent's hosted inbox read by the worker) | Ships; Cloud Amp has no inbox poll (see Differences) |

### History: implemented to the upload boundary, inactive

`src/amp/history.ts` ports the hosted control plane's Amp history sync and
history schedule up to the RelayHistory upload. It exports the
thread through `deps.run`, scrubs reply capabilities, parses it with
`ampExport` from `src/amp/provider.ts` (the RelayHistory parser, copied
byte-for-byte and pinned by `src/amp/provider-origin.json`), diffs per
message version against `selfhost_amp_history_syncs.versions`, keeps each
prepared page in an encrypted pending envelope until the receipt matches, and
advances the binding's `last_synced_at` watermark only after every page was
fully accepted. Metadata-only `sourceDigest` backfills are persisted without
an upload.

The upload Cloud sends, and this code sends once a session exists:

- `POST {session.baseUrl}/v1/ingest`, `authorization: Bearer
  {session.accessToken}`, 30 s timeout, no redirects.
- Body `{"machine":{"id":"amp:<workspaceId>","label":"Amp"},"batchId":"amp:<48 hex>","records":[AmpEvidence...]}`,
  up to 100 records per page.
- Success only when the receipt is exactly `{batchId, received: n, accepted: n}`.
  Anything else is `history_partial_accept` or `history_http_<status>` and
  the watermark does not move.

**It is inactive.** The upload needs a workspace-scoped, push-only
(`rth:sync`) RelayHistory session issued for a background job. Cloud mints it
with `createRelayhistorySandboxPushSession` (a RelayAuth
`/v1/tokens/relayhistory-assertion` with scopes `["rth:sync"]` and purpose
`amp-session-sync`, exchanged at History `POST /v1/cli/login`). This control
plane cannot:

- `src/relayhistory.ts` `issueRelayhistorySession` only exchanges the
  caller's own `sh_at_` person token at History `POST /v1/cli/login`. A
  background job has no caller.
- History verifies that exchange through `POST /internal/v1/auth/introspect`
  (`src/auth/introspect.ts`), which answers only `sh_at_` person access tokens
  and returns `wrong-kind` for every other token. There is no control-issued
  push credential for it to accept.
- The optional RelayAuth path (`relayauthAssertion`) asks for read and sync
  scopes with fixed `relayhistory-login` metadata on behalf of a person. It is
  not a push-only, binding-scoped job grant and is not wired.

So `src/amp/module.ts` sets `AmpDeps.pushSession` to `null`, and no mint,
trust or fallback path exists. While it is null:

- the worker never exports or polls Amp for history. It only records
  `history_error = "push_session_unavailable"` on bound bindings;
- the summary reports `history: {available: false, reason: "push_session_unavailable"}`
  and each binding's `history.state` as `unavailable`;
- the internal history job answers
  `501 {"error":"history_push_unavailable","message":"..."}`.

Supplying a `PushSessionFactory` (`(scope: {userId, organizationId,
workspaceId, bindingId}) => Promise<{baseUrl, accessToken} | null>`) is the
only change needed to activate it.

Scheduling (in-process worker, after the delivery drain):

- A bound thread whose connection still belongs to the binding's person is
  queued every 5 minutes (`AMP_HISTORY_INTERVAL_MS`, Cloud's interval) by
  setting `history_queued_at`. A queued thread keeps its original time, so
  repeated requests and ticks coalesce into one run.
- Each pass claims at most 2 queued threads with `FOR UPDATE SKIP LOCKED`
  and a run lease (`history_lease_owner`, `history_lease_until`, 15 minutes =
  Cloud's queue lease). A live lease is never claimed again; an expired one
  is. Every database step of a run re-checks, under the workspace Amp lock,
  the binding state, generation, person, connection key and lease owner, and
  renews the lease. A run that lost any of them stops without writing.
- A failure records `history_error` (a fixed code), keeps the thread queued
  and holds the lease for 15 minutes as the retry delay. The pending page is
  re-sent before a new export.
- Retired bindings (unbind, disconnect, member removal) drop their queue
  entry, lease and pending page and are never polled.

## Configuration

| Variable | Meaning |
| --- | --- |
| `SELFHOST_AMP_ENABLED` | `true` turns the feature on. Default `false`. |
| `AMP_TRANSPORT_ORIGIN`, `AMP_TRANSPORT_TOKEN[_FILE]` | The persistent Amp process service. Every Amp CLI operation (`discover`, `export`, `inject`) is `POST {origin}/v1/internal/amp/operation` with `Authorization: Bearer {token}` and body `{"v":1,"cliVersion":"...","key":"sgamp_...","operation":{...}}`. The response is `{"v":1,"cliVersion":"...","ok":true,"value":...}` or `{"ok":false,"outcome":"rejected"\|"unknown"}`. There is no sandbox. |
| `SELFHOST_AMP_INTERNAL_SECRET[_FILE]` | Bearer for the internal job route, at least 32 bytes. This is not Cloud's `BrokerHmacSecret` and not `SELFHOST_INTERNAL_TOKEN`. |
| `SELFHOST_AMP_WORKER_INTERVAL_MS` | Outbox drain interval. Default 5000. |
| `SELFHOST_AMP_LEASE_MS` | Delivery lease. Default 120000. |

When the feature is off:

- Every Amp route answers `404 {"error":"Not found"}` before any
  authentication, including through the `/cloud` alias.
- No worker starts.
- The MCP catalog leaves out the Amp tools.

Removing a member still revokes any Amp grants that person holds, whether the
feature is on or off.

The startup log shows `amp: {enabled, transport, internalJob}` as booleans
only.

## Routes

Every error body is `{ "error": code, "message": text }`. The one exception is
the gate-off and unset-secret 404, whose body is `{ "error": "Not found" }`.
Each route is also served under `/cloud`, except the internal job route.

### Workspace routes

All workspace routes live under `/api/v1/workspaces/{workspaceId}/amp`.

The caller must be a person:

- A device or session token, or a same-origin cookie. Cookie writes are
  CSRF-checked.
- The token must carry the `cli:auth` scope.
- The person must be an owner or admin of that workspace.

The role is re-read from Postgres under the workspace lock on every call.
Workspace API tokens (`sh_wk_`), `SELFHOST_INTERNAL_TOKEN` and members are
refused with 403.

| Method and path | Operation |
| --- | --- |
| `GET ""` | Summary: connection (key hint only), bindings (each with `history: {state, reason?, lastSyncedAt, lastError, queuedAt}`, state `unavailable` / `idle` / `queued` / `running` / `synced` / `error`), undelivered deliveries, top-level `history: {available, reason?}` |
| `POST /connection` `{key}` | connect: validates `sgamp_...` with a read-only `discover`, stores it encrypted, returns the summary plus `threads` |
| `DELETE /connection` | disconnect: retires every binding, deletes the key, releases Relaycast identities |
| `GET /threads` | discover: up to 100 recent threads of the connected key |
| `POST /bindings` `{threadId}` | bind one explicitly chosen thread (ID or `https://ampcode.com/threads/T-...`), `201 {binding_id, thread_id, agent}` |
| `DELETE /bindings/{bindingId}` | unbind |
| `POST /bindings/{bindingId}/deliveries/{messageId}/check` | reconcile: `{confirmed, state}` (below) |

The fences are the same as in Cloud:

- **API-key owner.** Only the person who connected the key can discover or
  bind with it (403 `not_connection_owner`). The connection cannot change
  hands while threads are bound (409 `connection_owner_locked`). A
  replacement key must be able to export every bound thread first (409
  `key_cannot_read_threads`).
- **Explicitly chosen thread.** Bind takes exactly one thread ID. It binds
  only after the stored key exports that thread (409 `amp_thread_unreadable`
  otherwise).
- A thread already bound elsewhere answers 409 `thread_owned`.
- A Relaycast name held by a foreign agent answers 409 `relay_name_taken`.

Bind runs in three committed phases so a crash or a Relaycast failure can be
recovered by binding the thread again:

1. Insert the row as `preparing` with a freshly minted `whsec_` secret
   (encrypted; a retry reuses it).
2. Register or recover the Relaycast agent and store its token. The row stays
   `preparing`.
3. Create the missing Relaycast subscriptions, store their IDs and mark the
   row `bound`.

If a subscription create fails, bind answers 502 `relay_subscription_failed`
(`{error, message}`). Any subscription this attempt already created is
deleted (best effort), including when storing an ID or the commit fails, so
the `preparing` row never points at a subscription it does not own. The retry
keeps the agent and the secret and creates the subscriptions again. There is
no fallback. The Relaycast agent is named
`amp-<sha256(thread)[0:16]>`. Its metadata carries the binding ID, the
workspace and an owner hash, and delivery authority follows the agent's
immutable ID.

Unbind, disconnect and member removal work the same way. Inside one
transaction they:

- retire the binding and bump its generation, which fences in-flight claims
- clear the agent token, the webhook secret, every reply capability and the
  queued payloads

After commit, both Relaycast subscriptions are deleted (404 counts as
deleted), and only then is the exact Relaycast agent released. Each
subscription ID is cleared once its subscription is gone. A failed delete or
release keeps the remaining IDs, leaves the row `retired`, the response says
`cleanup: "pending"`, and the worker retries.

### Relay events

`POST /api/v1/amp/relay-events/{bindingId}` is the Relaycast webhook for one
binding.

Bind creates the subscriptions itself, as hosted Cloud does. Both are
created with the workspace's Relaycast key, point at that URL and are signed
with the binding's minted `whsec_` secret using Standard Webhooks:

- DM and thread replies: events `dm.received` and `thread.reply`.
- Mentions: event `message.created`, filtered to mentions of the agent.

The secret is encrypted at rest and never returned. Without a stored secret
(a retired binding) every event is refused with 401. The summary shows
`relaySubscription: "configured"` only when both subscription IDs are stored,
otherwise `"not_configured"`.

Verification follows Standard Webhooks:

- The headers are `webhook-id`, `webhook-timestamp` and `webhook-signature`.
- The signature is `v1,<base64 HMAC-SHA256(secret bytes, "{id}.{timestamp}.{raw body}")>`.
  Several space-separated signatures are accepted during rotation.
- The timestamp must be within 300 seconds of now.
- The body is capped at 256 KiB (413 `payload_too_large`), checked against
  `content-length` and while streaming.

| Response | Meaning |
| --- | --- |
| 410 `binding_gone` | No such bound binding |
| 401 `unauthorized` | Bad signature, stale timestamp or no stored secret |
| 400 `invalid_request` | Bad JSON |
| `200 {ok:true,queued:true}` | Queued |
| `200 {ok:true,duplicate:true}` | Already queued, in flight, unknown or delivered |
| `200 {ok:true,delivered:false}` | Not addressed to this agent |

An event is addressed to this agent when it is one of:

- `dm.received` or `thread.reply` with `data.to` equal to the agent
- an `@agent` mention in a `message.created` or `thread.reply`
- a `thread.reply` whose parent the agent wrote

Events the agent sent itself are ignored. Accepting an event only writes the
outbox row.

### Reply capability

`POST /api/v1/amp/agents/{bindingId}/messages` accepts exactly one
credential, `Authorization: Bearer amp_reply_<43 base64url chars>`.

**Lifecycle**

- Each injected prompt carries a fresh bearer, minted at claim time.
- Only its SHA-256 is stored, in `selfhost_amp_deliveries.reply_hash`.
- It expires 24 hours after the claim.

**Binding.** The bearer is bound to one binding, one message ID, the original
sender and a request UUID. The body is
`{"to": sender, "text": "...", "message_id": "...", "request_id": "uuid"}`.

**Checks on every use.** The binding must still be `bound`, and its owner must
still be a member of the organization.

**Revocation.** Unbind, disconnect, member removal and workspace cleanup
revoke the bearer immediately.

**Idempotency**

- A repeat with the same text returns `{ok, duplicate, message_id}`.
- Different text answers 409 `reply_already_sent`.
- The Relaycast DM uses idempotency key `amp-<hash(binding:request)>`, so a
  retry after 502 `reply_uncertain` never sends twice.

**Refusals**

| Response | Meaning |
| --- | --- |
| 401 `unauthorized` | Wrong binding, unknown, revoked or expired bearer, or non-member owner |
| 403 `forbidden` | Recipient, message or request mismatch |

This helper is a prompt-embedded `curl` capability, not native MCP. A
successful reply proves the bearer was presented, not that the Amp thread
used an Agent Relay MCP server. When Agent Relay MCP is configured in the
thread, the prompt tells it to use `send_relay_message` instead.

### Internal job

`POST /api/v1/internal/amp/job`, with `Authorization: Bearer
$SELFHOST_AMP_INTERNAL_SECRET`. It is not served under `/cloud`.

| Response | When |
| --- | --- |
| 404 `{"error":"Not found"}` | The secret is unset |
| 401 | No bearer |
| 403 | Wrong bearer |
| 413 | Body over 64 KiB |
| 400 | Unknown job |

The job kinds:

- `{"v":1,"kind":"sweep"}` expires leases and wakes the worker. It returns
  `{queued:0, due, expired, deferred:true}`.
- `{"v":1,"kind":"inject","bindingId":"...","messageId":"..."}` processes
  exactly that delivery if it is pending. Otherwise it returns
  `{ok, duplicate, state}`.
- `{"v":1,"kind":"history","bindingId":"...","scheduledAt"?:"..."}` answers
  `501 {"error":"history_push_unavailable","message":"..."}` while no push
  session can be issued (always, today). With one it queues the binding
  (coalesced) and wakes the worker: `202 {"ok":true,"queued":true}`, or
  `200 {"ok":true,"queued":false,"skipped":true}` when the binding is not
  bound or a poll at or after `scheduledAt` already ran.

The in-process worker already drains the outbox. This route is for an
external scheduler that wants to drive it.

## Outbox semantics

`selfhost_amp_deliveries` is the outbox. The unique key is
`(binding_id, message_id)`. The states:

| State | Meaning |
| --- | --- |
| `pending` | Queued by a verified relay event or by inbox recovery |
| `sending` | Leased: `lease_owner`, `lease_until = now + SELFHOST_AMP_LEASE_MS`, `claim_generation = binding generation`, `attempts + 1`. Claimed with `FOR UPDATE SKIP LOCKED`, and at most one per binding at a time, so a thread never gets two concurrent prompts |
| `delivered` | Amp accepted the prompt |
| `rejected` | Amp definitely refused before submission. A redelivered event may queue it again |
| `unknown` | Amp may have accepted it: a lost response, a timeout or an expired lease |

**`unknown` is never resent.** Neither the worker, a redelivered event, nor
an inject job sends it again. Only reconciliation (`reconcileDelivery`, the
`.../check` route) settles it. That route re-checks admin, a bound binding in
the workspace and an unchanged workspace relay (409 `relay_changed`), exports
the thread read-only and looks for the prompt's own marker,
`[via Agent Relay — from ...; message <id>]`.

- Marker found: a `pending`, `rejected` or `unknown` row becomes `delivered`
  (text dropped, sender kept) and the binding's `last_error` clears. A
  `sending` row under a live lease is left to the worker's finalize.
- Marker absent: the state stays as it is (`confirmed: false`).
- It never sends. The export runs outside the lock; the write re-locks the
  binding and answers 404 `binding_not_found` if it was retired or rebound
  meanwhile, writing nothing.

The binding's `last_error` shows `amp_send_unknown: inspect the thread before
retrying`.

**Fencing.** Before injecting, the worker re-checks, in a transaction:

- the lease (owner and expiry)
- the claim generation against the binding generation
- that the binding is `bound`
- that the owner's connection still exists
- that the owner is still a member

Finalizing is one conditional `UPDATE`. It matches the `sending` state, the
same lease owner, the same claim generation, an unchanged binding generation
and a still-bound binding. A completion that lost its lease or outlived a
revocation changes nothing and logs `[amp] stale_completion` with the
delivery ID only.

**Payloads**

- Payloads are encrypted with the control-plane keyring.
- After a final state, a payload is reduced to the sender, which the reply
  check needs. The message text is dropped.

**Worker**

- The worker is an unref'd `setInterval` inside the API process.
- Passes never overlap, and relay events wake it immediately.
- Each pass:
  1. sweeps expired leases to `unknown`
  2. recovers missed messages from hosted inboxes (below)
  3. drains up to 25 deliveries
  4. retries up to 10 pending Relaycast releases
- Several replicas are safe: leases and `SKIP LOCKED`.
- There is no SQS.

**Inbox recovery**

A webhook can be lost (subscription outage, control plane down). Each pass
the worker reads hosted inboxes (`GET /v1/deliveries` with the agent token)
to recover such messages. It uses the existing worker interval; there is no
new setting.

- Only `bound` bindings with a token are polled, and only while the
  workspace's Relaycast workspace still matches the binding's.
- Fairness: up to 10 bindings and 50 inbox messages per pass, visited
  round-robin by binding ID (an in-process cursor), so the least recently
  polled go first. Unprocessed messages stay unacknowledged for a later pass.
- Every message goes through the webhook's admission rule: own messages
  (same name or agent ID) are ignored; it must be a DM to the agent, a
  mention, or a reply in a thread the agent started; ID, text and sender
  limits are the same. Inbox reasons map as `dm`/missing/unknown = DM,
  `thread-reply` = thread, `message`/`mention` = channel.
- Targeted messages use the webhook's outbox insert: under the workspace lock
  with the binding row locked, only for the generation read before the poll,
  idempotent on `(binding_id, message_id)`, payload keyring-encrypted. A
  message seen by both the webhook and the inbox is one delivery and one
  injection.
- A Relaycast delivery is acknowledged only after its row is committed or
  confirmed present. Dropped messages are acknowledged, as the webhook drops
  them. If the binding was retired, rebound or moved relay between the read
  and the insert, nothing is written and nothing is acknowledged.
- A failure on one binding is caught; the others continue. It logs
  `[amp] inbox_poll_failed` with the binding ID and an error code only, and
  sets `last_error = inbox_poll_failed` unless a send outcome is already
  recorded there. A later successful poll clears it.
- The drain in the same pass injects what was queued.

## Encryption at rest

These values are stored with `encryptSecret` under the active keyring key:

- the Amp key
- binding agent tokens
- webhook secrets
- outbox payloads
- pending history pages and stored history redactions (the version cursors
  hold only digests and version numbers)

Reply bearers are stored only as hashes. No route, log line or error returns
any of these values. The summary shows only `sgamp_…<last 4>`.

## MCP tools

These tools are registered only when the feature is on:

- `list_amp_threads`
- `bind_amp_thread {thread_id}`
- `unbind_amp_thread {binding_id}`

The acting person is the MCP connection's authenticated principal and
workspace. No tool takes a user, role or workspace argument: model-supplied
identity grants no authority. Each call goes through the same service
functions as the REST routes, so it re-reads the owner/admin role and applies
the key-owner fence. A refused call answers "Only current owners and admins
using a person connection can manage Amp."

## Differences from hosted Cloud

- Cloud exposes these operations as Next.js server actions. Here they are the
  REST paths above.
- Cloud stores each subscription ID as its own commit, so a retry after a
  partial failure creates only the missing one. Here the creates and ID
  updates share one transaction; a failed attempt deletes what it created and
  the retry creates both again with the same secret.
- If the binding's Relaycast workspace changed before release, the release
  step skips the subscription deletes (existing behaviour) where Cloud
  throws.
- Cloud Amp has no inbox poll: its recovery is the queue consumer's cron
  `sweep` and SQS redelivery. Inbox recovery here follows Cloud's MCP Events
  inbox pump instead (read, insert under a lock with a current-identity check,
  acknowledge only after commit, per-inbox error isolation). Cloud's pump
  acknowledges channel deliveries without queueing; here they go through the
  webhook's mention rule.
- An inbox row carries the sender's name, not an address, so a recovered
  delivery replies to the name. A webhook that wins the race keeps the
  address.
- Reconciliation (`reconcileDelivery`) exports outside the lock and re-checks
  the binding generation before writing; Cloud exports under the lock. Cloud
  settles any state as delivered; here a `sending` row under a live lease is
  left to the worker. It returns `{confirmed, state}` where Cloud returns
  `{confirmed}`, and it is a REST route, not a server action. Cloud has no
  MCP tool for it, and neither does this port.
- The webhook now also refuses to queue (answers `duplicate`) when the
  binding generation changed after verification or the workspace relay
  moved, matching Cloud's `boundRelayFor` check under the lock.
- History upload is implemented to the upload boundary and inactive until a
  push-only session can be issued (see above). Where it differs from Cloud:
  ingest protocol only (no `HISTORY_SYNC_PROTOCOL=delivery` chunks); no
  legacy-parser digest fallback (self-host never wrote pre-`sourceDigest`
  cursors); no `cloudPushAllowed` check (the session factory owns that
  decision); no immediate history enqueue after each delivery (Cloud's
  `onChanged`), only the 5-minute schedule and the internal job; a lease on
  the bindings row instead of an SQS queue plus a named lock; a separate
  `history_error` instead of the shared `last_error`; a failure retries after
  the 15-minute lease rather than when the queue lease lapses; nothing adds
  helper capabilities to the redaction list (per-delivery reply bearers are
  scrubbed by pattern).
- The internal job uses `SELFHOST_AMP_INTERNAL_SECRET` and a JSON body, not
  Cloud's `BrokerHmacSecret`-signed SQS messages.
