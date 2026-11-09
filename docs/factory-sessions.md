# Factory sessions

Factory sessions let a workspace admin bind a Factory (Droid) session to a
Relay agent. Relay messages sent to that agent are injected into the Factory
session, and the Droid answers through a single-use, sender-pinned reply
capability.

The feature is **off by default**. With `SELFHOST_FACTORY_ENABLED` unset or
`false`, every Factory route answers the generic `404 {"error":"not_found"}`
before authentication, and the worker does not start.

## What ships

- Connect a Factory API key per workspace (owner/admin only). The key is
  validated by listing computers. Only an encrypted envelope and a `key_hint`
  are stored, and the key is never returned.
- Discover computers and sessions, bind a session pinned to its computer, and
  list, read, unbind and disconnect.
- One hosted Relay agent per binding (`factory-<sha256(session)[0..16]>`),
  registered with `factory_binding_id` metadata and recovered after a crash.
- The worker. It polls each bound agent's inbox, writes an outbox row, injects
  the message into the Factory session, and lets the Droid reply through
  `POST /api/v1/factory-sessions/agents/{bindingId}/messages`.
- Delivery receipts (`GET .../deliveries/{messageId}`) for the binding owner.
- The internal job route `POST /internal/v1/factory/job` for manual kicks and
  sweeps.
- Teardown: unbind, disconnect, member removal and workspace cleanup, with a
  retrying remote release.
- MCP tools `list_factory_sessions`, `bind_factory_session` and
  `unbind_factory_session` on the shared-sessions MCP endpoint, registered
  only when the feature is on. They act as the connection's person, re-read
  the owner/admin role on every call, and leave browsing and binding to the
  person who connected Factory. OAuth connections never get them.
- MCP resolver hook: on a native (non-OAuth) connection, `send_relay_message`,
  `subscribe_relay_channel` and `read_relay_conversation` accept `as=<agent name>` of
  the caller's own bound Factory session and act with that binding's hosted
  token, without creating a participant. Retired bindings and removed members
  resolve to nothing. `check_relay_inbox`, `leave_relay`, `relay_status` and
  `join_relay` do not use the hook.

## Dormant or deferred

| Item | State |
|---|---|
| History capture and export | Dormant. `POST .../history/schedule` records an intent and answers `202 {queued:0, deferred:true}`. Every surface reports history as `deferred`, never completed. The history loop only advances intents. |
| Relay-events webhook and Relaycast subscriptions | Deferred. `POST /api/v1/factory-sessions/relay-events/{bindingId}` is always 404. Delivery uses inbox polling. |
| Acquisition transport, tokens and install envelope | Not implemented. |
| Session mapper and export | Not implemented. Unknown sends are never reconciled from session metadata. |
| Admin force-disconnect | Not provided, by design. Only the person who connected Factory manages that connection. |

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `SELFHOST_FACTORY_ENABLED` | `false` | `true` or `false`, and any other value fails startup. When off, routes are 404 and the worker stays off. |
| `SELFHOST_FACTORY_API_URL` | `https://api.factory.ai` | Must be an absolute https URL. Redirects are not followed. |
| `SELFHOST_FACTORY_HISTORY_INTERVAL_MS` | `300000` | Cadence of the dormant history loop, minimum 60000. |
| `SELFHOST_ENCRYPTION_KEY[_ID]` | required | Encrypts the Factory key and hosted agent tokens. |
| `SELFHOST_INTERNAL_TOKEN` | unset | Required for the job route. While it is unset, the job route is 404. |

The fixed limits are:

- Factory calls: 30 s per request, 55 s per operation, 16 MiB per response
  and 100 pages.
- Injected text: at most 64 KiB.
- Reply text: at most 20,000 characters, in a body of at most 64 KiB.
- Reply bearers expire after 24 hours.
- Worker loops: inbox every 5 s (up to 200 bindings per tick), injection every
  2 s (batch of 10), cleanup every 60 s.

## Routes

User routes live under `/api/v1/workspaces/{workspaceId}/factory` and are also
mounted under `/cloud`. Each request passes these gates in order:

1. A workspace API token or the internal token is refused with 403
   `factory_workspace_token`.
2. The caller must be a workspace owner/admin; anyone else gets 403 or 404.
3. The `cli:auth` scope is required.
4. The session cookie is accepted only under `/cloud`, behind the CSRF origin
   check.

Every response is `no-store`.

| Method and path | Success | Notes |
|---|---|---|
| `GET /connection` | 200 summary | `{connected, key_hint, validated_at, user_is_owner, bindings_count, history}` |
| `PUT /connection` `{key}` | 200 summary | Connect or replace the key. Replacing it re-verifies up to 8 bound sessions. |
| `DELETE /connection` | 204 | Connection owner only. Retires that owner's bindings. |
| `GET /computers` | 200 `{computers}` | Connection owner only |
| `GET /computers/{computerId}/sessions` | 200 `{sessions, warning?}` | Each row has `bound`: `here`, `elsewhere` or `null` |
| `POST /bindings` `{session_id, computer_id}` | 201 `{binding_id, session_id, agent}` | |
| `GET /bindings` | 200 `{bindings, history}` | The caller's own bindings only |
| `GET /bindings/{id}` | 200 binding | A foreign row is 404 |
| `DELETE /bindings/{id}` | 204 | A missing id is 204 too |
| `GET /bindings/{id}/deliveries/{messageId}` | 200 `{state, code?}` | Binding owner only |
| `POST /bindings/{id}/history/schedule` | 202 `{queued:0, deferred:true}` | Dormant |

Public and internal routes:

| Method and path | Auth | Notes |
|---|---|---|
| `POST /api/v1/factory-sessions/agents/{bindingId}/messages` `{text}` | `Bearer factory_reply_…` | Replies to the pinned sender only. Same body repeated: stored result. Different body: 409 `reply_already_recorded`. |
| `POST /api/v1/factory-sessions/relay-events/{bindingId}` | none | Always 404 (subscriptions deferred) |
| `POST /internal/v1/factory/job` | `Bearer $SELFHOST_INTERNAL_TOKEN` | Raw path only, never under `/cloud`. Envelope `{v:1, kind}`, where `kind` is `sweep {after?}`, `history {bindingId, scheduledAt?}` or `inject {bindingId, messageId}`. Unknown keys are refused with 400 `invalid_request`. Other errors: 401 `unauthorized`, 403 `forbidden`, 503 `factory_job_failed`. An inject for an absent delivery answers `{ok:true, skipped:true}`. |

Errors use `{error, message}` with stable codes. The Factory-specific codes:

| Status | Codes |
|---|---|
| 403 | `factory_workspace_token`, `factory_not_owner`, `factory_access_revoked` |
| 404 | `factory_not_connected`, `binding_not_found`, `delivery_not_found` |
| 409 | `factory_other_member_bindings`, `factory_session_other_workspace`, `factory_session_other_member`, `factory_session_moved`, `binding_retired`, `factory_cleanup_pending`, `factory_replace_limit`, `factory_bindings_changed`, `factory_agent_conflict`, `reply_already_recorded` |
| 422 | `invalid_factory_key`, `invalid_request` |
| 502 / 503 | `factory_key_rejected`, `factory_unavailable`, `relay_unavailable`, `factory_reply_failed` |

Provider error bodies are never echoed.

## Ownership, removal and rejoin

The member who connected Factory owns the connection. Only that member can:

- browse computers and sessions
- replace the key
- bind
- disconnect

Each member unbinds only their own bindings.

The connection stays owned by the member who connected it, even when it has no
bindings. Another admin can connect only when there is no current connection
and no other member holds a live (bound or preparing) binding. Otherwise the
connect is refused with 409 `factory_other_member_bindings`. Retired bindings
never block a connect.

When a member is removed, one transaction does all of the following:

- retires their bindings
- deletes their deliveries, which removes payload ciphertext and reply-bearer
  hashes
- clears their hosted tokens
- drops the connection if they owned it

Remote release runs after commit. A failed release keeps the retired row,
holding its remote agent id, until the cleanup loop succeeds. Until then, the
old session ID stays unavailable (409 `factory_cleanup_pending`).

Retired bindings keep their original cleanup locators and identity, whether
their former owner was removed, rejoined or is still a member. They reserve
only their old session ID until verified cleanup completes. They do not stop
another authorized owner or admin from connecting their own key and binding a
different session when there is no current connection, and they do not block
the current connection owner. Membership of a retired row's former owner is
never checked or locked for this.

A retired record never transfers the old Relay agent, its subscriptions, the
reply capability or unpublished history. Disconnect cleans up only the
connection owner's own bindings. No other admin gains authority over the old
cleanup or inherits the connection. A live (bound or preparing) binding of
another member always blocks connect and management.

Role changes and removal lock the organization row. Connect, bind, unbind,
disconnect and history scheduling re-read the caller's owner/admin role under
that lock inside their commit transaction. A removal or demotion that commits
first therefore wins. The late write fails, or its prepared row is retired, and
it never leaves a live binding.

Local unbind and disconnect keep the delivery rows as receipts. They clear
payload ciphertext and reply hashes, mark `pending` rows `rejected`
(`binding_retired`) and mark `sending` rows `unknown`.

## Outbox semantics

Inbox:

- The worker reads each bound agent's inbox and inserts one delivery per
  `(binding_id, message_id)`.
- The insert is fenced inside its transaction against a binding that is no
  longer live.
- The Relay ack happens only after commit. A re-poll after a lost ack inserts
  nothing new.
- Self-sent messages are acked and skipped.
- Messages without a sender, with empty text, or above the inject limit are
  recorded as `rejected` (`sender_unknown`, `message_empty` or
  `message_too_large`).

Claim and send:

1. A claim takes due `pending` rows with `FOR UPDATE SKIP LOCKED`, sets
   `sending` with a fresh lease owner, the binding's generation and a 5 minute
   lease, and mints a reply bearer. Only the bearer's hash is stored.
2. Just before the provider POST, a fence re-checks that the lease, the lease
   owner, the bound state and the generation still hold. If any check fails,
   nothing is sent.
3. A single conditional update records the outcome. A row that changed in the
   meantime is left alone and logged as `stale_completion`.

| Outcome | State |
|---|---|
| 2xx ack | `delivered` |
| 2xx without a parseable ack, 500 or other non-ok status, transport failure after send | `unknown`, never resent |
| 400, 401, 403, 404, 409, 422, invalid message | `rejected`, terminal |
| 429 or a definite pre-write failure | `pending`, backoff `min(2^attempts × 5 s, 10 min)`; after 8 attempts `rejected` `attempts_exhausted` |
| Lease expired while `sending` | `unknown` `lease_expired`; only the same claim's late 2xx ack can still confirm it |

`rejected` and `unknown` rows are never claimed again and never get a new
bearer. When a row lands in either state, the bound agent sends a fixed-text
notice to the sender (idempotency key `factory-notice-<sha256>`).

Logs carry only `{event, kind, bindingHash, code, outcome}`. The following are
never logged or returned:

- keys and hosted tokens
- reply bearers
- message bodies
- session ids
- provider error bodies
