# Runbook: delegation quote redaction queue

Owner-named trusted delegates (`docs/owner-delegates.md`) store an owner's
quote in Control's audit log and inside Relaycast's immutable
`owner_approval`. Whenever Control redacts a quote (the owner's request, or
the org's `quote_retention_days`), it queues a Relaycast redaction in
`delegation_quote_redactions`. This is a privacy and retention guarantee (§8,
§15.9): an unfinished row means Relaycast still holds a quote that Control
has already redacted. This mirrors Cloud's runbook for the same queue.

## How the queue drains

The server runs the delegation sweep hourly (and once at start). It redacts
expired quotes, then works through the due queue rows. Each row calls
`POST {RELAYCAST_URL}/internal/workspaces/{relay workspace}/messages/{message}/owner-approval/redact-quote`
with the `RELAYCAST_INTERNAL_SECRET` bearer and no body. Without that
secret, rows stay queued. An owner's `POST /delegates/quotes/redact` also
tries its own row at once.

| Relaycast answer | Row outcome |
|---|---|
| 2xx | finished: `relaycast_outcome = 'redacted'` |
| 404 with `owner_approval_not_found` | finished: `relaycast_outcome = 'absent'` (nothing to redact) |
| 5xx, 429, network error, 404 without that code, unresolvable workspace | retried: `attempts + 1`, `last_attempt_at = now()`, next try after `min(2^min(attempts, 9), 360)` minutes |
| any other 4xx, or a redirect | parked: `relaycast_outcome = 'rejected'`, unfinished, never retried automatically |

A retryable row is never dropped. After the 6-hour cap it is retried every
6 hours until Relaycast confirms it.

## Signals

- The sweep's result carries `relaycastPending` (unfinished rows, any
  state), `relaycastRejectedTotal` (parked rows), `relaycastStale`
  (unfinished rows older than 24 hours) and `relaycastOldestPendingSeconds`.
- After each sweep the server logs one JSON line with message
  `delegation.redaction_backlog` and fields `unfinished`, `rejected`, `stale`
  and `oldest_age_seconds`:
  - at `warn` while any row is rejected or older than 24 hours;
  - otherwise at `info`, and only when anything is unfinished.

**Alert:** a `delegation.redaction_backlog` line at `warn` for more than
6 hours, or any `rejected` above zero.

## Triage

1. Read the backlog. This needs read-only database access and never selects
   quote or message text:

   ```sql
   SELECT workspace_id, message_id, requested_at, attempts, last_attempt_at, relaycast_outcome, relaycast_status
     FROM delegation_quote_redactions
    WHERE relaycast_redacted_at IS NULL
    ORDER BY requested_at
    LIMIT 50;
   ```

2. Many rows retrying with `relaycast_status` 5xx, 429 or null means Relaycast
   or its internal route is down. If they all show 404, the redact-quote route
   has not been deployed on that Relaycast (relaycast#710). Fix Relaycast; the
   rows drain on their own at the next due try.

3. Rows that were **rejected**, for example with 401 or 403 (a wrong or
   rotated `RELAYCAST_INTERNAL_SECRET`) or 400 (a contract change):
   1. Fix the cause first: set the right secret, or deploy the matching
      Relaycast.
   2. Then requeue the rows so they retry on the next sweep:

      ```sql
      UPDATE delegation_quote_redactions
         SET relaycast_outcome = NULL, last_attempt_at = NULL
       WHERE relaycast_redacted_at IS NULL AND relaycast_outcome = 'rejected';
      ```

4. A failed sweep is logged as `delegation.unavailable` with
   `op: "retention"` and the error class. Check database health first.

Never delete queue rows. A deleted row means Relaycast keeps the quote forever.

## Other delegation failure signals

The attest, redeem, gate redeem and retention paths log the failures they
would otherwise swallow, as one JSON line each with a fixed message
(`src/delegation/observe.ts`):

- `delegation.unavailable` (error): an answer of `unavailable` caused by an
  exception. `op` is `attest`, `redeem`, `gate_redeem` or `retention`.
- `delegation.audit_write_failed` (error): a best-effort refusal or dry-run
  audit write failed. The answer is unchanged.
- `delegation.revoke_failed` (error): a durable system revocation failed. The
  use is still refused.
- `delegation.dependency_failed` (error): a JWKS read failed, with
  `stale_cache_served`, `refresh` and `status`.
- `delegation.refused` (info): one refusal, by `op` and `reason`.
- `delegation.audit_fenced` (info): a paged audit read held `held_back`
  events back behind a running transaction.

These lines carry only `op`, `workspaceId`, approval, grant and gate ids,
`reason`, the error class and the Postgres SQLSTATE. They never carry tokens,
quotes, message text or error messages.
