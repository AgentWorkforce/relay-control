# Workspace delete hand-off to relayfile-control

relayfile-control owns Flows data (definitions, runs, steps, events,
artifacts, workers and enrollment tokens) in its own database. Its rows carry
relay-control workspace ids without foreign keys, so deleting a workspace here
cannot cascade there. This hand-off carries the delete across.

## Configuration

| Variable | Meaning |
| --- | --- |
| `RELAYFILE_CONTROL_URL` | relayfile-control's internal origin. |
| `RELAYFILE_CONTROL_WORKSPACE_DELETE_SECRET` (or `_FILE`) | Bearer for the delete route, at least 32 bytes. |

Both or neither. The secret must differ from every other service secret.
relayfile-control already holds the broker secret to call this service, so
reusing it would let either side act in both directions. Unset, nothing is
queued and startup logs `flowsWorkspaceDelete: false`.

## Behaviour

1. `DELETE /api/v1/organizations/{org}/workspaces/{id}` writes a
   `flows_workspace_deletions` row in the transaction that deletes the
   workspace. A refused delete (last workspace, workspace in use) rolls back
   and owes nothing.
2. A worker on every replica claims due rows every 30 s (a two-minute lease,
   `FOR UPDATE SKIP LOCKED`) and sends
   `DELETE {RELAYFILE_CONTROL_URL}/internal/v1/flows/workspaces/{id}` with
   the secret as bearer and a 10 s timeout. The remote delete is idempotent,
   so a lease that expires mid-call is harmless.
3. Two answers complete the row: a `200` whose body names the same
   `workspaceId`, and a `404` with `{"error": "flows_not_enabled"}`, which
   relayfile-control sends only after the secret checks out and only when
   Flows is off there (it holds nothing). A bare `404` is what the route
   answers while relayfile-control's secret is unset; it deleted nothing, so
   it is retried like a refusal.
4. Any other answer, a network failure or a timeout keeps the row, records
   `last_error` (`http_<status>` or `unreachable`) and backs off: 30 s,
   doubling to one hour. A `4xx` logs `flows_workspace_delete_refused`
   (usually a secret mismatch); the rest log
   `flows_workspace_delete_deferred`. Neither log carries the secret or the
   remote body. A refusal is never a reason to drop the row: deleted data
   must not survive because of a configuration fault.

Operators can see what is owed with
`SELECT workspace_id, attempts, last_error FROM flows_workspace_deletions`.

## During the Flows cutover

While Flows is still served from relay-control's legacy `src/flows`, the
local Flows rows cascade with the workspace as before. Configure the hand-off
before relayfile-control takes Flows traffic, so a workspace deleted during
the switch is removed from both stores.
