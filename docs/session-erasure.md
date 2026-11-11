# Session hard delete

An organization owner/admin can permanently erase one session and its derived server-side artifacts (transcript
objects, buffered batches, ledger rows, search indexes, summaries and briefs) without using the end-user UI. Erasing a
session does not offboard its user: organization membership is never touched.

## Enable it

Set both on relay-control:

| Setting | Meaning |
| --- | --- |
| `SESSION_ERASE_API_URL` | Internal origin of the session pipeline's erase endpoint |
| `SESSION_ERASE_API_SECRET` (or `_FILE`) | Dedicated Control-to-pipeline secret, at least 32 bytes. Do not reuse `SESSION_READ_API_SECRET` |

While unset, both routes answer 501 `not_implemented`. `SELFHOST_OPERATOR_CONTROLS` (`always`, `off`) gates
`DELETE` exactly as it gates capture-policy writes (403 `operator_controls_not_entitled`); the read is never gated.

## Delete a session

`DELETE /api/v1/organizations/{org}/sessions/{sessionId}` (also under `/cloud/api/v1/...` with the session cookie;
cookie callers need an allowed Origin or `Sec-Fetch-Site: same-origin`). Owner/admin or bootstrap bearer; members 403,
other organizations 404. A session id is only unique within its workspace and source, so `workspaceId` and `source`
are required query parameters on both routes (400 `invalid_session_target` without them, 404 `workspace_not_found` if
the workspace is not in the organization).

```sh
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  "$CONTROL_URL/api/v1/organizations/$ORG/sessions/$SESSION?workspaceId=$WORKSPACE&source=$SOURCE"
```

| Status | Meaning |
| --- | --- |
| 200 | Erase completed; the body is the receipt below |
| 202 | Erase in progress; poll the verification read. Object-store and analytics deletes are asynchronous and can take up to about 48 hours |
| 501 `not_implemented` | The pipeline erase is not configured or not yet available |
| 502 `session_erasure_failed` | Erase failed; the receipt is in `erasure`. Repeat the `DELETE` to retry |
| 502 `invalid_session_erasure_response` | The pipeline's reply could not be trusted; treat the erase as not done |
| 503 `session_erasure_unavailable` | The pipeline could not be reached; repeat the `DELETE` |
| 503 `session_erasure_unsupported_storage` | The pipeline cannot erase this session with its current storage or ingest configuration; do not repeat the request, an operator change or supported cutover is required |

The route is idempotent: repeating a completed delete returns the same receipt. A 200 is only returned when the
pipeline reports completion with a completion time, nothing pending, and late uploads for that session fenced off.

An unknown session is not an error: the pipeline fences that id against a late first upload and reports zero counts.
All-zero counts therefore mean nothing was found, so check the id, workspace and source if you expected data.

## Verify a delete

`GET /api/v1/organizations/{org}/sessions/{sessionId}/erasure?workspaceId=&source=` (owner/admin or bootstrap bearer)
returns the pipeline's receipt, with ids and counts only and never content. 404 `erasure_not_found` means no erase
exists for that session.

```json
{
  "orgId": "…", "workspaceId": "…", "source": "…", "sessionId": "…", "requestId": "…",
  "status": "completed",
  "requestedAt": "2026-01-01T00:00:00.000Z", "completedAt": "2026-01-01T00:00:03.000Z",
  "artifacts": {
    "transcriptObjects": { "count": 12, "state": "done" },
    "ledgerRows": { "count": 40, "state": "done" },
    "briefs": { "count": 0, "state": "not_applicable" }
  },
  "uploadsFenced": true,
  "unreadable": true, "unreadableAt": "2026-01-01T00:00:01.000Z",
  "bytesErased": true, "bytesErasedAt": "2026-01-01T00:00:03.000Z",
  "legacyScope": "excluded",
  "failure": null,
  "audit": { "action": "session.hard_deleted", "actorKind": "user", "actorId": "…", "recordedAt": "2026-01-01T00:00:03.100Z" }
}
```

`artifacts` lists each store with its count and a state of `done`, `pending` or `not_applicable`. `uploadsFenced` turns
true once the fence commits. `unreadable` means the session is hidden in every store, which happens immediately;
`bytesErased` means every store's delete is verified. `status` is `completed` only when both are true. An erase that is
`unreadable` but still `in_progress` is hidden from everyone but not yet fully deleted. When a step fails, `failure` names
the `step`, a `code`, and whether it is `retryable`.

`legacyScope: "excluded"` means data held in older storage generations is **not** covered by this erase. Handle that
data separately if your retention obligations include it.

After deploying, check that `status` is `completed`, `audit` is present, and reading the session through the normal
session routes no longer returns it.

## Audit

Both events are written to `admin_audit_events` with the organization and workspace ids and target
`session:<id> source=<source> request=<request id>`. They contain ids only.

- `session.hard_delete.requested`: one per `DELETE` that passes authorization, committed before the pipeline is called.
- `session.hard_deleted`: exactly once per session and source, when Control first observes completion on a `DELETE` or
  the verification read, attributed to whoever first requested the erase. A long-running erase is audited when it is
  next polled, so poll until it completes.

## Internal pipeline contract

Control calls the pipeline with `Authorization: Bearer <SESSION_ERASE_API_SECRET>`.

- `POST /internal/v1/session-erase/organizations/{org}/workspaces/{workspace}/sources/{source}/sessions/{id}` with
  `{"requestId":"<uuid>","actor":{"kind":"user|bootstrap","id":"<user id, or bootstrap>"}}`. 200 completed or failed,
  202 in progress.
  Idempotent per target: a repeat returns the existing receipt and never erases twice.
- `GET` on the same path returns the receipt, or 404 `{"error":"erasure_not_found"}`.
- 501 means the erase is not available yet, and other 5xx are retryable.

A completed status means every artifact is `done` or `not_applicable`, each store is verified erased, and a late
in-flight upload can no longer restore the session. The receipt outlives the erase, and a failed erase can be retried
with another `POST`.
