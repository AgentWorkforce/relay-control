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

While unset, both routes answer 501 `not_implemented`. `SELFHOST_OPERATOR_CONTROLS` (`always`, `licence`, `off`) gates
`DELETE` exactly as it gates capture-policy writes (403 `operator_controls_not_entitled`); the read is never gated.

## Delete a session

`DELETE /api/v1/organizations/{org}/sessions/{sessionId}` (also under `/cloud/api/v1/...` with the session cookie;
cookie callers need an allowed Origin or `Sec-Fetch-Site: same-origin`). Owner/admin or bootstrap bearer; members 403,
other organizations 404.

```sh
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  "$CONTROL_URL/api/v1/organizations/$ORG/sessions/$SESSION"
```

| Status | Meaning |
| --- | --- |
| 200 | Erase completed; the body is the receipt below |
| 202 | Erase in progress; poll the verification read |
| 404 `session_not_found` | No such session in this organization; nothing was erased |
| 502 `session_erasure_failed` | Erase failed; the receipt is in `erasure`. Repeat the `DELETE` to retry |
| 502 `invalid_session_erasure_response` | The pipeline's reply could not be trusted; treat the erase as not done |
| 503 `session_erasure_unavailable` | The pipeline could not be reached; repeat the `DELETE` |

The route is idempotent: repeating a completed delete returns the same receipt. A 200 is only returned when the
pipeline reports completion with a completion time and with late uploads for that session fenced off.

## Verify a delete

`GET /api/v1/organizations/{org}/sessions/{sessionId}/erasure` (owner/admin or bootstrap bearer) returns the pipeline's
receipt, with ids and counts only and never content. 404 `erasure_not_found` means no erase exists for that session.

```json
{
  "orgId": "…", "sessionId": "…", "requestId": "…",
  "status": "completed",
  "requestedAt": "2026-01-01T00:00:00.000Z", "completedAt": "2026-01-01T00:00:03.000Z",
  "artifacts": { "transcriptObjects": 12, "bufferedBatches": 2, "ledgerRows": 40, "searchDocuments": 9, "summaries": 1, "briefs": 1 },
  "uploadsFenced": true,
  "failure": null,
  "audit": { "action": "session.hard_deleted", "actorKind": "user", "actorId": "…", "recordedAt": "2026-01-01T00:00:03.100Z" }
}
```

After deploying, check that `status` is `completed`, `audit` is present, and reading the session through the normal
session routes no longer returns it.

## Audit

Both events are written to `selfhost_admin_audit_events` with the organization id and target
`session:<id> request=<request id>`. They contain ids only.

- `session.hard_delete.requested`: one per `DELETE` that passes authorization, committed before the pipeline is called.
- `session.hard_deleted`: exactly once per session, when the pipeline first reports completion, attributed to whoever
  first requested the erase.

## Internal pipeline contract

Control calls the pipeline with `Authorization: Bearer <SESSION_ERASE_API_SECRET>`.

- `POST /internal/v1/session-erase/organizations/{org}/sessions/{id}` with
  `{"requestId":"<uuid>","actor":{"kind":"user|bootstrap","id":"<id or null>"}}`. 200 completed, 202 in progress,
  404 `{"error":"session_not_found"}`. Idempotent per organization and session.
- `GET` on the same path returns the receipt, or 404 `{"error":"erasure_not_found"}`.

A completed status means every store is erased and a late in-flight upload can no longer restore the session. The
receipt outlives the erase, and a failed erase can be retried with another `POST`.
