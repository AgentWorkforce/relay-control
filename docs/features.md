# Optional features

`SELFHOST_FEATURES` selects which optional components an installation serves.
It is a comma list of `flows`, `relayfile` and `chief`, read once at startup.
Unset or empty selects nothing, and an unknown name stops startup. Everything
else is core and always on.

| Feature | When selected |
|---|---|
| `flows` (Relayflows) | Flows routes, worker enrolment and the worker protocol serve |
| `relayfile` | Reported as a capability; Control has no Relayfile routes |
| `chief` | Chief routes serve; with no backend configured they answer 503 `chief_unavailable` |

## Reading it

- `GET /api/v1/capabilities` (also `/cloud/api/v1/capabilities`): any signed-in
  member. Returns `{ "capabilities": { "flows": bool, "relayfile": bool, "chief": bool } }`.
- `/readyz` includes the same `capabilities` object.

## Refusals

Every Flows route (including worker enrolment and the worker protocol) and
every Chief route checks the selection after authentication and membership
and before any backend call. A feature that is not selected answers 403:

```json
{ "error": "feature_not_enabled", "message": "...", "feature": "chief" }
```

Core startup and ordinary core routes do not initialize Flows storage or parse
its optional configuration. Selecting Flows retains its startup validation.
Disabled Flows protocol routes authenticate enrollment, worker, and run
credentials before returning `feature_not_enabled`; they do not redeem an
enrollment token, record callbacks, touch workers, or run queue maintenance.
