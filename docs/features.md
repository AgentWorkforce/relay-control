# Optional features

`SELFHOST_FEATURES` selects which optional components an installation serves.
It is a comma list of `flows`, `relayfile`, `chief`, `usage` and `launch`, read once at startup.
Unset selects `usage` and `usage_people` (the owner-only usage pages); an explicit list, including an empty one, is exact. An unknown name stops startup. Everything
else is core and always on.

| Feature | When selected |
|---|---|
| `flows` (Relayflows) | Flows routes, worker enrolment and the worker protocol serve |
| `relayfile` | Reported as a capability; Control has no Relayfile routes |
| `chief` | Chief routes serve; with no backend configured they answer 503 `chief_unavailable` |
| `usage` | The owner-only usage API serves and Control records daily counts ([usage.md](usage.md)); nothing is recorded while it is off. Selected by default |
| `usage_people` | The owner-only per-member People drill-down serves, with an audit row per view ([usage.md](usage.md#people-usage_people)). Selected by default |
| `launch` | The shared-sessions MCP endpoint serves the agent launch tools ([agent-launch.md](agent-launch.md)) |

## Reading it

- `GET /api/v1/capabilities` (also `/cloud/api/v1/capabilities`): any signed-in
  member. Returns `{ "capabilities": { "flows": bool, "relayfile": bool, "chief": bool, "usage": bool, "launch": bool } }`.
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
