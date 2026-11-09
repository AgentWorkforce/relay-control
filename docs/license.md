# Licence and feature selection

Two runtime inputs decide which optional features an installation serves:
what the operator selects, and what a signed licence entitles. Neither needs
a new image; both are read once at startup.

## Classes

| Feature | Class | Capability |
|---|---|---|
| `flows` (Relayflows) | paid | selected AND entitled |
| `relayfile` | paid | selected AND entitled (no routes yet; capability read only) |
| `chief` | optional core, default off | selected |

Everything else is core and always on.

## Environment

| Variable | Meaning |
|---|---|
| `SELFHOST_FEATURES` | Comma list of `flows`, `relayfile`, `chief`. Unset or empty selects nothing. An unknown name stops startup. |
| `SELFHOST_LICENSE` | The licence document inline. |
| `SELFHOST_LICENSE_FILE` | Path to a file holding the licence document. Setting both licence variables stops startup. |
| `SELFHOST_LICENSE_PUBLIC_KEY_OVERRIDE` | Tests only. Base64 of a raw 32-byte Ed25519 public key. Honoured only when `NODE_ENV=test`; otherwise ignored with one log line. No operator setting can supply a trusted key. |

## Licence document

`<base64url(payload JSON)>.<base64url(Ed25519 signature)>`, the signature
taken over `"relaycontrol-license-v1\n"` followed by the payload JSON bytes.

Claims: `v` (1), `license_id` (uuid), `customer`, `issued_at`, `expires_at`
(RFC 3339 UTC), `features` (array of names), `seats` (positive integer) and
optional `notes`. Unknown claims are ignored. Only `flows` and `relayfile` in
`features` grant anything; `chief` or unknown names are accepted and ignored.

The trusted public key is a source constant in `src/license/public-key.ts`.
It ships as `null` in this build, so every supplied licence reads as
`invalid` and the installation runs as core until a release compiles a key
in. A real key means a new image, not a values change.

## Status

| Status | Meaning |
|---|---|
| `absent` | No licence supplied. |
| `invalid` | Bad signature, malformed claims, unreadable file, or no trusted key. |
| `expired` | Signature verifies but `expires_at` has passed (checked per request). |
| `valid` | Signature verifies and the licence is in date. |

A licence that is not valid never stops the server: it logs once at startup
and runs as core. Seats are reported (`used` counts organization members,
owners included, across the installation), not enforced.

## Reading it

- `GET /api/v1/license` (also `/cloud/api/v1/license`): any signed-in member.
  Returns status, licence id, customer, expiry, seats, `features`, `paid`,
  `selected`, `entitled` and `capabilities`. See the `License` schema in
  `openapi.yaml`.
- `/readyz` adds `license.status` and `capabilities`.

## Refusals

Every Flows route (including worker enrolment and the worker protocol) and
every Chief route checks the capability after authentication and membership
and before any backend call. A refusal is 403:

```json
{ "error": "feature_not_enabled", "message": "...", "feature": "chief" }
```

- `feature_not_enabled`: the feature is not in `SELFHOST_FEATURES`.
- `feature_not_licensed`: a paid feature is selected but not entitled.
  Chief never answers this.

Chief selected with no backend configured still answers 503
`chief_unavailable`.
