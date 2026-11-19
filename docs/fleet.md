# Fleet view

`GET /api/v1/organizations/{org}/fleet` lists the organization's members with
the Agent Relay Desktop machines signed in for them, what each machine last
reported, and whether it runs the current workspace policy
(docs/workspace-policy.md). Owners and admins read it; members and the
bootstrap bearer are 403 `forbidden`.

## Query

- `days`: 7, 30 or 90 (default 30), the usage range, as on the Usage page.
- `cursor`: the `next_cursor` of the previous page. Members come 200 per page,
  ordered by email, then user id. A malformed cursor is 400
  `invalid_request`.

Any other query parameter, or `days` or `cursor` given twice, is 400
`invalid_request`.

## Response

```json
{
  "policy_revision": 4,
  "range": { "days": 30, "from": "2026-10-19", "to": "2026-11-17" },
  "totals": {
    "members": 2, "machines": 3, "managed": 1,
    "policy": { "current": 1, "stale": 1, "unknown": 1, "mismatch": 0 },
    "clientVersions": [{ "version": "1.4.0", "machines": 2 }, { "version": null, "machines": 1 }]
  },
  "members": [{
    "user": { "id": "…", "email": "ana@example.com", "name": "Ana" },
    "role": "member",
    "machines": [{
      "sessionId": "…", "hostName": "build-01", "clientVersion": "1.4.0", "platform": "macos",
      "enrolledVia": { "keyId": "…", "label": "laptop rollout" },
      "policyRevision": 4, "policyMatch": "current", "managed": true,
      "lastSeenAt": "2026-11-17T08:00:00.000Z", "status": "active"
    }],
    "usage": { "sessionsUploaded": 12, "lastSessionAt": "2026-11-16T17:20:00.000Z", "topProjects": [] }
  }],
  "usage_unavailable": [],
  "truncated": false,
  "next_cursor": null
}
```

`totals` counts the members and machines of the page returned.

### Machines

A machine is one device-client token session in the organization: the device
flow, the redeemed pair of a Desktop browser sign-in and an enrollment key
exchange (sessions carrying `rth:acquire`, without `account`, that are not a
Desktop handoff row). These are the sessions that record client telemetry
(docs/identity.md, "Desktop client telemetry"). Refresh keeps the same
session, so a machine keeps its `sessionId` until it signs in again. Live
sessions are listed, and revoked or expired ones for 30 days after they ended.

- `status`: `revoked` (revoked), `expired` (refresh token expired) or `active`.
- `hostName`: the host name the client gave at sign-in, or null.
- `clientVersion`, `platform`: from the last `AgentRelayDesktop/<version> (<platform>)`
  User-Agent the session presented; null for older clients.
- `enrolledVia`: the enrollment key the session was exchanged from, or null.
- `managed`: that key was minted with `policyConsent: "admin"`.
- `policyRevision`: the last `X-Agent-Relay-Policy-Revision` the session sent.
- `lastSeenAt`: when the session last reported telemetry, else when it last
  refreshed, else when it was created.
- `policyMatch`:
  - `unknown`: the session never reported a revision;
  - `current`: the reported revision is `policy_revision`;
  - `stale`: it is another revision;
  - `mismatch`: the policy locks or defaults a person-only key to a widening
    value (`true` or a non-empty list) and the session is not managed. Such a
    value never applies on that machine (docs/workspace-policy.md, "Consent").
    This overrides `current` and `stale`.

### Usage

With `usage_people` selected, each member's `usage` is
`{sessionsUploaded, lastSessionAt, topProjects}` from the People report
(docs/usage.md, "People"), read with the caller's authority over the
workspaces the caller belongs to, with the same budget and cache. Its
`unavailable` and `truncated` are passed through as `usage_unavailable` and
`truncated`. With `usage_people` off, `usage` is null for every member and
`usage_unavailable` is `["usage"]`; the fleet view itself needs no feature.

## Audit

Every read writes an organization-level audit row `fleet.viewed` (actor: the
caller, target: the organization id). There is no rate limit.
