# Usage page

An owner-only view of how an installation is used, for the dashboard's
Settings > Usage page. Off by default: select it with `usage` in
`SELFHOST_FEATURES` ([features.md](features.md)).

## API

`GET /api/v1/organizations/{org}/usage?days=7|30|90` (also under `/cloud`,
with the session cookie). `days` defaults to 30; any other value or any other
query parameter is 400. The range is the last `days` UTC days, ending today.

- Only an **owner** of the organization: admin and member are 403
  `forbidden`, as is the bootstrap bearer. A token for another organization is
  404.
- Feature not selected: 403 `feature_not_enabled` (checked after the role).

```json
{ "usage": {
  "range": { "days": 7, "from": "2026-10-27", "to": "2026-11-02" },
  "totals": { "activeUsers": 2, "sessionsUploaded": 20, "searches": 2, "summaries": null },
  "days": [ { "date": "2026-10-27", "activeUsers": 0, "sessionsUploaded": 2, "searches": 0, "summaries": null } ],
  "unavailable": ["summaries"]
} }
```

`totals.activeUsers` is distinct users over the range, not the sum of the days.

## Sources

| Metric | Source |
|---|---|
| `sessionsUploaded` | The session directory, through the read API `/v1/sessions/activity`, read once per workspace of the organization that the owner belongs to and summed |
| `summaries` | The read API `/v1/sessions/summaries/activity` (`{ days: [{ date, total }] }`, workspace-attested), when it serves it |
| `activeUsers` | Control: a user who authenticated to Control that day |
| `searches` | Control: a first-page session search (`/sessions/search`, or `/sessions?q=`); later pages of the same search are not counted |

A source that cannot be read (the read API is down, or does not serve the
path) is `null` and named in `unavailable`. It is never reported as 0.

Control counts only while the feature is selected, so `activeUsers` and
`searches` start from when it was turned on. There is no backfill.

## Privacy

Responses carry counts and dates only: no content, prompts, emails, names or
ids. Control stores `usage_daily_counters` (organization, day, metric,
value) and `usage_daily_users` (organization, day, user hash). The user hash
is HMAC-SHA256 of the user id under a random per-install secret in
`usage_state`. Neither the secret nor any hash is returned by any API.
