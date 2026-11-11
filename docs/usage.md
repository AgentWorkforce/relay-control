# Usage page

An owner-only view of how an installation is used, for the dashboard's
Settings > Usage page. `usage` (counts) and `usage_people` (the per-member
drill-down below) are selected by default when `SELFHOST_FEATURES` is unset;
set it explicitly to choose otherwise (for example `""` for none)
([features.md](features.md)).

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
| `activeUsers` | Control: a user whose access token Control accepted that day (dashboard, Desktop, MCP, or introspection by session ingest and the read API) |
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

## People (`usage_people`)

Owner-only, a separate feature from `usage`. Unlike the counts above, this
view is per member and shows member names, emails and their sessions'
recorded titles and summaries.

- `GET /api/v1/organizations/{org}/usage/people?days=7|30|90`: every member
  (name, email, role) with `sessionsUploaded`, `searches`, `lastActiveAt`,
  `lastSessionAt` and `topProjects` for the range. Session totals come from
  the read API with the owner's authority, for each organization workspace
  the owner belongs to, and are bounded:
  - Control prefers the read API aggregate `/v1/sessions/users` (one grouped
    query per workspace, `source: "aggregate"`). A read API without it (404
    or 501, remembered for 10 minutes) is sampled instead: the newest
    sessions from `/v1/sessions` pages of at most 200 (`source: "sample"`).
  - At most 3 read API calls and 2 seconds per load. Whatever is not read
    in that budget makes `truncated` true: the counts are lower bounds.
  - Session totals are cached in-process for 5 minutes per organization,
    owner and range. Control's own counters are always read fresh.
  If the read API cannot be read, `sessionsUploaded` is `null` and listed in
  `unavailable`. `searches` and `lastActiveAt` come from `usage_people_daily`,
  which is written only while `usage_people` is selected; `lastSessionAt` (the
  newest session in the range) covers activity from before that.
- `GET /api/v1/organizations/{org}/usage/people/{userId}/sessions?days&cursor`:
  that member's sessions in the range, newest first across all the
  organization's workspaces (merged by session time), 20 per page, read on
  demand with no prefetch (summaries not read within 2 seconds are `null`), each with
  its recorded title, the recorded short summary (`/v1/sessions/{id}/summary`,
  `null` when none is ready), agent name, project and times. The first page
  also carries a `rollup` built only from recorded titles and projects.
  Nothing is generated. A user who is not a member is 404 `user_not_found`.
- Every drill-down request, each page whatever its cursor, writes an
  organization-level audit row `usage.people.viewed` (viewer, subject, range,
  first or next page) before answering.
  `GET /api/v1/organizations/{org}/usage/people/audit` lists the latest 200
  for owners. These rows have no workspace, so a workspace's admin audit view does
  not list them.

Erased sessions are removed by the session pipeline and never appear here.
Admin, member and the bootstrap bearer are 403 `forbidden` on all three
routes; with `usage_people` off they are 403 `feature_not_enabled`.
