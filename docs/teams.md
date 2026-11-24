# Organization teams

Flat, organization-level groups of members, maintained in the dashboard. Off
unless `SELFHOST_FEATURES` selects `teams` ([features.md](features.md)); it is
not in the default set. `GET /api/v1/capabilities` reports `teams`.

- A person has at most one current team per organization. A person in two
  organizations has a separate team in each.
- Teams are not nested and are not tied to workspaces.
- Membership changes are kept as dated assignments: moving a person closes
  the current assignment and opens a new one, so past windows stay
  answerable. Closed assignments are kept until the user or the organization
  is deleted.
- The tables are `organization_teams` and `organization_team_assignments`
  (migration 0096).

## API

All routes are under `/api/v1/organizations/{organizationId}` (also under
`/cloud`, with the session cookie). Access:

- An **owner** or **admin** of the organization, or the bootstrap bearer.
  A member is 403 `forbidden`. A token for another organization is 404
  `organization_not_found`.
- Feature not selected: 403 `feature_not_enabled` (checked after the role).
- A cookie-carried write needs an allowed Origin (JSON bodies through the
  usual same-origin check; the bodiless `PUT` and `DELETE` an allowed Origin
  or same-origin fetch metadata), else 403 `csrf_rejected`.

Errors are `{ "error": code, "message": text }`.

A team:

```json
{ "id": "uuid", "name": "Platform", "memberCount": 3,
  "archivedAt": null, "createdAt": "2026-11-24T10:00:00.000Z", "updatedAt": "2026-11-24T10:00:00.000Z" }
```

`memberCount` counts open assignments of people who are still members.

| Route | Answer |
|---|---|
| `GET /teams` | 200 `{ teams }`: live teams by name ignoring case, then id. `?archived=true` adds archived teams after the live ones; any other `archived` value is 400 `invalid_request` |
| `POST /teams` `{ name }` | 201 team. The name is trimmed and must be 1 to 80 characters with no control characters (U+0000 to U+001F, U+007F) (400 `invalid_request`); 409 `team_name_taken` when a live team has the same name ignoring case |
| `PATCH /teams/{teamId}` `{ name }` | 200 team. Same name rules; 404 `team_not_found` (unknown, or another organization's), 409 `team_archived`, 409 `team_name_taken`. The current name is a no-op; a change of case renames |
| `DELETE /teams/{teamId}` | 200 `{ team, unassigned }`: archives the team and closes its open assignments. Already archived: `unassigned` 0. Archiving frees the name. 404 `team_not_found` |
| `PUT /teams/{teamId}/members/{userId}` | 200 `{ assignment: { userId, teamId, startsAt }, previousTeamId }`. Closes the person's current assignment, if any, and opens one in this team. Already in this team: nothing is written and `previousTeamId` is the team's id. 404 `team_not_found`, 404 `membership_not_found` (not a current member), 409 `team_archived`, checked in that order |
| `DELETE /teams/{teamId}/members/{userId}` | 200 `{ unassigned }`: true when the person's current assignment was in this team and is now closed, false (nothing written) otherwise. 404 `team_not_found` |

While the feature is selected and the caller is an owner or admin of the
organization or the bootstrap bearer, each item of `GET /memberships` also
carries `teamId`, the member's current team or null. A member, or any caller
while the feature is off, gets that response unchanged, with no `teamId`.

Usage per team (sessions and searches, owner-only, with `usage_people` also
selected) is in [usage.md](usage.md), "Teams".

## Member removal

Removing a member closes their current assignment in the same transaction,
whether or not the feature is selected, and keeps the closed ones. A person
added back starts with no team.

## Assignment windows

An assignment covers `[startsAt, endsAt)`. Assigning, unassigning and member
removal hold the person's membership row lock (removal deletes the row), so
one person's windows in an organization never overlap. Assigning and
unassigning also hold the team row lock shared; archiving holds it exclusively
and locks each of the team's open window rows as it closes them. A window is
only ever closed under its own row lock. For assigning, unassigning and
removal, the instant used is the database clock read after the locks, and
never earlier than the end of the person's latest closed window; archiving
uses the database clock. A window that would close at or before its own start
(a change within the same instant) is deleted instead of closed.

## Audit

One `admin_audit_events` row per effective change, at organization level
(no workspace). Team names are never written to targets.

| Action | Target |
|---|---|
| `team.create`, `team.rename`, `team.archive` | `<teamId>` |
| `team.assign`, `team.unassign` | `<userId> team=<teamId>` |

A move writes one `team.assign` row. Archiving writes one `team.archive` row,
not a row per closed assignment, and member removal writes only the existing
`membership.remove` row. A no-op (same name, already in the team, already
archived, not in the team) writes none.
