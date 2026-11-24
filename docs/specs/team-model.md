# Spec: teams for operator spend and usage grouping

Status: **proposal, not implemented.** This change is the spec only: no code, no migration, no flag and no
deployment. Every table, route and name below is a sketch for review. Building any of it is a separate decision
(section 12).

Scope: a team model owned by relay-control (people grouped into teams inside an organization), and the rule for
grouping session counts, tokens and cost by team on the operator dashboard. It is written to slot into the
session-intelligence spend attribution proposal of the history pipeline
(`docs/proposals/session-intel-spend-attribution.md` in that repository), which attributes recorded usage by
organization, workspace, person and project and leaves teams as an open question.

## 1. Problem

An operator can see usage per organization and per person, but not per team, because nothing maps a person to a
team:

- relay-control stores people (`users`), organizations, `organization_memberships` (role `owner`, `admin` or
  `member`, primary key `(organization_id, user_id)`) and workspaces. There is no team or group table.
- Sign-in reads `email`, `email_verified` and the name claims only. No `groups` claim is read, and neither the
  subject nor the issuer is stored. There is no SCIM.
- The session pipeline owns the session to person link (`userIds` on the session row), the project fields and all
  token and cost data. relay-control stores no token or cost numbers.

A second problem decides the shape of the answer. A session can have several users. The existing People view
(`GET /api/v1/organizations/{org}/usage/people`, [usage.md](../usage.md)) counts such a session once for each of
its users, which is right for a person's row ("sessions this person took part in") and wrong for any sum built from
those rows. A team figure made by adding up its members' rows counts a shared session twice, and its cost twice.

## 2. Goals and non-goals

Goals:

1. A team is something an organization's owners and admins define and maintain in the dashboard.
2. Every additive figure (sessions, tokens, cost) can be grouped by team so that the groups add up to the total of
   the scope, with no session counted twice.
3. The pipeline stays team-agnostic: it needs no team table, no team claim in tokens and no new credential.
4. A past window keeps its grouping when people move between teams or leave.

Non-goals: billing, budgets, chargeback, alerts, nested teams, team-based access control (who may read which
session stays with the existing session access rules), a team lead role, IdP group sync and SCIM. Section 9 says
how the last two could be added later.

## 3. Model

### 3.1 Rules

- **A team belongs to one organization.** It is not tied to a workspace. Memberships are per organization, and a
  session's workspace is already a filter on the session, so a workspace view is "this workspace's sessions,
  grouped by the organization's teams".
- **A person has at most one team per organization at any time.** This is what makes team figures add up. A person
  who belongs to two organizations has an independent team in each. Tags or secondary teams are not in this
  proposal; they could be added beside it but could never be summed.
- **Teams are flat.** No parent team.
- **Assignments have a start and an end.** Moving a person closes the current assignment and opens a new one.
  Nothing is updated in place, so "which team was this person in during that window" stays answerable.
- **Having no team is a normal state.** New members start without one.

### 3.2 Tables (sketch, not a migration)

The names carry the `organization_` prefix on purpose: in the hosted product's schema `teams` and `team_members`
already mean short-lived groups of agents, and "team activity" names a session view.

```sql
CREATE TABLE organization_teams (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  archived_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, organization_id)
);
-- A name is unique among the organization's live teams, whatever its case.
CREATE UNIQUE INDEX organization_teams_name ON organization_teams (organization_id, lower(name))
  WHERE archived_at IS NULL;

CREATE TABLE organization_team_assignments (
  id              uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  team_id         uuid NOT NULL,
  user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  starts_at       timestamptz NOT NULL,
  ends_at         timestamptz,               -- null: the current assignment
  source          text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual')),
  FOREIGN KEY (team_id, organization_id) REFERENCES organization_teams (id, organization_id) ON DELETE CASCADE,
  CHECK (ends_at IS NULL OR ends_at > starts_at)
);
-- One current team per person and organization.
CREATE UNIQUE INDEX organization_team_assignments_current
  ON organization_team_assignments (organization_id, user_id) WHERE ends_at IS NULL;
CREATE INDEX organization_team_assignments_team ON organization_team_assignments (team_id, starts_at);
```

Notes on the sketch:

- **No foreign key to `organization_memberships`.** Removing a member deletes the membership row, and a cascade
  would delete the person's team history with it. Their sessions of last week would then fall out of their team.
  Instead, removing a member closes the open assignment in the same transaction, and assigning requires a current
  membership at the time of the write.
- **Deleting the user or the organization deletes the rows** (the two cascades). A closed assignment holds a user
  id, a team id and two timestamps, nothing else.
- **Archiving a team** closes its open assignments and frees its name. The team keeps its id, so older windows still
  show it, marked archived. Hard deletion is not offered.
- **Closed intervals do not overlap** because the store closes and opens inside one transaction while holding the
  membership row's lock. A database exclusion constraint would need an extension, which this repository avoids.
- Both tables would be added to `src/control-tables.ts`, and the migration would refresh the schema manifest.
  No migration number is reserved by this document.

## 4. The grouping rule

This section is the contract. It applies to every additive measure: session counts, observed-session counts, each
token field, known-cost session counts and cost.

### 4.1 The unit is the session

The pipeline counts each session once, on its directory key (organization, workspace, harness, session id). A
session carries a set of user ids, which may be empty, one or several. Grouping by team assigns **each session to
exactly one bucket**:

| The session's users resolve to | Bucket |
|---|---|
| no users at all | `unattributed` (the pipeline's own bucket) |
| one team, for every user | that team |
| no team, for every user | `noTeam` |
| anything else: two or more teams, or a mix of a team and no team | `crossTeam`, keyed by the sorted set of teams involved (`null` standing for no team) |
| not known: the session is in the read API's `other` remainder (section 5.1) | `notResolved` |

A cross-team session is never split between its teams and never added to each of them. It is reported on its own
row ("shared by Platform and Payments"), with its session count.

**Invariant.** For every additive measure and every scope:

```
sum(team rows) + sum(crossTeam rows) + noTeam + unattributed + notResolved = the scope's total
```

The same holds for each denominator (`sessions`, `observedSessions`, `knownCostSessions`). A report that cannot
keep the invariant (an input was truncated, section 5.3) says so instead of showing rows that silently fall short.

**What is never done:**

- summing per-person rows into a team row (a shared session is in several person rows);
- dividing a shared session's cost by its number of users or teams;
- showing a cost on a "sessions this team took part in" figure. If such a figure is ever shown it is a count,
  labelled as not additive.

Counts of people follow the usual rule for distinct counts: a team's active members are counted as distinct
users, and team rows of such a measure are not summed into a total.

### 4.2 Which team a person counts under

Resolution happens inside the session's own organization, as the spend proposal already requires for people: a
membership or an assignment never moves a session to another organization.

For a report over the window `[since, until)`, a user's team is **their last team in the window**: the assignment
in force at `min(until, now)`, or, when there is none at that instant, the most recent assignment that ended
inside the window. Otherwise the user has no team for that report.

Consequences, all intended:

- A person who changed team during the window counts under the later team for the whole window. The session
  totals the pipeline reports are per session, not per day, so there is nothing finer to split.
- A person who left the organization during the window still counts under the team they left from. In the spend
  proposal their sessions sit in the `former member` bucket per person; by team they stay where they were.
- A person given a team today does not move their sessions of earlier windows.
- The report states the rule in its output (`teamAsOf`), as the spend proposal states what its window means.

Alternatives are listed in section 12 (decision 4).

## 5. Where the join runs

### 5.1 Proposed: in relay-control, over user-set buckets

relay-control already reads the read API with the viewer's own read token for the Usage and People pages. The
team report does the same and groups the answer itself:

1. The pipeline's spend block (or, for plain session counts, its per-user aggregate) returns **buckets keyed by
   the session's user set**: one row per distinct sorted `userIds` list, each with the additive measures and their
   denominators. Every session is in exactly one row. A row with one user is the proposal's per-person row; a row
   with several is its `shared` bucket, with the user ids themselves instead of only their number.
2. relay-control resolves each user id to a team (section 4.2) and adds the row to one bucket (section 4.1).
3. For an organization-wide report it repeats this per workspace and adds the results. That is safe because a
   session belongs to exactly one workspace.

What this needs from the pipeline, and nothing more:

- on each shared bucket, the sorted list of user ids (they are the ids the reader already scopes by; no names or
  e-mail addresses);
- a stated cap on the number of rows, with the remainder in one `other` row so totals still hold;
- the person join done at read time in the read API, scoped by the caller's read token.

The spend proposal's current draft states all three: one bucket per sorted user set, at most 200 user-set buckets
per scope (largest first by session count) and an `other` remainder. relay-control cannot resolve the `other` row to
teams, so it is carried through as `notResolved` and shown as such. An organization whose sessions spread over more
than 200 distinct user sets in one scope therefore sees part of its usage outside the team rows; the report gives
that share, and it is the first thing to revisit if it is large in practice.

Still open on the pipeline side: the same user-set grouping on the per-user session aggregate (section 6), which
is a different route from the spend block.

Team data never leaves relay-control, the pipeline learns nothing about teams, and no service credential or
service route is added.

### 5.2 Until the pipeline carries user sets

If the spend block has per-person rows and shared buckets with only a user count, the report still works without
double counting: sessions with one user are grouped by team, and every shared session goes to the
`notResolved` row. The invariant holds. The row shrinks to the `other` remainder when the user sets arrive.

### 5.3 Bounds

- The read API calls keep the limits the People view has today (a few calls and a short time budget per load).
  Anything not read makes the report `truncated`, and a truncated report shows lower bounds, labelled as such.
- relay-control computes a report for the requested window only. It does not store team sums, roll them up per
  day, or add windows together: the pipeline's totals are per session, and a long session appears in several
  windows.
- The existing limitation stays: an organization-wide report covers the workspaces the viewer can read.

### 5.4 Alternatives considered

- **The pipeline fetches a team roster from relay-control and groups by team itself.** It could then use the team
  in force at each session's own time, and no row cap would apply. It needs a new service route that hands out
  membership data, a cache that can be stale, and a second place that must implement section 4 exactly. Not
  proposed for the first version; it remains possible later because the tables are the same.
- **A team claim in read tokens.** It would describe the reader, not the people being reported on. Rejected.
- **Summing the People view by team.** Rejected for the reason in section 1.

## 6. The existing Usage, People and Fleet figures

| Figure | Per team |
|---|---|
| `sessionsUploaded` | From user-set buckets by the rule in section 4, never from People rows. Needs the per-user aggregate (`/v1/sessions/users`) to offer a user-set grouping; until then the fallback of section 5.2 applies to the sample path only. |
| `searches` | A search has exactly one user, so a team's searches are the sum of its members' (`usage_people_daily`), using the same team resolution. |
| `activeUsers`, last activity | Distinct members; not summed across teams. |
| tokens and cost | Only when the read API serves the spend block; otherwise `null` and listed in `unavailable`, never 0. |

The People and Fleet responses would gain the person's current `teamId` so the dashboard can show and filter by
it. Their numbers do not change.

## 7. API sketch

All under `/api/v1/organizations/{organizationId}` (and `/cloud` with the session cookie), behind a new feature
name in `SELFHOST_FEATURES` that is off unless selected, with its boolean in `GET /api/v1/capabilities`.

| Route | Who | Notes |
|---|---|---|
| `GET /teams` | owner, admin | Live teams with member counts; `?archived=true` includes archived ones. |
| `POST /teams` `{name}` | owner, admin | 409 on a name in use. |
| `PATCH /teams/{teamId}` `{name}` | owner, admin | Rename only. |
| `DELETE /teams/{teamId}` | owner, admin | Archives; closes its assignments. |
| `PUT /teams/{teamId}/members/{userId}` | owner, admin | Assigns or moves the member. Idempotent. 404 for a user who is not a member. |
| `DELETE /teams/{teamId}/members/{userId}` | owner, admin | Ends the assignment. |
| `GET /usage/teams?days=7\|30\|90` | owner | The team report. Same audience, feature check order and bounds as the People view. |

The report, in outline:

```json
{ "teams": {
  "range": { "days": 30, "from": "2026-10-26", "to": "2026-11-24" },
  "teamAsOf": "2026-11-24T23:59:59.999Z",
  "rows": [
    { "kind": "team", "teamId": "<id>", "name": "Platform", "archived": false, "members": 6, "activeUsers": 5,
      "sessions": 212, "searches": 40,
      "spend": { "observedSessions": 190, "inputTokens": 0, "outputTokens": 0, "cachedInputTokens": 0,
                 "knownCostSessions": 120, "costUSD": 0 } },
    { "kind": "crossTeam", "teamIds": ["<id>", "<id>"], "sessions": 9, "spend": null },
    { "kind": "noTeam", "sessions": 14, "spend": null },
    { "kind": "unattributed", "sessions": 3, "spend": null },
    { "kind": "notResolved", "sessions": 0, "spend": null }
  ],
  "total": { "sessions": 238 },
  "source": "aggregate",
  "truncated": false,
  "unavailable": ["spend"]
} }
```

`spend` repeats the field names and rules of the spend proposal (two independent denominators; `costUSD` is `null`
when no session in the row has a known cost; nothing imputed). The numbers above are placeholders.

Audit rows (`admin_audit_events`, organization level): `team.create`, `team.rename`, `team.archive`,
`team.assign` and `team.unassign` (target: user id and team id), and `usage.teams.viewed`. Organization-level audit
rows are not listed by the workspace audit route today; the People view added its own owner-only audit list, and
the team report would be listed there too.

## 8. Privacy and permissions

- A team of one shows one person's figures, so the report has the People view's audience: owners only. Admins
  manage teams but do not see the report, as they do not see People today. Widening either is decision 6.
- Team names are free text written by operators and shown only inside the organization. They are not sent to the
  pipeline or to any other service.
- relay-control sends the pipeline nothing new. It receives user ids it already knows.
- Closed assignments of a removed member keep that member's user id until the user or the organization is
  deleted, or for a shorter retention if one is chosen (decision 5).

## 9. Other sources of team membership (later)

- **IdP groups.** Nothing reads a `groups` claim today, and group claims differ by provider (names, object ids,
  or a pointer to fetch when the list is long). They are also many per person and only refresh at sign-in. Using
  them would need a mapping from group to team with an order of precedence, to keep one team per person, and a
  decision on who wins when an operator has also assigned the person by hand. The `source` column leaves room for
  it; nothing else here depends on it.
- **SCIM.** Not present in relay-control. It would be its own project and could write the same two tables.

Starting with the hand-maintained table does not block either.

## 10. Hosted product

The hosted product has no people-team model either, so the importer has nothing to copy, and this proposal adds
no import step. Whether the hosted product gets the same model is a separate decision (decision 7); the grouping
rule in section 4 does not depend on which control plane holds the tables.

## 11. If approved: order of work and tests

Each step is its own change and needs its own go-ahead.

1. Tables, store functions and the team routes, behind the feature. Member removal closes the assignment.
2. The dashboard's team settings (create, rename, archive, assign), and the team shown on People and Fleet.
3. The team report for sessions and searches. Needs the user-set grouping on the read API's per-user aggregate.
4. Tokens and cost in the report, once the read API serves the spend block.

Tests that must exist before step 3 ships:

- the invariant of section 4.1, on a fixture with single-user sessions, a session shared inside one team, one
  shared across two teams, one shared between a team and a person without a team, and one with no users;
- a shared session's cost appears once in the whole report;
- a person who moves teams inside the window, one who leaves the organization inside it, and one assigned after it;
- the fallback of section 5.2 and an `other` remainder from the read API, each with the invariant;
- a truncated read is labelled and never presented as a total;
- a second organization's teams never resolve a session of the first, for a user who belongs to both;
- removing a member, deleting a user and archiving a team leave the tables as section 3.2 says.

## 12. Open decisions

1. **Source of teams.** A table maintained in the dashboard (proposed), or IdP groups first.
2. **One team per person** (proposed, so figures add up), or several with one marked primary.
3. **Organization-level teams** (proposed), or teams per workspace.
4. **Which team counts for a window.** The last team in the window (proposed); the team right now, which is
   simpler but rewrites past windows when people move; or the team at each session's own time, which needs the
   pipeline to group (section 5.4).
5. **How long closed assignments of removed members are kept.** Until the user or organization is deleted
   (proposed), or a fixed number of days.
6. **Who sees the team report.** Owners only (proposed, as for People), or admins too.
7. **The hosted product.** Same model there, or self-hosted installations only for now.
8. **The pipeline contract in section 5.1.** The spend proposal's draft now carries it (user ids on shared buckets,
   a cap of 200 with an `other` row, the join at read time). It is a draft on that side too, and the per-user
   session aggregate has no user-set grouping yet. Section 5.2 is what happens without either.
