# Staff read grants

A staff read grant lets the people who run the installation read one customer
workspace's shared sessions without becoming a member of it. A grant is a
short-lived, read-only credential (`sh_sr_`) that works only on the
shared-sessions MCP facade, only for the shared-session read tools, and only
for the one workspace it names.

## Who is staff

A person is staff when both hold:

- they are an `owner` of the **operator organization**: the organization
  recorded in `installation_bootstrap` in multi tenancy, or the only
  organization in single tenancy (with more than one organization in single
  tenancy, nobody is staff); and
- if the operator organization has assigned domains (`organization_domains`),
  their email is on one of them.

The rule is checked when a grant is minted and again on every use of the
credential. Demoting the person, removing them from the operator
organization, or moving their email off the operator's domains stops every
grant they hold on its next request. The bootstrap token is not a person and
can neither mint nor hold a grant.

A member of the workspace does not need a grant: their own sign-in already
gets the full tool plan.

## Routes

All three routes are staff only. Every other caller, including a missing or
invalid credential, gets `404 not_found`, the same answer as an unknown
workspace.

The caller must be signed in interactively: the dashboard browser session or
a CLI login (`sh_at_` with `cli:auth`). A Desktop session
(`desktop:workspaces`), a device-code login Agent Relay Desktop started
(the code names a `desktop_host_name`), a Desktop provider credential, a
session issued by an
enrollment key, a pending handoff, workspace API tokens, the service token
and a staff read grant itself are all refused.

- `GET /api/v1/workspaces/{workspaceId}/staff-read-grants` lists the
  workspace's grants, newest first: id, workspace and organization, staff
  person and operator organization, reason, `status` (`active`, `revoked`,
  `expired`), created, expiry, revocation and last use. Never token material.
- `POST /api/v1/workspaces/{workspaceId}/staff-read-grants` with
  `{ "reason": "...", "expires_in_days": 7 }`. `reason` is trimmed and must be
  1 to 500 characters. `expires_in_days` is an integer from 1 to 365 (default
  90, so a longer grant must be asked for). Answers `201 { grant, token: { accessToken, workspaceId, expiresAt } }`.
  The token is shown once; only its SHA-256 is stored. At most 10 mints per
  staff person per hour (`429 rate_limited`).
- `DELETE /api/v1/workspaces/{workspaceId}/staff-read-grants/{grantId}`
  revokes the grant and answers `200 { grant }`. Revoking a revoked grant
  answers it unchanged.

Browser-session writes are refused from another origin
(`403 csrf_rejected`), like every other cookie write.

## The credential

- Prefix `sh_sr_`, opaque, scope exactly `rth:read`.
- No refresh token and no session row. It is never refreshed and never used
  to mint another credential.
- Accepted only as an `Authorization: Bearer` header on
  `POST /api/v1/mcp/shared-sessions` (and its `/cloud` alias). A cookie, the
  `/mcp` path, and every other route treat it as no credential at all.
- Each request runs one update that sets `last_used_at` only while the grant
  is neither revoked nor expired, then re-reads the staff rule. The holder and
  the workspace come only from the grant row; the credential never falls back
  to a membership.

### What it can call

Before any MCP server is built, every JSON-RPC message is checked; a request
with any message outside this list (also inside a batch) is refused with
`403`:

- `initialize`, `ping`, `tools/list`, and notifications (`notifications/...`);
- `tools/call` of `open_shared_sessions`, `search_shared_sessions`,
  `get_shared_session`, `get_shared_session_context`, `list_session_timings`,
  `list_session_summaries`, `get_session_summary` and
  `describe_capabilities`.

`resources/read` and every other method are refused. `tools/list` names
exactly the tools above, and `describe_capabilities` reports
`auth_mode: "staff_read_grant"` with every other group unavailable because
the connection is a staff read grant. A `workspace_id` other than the
grant's is refused by the tools. Relay messaging, Connect, launches, Amp,
Factory, Capy and customer support are never attached.

Every read is recorded in the [shared-session read audit](shared-session-read-audit.md)
with `auth_mode` `staff_read_grant` and the staff person as `caller_user_id`.

What the read tools return is the workspace's shared sessions, activity and
summaries. Nothing about pipeline health, backlog or search lag is reachable,
and the scope is not widened.

### Introspection

RelayHistory introspects the credential at
`POST /internal/v1/auth/introspect`. Only the History audience activates a
grant: an origin listed in `SELFHOST_RELAYHISTORY_AUDIENCES` (by default the
session read API's public URL) that is the workspace's own History origin
when it has one, else the configured History URL. Every other introspection
audience, including those in `SELFHOST_INTROSPECT_AUDIENCES`, is inactive
with `audience`. An active grant answers
`principal_type: "desktop-user"` with `sub` the staff person, `org` and
`workspace` the grant's customer organization and workspace,
`role: "member"`, `scopes: ["rth:read"]`, and `iat`/`exp` from the grant.
Any `machine` is `machine_not_owned`; another `workspace`, another
audience, revocation, expiry or a lost staff rule is inactive. Introspection
does not count as a use.

## Lifetime

At most 365 days (90 before migration 0080), enforced by the table as well
as the route. A mint without `expires_in_days` lasts 90 days. Revocation,
expiry or losing the staff rule fails the next request. Deleting the staff
person, the operator organization or the workspace deletes the grant.

## Audit

In the customer workspace's audit log (`GET /api/v1/workspaces/{id}/admin/audit`),
actor the staff person:

- `staff_read_grant.minted`: target `<grantId> workspace <workspaceId> (expires <time>)`
- `staff_read_grant.revoked`: target `<grantId> workspace <workspaceId>`

## Storage

Table `staff_read_grants` (migration 0061): `id`, `workspace_id` and
`organization_id` (the customer workspace), `staff_user_id`,
`staff_organization_id` (the operator organization at mint), `reason`,
`token_hash` (unique), `created_at`, `expires_at`, `revoked_at`,
`revoked_by`, `last_used_at`.
