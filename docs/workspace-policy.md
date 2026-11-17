# Workspace policy (v2)

An organization owner/admin can set the Agent Relay Desktop settings that apply to every member of the
organization: capture, spawning, auto-join, inbound delivery and analytics. The document is served next to the
capture policy ([capture-policy.md](capture-policy.md)), which stays exactly as it was for older clients.
This file is the allowlist the client pins: a key not listed here is refused on write and never served.

Storage: the organization's `capture_policies` row (migration 0072 adds `workspace_settings`, `workspace_revision`
and `consent`). The capture section is the row's existing `settings`.

## Document

```json
{
  "version": 2,
  "revision": 5,
  "managed": false,
  "consent": ["spawn_full_access_claude", "spawn_requester_approvals"],
  "sections": {
    "capture":   { "locked": { "sharing_mode": "selected" }, "defaults": {} },
    "spawn":     { "locked": { "spawn_max_agents": 8 }, "defaults": { "accept_spawns": true } },
    "join":      { "locked": { "auto_join_repositories": ["acme/web"] }, "defaults": { "auto_join_general": true } },
    "delivery":  { "locked": { "admin_senders": ["lead", "lead@cloud-example"], "inbound_default": "hold" }, "defaults": {} },
    "analytics": { "locked": { "analytics_enabled": false }, "defaults": {} }
  }
}
```

- `locked`: an operator value the person cannot change. `defaults`: an initial value the person may change.
  A key that is absent leaves the client's own behaviour unchanged. Nothing is ever defaulted server-side.
- All five sections are always present, each with both tiers (empty when unset).
- Unset policy: `{version: 2, revision: 1, managed: false, consent: [], sections: {...every tier empty}}`.

## Allowlist

| section | key | type / values | tier allowed | person-only |
| --- | --- | --- | --- | --- |
| capture | `sharing_mode` | `all` \| `new` \| `selected` | locked only | no |
| capture | `upload_control` | `operator` \| `user` | locked only | no |
| capture | `oops_window_seconds` | integer 0..86400 | locked only | no |
| capture | `user_retroactive_delete` | boolean | locked only | no |
| spawn | `accept_spawns` | boolean | locked or defaults | yes |
| spawn | `spawn_allow_teammates` | boolean | locked or defaults | yes |
| spawn | `spawn_max_agents` | integer 1..32 | locked or defaults | no |
| spawn | `spawn_native_input` | boolean | locked or defaults | yes |
| spawn | `spawn_requester_approvals` | boolean | locked or defaults | yes |
| spawn | `spawn_repositories` | array of 0..200 strings, each 1..200 characters | locked or defaults | yes |
| spawn | `spawn_full_access_claude` | boolean | locked or defaults | yes |
| spawn | `spawn_full_access_codex` | boolean | locked or defaults | yes |
| spawn | `spawn_billing_claude` | `subscription` \| `api` \| `unspecified` | locked or defaults | no |
| spawn | `spawn_billing_codex` | `subscription` \| `api` \| `unspecified` | locked or defaults | no |
| join | `auto_join_general` | boolean | locked or defaults | no |
| join | `auto_join_repositories` | array of up to 200 `owner/name` (`[A-Za-z0-9_.-]{1,100}` each part), stored lower-cased, duplicates collapsed | locked or defaults | no |
| join | `trust_workspace_members` | boolean | locked or defaults | no |
| delivery | `inbound_default` | `deliver` \| `hold` | locked or defaults | no |
| delivery | `trusted_relay_senders` | array of 0..200 strings, each 1..200 characters | locked or defaults | no |
| delivery | `admin_senders` | array of strings, computed by the server (read only) | served in locked | no |
| analytics | `analytics_enabled` | boolean | locked or defaults | no |

Capture keys keep the capture policy's validation and served projection (an `operator` upload control without a
window serves `oops_window_seconds: 900`).

## Consent

`consent` lists the person-only keys whose operator value applies only after the person on that computer agrees.
It may name only the keys marked person-only above; it is stored sorted and deduplicated. A person-only key that is
set but not named in `consent` is still served; the client decides how to ask.

## managed

Always `false` on this server until enrollment-key consent lands; then the enrollment decides it.

## admin_senders

Served in `delivery.locked.admin_senders` on `access/me` only, and only while the stored delivery section sets
`inbound_default` (either tier). It is the sorted, deduplicated union of `agent_name` and `address` of every Agent
Relay Desktop identity synced into that workspace (`PUT /api/v1/workspaces/{ws}/messaging/desktop-identities`) by a
user who is an owner or admin of the organization. It is resolved on every read, never stored, and never served on
the organization route (which has no workspace). Writing it is 400 `admin_senders is computed by the server`.

## Revision counters

The row carries two counters:

- `revision` (capture, v1): moves only when the capture settings change. Desktop uploaders send it in
  `X-Agent-Relay-Capture-Policy-Revision` and stale uploads are refused, so a spawn or delivery change must not
  invalidate in-flight uploads.
- `workspace_revision` (served here as `revision`): moves on every write through either route, so a client can tell
  its cached document is stale.

Both start at 1 when the organization never wrote a policy; the first write of either makes both 2 (the capture
route always moves both). Writes through both routes are serialized per organization. A `PUT` here whose capture
section equals the stored settings keeps the capture revision and `sharing_mode_since`.

## Routes

Also under `/cloud/api/v1/...` with the session cookie; cookie writes need JSON from an allowed Origin, cookie
`DELETE` needs an allowed Origin or `Sec-Fetch-Site: same-origin` (same rules as the capture policy).

- `GET /api/v1/workspaces/{ws}/access/me`: any workspace member; returns
  `{ workspace, role, policy, workspace_policy }` (`policy` is the v1 capture policy, unchanged).
- `GET /api/v1/organizations/{org}/workspace-policy`: owner/admin (or bootstrap bearer); members 403, other
  organizations 404. Never includes `admin_senders`.
- `PUT /api/v1/organizations/{org}/workspace-policy`: body `{ sections, consent? }`, a full replace. Sections
  absent from the body are stored empty; `consent` defaults to `[]`. Optional `If-Match: <revision>` is compared
  with `workspace_revision`. Returns the served document.
- `DELETE /api/v1/organizations/{org}/workspace-policy`: clears every section (capture included) and consent;
  the row is kept and `workspace_revision` moves on, so revisions never go backwards. Optional `If-Match`.

## Errors

- 400 `invalid_policy`: unknown top-level field (`Unknown field: x`), unknown section, unknown tier, unknown key,
  wrong type or range, a key in both `locked` and `defaults`, a capture key in `defaults`, `admin_senders` on write,
  a consent entry that is not a person-only key.
- 403 `operator_controls_not_entitled` (writes with the switch off), 403 `csrf_rejected` (cookie write from a
  disallowed origin), 403 for members.
- 409 `revision_mismatch`: `Workspace policy is at revision N, not M`.

## Audit

Writes audit `workspace_policy.set` / `workspace_policy.cleared` with target
`<org> revision=<workspace_revision> keys=<section.key,...>`: key names only, sorted, never values; consent entries
appear as `consent.<key>`.

## Introspection

Active user-token answers from `POST /internal/v1/auth/introspect` carry `workspace_policy: {revision}` (the
workspace revision, 1 when unset, read in the same query as the token) and `managed: false`, next to
`capture_policy`. Agent, service and staff read grant answers carry neither.

## Operator switch

`SELFHOST_OPERATOR_CONTROLS` = `always` (default) | `off` gates `PUT`/`DELETE` only (403
`operator_controls_not_entitled`); reads are never gated.
