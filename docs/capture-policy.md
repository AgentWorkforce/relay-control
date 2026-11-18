# Capture policy

An organization owner/admin can mandate how members' Desktop sessions are captured and uploaded.
Storage: `capture_policies` (migration 0019), one row per organization.

**Policy object** (`version` 1): `{ "version": 1, "revision": 7, "settings": { ... } }`

| key | values | when absent |
| --- | --- | --- |
| `sharing_mode` | `all` \| `new` \| `selected` | user chooses |
| `upload_control` | `operator` \| `user` | user |
| `oops_window_seconds` | integer 0..86400 | no window (upload immediately) |
| `user_retroactive_delete` | boolean | user chooses |

- Unset policy is `{version:1, revision:1, settings:{}}`. Nothing is defaulted in storage. The only server-side
  default is a deployment default sharing mode, served only when `SELFHOST_DEFAULT_SHARING_MODE` is set (see
  "Deployment default and override roles" below). Unknown keys, bad enums and out-of-range values: 400 `invalid_policy`.
- Served projection: when stored settings have `upload_control: operator` and no `oops_window_seconds`, responses
  carry `oops_window_seconds: 900` (15 min). Storage keeps exactly what was written.
- `revision` is monotonic per organization. The first write is revision 2. `DELETE` keeps the row with empty
  settings and revision + 1 (it does not delete the row), so a client never sees a revision go backwards.

**Routes** (also under `/cloud/api/v1/...` with the session cookie; cookie writes need JSON from an allowed Origin,
cookie `DELETE` needs an allowed Origin or `Sec-Fetch-Site: same-origin`):

- `GET /api/v1/workspaces/{ws}/access/me`: any workspace member (user token or cookie; bootstrap and `sh_wk_` 401)
  returns `{ workspace: {id, name}, role, policy }`. `policy` is the policy as served to the caller's role (the
  same as the organization route unless a deployment default or override role applies, see below).
- `GET|PUT|DELETE /api/v1/organizations/{org}/capture-policy`: owner/admin (or bootstrap bearer); members 403, other
  organizations 404. `PUT` body `{ settings }` is a full replace; optional `If-Match: <revision>` gives 409
  `revision_mismatch` when stale. Writes audit `capture_policy.set` / `capture_policy.cleared` with target
  `<org> revision=<n> keys=<k,...>` (key names only, never values).

**Operator switch**: `SELFHOST_OPERATOR_CONTROLS` = `always` (default) | `off` gates PUT/DELETE only
(403 `operator_controls_not_entitled`); reads are never gated. An unrecognised value is treated as `off`.

**Erasure**: erasure never removes membership; erase and offboard are separate operator actions. See
[session-erasure.md](session-erasure.md) for the per-session hard delete, which shares this switch.

**Server enforcement**: token introspection (`POST /internal/v1/auth/introspect`) returns this served policy as
`capture_policy` on every active user-token answer, next to the caller's live `role`. The sessions pipeline enforces it
from there rather than storing a copy:

- `user_retroactive_delete: false`: the ingest edge refuses a member's own Cloud delete
  (`POST /v1/delivery/sessions/selection` with `enabled: false`, and reset) with 403 `policy_forbids_user_delete`.
  Organization owners and admins can still delete, and the operator hard delete
  ([session-erasure.md](session-erasure.md)) is owner/admin only and unaffected.
- An older Control without `capture_policy` in its answers leaves deletes unrestricted, as before.
- Uploads: Agent Relay Desktop names the policy revision it applies in `X-Agent-Relay-Capture-Policy-Revision` on every
  upload and every direct-upload credentials ask. When the policy sets any key, a missing or older revision is logged
  (`capture_policy_upload_violation`) and, in enforce mode, refused 409 `capture_policy_stale` so Desktop reads the
  policy again. Control checks the credentials ask (`SELFHOST_CAPTURE_POLICY_UPLOADS`); the sessions pipeline ingest
  edge checks batch uploads (`RELAYHISTORY_SELFHOST_CAPTURE_POLICY_UPLOADS`). Both are `report` (log only) by default.
- `sharing_mode_since`: served with the policy while `sharing_mode` is `new`, the time it became `new` (kept across
  writes that keep it). In enforce mode the ingest edge refuses (422 `capture_policy_session_predates_policy`) a
  batch carrying a session record whose first activity is earlier.

**Deployment default and override roles**: two optional environment variables set a sharing mode for the whole
deployment and let organization owners and/or admins keep choosing their own. Both are unset by default; unset, every
response is exactly the stored policy.

- `SELFHOST_DEFAULT_SHARING_MODE` = `all` | `new` | `selected`: the sharing mode served when the organization has not
  saved one. The effective mode is the organization's stored `sharing_mode`, else this default, else none. The
  organization-saved mode always wins.
- `SELFHOST_SHARING_MODE_OVERRIDE_ROLES` = a comma-separated list of `owner` and/or `admin`: callers with one of these
  organization roles are never locked on sharing mode. `settings.sharing_mode` and `sharing_mode_since` are left out
  of the policy served to them, so Agent Relay Desktop shows them the control. The v2 document serves them the
  effective mode as the initial value `sections.capture.defaults.sharing_mode` instead (workspace-policy.md).
- Every other caller (members, roles not listed, and a missing or unknown role) is locked: under a deployment default
  with no stored mode, `settings.sharing_mode` is the default. Role names are compared exactly (lower case).
- Applied on `access/me`, the enrollment key exchange, the direct-upload credentials check (the upload check runs on
  the policy as served to that caller), and introspection `capture_policy` by the token's live role (a staff read
  grant is served as a member; an answer held through a database outage is projected the same way as a live one).
- The organization `capture-policy` and `workspace-policy` routes, the fleet view and the audit log show only what is
  stored; a deployment default never appears there and saving the policy never writes it.
- `revision` and `workspace_revision` do not move when either variable is set, changed or removed, or when a
  person's role changes (for example an owner made a member). Desktop applies the new document on its next policy
  read (sign-in, token refresh or every 15 minutes). The upload revision check cannot see such a change, so until
  that read the computer keeps the mode it last read.
- A deployment default `new` has no `sharing_mode_since` (it was never stored with a time), so the ingest edge
  `capture_policy_session_predates_policy` check has no time to compare against and does not apply. The
  organization saving `new` sets the time.
- Agent Relay Desktop keeps the last policy it read per workspace and operating-system account. People with
  different roles who share one operating-system account share that copy until the next successful read.
- A Desktop build that carries its own compiled policy defaults applies them until its first policy read; give it
  the same sharing mode as the deployment default.
- An invalid value in either variable stops Control at start. The upload check (`SELFHOST_CAPTURE_POLICY_UPLOADS`)
  treats a served deployment default like any other setting: a locked caller must name a revision (1 when the
  organization never saved a policy).

**Workspace policy (v2)**: [workspace-policy.md](workspace-policy.md) serves this policy as the `capture` section of a
larger document (spawn, join, delivery, analytics) on `access/me` as `workspace_policy` and on
`/api/v1/organizations/{org}/workspace-policy`. Writes through either route land in the same row. This policy's
`revision` moves only when the capture settings change, so writes that touch only the other sections never make an
upload stale; the v2 document has its own `workspace_revision`, which every write through either route moves.

**Desktop semantics**: a key present in `settings` locks that choice; Desktop hides the matching user control
(hidden, not disabled). An absent key means the user chooses. Desktop reads the policy at sign-in, token refresh
and every 15 minutes.
