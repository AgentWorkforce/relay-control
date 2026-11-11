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

- Unset policy is `{version:1, revision:1, settings:{}}`. Nothing is ever defaulted server-side
  (in particular never `sharing_mode: all`). Unknown keys, bad enums and out-of-range values: 400 `invalid_policy`.
- Served projection: when stored settings have `upload_control: operator` and no `oops_window_seconds`, responses
  carry `oops_window_seconds: 900` (15 min). Storage keeps exactly what was written.
- `revision` is monotonic per organization. The first write is revision 2. `DELETE` keeps the row with empty
  settings and revision + 1 (it does not delete the row), so a client never sees a revision go backwards.

**Routes** (also under `/cloud/api/v1/...` with the session cookie; cookie writes need JSON from an allowed Origin,
cookie `DELETE` needs an allowed Origin or `Sec-Fetch-Site: same-origin`):

- `GET /api/v1/workspaces/{ws}/access/me`: any workspace member (user token or cookie; bootstrap and `sh_wk_` 401)
  returns `{ workspace: {id, name}, role, policy }`.
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

**Desktop semantics**: a key present in `settings` locks that choice; Desktop hides the matching user control
(hidden, not disabled). An absent key means the user chooses. Desktop reads the policy at sign-in, token refresh
and every 15 minutes.
