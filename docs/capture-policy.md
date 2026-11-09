# Capture policy

An organization owner/admin can mandate how members' Desktop sessions are captured and uploaded.
Storage: `selfhost_capture_policies` (migration 0019), one row per organization.

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

**Entitlement**: `SELFHOST_OPERATOR_CONTROLS` = `always` (default) | `licence` | `off` gates PUT/DELETE only
(403 `operator_controls_not_entitled`); reads are never gated. `licence` needs the licence feature
`operator_controls` (feature switch, PR #37) and is not entitled until that lands.

**Erasure**: erasure never removes membership; erase and offboard are separate operator actions. See
[session-erasure.md](session-erasure.md) for the per-session hard delete, which shares this entitlement.

**Desktop semantics**: a key present in `settings` locks that choice; Desktop hides the matching user control
(hidden, not disabled). An absent key means the user chooses. Desktop reads the policy at sign-in, token refresh
and every 15 minutes.
