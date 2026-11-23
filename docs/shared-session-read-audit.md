# Shared-session read audit

Every call of an MCP shared-session read tool on
`/api/v1/mcp/shared-sessions` (and `/mcp`) writes one append-only row to
`shared_session_read_audit` (migration 0042). The record shows who asked,
from which calling chat, what they asked for, and which teammates' sessions
were returned and cited. It lets an owner prove, from data that stays in the
installation's own database, that engineering questions were answered using
teammates' sessions.

Always on; there is no setting. Nothing leaves the installation.

## Audited tools

`open_shared_sessions`, `search_shared_sessions`, `get_shared_session`,
`get_shared_session_context`, `list_session_timings`, `list_session_summaries`
and `get_session_summary`. Successful and failed
calls alike (a refused workspace, an unknown session, a History outage, a
timeout, arguments refused by the input schema: recorded as `Input validation
error.` without the validation detail). Other MCP tools are not recorded here.

## The record

| Column | Meaning |
|---|---|
| `id` | Record id (uuid) |
| `occurred_at` | When the call finished (database clock, microseconds, UTC) |
| `organization_id`, `workspace_id` | The credential's organization and workspace |
| `caller_user_id` | The person the credential belongs to |
| `identity_kind` | `desktop` (an Agent Relay Desktop call: a Desktop provider credential or the Desktop marker), `oauth` (a hosted MCP OAuth connector), or `hosted` (a CLI-login bearer or the dashboard session) |
| `auth_mode` | `cli_login`, `session`, `oauth`, or `staff_read_grant` (a [staff read grant](staff-read-grants.md); `caller_user_id` is the staff person) |
| `desktop_provider` | The Desktop provider bound to a provider credential (`claude`, `copilot`, `codex`, ...), else null |
| `oauth_client_id`, `oauth_grant_id` | The OAuth connector's client and grant, else null |
| `mcp_session_id` | The `Mcp-Session-Id` header, when sent |
| `native_session_id`, `native_session_provider` | The calling chat (native agent session) on a Desktop call, when it names one |
| `native_session_verified` | `true` only when a signed Claude Code or Copilot hook proof named the chat (see `src/mcp/claude-attestation.ts`, `copilot-attestation.ts`); other providers' ids are injected by the client and recorded as `false` |
| `tool_name` | The MCP tool |
| `outcome`, `error_message` | `ok` or `error`; the public error message the caller saw (no stack, no upstream detail) |
| `query_text` | The caller's own search text (`query`), at most 500 characters |
| `agent_filter` | `agent` on an agent search |
| `requested_session_id`, `requested_source` | The session asked for by id |
| `filters` | Other request filters: `source`, `project`, `since`, `until`, `user_id`, `focus_timestamp`, `order`, and `cursor: true` for a continuation page (never the cursor value) |
| `result_count` | Matches, events or sessions returned |
| `result_sessions` | The returned (cited) sessions, `[{ session_id, source, owner_user_ids }]`, at most 50 sessions and 10 owners each; owners are the user ids recorded on the returned events, grouped by each event's own source (or the session's recorded members, for timings and agent searches) |
| `result_sessions_truncated` | `true` when that list was cut |
| `correlation_id` | The History correlation id, or the search's own id on a failed search |
| `duration_ms` | Time spent in the tool |

**Never stored:** transcript content (event text, task titles, tool output),
tokens, emails or names. The only caller-supplied text kept is the bounded
query the person typed.

The write is a single insert after the tool answers, awaited so the record is
durable before the response. If it fails, the read still succeeds and Control
logs `[selfhost-mcp] Shared-session read audit write failed` with the tool
name.

Rows are append-only: a trigger refuses `UPDATE`. Rows are removed with the
organization or workspace (cascade); removing a member keeps their rows.

## Export

`GET /api/v1/workspaces/{workspace}/shared-session-read-audit` (also under
`/cloud`, with the session cookie).

- Workspace **owner or admin** with a token for that workspace. A member is
  403 `forbidden`; another workspace is 404; no credential is 401.
- Query parameters, each at most once (anything else is 400):
  - `since`, `until`: ISO-8601 date-times; `since` inclusive, `until`
    exclusive.
  - `limit`: 1 to 1000, default 100.
  - `cursor`: the previous page's `next_cursor`.
  - `format`: `json` (default) or `csv`.
- Oldest first, ordered by `(occurred_at, id)`.

JSON:

```json
{
  "workspace_id": "…",
  "records": [{
    "id": "…", "occurred_at": "2026-11-10T09:12:03.512345Z",
    "caller_user_id": "…", "identity_kind": "desktop", "auth_mode": "cli_login",
    "desktop_provider": "claude", "native_session_id": "…",
    "native_session_provider": "claude", "native_session_verified": true,
    "tool_name": "search_shared_sessions", "outcome": "ok",
    "query_text": "why does the deploy job retry", "result_count": 4,
    "result_sessions": [{ "session_id": "…", "source": "codex", "owner_user_ids": ["…"] }],
    "correlation_id": "…"
  }],
  "next_cursor": "…"
}
```

(Every column in the table above is present; null when unset.)

CSV: the same columns, a header row, CRLF line ends; `filters` and
`result_sessions` are JSON in their cells. A cell that starts with `=`, `+`,
`-`, `@`, tab or CR is prefixed with `'` so a spreadsheet does not run it. The
next page's cursor is in the `x-next-cursor` response header (absent on the
last page).

Example: a full ledger for October.

```sh
url="$SITE/api/v1/workspaces/$WS/shared-session-read-audit?since=2026-10-01T00:00:00Z&until=2026-11-01T00:00:00Z&limit=1000"
cursor=""
while :; do
  page=$(curl -fsS -H "authorization: Bearer $TOKEN" "$url${cursor:+&cursor=$cursor}")
  echo "$page" | jq -c '.records[]'
  cursor=$(echo "$page" | jq -r '.next_cursor // empty')
  [ -n "$cursor" ] || break
done > read-audit-2026-10.jsonl
```

Useful aggregates from the ledger: distinct `caller_user_id` with an `ok`
search, reads whose `result_sessions[].owner_user_ids` contain someone other
than the caller (a teammate's session), and the share of calls with
`native_session_verified = true`.

### Per-session access

When session reads follow per-session access (read token mints carry the
reader kind; see [sessions-read-api.md](sessions-read-api.md#session-access)),
an owner or admin is not necessarily allowed to read every session, and the
export does not reveal sessions the exporter cannot read:

- Each page is read from the database exactly as above (same filters, order,
  page size and cursor), then checked with the exporter's own read token.
- One administrator check: `GET /v1/sessions/{id}/access` for one session id
  on the page. A 200 or 404 means the exporter is a session access
  administrator, and the page is exported unchanged. Anything else, including
  a timeout or an error, means it is not.
- Otherwise each distinct session id on the page (`requested_session_id`,
  `native_session_id`, `result_sessions[].session_id`) is checked with a read
  of that session: at most 100 per page, 4 at a time, within 15 seconds for
  the whole page. An id that is not proven readable is withheld: it becomes
  null wherever it appears, and so does that result session's
  `owner_user_ids` (its `source` is kept). A record that names several
  sessions keeps the readable ones.
- Every record on such a page carries `restricted`: `true` when any of its
  session ids was withheld, else `false`. The CSV adds a `restricted` column
  after every other column.
- An exporter whose credential cannot hold a person's read token (no
  `rth:read`, or a sign-in handoff not yet exchanged) sees no session ids.
- A page naming no session, an administrator's export and every export
  without per-session access are unchanged and carry no `restricted`.

`caller_user_id`, query text, filters, counts and the other columns are not
redacted. The stored rows are never changed.

## Retention and purge

Rows are kept indefinitely by default; Control never deletes them. They live
only in this installation's PostgreSQL. To purge, an operator runs SQL as the
migration (or runtime) role, for example:

```sql
-- Everything older than 180 days.
DELETE FROM shared_session_read_audit WHERE occurred_at < now() - interval '180 days';
-- One workspace.
DELETE FROM shared_session_read_audit WHERE workspace_id = '<workspace uuid>';
```

`DELETE` is allowed; `UPDATE` is not. Schedule the first statement (cron,
`pg_cron`) for a rolling retention window.
