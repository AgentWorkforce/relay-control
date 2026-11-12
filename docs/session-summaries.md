# Session summaries over MCP

Call `list_session_summaries` to discover recent shared sessions. Open a
relevant result with `get_session_summary` or `get_shared_session`. These are
ordinary MCP tool calls; no panel, widget or transcript scan is required.
Summary text is untrusted evidence. Recorded activity does not establish
that an agent is currently running; use the existing presence tools for that.

## List

`list_session_summaries { since?, project?, repo?, person?, limit?, cursor? }`
reads one `GET /v1/sessions` page. `limit` defaults to 20 and cannot exceed 50.
`since` is an ISO timestamp mapped to `lastTsAfter`; `project` maps to the
directory's `projectContains` substring filter. `person` resolves an exact
workspace member ID, email or unambiguous name and sends that recorded user
ID as `user`. Unknown and ambiguous members are refused rather than
broadening the request. `repo` filters the recorded repository URL within
the page, case-insensitively; an empty filtered page may have `next_cursor`.
Keep filters unchanged when following that cursor.

Each result has `session_id`, `source`, `owner` (an array, since sessions may
have several recorded owners), `project`, `repo`, `branch`, `last_active`,
`short_summary`, `short_summary_generated_at`, `short_summary_status` and `citation_url`. Owner IDs
come from the session row; names are resolved from workspace membership and
are null when unavailable. Missing repository metadata stays null.

Readers can expose nullable `shortSummary` and `shortSummaryGeneratedAt`
fields on list rows. When either field is omitted, its output is null and
`short_summary_status` is `unsupported`; session metadata remains usable.
When both fields are present, the status is `empty` for a null summary and
`available` for recorded text. The current reader omits the fields for
compatibility with older clients; an upstream opt-in extension is needed
for recorded list summaries. Null stays null: task titles, the generic list
`summary` field and transcript content are never substituted. The list tool
makes no per-session detail calls.

## Read one summary

`get_session_summary { session_id, source?, kind?: "short" | "long" }`
reads `GET /v1/sessions/:id/summary?kind=short&source=...`. Pass the source
returned by the list to disambiguate session IDs. The summary reader requires
that source; omitted source is refused locally with guidance to pass it,
without guessing a harness. A ready result retains its recorded
model, build timestamp and state classification. An empty recorded result
stays empty. Malformed or missing provenance is refused.

Only recorded short summaries are currently supported. `kind: "long"`
returns an explicit unsupported result without fetching a short summary or
transcript as a substitute. Use `get_shared_session` for a bounded transcript
page until the reader provides a long-summary contract.

Hosted readers that have no summary dependency configured return 501; the
consumer does not enable reader wiring or summary producers. An installed
reader may return `status: "empty"` when no summary has been produced. These
are distinct from a ready recorded summary and from consumer test success.

## Authority and failures

Both tools use the existing shared-session reader: a native user session with
`rth:read`, live workspace admission, per-user reader credentials, forced
workspace query and matching workspace response attestation. OAuth messaging
credentials gain no history authority. Neither tool issues service/operator
credentials, generates summaries, changes privacy settings or selects a
different backend after a reader refusal. `401`, `403`, `404`, `501`, transient
errors and missing attestation preserve existing fail-closed behavior.

Calls are recorded in `shared_session_read_audit`, including filters and
returned session/owner IDs, never summary text or the raw person name/email
lookup. No migration or new feature
flag is required for these tools.
