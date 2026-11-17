# Workspace leaders

Workspace leaders are the agents a workspace treats as its coordinators: a list of agent-name patterns, and the
currently registered workspace agents whose name matches one of them. Agent hosts use the setting to identify who
may direct their work.

The setting is stored by the Relaycast engine (`/v1/workspace/leaders`). relay-control stores nothing: it proxies
both routes to the engine with the workspace's server-side Relaycast key, so organization admins can manage the
setting without holding that key. Agent hosts read it from the engine directly and cache it for about a minute,
so a change can take that long to reach every host.

## Routes

`GET /api/v1/workspaces/{workspaceId}/leaders`: any workspace member (bearer, or the session cookie under
`/cloud`). Never 404: an unset setting answers empty lists. `leaders` holds the agents whose names match a pattern,
skipping released agents, one entry per agent id, sorted by name then id.

```json
{
  "leaders": [{ "name": "reviewgrok", "agent_id": "ag_123" }, { "name": "lead", "agent_id": "ag_456" }],
  "patterns": ["*grok", "lead"]
}
```

`PUT /api/v1/workspaces/{workspaceId}/leaders`: workspace owner or admin. Replaces the patterns; `{"patterns": []}`
clears them. Answers the same document as `GET`.

```json
{ "patterns": ["*grok", "lead"] }
```

- Cookie callers must send JSON from an allowed Origin (`403 csrf_rejected` otherwise).
- Audited as `workspace_leaders.set` with the pattern count and the stored patterns.
- Not gated by `SELFHOST_OPERATOR_CONTROLS`: this is a workspace setting, not an operator control.
- Both routes share a per-user rate limit (`429 rate_limited`), since each call spends the workspace key.
- An unreachable or failing engine answers `502 workspace_leaders_unavailable`.

## Pattern rules

Checked by relay-control before the engine is called, and again by the engine (`400 invalid_request`):

- at most 64 patterns;
- each pattern is trimmed and must then be 1 to 128 characters, with no control characters;
- duplicates collapse, keeping the first occurrence's order;
- `*` (any run of characters) and `?` (one character) are the only wildcards; every other character is literal;
- a pattern matches the whole agent name, case-sensitively, so `lead` is an exact name and `Grok*` does not match
  `grokbot`.
