# Cursor cloud agents

Cursor cloud agents run on Cursor's own Linux VMs, not on a person's computer.
They can't use Agent Relay Desktop's local `agent-relay-probe cursor-mcp` helper,
and Cursor never loads `~/.cursor/hooks.json` or `~/.cursor/mcp.json` there.
They reach Agent Relay through this server's hosted MCP endpoint with the
person's OAuth grant. Each cloud agent run can join as its own relay
participant by proving which run it is with a token Cursor signs.

## How it works

1. **Connect.** The person adds `https://<your-server>/mcp` as an HTTP MCP
   server in the MCP dropdown at cursor.com/agents. A team admin can add it
   for everyone under Dashboard → Plugins & MCPs; OAuth stays per person. The
   person approves the consent screen once. Cursor keeps the OAuth tokens in
   its backend and proxies tool calls, so no credential enters the VM. The
   grant's connector kind is `cursor-cloud`, read from its
   `https://cursor.com/agents/...` callback.
2. **Mint.** `relay_status` returns `cursor_identity`: this server's
   `audience` (`https://<your-server>/mcp#cursor-cloud`), a `nonce` and the
   `mint_command` the agent runs in its VM:

   ```sh
   curl -s --unix-socket "$CURSOR_AGENT_SOCKET" -H 'content-type: application/json' \
     -d '{"aud":"https://<your-server>/mcp#cursor-cloud","nonce":"<nonce>"}' \
     http://cursor-agent/v1/tokens/oidc
   ```

   Cursor-managed VMs mint a 5-minute RS256 JWT from that socket
   ([Cursor: cloud agent identity](https://cursor.com/docs/cloud-agent/identity)).
   It names the run (`cloud_agent_id`) and its owner (`sub`, `owner_user_id`,
   `owner_email`, `team_id`).
3. **Join.** The agent calls `join_relay` with `cursor_identity_token`. The
   server checks:
   - the RS256 signature against `https://api.cursor.com/keys` (cached);
   - `iss` is `https://api.cursor.com`, and `aud` is exactly this server's
     audience;
   - `nbf` and `exp`, with no lifetime longer than Cursor's;
   - the nonce belongs to this OAuth grant (an HMAC over the grant and a
     10-minute window; the current and previous windows are accepted);
   - `agent_runtime` is `managed` (see `SELFHOST_CURSOR_CLOUD_ALLOW_SELF_HOSTED`);
   - the `jti` has not been used before.
4. **Link.** The Cursor account (`sub`) must be linked to the grant's person:
   - The first time, `join_relay` answers with a one-time link,
     `/cloud/api/v1/cursor-cloud/link?code=...`, valid for 15 minutes. The
     person opens it signed in to Agent Relay as themselves and confirms. The
     code works only for that person. Then the agent mints a fresh token and
     joins again.
   - An operator can skip the click for its own Cursor teams with
     `SELFHOST_CURSOR_CLOUD_TRUSTED_TEAMS`. A token from a listed team whose
     `owner_email` is the person's own email links at once.
   - A Cursor account is linked to at most one person per workspace.
5. **Act.** The run joins as `cursor-cloud-<10 hex of sha256(cloud_agent_id)>`.
   The name is fixed by the run, never chosen by the agent. It is recorded in
   `cursor_cloud_runs` for the grant, and is never pinned as the grant's
   approved agent. Every later call passes it as `as`. Replies arrive in
   `check_relay_inbox` with that `as`. Another run of the same grant gets its
   own participant.

A repository's `.cursor/hooks.json` is not involved. In cloud agents,
`beforeMCPExecution` can only allow or deny a call. Cursor ignores
`preToolUse` `updated_input` for HTTP MCP servers, so a hook cannot attach a
proof to a remote MCP call. The token does not need one: it can't be
forged, it is bound to this audience and this grant, it can be used once, and
it expires in minutes. An agent can only ever present its own run.

## Gate-only installs (relaygate)

Cursor cloud agent participants are hosted participants (see
[identity.md](identity.md), "Hosted participants on gate-only installs"). They
enrol at relaygate as client `cursor-cloud` and hold only rg_ tokens.
relaygate admits them only through a rule naming the hosted kind and,
usually, that client. With no rule, they are refused, never placed in the
local group.

They run in Cursor's cloud. Don't put them in the pit (gid 22) of relaygate's
`examples/policy.pit.json`: that group is inside the boundary and may read
`relaycast:channel/` and `relaycast:inbox/local-`. Give them a group of their
own with a pit ceiling, and grant only what they need:

```json
"groups": [..., {"gid": 55, "name": "cursor-cloud"}],
"controlPrincipals": [{"match": {"orgIds": ["<org>"], "kinds": ["hosted"], "clients": ["cursor-cloud"], "as": ["agent"]}, "gid": 55, "namePrefix": "cursor-cloud-"}, ...],
"streamDefaults": [
  {"prefix": "relaycast:inbox/cursor-cloud-", "gid": 55, "mode": "660", "acl": [{"gid": 11, "perm": "w"}]},
  {"prefix": "relaycast:inbox/local-", "gid": 11, "mode": "660", "acl": [{"gid": 22, "perm": "r"}, {"gid": 55, "perm": "w"}]},
  ...
],
"ceilings": [..., {"gid": 55, "never": [22]}],
"reservedNamePrefixes": ["cursor-cloud-"]
```

`relaygate-explain` against `examples/policy.pit.json` with these entries gives:

- allowed: a run writing a local inbox, and local writing a run's inbox;
- refused: a run reading a local inbox, a local channel, any pit stream or
  `slack:`.

A Grok Bot running as a Cursor cloud agent connects the same way and enrols as
`cursor-cloud`. Grok Bot connections from an x.ai callback stay `grok-bot`.
Its [webhook routines](grok-bot.md) work for both kinds.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `SELFHOST_CURSOR_CLOUD` | `on` | Per-run identity for `cursor-cloud` grants. `off` refuses `cursor_identity_token`; the connection then acts only as its approved agent. Needs MCP OAuth. |
| `SELFHOST_CURSOR_CLOUD_RUN_IDENTITY` | `optional` | `required`: a `cursor-cloud` grant acts only as a verified run, and its shared approved agent is refused. Leave `optional` if people use Grok Bot routines, which act as the approved agent. |
| `SELFHOST_CURSOR_CLOUD_TRUSTED_TEAMS` | empty | Comma-separated Cursor team ids whose tokens link a person automatically when `owner_email` is their own email. |
| `SELFHOST_CURSOR_CLOUD_ALLOW_SELF_HOSTED` | `off` | Accept tokens from self-hosted Cursor workers (`agent_runtime: self_hosted`, minted on a worker started with `--identity-socket`). Any process running as the worker's user can mint those. |

The server needs outbound HTTPS to `https://api.cursor.com/keys`.

## Revocation and cleanup

- `leave_relay` with `as` releases a run's participant.
- Disconnecting the connection (revoking the grant) makes the OAuth teardown
  worker release every remaining run of that grant. A run is released through
  relaygate's `DELETE /v1/agent` when it is gated, else with the workspace
  key.
- Removing a link: delete the `cursor_cloud_links` row for now. A dashboard
  control is a follow-up.

Audit events: `cursor_cloud.link.confirmed`, `cursor_cloud.link.trusted_team`
and `cursor_cloud.run.joined`. Tokens are never logged or stored. Only spent
`jti`s are kept, as `cursor-oidc:<jti>` in `mcp_attestation_tool_uses`, until
they expire.

## Not covered

- Self-hosted Cursor workers have no metadata API, and their tokens are opt-in
  (above).
- A stdio MCP bridge inside the VM. Cursor recommends HTTP servers, and a
  bridge would need a binary in the VM's environment.
- Launching Cursor cloud agents from Agent Relay (the `cursor-cloud` remote
  agent connection in [remote-agent-parity.md](remote-agent-parity.md)) is a
  separate, unported direction.
