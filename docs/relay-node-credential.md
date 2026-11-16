# Relay node credential

A relay node host (an `agent-relay-node` machine that runs agents for a
workspace) needs a few Relaycast workspace-level calls: read the workspace,
list and read nodes and agents, and enroll itself as a node. Handing the host
the workspace's Relaycast key (`rk_`) for that is too much: every agent the
node spawns runs under the same user and can read the key, and the key can do
anything in the workspace.

Instead the node holds a **relay-node workspace API token**: an `sh_wk_` token
of purpose `relay-node`, bound to one node name, accepted only by a small
broker in relay-control. The broker calls Relaycast with the stored workspace
key, which never leaves relay-control.

## Token

- Purpose `relay-node`. Scopes are fixed: `relay:workspace:read`,
  `relay:nodes:read`, `relay:nodes:enroll`, `relay:agents:read`.
- `nodeName` is required and follows the node id pattern
  (`[A-Za-z0-9._:-]`, 1-200). The broker only enrolls that name.
- Expires after `expiryDays` (1-365, default 90). It can never be
  non-expiring: `neverExpires`, `aud`, `agent_name`, `scope` and `scopes` are
  a 400.
- Several non-revoked tokens may share one `nodeName`, so rotation does not
  need a gap.
- Accepted **only** under `/relay-node/v1`. Every other route that takes a
  workspace API token (the runtime read contract, `/resolve`, and so on)
  treats it as no credential (401), and token introspection answers
  `active: false, reason: "wrong-kind"`.

### Mint, rotate, revoke

A workspace owner or admin uses the ordinary workspace API token routes with
their own user token (also served at `/cloud/api/v1`):

```
POST /api/v1/workspaces/{id}/deployment-api-tokens
{"label": "node build-01", "purpose": "relay-node", "nodeName": "build-01", "expiryDays": 90}
```

The `sh_wk_` value is in the answer once and is stored only as a SHA-256 hash.
Records in `GET .../deployment-api-tokens` carry `nodeName` (and the same value
in `agent_name`). The admin audit trail records each mint and revoke with the
target `<token id> (relay-node: <nodeName>)`.

To rotate: mint a successor for the same `nodeName`, place it on the node,
restart the node, then `DELETE .../deployment-api-tokens/{oldTokenId}`.
Revocation takes effect on the next broker request.

### Placing it on the node

Treat the token like any other secret:

- Deliver it through the host's secret store (or the operator's provisioning
  system), and have a privileged start step write the node's
  `workspaces.json` readable only by the node's service account.
- Never put it in an environment variable, a command line, or a file that
  spawned agents can read.

The node's workspace entry:

```json
{"key": "sh_wk_...", "base_url": "<relaycast origin>", "control_url": "<relay-control origin>"}
```

## Broker routes

All under `/relay-node/v1`, with `Authorization: Bearer <relay-node token>`.
Not served through the `/cloud` alias.

| Route | Relaycast call | Notes |
| --- | --- | --- |
| `GET /workspace` | `GET /v1/workspace` | Answers only `{"ok": true, "data": {"id", "name"}}` |
| `GET /nodes` | `GET /v1/nodes` | Forwards only the `status`, `limit` and `cursor` query keys |
| `GET /nodes/{name}` | `GET /v1/nodes/{name}` | |
| `POST /nodes` | `POST /v1/nodes` | Body `name` must equal the token's `nodeName`; forwards the body unchanged with `Content-Type`, `Idempotency-Key` and `X-Relaycast-Node-Token` |
| `GET /agents` | `GET /v1/agents` | Same query rule as `GET /nodes` |
| `GET /agents/{name}` | `GET /v1/agents/{name}` | |

Any other path or method is `403 scope_denied`. Request headers and answers
can carry node tokens; relay-control does not log them.

## Errors

Every answer is `Cache-Control: no-store`, and the broker's own errors use Relaycast's
envelope `{"ok": false, "error": {"code", "message"}}`:

| Status | `code` | When |
| --- | --- | --- |
| 401 | `token_invalid` | No bearer, or not a live (unrevoked, unexpired) relay-node token |
| 403 | `scope_denied` | Path or method outside the table above |
| 403 | `node_mismatch` | `POST /nodes` body names another node; nothing is sent to Relaycast |
| 400 | `invalid_request` | `POST /nodes` body is not JSON, or a malformed path segment |
| 413 | `payload_too_large` | Body over 1 MiB |
| 429 | `rate_limited` | Over 600 requests per minute for this token |
| 502 | `relaycast_unavailable` | The workspace has no Relaycast binding; Relaycast is unreachable, times out (10 s), redirects or answers something other than JSON; or Relaycast answers 401 to the stored workspace key |

A Relaycast 401 is never passed through, so a node never mistakes a stale
workspace key on the relay-control side for its own token being rejected. Any
other Relaycast status and JSON body (for example 403 for a suspended
workspace, 404, 409, 429 with `Retry-After`, 5xx) passes through unchanged.

## Gate-only installs

On a gate-only install (`SELFHOST_RELAYGATE_PUBLIC_URL` set, see
[identity.md](identity.md#gate-only-installs-relaygate)) the node host never
holds its Relaycast node token either: relay-control keeps it and bridges the
node's socket. Unset, everything above is unchanged.

### Enrolment

`POST /relay-node/v1/nodes` keeps the same `node_mismatch` rule, but:

- The host's `X-Relaycast-Node-Token` header is ignored. When the node
  enrolled through this relay-control before, relay-control sends the node
  token it holds in that header itself, so Relaycast treats the call as a
  rotation. `Idempotency-Key` is still forwarded.
- On a 2xx answer, relay-control stores the node token sealed under the active
  encryption key (table `relay_node_credentials`, migration 0059, one row per
  workspace and node name, rotated in place with the Relaycast node id and the
  enrolling relay-node token's id) and answers the host
  `{"ok": true, "data": {"id", "name"}}`: the token is never returned.
- A 2xx answer without a string token is `502 relaycast_unavailable` and
  nothing is stored. Any other status passes through as above.

### Node socket

Instead of Relaycast's `/v1/node/ws`, the node connects to:

```
GET /relay-node/v1/ws
Authorization: Bearer <relay-node token>
```

The token is read from the `Authorization` header only, never from the query
string. relay-control opens Relaycast's node socket with the stored node token
and relays frames in both directions (up to 4 MiB each; up to 100 node frames
are held while the Relaycast socket opens). When either side closes, the other
is closed with the same code; codes a peer may not send (1005, 1006, 1015)
become 1011. Node frames pass through unchanged; `node.register` and
`node.heartbeat` also update the row's `last_heartbeat_at` (at most once per
30 s per connection). Frames that are not JSON objects pass through untouched.

Two edits on frames from Relaycast to the node, and no others:

- **Launch credential.** An `action.invoke` whose `action` starts with
  `spawn:` and whose `invocation_id` is a launch journaled by
  `spawn_relay_agent` for this node gains one field,
  `input.launch_credential`: the launch's one-time `sh_lt_` credential
  ([identity.md](identity.md#relay-launch-credentials)). The node reads it
  once, exports it to the launched agent only as `RELAY_LAUNCH_CREDENTIAL`
  for its relaygate registration, and never persists or logs it. Attaching
  does not redeem it; relaygate's introspection does. An invocation that
  matches no launch, or whose credential is expired or redeemed, passes
  through unchanged, and relaygate then refuses that agent's registration.
- **No message delivery.** `deliver` frames are dropped and not acknowledged
  by relay-control: launched agents read their messages through relaygate.

Everything else, including `action.invoke` for `release`, `ping`, `reply` and
`error`, passes through unchanged.

Audit events (actor: service `relay-node:<token id>`):
`relay_node.socket.opened` (target `node=<name>`),
`relay_node.socket.closed` (target `node=<name> code=<n>`) and
`relay_node.launch_credential.attached` (target `node=<name> spawn=<spawn id>`).
Tokens and frames are never logged or audited.

Upgrade refusals are plain HTTP answers with no body:

| Status | When |
| --- | --- |
| 401 | No bearer, or not a live relay-node token |
| 403 | The node has not enrolled through this relay-control, or its stored node token cannot be read with the current encryption keyring (re-enrol) |
| 404 | Not a gate-only install, or any other upgrade path |
| 429 | Over 600 requests per minute for this token (shared with the broker routes) |
| 503 | The bridge is at its connection limit or shutting down |
