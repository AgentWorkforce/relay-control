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
| `GET /workspace` | `GET /v1/workspace` | Answers only `{"id", "name"}` |
| `GET /nodes` | `GET /v1/nodes` | Forwards only the `status`, `limit` and `cursor` query keys |
| `GET /nodes/{name}` | `GET /v1/nodes/{name}` | |
| `POST /nodes` | `POST /v1/nodes` | Body `name` must equal the token's `nodeName`; forwards the body unchanged with `Content-Type`, `Idempotency-Key` and `X-Relaycast-Node-Token` |
| `GET /agents` | `GET /v1/agents` | Same query rule as `GET /nodes` |
| `GET /agents/{name}` | `GET /v1/agents/{name}` | |

Any other path or method is `403 scope_denied`. Request headers and answers
can carry node tokens; relay-control does not log them.

## Errors

Every answer is `Cache-Control: no-store`, with a JSON body `{error, message}`
for the broker's own errors:

| Status | `error` | When |
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
