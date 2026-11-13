# Customer support MCP

`ask_customer_support` is registered on the shared-sessions MCP endpoint and its
`/cloud` alias. Every authenticated workspace member can use it: personal browser
or CLI sessions, verified Desktop MCP leases, and workspace-bound MCP OAuth with
`relay:mcp`. Service credentials, workspace keys and narrowed History tokens do
not become personal support authority. There is no customer allowlist or staff
enrollment requirement.

The input contract matches Cloud: `message` (at most 12,000 characters), a stable
`request_id` (8–64 URL-safe characters), optional 32-hex `conversation_id`, and
optional `mode` (`wait`, `hybrid`, `async`). A new case needs a nonblank message.
Continuation may use an empty message. Waits are 25 seconds, 4 seconds and zero,
respectively. First-call conversation handles use Cloud's `support-case-v1`
hash of organization, workspace, user and request ID, preserving retry and case
identity when those identities are migrated to Control.

The tool returns `reply` with `replies`, `pending` with continuation instructions,
or an explicit refusal/outage status. Pending is not an answer or escalation
receipt. Arguments and responses are never written to shared session History or
the shared-session read audit. A user's own MCP client may retain its transcript.

## Connection and trust

Configure `SELFHOST_CUSTOMER_SUPPORT_URL` as the support service origin and
`SELFHOST_CUSTOMER_SUPPORT_TOKEN` (or `SELFHOST_CUSTOMER_SUPPORT_TOKEN_FILE`) as a dedicated secret of at
least 32 bytes. Both are required together. Remote support service origins must use HTTPS; HTTP
is accepted only for loopback development origins. Without a connection the tool stays
discoverable and reports unavailable; `describe_capabilities` explains the
missing service configuration. No hosted origin is selected implicitly.

On relay-agent, set `SUPPORT_CONTROL_ORIGIN` to Control's `SELFHOST_PUBLIC_URL`
origin and `SUPPORT_CONTROL_TOKEN` to the matching dedicated secret. This trusts
exactly that Control deployment as the identity authority. Do not reuse the
Worker admin, bootstrap, introspection or workspace credential. For multiple
independent Control authorities, use independent support deployments/credentials;
the protocol does not accept a caller-selected issuer or callback URL.

The two HTTP contracts are:

| Direction | Route | Authority |
| --- | --- | --- |
| Control → relay-agent | `POST /api/v1/agents/agent-relay/support/control` | Dedicated service bearer plus exact `controlOrigin` |
| relay-agent → Control | `POST /internal/v1/customer-support/reply-notice` | Dedicated service bearer; current membership and exact synced Desktop ownership |

The first route is under the existing `/api/v1/agents/*` support ingress. It accepts
the following server-generated body (never exposed as tool input):

```json
{
  "controlOrigin": "https://control.example.com",
  "organizationId": "33333333-3333-4333-8333-333333333333",
  "workspaceId": "22222222-2222-4222-8222-222222222222",
  "userId": "11111111-1111-4111-8111-111111111111",
  "conversationId": "0123456789abcdef0123456789abcdef",
  "requestId": "support-message-001",
  "message": "Help me connect Agent Relay",
  "entitlements": ["selfhost"],
  "waitMs": 0,
  "notify": { "desktopAddress": "agent@machine" }
}
```

`waitMs` and `notify` are optional. All other fields are required. Unknown fields
are refused. Control revalidates the exact live credential and workspace
membership before sending and again before releasing an answer. Identity comes
only from that admitted context. No customer token or workspace key is forwarded.
Self-hosting support is available to all current members, matching Cloud's default
open self-host entitlement policy; tool arguments cannot select entitlements.

relay-agent independently resolves any configured customer tenant by the exact
organization/workspace and checks its immutable owner. Otherwise it initializes
`cloud-<lowercase workspace UUID without hyphens>` once. Existing context and
configuration stay in the support service. Legacy enrolled routes are indexed
lazily from service-owned Durable Object configuration, without Cloud DB access.
New staff configurations update that index. Conflicting aliases fail closed.
Disabled and removed configurations are not overwritten by initialization.
Enrollment/removal publishes the immutable workspace binding before releasing its
reservation. Before cutover, replay authenticated support DELETE for revoked aliases
recorded by older builds that deleted their directory names, so their surviving
owner tombstones are indexed too.

HTTP success is the same strict `kind` union as the Cloud RPC: `reply` with up to
100 strings, `pending` with bounded text, or `unauthorized`, `unavailable`,
`rate_limited`, `invalid_request`. HTTP 401/403 means refusal; 429 means rate
limited; other non-success, malformed replies and transport failures mean outage.
Redirects are never followed. Requests and response reads share a 30-second
deadline, and responses are capped at 10.5 MB. HTTP responses are `no-store`.

## Late replies and cutover

Control resolves the caller's verified native Desktop identity or its owned
`join_relay desktop_address` session link. OAuth connections do not choose a
Desktop. Missing or stale links leave normal pending/polling behavior.

For a linked call, relay-agent's existing durable outbox sends a notice directly
to the configured Control origin, with bounded retries. It does not use Cloud's
queue. The notice contains `version: 1`, the three identity UUIDs,
`desktopAddress`, `conversationId`, `revision` and `replyId`; no reply text.
Control verifies membership, current relay binding and Desktop ownership before
DMing the user's own session as that user. A stable Relaycast idempotency key
prevents duplicate DMs. The agent then pulls the answer through the MCP tool,
where authorization is checked again.

Deploy the support HTTP seam before Control, provision the paired server secret,
and preserve organization/workspace/user IDs when migrating identities. Verify
an existing private case and an unenrolled member before switching ingress.
This code does not change production routing, migrate account data, or deploy.

Parity coverage includes actual MCP calls through Control's HTTP client, member
admission, argument rejection, wait modes, retry handles, revocation during a
reply, private audit exclusion, Desktop notice delivery, service authentication,
Worker responses without Cloud, legacy case routing and durable notice retries.
