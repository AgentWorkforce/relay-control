# Events shim: a webhook inbox that wakes your agent

The events shim gives an agent a webhook URL. A signed-in person creates an
inbox and gets two URLs:

- an **MCP URL** for the agent: `claude mcp add --transport http webhooks <mcp_url>`
- a **webhook URL** to paste into GitHub, Stripe, Linear or anything that posts

Each post to the webhook URL is stored and forwarded to the agent's own Agent
Relay session webhook (a Relaycast inbound hook). Agent Relay Desktop injects
it into the session, waking it when idle. Without Desktop the agent calls
`wait_for_webhook` in the background, which blocks until a post arrives.

All behaviour (routes, MCP tools, verification, limits, wake text) comes from
the `@agent-relay/events-shim` package. This server provides storage
(Postgres) and mounts the routes. Hosted Agent Relay Cloud serves the same
feature separately.

It is a per-agent inbox, not provider ingestion: it never subscribes to a
provider, syncs provider state or feeds Relayfile. The GitHub, Stripe and
Linear modes only check the sender's HMAC signature over the body of posts a
person points at their own inbox. The bearer mode checks a shared token in the
`Authorization` header and does not sign or verify the body. Provider webhook
ingress stays with relayfile-control.

This is not the `SELFHOST_MCP_EVENTS` setting, which belongs to a different module.

## Turning it on

Add `events_shim` to `SELFHOST_FEATURES` (for example
`SELFHOST_FEATURES=usage,usage_people,events_shim`). While it is off, every
path under `/api/v1/events-shim` (and `/cloud/api/v1/events-shim`) answers
404 `{"error":"Not found"}` before any authentication.

| Variable | Meaning |
|---|---|
| `SELFHOST_FEATURES` | Include `events_shim` to serve the routes |
| `SELFHOST_EVENTS_SHIM_RELAY_ORIGINS` | Optional comma list of https origins a wake link may name. Default: the origin of `RELAYCAST_PUBLIC_URL`. Set it (for example to `https://cast.agentrelay.com`) when your agents' Agent Relay uses another Relaycast |

URLs are built on `SELFHOST_PUBLIC_URL`, so it must be reachable by whatever
posts webhooks and by the agent's MCP client.

## Routes

All under `/api/v1/events-shim` (also `/cloud/api/v1/events-shim`).

| Route | Authority |
|---|---|
| `POST /shims` | A signed-in person (bearer access token, or the session cookie on `/cloud` with a same-origin JSON request). Records the person and workspace; at most 20 per person per hour |
| `GET /shims/current` | `Authorization: Bearer <manage token>`: the feed |
| `POST /shims/current/rotate` | Manage token: replaces the webhook URL; the old one answers 404 at once |
| `PUT /shims/current/secrets/{github,stripe,linear,bearer}` | Manage token: sets (`{"secret": "..."}`) or clears (`null`) a verification secret; `bearer` with no secret generates one, shown once |
| `POST /h/<hook token>[/<mode>]` | The token in the URL. `open` is unverified; the other modes check the sender's signature or bearer against the stored secret |
| `POST /t/<mcp token>/mcp` | The token in the URL. Stateless Streamable HTTP MCP |
| `POST /t/<mcp token>/workspace` | The token in the URL. The inbox's temporary Agent Relay workspace (`workspace_id`, `workspace_key`, `workspace_expires_at`), made on first call; see below |

`POST /shims` answers `{shim_id, mcp_url, webhook_url, webhook_urls, manage_token, limits}`.
The three tokens are shown once; an unknown or expired token answers 404.

MCP tools: `watch_webhooks` (start here), `link_relay_wake`,
`unlink_relay_wake`, `get_webhook_events`, `wait_for_webhook`.

## Waking the agent

Inside an Agent Relay session the agent runs
`agent-relay-probe webhook --socket <relay socket>`, which prints a Relaycast
inbound hook (`https://<relaycast>/v1/hooks/<id>`) and its `wh_live_` secret,
and passes both to `link_relay_wake`. The link is checked with a test post
before it is stored. Only `/v1/hooks/<id>` URLs on an allowed origin are
accepted, so holding an MCP URL cannot make this server post anywhere else.
A wake answered 401, 403, 404 or 410 marks the link broken; posts then wait
for `get_webhook_events` or `wait_for_webhook` until the agent relinks.

## Temporary Agent Relay workspace

`events-shim setup --codex` (and the other CLIs it wakes through an Agent Relay
core) asks `POST /t/<mcp token>/workspace` for a workspace to run its own
headless core on when the machine's Agent Relay is not signed in here. The
first call creates one through Relaycast's internal admin API
(`POST /internal/workspaces`, with `RELAYCAST_INTERNAL_SECRET`) and gives it a
7-day deadline (`POST /internal/workspaces/:id/expiry`), the inbox's own idle
expiry; Relaycast deletes it then. Activity on the inbox (a post, an agent's
MCP call, asking for the workspace) moves the deadline back to 7 days once it is
under 6 days away. A workspace past its deadline is replaced on the next call.
The key is stored encrypted with the keyring.

The response says when it is deleted and that signing the machine's Agent Relay
in to this control plane uses the person's own workspace instead: the inbox
already belongs to a signed-in person, so there is nothing to claim. Without
`RELAYCAST_INTERNAL_SECRET` the route answers `503 not_configured`; a Relaycast
without the expiry route (older than relaycast#660) answers `503` and the
workspace it made is deleted rather than left permanent.

## Limits

Set by the package: 64 KiB per body (larger bodies are refused before they
are read), 60 posts per hour and 500 per day per inbox, the last 50 posts kept,
and an inbox expires after 7 days without a post or MCP call. Duplicate
posts (same `Idempotency-Key`, `X-GitHub-Delivery`, `Linear-Delivery` or
Stripe event id) are stored once and still count toward the limits.

## Storage

Migration 0047 adds `events_shims`, `events_shim_posts` and
`events_shim_events`.

- MCP, webhook and manage tokens are stored as SHA-256 hashes. The webhook
  token is also stored encrypted with `SELFHOST_ENCRYPTION_KEY` so the MCP
  tools can tell the agent its URL; verification secrets and the wake
  `wh_live_` secret are encrypted the same way.
- Post sequence numbers come from `events_shims.next_seq`; appends are
  serialized per inbox, and `(shim_id, idempotency_key)` is unique.
- An inbox belongs to its creator: deleting the person or the workspace
  deletes it. Expired inboxes and feeds idle for a day are pruned when someone
  creates an inbox.
- A post the agent has already read stays `read` when a late wake result
  arrives.

## Recovering stalled wakes

When Relaycast refuses a forward for a while (a 5xx or a timeout), the post
stays pending. Every minute while `events_shim` is on, the server re-drains
inboxes with a working wake link and a pending post older than 30 seconds
(`recoverStalledWakes`), so the idle agent still gets it without a new post.
A permanent refusal (the hook was revoked) marks the link broken instead.
