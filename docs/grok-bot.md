# Grok Bot webhook wake-ups on a self-hosted server

Grok Bot can receive Relay wake-ups without Agent Relay Cloud or Desktop.
Its MCP connection sends and reads messages as the agent approved at OAuth
consent. A Grok webhook routine wakes that same bot when its inbox has new
deliveries. This is messaging, not provider ingestion or a Flow.

## Set up

1. Apply migration `0051_grok_bot_routines.sql` before starting this build.
   OAuth must be available (`SELFHOST_MCP_OAUTH`, on by default), with a public
   HTTPS URL and the configured encryption keyring. The old reserved
   `SELFHOST_MCP_EVENTS` / `SELFHOST_MCP_EVENTS_PUMP` switches are not required.
2. Connect Grok Bot to
   `https://<your-server>/cloud/api/v1/mcp/shared-sessions` using its own labeled
   connector account. The root `https://<your-server>/mcp` alias also works when
   your ingress routes it to Control. No new
   consent is needed for an existing `relay:mcp` grant. Sign in through your
   server and approve the bot's name and workspace. Each bot needs its own
   connection. The server recognizes Grok's registered OAuth callback.
3. Call `describe_capabilities`, then `connect_grok_bot_routine` with
   `{"mode":"webhook"}`. This joins/pins the approved Relay identity and returns
   `inbox_address`, `routine_prompt` and a `setup_url` on your server.
4. Create a Grok routine with **When a webhook fires**, using the returned
   prompt. Open `setup_url` in your signed-in browser. Copy the routine's
   **POST to** URL and **Authorization** header from Grok into the page's
   **Webhook URL** and masked **Authorization header** fields. Save.
5. Send a real Relay message to `inbox_address` and confirm it appears in the
   bot's chat. `grok_bot_routine_status` reports `configured`,
   `webhook_accepted`, `last_delivered_at` and `last_error`. Configuration alone
   does not prove delivery. Acceptance means Grok accepted a trigger; it does
   not prove the routine ran or read the message.

The server needs outbound HTTPS access to
`https://api2.cursor.sh/automations/webhook/<routine-id>`. Grok needs access
to your public MCP server. Do not paste routine credentials into chat.

The setup page is `GET /cloud/api/v1/grok-bot/routine?grant=<grant-id>`. It uses
the existing `/cloud/api` ingress to Control on shared dashboard hosts. `POST`
on the same URL takes JSON `{webhook_url, authorization}`; `DELETE` removes
the saved routine. Every method requires the grant owner's browser account
in its issue-time workspace and current membership. Mutations additionally
require the configured public Origin. A grant ID is correlation, not authority.
MCP bearers cannot use this page. Responses are `no-store`; stored credentials
and provider response bodies are never returned.

## Delivery and lifecycle

The server checks up to 20 due connections per pass, normally every five
seconds. It verifies the pinned remote agent's ID, workspace and owner metadata
before reading its pending inbox. One batch wake contains
`{eventId, name:"relay.inbox", agent, pending_count}` with no message text.
The routine reads and acknowledges deliveries through `check_relay_inbox`.
This also handles channel deliveries returned by that inbox; replies stay in
the channel/thread indicated by `reply_hint`.

Accepted delivery IDs are persisted, bounded to the current inbox page of up
to 100 messages. Subsequent scans and restarts do not wake repeatedly for the
same pending page. Once the bot acknowledges it, later pages can advance.
Failures retry with exponential backoff capped at five minutes. The worker
never acknowledges messages. A crash after Grok accepts a trigger but before
the database commits can cause a duplicate; `webhook-id` remains stable for a
retry of the same batch. The routine must deduplicate by `delivery_id`.
Both Relaycast reads (including response bodies) and the Grok POST share a
five-second request budget while the revocation fence is held. Shutdown aborts
those requests immediately. The prompt reads the approved inbox without an
explicit `as` name, so renaming the pinned bot does not break its routine.

Only the exact HTTPS routine endpoint is accepted; alternate hosts, ports,
URL credentials, queries and fragments are refused, and redirects are disabled.
The routine URL and key are encrypted together with the Control keyring.
Delivery holds the user, organization and grant fence, so revocation waits for
an already admitted request to finish and no subsequent wake is admitted.
Revoking a grant deletes its routine credential in the same transaction.
Membership loss, expired/revoked credential families, invalid ownership or a
removed participant prevent delivery. Expired connections are removed on scan.

`disconnect_grok_bot_routine` deletes the stored credential while keeping the
MCP connection for direct messaging. Pause/delete the Grok routine too. Replacing
a routine resets acceptance state and may wake for currently pending messages.

## Differences from hosted Cloud

This build registers `connect_grok_bot_routine`, `disconnect_grok_bot_routine`
and `grok_bot_routine_status` in `grok_routines` for Grok OAuth connections on
the existing messaging endpoints. It does not mount Cloud's MCP Events endpoint.
Use `check_relay_inbox`, not `get_event` or `get_recent_events`. OAuth still
does not grant transcript history or agent launches. No sender-check/reply-mode
app block is supplied: incoming content is untrusted and does not authorize
automatic action or replies. The prompt requires the person's authorization
before replying or acting beyond their existing instructions.

Scheduled polling can be a Grok schedule that calls `check_relay_inbox`; the
self-hosted connect tool accepts only `mode:"webhook"`. Use the
`agent-relay-grok-bot-selfhosted` skill from `AgentWorkforce/skills` for the
customer-facing setup; the hosted plugin's configured MCP URL points to Cloud.
