# Slashy inbox on a self-hosted server

Slashy (slashy.com) is an email and calendar AI assistant. Its MCP connection
sends and reads Relay messages as the agent approved at OAuth consent. A
recurring Slashy reminder reads and answers that agent's inbox. This is
messaging, not provider ingestion or a Flow. Hosted Cloud serves the same
tools and prompt (Cloud `docs/mcp/slashy.md`).

## Set up

1. OAuth must be available (`SELFHOST_MCP_OAUTH`, on by default), with a public
   HTTPS URL. No migration and no feature flag.
2. In Slashy: Settings (Cmd+,) > Integrations > Add MCP. URL
   `https://<your-server>/cloud/api/v1/mcp/shared-sessions` (or the root
   `https://<your-server>/mcp` alias when your ingress routes it to Control),
   authentication **Automatic**. Sign in through your server and approve the
   workspace and an agent name for Slashy. Slashy must reach your server.
3. Tell Slashy "connect to Agent Relay". Slashy calls `connect_slashy_inbox`,
   then its own `list_reminders` and `set_reminder` with the returned
   arguments. Nothing more is configured on this server.
4. Send a real Relay message to `inbox_address` and wait one reminder interval.
   `slashy_inbox_status` reports whether the reminder reads the inbox.

## Why a reminder, and not delegate_to_slashy

Slashy has no inbound webhook, so this server cannot push-wake it.

**Do not build a wake on `delegate_to_slashy`.** Slashy's own MCP tool
`delegate_to_slashy` (`{prompt, conversation_id?}`) runs synchronously, and
runs it starts do **not** get the user's added MCP servers, so a delegated
run cannot read or answer the relay inbox. Slashy's Slack bot also takes
instructions only from the account owner.

A recurring reminder does get the user's MCP servers. Slashy's native
`set_reminder` takes `{name, schedule_expression: "rate(5 minutes)",
write_enabled: true, reminder_text, tz}`. At five minutes a relay message was
answered in about 60-75 seconds (measured on hosted Cloud, 2026-11-26). This
server does not poll Slashy and stores no schedule. Each interval costs one
Slashy run, including empty runs that stop immediately.

## Tools

Registered in `slashy_inbox` only for an OAuth grant whose registered callback
classifies as Slashy (`connectorKind` returns `slashy`). Neither tool adds
authority beyond `join_relay`/`relay_status` for the approved agent.

- `connect_slashy_inbox` `{interval_minutes?: 5-60, default 5}` joins (or
  reuses) the approved hosted participant and returns `{agent, inbox_address,
  set_reminder_arguments: {name, schedule_expression, write_enabled: true,
  reminder_text}, next_steps, note}`. The reminder name is
  `Agent Relay inbox (<agent>)`, so a repeated setup keeps the existing
  reminder. Idempotent.
- `slashy_inbox_status` `{}` returns `{agent, joined, inbox_address,
  last_seen, looks_active, pending_count, pending_count_is_lower_bound,
  stale_after_seconds: 900, reminder_name}`. `last_seen` is Relaycast's
  last-seen time for the agent, which each reminder run refreshes by reading
  the inbox (other relay calls refresh it too). `looks_active` means within 15
  minutes. The status read sends no heartbeat and acknowledges nothing.

`src/mcp/slashy.ts` holds the reminder text, mirrored word for word from
Cloud's `packages/web/lib/mcp/slashy-inbox.ts`.

## sender_is_owner

For a Slashy connection only, each `check_relay_inbox` message carries
`sender_is_owner`. It is true only when the message's Relaycast `sender_id`
(stamped from the sending token, unlike the name) is one of the owner's own
rows in this workspace's relay: their person identity, synced Desktop
identities, hosted participants or launched workers (`relay_spawns.worker_id`).
Other people's agents and an unreadable proof are false. The reminder takes
mail, calendar, task, reminder, memory or Slack actions only for such a
message and otherwise answers from read-only lookups or asks the owner.

## Classification (assumption)

A Slashy grant is one with a registered **https** redirect URI whose host is
`slashy.com` or a subdomain. The client name never decides. The exact URI
Slashy registers was not verified against stored registrations: Slashy's web
app starts MCP connections server-side (`POST /integrations/mcp/connect` with
`frontend_url`, completed at `/integrations/mcp/complete`), so the callback is
on a Slashy-owned origin. If it is elsewhere, the grant stays `mcp` and the
tools do not appear. Read the stored `mcp_oauth_clients.redirect_uris` for the
Slashy client to confirm.

A Slashy grant keeps the generic `mcp` delegation connector kind and relaygate
client kind it had before it was classified. Its agent card kind is `slashy`.
