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

- `connect_slashy_inbox` `{interval_minutes?: 5-15, default 5}` joins (or
  reuses) the approved hosted participant and returns `{agent, inbox_address,
  set_reminder_arguments: {name, schedule_expression,
  write_enabled: true, reminder_text}, next_steps, note}`. The reminder name is
  `Agent Relay inbox (<agent>)`. `next_steps` keep an identical reminder, and
  replace one with different text, so there is never a second. Idempotent.
- `slashy_inbox_status` `{}` returns `{agent, joined, inbox_address,
  last_seen, looks_active, pending_count, pending_count_is_lower_bound,
  stale_after_seconds: 1800, reminder_name}`. `last_seen` is Relaycast's
  last-seen time for the agent, which each reminder run refreshes by reading
  the inbox (other relay calls refresh it too). `looks_active` means within 30
  minutes. The status read sends no heartbeat and acknowledges nothing.

`src/mcp/slashy.ts` holds the reminder text, mirrored word for word from
Cloud's `packages/web/lib/mcp/slashy-inbox.ts`. `test/fixtures/slashy-reminder.fixture.json`
is a verbatim copy of Cloud's fixture, and both repos assert their output against it.

The reminder replies to a direct message with `send_relay_message` and
`reply_to`, and to a channel post with `post_relay_channel` and the
`reply_hint`'s channel and `thread_id`. It acknowledges with
`acknowledge: [delivery_id]`. A sender that does not pass the gate below gets
only information safe to share publicly, or a reply that the request needs
the owner's approval. It never gets a lookup of the owner's private data. Private details are never posted in a channel, even for the owner: the
reminder posts a public-safe line in the thread ("Sent you the details by DM")
and sends the private answer by `send_relay_message` to the sender's
`sender_address`.

## The owner gate: sender_is_owner

The policy is owner-only: the owner's mail, calendar or accounts are used only
for a message from the owner's own human identity. The owner's agents and
everyone else get only answers that are safe to share. There is no
trusted-agent list, so there is no model-side `sender_id` comparison for a
message body to spoof.

`sender_is_owner` appears on each `check_relay_inbox` message, for a Slashy
connection only. It is computed in `src/mcp/relay-participants.ts`
(`ownedSenders`) and is true only when the message's Relaycast `sender_id` is
the grant user's own `person_identities.agent_remote_id` in this workspace's
relay. Person identities register with Relaycast directly, on gate-only
installs too, so the stored id matches the id deliveries carry. Desktop
identities on gate-only installs hold relaygate ids instead, and the owner's
Desktop sessions, hosted participants and launches are all false. An
unreadable proof is false.

`slashy_inbox_status` creates nothing. It reads the participant the way
`relay_status` does, without a heartbeat (that read still records the grant's
pin to its agent id). There is no relay provisioning to trigger on a
self-hosted server. No MCP Events pump consumes a self-hosted Slashy inbox,
because Grok routines are never mounted for a Slashy grant.

## Classification

A Slashy grant is one whose registration has at least one redirect URI and
**every** redirect URI is an **https** URL whose host is `slashy.com`, a
subdomain of it, or exactly `slashy.ctrlcenter.ai`. A registration that mixes
in any other callback (another host, `http`, localhost) is `mcp`, because the
`slashy` kind turns on owner-data behaviour (`sender_is_owner`). The client
name never decides. The Agent Relay consent screen for a real Slashy
connection (2026-11-27) showed "Returns to slashy.ctrlcenter.ai", Slashy's
original MCP host, so its callback is not under slashy.com. Other
`ctrlcenter.ai` hosts are not Slashy. If Slashy moves its callback elsewhere,
the grant stays `mcp` and the tools do not appear. Read the stored
`mcp_oauth_clients.redirect_uris` for the Slashy client to confirm.

A Slashy grant keeps the generic `mcp` delegation connector kind and relaygate
client kind it had before it was classified. Its agent card kind is `slashy`.
