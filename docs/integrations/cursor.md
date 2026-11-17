# Cursor chat identity on Relay (self-host)

Cursor sends no native chat field to MCP servers: a `tools/call` from Cursor
3.30 to a stdio server carries only `_meta.progressToken`. Its
`beforeMCPExecution` hook sees the chat (`conversation_id`, a lowercase UUID,
equal to `session_id`), `generation_id`, a per-call `tool_use_id`, the bare
`tool_name`, `tool_input` as a JSON string, and `mcp_server_name` with
`command` (stdio) or `url` (HTTP), but it can only allow or deny the call.

So Agent Relay Desktop points Cursor's `agent-relay` MCP entry at its own
stdio helper (`agent-relay-probe cursor-mcp`), which adds a signed proof to
each call and forwards it to the hosted MCP endpoint
(`/api/v1/mcp/shared-sessions`, also `/cloud/...`) with a Desktop provider
credential bound to `cursor` (a `cld_at_` bearer from
`/api/v1/workspaces/{ws}/mcp/shared-sessions-tokens`). This is the same
contract as Cloud's (`docs/hosted-mcp-native-session-identity.md` there) and
uses the Claude Code verification path in `src/mcp/claude-attestation.ts`; see
[claude-code.md](claude-code.md) for the shared parts.

## Negotiation and key registration

`GET .../messaging/desktop-identities?source_id=<id>` advertises
`capabilities.cursor_session_attestation: 1`, and MCP `initialize` advertises
`capabilities.experimental["com.agentrelay/cursor-session-attestation"].version: 1`.
Desktop signs Cursor proofs only after it sees the flag. Identity sync then
names each registered Cursor chat with
`native_session: {kind: "cursor", id: <conversation_id>}` (stored lowercase)
and registers the installation's Ed25519 `attestation_key`, the same key as
Claude Code and Copilot proofs.

## The proof

`_agent_relay_attestation` in the call's arguments: a compact JWS with header
`{"alg":"EdDSA","kid":<kid>,"typ":"agent-relay-attest+jws"}` and payload
`{"v":1,"kind":"cursor","sid":<lowercase conversation_id>,"src":<source_id>,"tuid":<Cursor tool_use_id>,"tool":<MCP tool name>,"args":<forwarded arguments>,"iat":<s>,"exp":<s>}`.

It is verified like a Claude Code proof (exact members, registered `kid` for
`src` under the authenticated owner and workspace, Ed25519 signature,
`tool` equals `params.name`, `exp - iat <= 60`, `now <= exp`,
`iat <= now + 30 s`), except:

- `tuid` is the hook's per-call `tool_use_id` (`^[A-Za-z0-9_.:-]{1,256}$`),
  not matched against `_meta`, because Cursor sends none. It is single-use:
  spent as `cursor:["<src>","<tuid>"]` (a JSON pair: self-host source ids may contain `:`) in `mcp_attestation_tool_uses` until two
  minutes past `exp`.
- `args` is required: the forwarded arguments without the proof (Desktop
  signs canonical JSON, sorted keys, no whitespace, at most 32 KB). They must
  equal the call's arguments after the proof is removed (JSON structural
  equality). With `tool`, they are what tie a proof to one call.
- A proof may be up to 96 KiB; requests on a `cursor` credential share the
  128 KiB Copilot body limit.

A proof's `kind` must match the credential's bound provider (`cursor` accepts
only Cursor proofs); on the app bearer with `X-Agent-Relay-Desktop: 1` either
kind is accepted. Failures are refused with JSON-RPC
`-32602 Invalid native chat context.` before any tool runs. A verified proof
sets the native chat to `{kind: "cursor", id: sid}` and requires exactly one
identity synced by `src` with that native session, owned by the same person
and workspace. Relay tools (`join_relay`, `send_relay_message`,
`post_relay_channel`, `check_relay_inbox`, `relay_status`, ...) then act as
that chat's Desktop identity.

A call on a `cursor` credential without a proof is refused for actor tools
with a message naming what is missing: the Cursor integration in Agent Relay
Desktop must run the helper and register the chat.
