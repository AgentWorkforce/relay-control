# Claude Code chat identity on Relay (self-host)

Agent Relay Desktop connects Claude Code to the hosted MCP endpoint
(`/api/v1/mcp/shared-sessions`, also `/cloud/...`) with the app's own login
and the `X-Agent-Relay-Desktop: 1` marker. Claude Code caches MCP headers per
connection and one process can change chats (`/resume`, `/clear`), so headers
cannot name the chat. Instead Desktop signs every hosted tool call. This is a
port of Cloud's `lib/mcp/claude-attestation.ts`
(`src/mcp/claude-attestation.ts`); no environment variable is involved.

## Negotiation and key registration

`GET /api/v1/workspaces/{ws}/messaging/desktop-identities?source_id=<uuid>`
advertises `capabilities.claude_session_attestation: 1`, and MCP `initialize`
advertises `capabilities.experimental["com.agentrelay/claude-session-attestation"].version: 1`.
Desktop reports Claude Code **Messaging unavailable** until it sees the flag.
Both are advertised because the endpoint verifies and enforces the proof.

After negotiation, identity sync (`PUT` on the same path) names each
registered Claude Code chat with `native_session: {kind: "claude", id: <session UUID>}`
and sends the installation's Ed25519 key as
`attestation_key: {kid, alg: "Ed25519", public_key: <base64url raw 32 bytes>}`.
`kid` must be base64url (no padding) of the first 16 bytes of SHA-256 over the
raw key; any other `kid` is refused with 400. The key is stored per owner,
workspace and source in `desktop_attestation_keys` (migration 0020, shared
with Copilot): each sync replaces it, a sync without it removes it, and
clearing the source's identities removes it.

## The proof

Desktop's PreToolUse hook adds `_agent_relay_attestation` to the call's
arguments: a compact JWS with header
`{"alg":"EdDSA","kid":<kid>,"typ":"agent-relay-attest+jws"}` and payload
`{"v":1,"kind":"claude","sid":<lowercase chat UUID>,"src":<source_id>,"tuid":<tool use id>,"tool":<MCP tool name>,"iat":<s>,"exp":<s>}`.
Claude Code itself sends the tool-use id as `params._meta["claudecode/toolUseId"]`,
which the model cannot set.

Before any tool runs, the MCP route removes the proof from the arguments
(whether or not it verifies) and, on a desktop-managed call (the app bearer
with `X-Agent-Relay-Desktop: 1`, or a provider credential bound to `claude`),
fails closed unless all of these hold:

- header and payload have exactly these members and values;
- `kid` is the key registered for `src` under the authenticated owner and
  workspace, and the Ed25519 signature verifies;
- `tuid` equals `_meta["claudecode/toolUseId"]` and `tool` equals `params.name`;
- `exp - iat <= 60`, `now <= exp` and `iat <= now + 30 s`;
- `tuid` was not spent before. Spent ids live in `mcp_attestation_tool_uses`
  until two minutes past `exp`.

A failed proof, a batched request carrying a proof, a proof on a credential
bound to another provider, or a proof alongside other native context
(`_meta.threadId`, OpenCode metadata, `X-Agent-Relay-Native-Session-Id`) is
refused with JSON-RPC `-32602 Invalid native chat context.` A verified proof
sets the call's native chat to `{kind: "claude", id: sid}` and requires the
synced identity that resolves it to come from source `src`.

Desktop-managed calls act only as that chat's synced Desktop identity
(Relaycast re-verifies the token on every call) and cannot pick another actor
with `as`, `hosted` or `as_person`. A managed call with no verified chat (no
proof, an unsynced chat, a duplicate mapping) fails closed; it never falls
back to a hosted participant. Outside desktop management a proof is stripped
and ignored.
