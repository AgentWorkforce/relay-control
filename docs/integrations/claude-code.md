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

## Handing the proof off ahead of the call

Claude Code's auto mode refuses any call whose input a hook rewrote, so a hook
that adds `_agent_relay_attestation` (or strips `name` from a `join_relay`)
breaks every hosted call in auto mode. Identity sync therefore also advertises
`capabilities.claude_attestation_handoff: 1`, and Desktop, when it sees it,
hands the same proof over first and sends the call unchanged:

    POST /api/v1/workspaces/{ws}/messaging/desktop-identities/attestations
    {"attestation": "<compact JWS>"}

Auth is the identity sync's (`cli:auth`; cookie requests pass the origin
check, also under `/cloud`). The body has exactly that member. The proof's
format, `kind: "claude"`, lifetime, key and signature are checked as above
(not its tool or tool use: there is no call yet, and nothing is spent), then
it is stored for the authenticated workspace and user under its `tuid` in
`mcp_attestation_handoffs` (migration 0097) until two minutes past `exp`;
expired rows are pruned on later handoffs. Answers: 204 (also for the same
proof again); 400 `invalid_attestation` for a malformed body or proof or
another kind; 403 `attestation_rejected` for an unknown key, a bad signature,
an expired proof or one issued in the future; 409 `conflict` when another
proof is stored for that tool use or a call already spent it; otherwise the
identity sync's 401, 403 and 404. The Desktop sign-in's redirect token is
refused here and at identity sync (403 `handoff_not_exchanged` before its PKCE
exchange, 403 `forbidden` after), as at the MCP route. Neither the proof nor
key material is echoed or logged. Each handoff logs `claude attestation
handoff` with `outcome` (`stored`, `repeat`, `conflict`, `invalid`,
`rejected`) and a fixed `reason`, plus workspace and user ids.

On a single desktop-managed `tools/call` with no proof in its arguments, on
the app bearer with the marker or a credential bound to `claude` (never
`cursor` or `copilot`), the route takes (reads and deletes, in one statement)
the proof handed off for `_meta["claudecode/toolUseId"]` and verifies it
exactly as an in-argument proof, spend included; any failure is the same
`-32602 Invalid native chat context.` With nothing handed off the call has no
verified chat, as a call without a proof always had. A store failure while
taking the proof is logged and treated the same way (the call fails closed,
never a 500); a store failure while verifying a proof, handed off or not,
still fails the request as before. Each take logs `claude attestation
handoff take` with `outcome` `hit`, `miss`, `error` or `verify_failed` (with a
fixed `reason`), never the proof, the tool-use id or key material. An
in-argument proof still works and is checked first.

What a pending handoff proves: it can be consumed by any client that holds
its tool-use id and a desktop-managed credential of the same user in the same
workspace (the app bearer with the Desktop marker, or a `claude` provider
credential). The proof's tool name is still bound to `params.name`, it lives
at most 60 seconds, and it is spent once. Tool-use ids are not secrets: they
appear in Claude Code's transcripts and hook input, so the handoff's security
rests on the signature, the owner's credential and the tool binding, not on
the id being unguessable.

Because Desktop no longer strips them, a desktop-managed `join_relay` may
carry `name` when it is the verified identity's own name (trimmed, any letter
case); `description` is ignored, since the join never changes the card, and
the result then carries a `note` saying it was not applied. Any
other `name`, or a `desktop_address` that is not the identity's, is refused
with "This chat can only use its verified desktop identity."
