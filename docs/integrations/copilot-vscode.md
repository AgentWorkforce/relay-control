# Copilot in VS Code on Relay (self-host)

Select **GitHub Copilot (VS Code)** in Agent Relay Desktop's provider setup.
Copilot keeps its existing GitHub sign-in; no Copilot or model API key is
required or accepted by relaycontrol. Start a new chat with VS Code's
**Copilot** harness and approve the Agent Relay MCP tools through the normal
prompt. The older **Local** harness is not supported for verified messaging.

Desktop owns everything on the computer: the provider secret, the native
hooks, the attestation signing key, and native wake (the stop hook that waits
for an inbound message and resumes the same chat). relaycontrol registers the
provider credential, stores the Desktop identities and verifies each Copilot
tool call. Nothing here is specific to the hosted Cloud deployment, and no
environment variable was added.

## Port status

Ported from the hosted control plane's Copilot Desktop integration.

| Area | Cloud source | Status |
| --- | --- | --- |
| Provider credential routes (GET/POST collection, PUT/DELETE item) | `app/api/v1/workspaces/[workspaceId]/mcp/shared-sessions-tokens/**`, `lib/auth/desktop-provider-credentials.ts` | Ported for provider credentials. Dashboard-minted personal tokens (no-body POST) not ported |
| Verified parent sign-in | Cloud desktop session provenance (migrations 0348/0349) | Ported: `desktop_host_name` and `desktop_verified_at` on `token_sessions`, set only by an approved browser consent redeemed with S256 |
| Child token class `mcp:desktop` + `rth:read`, 15-minute renewable lease | same | Ported. Usable only at the shared-sessions MCP endpoint |
| Desktop identity sync (GET/PUT `messaging/desktop-identities`) | `app/api/v1/workspaces/[workspaceId]/messaging/desktop-identities/route.ts`, `lib/messaging/desktop-identities.ts` | Ported. `linked_mcp`/`linked_at` report a hosted MCP session link; `web_session_id` is accepted and ignored |
| Attestation key registration (`attestation_key`) | same | Ported |
| Copilot tool-call attestation | `lib/mcp/copilot-attestation.ts`, `lib/mcp/claude-attestation.ts` helpers | Ported verbatim in behaviour; the Cloud fixture signed by the Rust Desktop signer verifies here |
| Capability `copilot_session_attestation: 1` and MCP experimental `com.agentrelay/copilot-session-attestation` | same | Ported, advertised because verification exists |
| Managed join/send as the verified Desktop identity | `lib/mcp/relay-participants` desktop path | Ported for provider-bound (child credential) connections |
| 128 KiB Copilot body cap | MCP route | Ported (64 KiB for every other caller) |
| Claude session attestation (`claude_session_attestation`) | `lib/mcp/claude-attestation.ts` | Not ported; not advertised |
| Provider-native capability flags beyond `native_session_identity` | identities route | Not ported; not advertised |
| Codex managed mode via `X-Agent-Relay-Desktop` on a parent connection | MCP route | Not ported; such calls keep the existing hosted participant behaviour |
| Linked MCP connection (`join_relay desktop_address`, `linked_mcp`) | `lib/mcp/relay-service.ts`, `lib/mcp/relay-dependencies.ts`, identities route | Ported (migration 0035, `desktop_relay_session_bindings`); no Claude Code on the web auto-link |
| Native wake / stop-hook delivery | Desktop | Out of scope (Desktop's job) |
| Native history acquisition and upload | RelayHistory / Desktop upload edge | Out of scope here (owned by the history pipeline) |
| Copilot API key / hosted model access | none | Intentionally absent |

## Token contract

All routes are under `/api/v1/workspaces/{workspaceId}/mcp/shared-sessions-tokens`
and also under `/cloud/api/v1/...`. They accept only a header bearer
(`Authorization: Bearer <token>`); the session cookie is never a Desktop
sign-in, on either mount.

The bearer must be a **verified Desktop parent**: a live (access and refresh)
token session with `cli:auth`, in this workspace, that was redeemed with its
S256 verifier from a handoff whose browser consent was approved and named the
Desktop host. Device-flow sessions, sessions issued before migration 0020, a
redeemed handoff without approved consent, the one-time handoff token itself,
cookie sessions and provider child tokens are all refused. The caller must be
a current member of the workspace's organization on every request; removing
the membership deletes the caller's sessions, which deletes every child.

| Method | Path | Body | Success |
| --- | --- | --- | --- |
| GET | `.../shared-sessions-tokens` | none | 200 `{tokens: DesktopMcpCredential[]}`: the parent's own live provider credentials |
| POST | `.../shared-sessions-tokens` | `{provider, installationId, accessToken}`, exactly these keys | 201 `DesktopMcpCredential` |
| PUT | `.../shared-sessions-tokens/{tokenId}` | none | 200 `DesktopMcpCredential` with a fresh lease |
| DELETE | `.../shared-sessions-tokens/{tokenId}` | none | 204 |

- `provider` matches `^[a-z][a-z0-9-]{0,63}$` (Copilot uses `copilot`).
  `installationId` is a UUID (case-insensitive, stored lowercase).
  `accessToken` is the secret Desktop generated and saved before calling:
  `sh_at_` followed by 43 base64url characters (32 random bytes).
- Only `sha256(accessToken)` is stored, as the child session's access hash.
  No response ever contains a secret; POST does not echo `accessToken`.
- `DesktopMcpCredential` is `{id, workspaceId, provider, installationId,
  accessTokenExpiresAt, leaseExpiresAt, createdAt, scopes}`; `scopes` is
  `["rth:read", "mcp:desktop"]`.
- Lease: 15 minutes from issue or renew, never later than the parent's refresh
  expiry. An expired child is refused at MCP until Desktop renews it with PUT.
- Idempotence: a POST with the same parent, `installationId`, `provider` and
  `accessToken` renews and returns the same `id`. The same triple with a
  different secret is 409 `credential_conflict` (DELETE first); that body is
  `{error, message, credential_id}` where `credential_id` is the surviving
  row to pass to `DELETE .../shared-sessions-tokens/:tokenId`, so Desktop can
  recover after losing its local id. A secret already registered anywhere else
  is also 409 `credential_conflict`, without an id.
- Parent refresh rotates the parent's tokens on the same session row, so
  children survive it. Revoking the parent (or its family) revokes every child.
- At most 128 provider credentials per parent (409 `too_many_credentials`).
  30 requests per minute per workspace and user (429 `rate_limited`).
- Item routes act only on the caller's parent's own children; anything else
  is 404 `token_not_found`.
- The child is accepted only by `POST /api/v1/mcp/shared-sessions` (and
  `/cloud/...`), as a header bearer. Every other route rejects it with 401,
  including whoami, workspace resolve, refresh, these token routes and the
  identities routes. Through MCP it reaches History reads only while its
  parent is live.

## Desktop identities

`GET|PUT /api/v1/workspaces/{workspaceId}/messaging/desktop-identities`
(and `/cloud/...`). The caller needs `cli:auth`: a Desktop bearer, or a
`/cloud` session cookie that passes the browser origin check. Provider child
tokens are refused.

- `GET ?source_id=<uuid>` returns `{identities: [{agent_id, linked_mcp,
  linked_at}], capabilities: {native_session_identity: 1,
  copilot_session_attestation: 1}}`. `linked_mcp` is `"agent-relay-sessions"`
  and `linked_at` the ISO time of the newest link when a hosted MCP session
  has linked that identity with `join_relay desktop_address`, else both are
  null. The PUT response reports the same pair per synced identity. No token
  is returned.
- `PUT` body (strict):
  `{source_id, identities: [{name, address, agent_id, token, web_session_id?,
  native_session?: {kind, id}}], attestation_key?: {kid, alg: "Ed25519",
  public_key}}`. `native_session.kind` is one of codex, grok, pi, claude,
  copilot (UUID id) or opencode (`ses_...`). `kid` must equal base64url of
  the first 16 bytes of SHA-256 of the raw 32-byte public key.
- Each identity is kept only after Relaycast confirms the token authenticates
  exactly that agent, and the workspace-key lookup shows
  `metadata.source = "relay-desktop"` and `owner_hash = sha256(userId)` hex.
  Others are reported in `skipped` with reason `unverified` or `not_owned`.
- The sync replaces the source's set: identities not listed are removed, and
  the attestation key is replaced or removed. Agent tokens are stored as
  keyring envelopes (`SELFHOST_ENCRYPTION_KEY`), never in plain text.
- Response: `{synced, skipped?, identities}`.

## Messaging identity and attestation

The provider credential is not permission to pick an arbitrary chat. Copilot's
MCP requests carry no native chat id. Desktop's PreToolUse hook proves the
live chat and adds `_agent_relay_attestation` to the tool arguments with
`modifiedArgs`: a compact JWS (`typ` `agent-relay-attest+jws`, `alg` EdDSA)
over the tool name, exact arguments, user, workspace, Desktop source, native
Copilot session id and a fresh nonce, signed with the source's registered key.

On every `tools/call` relaycontrol:

1. Removes `_agent_relay_attestation` from the arguments before anything else
   sees them, for every caller.
2. On a `copilot` provider connection, verifies the registered key for the
   owner and source, the signature, the exact tool and arguments, user and
   workspace, a lifetime of at most 60 seconds (`exp - iat <= 60`, not yet
   expired, `iat` at most 30 seconds ahead for clock skew), and spends the
   nonce once (`mcp_attestation_tool_uses`).
3. A proof that fails any check, a proof on a non-Copilot connection, or a
   proof inside a batch is refused with JSON-RPC 400 `-32602`
   "Invalid native chat context.". There is no fallback to an unattested call.
4. A Copilot call without a proof gets a tool error saying the chat's desktop
   identity cannot be verified; relay tools are unavailable for it. The MCP
   session id, API key, model name and `as`/address arguments are never proof
   of a chat.
5. With a valid proof, `join_relay` and `send_relay_message` act as the synced
   Desktop identity whose `native_session` is that Copilot chat, re-checked
   with Relaycast on each call. No hosted participant is created, and the
   proof never reaches Relaycast.

Copilot connections may send bodies up to 128 KiB; all other callers keep the
64 KiB cap.

## Errors and paths

REST errors are `{error, message}` with a stable `error` code:
`invalid_request` (400), `unauthorized` (401), `desktop_login_required` (403),
`workspace_access_changed` (403), `forbidden` (403), `csrf_rejected` (403),
`workspace_not_found` (404, also for a parent from another workspace),
`token_not_found` (404), `method_not_allowed` (405, with `Allow`),
`credential_conflict` (409), `too_many_credentials` (409), `rate_limited`
(429), `upstream_unavailable` (502). MCP errors stay JSON-RPC envelopes.

Every route is served at `/api/v1/...` and `/cloud/api/v1/...`. The
`agent_relay_session` cookie is honoured only under `/cloud`, and never on the
provider credential routes.

## Decisions

- Verified parent = an S256-redeemed handoff from an approved consent that
  named the host; everything else is unverified (no relaxation).
- Child credentials are ordinary token sessions with a binding row
  (`desktop_mcp_credentials`), so revocation, refresh-family
  revocation and membership cascades apply without new code paths.
- POST returns 201 also for an idempotent renew.
- The child lease is capped at the parent's refresh expiry.
- Identity capabilities are advertised to every MCP connection, as Cloud does.
  Managed (Desktop identity) mode applies only to provider-bound child
  connections.
- `owner_hash` uses the self-host user id.
- Encryption-key rotation status does not yet count identity ciphertexts.
- Migration `0020_desktop_mcp_credentials.sql` follows main's
  `0018_acquisition_operator_tokens.sql` and `0019_capture_policies.sql`
  (0015-0017 stay reserved by other open branches).

## API compatibility gaps

- Error body: relaycontrol returns `{error: <code>, message}`; Cloud returns
  `{error: <message>}` with no code. Desktop must treat `error` as the code
  and `message` as the text.
- Secret prefix: relaycontrol accepts `sh_at_` + 43; Cloud accepts `cld_at_`
  + 43. Desktop must mint the self-host prefix for a self-host server. There
  is no exchange between the two token classes.
- POST does not echo `accessToken`; Cloud's provider POST returns it.
- No dashboard personal tokens on these routes (no-body POST, dashboard list).
- A parent from another workspace gets 404 `workspace_not_found`, not 403.
- `web_session_id` is ignored: there is no Claude Code on the web auto-link.
- `claude_session_attestation` and other provider-native capability flags are
  not advertised.
- Codex `X-Agent-Relay-Desktop` calls on a parent connection keep the hosted
  participant path instead of Cloud's managed path.

## Release verification

1. Sign Desktop in through the browser consent, connect the Copilot provider
   and confirm `GET .../shared-sessions-tokens` lists one `copilot` credential.
2. Start two Copilot harness chats and confirm each joins as its own identity.
3. From another relay agent, ask a chat to reply with `send_relay_message`;
   verify the reply arrives from that Desktop agent.
4. Remove the member or revoke the Desktop sign-in and confirm the provider
   credential stops working at MCP immediately.

Test proofs: `test/copilot-attestation.test.ts`,
`test/desktop-mcp-credentials.test.ts`,
`test/copilot-desktop-identities.test.ts` (PGlite, in-process Relaycast).
