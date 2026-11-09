# MCP OAuth connectors

The OAuth module connects public MCP clients to a person's selected
workspace. It is on by default; the database migrations must already be
applied. To turn it off, set `SELFHOST_MCP_OAUTH=off` (`false` and `0` are
accepted too; `on`, `true` and `1` enable it explicitly). Any other spelling
stops start-up, so a typo never silently changes the setting.

OpenID Connect stays optional (see below). A partial or invalid OIDC key set
no longer stops the server: the whole OAuth surface answers
`501 mcp_oauth_unavailable` with reason `oidc_signing_key` until it is fixed
(see [Unavailable mode](#unavailable-mode)).

The existing native MCP endpoint continues to use native credentials.
OAuth connections receive `mcp_at_` access tokens and `mcp_rt_` refresh
tokens. These credentials work only at their granted MCP resource.

## URLs

For a site whose public origin is `https://relay.example.com`:

| Purpose | URL path |
| --- | --- |
| Issuer | `/cloud` |
| Authorization-server metadata | `/cloud/.well-known/oauth-authorization-server` |
| Consent page | `/cloud/oauth/authorize` |
| Registration | `/cloud/api/oauth/register` |
| Consent submission | `/cloud/api/oauth/authorize` |
| Agent-name availability | `/cloud/api/oauth/authorize/agent-name` |
| Token exchange and refresh | `/cloud/api/oauth/token` |
| Token revocation | `/cloud/api/oauth/revoke` |
| List connections | `/cloud/api/v1/oauth/grants` |
| Disconnect one connection | `/cloud/api/v1/oauth/grants/{grantId}` |

The root MCP resource is `https://relay.example.com/mcp`. Its RPC endpoint
also accepts the `/cloud/mcp` alias; that alias does not become a token
audience. The shared-sessions resource is
`https://relay.example.com/cloud/api/v1/mcp/shared-sessions`. A token granted
for one resource is refused at the other.

An unauthenticated MCP POST returns a Bearer challenge with the resource's
metadata URL. Clients should follow that URL rather than construct it.
The standard issuer-discovery alias
`/.well-known/oauth-authorization-server/cloud` is also served.
Shared-resource metadata is also available at
`/.well-known/oauth-protected-resource/cloud/api/v1/mcp/shared-sessions`.
Bare `/api/oauth/*` and `/api/v1/oauth/grants*` routes are not mounted.

## Unavailable mode

When the module is enabled but cannot run, the server still starts and every
OAuth route above (discovery, protected-resource metadata, JWKS, consent,
registration, token, revocation and the connection list) answers:

```http
HTTP/1.1 501 Not Implemented
Cache-Control: no-store
Content-Type: application/json

{"error":"mcp_oauth_unavailable","reason":"oidc_signing_key"}
```

Public routes keep their CORS headers. Other routes are unaffected.

| Reason | Cause | Fix |
| --- | --- | --- |
| `oidc_signing_key` | Some but not all of the OIDC inputs are set, or the key, salt or retained public keys are invalid | Provide all three inputs correctly, or remove them all to run without OIDC |
| `public_url` | `SELFHOST_PUBLIC_URL` is plain HTTP on a non-loopback host, so it cannot be an OAuth issuer | Serve the public origin over HTTPS |

The server logs `[selfhost-api] hosted MCP OAuth unavailable` once at start-up
with the reason and a short detail naming the input, never a configured value. Meanwhile `mcp_at_` bearers are
refused with `401` at the MCP resources, the root `/mcp` resource is not
mounted and the cleanup worker does not run. When the module is turned off
explicitly nothing is logged.

## Consent and credentials

Clients register without a client secret and use authorization code with S256
PKCE. Consent uses a signed-in browser account session, bound to its issued
organization and workspace. Switch the account's workspace before connecting
to a different workspace. Request fields cannot choose another user or
organization. Consent submission and connection deletion require the exact
public Origin.

An omitted scope receives the resource's baseline. A supplied scope that
contains no resource permission is refused with `invalid_scope`. The shared
and root resources require `relay:mcp`. Optional `relay:agents` does not grant
native API, desktop or transcript-history authority.

Access tokens last one hour; refresh tokens last 30 days. Refresh rotates the
pair and preserves its issued scope limit. Retired refresh tokens are always
refused. Verified reuse within 30 seconds leaves the family live to tolerate
racing refresh requests; verified reuse after that window revokes the grant.

Each connection acts only as its approved relay agent. First use pins the
agent's immutable ID. A rename follows that same ID; a replacement holding
its previous name cannot take over the connection. MCP session IDs identify
chats, so multiple chats using the connection share the approved agent.
The connection cannot act as the person or another owned agent.

Transcript history is unavailable through this OAuth credential. Capability
discovery reports that restriction; an authorized native Agent Relay session
is required for transcript reads.

## OpenID Connect

OAuth works without OpenID Connect. To enable optional `openid` grants and
signed ID tokens, provide all three:

```sh
SELFHOST_MCP_OIDC_SIGNING_KEY_ID=site-key-1
SELFHOST_MCP_OIDC_SIGNING_KEY_FILE=/run/secrets/mcp-oidc-private-key
SELFHOST_MCP_OIDC_SUBJECT_SALT_FILE=/run/secrets/mcp-oidc-subject-salt
```

The signing key is an RSA private key in PEM form, at least 2048 bits.
The direct `SELFHOST_MCP_OIDC_SIGNING_KEY` and
`SELFHOST_MCP_OIDC_SUBJECT_SALT` inputs are alternatives to their file
inputs; each direct/file pair is mutually exclusive. Keep the subject salt
stable across restarts.

JWKS is served at `/cloud/.well-known/jwks.json` when OIDC is configured.
For rotation, assign distinct key IDs and provide up to two previous public
keys through `SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS[_FILE]`. The JSON array
contains `kid`, `publicJwk` and ISO `expiresAt` fields. Unexpired retained
keys are served alongside the active public key. Private retained keys and
duplicate key material under different IDs are rejected.

## Disconnect and operating limits

The account's connection list is restricted to its issued workspace.
Disconnect and membership departure revoke local authority transactionally
and queue remote cleanup. Cleanup retries after Relaycast failures, uses
immutable IDs and preserves identities still used by another live connection
or a bound native MCP session.

Workspace deletion returns `409 workspace_in_use` while live connections or
pending cleanup exist. Disconnect them and let cleanup finish before deleting
the workspace or disabling the module. This preserves the workspace credential
needed to retry a failed remote release; teardown does not copy that secret
into the cleanup record.

### Stuck cleanup

Each cleanup attempt claims its record in a short transaction, talks to
Relaycast with no tenant lock held, then commits only if the local state it
decided on is unchanged; otherwise the record stays pending for its next
attempt. Each request to Relaycast has a 10-second abort deadline.

Retryable failures (network errors, timeouts, 5xx, 429, or a 404 while the
agent is still listed) retry after 60 seconds, doubling per attempt up to one
hour. A pass handles at most 20 due records and stops after about 30 seconds,
continuing immediately with the rest. A new disconnect is attempted at once.

Some failures cannot be fixed by retrying: a missing or relocated workspace, a
workspace key that no longer decrypts, or a remote agent whose identity does
not match. These complete the record (`workspace_mismatch`, `decrypt_failed`,
`metadata_mismatch`) without releasing anything and are logged once, so they
no longer block workspace deletion.

If cleanup is still pending and can never finish, the operator can abandon it:

```sh
curl -X POST -H "Authorization: Bearer $SELFHOST_BOOTSTRAP_TOKEN" \
  https://relay.example.com/api/v1/organizations/{organizationId}/workspaces/{workspaceId}/mcp-oauth/abandon-cleanup
```

Only the bootstrap token is accepted. The workspace's pending records complete
as `operator_abandoned` without releasing their Relaycast agents, and the
audit action `mcp_oauth.cleanup_abandoned` is recorded. Live connections are
not touched: disconnect them first, because workspace deletion still answers
`409` while any remains.

Add `?revoke_live=true` when nobody can disconnect them, for example while the
module is `off` or unavailable:

```sh
curl -X POST -H "Authorization: Bearer $SELFHOST_BOOTSTRAP_TOKEN" \
  "https://relay.example.com/api/v1/organizations/{organizationId}/workspaces/{workspaceId}/mcp-oauth/abandon-cleanup?revoke_live=true"
```

In one transaction this revokes every live connection of the workspace (reason
`operator_abandoned`, ending its sessions and expiring unredeemed
authorization codes), then completes all of the workspace's cleanup records,
including the new ones, without releasing any Relaycast agent. The response
is `{"abandoned": n, "revoked": m}` and the audit target records both counts.
The workspace can then be deleted. The route works whether the module is on,
`off` or unavailable.

Turning the module `off` does not revoke connections and does not run
cleanup: grants and their sessions are kept, and pending cleanup records stay
pending while the module is off or unavailable. Turning it back on resumes
cleanup and makes unexpired sessions usable again. To delete a workspace that
still has connections while the module is off, use `revoke_live=true` as
above.

Issuer requests have a 64 KiB body limit. Public registration allows 20
requests per client-address bucket per hour and 500 per process per hour.
Control uses its `SELFHOST_TRUSTED_PROXIES` policy and groups IPv6 addresses
by /64. The default of zero trusted proxies ignores forwarded headers and
uses the socket peer. Standalone module callers without an address resolver
also use the socket peer. Account and consent endpoints do not enable public
credentialed CORS.

Events and its pump have separate default-off settings:
`SELFHOST_MCP_EVENTS` and `SELFHOST_MCP_EVENTS_PUMP`; the pump requires Events.
The Events endpoint is a separate module and is not advertised by this module.

Existing hosted grants are not carried over. Clients must reconnect unless
the operator has a separately reviewed import procedure. Legacy hosted tokens
are not accepted by this issuer or MCP resolver.
