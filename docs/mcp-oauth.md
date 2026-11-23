# MCP OAuth connectors

The OAuth module connects public MCP clients to a person's selected
workspace. It is on by default; the database migrations must already be
applied. To turn it off, set `SELFHOST_MCP_OAUTH=off` (`false` and `0` are
accepted too; `on`, `true` and `1` enable it explicitly). Any other spelling
stops start-up, so a typo never silently changes the setting.

While on, the server exposes to the internet:

- anonymous dynamic client registration: anyone can register a client (with
  rate limits, see [Disconnect and operating limits](#disconnect-and-operating-limits));
- the root MCP resource `/mcp` for OAuth bearers, next to the native endpoint;
- the consent page, token, refresh and revocation endpoints. Access tokens
  last one hour and refresh tokens 30 days.

Nobody gets a connection without a signed-in account approving it on the
consent page. When the module becomes active the server logs one line,
`[selfhost-api] hosted MCP OAuth active`, naming the authorize, token and
registration paths and the `SELFHOST_MCP_OAUTH=off` switch.

Turning the module `off` hides these routes but does not revoke existing
connections or drain pending cleanup; both are kept and resume when it is
turned on again (see [Stuck cleanup](#stuck-cleanup)).

OpenID Connect stays optional (see below). A partial or invalid OIDC key set
no longer stops the server: the whole OAuth surface answers
`501 mcp_oauth_unavailable` with reason `oidc_signing_key` until it is fixed
(see [Unavailable mode](#unavailable-mode)).

The existing native MCP endpoint continues to use native credentials.
OAuth connections receive `mcp_at_` access tokens and `mcp_rt_` refresh
tokens. These credentials work only at their granted MCP resource.

Cursor cloud agents can also join as their own runs ([cursor-cloud-agents.md](cursor-cloud-agents.md)). Grok Bot connections also support [webhook routine wake-ups](grok-bot.md)
through their existing `relay:mcp` grant. The `grok_routines` tools return a
setup page on this server; no Cloud MCP Events endpoint or Desktop is needed.

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
| `oidc_signing_key` | Some but not all of the OIDC inputs are set, the key, salt or retained public keys are invalid, or one of their `_FILE` paths cannot be read (the log names the variable, never the path) | Provide all three inputs correctly, or remove them all to run without OIDC |
| `public_url` | `SELFHOST_PUBLIC_URL` is plain HTTP on a non-loopback host, so it cannot be an OAuth issuer | Serve the public origin over HTTPS |

The server logs `[selfhost-api] hosted MCP OAuth unavailable` once at start-up
with the reason and a short detail naming the input, never a configured value. Meanwhile `mcp_at_` bearers are
refused with `401` at the MCP resources, the root `/mcp` resource is not
mounted and the cleanup worker does not run. When the module is turned off
explicitly nothing is logged. A value supplied both directly and through its
`_FILE` variable is still a configuration error that stops start-up.

## Consent and credentials

Clients register without a client secret and use authorization code with S256
PKCE. Consent uses a signed-in browser account session, bound to its issued
organization and workspace. Switch the account's workspace before connecting
to a different workspace. Request fields cannot choose another user or
organization. Consent submission and connection deletion require the exact
public Origin.

Client names are self-reported by whoever registered the client. The consent
page heading reads `Connect an app calling itself "<name>"`, and the page
shows where the authorization code goes: `Returns to: <host>` from the
registered redirect URI (`this computer` for loopback), with a caution line
for any other host. Registration refuses names reserved for this product's own
apps (compared ignoring case, spaces, hyphens and underscores, including any
name starting with the product brand) and names over 100 characters, with
`400 invalid_client_metadata`.

The agent name field starts empty unless the client suggested a name; there
is no shared default. A new connection may not take a name held by another
member's agent or by an agent still being released after a disconnect
(`409 agent_name_taken`). A name that belongs to one of the person's own
agents needs explicit confirmation: the page shows "Attach to my existing
agent", which sends `attach_existing: true`; without it the submission answers
`409 agent_name_in_use`. Continuing an existing connection skips this check.
If the name cannot be checked the submission answers `503` and no code is
issued.

An omitted scope receives the resource's baseline. A supplied scope that
contains no resource permission is refused with `invalid_scope`. The shared
and root resources require `relay:mcp`. Optional `relay:agents` does not grant
native API, desktop or transcript-history authority. Optional `relay:history`
is offered only by the shared-sessions resource, is never part of the baseline
and is refused with `invalid_scope` unless `relay:mcp` is requested with it
(see Session reads).

Access tokens last one hour; refresh tokens last 30 days. Refresh rotates the
pair and preserves its issued scope limit. A retired refresh token presented
within 30 seconds of its rotation is refused and the connection stays live, to
tolerate racing refresh requests. After that window, if the exact pair it was
rotated into has never been used as a bearer token, the client is assumed to
have lost the refresh response: the server rotates that unused pair again and
returns the new pair on the same connection and approved agent. Recovery is
available for 36 hours after the token's first rotation and never past the
retired token's own expiry. A re-issued pair keeps the refresh expiry it had;
its access expiry never passes it. A retry within 30 seconds of a recovery is
refused without revoking, like a retry within 30 seconds of the rotation.
Otherwise the retired token counts as reuse
and revokes the grant. Revoking a retired refresh token at the revocation
endpoint ends the grant. Each refresh logs one `mcp_oauth_refresh` line with
`outcome` (`rotated`, `extended`, `reissued_undelivered`, `refused` or
`revoked`), the
grant ID, a reason and the seconds since retirement; it never logs tokens,
hashes, user IDs or agent names.

Google Connected Apps requires a refresh to return the refresh token it was
given. A client whose every registered redirect URI is a Google Connected Apps
callback (`https://oauth-redirect.googleusercontent.com`, or its `-sandbox`
and `-test` hosts, with a single `/r/<id>` or `/a/<id>` path segment and no
query, fragment or userinfo) therefore gets stable refresh instead of
rotation: the refresh response returns the presented refresh token, its
expiry moves to 30 days after that refresh, and the new access token is
issued as a separate session row linked to the code-issued session. Earlier
access tokens stay valid until their own one-hour expiry. A linked row's own
refresh token is never returned and is refused if presented; expired linked
rows are deleted at the next refresh. This is a weaker bearer lifecycle than
rotation: a copied refresh token keeps working until it expires or is
revoked, with no reuse detection or undelivered-response recovery, so it is
limited to that callback set. A client with any other redirect URI keeps
rotation. Revoking the refresh token or the grant ends every access token it
issued. A replayed authorization code that continued an existing connection
revokes only the session that code issued and the access tokens refreshed
from it; continuation detection does not count those refreshed rows.

Upgrading to migration 0084: rotations made before the upgrade are not
recoverable, so their reuse revokes the grant as before. During a rolling
upgrade a server still on the previous version neither records first use nor
writes the successor link.

Upgrading to migration 0085 (`mcp_oauth_sessions.parent_session_id`): apply it
before the new version serves traffic, because new sessions write that
column. During a rolling upgrade a server still on the previous version
rotates the refresh token of a Google callback client as before and counts
its refreshed rows in continuation detection, and its code-replay
revocation of a continuation session leaves that session's linked rows live
until their one-hour expiry. A Google callback connection whose refresh
token a previous version already rotated is not repaired by the upgrade: a
client that kept the earlier token presents a retired token, which follows
the reuse rules above, and the connector must be reconnected once.

Each connection acts only as its approved relay agent. First use pins the
agent's immutable ID. A rename follows that same ID; a replacement holding
its previous name cannot take over the connection. MCP session IDs identify
chats, so multiple chats using the connection share the approved agent.
The connection cannot act as the person or another owned agent.

### Session reads

An OAuth connection reads shared sessions only when the client explicitly
requested `relay:history` on the shared-sessions resource and the person
approved it. The consent page lists it as its own line ("Read this
workspace's shared session history on your behalf"); approving `relay:mcp`
never implies it, and an omitted scope never includes it. The root and
relay-events resources never carry it.

Reads run on the person's behalf through the server-side History reader: a
read session is minted for exactly that person, organization and workspace
with reader kind `mcp`, in both read API modes. The OAuth access token is
never forwarded to History or the session-read route and never gains
`rth:read`. Without the scope every shared-session tool answers "Session reads
need the relay:history scope on this OAuth connection.", and capability
discovery reports `shared_session_reads` as restricted with how to enable it.
Relay messaging on the same connection is unaffected either way.

Admission narrows each request to the scopes of both the session and the live
grant, so revoking the connection, or the grant losing `relay:history`, refuses
further reads. Every read is audited with `auth_mode` `oauth` and the OAuth
client and grant ids. There is no installation switch: the operator control is
OAuth client and grant revocation.

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

A database without migration 0032 makes every pass fail with an undefined
column. The worker then logs `[mcp-oauth] teardown needs migration 0032; apply
pending migrations` once and retries every five minutes instead of every 15
seconds, until a pass succeeds.

Some failures cannot be fixed by retrying: a missing or relocated workspace or
a remote agent whose identity does not match. These complete the record
(`workspace_mismatch`, `metadata_mismatch`) without releasing anything and are
logged once, so they no longer block workspace deletion.

A workspace key that does not decrypt (for example a replica missing a
retired encryption key, or a mis-mounted keyring) is retried with the same
backoff and logs `[mcp-oauth] teardown key unavailable` with the record id and
attempt count on each attempt. After 8 attempts (about four hours) the record
completes as `decrypt_failed` without releasing anything.

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
requests per client-address bucket per hour and 500 per process per hour;
token, refresh and revocation requests of registered clients never count
against it. A registration holds at most 10 redirect URIs of up to 2048
characters each and a `client_name` of up to 100 characters. While the module
is active, the cleanup worker deletes registered clients older than 24 hours
that have no connection and no pending authorization code, up to 500 per pass
and at most every 15 minutes. A client that registered but never connected
within a day registers again.
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
