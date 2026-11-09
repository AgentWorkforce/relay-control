# MCP OAuth connectors

The optional OAuth module connects public MCP clients to a person's selected
workspace. It is off by default. Set `SELFHOST_MCP_OAUTH=on` to enable it;
the database migrations must already be applied.

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
Bare `/api/oauth/*` and `/api/v1/oauth/grants*` routes are not mounted.

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
or a bound native MCP session. Missing workspace credentials leave cleanup
pending.

Workspace deletion returns `409 workspace_in_use` while live connections or
pending cleanup exist. Disconnect them and let cleanup finish before deleting
the workspace or disabling the module. This preserves the workspace credential
needed to retry a failed remote release; teardown does not copy that secret
into the cleanup record.

Issuer requests have a 64 KiB body limit. Public registration allows 20
requests per TCP peer per hour and 500 per process per hour. Forwarded headers
do not choose the peer identity. Account and consent endpoints do not enable
public credentialed CORS.

Events and its pump have separate default-off settings:
`SELFHOST_MCP_EVENTS` and `SELFHOST_MCP_EVENTS_PUMP`; the pump requires Events.
The Events endpoint is a separate module and is not advertised by this module.

Existing hosted grants are not carried over. Clients must reconnect unless
the operator has a separately reviewed import procedure. Legacy hosted tokens
are not accepted by this issuer or MCP resolver.
