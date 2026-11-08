# Self-host sessions backend: the RelayHistory read API container

relaycontrol does not store sessions. The dashboard session views, the
`relay_messaging`/shared-sessions MCP reads and `POST
/api/v1/workspaces/{ws}/relayhistory/session` all read through a RelayHistory
service. In a self-hosted install that service is the containerized
**RelayHistory read API**, built and owned by the sessions pipeline maintainers in the
relayhistory-pipeline repo:

- relayhistory-pipeline #317 (head `33f33c4e`): container entry point;
- relayhistory-pipeline #318 (head `1d416c96`): `/v1/cli/login` (scopes = token scopes ∩ {`rth:read`}; none served is `403 forbidden "missing required scope: rth:read"`) and catalog.

Merge SHAs will be recorded here once both land. relaycontrol only consumes
the container; it has no code of its own for storing or indexing sessions.

## relaycontrol configuration

No new environment variables. Point the existing ones at the container:

| Variable | Value |
| --- | --- |
| `RELAYHISTORY_URL` | The container's in-cluster service URL (for example `http://relayhistory-read-api.<ns>.svc.cluster.local:8080`). All logins and reads go here. |
| `RELAYHISTORY_PUBLIC_URL` | The container's `READ_API_ORIGIN`. It is the introspection audience the container sends as `aud`, and the `baseUrl` returned to clients. |
| `RELAYAUTH_URL`, `RELAYAUTH_API_KEY` | Unset. Without them relaycontrol forwards the caller's own `sh_at_` token. |
| `RELAYCONTROL_INTROSPECT_SECRET` | Set, and shared with the container, which calls `POST /internal/v1/auth/introspect` with it. |
| `SELFHOST_INTROSPECT_AUDIENCES` | Only if `READ_API_ORIGIN` differs from `RELAYHISTORY_PUBLIC_URL`; must contain it. `GET /readyz` lists the accepted audiences. |

## Container configuration (owned by the pipeline)

| Variable | Meaning |
| --- | --- |
| `RELAYHISTORY_SELFHOST_READ_API` | `"true"` serves; anything else is dormant. |
| `RELAYHISTORY_READ_API_PORT` | Listen port, default `8080`. |
| `RELAYHISTORY_READ_API_SECRET` | Container secret (pipeline-defined). |
| `READ_API_ORIGIN`, `READ_API_DIRECTORY_WORKSPACES`, introspection settings | The existing read API settings (relayhistory-pipeline #313): the relaycontrol introspection URL and `RELAYCONTROL_INTROSPECT_SECRET`. |

Health and readiness: `GET /healthz` answers `200 {"ok":true,"enabled":true}`
when serving and `200 {"ok":true,"enabled":false}` when dormant. While dormant
every other route answers `503 not_configured`.

## Authentication

There is no separate service credential.

1. relaycontrol checks workspace membership, then POSTs the caller's `sh_at_`
   access token to `/v1/cli/login` as `agentRelayToken`.
2. The container introspects it against relaycontrol (`aud` =
   `READ_API_ORIGIN`) and answers the same token as `accessToken`, expiring at
   `min(exp, now + 15m)`, with `refreshToken` equal to `accessToken`. Scopes
   are the token's scopes intersected with what the backend serves
   (`rth:read`); a token without `rth:read` gets `403 forbidden` ("missing
   required scope: rth:read"), which relaycontrol reports as `502
   relayhistory_session_failed` (stage `exchange`, `upstreamStatus` 403).
3. Every read is a GET with that token as `Bearer` and `workspace=` set to the
   authorized workspace. Organization and workspace come only from the
   verified claims; the response must attest the workspace through
   `X-Relayhistory-Workspace-Id`, as with hosted RelayHistory.

The login step is not strictly required by the container (a GET with a fresh
`sh_at_` bearer is introspected the same way), but relaycontrol keeps it as
the client flow so the RelayAuth and RelayAuth-free paths stay one code path.

**Refresh is unsupported, and relaycontrol never refreshes.** Read tokens are
cached per {user, organization, workspace, caller token} for at most 5
minutes (and never past the upstream expiry minus 60 s). On a 401 the cached
token is dropped and relaycontrol logs in again once; a second 401 is an
upstream error. Clients that receive a session from
`POST .../relayhistory/session` get `refreshToken == accessToken` and must
request a new session instead of refreshing.

## Served views

The container serves the RelayHistory recall contract with the same shapes,
which is exactly what `src/sessions/routes.ts` proxies: `GET /v1/sessions`,
`/v1/sessions/activity`, `/v1/sessions/:id/events`, `/v1/events?session=&q=`,
`/v1/sessions/:id/turns`, `/timing`, `/metadata`, `/catalog`,
`/v1/sessions/titles`, `/v1/delivery/records`.

Not served: `/v1/sessions/output` and `/v1/digest/daily` answer `501
unsupported_by_backend` with a reason. Any first page the backend cannot
answer exactly is also a 501, never an approximation.

How relaycontrol answers each upstream outcome on the dashboard session
routes (`/cloud/api/v1/workspaces/{ws}/sessions...`):

| Upstream | relaycontrol |
| --- | --- |
| 200, workspace attested | 200 with the view |
| 501 (any route) | `501 {"error":"unsupported_by_backend","reason":<upstream reason>,"message":"The configured session backend does not serve this view"}`, `Cache-Control: no-store`. `reason` is the upstream `reason`, else its `error` string, else `unsupported_by_backend`. No attestation is required since no data is returned. The cached token is kept. |
| 404 on catalog (unknown session) | 200 empty catalog `{catalog:null,parents:[],children:[],commitLinks:[],truncated:false}` |
| 404 on timing | 200 `{timing:null}` |
| 404 on output (older hosted builds) | 200 `{output:null,unsupported:true}` |
| 401 | cached token dropped, one re-login and retry |
| 503 (dormant container) or other failures | `502 {"error":"relayhistory_session_failed","stage":"read","upstreamStatus":503}`. No retry, and the cached token is kept. |

The MCP shared-sessions tools report any non-200 read, including a 501, as
their usual "unavailable" tool error.

## Sync sessions

`POST /api/v1/workspaces/{ws}/relayhistory/session` with `mode=sync` (the
default) forwards the same caller token to `/v1/cli/login`. The read
container serves reads only, so its login reply grants `rth:read` even when
the caller's token also carries `rth:sync`. relaycontrol checks the granted
scopes on the RelayAuth-free path:

- `mode=sync` without `rth:sync` in the reply: `501
  {"error":"unsupported_by_backend","reason":"sync_not_served","message":"The
  configured session backend serves reads only; sync sessions are not
  available"}`. No session is returned or cached.
- `mode=read`: 200 as before, with `scopes: ["rth:read"]`.
- A reply without `rth:read` at all: `502 relayhistory_session_failed`
  (stage `exchange`), as for any invalid session.
- A reply with no `scopes` field is trusted as before (compatibility with
  History builds that omit it): the session is returned with `scopes: []`.

The caller must still hold `rth:sync` to ask for sync (403
`mode_not_authorized` otherwise, before anything is forwarded). Desktop
session upload is a separate, pipeline-owned edge and does not go through
this container.

## Open gap (pipeline-owned)

The current container assembly needs ClickHouse for events and search, and
requires TLS to Postgres. A Postgres-only assembly is an open follow-up that the
sessions pipeline maintainers are tracking. Until it lands, a self-host
install that wants transcripts and search must provide ClickHouse and a
TLS-enabled Postgres to the container.


## Connecting the GET-only hosted read Worker

The hosted pipeline read Worker and the self-hosted read container have different
login contracts. The Worker accepts GET only; it cannot answer the container's
`POST /v1/cli/login`. Do not replace `RELAYHISTORY_URL` with the hosted Worker
origin: that would break session issuance and the existing login-based reads.

For an installation that is explicitly using the hosted Worker, set
`RELAYHISTORY_READ_API_URL` to its accepted bare public HTTPS origin. This is an
optional connection, off when unset. It sends only unsearched `/v1/sessions`
and `/v1/sessions/:id/turns` reads directly to that origin using the authenticated
caller's own `sh_at_` access token. The reader must verify that token by
introspecting it against this control plane. No login exchange, RelayAuth
assertion, or service bearer is substituted. Workspace membership is checked
before forwarding; the query always names the caller's authorized workspace;
every successful response still needs the matching workspace attestation.

All other views, search, session issuance and uploads keep the existing
History connection. Selection follows the upstream read path, including calls
through the shared MCP reader: the timing tool's initial unsearched session
list uses the direct reader, while its timing requests and the MCP transcript
and search requests stay on History. This option does not migrate dashboard
metadata, events or search. Self-hosted installations using the read container
can keep the original `RELAYHISTORY_URL` path without this option.

Control configuration:

- `RELAYHISTORY_READ_API_URL`: the accepted Worker origin, without a path.
- `RELAYCONTROL_INTROSPECT_SECRET` (or `_FILE`): the existing internal
  introspection credential, also configured on the Worker. No credential is
  copied into a client response.
- `SELFHOST_INTROSPECT_AUDIENCES`: include the Worker's exact `READ_API_ORIGIN`
  (the same origin as `RELAYHISTORY_READ_API_URL`), retaining the audiences
  required by existing consumers. Startup refuses an absent secret or missing
  audience rather than starting with a broken connection.
- Keep `RELAYHISTORY_URL`, `RELAYHISTORY_PUBLIC_URL` and any existing RelayAuth
  settings for the old session/login paths.

Worker configuration, owned by the pipeline operator:

- `RELAYHISTORY_ACCEPT_RELAYCONTROL_TOKENS=true`.
- `RELAYCONTROL_INTROSPECT_URL`: the accepted reachable control introspection
  endpoint; `RELAYCONTROL_INTROSPECT_SECRET`: the matching credential.
- `READ_API_ORIGIN`: the configured Worker origin above.
- The directory/owner-buffered allowlists, exact-user G2 parity and runtime
  privacy authority remain authoritative. The control connection grants no G2
  or buffered-content authority. Do not widen either allowlist or grant new
  users through this connection alone.

The introspection route is internal. Establish the approved private connection
between the Worker and control; do not expose `/internal` at a public ingress
or remove an existing ingress restriction to make this work.

Before enabling, retain the current configuration for rollback and obtain the
accepted schema/generation, G2, privacy-binding and read-Worker deployment
receipts. Then prove an authorized user's list and turns from that backend and
content denial for a different user/workspace. A passing readiness probe or a
successful unit test is not that live proof. No deployed URL or accepted image
is selected by this document.

A direct read failure never falls back to older History, since that could
bypass a privacy refusal or silently restart pagination. Worker 503 refusals
remain retryable HTTP 503; other failures retain the bounded upstream-error
response without exposing the upstream body. Rollback unsets
`RELAYHISTORY_READ_API_URL` and redeploys control. Ordinary first pages return
to History; outstanding `b96…` cursors fail with 503 instead of restarting.
