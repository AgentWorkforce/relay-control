# Self-host sessions backend: the sessions pipeline

relaycontrol does not store sessions. History in a self-hosted install is
served only by the sessions pipeline, owned by the sessions pipeline
maintainers:

- the **read API** container, which issues, rotates, revokes and verifies its
  own read tokens and serves the session views;
- the **session ingest edge** (pipeline `SERVICE=session-ingest`), which
  accepts Desktop session uploads.

One public origin serves both. The dashboard session views, the
`relay_messaging`/shared-sessions MCP reads and `POST
/api/v1/workspaces/{ws}/relayhistory/session` all go through them.

The standalone RelayHistory service and RelayAuth were removed from
self-hosted installs. relaycontrol has no other History dependency and no code
of its own for storing or indexing sessions.

## Native backend

This is the only backend. `RELAYHISTORY_BACKEND` may stay unset or be
`native`; any other value refuses startup with:

```
RELAYHISTORY_BACKEND=<value> is no longer supported: the standalone RelayHistory service and RelayAuth were removed; unset it or set native
```

### relaycontrol configuration

| Variable | Value |
| --- | --- |
| `SESSION_READ_API_URL` | Required. The read API's in-cluster HTTP(S) service URL (for example `http://relayhistory-read-api.<ns>.svc.cluster.local:8080`). The credential handoff and every read go here. |
| `SESSION_READ_API_PUBLIC_URL` | Required. Bare public HTTPS origin: the read API's `READ_API_ORIGIN` and the ingest edge's `RELAYHISTORY_INGEST_ORIGIN`. It is the read token audience, the introspection audience the edge sends as `aud`, and the `baseUrl` returned to clients. |
| `SESSION_READ_API_SECRET` | Required, at least 32 bytes (`_FILE` supported, mutually exclusive). Dedicated Control-to-reader secret for the internal handoff; never sent to clients. |
| `RELAYCONTROL_INTROSPECT_SECRET` | Required, at least 32 bytes (`_FILE` supported). Shared with the ingest edge (and relayfile), which call `POST /internal/v1/auth/introspect` with it. |
| `SELFHOST_INTROSPECT_AUDIENCES` | Optional; defaults to `SESSION_READ_API_PUBLIC_URL`. If set, it must include that origin. `GET /readyz` lists the accepted audiences. |
| `RELAYHISTORY_URL`, `RELAYHISTORY_PUBLIC_URL` | Optional aliases. Leave them unset; if set they must equal `SESSION_READ_API_URL` and `SESSION_READ_API_PUBLIC_URL`. |

Startup fails with an explicit message when any required value is missing,
when the public URL is not a bare origin, when the introspection secret is
absent, or when the audiences do not include the public origin. It also
refuses the removed variables by name when they are non-empty:

| Removed variable | Startup error |
| --- | --- |
| `RELAYAUTH_URL`, `RELAYAUTH_API_KEY`, `RELAYAUTH_API_KEY_FILE` | `<name> is no longer supported: RelayAuth was removed from self-hosted installs; unset it` |
| `RELAYHISTORY_READ_API_URL` | `RELAYHISTORY_READ_API_URL is no longer supported: the read API is configured only through SESSION_READ_API_URL, SESSION_READ_API_PUBLIC_URL and SESSION_READ_API_SECRET; unset it` |

The telemetry and readiness probe for History is
`${SESSION_READ_API_URL}/healthz`.

### Container configuration (owned by the pipeline)

| Variable | Meaning |
| --- | --- |
| `RELAYHISTORY_SELFHOST_READ_API` | `"true"` serves; anything else is dormant. |
| `RELAYHISTORY_READ_API_PORT` | Listen port, default `8080`. |
| `READ_API_ORIGIN` | `SESSION_READ_API_PUBLIC_URL`. |
| Control handoff secret | The value of `SESSION_READ_API_SECRET`. |
| Introspection settings | The relaycontrol base URL and `RELAYCONTROL_INTROSPECT_SECRET` (ingest edge). |

`GET /healthz` answers `200 {"ok":true,"enabled":true}` when serving and
`200 {"ok":true,"enabled":false}` when dormant. While dormant every other
route answers `503 not_configured`.

### Read credentials

Control authenticates the user, refuses unexchanged Desktop handoffs, checks
live workspace membership and `rth:read`, then calls the internal handoff
`POST /internal/v1/session-read/sessions` (or `/sessions/refresh`) with
`Bearer <SESSION_READ_API_SECRET>`. The body is `{ userId, orgId,
workspaceId, audience, scopes: ["rth:read"], label? }`, with `refreshToken`
instead of `label` on refresh. The caller's own token never reaches the read
API. Control validates the reply's identity, audience, read-only scope, token
format (`rth_at_read_`/`rth_rt_read_`) and expiry, and sets `baseUrl` from
configuration. Keep the internal routes off public ingress.

Dashboard reads cache one read token per caller token session (at most 5
minutes, never past the upstream expiry minus 60 s) and renew it on its own
refresh lineage. On a 401 the cached token is dropped and Control requests a
new pair once; a second 401 is an upstream error.

### `POST /api/v1/workspaces/{ws}/relayhistory/session`

- `mode: "read"`: the read API handoff, with the same credentials as
  `POST .../session-read/session`. Bearer clients receive `{ baseUrl,
  sessionId, userId, orgId, workspaceId, audience, scopes: ["rth:read"],
  accessToken, accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt,
  tokenType: "Bearer" }`; browser cookie clients receive it without the
  refresh fields.
- `mode: "sync"` (the default): bearer clients holding `rth:sync` only.
  Control introspects the caller's own `sh_at_` token for the public origin
  and returns it unchanged as `accessToken`, with `{ baseUrl, accessToken,
  accessTokenExpiresAt, refreshToken: "native_ingest_no_refresh",
  refreshTokenExpiresAt, tokenType: "Bearer", scopes: ["rth:sync"], orgId,
  workspaceId }`. The expiry is the token's own expiry, capped at 15 minutes.
  Nothing is minted and no upstream is called. The ingest edge re-introspects
  the token (audience = the public origin) on every upload, so revoking or
  refreshing it cuts uploads off. `refreshToken` is a fixed placeholder: the
  edge answers `POST /v1/auth/token/refresh` with 401 `refresh_not_supported`,
  and Desktop renews through this route.

## Served views

The read API serves the recall contract that `src/sessions/routes.ts`
proxies: `GET /v1/sessions`, `/v1/sessions/activity`,
`/v1/sessions/:id/events`, `/v1/events?session=&q=`, `/v1/sessions/:id/turns`,
`/timing`, `/metadata`, `/catalog`, `/v1/sessions/titles`,
`/v1/delivery/records`. Every read is a GET with the read token as `Bearer`
and `workspace=` set to the authorized workspace; the response must attest the
workspace through `X-Relayhistory-Workspace-Id`.

Views the backend does not serve (for example `/v1/sessions/output` and
`/v1/digest/daily`) answer `501 unsupported_by_backend` with a reason. Any
first page the backend cannot answer exactly is also a 501, never an
approximation.

How relaycontrol answers each upstream outcome on the dashboard session
routes (`/cloud/api/v1/workspaces/{ws}/sessions...`):

| Upstream | relaycontrol |
| --- | --- |
| 200, workspace attested | 200 with the view |
| 501 (any route) | `501 {"error":"unsupported_by_backend","reason":<upstream reason>,"message":"The configured session backend does not serve this view"}`, `Cache-Control: no-store`. `reason` is the upstream `reason`, else its `error` string, else `unsupported_by_backend`. The cached token is kept. |
| 404 on catalog (unknown session) | 200 empty catalog `{catalog:null,parents:[],children:[],commitLinks:[],truncated:false}` |
| 404 on timing | 200 `{timing:null}` |
| 401 | cached token dropped, one new handoff and retry |
| 410 | `410 {"error":"cursor_expired"}`: the client restarts from the first page |
| 503 (dormant or refusing) | `503 {"error":"relayhistory_session_failed","stage":"read","upstreamStatus":503}`, retryable; the cached token is kept |
| other failures | `502 {"error":"relayhistory_session_failed","stage":"read","upstreamStatus":<status>}`; no retry, no upstream body |

Handoff failures report `stage: "exchange"` the same way. Redirects are
refused and never followed. The MCP shared-sessions tools report a 501 as an
unsupported view, a 410 as an explicit restart instruction, and any other
non-200 read as their usual "unavailable" tool error.

`SESSION_READ_API_MCP_READS=true` additionally gives MCP its own per-user read
pair through Control (see the README); without it MCP reads use the same
dashboard path above. Both paths use the read API, so cursors stay valid
whichever one is selected.

## Revocation

Control rechecks the token row on every introspection call, and the ingest
edge introspects per upload without a positive cache. Read tokens are the read
API's own: revoking a caller's Control session stops new handoffs, while an
already issued read token stays valid until its expiry or until the read API
revokes it.

## Open gap (pipeline-owned)

The current container assembly needs ClickHouse for events and search, and
requires TLS to Postgres. A Postgres-only assembly is an open follow-up that
the sessions pipeline maintainers are tracking. Until it lands, a self-host
install that wants transcripts and search must provide ClickHouse and a
TLS-enabled Postgres to the container.
