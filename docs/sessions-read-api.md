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

### `POST /api/v1/workspaces/{ws}/relayhistory/upload-credentials`

Direct-to-S3 session uploads. A bearer client that passes the same caller
checks as `mode: "sync"` above (live `sh_at_` token with `rth:sync`, no
unexchanged handoff, no browser cookie) gets credentials to write session
objects straight into a per-user upload inbox prefix of the pipeline bucket,
plus a signed privacy witness. The ingest edge stays the fallback.

Configuration (all read once at start-up; errors name the variable only):

| Variable | Meaning |
| --- | --- |
| `SELFHOST_HISTORY_UPLOAD_DIRECT` | `off` (default), `allowlist` or `on` |
| `SELFHOST_HISTORY_UPLOAD_ALLOWLIST` | comma-separated user ids; required for `allowlist`, ignored for `on` |
| `SELFHOST_HISTORY_UPLOAD_BUCKET` | pipeline bucket |
| `SELFHOST_HISTORY_UPLOAD_REGION` (or `AWS_REGION`) | bucket and STS region |
| `SELFHOST_HISTORY_UPLOAD_KEY_ROOT` | top-level key root shared with the pipeline (default `96bulls`) |
| `SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT` | optional public S3-compatible endpoint origin upload clients reach (for example a bundled MinIO); unset means AWS S3 |
| `SELFHOST_HISTORY_UPLOAD_INTERNAL_ENDPOINT` | optional endpoint Control reads privacy journals through (an in-cluster service URL); only with `SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT`, defaults to it |
| `SELFHOST_HISTORY_UPLOAD_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` (or `_FILE`) | static keys of the store's dedicated issuer user; required with `SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT`, unset otherwise |
| `SELFHOST_HISTORY_UPLOAD_ROLE_ARN` | upload role Control assumes; AWS only (unset with an endpoint) |
| `SELFHOST_HISTORY_UPLOAD_KMS_KEY_ARN` | KMS key every object must be encrypted with; required on AWS; optional key id with an endpoint |
| `SELFHOST_HISTORY_UPLOAD_WITNESS_KEY` (or `_FILE`) | witness HMAC key: base64url of 32 random bytes, shared with the pipeline consumer (must decode to at least 32 bytes) |
| `SELFHOST_HISTORY_UPLOAD_MAX_OBJECT_BYTES` | per-object cap reported to clients (default 2097152, 1024 to 104857600) |

Request: `{ originId, kind: "sts" | "presigned", keys? }`. `keys` is 1 to 64
`{ key, sha256 }` objects with unique keys, required for `presigned` and
validated but ignored for `sts`. `key` is relative to `keyPrefix`: 1 to 512
characters of `/`-separated segments matching
`^[A-Za-z0-9][A-Za-z0-9._=-]{0,159}$`. Control validates only the segment
rule; the pipeline's layout under the prefix is (informative)
`o=<originId>/b=<sha256hex(batchId)[:32]>/d=<sha256hex(objectBytes)[:32]>-w<witnessSeq>.json.zst`.
`originId` is itself a key segment (`^[A-Za-z0-9._-]{1,128}$`, not
dot-leading). `sha256` is
base64 of the raw 32-byte SHA-256 of the object bytes as uploaded (the zstd
wire bytes).

Both responses lead with `contract: "relay-upload-inbox-v1"` (the sessions
pipeline's frozen upload contract).

- `kind: "sts"`: `{ contract, kind, bucket, region, endpoint, keyPrefix,
  kmsKeyId, credentials: { accessKeyId, secretAccessKey, sessionToken,
  expiresAt }, witness, witnessSeq, maxObjectBytes, refreshAfter }`.
  `endpoint` is always null (`sts` is served on AWS only). The
  session lasts 1 hour (the role chaining cap); `refreshAfter` is 10 minutes
  before expiry.
- `kind: "presigned"`: the same fields (`contract` first) without `credentials`, plus
  `urls: [{ key, url, expiresAt }]`, one presigned PUT per requested key,
  valid for at most 15 minutes; `refreshAfter` is 5 minutes before the URLs
  expire. Each URL signs `Content-Encoding: zstd`, `If-None-Match: *`,
  `x-amz-checksum-sha256: <sha256>`, the witness metadata header and, when
  `kmsKeyId` is non-null, both SSE-KMS headers, so the client must send all
  of them verbatim.

Every PUT carries `If-None-Match: *` and
`x-amz-meta-relay-witness: <witness>`, plus
`x-amz-server-side-encryption: aws:kms` and
`x-amz-server-side-encryption-aws-kms-key-id: <kmsKeyId>` only when
`kmsKeyId` is non-null. Objects over `maxObjectBytes` are refused by the
consumer.

#### S3-compatible stores

With `SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT` set:

- `endpoint` in the response is the endpoint origin, and clients build
  path-style URLs `<endpoint>/<bucket>/<key>` (presigned URLs already are).
- `kmsKeyId` may be null; then no SSE headers are signed and the client must
  not send them.
- `kind: "sts"` answers 501 `unsupported_by_backend`; clients request
  `presigned`.
- URLs (and journal reads) are signed with the dedicated issuer user's keys
  from `SELFHOST_HISTORY_UPLOAD_ACCESS_KEY_ID` /
  `SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY` (or `_FILE`), required with the
  public endpoint. Only the upload issuer uses them, so the process-wide AWS
  credential chain is untouched. The user must be allowed to PUT under `<keyRoot>/.upload-inbox/` and GET
  `<keyRoot>/.admission-inbox/*/privacy-journal.json`. Because one key
  signs every user's URLs, the per-user prefix is enforced by Control
  choosing the signed key, not by a session policy.
- The store must honour `x-amz-checksum-sha256`, conditional
  `If-None-Match: *` PUTs and `x-amz-meta-*` metadata (recent MinIO does).

Key layout: `<keyRoot>/.upload-inbox/<org>/v1/ws=<ws>/u=<userHash>/`,
where `<ws>` is the pipeline's layout component of the workspace id and
`<userHash>` is the pipeline's admission user hash (the first 32 hex of
sha256 of `["admission-user-v1", ws, user]` as JSON), the same hash as the
user's admission inbox directory. STS `SourceIdentity` is `u_<userHash>`; the
raw user id never reaches AWS. `.upload-inbox` is distinct from the
pipeline's `.admission-inbox` (privacy journals) and from the unrelated
non-dotted `upload-inbox/v1` root.

Witness: `witness` is opaque to clients. Control reads the user's privacy
journal (`<keyRoot>/.admission-inbox/<org>/v1/ws=<ws>/m=srv_<userHash>/privacy-journal.json`;
missing means seq 0, unreadable or invalid fails closed with 503) and signs
`{ v: 1, org, ws, user, seq, exp }` as `v1.<payload>.<mac>`: `<payload>` is
unpadded base64url of that JSON (in that key order) and `<mac>` is unpadded
base64url of HMAC-SHA256 under the decoded witness key bytes over
`"relay-upload-witness-v1\n" + <payload>`.
The consumer verifies it before admitting an uploaded object, so an object
uploaded before a privacy change (a higher journal seq) is not admitted
silently. `witnessSeq` is that same seq as a plain field; clients name their
object key with it.

Session policy (inline on AssumeRole, so the credentials can do no more than
this even if the role allows more): `s3:PutObject` and
`s3:AbortMultipartUpload` on `arn:aws:s3:::<bucket>/<keyPrefix>*` only when
`s3:x-amz-server-side-encryption` is `aws:kms`, the KMS key id is the
configured key and `s3:if-none-match` is present (create only); and
`kms:GenerateDataKey` on the key only for that object prefix.

Operator IAM requirements:

- Control's own role needs `sts:AssumeRole` and `sts:SetSourceIdentity` on
  the upload role, and `s3:GetObject` on
  `<keyRoot>/.admission-inbox/*/privacy-journal.json`.
- The upload role trusts Control's role (including `sts:SetSourceIdentity`).
  Because this is role chaining, sessions are capped at 1 hour.

Responses: 404 `history_upload_direct_off` means direct uploads are off for
this caller (the feature is off, or the caller is not allowlisted; the two
are indistinguishable) and the client falls back to the ingest edge.
Authentication and authorization refusals are always 401/403, never 404:
401 `unauthorized`, 403 `forbidden` (browser cookie) and 403
`handoff_not_exchanged`. Also 400 `invalid_request` / `invalid_tenant`, 429
`rate_limited` (12 per user/workspace per minute), 501
`unsupported_by_backend` (`kind: "sts"` against an S3-compatible endpoint;
request `presigned`), and 503
`upload_credentials_unavailable` / `privacy_journal_unavailable` (fall back
to the ingest edge).

Open item: the `s3:if-none-match` session-policy condition must be proven
against AWS before an operator sets `SELFHOST_HISTORY_UPLOAD_DIRECT=on`; run
`allowlist` first.

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
| 501 (any route) | `501 {"error":"unsupported_by_backend","reason":<upstream reason>,"message":"The configured session backend does not serve this view"}`, `Cache-Control: no-store`. `reason` is the upstream top-level `reason`, nested `error.reason`, nested `error.code`, or legacy `error` string, in that order; otherwise `unsupported_by_backend`. Upstream messages are not forwarded. The cached token is kept. |
| 400 on an agent-filter read | A nested `error.code` beginning with `agent_` is preserved as a 400 refusal; its explanatory reason and message are not forwarded. Other 400s remain upstream failures. |
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
