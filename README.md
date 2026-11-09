# Self-hosted sessions control plane

`relay-control` is a standalone Node/Postgres server for headless Agent
Relay session clients. It does not import Next, SST, Cloudflare, or the Cloud
web application, so building and running it cannot change the existing hosted
Cloud deployment.

Included:

- RFC 8628-style device start/approve/token flow
- rotating access/refresh sessions and revocation
- whoami, organizations, workspaces, and organization memberships
- single-organization (default) or multi-tenant installations
  (`SELFHOST_TENANCY=multi`: personal and self-serve organizations,
  operator-assigned auto-join domains, cross-organization workspace switching;
  see [docs/identity.md](docs/identity.md#tenancy))
- Relaycast workspace URL/key resolution
- RelayHistory session issuance, with or without RelayAuth, and internal
  token introspection for History
- Cloud-compatible `/cloud/api` aliases and fixed RelayHistory session reads
- Secure HttpOnly same-origin browser device login at `/login`
- Agent Relay Desktop browser sign-in (`/cli/login` handoff, `/auth/desktop/session`) and fleet node claims
- opaque per-workspace runtime configuration
- liveness/readiness and an OpenAPI contract
- opt-in, aggregate-only telemetry with a "what we send" preview, an
  air-gapped export, and a customer "report an issue" API
  ([docs/telemetry.md](docs/telemetry.md))
- Relayflows: flow definitions, runs, run events/steps/logs/artifacts, and the
  cloud worker assignment protocol used by `agent-relay cloud worker`
- workspace admin: environment variables, provider connections (bring-your-own
  OAuth apps), workspace API tokens, organization rename, and an admin audit
  trail (see [Workspace admin](#workspace-admin))

- hosted MCP at `POST /api/v1/mcp/shared-sessions` (also
  `/cloud/api/v1/mcp/shared-sessions`, the Desktop path) for personal `cli:auth`
  credentials, serving the shared session reads, team activity (Relaycast roster
  and presence plus RelayHistory; no running flows), relay messaging (DMs,
  inbox and channels as a hosted Relaycast participant per MCP session or
  `join_relay` name, kept in `hosted_relay_participants`), and
  capability discovery tool groups. Launches, person-identity sends
  (`as_person`) and desktop-linked identity (`join_relay desktop_address`) are
  not yet available.
- provider catalog at `GET /api/v1/workspaces/:id/providers` (and in
  `describe_capabilities`): Amp, Factory, Copilot, Capy, Replicas, Dot and Grok
  Bot descriptors with separate `implemented`/`configured`/`enabled` runtime
  states (all false until a build injects `providerProbes` into `createApp`).
- Copilot in VS Code through Agent Relay Desktop: provider MCP credentials
  (`/api/v1/workspaces/{ws}/mcp/shared-sessions-tokens`), Desktop identity
  sync (`.../messaging/desktop-identities`) and Ed25519-attested Copilot tool
  calls that act as the chat's own Desktop identity. No environment variables;
  see [docs/integrations/copilot-vscode.md](docs/integrations/copilot-vscode.md)

Explicitly absent: billing, fleet, and Relayfile.

### Relay Chief integration

`createApp` accepts an optional `chief` backend implemented by `relay-chief`.
Workspace-scoped `/cloud/api/v1/workspaces/:id/chiefs` routes preserve the existing
cookie/bearer login and workspace membership checks. Setup and scans require an
owner/admin; cookie mutations require same-origin JSON. Without a backend the
routes return an explicit unavailable response.

For integrated local validation, `scripts/dev-server.ts` accepts a trusted
operator-selected `DEV_CHIEF_MODULE` exporting `createChiefBackend({dataDir})`,
with `DEV_CHIEF_DATA_DIR` pointing to a private state directory. This development
composition is not enabled by production startup and does not provision EC2.
Set `SELFHOST_DASHBOARD_URL` when the local dashboard origin differs from the API.

## Configuration

There are no hosted service defaults. Startup fails until every required value
is explicit. RelayAuth is optional: see
[RelayAuth and RelayHistory](#relayauth-and-relayhistory).

| Variable | Meaning |
| --- | --- |
| `DATABASE_URL` | Least-privilege runtime Postgres connection; server only |
| `DATABASE_MIGRATIONS_URL` | Migration-owner Postgres connection; migrate CLI only |
| `SELFHOST_RUNTIME_DATABASE_ROLE` | Runtime Postgres role granted CRUD on application tables, but not migration metadata or schema creation |
| `SELFHOST_PUBLIC_URL` | Public origin of this API |
| `RELAYCAST_URL` | Internal Relaycast origin for server-to-server traffic |
| `RELAYCAST_PUBLIC_URL` | Public Relaycast origin returned to clients; bare HTTPS public DNS origin |
| `RELAYAUTH_URL` | Optional, set together with `RELAYAUTH_API_KEY`. Internal RelayAuth origin; when set, History sessions use RelayAuth assertions (transitional). Unset: History sessions exchange the caller's own access token |
| `RELAYHISTORY_URL` | Internal RelayHistory origin for session exchange and reads; self-host: the read API container's service URL ([docs/sessions-read-api.md](docs/sessions-read-api.md)) |
| `RELAYHISTORY_BACKEND` | Optional `legacy` (default) or `native`. `native` is the self-host mode without RelayAuth or a standalone RelayHistory: see [sessions-read-api.md](docs/sessions-read-api.md#native-backend-relayhistory_backendnative). |
| `RELAYHISTORY_READ_API_URL` | Optional bare public HTTPS origin of the GET-only pipeline read Worker for unsearched session lists and turns. Unset keeps existing routing. Requires the introspection secret and an explicit matching `SELFHOST_INTROSPECT_AUDIENCES` entry; see [read backend connection](docs/sessions-read-api.md#connecting-the-get-only-hosted-read-worker). |
| `RELAYHISTORY_PUBLIC_URL` | Public RelayHistory origin used as assertion and default introspection audience and returned to clients; bare HTTPS public DNS origin |
| `RELAYAUTH_API_KEY` | Optional, set together with `RELAYAUTH_URL` (`_FILE` supported). Key allowed to mint RelayHistory assertions |
| `RELAYCONTROL_INTROSPECT_SECRET` | Optional, at least 32 bytes (`_FILE` supported). Bearer for `POST /internal/v1/auth/introspect`, shared only with RelayHistory (and relayfile). Unset: that route answers 404 |
| `RELAYFILE_CONTROL_BROKER_SECRET` | Optional, at least 32 bytes, `_FILE` supported. Enables the internal credential routes under `/internal/v1/flows/credentials/` for relayfile-control's Flows service. Unset, they answer 404. |
| `SELFHOST_INTROSPECT_AUDIENCES` | Optional comma-separated http(s) origins a token may be introspected for, default `RELAYHISTORY_PUBLIC_URL`. Matched as normalized origins (scheme, lowercase host, port); `GET /readyz` lists them under `introspection.audiences` |
| `SELFHOST_ACQUISITION_ISSUER_ENABLED` | Optional, default off (`true`/`false`). Turns on the dormant cloud-class acquisition assertion issuer ([docs/acquisition-issuer.md](docs/acquisition-issuer.md)); off, no other issuer variable is read and `/api/v1/acquisition/*` answers 404 |
| `SELFHOST_ACQUISITION_ORIGIN` | Required when the issuer is enabled. The pipeline's `ACQUISITION_ORIGIN`; must also be listed in `SELFHOST_INTROSPECT_AUDIENCES` |
| `SELFHOST_ACQUISITION_ISSUER_KEY_ID` | Required when the issuer is enabled. The `issuerKeyId` published and stamped into every assertion |
| `SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY` | Required when the issuer is enabled (`_FILE` supported). Unencrypted PKCS#8 PEM Ed25519 key |
| `SELFHOST_ACQUISITION_ISSUER_PREVIOUS_PUBLIC_KEYS` | Optional. JSON array of `{issuerKeyId, publicKeyBase64}` still published during a key rotation |
| `SELFHOST_BOOTSTRAP_TOKEN` | At least 32 bytes; initial management bearer |
| `SELFHOST_ENCRYPTION_KEY_ID` | 1-64 URL-safe characters; stamped into each new ciphertext |
| `SELFHOST_ENCRYPTION_KEY` | Exactly 32 bytes encoded as 64 hex chars or base64 |
| `SELFHOST_ENCRYPTION_PREVIOUS_KEY_ID` | Optional prior key ID for decryption during rotation; must be set with the previous key |
| `SELFHOST_ENCRYPTION_PREVIOUS_KEY` | Optional prior 32-byte key for decryption during rotation |
| `SELFHOST_FLOWS_STORAGE` | Optional run object storage: `postgres` (default, bytes inline) or `gcs` |
| `SELFHOST_FLOWS_GCS_BUCKET` | Bucket for `gcs` storage; credentials come from the GKE metadata server (Workload Identity) |
| `SELFHOST_FLOWS_GCS_PREFIX` | Optional object prefix in the bucket, default `relayflows` |
| `SELFHOST_FLOWS_WORKER_RELAYCAST_URL` | Optional Relaycast origin handed to workers; default `RELAYCAST_PUBLIC_URL` |
| `SELFHOST_FLOWS_WORKER_RELAYFILE_URL` | Optional Relayfile origin handed to workers; default empty |
| `SELFHOST_FLOWS_QUEUE_WAIT_MS` | How long queued work waits for a worker before failing, default 600000 |
| `SELFHOST_FLOWS_ENROLLMENT_TTL_MS` | Default enrollment token lifetime, default 3600000 (max 7 days) |
| `SELFHOST_FLOWS_QUEUE_PING_MS` | SSE keepalive cadence, default 20000; keep it below proxy idle timeouts |
| `SELFHOST_INTERNAL_TOKEN` | Optional, at least 32 bytes (`_FILE` supported). Service bearer for `/internal/v1/*` runtime reads across all workspaces. Unset disables that credential (workspace API tokens and flows worker tokens still work). When set, each flows assignment payload also merges the workspace runtime environment from `GET /internal/v1/workspaces/{id}/environment?includeIntegrations=1` |
| `SELFHOST_FLOWS_RUNTIME_ENV_URL` | Origin serving that internal route, default `http://127.0.0.1:$PORT` (this process) |
| `SELFHOST_OAUTH_REDIRECT_URL` | Optional. OAuth redirect URI registered in each provider OAuth app. Default `$SELFHOST_PUBLIC_URL/api/v1/integrations/oauth/callback` |
| `SELFHOST_DASHBOARD_URL` | Optional dashboard origin. Link shown on the OAuth result page (default `$SELFHOST_PUBLIC_URL/`) and, when https, `runUrl` on mirrored flow runs |
| `SELFHOST_BOOTSTRAP_ORG_NAME` / `SELFHOST_BOOTSTRAP_ADMIN_EMAIL` | Optional, set together (or the org name with `SELFHOST_ADMIN_EMAILS`). First-boot bootstrap: creates the organization with this admin as owner and a default workspace bound to a new Relaycast workspace. Idempotent. See [docs/identity.md](docs/identity.md) |
| `SELFHOST_BOOTSTRAP_ADMIN_NAME` / `SELFHOST_BOOTSTRAP_WORKSPACE_NAME` | Optional display name for the admin (default: the email's local part) and the workspace name (default `Default`) |
| `RELAYCAST_INTERNAL_SECRET` | Optional (`_FILE` supported), at least 32 bytes, equal to Relaycast's own internal secret. Lets the bootstrap create the default workspace through Relaycast's `POST /internal/workspaces` |
| `SELFHOST_OIDC_ISSUER` / `SELFHOST_OIDC_CLIENT_ID` / `SELFHOST_OIDC_CLIENT_SECRET[_FILE]` | Optional OpenID Connect sign-in (Google Workspace, Okta, Entra ID, Keycloak...). Authorization code + PKCE. See [docs/identity.md](docs/identity.md) |
| `SELFHOST_OIDC_ALLOWED_DOMAINS` / `SELFHOST_OIDC_DISPLAY_NAME` / `SELFHOST_OIDC_SCOPES` / `SELFHOST_OIDC_REDIRECT_URL` | Optional OIDC refinements: email domains allowed to sign in, button label, scopes (default `openid email profile`), and a fixed redirect URI (default `<site>/login/oidc/callback`) |
| `SELFHOST_SMTP_HOST` / `_PORT` / `_SECURITY` / `_USERNAME` / `_PASSWORD[_FILE]`, `SELFHOST_EMAIL_FROM` | Optional SMTP for invite emails and sign-in links |
| `SELFHOST_EMAIL_LOGIN` | Optional `true`: email sign-in links (requires SMTP) |
| `SELFHOST_SIGNIN_METHODS` | Optional comma list of `email_link` and `password` (both require SMTP). Default: `email_link` when `SELFHOST_EMAIL_LOGIN=true`. Unlisted methods answer 404 `signin_method_disabled`. Failed password sign-ins lock per account and client (5 free, then 30 s doubling to 15 min) and per account across all clients (50 in an hour locks it for 15 min and mails the owner, at most once a day). See [docs/identity.md](docs/identity.md#email-and-password-optional) and [Lockout](docs/identity.md#lockout) |
| `SELFHOST_PASSWORD_PEPPER_FILE` / `SELFHOST_PASSWORD_HIBP` / `SELFHOST_PASSWORD_ARGON2_MEMORY_KIB` / `_TIME_COST` / `_PARALLELISM` | Optional password sign-in settings: a versioned HMAC pepper file (`v<n>:<secret>` lines, owned by the server's user, mode `0600` or `0400`), the Have I Been Pwned check (default `off`), and argon2id parameters, which can only be raised above m=19456 KiB, t=2, p=1 |
| `SELFHOST_TRUSTED_PROXIES` | Number of reverse proxies that append to `X-Forwarded-For` (default `0`: use the TCP peer address and ignore the header). Use `1` only behind a single HTTP proxy that appends to `X-Forwarded-For` (for example the Helm chart's ingress) and only when direct access to the pod or Service that bypasses that proxy is restricted; any other proxy chain needs its actual hop count. Used by every per-IP limit and the password lockout; IPv6 is bucketed by /64. **Required when `SELFHOST_SIGNIN_METHODS` includes `password`: set it explicitly, even to `0`** (unset or empty refuses to start). Use `0` when clients connect directly. See [docs/identity.md](docs/identity.md#client-address) |
| `SELFHOST_LOGIN_LOGO_URL` | Optional https logo URL, published by `GET /api/v1/auth/login-config` |
| `SELFHOST_LOGIN_ORG_NAME` | Optional name shown beside the logo (default `SELFHOST_BOOTSTRAP_ORG_NAME`); published only while a logo is set |
| `SELFHOST_ADMIN_EMAILS` | Optional comma list of admin addresses: the first to sign in with a verified email becomes owner, the rest admins. `SELFHOST_BOOTSTRAP_ADMIN_EMAIL` is an alias that is made owner at first boot |
| `SELFHOST_AUTO_JOIN_DOMAINS` | Optional, single mode only (multi mode refuses to start with it). Email domains whose verified users join as `member` on first sign-in, without an invite. The only authority for auto-join in single mode: absent or empty means none |
| `SELFHOST_TENANCY` | `single` (default): one organization. `multi`: many organizations on one installation; requires `SELFHOST_BOOTSTRAP_ORG_NAME` / `SELFHOST_BOOTSTRAP_ADMIN_EMAIL`. See [docs/identity.md](docs/identity.md#tenancy) |
| `SELFHOST_PERSONAL_ORG_ON_SIGNIN` | Multi mode only, default `true`: a first sign-in with no invite, membership or assigned domain creates a personal organization. The bootstrap bearer can override it at runtime via `PATCH /api/v1/installation/settings` |
| `SELFHOST_SELF_SERVE_ORGANIZATIONS` | Multi mode only, default `true`: signed-in people may create organizations. Overridable the same way |
| `SELFHOST_INVITE_TTL_HOURS` | Invite link lifetime, default 168 (7 days), 1-720 |
| `SELFHOST_FACTORY_ENABLED` | Optional `true`/`false`, default `false`. Factory sessions: when off every Factory route is 404 and the worker does not start. See [docs/factory-sessions.md](docs/factory-sessions.md) |
| `SELFHOST_FACTORY_API_URL` | Factory API origin, default `https://api.factory.ai`; absolute https only |
| `SELFHOST_FACTORY_HISTORY_INTERVAL_MS` | Dormant Factory history loop cadence, default 300000, minimum 60000 |
| `SELFHOST_OPERATOR_CONTROLS` | Operator-control writes (capture policy PUT/DELETE, session hard delete): `always` (default), `licence`, or `off`; an unrecognised value is treated as `off`. Reads are never gated. See [docs/capture-policy.md](docs/capture-policy.md) and [docs/session-erasure.md](docs/session-erasure.md) |
| `SESSION_ERASE_API_URL`, `SESSION_ERASE_API_SECRET` (or `_FILE`) | Internal origin and dedicated secret (at least 32 bytes) of the session pipeline's per-session erase. Unset, the session hard-delete routes answer 501. See [docs/session-erasure.md](docs/session-erasure.md) |
| `SELFHOST_DESKTOP_FEED_SIGNER` / `SELFHOST_DESKTOP_FEED_STORAGE` | Optional, set together: turn on the signed Desktop release feed (`/api/v1/desktop/feed/*`). Signer `awskms` (or `memory`, tests and development only), storage `s3` (or `memory`). Unset: the feed routes answer 404. See [docs/desktop-feed.md](docs/desktop-feed.md) |
| `SELFHOST_DESKTOP_FEED_KMS_REGION` / `SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES` | `awskms`: region (default `AWS_REGION`) and a JSON object of profile id to KMS alias, one Ed25519 key per profile. Credentials: the instance role via IMDSv2, or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` |
| `SELFHOST_DESKTOP_FEED_KEY_LABEL` | The `key_id` label, default `k1` for `awskms` |
| `SELFHOST_DESKTOP_FEED_S3_BUCKET` / `_S3_REGION` / `_S3_PREFIX` | `s3`: private bucket without dots, its region (default `AWS_REGION`, then the KMS region) and key prefix (default `desktop-feed`) |
| `SELFHOST_DESKTOP_FEED_PUBLISHER_TOKEN_HASHES` | Optional JSON object of profile id to token sha256 hex digests, for publisher tokens (`sh_dfp_...`) provisioned through env; tokens can also be minted through the admin routes |
| `SELFHOST_TELEMETRY_LEVEL` | Telemetry: `off` (default when unset), `errors`, or `full`. See [docs/telemetry.md](docs/telemetry.md) for this and the other `SELFHOST_TELEMETRY_*` settings |
| `PORT` | Listener port, default `3000` |
| `SELFHOST_AMP_ENABLED` | Optional `true` turns on Amp control (default `false`). Off: every Amp route answers 404 `{"error":"Not found"}` before authentication and no outbox worker runs. See [docs/amp.md](docs/amp.md) |
| `SELFHOST_MCP_OAUTH` | Optional, default on. Hosted MCP OAuth connectors; `off`, `false` or `0` disables them (`on`/`true`/`1` enables; other spellings fail start-up). A missing or partial signing-key set, invalid key material or an unreadable MCP OIDC `_FILE` leaves the server running (routes answer 501 `mcp_oauth_unavailable`); a value supplied both directly and via `_FILE` still fails start-up. See [docs/mcp-oauth.md](docs/mcp-oauth.md) |
| `SELFHOST_MCP_EVENTS` | Optional, default off (`on`/`true`/`1` or `off`/`false`/`0`). Setting for the separate MCP Events module, which this server does not mount. See [docs/mcp-oauth.md](docs/mcp-oauth.md) |
| `SELFHOST_MCP_EVENTS_PUMP` | Optional, default off, same spellings. Events pump setting; `on` requires `SELFHOST_MCP_EVENTS=on` or start-up fails |
| `AMP_TRANSPORT_ORIGIN` / `AMP_TRANSPORT_TOKEN[_FILE]` | Optional, set together. Bare https origin of the persistent Amp process service and its bearer (at least 32 bytes); calls go to `POST /v1/internal/amp/operation`. Unset: every Amp operation answers 503 `amp_transport_not_configured` |
| `SELFHOST_AMP_INTERNAL_SECRET` | Optional (`_FILE` supported), at least 32 bytes. Bearer for `POST /api/v1/internal/amp/job` (scheduler sweeps and inject jobs). Unset: that route answers 404 |
| `SELFHOST_AMP_WORKER_INTERVAL_MS` / `SELFHOST_AMP_LEASE_MS` | Outbox drain interval, default 5000 (250-600000), and delivery lease, default 120000 (1000-3600000). An expired lease becomes `unknown` and is never resent |
| `HOST` | Listener address, default `0.0.0.0` |

**Upgrade note (client address).** Per-IP limits and the password lockout now use the TCP peer address unless `SELFHOST_TRUSTED_PROXIES` is set. Deployments behind a proxy must set `SELFHOST_TRUSTED_PROXIES` to the number of proxy hops that append to `X-Forwarded-For` (`1` only for a single such proxy, such as the Helm chart's ingress, with direct pod or Service access restricted); otherwise every client shares the proxy's bucket, and the server logs one warning when it sees `X-Forwarded-For` with `0` trusted hops (per-IP limits, including the password IP lockout, use the socket address). With password sign-in enabled the variable must now be set explicitly, even to `0`, or the server refuses to start; `1` is correct for a Helm install only when the chart's ingress is the single proxy and direct access to the pod or Service that bypasses it is restricted. `X-Real-IP` is no longer read.

Sensitive variables also accept a mutually exclusive `_FILE` form. The API
server reads `DATABASE_URL_FILE`; `agent-relay-selfhost-migrate` reads only
`DATABASE_MIGRATIONS_URL_FILE`. It never falls back to the runtime credential,
and the server never reads the migration credential.
The migrate command rejects a runtime role that is the connected migration
owner, and never grants that role access to `control_schema_migrations`.

The two public service origins are intentionally separate from their internal
counterparts. They must be bare HTTPS origins on multi-label public DNS hosts;
IP literals, single-label names, credentials, paths, query strings, fragments,
and special-use names such as `localhost`, `.local`, `.internal`, and
`.example` are rejected. RelayAuth and RelayHistory fetches use the internal
URLs. Workspace resolution returns `RELAYCAST_PUBLIC_URL`; RelayHistory
assertions (when RelayAuth is set) use `RELAYHISTORY_PUBLIC_URL` as
`historyOrigin`/`aud`, and issued sessions return it as `baseUrl`.

### RelayAuth and RelayHistory

The independent session read API has its own credential handoff:

- `POST /api/v1/workspaces/{workspace}/session-read/session`, body `{ label? }`.
- `POST /api/v1/workspaces/{workspace}/session-read/refresh`, body `{ refreshToken }`.

Both also accept the `/cloud` prefix. Enable them with all three settings:
`SESSION_READ_API_URL` (internal HTTP(S) origin), `SESSION_READ_API_PUBLIC_URL`
(bare public HTTPS origin), and `SESSION_READ_API_SECRET` or its mutually
exclusive `_FILE` form (at least 32 bytes). Leave all unset to keep this
handoff disabled. Use a dedicated Control-to-reader secret; it is never sent
to clients. These settings do not change the existing History connection.

`SESSION_SEARCH_AGENT_TOKENS=true` (default false) reads `@name` tokens in API and MCP search text as agent filters. Enable it once the session backend's agent catalog is ready; until then those tokens stay ordinary search text. The explicit `agent` parameter does not need this setting and answers 501 `agent_filter_not_ready` until the backend is ready.

`SESSION_READ_API_MCP_READS=true` (default false) sends MCP session reads to that read API. MCP obtains and refreshes the calling user's pair through Control, validates its user/organization/workspace, audience and `rth:read` scope, and uses the returned reader URL. Only `rth_at_read_` access tokens reach read routes; the MCP reader client has no internal issuer or service credential. Once the reader is selected, no response or failure switches the request to History, including an unsupported first page (501). Unsupported views remain unavailable on that backend. A refused refresh requires reauthentication; an unavailable refresh retains the pair for a same-reader retry. History is used only when selected before the request, such as an explicitly legacy view or when the feature is off. Cursor continuations never switch backends.

Control authenticates the user, refuses unexchanged Desktop handoffs, checks
live workspace membership and `rth:read` on every issue and refresh, and
requests credentials from the read API. The read API issues, stores, rotates,
revokes and verifies its own opaque tokens. Control neither creates nor
persists reader tokens. Caller-supplied tenant, audience, scope and URL fields
are rejected. The response's identity, audience, read-only scope, token format
and expiry are validated before credentials are returned with `Cache-Control:
no-store`. Each user/workspace may request credentials 30 times per minute.

Bearer-authenticated clients receive `{ baseUrl, sessionId, userId, orgId,
workspaceId, audience, scopes: ["rth:read"], accessToken,
accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt, tokenType: "Bearer" }`.
Refresh requires both a current Control access token and the reader refresh
token. The reader binds and atomically rotates that token for the authorized
identity. A rejected refresh requires sign-in again; an unavailable reader
fails closed without falling back to older History or returning upstream bodies.

Browser cookie clients call `/cloud/.../session` with JSON and the dashboard
or API `Origin`. They receive only the access credential; both refresh fields
are omitted. After expiry they request a new session through Control, checking
membership again. Cookie requests to `/refresh` are refused. No refresh token
custody or reader token storage is added to Control.

The internal reader contract is `POST /internal/v1/session-read/sessions` or
`/internal/v1/session-read/sessions/refresh`, authenticated by the dedicated
secret. Control supplies `{ userId, orgId, workspaceId, audience, scopes:
["rth:read"], label? }`, with `refreshToken` instead of `label` on refresh.
The reader returns the bearer response above without `baseUrl`; Control sets
that from configuration. Keep these internal routes off public ingress.

`POST /api/v1/relayhistory/session` (and the `/cloud` alias) works in two
modes, chosen by whether `RELAYAUTH_URL`/`RELAYAUTH_API_KEY` are set. Setting
only one of them fails startup.

- **Without RelayAuth (recommended).** relaycontrol posts the caller's own
  `sh_at_` access token (bearer or `/cloud` session cookie) to the internal
  History `/v1/cli/login`. History verifies it by calling
  `POST /internal/v1/auth/introspect` with `RELAYCONTROL_INTROSPECT_SECRET`,
  its own public origin as `aud`, and the workspace. `workspace` is optional:
  absent or null, the answer's `workspace` (the token session's only
  workspace) is authoritative; present, it must be a non-empty string equal
  to the session's workspace (an empty string or another type is a 400).
  relaycontrol answers
  from the token session row on every call (no cache): active with the user,
  organization, workspace, scopes, `iat`/`exp` and a `token_id` that changes
  on every refresh, or inactive with one reason in this order: `wrong-kind`,
  `unknown`, `revoked`, `expired`, `audience`, `workspace`. History may also
  send `machine`, the caller's claimed machine (a Relaycast node id, as
  claimed through `POST /api/v1/fleet/nodes/claim`; malformed is a 400).
  Only after the token checks pass, relaycontrol answers active with
  `machine_id` set to it when the token's user claimed that node in the
  token's workspace, else inactive with `machine_not_owned` (another user's
  claim in this workspace), `machine_workspace_mismatch` (claimed only in
  another workspace) or `machine_unclaimed`. Without `machine`,
  `machine_id` is null and History refuses writes. History takes the machine
  id only from this answer. History decides
  the granted scopes from that answer, so `mode` is enforced only by
  relaycontrol (sync requires `rth:sync`); a read request may get a session
  that also carries sync scopes. The response shape is unchanged.
  Revoking or refreshing the access token makes History's next
  introspection fail.
- **With RelayAuth (transitional).** relaycontrol mints an origin-bound
  RelayAuth assertion and exchanges it at History, as before; the caller's
  token never reaches History.

`GET /api/v1/workspaces/{workspace}/relayhistory/origin` (and the `/cloud`
alias) answers `{ workspace, origin, audience }` for a caller authorized like
the session route: `origin` and `audience` are both `RELAYHISTORY_PUBLIC_URL`,
the value sessions are bound to. It is read-only and throttle-independent:
nothing is issued, History is not called, and it shares no state with session
issue/renew, so Agent Relay Desktop uses it for site-push admission and
cold-process delete/revoke lookups. It accepts the user sessions the session
route accepts (device session, exchanged Desktop handoff, `/cloud` browser
cookie) except an unexchanged Desktop sign-in handoff, which answers 403
`handoff_not_exchanged`; service, bootstrap, workspace API, revoked and
expired tokens answer 401. A workspace in the token's own organization that
the caller is a member of, but the token is not bound to, answers 403
`forbidden`; any workspace outside the token's organization (even one the same
person belongs to) or unknown answers 404 `workspace_not_found`; an install
without RelayHistory 404 `relayhistory_not_configured`.

Fixed session reads under `/cloud/api/sessions` cache a History token per
user, workspace and caller token session, so a refreshed or revoked caller
token never reuses another session's History token.

In a self-hosted install `RELAYHISTORY_URL` points at the RelayHistory read
API container owned by the sessions pipeline (`RELAYHISTORY_PUBLIC_URL` is
its `READ_API_ORIGIN`). It serves reads only: views it does not serve answer
501 `unsupported_by_backend`, and sync sessions answer 501 `sync_not_served`.
See [docs/sessions-read-api.md](docs/sessions-read-api.md).

## Run

From the repository:

```sh
npm run build
npm run migrate
npm run start
```

Published images are available at `ghcr.io/agentworkforce/relay-control`
(pin a release tag or, better, an `image@sha256:...` digest). To build the
production image yourself, use the repository root as context:

```sh
docker build -t agent-relay-selfhost-api .
```

Repository maintainers can publish a multi-architecture GHCR release with the
manual **Release relay-control image** workflow. Dispatch it from `main` with a
unique lowercase release tag, the exact selected commit SHA, and the
`publish-relay-control` confirmation. The publishing job uses the protected
`selfhost-api-release` GitHub Environment; repository administrators must
configure its required reviewers before the first release.

The workflow publishes `linux/amd64` and `linux/arm64` manifests to
`ghcr.io/<repository-owner>/relay-control`. It refuses to overwrite the release
tag or its `sha-<commit>` tag, and reports the resulting digest in the run
summary. The legacy `selfhost-api` image name is deprecated and receives no new
releases. Deploy by the `image@sha256:...` reference when
immutability matters. BuildKit SBOM and max-mode provenance attestations are
attached where GHCR supports them. The workflow only publishes this standalone
image; it does not invoke or modify the hosted Cloud deployment.

### Verifying image provenance

Each release also carries a signed Sigstore provenance bundle (GitHub artifact
attestation) for the published index digest. Verify it with
the GitHub CLI, using the digest from the run summary:

```sh
gh attestation verify oci://ghcr.io/agentworkforce/relay-control@sha256:<digest> --owner AgentWorkforce
```

Images published before signed attestations were added, including `0.4.0`
(`sha256:f57b2da3fae1615790aeffbb01bad0b85fa30ee5c239bd892d9322bf1ff84dce`),
have no signed attestation; they carry only the unsigned BuildKit SBOM and
provenance statements, so `gh attestation verify` fails for them.

The image runs as an unprivileged user. In production, run
`agent-relay-selfhost-migrate` as a one-shot job with only
`DATABASE_MIGRATIONS_URL_FILE`, then run the server with only
`DATABASE_URL_FILE`.

## Bootstrap

Set `SELFHOST_BOOTSTRAP_ORG_NAME`, `SELFHOST_BOOTSTRAP_ADMIN_EMAIL` and
`RELAYCAST_INTERNAL_SECRET`, and configure a sign-in method (OIDC or email
links): on first start the API creates the organization, its owner and a
`Default` workspace bound to a fresh Relaycast workspace, and the admin signs
in at `/login`. Teammates are invited from the dashboard (Settings > Members).
[docs/identity.md](docs/identity.md) covers sign-in, invites and roles.

The manual path below remains available as the operator break-glass.

Create the first tenant with the bootstrap bearer:

```sh
curl -X POST "$SELFHOST_PUBLIC_URL/api/v1/organizations" \
  -H "Authorization: Bearer $SELFHOST_BOOTSTRAP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme","ownerEmail":"owner@acme.example","ownerName":"Owner"}'
```

Then create a workspace under the returned organization ID. A Relaycast key is
required and encrypted before storage:

```sh
curl -X POST "$SELFHOST_PUBLIC_URL/api/v1/organizations/$ORG_ID/workspaces" \
  -H "Authorization: Bearer $SELFHOST_BOOTSTRAP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Default","relaycastApiKey":"rk_live_..."}'
```

The bootstrap bearer can approve the first device code by supplying the
returned owner and workspace IDs. After that, user access tokens can approve
additional devices for their own identity.

### Approving a device (Agent Relay Desktop, CLI)

`POST /api/v1/auth/device/start` returns
`verification_uri = $SELFHOST_PUBLIC_URL/cloud/api/v1/auth/device/approve` (under
`/cloud/api` so it reaches this service on a shared dashboard origin too). Opening
it redirects (303) to the dashboard approval route
`$SELFHOST_DASHBOARD_URL#/device?user_code=...`. A signed-out person goes through
`/login?next=...` and returns there. The dashboard looks the code up (`action:
"lookup"`: client name, Desktop host name, target workspace), and the person
approves or denies it with their session cookie. Cookie decisions must be JSON
from the dashboard or API origin (CSRF check); the session's workspace is the
target.

The token endpoint returns `api_url: <site>/cloud` and refresh returns `apiUrl`
with the same value, matching hosted Cloud. Agent Relay Desktop refuses any other
value, and requires `verification_uri` to be on its site. `<site>` is the
configured origin the request arrived on: `SELFHOST_DASHBOARD_URL`'s origin when
the request's Host is the dashboard host (which also serves `/cloud/api`),
otherwise `SELFHOST_PUBLIC_URL`. A Host that matches neither falls back to
`SELFHOST_PUBLIC_URL`; it is never echoed. So a Desktop built for either origin
signs in. The same rule applies to `verification_uri`, the browser handoff's
`api_url` and the desktop session's `apiUrl`.

Rate limits match hosted Cloud and are per process: device start 10 per 5 minutes
and token polling 120 per minute per client address (the TCP peer, or the
`X-Forwarded-For` entry chosen by `SELFHOST_TRUSTED_PROXIES`), and approval 30 per 5 minutes per signed-in user. Desktop's PKCE proof
fields are accepted but not enforced (self-host has no Desktop-authority grant).

See `openapi.yaml` (also served at `/openapi.yaml`) for the exact contract.

### Browser sign-in (Agent Relay Desktop welcome screen)

Desktop's GUI signs in with hosted Cloud's browser flow, not the device flow:
it opens `$SELFHOST_PUBLIC_URL/cloud/api/v1/cli/login?redirect_uri=http://127.0.0.1:<port>/callback/<state>&state=<state>&client=desktop&workspace_selection=desktop&code_challenge=<S256>&code_challenge_method=S256[&desktop_host_name=<host>]`
(or hosted's `/cloud/api/auth/google/start` and `/cloud/api/auth/microsoft/start`
with `next=/api/v1/cli/login?...`, which here just land on `/login` with the
inner parameters kept). A signed-out browser goes through `/login` and
returns. With a session cookie the API issues a 15-minute handoff access
token bound to the challenge and redirects to the loopback `redirect_uri`
with `state`, `access_token`, `access_token_expires_at` and
`api_url=<site>/cloud` (see above); no refresh token is placed in the URL.
When the sign-in names its host, a same-origin consent page asks the person
to approve "Agent Relay Desktop on <host>" first (single-use consent token,
Origin and Fetch Metadata checked). Desktop then redeems the handoff once at
`POST /cloud/api/v1/auth/desktop/session` with `codeVerifier`, receiving a
renewable access/refresh pair in the same token family. Rate limits match
hosted: 30 per minute per client address on both routes.

Self-host has no Desktop-authority grant: approving a named host records
nothing beyond the session itself. A session is bound to one workspace, so a
`workspace` parameter naming another is refused (403).

### Fleet node claims

`POST /api/v1/fleet/nodes/claim` with `{workspaceId, nodeToken}` records a
Relaycast node as the caller's computer, as hosted does for Desktop's spawn
node: the token is proven with Relaycast's `/v1/node/me` and the workspace
key's read of that node, then stored only as the owner record. A node owned by
someone else, through another workspace, or through a previous relay binding
is refused (409). `DELETE` with `{workspaceId, nodeId}` releases it (owner or
organization owner). Revoking a membership drops its node ownerships.

### Resolving a workspace's Relaycast key

`GET /api/v1/workspaces/{workspaceId}/resolve` returns the decrypted
workspace Relaycast key to a person credential with the `cli:auth` scope
(device and browser sessions carry it; any workspace role). Tokens without
`cli:auth`, workspace API tokens (`sh_wk_`), and `SELFHOST_INTERNAL_TOKEN` get
`403`; the bootstrap token gets `401`; another or departed tenant gets `404`.
Each disclosure is audited as `workspace.relaycast_key.resolved` with the
session id, never the key or token.

### Replacing a workspace's Relaycast key

`PUT /api/v1/organizations/{organizationId}/workspaces/{workspaceId}` with any
of `relaycastApiKey`, `relaycastWorkspaceId`, `name` (bootstrap bearer or an
organization owner/admin) replaces the stored, encrypted key, for a Relaycast
that was reset and re-minted. The workspace id, and so Desktop sign-ins bound
to it, stay the same.

### Deleting a workspace

`DELETE /api/v1/organizations/{organizationId}/workspaces/{workspaceId}`
(bootstrap bearer or an organization owner/admin) answers `204` and removes the
workspace with its sessions, tokens, credentials, flows and workspace-scoped
audit events; the deletion is audited at organization level as
`workspace.deleted`. A workspace outside the organization is `404`. An
organization's last workspace is `409 last_workspace` unless the bootstrap
bearer deletes it, and a workspace with a Factory connection or binding is
`409 workspace_in_use`.

Stored objects are not cleaned up. The Relaycast workspace behind it stays, as
do uploaded run objects (`SELFHOST_FLOWS_STORAGE=gcs`) and the encrypted
subscription-login blobs in Postgres, GCS or S3. Control has no route to them
once the workspace is gone; use a bucket lifecycle rule for bucket storage.

## Dashboard contract

Every Desktop route under `/api/v1/*` has an identical
`/cloud/api/v1/*` alias. Bearer authentication continues to work. Browser
requests may instead use the Secure, HttpOnly, SameSite cookie issued by
`/login`; the page keeps both the device code and resulting access token out of
JavaScript and returns no access or refresh token to the browser.

The dashboard session endpoints are deliberately not a general proxy:

- `GET /cloud/api/v1/workspaces/:id/sessions` forwards only `q` and `cursor`
  to RelayHistory's fixed `/v1/sessions` path.
- `GET /cloud/api/v1/workspaces/:id/sessions/:sessionId/events` forwards only
  `source` to the fixed session-events path and requests ascending order.

Both upstream requests add `workspace=` from the tenant-authorized database
record. Caller-supplied origins, paths, workspace IDs, and credentials are
never forwarded.

## Relayflows

Flows are saved definitions (`/api/v1/flows`). Runs (`/api/v1/workflows/*`)
execute on self-registered workers that speak the same assignment protocol as
hosted Agent Relay Cloud, so the stock CLI works unchanged:

```sh
# Workspace owner/admin, from the dashboard or:
curl -X POST "$SELFHOST_PUBLIC_URL/cloud/api/v1/workers/enrollment-tokens" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"relayflows-worker"}'
# On the worker host (or the relayflows chart in cloudWorker mode):
agent-relay cloud worker register --token "$ENROLLMENT_TOKEN" \
  --name relayflows-worker --base-url "$SELFHOST_PUBLIC_URL"
agent-relay cloud worker start --name relayflows-worker --base-url "$SELFHOST_PUBLIC_URL"
```

`--base-url` may be the bare origin or `<origin>/cloud`; both route to the same
handlers. Protocol summary:

- `POST /api/v1/workers/register` consumes a single-use, hashed enrollment
  token and returns `{workerId, workerToken, heartbeatIntervalMs}`.
- `POST /api/v1/workers/{id}/heartbeat`, `GET /api/v1/workers/{id}/queue`
  (SSE: `ping`, `assignment`, `revoke`), `POST .../assignments/{runId}/ack`,
  `POST .../assignments/{runId}/status`, and `GET|HEAD|PUT
  .../assignments/{runId}/storage/{key}` authenticate with the worker token.
- A worker runs one assignment at a time. Work can be pinned to a worker
  (`runtime.config.workerId|name`) or require tags. Unacknowledged work is
  redelivered when the queue stream reconnects. The queue polls Postgres, so
  multiple API replicas are safe.
- The assignment payload is built at delivery time and includes the
  workspace's decrypted Relaycast key and any run `envSecrets`; envSecrets are
  stored encrypted with `SELFHOST_ENCRYPTION_KEY` and never returned by the
  dashboard API.

Workspace environment and integrations reach runs this way:

- **Delivery.** The stock worker cannot call the internal runtime contract, so
  relaycontrol resolves the workspace environment (env vars and integration
  tokens) when it builds the assignment payload for the authenticated worker
  that claimed the run. It never resolves it into the queued row.
- **Precedence.** The result merges under the run's own `envSecrets`, which
  win.
- **Redaction.** `RELAY_SECRET_ENV_NAMES` lists every delivered name.
- **Store unreachable.** If the store is unreachable, the claim is released
  and retried.
- **Warnings.** Skipped names and integration errors are recorded as a
  `run.environment_warnings` event with names only.
- **Just-in-time tokens.** A worker token can also read
  `/internal/v1/workspaces/{id}/integrations/{provider}/token`. To enable
  this, pass `runtimeCredentialVerifier: (token) =>
  flows.verifyRuntimeCredential(token)` to `createAdminModule`.
- **v1 shell steps.** The v1 runtime passes only an allow-listed environment
  to `deterministic` shell steps. Delivered values reach the runtime and agent
  steps, not arbitrary shell commands.

What the dashboard sees:

- Lifecycle events for every run (`run.queued`, `run.assigned`,
  `run.acknowledged`, `run.running`, `run.completed|failed|cancelled`), plus
  exit code, duration, summary, and error from the worker.
- Steps: the `agent-relay` worker executes the v1 relayflows runtime, which
  reports only run-level status. For those runs, YAML-declared steps are shown
  with a status inferred from the run. Runtimes that mirror progress (the
  v2 cloud-mirror contract: `local-run`, `runs/{id}/events`,
  `runs/{id}/steps/snapshot`, `runs/{id}/steps`, `runs/{id}/storage/{key}`,
  `callback`) produce reported steps, logs, and artifacts.
- Cancel withdraws queued work at once. Work already running on a worker
  cannot be interrupted over the protocol; the run is marked cancelled and
  stays cancelled.
- Resume re-queues a finished run as a linked run, optionally with
  `startFrom` (`--start-from`). The v1 runtime's `--resume` needs its own
  internal run ID, which workers do not report.

Local development without Postgres: `npx tsx scripts/dev-server.ts` runs the
API on PGlite at `http://127.0.0.1:8787` with fixed development secrets.

## Security boundaries

- Access tokens are bound to one user, organization, and workspace.
- The transport (bearer header or `/cloud` cookie) never confers authority.
  Reaching another workspace needs a capability scope fixed at issue:
  `account` (browser sessions) or `desktop:workspaces` (Desktop sessions);
  see the mint matrix in [docs/identity.md](docs/identity.md#scope-mint-matrix).
- In multi mode the bootstrap bearer is the only credential that reaches
  every organization; each use on an organization route is audited as
  `bootstrap.access`.
- Every workspace query joins through active organization membership.
- Cross-tenant workspace lookups return `404`.
- Tokens and device codes are stored only as SHA-256 hashes.
- Refresh rotates the access and refresh hashes in one conditional update;
  both previous tokens immediately stop working.
- Relaycast keys and run envSecrets use AES-256-GCM at rest.
- Worker enrollment tokens, worker tokens, and run ingestion tokens are
  stored only as SHA-256 hashes; each worker token is scoped to one worker
  and can only read or write storage for its own active assignment.
- RelayHistory assertions (RelayAuth mode) must exactly match user,
  organization, workspace, scopes, and the configured public History origin
  before exchange through the internal History URL.
- Token introspection requires its own secret, compared in constant time;
  only `sh_at_` access tokens are looked up, and the token, its hash, the
  secret and the request body are never logged.
- Browser access/refresh tokens are never returned in HTML or JSON; only the
  opaque access credential is carried in a Secure HttpOnly same-origin cookie.

## Workspace admin

Ported from the hosted dashboard's Settings (Environment, Connections, API
tokens, Organization). Differences from hosted are listed at the end.

**Roles.** Reads are open to every workspace member. Every write is owner/admin
only (hosted lets any member edit environment variables and connections;
self-host is stricter). Cookie-authenticated writes must be `application/json`.

**Environment variables** (`/api/v1/workspaces/:id/secrets`, hosted path and
shapes). `POST` creates or replaces; values are AES-256-GCM encrypted with the
`SELFHOST_ENCRYPTION_KEY` keyring and never returned again (only
`maskedValue`, first/last two characters). Records carry `createdBy`,
`updatedBy`/`setBy`, `createdAt`, `updatedAt`, and every write is audited.
Hosted validation and limits apply: names `^[A-Za-z_][A-Za-z0-9_]{0,127}$`,
values up to 32 KiB without NUL, at most 200 variables / 256 KiB per
workspace; startup-altering names and sandbox-provider credentials are refused,
and launcher-owned names (`RELAY_*`, `RELAYFILE_*`, ...) are stored but not
delivered. Scope is the workspace (hosted has no per-environment scope).

**Provider connections.** Hosted delegates OAuth to Nango. Self-host replaces
it with the customer's own OAuth app per provider, configured by the operator,
and connects just in time: the CLI (`agent-relay cloud integration connect`,
relayfile setup), flow onboarding and flow creation call `connect-session`
(any workspace member), open the provider's authorize URL, and the callback
page links back to where the user started (`returnTo`). relaycontrol runs the
authorization-code flow (PKCE where supported, single-use hashed state,
10-minute expiry), stores tokens encrypted, refreshes them on demand under a
row lock, and never returns tokens to users. There is no settings page for it.

OAuth apps are operator configuration, not a per-user action:

| Env (chart: `relay-cloud-api.integrations.<provider>.existingSecret`) | Meaning |
| --- | --- |
| `SELFHOST_OAUTH_<PROVIDER>_CLIENT_ID` | the app's client ID (`<PROVIDER>` upper-cased, `-` as `_`) |
| `SELFHOST_OAUTH_<PROVIDER>_CLIENT_SECRET_FILE` (or `_CLIENT_SECRET`) | the client secret, mounted from a Secret |
| `SELFHOST_OAUTH_<PROVIDER>_SCOPES` | optional scope override |

Register this callback URL in every provider app:
`$SELFHOST_PUBLIC_URL/api/v1/integrations/oauth/callback` (or
`SELFHOST_OAUTH_REDIRECT_URL`). An operator app wins over a per-workspace app
stored through `PUT integrations/{provider}/oauth-app` (kept for existing
installs). When neither exists, `connect-session` answers 409
`oauth_app_not_configured` with "Your administrator needs to configure the
<Provider> app before it can be connected.", and `integrations/providers`
returns the same text as `adminMessage`. The registry in
`src/admin/providers.ts` ships GitHub, Slack, Linear, and Notion (OAuth) and
PostHog, Shortcut, Telegram, Cloudflare, and Neon (API key). Routes keep
hosted/relayfile CLI shapes (`integrations/catalog`, `connect-session` with
`relayWorkspaceId`, bare-array list, `{provider}/status`).

**Coding agents** (`/cloud-agents`, `/provider-credentials/byok`,
`/provider-credentials/setup-token`; hosted Settings > Connections > "Coding
agents"). Model-provider credentials for the workspace: API keys for
Anthropic, OpenAI, OpenRouter, xAI, and Google, and Claude setup
tokens (`claude setup-token`). Secrets are encrypted with the
`SELFHOST_ENCRYPTION_KEY` keyring; responses carry only `secretPreview` (first
7 and last 4 characters) and metadata. Each provider has two selections, as
hosted: **LLM call access** (`isActive`, any connected credential) and
**Sandbox access** (`harnessActive`, setup tokens only). The first credential
of a provider takes the selection, and deleting a selected credential promotes
the most recent remaining one. `POST cloud-agents/:id/check` makes one
authenticated provider read; a rejected key is marked `error` and is not
delivered until a later check passes. Flow runs receive the selections through
the runtime environment read below:

| Selection | Env var in the run |
| --- | --- |
| LLM call access, API key | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `XAI_API_KEY`, `GEMINI_API_KEY` |
| LLM call access, setup token | `CLAUDE_CODE_OAUTH_TOKEN` |
| Sandbox access (setup token) | `CLAUDE_CODE_OAUTH_TOKEN` (wins over an LLM-selected setup token) |

A selected credential wins over a workspace variable of the same name; a run's
own `envSecrets` win over both.

**Subscription logins** (hosted `provider_oauth`). Codex (ChatGPT) and Grok
(xAI) sign in from the dashboard's Connect agent dialog with the providers'
device flows (`POST provider-credentials/{openai,xai}-device/start|status`):
the operator approves a one-time code on the provider's site and relaycontrol
exchanges it, with no hosted callback. The resulting auth file is stored as an
envelope: a fresh AES-256-GCM data key per write, wrapped with the
`SELFHOST_ENCRYPTION_KEY` keyring (so keyId rotation applies), AAD-bound to the
credential and version. Envelopes go to object storage:

| `SELFHOST_CREDENTIAL_STORAGE` | Where |
| --- | --- |
| unset | `gcs` when `SELFHOST_FLOWS_STORAGE=gcs` (same bucket), else `postgres` |
| `postgres` | inline in `coding_agent_credential_blobs` |
| `gcs` | `SELFHOST_CREDENTIAL_GCS_BUCKET` (or `SELFHOST_FLOWS_GCS_BUCKET`), Workload Identity |
| `s3` | `SELFHOST_CREDENTIAL_S3_BUCKET`, `SELFHOST_CREDENTIAL_S3_REGION`/`AWS_REGION`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`[/`AWS_SESSION_TOKEN`], optional `SELFHOST_CREDENTIAL_S3_ENDPOINT` (R2, MinIO) |

Objects are `${SELFHOST_CREDENTIAL_PREFIX:-coding-agent-credentials}/workspaces/<ws>/accounts/<id>/v<n>.json.enc`.
A login is sandbox-only (never an env var). When a workspace has a selected
login, the assignment payload carries `cliCredentials` with a short-lived,
run-scoped reference (hashed at rest, revoked when the run finishes). The
worker presents it with its worker token at
`GET /api/v1/workers/:w/assignments/:run/cli-credentials` and gets each auth
file, refreshed first (under a per-credential advisory lock, so concurrent
runs spend one single-use refresh token) when it expires within 45 minutes. It
writes them 0600 under the run's private directory as `$CODEX_HOME/auth.json`
/ `$GROK_HOME/auth.json`, and after the run `PUT`s back a file the CLI
refreshed (same account only, never over a newer login). A login that is
expired and cannot refresh becomes `refresh_failed` and is skipped.
Claude has no browser login on hosted either; it uses the setup token above.

**Workspace API tokens** (`/deployment-api-tokens`, hosted shapes). Owner/admin
only, shown once, stored as SHA-256. Purposes: `agent-runtime` (runtime env and
integration reads), `workflow` (adds workflow scopes; may never expire), and
`deployment`, plus `relayfile-agent` (`fs:read`, `fs:write`, `sync:read`,
`sync:trigger`; requires `agent_name`, unique among a workspace's live
relayfile-agent tokens, and `aud`, one of the accepted introspection
audiences; may never expire), which relayfile verifies through
`POST /internal/v1/auth/introspect` as an `agent` principal, and
`acquisition-operator` (`acquisition:operate`; requires `aud`, one of the
accepted introspection audiences, refuses `agent_name`; may never expire;
several may coexist), which RelayHistory verifies through the same endpoint
as a `service` principal. Scopes are fixed by purpose (`scope`/`scopes` in the
body is a 400). Minted and revoked only through these owner/admin user-token
routes, also served at `/cloud/api/v1`. Desktop-issued sessions (device flow,
Desktop browser handoff and exchange) carry `cli:auth rth:read rth:sync
rth:acquire` (Desktop handoff sessions add `desktop:workspaces`); dashboard
browser sessions carry `cli:auth rth:read rth:sync account`, never `rth:acquire`.

**Runtime read contract** (`/internal/v1/workspaces/:id/...`). For the flows
worker and run executors, never user sessions. Accepts
`SELFHOST_INTERNAL_TOKEN`, a workspace API token with the runtime scope (bound
to its workspace), or a credential accepted by the optional
`runtimeCredentialVerifier` hook passed to `createAdminModule`.

- `GET environment[?includeIntegrations=1]`: decrypted deliverable env and
  the selected coding-agent credentials, plus, optionally, `WORKFORCE_INTEGRATION_<PROVIDER>_TOKEN` (hosted naming), and
  `secretEnvNames` for log redaction.
- `GET integrations`: connection metadata, no tokens.
- `POST integrations/:provider/token {forceRefresh?}`: a usable access token.

Every runtime read is audited. These routes are bearer-authenticated, but
deployments should still deny `/internal` at the public edge.

**Differences from hosted.** No Nango or Composio, so no syncs, webhooks, or
provider proxying, and no upstream connection deletion on disconnect. GitHub
uses an OAuth app rather than the hosted GitHub App installation. Model-provider
keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, ...) saved as workspace variables
are delivered, because self-host has no hosted credential proxy. Coding
agents are workspace credentials (hosted stores one set per member), there is
no Agent Relay house key ("Agent Relay API key", "OpenCode managed"), keys are
not probed at save (use Check token). Members are
added directly (there is no email invite flow), and workspaces cannot be
deleted from the API.
