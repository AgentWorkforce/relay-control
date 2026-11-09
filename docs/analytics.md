# Product analytics in self-hosted Agent Relay

Product analytics is separate from [operational telemetry](telemetry.md). It is
off by default (`none`). When enabled, the control server sends a small set of
installation-scoped lifecycle events to a destination you configure. Nothing is
sent to Agent Relay unless you configure that yourself: no hosted endpoint or key
is built in, and the collector destination never falls back to PostHog.

Events are queued in memory and sent in the background. Capturing an event never
waits on the network, and export failures never fail a product request or startup.
Delivery is best effort with bounded retries. Each event keeps its `event_id`
across retries, so a batch may arrive twice after a lost acknowledgement, and
events are dropped (and counted) when the queue, retry budget or delivery
deadline runs out.

## Configuration

All variables use the `SELFHOST_ANALYTICS_` prefix.

| Variable | Default | Notes |
|---|---|---|
| `DESTINATION` | `none` | `none`, `collector` or `posthog` |
| `DEPLOYMENT_ID` | none | Required unless `none`. Opaque, 8-64 of `A-Z a-z 0-9 _ -`, stable across replicas, restarts and upgrades. Never derived from the telemetry install ID. |
| `PROFILE` | `production` | `development` allows plain `http` to installation-local hosts only |
| `COLLECTOR_URL` | none | The complete endpoint URL, including `/v1/events` (for example `https://analytics-collector.relay.svc.cluster.local/v1/events`); used as-is, nothing is appended. Absolute, with a path, and no credentials, query or fragment. `https`, or `http` under the development profile for loopback or `<svc>.<ns>.svc[.cluster.local]` |
| `COLLECTOR_TOKEN` / `COLLECTOR_TOKEN_FILE` | none | Opaque producer credential; exactly one of the two. Must not equal any other secret of the deployment (see below). |
| `COLLECTOR_CA_FILE` | system CAs | PEM bundle for the collector's installation CA. When set it replaces the system roots for the collector connection only, pinning the collector to the installation CA. Hostname verification is never disabled. |
| `POSTHOG_HOST` | none | `https` only. Required for `posthog`. |
| `POSTHOG_PROJECT_KEY` / `POSTHOG_PROJECT_KEY_FILE` | none | Required for `posthog`. Must not equal any other secret of the deployment (see below). |
| `MAX_EVENT_BYTES` | 4096 | 512-32768 |
| `MAX_BATCH_EVENTS` | 50 | 1-500 |
| `MAX_BATCH_BYTES` | 262144 | 4096-1048576; at least `MAX_EVENT_BYTES` + 55 (the batch envelope) and at most `QUEUE_MAX_BYTES` |
| `QUEUE_MAX_EVENTS` | 1000 | 10-10000 |
| `QUEUE_MAX_BYTES` | 1048576 | 65536-16777216 |
| `REQUEST_TIMEOUT_MS` | 5000 | 500-30000; per attempt, and never more than the remaining delivery or flush deadline |
| `DELIVERY_DEADLINE_MS` | 60000 | 1000-600000, at least `REQUEST_TIMEOUT_MS`. Total budget per event from enqueue: queue time, every attempt and every retry wait |
| `MAX_ATTEMPTS` | 4 | 1-10 per batch |
| `FLUSH_INTERVAL_MS` | 5000 | 500-60000 |
| `SHUTDOWN_DEADLINE_MS` | 3000 | 100-8000; flush budget on SIGINT/SIGTERM |
| `GATEWAY_MAX_BODY_BYTES` | 32768 | 1024-262144; client gateway request body limit |
| `GATEWAY_MAX_EVENTS` | 20 | 1-100; events per client gateway request |

Limits are plain decimal integers; forms such as `0x10` or `1e2` are refused.
Variables for the other destination are refused at startup, as are invalid
values. Errors never include the credential. The startup log line
`analytics started` shows the effective configuration with credentials reduced
to `...Configured: true|false`.

The collector token and the PostHog key are refused when they equal (directly or
through a `_FILE` variable) `SELFHOST_INTERNAL_TOKEN`, `SELFHOST_BOOTSTRAP_TOKEN`,
`DATABASE_URL` or `DATABASE_MIGRATIONS_URL` (or the password in either),
`RELAYAUTH_API_KEY`, `RELAYCAST_INTERNAL_SECRET`, `SELFHOST_ENCRYPTION_KEY`,
`SELFHOST_ENCRYPTION_PREVIOUS_KEY`, `SELFHOST_TELEMETRY_INSTALL_KEY`,
`SELFHOST_OIDC_CLIENT_SECRET`, `SELFHOST_SMTP_PASSWORD` or any
`SELFHOST_OAUTH_<PROVIDER>_CLIENT_SECRET`.

## Events

| Event | Scope | Client | Properties |
|---|---|---|---|
| `config_loaded` | Installation | server only | `telemetry_level`, `telemetry_transport`, `sign_in_oidc`, `sign_in_email_link`, `sign_in_smtp`, `flows_enabled`, `operator_oauth_apps` |
| `service_started` | Installation | server only | `component_version`, `config_fingerprint` |
| `service_stopping` | Installation | server only | `reason` (`SIGINT`, `SIGTERM`, `startup_failed`) |
| `dashboard.page_viewed` | Workspace | `dashboard` | `page` (`overview`, `sessions`, `agents`, `workflows`, `flows`, `settings`, `members`, `device`) |
| `dashboard.session_opened` | Workspace | `dashboard` | `source` (`list`, `search`, `link`) |
| `desktop.app_started` | Tenant | `desktop` | `desktop_version` (a version, see below), `os` (`macos`, `windows`, `linux`) |
| `desktop.sign_in_completed` | Tenant | `desktop` | none |

`desktop_version` is client-reported text, so it is checked against a version
grammar instead of the generic token rule: `MAJOR.MINOR.PATCH` (each 1 to 5
digits), then optionally `-` and a prerelease, then optionally `+` and build
metadata, where prerelease and build are dot-separated identifiers of
`[0-9A-Za-z-]+`. At most 32 characters, nothing else: `1.4.2`, `1.4.2-beta.1`,
`1.4.2+build.7` and `1.4.2-rc.1+sha.abc` pass; `v1.4.2`, `1.4`, `1.4.2 beta`,
an email address or a secret-shaped string such as `sk_live_abc123` do not.
`component_version` and `config_fingerprint` are server-derived and keep the
token rule.

Client kinds also carry the server-set `client` (`dashboard` or `desktop`) and,
when the client sent one, `client_event_id` (a UUID, lowercased). See
[Client gateway](#client-gateway).

Every event carries `version`, `event_id`, `occurred_at`, `component`
(`relaycontrol`), `deployment_id`, `event`, `trace_id` (one per process for
server events, one per request for client events) and
allowlisted `properties`. Unknown properties are dropped; properties that try
to set an envelope field are refused.

The registry fixes each event kind's scope, and with it the attribution the
event must carry; a caller cannot choose a weaker scope:

| Scope | Attribution |
|---|---|
| Installation | Neither `tenant_id` nor `workspace_id` |
| Tenant | `tenant_id` only |
| Workspace (tenant model) | Both `tenant_id` and `workspace_id` |
| Native workspace (no tenant model) | `workspace_id` only; never `tenant_id` |

The control server uses the tenant model (organization = tenant), so native
workspace kinds cannot be registered for it. Missing required IDs, IDs on an
installation-only event, a scope outside the model (for example a workspace
event with only `workspace_id`) and unknown scopes are refused and counted as
`dropped.invalid`. The three server events are installation-scoped and omit
`tenant_id` and `workspace_id`; the client kinds are tenant- or
workspace-scoped and take their IDs from the authenticated session.

The adapter emits no exception events. Any future error field must map to a
registered classification, never a raw exception name, message or context.

## Collector destination

The receiving side (the collector runtime, its storage and limits) is documented in
[analytics-collector.md](analytics-collector.md).

`POST {COLLECTOR_URL}` (the URL as configured, already ending in `/v1/events`) with body
`{"schema":"agent-relay.analytics.batch/v1","events":[...]}` and exactly one
`Authorization: Bearer <token>` header. One request is in flight at a time.

| Response | Producer behaviour |
|---|---|
| `204` | Accepted; dequeue the batch. The only acceptance. |
| Other `2xx` (`200`, `202`, `206`, ...) | Protocol error, never acceptance: the batch stays queued and is retried with backoff; after `MAX_ATTEMPTS` it is `dropped.protocol` |
| `400`, `404`, `422`, other `4xx` | Terminal; `dropped.rejected` |
| `401` / `403` | Terminal; `dropped.rejected` plus `failures.auth` / `failures.config` |
| `413` | Split into halves down to single events; a single oversized event is `dropped.oversize` |
| `429` / `503` | Retry, honouring `Retry-After` (see below) |
| `507` | Retry, honouring `Retry-After`; `failures.storage` |
| Other `5xx`, `408`, timeout, connection loss | Retry with 1, 2, 4, 8 s backoff (±20%, cap 30 s); `408`, timeouts and connection loss also count `failures.transport` |
| Redirect | Never followed; `failures.redirect` plus `dropped.rejected` |

After `MAX_ATTEMPTS` a batch is `dropped.retryExhausted` (or `dropped.protocol`
when the last answer was a non-`204` `2xx`).

`Retry-After` is honoured only as unsigned decimal delta-seconds. HTTP-date and
malformed values are ignored and the local backoff applies. The wait is capped
at 30 s, and further at the batch's remaining delivery deadline and, during a
flush, at the flush deadline. Every attempt counts against `MAX_ATTEMPTS`, even
after a zero delay. A zero wait (`Retry-After: 0`, or a wait clipped to zero)
retries immediately rather than after `FLUSH_INTERVAL_MS`.

Each event's delivery deadline is its enqueue time plus `DELIVERY_DEADLINE_MS`.
A batch uses the earliest deadline of its events; retries and `413` splits never
reset it. Each attempt's timeout is the smallest of `REQUEST_TIMEOUT_MS`, the
batch's remaining delivery deadline and, during a flush, the remaining flush
deadline. Before any attempt or retry wait, events whose deadline has passed are
dropped and counted as `dropped.deadline`; no further request or wait is made
for them.

## PostHog destination

`POST {POSTHOG_HOST}/batch/` with the project key, `distinct_id` set to the
deployment ID and `$process_person_profile: false`. Any `2xx` is success, per
PostHog's own contract (the collector's `204`-only rule does not apply). Other
statuses, `Retry-After` and the delivery deadline follow the collector rules
above.

## Client gateway

`POST /api/v1/analytics/events` (also `/cloud/api/v1/analytics/events`) lets
the dashboard and Desktop send the registered client kinds above through the
same port, queue and destination as the server's own events. It is mounted only
when `DESTINATION` is not `none`; with `none` the path is `404 not_found`, as
before the gateway existed.

### Credentials

| Client | Credential | Path |
|---|---|---|
| `dashboard` | Session cookie | `/cloud/...` only. The request must be `application/json` with an allowed `Origin` (the API or dashboard origin) or `Sec-Fetch-Site: same-origin`, else `403 forbidden`, checked before the body is read. |
| `desktop` | User bearer token | Either path |

The session needs scope `cli:auth` (`403 forbidden` otherwise); every session
the server issues today has it. Bootstrap, internal and workspace API tokens
are `401`. The body's `client` must match the credential (cookie = `dashboard`,
bearer = `desktop`), else `400 client_mismatch`.

### Request

```json
{
  "schema": "agent-relay.analytics.client-batch/v1",
  "client": "desktop",
  "events": [
    {
      "event": "desktop.app_started",
      "occurred_at": "2026-11-08T12:00:00Z",
      "client_event_id": "6f1c2a4e-8b3d-4e5f-9a1b-2c3d4e5f6a7b",
      "properties": { "desktop_version": "1.4.2", "os": "macos" }
    }
  ]
}
```

- The body is read up to `GATEWAY_MAX_BODY_BYTES` (default 32768), counted on
  the streamed bytes; beyond that the answer is `413 payload_too_large`.
- `events` holds 1 to `GATEWAY_MAX_EVENTS` (default 20) entries; more is
  `400 too_many_events`.
- Malformed JSON, unknown top-level fields, a wrong `schema` or `client`, and a
  missing or empty `events` are `400 invalid_request`.
- The whole body is validated before anything is captured. An event that is
  not a registered kind for this client (including every server-only kind),
  has an unknown field, an unregistered property, a property value outside its
  spec (for example a `desktop_version` outside the version grammar), a
  non-UUID `client_event_id`, or sets `client` / `client_event_id`
  inside `properties` makes the request `400 invalid_event`, with the message
  naming `events[i]`.
- `deployment_id`, `component`, `tenant_id`, `workspace_id`, `event_id`,
  `trace_id` and `version` are refused at any depth: `400 reserved_field`.
- `occurred_at` (ISO-8601 with a zone) is kept when within 5 minutes of server
  time. Outside that window, or unparseable, it is replaced by server time and
  counted as `clock_adjusted`. Omitted, it is server time.

### Authority

Before reading the body the gateway re-checks the session's workspace
membership; if it is gone the answer is `404 workspace_not_found`. `tenant_id`
is the session's organization and `workspace_id` its workspace, attached only
as the event's registry scope requires. No user ID, email, name, session ID or
IP address is exported. Each request gets one fresh `trace_id` shared by its
events. `event_id` is always minted by the server; the client's
`client_event_id` is kept as a property for de-duplication downstream.

### Limits and response

Requests are limited to 60 per minute per session and 300 per minute per client
IP; beyond that the answer is `429 rate_limited` with `Retry-After`. See
[Rate limits and the forwarded-header boundary](#rate-limits-and-the-forwarded-header-boundary).

`202 {"accepted": n, "queued": true|false}` means the events were accepted for
best-effort export, not that they were durably stored. `queued: false` means
the in-memory queue dropped at least one of them (for example `queueFull`); the
request still succeeds and nothing else on the server is affected. Errors use
the usual `{"error", "message"}` shape.

### Rate limits and the forwarded-header boundary

| Limit | Key | Rule |
|---|---|---|
| Per session | `analytics:session:<session id>` from the authenticated credential | 60 per minute |
| Per client IP | `analytics:ip:<clientIp(request)>` | 300 per minute |

Both are checked after authentication and before the body is read. A request
over either is `429 rate_limited` with `Retry-After` and captures nothing.

The IP key comes from `clientIp` in `src/auth/device-approval.ts`, the same
helper the existing auth limiters use (`cli-login`, `desktop-session`,
`device-start`, `device-token`). The rule depends on
`SELFHOST_TRUSTED_PROXIES` (the number of reverse proxies in front of the
service that append to `X-Forwarded-For`, default `0`):

- With `0` it is the socket address. `X-Forwarded-For` is ignored and
  `X-Real-IP` is never read, since any client can send them. Behind an
  ingress this puts every client in the proxy's bucket; the server logs one
  warning per process when it sees `X-Forwarded-For` with this setting.
- With `N` it is the Nth address from the right of `X-Forwarded-For`, the
  address the outermost trusted proxy saw. Entries further left are client
  supplied and are not used. A header shorter than `N` falls back to its
  leftmost entry.

- Deployments behind an ingress or load balancer MUST set
  `SELFHOST_TRUSTED_PROXIES` to the number of proxy hops (usually `1`), and
  each of those proxies must append to `X-Forwarded-For`.
- The per-IP limit is defence in depth behind the per-session limit. It is not
  a security control on its own. The per-session key comes from the
  credential, so the client cannot choose it.

[Desktop feed](desktop-feed.md) documents the same helper and keying for the
feed's limits (the "Rate limits (proposed numbers)" item).

### Open points

- `component` stays `relaycontrol` for client events; the client is in the
  `client` property. Whether the collector interface should instead get one
  component per client (`relaycontrol-dashboard`, `relaycontrol-desktop`) is
  open.
- Desktop uses its ordinary session token with `cli:auth`; a dedicated
  analytics scope would need a change to the scopes the server issues.
- Which repository owns the dashboard sender, and its final page list, is
  open; the `page` enum above is the proposed set.

## Counters

`stats()` on the in-process port reports `captured`, `sent.{batches,events}`,
`dropped.{oversize,queueFull,rejected,protocol,retryExhausted,deadline,shutdown,aborted,invalid}`,
`failures.{auth,config,storage,redirect,transport}`, `queueEvents`,
`queueBytes`, `lastFailureReason`, `lastSuccessAt` and the client gateway's
`gateway.{requests,accepted,clock_adjusted}` and
`gateway.rejected.{auth,csrf,client_mismatch,body,invalid,reserved_field,rate_limited}`.
`gateway.accepted` and `gateway.clock_adjusted` count events; the others count
requests. `auth` covers `401`, the `403` for a missing scope and
`404 workspace_not_found`; `csrf` the cookie `403`; `body` `413`,
`invalid_request` and `too_many_events`; `invalid` `invalid_event`. A full queue drops the
newest event (`queueFull`). Events past their delivery deadline count as
`deadline`. When a flush reaches its deadline, events never
attempted count as `shutdown`, and the events of the request then in flight count
as `aborted`: that request is cancelled, so the collector may or may not have
committed them. Events captured after a flush gave up are sent normally. Every
captured event ends in exactly one of `sent.events`, a `dropped` counter or
`queueEvents`. The `analytics stopped` log line prints the counters on exit.

The flush on shutdown is bounded by `SHUTDOWN_DEADLINE_MS`, and the whole
shutdown (telemetry, analytics flush, HTTP server and database close) by a 10 s
hard exit. A startup failure exits non-zero after the same bounded flush.

## Out of scope

- A counters HTTP route; `stats()` is in-process only.
- Server-side request-path events; tenant and workspace kinds come only from
  the client gateway.
- The dashboard and Desktop senders themselves.
- The collector's image, Helm wiring and CI (the runtime entrypoint is a draft;
  see [analytics-collector.md](analytics-collector.md)).
- Persistent spooling across restarts.
