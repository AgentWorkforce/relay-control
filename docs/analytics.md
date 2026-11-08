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

| Event | Properties |
|---|---|
| `config_loaded` | `telemetry_level`, `telemetry_transport`, `sign_in_oidc`, `sign_in_email_link`, `sign_in_smtp`, `flows_enabled`, `operator_oauth_apps` |
| `service_started` | `component_version`, `config_fingerprint` |
| `service_stopping` | `reason` (`SIGINT`, `SIGTERM`, `startup_failed`) |

Every event carries `version`, `event_id`, `occurred_at`, `component`
(`relaycontrol`), `deployment_id`, `event`, `trace_id` (one per process) and
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
`dropped.invalid`. All three current events are installation-scoped and omit
`tenant_id` and `workspace_id`.

The adapter emits no exception events. Any future error field must map to a
registered classification, never a raw exception name, message or context.

## Collector destination

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

## Counters

`stats()` on the in-process port reports `captured`, `sent.{batches,events}`,
`dropped.{oversize,queueFull,rejected,protocol,retryExhausted,deadline,shutdown,aborted,invalid}`,
`failures.{auth,config,storage,redirect,transport}`, `queueEvents`,
`queueBytes`, `lastFailureReason` and `lastSuccessAt`. A full queue drops the
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
- Request-path, tenant- or workspace-scoped events.
- Browser and Desktop gateways.
- The collector itself, its storage and its Helm wiring.
- Persistent spooling across restarts.
