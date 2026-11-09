# Analytics collector runtime

Draft. The receiving side of the [collector destination](analytics.md#collector-destination):
one process that accepts authenticated analytics batches from producers on an
internal `POST /v1/events` and commits each accepted batch as an immutable
NDJSON segment on a local volume. Contract: infra
`docs/analytics-collector-interface.md` (#84 @62599fb as amended by #85
@ca91118, merged 91c9b79).

## Purpose and boundary

- Separate entrypoint: `src/collector-cli.ts`, bin
  `agent-relay-analytics-collector`, modules in `src/analytics-collector/`
  (`config`, `producers`, `validate`, `storage`, `server`, `index`).
- Imports nothing from the control server except `src/analytics/types.ts` and
  `src/analytics/events.ts` (the batch schema, the event registry and its
  grammars), so it can move to another repository unchanged.
- The control server (`src/app.ts`, `src/server.ts`), the image, Helm and CI
  are unchanged. Nothing starts the collector today.
- One process, one listener, one writer. Routes: `POST /v1/events` and
  `GET /healthz`; anything else is `404 not_found` or `405 method_not_allowed`
  (with `Allow`).
- Producers are server components (their analytics adapter with
  `DESTINATION=collector`). Browsers and Desktop never hold a producer token;
  they go through the [client gateway](analytics.md#client-gateway).
- Not an operator telemetry endpoint and not OTLP.

## Configuration

Every variable has the prefix `ANALYTICS_COLLECTOR_`. Every number is a
decimal integer within the range below. A missing required variable or an
out-of-range value stops startup with an error naming the variable only, never
the value.

| Variable | Default | Range | Meaning |
|---|---|---|---|
| `HOST` | `127.0.0.1` | hostname or IP | Listen address |
| `PORT` | required | 0 to 65535 | Listen port (`0` picks a free port, for tests) |
| `DATA_DIR` | required | existing writable directory | `segments/` and `tmp/` are created inside (mode 0700) |
| `PRODUCERS_FILE` | required | readable JSON file | Producer registrations, see below |
| `MAX_BATCH_BYTES` | 262144 | 1024 to 16 MiB | Streamed body cap; `413` as soon as it is passed |
| `MAX_BATCH_EVENTS` | 500 | 1 to 10000 | Events per batch; more is `400 invalid_batch` |
| `MAX_EVENT_BYTES` | 4096 | 256 to 1 MiB | Canonical NDJSON line cap; `413 event_too_large` |
| `REQUEST_TIMEOUT_MS` | 10000 | 100 to 300000 | Body read deadline; `408 timeout` |
| `MAX_IN_FLIGHT` | 16 | 1 to 1024 | Concurrent authenticated requests; beyond is `429 busy` |
| `MAX_SEGMENTS` | 100000 | 1 to 10000000 | Closed segment file count |
| `MAX_DISK_BYTES` | 1073741824 (1 GiB) | 1 MiB to 16 TiB | Sum of closed segment sizes |
| `RETENTION` | `reject-new` | `reject-new` or `delete-oldest-closed` | Policy at the caps |
| `RETENTION_MAX_AGE_MS` | unset | 60000 to 3153600000000 | Only with `delete-oldest-closed` (an error otherwise): segments older than this are removed at startup and on each commit |
| `SHUTDOWN_DEADLINE_MS` | 5000 | 100 to 60000 | SIGTERM/SIGINT: stop accepting, finish in-flight commits, exit |

`MAX_EVENT_BYTES` must not exceed `MAX_BATCH_BYTES`, which must not exceed
`MAX_DISK_BYTES`.

### Producers file

```json
[
  {
    "name": "control-a",
    "component": "relaycontrol",
    "deployment_id": "deploy_a",
    "token_file": "/var/run/secrets/analytics/control-a"
  }
]
```

- Exactly these keys. 1 to 256 producers.
- `name` and `component` are lowercase identifiers (`[a-z0-9][a-z0-9_.-]{0,63}`).
- `deployment_id` follows the opaque ID grammar of `events.ts`.
- `component` must have a registered event registry. The CLI wires
  `relaycontrol` to `EVENT_REGISTRY`; another component is a startup error.
- `token_file` (a Secret mount) is read once at startup and trimmed. The token
  must be 32 to 512 bytes of visible ASCII.
- Only the SHA-256 digest of each token is kept. A request token is hashed and
  compared against every registration with `crypto.timingSafeEqual`.
- A duplicate name, a duplicate `component` plus `deployment_id`, or a shared
  token is a startup error.
- The startup log lists name, component and deployment ID per producer, never
  a token.

Changing producers or tokens needs a restart.

## Request handling

`POST /v1/events`, in this order. The first failing step answers.

1. Route and method (`404`, `405` with `Allow: POST`), then
   `Content-Type: application/json`, with `charset=utf-8` the only allowed
   parameter (`415`).
2. Authorization. Exactly one `Authorization` header must be present. Node
   keeps only the first duplicate in `request.headers`, so the collector counts
   `request.rawHeaders` names case-insensitively. The value must be
   `Bearer <token>`, and the token must match a registration. Anything else is
   `401` with `WWW-Authenticate: Bearer`. Tokens in the query string, cookies
   or the body are never read. Nothing is read from the body before this step.
   For `401`, `405`, `415`, `429`/`503`, `408` and `413` the connection is
   closed without draining the rest of the upload.
3. In-flight gate: `429 busy` with `Retry-After: 1` above `MAX_IN_FLIGHT`
   (`503 busy` once shutdown has started).
4. Body. Streamed under `MAX_BATCH_BYTES`. A larger `Content-Length` is
   refused at once. A body that passes the cap while streaming (chunked or
   understated) is refused as soon as the cap is passed. In both cases the
   answer is `413 payload_too_large` and the connection is then dropped.
   `REQUEST_TIMEOUT_MS` bounds the read (`408 timeout`).
5. Shape. The body must be strict UTF-8 JSON with exactly `schema` and
   `events`. `schema` must be `agent-relay.analytics.batch/v1`. `events` must
   be an array of 1 to `MAX_BATCH_EVENTS` events. Each event has exactly the
   envelope keys:
   - `version` 1
   - `event_id` a UUID
   - `occurred_at` an ISO-8601 UTC time
   - `component`
   - `deployment_id` the opaque ID grammar
   - `event`
   - `trace_id` the trace grammar
   - optional `tenant_id` and `workspace_id`
   - `properties` an object of primitive values
6. Authority. Every event's `component` and `deployment_id` must equal the
   producer's registration, else `403 forbidden` for the whole batch.
7. Registry:
   - The kind must be registered for the component.
   - Scope rules: installation means neither ID; tenant means `tenant_id`
     only; workspace means both IDs; native_workspace means `workspace_id`
     only.
   - Properties must be in the kind's typed allowlist and pass its spec (the
     same `propertyValue` checks as the adapter). No property may carry an
     envelope field name.
   - Any failure is `400 invalid_batch` with the event's `index`.
8. Size. Each event is serialised as one canonical NDJSON line, keys in
   envelope order. A line over `MAX_EVENT_BYTES` is `413 event_too_large` with
   `index`.
9. Commit. See [storage](#storage-layout-and-recovery). The answer is `204`
   with an empty body only after the file fsync, the rename and the directory
   fsync.

Nothing is written for any request refused before step 9. There is no partial
acceptance: all events of a batch are committed or none are.

## Responses

| Status | Body `error` | When | Producer behaviour (contract) |
|---|---|---|---|
| `204` | (empty) | Batch durably committed | Accepted; dequeue |
| `400` | `invalid_batch` (+ `index` for one event) | Shape, schema, count, registry, scope or property failure | Terminal |
| `401` | `unauthorized` | Missing, malformed, unknown or duplicate `Authorization`; with `WWW-Authenticate: Bearer` | Terminal authentication failure |
| `403` | `forbidden` | `component` or `deployment_id` differs from the registration | Terminal authority failure |
| `404` | `not_found` | Unknown path | (configuration error) |
| `405` | `method_not_allowed` | Wrong method; with `Allow` | (configuration error) |
| `408` | `timeout` | Body not complete within `REQUEST_TIMEOUT_MS` | Bounded retry |
| `413` | `payload_too_large` | Body over `MAX_BATCH_BYTES` | Split allowed |
| `413` | `event_too_large` + `index` | One canonical line over `MAX_EVENT_BYTES` | Oversized single events dropped |
| `415` | `unsupported_media_type` | Not `application/json` | (configuration error) |
| `429` | `busy`; `Retry-After: 1` | Above `MAX_IN_FLIGHT` | Backpressure; bounded retry honouring `Retry-After` |
| `503` | `busy`; `Retry-After: 1` | Shutting down | Backpressure; bounded retry honouring `Retry-After` |
| `507` | `storage_exhausted`; `Retry-After: 5` | Capacity reached under `reject-new`, or any write, fsync or rename failure | Storage exhausted; bounded retry |
| `500` | `internal` | Unexpected error (not expected to occur) | Bounded retry |

Bodies are always `{"error": "<code>"}`, plus `index` where shown. They never
contain event content, tokens, request bodies or exception text. Responses
carry `Cache-Control: no-store`. The collector never redirects.

## Storage layout and recovery

```
DATA_DIR/
  segments/<epoch-ms 13 digits>-<seq 10 digits>-<uuid>.ndjson   closed, immutable
  tmp/<seq>-<uuid>.ndjson.part                                  being written
```

- Each accepted batch is its own closed segment: one event per line, keys in
  envelope order, each line ending in `\n`.
- There is no open segment and no rotation step. Consumers may read any file
  in `segments/` that matches the name pattern. Names sort by commit time,
  then sequence.
- Commits are serialised through one promise chain:
  1. Apply the age policy.
  2. Check capacity: the segment count plus one must stay within
     `MAX_SEGMENTS`, and the byte total plus this batch within
     `MAX_DISK_BYTES`.
     - `reject-new`: `507`, nothing written.
     - `delete-oldest-closed`: the oldest closed segments are removed until
       the batch fits, counted in `retention_loss`. A batch larger than the
       whole `MAX_DISK_BYTES` is `507` and evicts nothing.
     - The commit in progress is never a candidate.
  3. Write `tmp/*.part` (created exclusively, mode 0600), fsync it, close it,
     rename it into `segments/`, then fsync `segments/`.
  4. Only then `204`.
- Any failure in step 3 (ENOSPC included) is handled the same way:
  - the part file is removed (or the renamed file, if the directory fsync
    failed), so a batch answered `507` is not left visible;
  - `write_failures` is incremented;
  - the answer is `507`;
  - the log line carries the producer name, event count and errno code only.
- Startup recovery:
  1. `DATA_DIR` must already exist as a directory. The collector never creates
     it: it is an operator-provisioned volume or mount, and its own entry in
     its parent is the operator's to make durable. Nothing above `DATA_DIR` is
     synced.
  2. `segments/` and `tmp/` are created if missing (mode 0700).
  3. `DATA_DIR` is opened and fsynced, then closed. Syncing a file or
     `segments/` does not make a newly created directory entry durable; only
     syncing its parent does. This runs on every start, fresh or existing
     layout (cheap and idempotent), before any batch can be acknowledged. It
     is not repeated per commit.
  4. `DATA_DIR` is checked for writability (a probe file in `tmp/`).
  5. Every file in `tmp/` is deleted, so incomplete batches are never exposed.
     `tmp/` is not fsynced after this: a deleted part file that comes back
     after a crash is deleted again on the next start.
  6. `segments/` is indexed (count and bytes). The next sequence number
     follows the highest seen.
  7. The age policy is applied.

  A failure in steps 1-4 (including a failed open or fsync of `DATA_DIR`) is a
  startup error: the collector never listens and so never answers `204`. The
  message names `ANALYTICS_COLLECTOR_DATA_DIR` only, with no path or errno.

  A file in `segments/` that does not match the name pattern is left alone
  and not counted. A recovery failure stops startup with its errno code only.
- The age policy (`RETENTION_MAX_AGE_MS`) uses the commit time in the
  segment name.

## Health

`GET /healthz` returns `200` JSON with these fields:

| Field | Meaning |
|---|---|
| `ok` | `false` once shutdown has started |
| `segments`, `disk_bytes` | Indexed closed segments and their total size |
| `accepted.batches`, `accepted.events` | Committed since start |
| `rejected.unauthorized` | `401` responses |
| `rejected.forbidden` | `403` responses |
| `rejected.invalid` | `400` responses |
| `rejected.oversize` | `413` responses (both codes) |
| `rejected.busy` | `429` and `503` responses |
| `rejected.timeout` | `408` responses |
| `rejected.capacity` | `507` responses from capacity |
| `write_failures` | Failed write, fsync or rename (each also a `507`) |
| `retention_loss.segments`, `retention_loss.bytes` | Removed by `delete-oldest-closed` (capacity or age) |
| `producers.<name>.accepted_batches`, `.rejected` | Per producer, counted after authentication, so one producer's failures are visible apart from another's |

Counters are in memory and reset on restart.

The response carries no event content and no tokens. The collector never
writes its own failures into `segments/`. Logs go to stdout and stderr as
`[analytics-collector] <message> {fields}`. Fields are codes, counts,
producer names and limits only.

## Limits

Every bound is finite and configured above:

- batch bytes (streamed, not just `Content-Length`)
- events per batch
- event line bytes
- body read deadline
- concurrent requests
- segment count
- total disk bytes
- shutdown deadline

Header and request backstops follow `REQUEST_TIMEOUT_MS`:

- `headersTimeout` = `REQUEST_TIMEOUT_MS` + 1 s, at most 60 s
- `requestTimeout` = `REQUEST_TIMEOUT_MS` + 5 s

Producers are limited to 256 and tokens to 512 bytes. Segment sequence numbers
stop at 9999999999, after which commits are `507`.

On SIGTERM or SIGINT the collector:

1. stops accepting connections;
2. answers `503` on kept-alive sockets;
3. lets in-flight requests and commits finish;
4. closes;
5. exits 0.

If the work is not done within `SHUTDOWN_DEADLINE_MS`, the remaining
connections are closed and the process exits 1. A hard exit fires one second
after the deadline in any case.

## Not provided

- TLS. The listener is plain HTTP. Transport, CA and network policy belong to
  the reviewed deployment profile. The Service must not be a public ingress.
- Fencing. The collector assumes it is the only writer of `DATA_DIR`, but it
  neither checks nor enforces this. One replica, no overlapping writer during
  rollout, and demonstrated volume fencing are the deployment's job.
- Deduplication. A retry after a lost `204` commits the batch again. Event IDs
  are kept so consumers can deduplicate.
- Hosted egress. The collector makes no outbound request. Nothing is
  forwarded to PostHog or any hosted endpoint.
- An image, Helm chart, CI job or Desktop or browser access. Health route
  authentication is also not provided.

## Open points

- Home repository (maintainers' decision). The module boundary above lets it move
  unchanged.
- One file per batch is simple and crash-safe but file-heavy. A journal
  variant is a follow-up if consumers prefer fewer files.
- Health route authentication for non-local listeners.
