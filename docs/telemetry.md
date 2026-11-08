# Telemetry in self-hosted Agent Relay

> **Draft disclosure.** Agent Relay must approve the wording and the default
> level before this ships to customers.

Self-hosted Agent Relay can send Agent Relay a small amount of operational
telemetry. We use it to learn how the self-hosted suite is used and which
errors installs hit, so that we can fix problems, sometimes before you
report them. You control it with a single setting. You can see exactly what
would be sent before anything leaves your cluster.

Product analytics is a separate, off-by-default feature; see [analytics.md](analytics.md).

## What we never collect

Telemetry never leaves your cluster with any of the following:

- message content, channel or DM text, attachments
- session transcripts, prompts, model output, tool input or output
- file contents, repository contents, file names, or paths in your data
- secrets, tokens, API keys, passwords, or connection strings
- email addresses, user names, display names, IP addresses
- raw workspace, organization, user, or agent IDs. Where a per-workspace
  count needs an identifier, it is replaced with a salted hash. The salt is
  generated in your database and never sent, so we cannot reverse the hash
  or match it across installs.

This is enforced in code, not only by policy:

1. Payloads are built from an allowlist of aggregate fields. Error reports
   carry the error class, status code, a route template such as
   `/api/v1/workspaces/:id/sessions`, counts, timestamps, and a stack
   fingerprint, which is a hash of function and file names. They never carry
   the error message or the stack trace.
2. Every outbound payload, including the preview, is passed through the
   shared Technical Foul secret scrubber (the same rules that protect
   RelayHistory and the sessions pipeline). Keys that name personal data or
   secrets are then dropped whatever their value. The scrubber's test corpus
   runs in this repository's test suite.
3. Every payload is signed with your install key and sent only over HTTPS to
   the configured endpoint.

## Levels

One setting, `SELFHOST_TELEMETRY_LEVEL` (chart value `telemetry.level`),
controls telemetry.

| Level | What is collected and sent |
| --- | --- |
| `off` | Nothing is collected and nothing is sent automatically. Issue reports are sent only when someone files one (see below). |
| `errors` | Error aggregates and error-burst reports, component health and versions, and the deployment shape (chart version, replicas, backends, storage type). No usage counters. |
| `full` | Everything in `errors`, plus usage aggregates: request counts per feature area and status class, active workspaces and agents, message counts, login counts, flow run outcomes, and counts of workers, env vars, integration connections and API tokens. |

The default is set by the Helm chart. *(Decision pending; see the chart
values.)*

### What a report contains

- **Digest**, sent every `SELFHOST_TELEMETRY_DIGEST_INTERVAL_SECONDS`
  (default 1 hour):
  - the time window
  - relaycontrol version, the deployment shape, and each probed component's
    health, HTTP status, latency, and reported version
  - errors since the last digest
  - at `full` only, usage aggregates
- **Error burst**, sent immediately when one error fingerprint occurs
  `SELFHOST_TELEMETRY_BURST_THRESHOLD` times (default 20) within
  `SELFHOST_TELEMETRY_BURST_WINDOW_SECONDS` (default 300), or when a
  component fails three health checks in a row. At most one report per
  fingerprint every 30 minutes.
- **Issue report**, sent only when you or your agent file one.

Example error entry:

```json
{
  "component": "relayhistory",
  "errorClass": "UpstreamError",
  "route": "/cloud/api/v1/workspaces/:id/sessions",
  "status": 502,
  "count": 37,
  "firstSeen": "2026-11-03T03:10:04.000Z",
  "lastSeen": "2026-11-03T03:14:58.000Z",
  "firstSeenEver": "2026-11-03T03:10:04.000Z",
  "fingerprint": "fp_6a1c0e9b2d4f7a13"
}
```

## See exactly what we send

- **Admin page.** Organization owners and admins can open
  `https://<your dashboard host>/cloud/api/v1/telemetry/admin`. It shows the
  current level, endpoint and outbox state, the exact body of the next
  digest, and every queued report. You can also preview what each other
  level would send; previewing changes nothing.
- **API.** `GET /api/v1/organizations/{organizationId}/telemetry/preview`
  (`?level=errors|full` for a hypothetical). In-cluster callers with
  `SELFHOST_INTERNAL_TOKEN` can use `GET /internal/v1/telemetry/preview`.

```sh
curl -s "$SELFHOST_PUBLIC_URL/api/v1/organizations/$ORG_ID/telemetry/preview" \
  -H "Authorization: Bearer $TOKEN" | jq .nextDigest
```

## Configuration

| Variable | Meaning |
| --- | --- |
| `SELFHOST_TELEMETRY_LEVEL` | `off` (default when unset), `errors`, or `full` |
| `SELFHOST_TELEMETRY_TRANSPORT` | `https` (default) or `file` (air-gapped: never sends over the network) |
| `SELFHOST_TELEMETRY_ENDPOINT` | HTTPS ingest URL, required for `https` unless the level is `off` |
| `SELFHOST_TELEMETRY_INSTALL_ID` | `inst_...`, issued by Agent Relay |
| `SELFHOST_TELEMETRY_INSTALL_KEY` / `_FILE` | Signing key issued by Agent Relay, at least 32 bytes. Never logged, displayed, or sent. |
| `SELFHOST_TELEMETRY_DIGEST_INTERVAL_SECONDS` | 300 to 86400, default 3600 |
| `SELFHOST_TELEMETRY_BURST_THRESHOLD` | Errors per window that count as a burst, default 20 |
| `SELFHOST_TELEMETRY_BURST_WINDOW_SECONDS` | 60 to 3600, default 300 |
| `SELFHOST_TELEMETRY_PROBES` | Extra health probes, `name=url,...` (for example `96bulls=http://alleyoop:8080/readyz,relayfile=http://relayfile:8080/health`). Relaycast `/health`, RelayAuth `/health` and RelayHistory `/readyz` are always probed through their internal URLs. |
| `SELFHOST_TELEMETRY_DEPLOYMENT` | JSON deployment shape rendered by the chart. Only short keys, numbers, booleans and version-like strings are kept. |
| `SELFHOST_IMAGE_VERSION` | Set by the image; reported as the relaycontrol version |
| `SELFHOST_INTERNAL_TOKEN` | Optional. The same service token as `/internal/v1`; also authorizes the service routes for issue reports and preview. |

If telemetry is misconfigured, startup fails, as it does for any other
required setting. When the level is `off`, no telemetry setting is required.

## Delivery, buffering, and offline clusters

Reports are written to a Postgres outbox (`selfhost_telemetry_outbox`) before
they are sent, so a cluster without egress loses nothing. Sending retries
with exponential backoff and jitter: 30 seconds, doubling up to 6 hours. A
report is dropped after 40 attempts or 14 days. Pending digests are capped
at 500. Delivered rows are deleted after 14 days. Requests are signed:

```
x-relay-telemetry-install:   inst_...
x-relay-telemetry-signature: t=<unix seconds>,v1=<hex HMAC-SHA256(installKey, "<t>.<raw body>")>
```

### Air-gapped installs

Set `SELFHOST_TELEMETRY_TRANSPORT=file`. Nothing is ever sent over the
network. The level still controls what is collected. Reports accumulate in
the outbox, and an organization admin downloads them as a signed file:

```sh
curl -s -o telemetry-export.json \
  "$SELFHOST_PUBLIC_URL/api/v1/organizations/$ORG_ID/telemetry/export?snapshot=1" \
  -H "Authorization: Bearer $TOKEN"
```

`snapshot=1` adds a fresh one-off digest. When the level is `off`, the
snapshot is the only content, and downloading it is an explicit operator
action. Inspect the file, then send it from any connected machine. The
file carries its own signatures:

```sh
curl -X POST https://agentrelay.com/api/v1/selfhost/telemetry \
  -H "Content-Type: application/json" --data-binary @telemetry-export.json
```

## Report an issue (for operators and agents)

Anyone in your organization with owner or admin rights, and any in-cluster
agent holding `SELFHOST_INTERNAL_TOKEN`, can file a diagnostic report. It
goes through the same scrubbed and signed channel and reaches Agent Relay's
triage agents directly. Each report includes:

- the text you provide (scrubbed: tokens, emails, IP addresses and UUIDs are
  masked)
- current component health and versions
- the top recent error fingerprints
- optionally, the JSON documents from the Helm chart support bundle
  collector

Set `"dryRun": true` to get the exact body back without sending it. Issue
reports are limited to 20 per hour. In multi mode an organization admin's
report carries `diagnostics: {"scope": "organization"}` instead of the
installation's component health and errors, and counts against a limit of
20 per hour per organization; the bootstrap and service-token lanes keep
the installation-wide limit.

```sh
# Operator (organization admin token or bootstrap token)
curl -X POST "$SELFHOST_PUBLIC_URL/api/v1/organizations/$ORG_ID/telemetry/issues" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"title":"RelayHistory 5xx since 03:10","summary":"Sessions page fails for every workspace after the 0.4.1 upgrade.","severity":"high","component":"relayhistory","dryRun":true}'

# In-cluster agent or job
curl -X POST "http://relay-cloud-api/internal/v1/telemetry/issues" \
  -H "Authorization: Bearer $SELFHOST_INTERNAL_TOKEN" -H "Content-Type: application/json" \
  -d @issue.json
```

To attach the support bundle, run the chart's collector
(`scripts/support/collect-support-bundle.py`). Then pass its manifest and
JSON documents as `supportBundle` in the form `{manifest, documents}`, for
example `{"versions.json": {...}, "workload-status.json": {...}}`. Only the
collector's known documents are kept, each at most 64 KiB.

### MCP tool

`GET /api/v1/telemetry/mcp-tool` returns the tool definition, so a
customer's agent framework can register it. Its input schema matches the
request body above:

```json
{
  "name": "report_selfhost_issue",
  "description": "File a diagnostic issue report with Agent Relay support from this self-hosted install. ...",
  "inputSchema": { "type": "object", "required": ["title", "summary"], "properties": { "...": "..." } }
}
```

Implement the tool as a POST of its arguments to
`/internal/v1/telemetry/issues` with the service token.

## What happens on our side

Reports arrive at Agent Relay's ingest. The ingest verifies the install
signature and stores the report. If the report is notable, it posts a
one-line summary to our internal triage channel, where our agents pick it
up. Notable means an error burst, an issue report, or a digest with an
unhealthy component or a server-error spike. An example summary:

```
[selfhost-telemetry] Acme (inst_…): relayhistory 5xx spike since 03:10Z: UpstreamError 502 /cloud/api/v1/workspaces/:id/sessions x37 fp_6a1c… in 300s
```

To stop telemetry, set the level to `off`. To have stored reports deleted, or
to have your install key revoked, contact Agent Relay support.

## Known gaps

- Relaycast reports only per-workspace stats (`/v1/console/stats`, read with
  each workspace's own key). It has no instance-wide totals, no error
  counters, and no `/metrics` endpoint. Its self-hosted `/health` reports
  version `0.1.0` and build `unknown`, because the self-host entrypoint does
  not wire in the app version.
- RelayHistory and 96bulls report no version or counts. Their health
  endpoints say only ready or not, with a reason. "Sessions delivered" is
  therefore approximated by relaycontrol's own session-route counts.
- Flow run outcomes, worker counts, env var counts, integration counts, and
  API token counts are read from the flows and admin tables when those
  modules are installed.
