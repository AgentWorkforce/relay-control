# Replicas agent bridge

Tracked by [Control #99](https://github.com/AgentWorkforce/relay-control/issues/99).
The bridge starts a Replicas agent (or connects an existing Replicas chat),
gives it its own Agent Relay identity, installs a scoped Agent Relay MCP server
and reply helper inside the replica through the provider exec API, and delivers
Relay messages addressed to it into its chat. Its contract mirrors the Agent
Relay Cloud Replicas bridge.

## Enabling

- `SELFHOST_REPLICAS_ENABLED=true` (default off). While off, every route below
  answers 404 `{"error":"Not found"}` before authentication, no Replicas MCP
  tool is registered and the connection reports `relayBinding: false`.
- An owner or admin connects the workspace's Replicas API key through
  `POST /api/v1/workspaces/{ws}/remote-agent-connections/replicas`. That store
  is the only credential source; the key never leaves Control.
- `publicBaseUrl` must be reachable from the replica and from Relaycast: the
  replica calls `{publicBaseUrl}/api/v1/replicas/agents/{spawn}/messages` and
  Relaycast posts webhooks to `{publicBaseUrl}/api/v1/replicas/relay-events/{spawn}`.
- `SELFHOST_REPLICAS_SYNC_INTERVAL_SECONDS` (default `60`, minimum `30`; lower
  values are raised to 30; `0` turns it off): how often Control runs the
  environment sync for every Replicas connection whose all-environments
  default is on (see "Policies and registration").

## Who may call

Every dashboard route and MCP tool needs a signed-in person (not a workspace
token or service token) who is currently an owner or admin; the role is
re-read from the database on each call. MCP connections authorised through
the MCP OAuth connector do not get the Replicas tools.

## Flow

1. **Spawn** (`spawn_replica`, `POST .../replicas/spawns`): records the launch,
   then creates the replica. `client_request_id` makes an equivalent retry
   return the same launch; the same id with different options answers 409.
2. **Status** (`get_replica_spawn`, `GET .../replicas/spawns/{id}`): each read
   continues preparation: find the original chat, register the relay agent
   (`replicas-<16 hex>`), mint the per-launch capability and webhook secret,
   install the reply helper and the MCP server, create two Relaycast
   subscriptions (DMs and thread replies; mentions of the agent) and send the
   task once. The result reaches `bound` with `binding.agent`.
3. **Recover** (`recover_replica_spawn`): an unconfirmed create or task send is
   matched against its launch marker in the original chat; nothing is replayed.
4. **Bind** (`bind_replica`): connects an existing replica chat without creating
   a replica or sending a task. A chat already bridged elsewhere is refused.
5. **Release** (`release_replica`, `DELETE .../replicas/spawns/{id}`): first
   revokes the capability and webhook secret in one committed transaction, then
   deletes both subscriptions, releases the relay agent and sleeps the replica.
   It is repeat-safe and keeps the replica and its history.

A new launch has no relay pin; its first bind uses the workspace's canonical
relay and pins it. A pinned launch whose relay no longer matches answers 409
and is never moved to another relay.

When the MCP install fails the result carries `binding` plus
`provisioning_error: {code: "relay_mcp_provisioning_failed", stage: "relay_mcp", retryable: true}`
and no provider output. A later status read retries it. A replica that was
already bound keeps its helper sends and Relay delivery working while the
install is retried. Every bind installs the same `agent-relay-replica` MCP
entry; it reads the current capability from the replica's private credential
file, so a rebind replaces rather than adds an entry and a release takes effect
at once. The installer refuses to overwrite a foreign entry under that name, and
removes older per-launch `agent-relay-<spawn id>` entries for this replica only
when it verifies they run exactly this server.

Inside the replica, the MCP server offers `list_relay_agents`,
`check_relay_inbox` and `send_relay_message`, backed by the capability route.
The capability grants no session, admin, spawn or channel-management scope.
Whether the agent actually picks up the MCP tools depends on its harness; the
helper script remains the fallback named in the task prompt.

## Routes

| Route | Purpose |
| --- | --- |
| `GET /api/v1/workspaces/{ws}/replicas` | `{connection, spawns}`, masked |
| `GET /api/v1/workspaces/{ws}/replicas/environments` | Environments the key can use |
| `GET /api/v1/workspaces/{ws}/replicas/environment-policies` | Environment policies (see below) |
| `POST /api/v1/workspaces/{ws}/replicas/spawns` | Spawn (201) |
| `GET /api/v1/workspaces/{ws}/replicas/spawns/{id}` | Status, continues preparation |
| `DELETE /api/v1/workspaces/{ws}/replicas/spawns/{id}` | Release (writes a tombstone for the replica) |
| `POST /api/v1/replicas/agents/{id}/messages` | Capability calls from the replica |
| `POST /api/v1/replicas/relay-events/{id}` | Relaycast webhook (Standard Webhooks) |
| `POST /api/v1/replicas/mcp` | Environment-level MCP (workspace identity) |

Responses are `Cache-Control: no-store`. The capability, webhook secret and
provider key are stored encrypted and never returned, logged or audited.
Provider errors are reported without provider bodies. Audit actions:
`replicas.spawn.created`, `replicas.spawn.bound`, `replicas.mcp.provisioned`,
`replicas.mcp.failed`, `replicas.spawn.released`, `replicas.capability.used`.
Launches are stored in `replica_spawns` (migration 0065).

## Provider transport

`src/replicas/runtime.ts` supports identity, environments, create/list/get,
message, history, exec and sleep/wake. The origin is fixed and redirects are
refused; API version `2026-10-07` is sent on every request. API resource IDs use
the UUID grammar already required by the pinned Cloud service. This does not
constrain Relaycast identity IDs, which remain opaque text. Returned object
and page identity must match the request; UUID casing does not change identity.
Unknown provider status strings remain readable, and transcript event payloads
are preserved for the later history projection.

Fetch and every body read share one referenced timer for a 45-second operation
deadline (the provider exec request has a 30-second command budget). A caller
may choose a shorter budget. The timer is cleared on completion, including all
failure paths. Decoded responses are limited to 2 MiB, and an ignored abort
cannot keep the caller waiting or retain a late response. No raw body, header, API key or
transport exception enters an error. Definitive HTTP refusals retain their
status even when their body is empty, HTML, oversized or stalled.

Writes are never automatically retried. A network failure, timeout, 5xx or
malformed successful acknowledgement is an unknown outcome; callers need durable
intent and reconciliation before replay. The pinned API client establishes no
provider-side create/message idempotency contract, so a locally stable request
ID must not be advertised as one. A lifecycle 204 is a bodyless command
acknowledgement, not proof of final sleep/wake state. Read that state separately.

## Environment-level MCP (workspace identity)

Instead of installing an MCP server inside each replica, an admin can register
one HTTP MCP entry in a Replicas environment's configuration. Every Replicas
workspace in that environment then reaches
`POST /api/v1/replicas/mcp` with a short-lived `workspace_identity` token that
the provider mints for the entry's audience. Control installs nothing inside
the replica: no helper, credentials file or exec call.

The endpoint is stateless streamable HTTP and pull-only. It answers 404 before
authentication while `SELFHOST_REPLICAS_ENABLED` is off, is not an OAuth
resource, and accepts only a Bearer `workspace_identity` token. Person
credentials and capabilities are refused. It is rate limited per source IP
(120 requests per minute): over the limit it answers 429 with JSON-RPC error
-32000 `rate_limited` and `Retry-After`.

Each call is admitted in this order:

1. The token is an RS256 JWT from `SELFHOST_REPLICAS_IDENTITY_ISSUER`, signed by
   a key from the issuer's discovery document (same-origin JWKS), with this
   endpoint's URL as audience and a valid expiry no more than one hour ahead
   (30 s skew). Otherwise 401
   `replica_identity_invalid`. The `jti` is not treated as single-use. When
   the issuer's discovery document or JWKS cannot be read (network error,
   timeout, non-2xx, a body over 64 KiB, invalid JSON or schema, a foreign
   JWKS origin) the call answers 503 `replica_identity_unavailable` without
   `WWW-Authenticate`: the outage is not the token's fault.
2. A released replica (tombstone) is refused with 403 `replica_released`.
   Any tombstone for the token's issuer, organization and replica counts,
   including one whose workspace was deleted.
3. The token's provider organization must not be connected in more than one
   Control workspace, otherwise 403 `organization_shared` (as Cloud). The
   token's environment must be enabled in exactly one Control workspace whose
   Replicas connection belongs to the token's organization, otherwise 403
   `replica_environment_not_enabled`.
4. The replica acts as one Control person, who must still be a current member
   of the organization:
   - a creator mapped for the environment acts as the mapped person; a
     mapping to a former member is refused, never moved to the principal;
   - otherwise (no creator, or an unmapped one) it acts as the workspace's
     VM principal, an explicit member chosen by an admin. Control never
     derives it from an email or the workspace owner;
   - with no principal set, the call is refused.

   Refusals answer 403 `replica_creator_not_allowed`. Mapping, principal and
   membership are re-read on every call, so removing a member stops their
   replicas at once. An unmapped creator of an enabled environment is
   recorded as a pending creator (see below) so an admin can map it.
5. The first admitted call enrols the replica: one `replica_spawns` row with
   source `environment_identity`, `replica_id` = the Replicas workspace id and
   a Relay identity named `replicas-<16 hex>`. Later calls reuse it. A replica
   with a live binding in another Control workspace answers 409
   `replica_already_bound`. A Relay agent left behind
   by this replica's own released binding (its cleanup failed after a
   disable, principal or mapping change) is not a conflict: enrolment retries
   its cleanup first and answers a retryable 503 while that keeps failing.

   A replica already launched or bound through the API in this workspace (a
   live `spawn` or `bind` record for the same replica id) is not enrolled:
   once steps 1-4 pass, the environment MCP acts as that binding and its
   owner, with the binding's Relay name, task, state and deliveries unchanged,
   and answers a retryable 503 until the launch is bound (a rejected launch
   stays 409 until it is recovered or released). The mapped creator
   or principal of step 4 does not replace the owner. When the owner is no
   longer a member of the organization, calls are refused with 403
   `replica_creator_not_allowed`; nothing falls back to the principal.
   Releasing that binding tombstones the replica as any per-launch release.

The server offers the same three tools as the per-launch server:
`list_relay_agents`, `check_relay_inbox` and `send_relay_message`. Messages are
pulled with `check_relay_inbox`; nothing is pushed into the replica's chat.
Future wake-up delivery will need a chat selection and will answer 409
`replica_chat_selection_required` when none is set.

Audit actions: `replicas.identity.enrolled` and `replicas.identity.refused`
(reason code only, no token, claim or email; written only when the refusal
names a Control workspace, so tokens of an unknown organization or
environment cannot fill the audit log), `replicas.identity.revived`,
`replicas.environment.enabled`, `replicas.environment.disabled`,
`replicas.environment.creators_updated`, `replicas.environment.principal_updated`,
`replicas.environment.mcp_registered`, `replicas.environment.mcp_removed`,
`replicas.environment.all_enabled` and `replicas.environment.all_disabled`.

### Policies and registration

When an owner or admin connects Replicas, every environment of the connected
organization gets Relay by default, including environments discovered later
on sync. A fresh connect (no Replicas connection before it, including a
connect after a disconnect) discovers the environments, enables each one and
registers its MCP entry. A re-connect over an existing connection (a key
rotation) keeps the default and every opt-out as they are and runs the sync
semantics below. The connect response reports `environmentDiscovery`
(the discovery report per environment) and `environmentSetup:
{allEnvironments, environments}` (the enable and registration status per
environment). Setup failures are reported there and never fail the connect:
the connection is saved and a sync, a re-connect or an enable retries them
(a failed or refused default enable is not an opt-out). When discovery failed
or any environment ends in `registration_failed`, `registration_unconfirmed`,
`enabled_elsewhere`, `organization_shared` or `stale_connection`, the 200
response also carries `provisioning_error: {code:
"replica_environment_setup_failed", stage: "environment_setup", retryable,
environments: [ids]}`: `environments` lists the failing environments (empty
when discovery failed) and `retryable` is true when discovery failed or any
failing environment can be retried as is. Admins opt out per
environment. Enabling an environment never admits a replica on its own:
each call still needs a mapped creator or the VM principal (see the
admission order above).

| Route | Purpose |
| --- | --- |
| `GET /api/v1/workspaces/{ws}/replicas/environment-policies` | Policies: enabled, opted out, registration status, creator mapping with masked email hints, pending creators, binding counts |
| `PUT /api/v1/workspaces/{ws}/replicas/environments/{id}` | `{enabled?, creators?: [{creatorId, userId}]}`; creators replace the list and must be current members |
| `PUT /api/v1/workspaces/{ws}/replicas/environment-principal` | `{userId: <member id> \| null}`: set or clear the VM principal; answers the policy view |
| `POST /api/v1/workspaces/{ws}/replicas/environment-mcp` | `{environmentIds}` (re-enable those) or `{all: true}` (turn the default back on and clear every opt-out and re-enable every environment), optionally with `principalUserId`: set the principal, then enable and register the entry |
| `DELETE /api/v1/workspaces/{ws}/replicas/environment-mcp` | `{environmentIds}`: opt those environments out; `{all: true}`: turn the default off for the workspace and disable every environment. Disables, then removes the entry |
| `POST /api/v1/workspaces/{ws}/replicas/environments/sync` | Rediscover; while the default is on, every disabled environment that is not opted out (newly found, or a default enable that failed or was refused) is enabled and registered and enabled ones without an entry are registered again. Opted-out environments stay disabled |
| `DELETE /api/v1/workspaces/{ws}/replicas/environment-tombstones/{providerWorkspaceId}` | Revive a replica whose tombstone outlived its workspace (see below). Owner or admin of the workspace holding that organization's Replicas connection; 404 when there is no such tombstone |

`GET .../environments` stays the live list of environments the key can use
(`{environments: [{id, name}]}`). Discovery lists every environment of the
organization (`scope=all`), not only the key holder's. Environments that
appear later are picked up by the next sync: `POST .../environments/sync`, or
the periodic sync Control runs at startup and then every
`SELFHOST_REPLICAS_SYNC_INTERVAL_SECONDS` (default 60) for every Replicas
connection whose all-environments default is on (a workspace without a
settings row counts as on). The periodic sync has the same semantics as the
route, never overlaps a running sync, logs a failing connection and goes on
with the next, never sets or infers the VM principal, and is audited as the
`replicas-sync` service. It stops on shutdown.

An admin opts one environment out with `PUT .../environments/{id}` and
`enabled: false`, or `DELETE .../environment-mcp` with `{environmentIds}`;
the policy view shows it as `optedOut`. An opted-out environment stays
disabled across syncs and re-connects until an admin enables it again (`PUT`
with `enabled: true` or `POST .../environment-mcp`), which clears the
opt-out. `DELETE .../environment-mcp` with `{all: true}` turns the default off
for the workspace: every environment is disabled and sync enables nothing
new, but no environment is opted out. `POST .../environment-mcp` with
`{all: true}` turns it back on, clears every opt-out and re-enables every
environment. The policy view reports the default as
`allEnvironments`. A key rotation (re-connect) changes neither the default nor
any opt-out. Disconnecting Replicas turns the default off; connecting again
after the disconnect turns it back on and enables every environment again.

The dashboard's Settings → Connections → Replicas one-click setup and the CLI
use the same routes with the person's own credential (a cookie session or a
`cli:auth` bearer token): connect, then set the VM principal (`PUT
.../environment-principal`, or `principalUserId` on `POST
.../environment-mcp`). From then on every replica of the enabled
environments is admitted, including ones started without a creator. A
replica without a creator is admitted only as that explicit principal,
re-checked on every admission and every call, never through an email match
or the workspace owner.

The policy view also returns `principal` (`{userId, member}` or `null`;
`member: false` means the principal left the organization and admits nobody)
and `organizationShared`: true when the same Replicas organization is
connected in another Control workspace. A shared organization admits no
token, and enabling refuses: `PUT .../environments/{id}` with `enabled: true`
answers 409 "This Replicas organization is connected in another workspace.",
and `POST .../environment-mcp`, sync and the connect setup report
`organization_shared` and enable nothing. The connection is still saved.

Changing or clearing the principal releases every live binding that acts as
the principal (no tombstone): those replicas enrol again under the new
principal on their next call, or are refused when it was cleared. Mapping a
creator releases that creator's bindings that act as the principal or as a
different person, so they enrol again as the mapped member. Removing a
mapping releases nothing: a binding keeps acting for its person and its calls
are refused unless the rules above still select that person.

Each policy lists `pendingCreators`: `[{creatorId, emailHint, lastSeenAt,
count}]`, newest first: creators seen without a mapping (admitted as the
principal when one is set, refused otherwise). The 50 most recent are kept per
environment; a token without a creator is not recorded. Mapping a creator with
`PUT` removes its pending entry.

All are owner/admin only. The registered entry is:

```json
{"name": "agent-relay-replica", "transport": "http",
 "config": {"url": "<public base>/api/v1/replicas/mcp", "headers": {},
            "auth": {"type": "workspace_identity", "audience": "<same url>"}}}
```

Registration and removal report a status per environment (`registered`,
`registration_failed`, `registration_unconfirmed`, `enabled_elsewhere`,
`organization_shared`, `disabled`, `removal_failed`) with `retryable` on
failures. Registration first reads the environment's MCP entries: a single
matching `agent-relay-replica` entry is reused; two or more entries with that
name, or one with another transport or config, are never overwritten and
report `registration_failed` with `retryable: false`. Otherwise the entry is
created and read back. `registration_failed` with `retryable: true` means the
entries could not be read or the provider rejected the create (HTTP 400, 401,
402, 403, 404, 422 or 429). `registration_unconfirmed` (retryable) means the
create was sent but the entry could not be confirmed by reading it back
(timeout, provider 5xx, unreadable response, or the result could not be
stored); a retry reads the entries again and reuses one that landed. A 409 on
create is resolved by the read-back. An environment can be enabled in only
one Control workspace; a concurrent enable elsewhere reports
`enabled_elsewhere`.

Disabling an environment (`PUT` with `enabled: false`, `DELETE
environment-mcp`, or disconnect) commits the disable first, then removes the
provider entry, and releases the environment's enrolled bindings in this
workspace: their Relay identities are retired, no tombstone is written, and
each replica enrols again on its next call once the environment is enabled
again.

Releasing a replica writes a tombstone in the same transaction as the
revoke, before any cleanup, so its tokens keep being refused. This holds for
an environment-enrolled replica and for a per-launch spawn or bind released
with `release_replica` or `DELETE .../replicas/spawns/{id}` (keyed by the
connection's provider organization and the replica id; skipped when no
identity issuer is configured). An owner or admin revives it with
`recover_replica_spawn` and `revive: true`, which deletes the tombstone and
is audited as `replicas.identity.revived`; the next call enrols again.
A release of an already released replica is a no-op, so a repeated release
does not undo a revive. A binding left released without a tombstone (by a
disable, a principal or creator mapping change, or a member removal) is still
tombstoned by its first explicit release.
Disconnecting Replicas disables every policy and releases its bindings first,
then removes the registered entries best effort.

Policies, pending creators and the principal (migration 0067) are deleted
with their workspace. Tombstones are not: deleting a workspace tombstones
every live environment-enrolled replica of it (reason `workspace_deleted`)
and removes its environment-identity bindings in the same transaction, and
from migration 0069 a tombstone outlives its workspace with no workspace
attached, so those replicas stay refused. An owner or admin of the workspace
now holding that organization's Replicas connection revives one with `DELETE
.../replicas/environment-tombstones/{providerWorkspaceId}`. A workspace with
launch or bind records still answers 409 `in_use` until those replicas are
released.

## Not yet covered

- Background history through the push-only producer/consumer contract.
- Webapp journeys and acceptance on an owned test instance.
