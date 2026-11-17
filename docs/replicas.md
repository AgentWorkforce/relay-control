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
credentials and capabilities are refused. It is rate limited twice: a coarse
guard per source IP (10000 requests per minute, checked before the token)
and a quota per verified identity (120 requests per minute per provider
organization and Replicas workspace, checked right after the token is
verified and before the body is read or admission runs), so replicas behind
one egress IP do not share a budget. Over either limit it answers 429 with
JSON-RPC error -32000 `rate_limited` and `Retry-After`.

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
   A replica enrolled in another Control workspace (an environment-identity
   record in any state, or a launch or bind there that a verified call
   reused) is refused with 403 `replica_owned_elsewhere` once the
   enabled candidate workspace is known (step 3), before its connection
   and creator checks.
3. The token's provider organization must not be connected in more than one
   Control workspace, otherwise 403 `organization_shared` (as Cloud). A
   connect cannot create that state (see "Policies and registration"); it
   covers connections saved before that rule. The
   token's environment must be enabled in exactly one Control workspace whose
   Replicas connection belongs to the token's organization, otherwise 403
   `replica_environment_not_enabled`. The same refusal applies while that
   connection's access-revoked latch is set (the provider refused the stored
   key, see "Revoked provider access") and while the environment is fenced by
   discovery (a complete listing no longer showed it, see below).
4. The replica acts as one Control person, who must still be a current member
   of the organization:
   - a creator mapped for the environment acts as the mapped person; a
     mapping to a former member is refused, never moved to the principal
     and never recorded as a pending creator;
   - otherwise (no creator, or an unmapped one) it acts as the workspace's
     VM principal, an explicit member chosen by an admin. Control never
     derives it from an email or the workspace owner;
   - with no principal set, or a creator mapped to a former member, the call
     is refused, unless the replica has a live launch or bind in this
     workspace whose owner is still a member: that owned launch or bind is
     reused (step 5) before a creator mapping or principal is required.

   Refusals answer 403 `replica_creator_not_allowed`. Mapping, principal and
   membership are re-read on every call, so removing a member stops their
   replicas at once. An unmapped creator of an enabled environment is
   recorded as a pending creator (see below) so an admin can map it.
5. The first admitted call enrols the replica: one `replica_spawns` row with
   source `environment_identity`, `replica_id` = the Replicas workspace id and
   a Relay identity named `replicas-<16 hex>`. Later calls reuse it. A replica
   with a live launch or bind in another Control workspace answers 409
   `replica_already_bound`. A Relay agent left behind
   by this replica's own released binding (its cleanup failed after a
   disable, principal or mapping change) is not a conflict: enrolment retries
   its cleanup first and answers a retryable 503 while that keeps failing.

   An authorized first call from a replica in a workspace that has no Relay
   binding yet (an imported workspace binds lazily) reserves the binding row
   under the admission lock with no relay pinned. Control then provisions the
   workspace's canonical Relay binding through the same lazy binding every
   other service uses, outside that lock, and re-runs the full admission
   (steps 2-4) before it registers the replica or serves the call. One
   provisioning attempt is made per request. A failed or unconfirmed attempt
   (no provisioner configured, an error, or a binding that did not persist)
   answers 503 JSON-RPC -32000 `relay_mcp_provisioning_failed` with
   `Retry-After: 5` and keeps the reserved row for the next call; that call
   refuses the replica only if policy, mapping or membership changed. A replica
   refused in steps 1-4 never reserves or provisions anything. The server logs
   a safe diagnostic (`replicas_relay_provisioning_failed` with the workspace
   id, the reserved row id and an enum reason: unavailable, repeated, threw
   or returned_null), never provider output or credentials. Saved relay
   pins, lookups, the API launch and bind path and cleanup never provision:
   there an unbound workspace answers 409 "The replica's relay is
   unavailable.".

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
`replicas.environment.mcp_registered`, `replicas.environment.registration_retried`,
`replicas.environment.mcp_removed`, `replicas.environment.mcp_retained`,
`replicas.environment.cleanup_abandoned`, `replicas.environment.all_enabled` and `replicas.environment.all_disabled`.

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
environment). A connect for a provider organization that is already
connected in another Control workspace is refused with 403
`organization_shared` and saves nothing (see below). Other setup failures
are reported there and never fail the connect:
the connection is saved and a sync, a re-connect or an enable retries them
(a failed or refused default enable is not an opt-out). When discovery failed
or any environment ends in `registration_failed`, `registration_unconfirmed`,
`enabled_elsewhere`, `organization_shared`, `stale_connection` or
`access_revoked`, the 200
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
| `PUT /api/v1/workspaces/{ws}/replicas/environments/{id}` | `{enabled?, creators?: [{creatorId, userId}], retry_registration?: true}`; creators replace the list and must be current members; `retry_registration` recovers an unconfirmed registration (see below) |
| `PUT /api/v1/workspaces/{ws}/replicas/environment-principal` | `{userId: <member id> \| null}`: set or clear the VM principal; answers the policy view |
| `POST /api/v1/workspaces/{ws}/replicas/environment-mcp` | `{environmentIds}` (re-enable those) or `{all: true}` (turn the default back on and clear every opt-out and re-enable every environment), optionally with `principalUserId`: set the principal, then enable and register the entry |
| `DELETE /api/v1/workspaces/{ws}/replicas/environment-mcp` | `{environmentIds}`: opt those environments out; `{all: true}`: turn the default off for the workspace and disable every environment. Disables, then removes the entry |
| `POST /api/v1/workspaces/{ws}/replicas/environments/sync` | Rediscover; while the default is on, every disabled environment that is not opted out (newly found, or a default enable that failed or was refused) is enabled and registered and enabled ones without an entry are registered again. Opted-out environments stay disabled |

`GET .../environments` stays the live list of environments the key can use
(`{environments: [{id, name}]}`). Discovery lists every environment of the
organization (`scope=all`), not only the key holder's. Environments that
appear later are picked up by the next sync: `POST .../environments/sync`, or
the periodic sync Control runs at startup and then every
`SELFHOST_REPLICAS_SYNC_INTERVAL_SECONDS` (default 60) for every Replicas
connection whose all-environments default is on (a workspace without a
settings row counts as on). The periodic sync has the same semantics as the
route except for unconfirmed creates (below), never overlaps a running sync,
logs a failing connection and goes on with the next, never sets or infers the
VM principal, and is audited as the `replicas-sync` service. It stops on
shutdown.

Each sweep tick then retries unfinished cleanup for every Replicas
connection: a released binding whose Relay identity or compute could not be
retired (for example Relay answered 5xx during a disable) is retired again.
Each attempt is counted on the row (`cleanup_attempts`,
`cleanup_last_attempt_at`) and a failing row backs off exponentially, from
one minute doubling per attempt up to one hour. A failing row is logged
(`replicas_cleanup_failed` with the launch id) and the sweep goes on.

The same tick abandons launches and binds stuck in `preparing` or `binding`
for 7 days that never got a relay identity (no relay workspace, agent name or
subscriptions). Nothing advances one in the background, since that could
wake paid compute; only the person's status read retries it. An abandoned row
becomes `gone` with an error asking to spawn or bind again, and is audited as
`replicas.spawn.abandoned`. A replica Relay launched is put to sleep first, as
release does; an existing chat the person bound is left awake. A failed sleep
keeps the row for the next tick. Rows that got a relay identity are left for
`release_replica`, and environment identities are never touched.

Discovery fencing: a complete discovery listing (every page read) that no
longer shows an enabled environment records `discovery_missing_since` on its
policy (the first time only). The environment stays enabled and keeps its
opt-out flag and registration, but admits no token and is skipped by the
sync default selection; the policy view reports status `discovery_missing`
with `discoveryMissingSince`. Listing the environment again lifts the fence.
A partial or failed listing changes nothing.
A listing made for a connection that was replaced while it was in flight
(disconnect and connect, to another organization or with a new key) is
discarded: the discovery reports `failed`, records nothing and fences nothing;
the new connection's own discovery is authoritative.

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
connected in another Control workspace. One Replicas organization belongs to
one Control workspace: a connect (or a re-connect) for an organization that
is connected in another workspace is refused with 403 `organization_shared`
before anything is saved, so no connection row is written and nothing is
registered at the provider. The check runs under a per-organization lock, so
of two concurrent first connects in different workspaces exactly one wins.
Connections saved before this rule can still share an organization: such a
shared organization admits no token, and enabling refuses: `PUT
.../environments/{id}` with `enabled: true` answers 409 "This Replicas
organization is connected in another workspace.", and `POST
.../environment-mcp`, sync and a re-connect report `organization_shared` and
enable nothing. Once the other workspace disconnects, a connect succeeds.

Changing or clearing the principal releases every live binding that acts as
the principal (no tombstone): those replicas enrol again under the new
principal on their next call, or are refused when it was cleared. Mapping a
creator releases that creator's bindings that act as the principal or as a
different person, so they enrol again as the mapped member. Removing a
mapping releases, in the same transaction, the environment's bindings that
acted as that creator (no tombstone): each replica enrols again on its next
call as the principal, or is refused when no principal is set.

Each policy lists `pendingCreators`: `[{creatorId, emailHint, lastSeenAt,
count}]`, newest first: creators seen without a mapping (admitted as the
principal when one is set, refused otherwise). The 50 most recent are kept per
environment; a token without a creator is not recorded. A creator is written
at most once per minute: a call seen again within a minute of its
`lastSeenAt` writes nothing (`count` and `lastSeenAt` keep their value), so a
replica retrying in a loop does not turn every call into a write. Mapping a
creator with `PUT` removes its pending entry.

All are owner/admin only. The registered entry is:

```json
{"name": "agent-relay-replica", "transport": "http",
 "config": {"url": "<public base>/api/v1/replicas/mcp", "headers": {},
            "auth": {"type": "workspace_identity", "audience": "<same url>"}}}
```

Registration and removal report a status per environment (`registered`,
`registration_failed`, `registration_unconfirmed`, `enabled_elsewhere`,
`organization_shared`, `access_revoked`, `disabled`, `removal_failed`) with
`retryable` on failures. Registration first reads the environment's MCP entries: a single
matching `agent-relay-replica` entry is reused; two or more entries with that
name, or one with another transport or config, are never overwritten and
report `registration_failed` with `retryable: false`. Otherwise the entry is
created and read back. `registration_failed` with `retryable: true` means the
entries could not be read or the provider rejected the create (HTTP 400, 401,
402, 403, 404, 422 or 429). `registration_unconfirmed` (retryable) means the
create was sent but the entry could not be confirmed by reading it back
(timeout, provider 5xx, unreadable response, or the result could not be
stored); a retry reads the entries again and reuses one that landed. A 409 on
create is resolved by the read-back. `access_revoked` (`retryable: false`)
means the provider answered 401 or 403 to the listing or the create.

The create intent is persisted (`create_unconfirmed` on the policy, migration
0070) before a create is sent, and the policy view reports such a policy as
`registration_unconfirmed`. While it is set, every run is read-only: the
startup run, the periodic sync, `POST .../environments/sync`, `POST
.../environment-mcp` and a plain `PUT .../environments/{id}` with `enabled:
true` only list the entries again and never send another create, whoever
started them. The intent clears only when:

- a later complete listing finds a matching entry, which is recorded as
  registered; or
- a create sent by the same run is definitely rejected by the provider.

A failed listing leaves the intent as it was. Disconnect reads an
unconfirmed create back before the key is deleted: a complete listing that
finds the matching entry records its id and the entry is removed. A failed
listing, a conflicting entry or no entry fails the disconnect with 503
`replicas_cleanup_failed` (retryable), and the connection and the intent
stay. Disconnect never sends a create. Each time the intent is set its
generation (`create_attempt`) is incremented, and a run clears only the
generation it set itself: when an operator recovery sent its own create
between a run's two locked steps, that run neither clears the recovery's
intent nor creates again, and reports `registration_unconfirmed`. An environment can be enabled
in only one Control workspace; a concurrent enable elsewhere reports
`enabled_elsewhere`.

Recovering an unconfirmed registration is a separate, explicit operator
action, not a sync: `PUT .../environments/{id}` with `retry_registration:
true` (owner or admin only; the environment must be enabled or enabled in the
same request, otherwise 400). It retries an unresolved write, a create whose
outcome is unknown: after the enable it registers the entry once more and,
while the intent is set, sends the create again. A complete listing and a
second listing just before the create must both show no entry; that is the
precondition for re-sending, not proof that the earlier create failed. Using
the flag is an operator decision that accepts a possible duplicate entry,
which the provider may surface later. Each create it sends is audited as
`replicas.environment.registration_retried`. On an environment without an
unconfirmed create it registers like an enable does (an existing entry is
reused). The response is the usual `{environment}` view.

Disabling an environment (`PUT` with `enabled: false`, `DELETE
environment-mcp`, or disconnect) commits the disable first, then removes the
provider entry, and releases the environment's enrolled bindings in this
workspace: their Relay identities are retired, no tombstone is written, and
each replica enrols again on its next call once the environment is enabled
again. Disable keeps reporting `removal_failed` per environment.

Disconnect runs in this order: the disable and the disconnect fence are
committed (every policy disabled, the all-environments default off, the
bindings released); then every launch, bind and environment-identity binding
of the workspace is retired (compute stopped, Relay identity released); only
then is each unconfirmed create read back (see above) and each provider entry
removed; the connection is deleted last. An unknown launch create stops the
retirement with 409 `replicas_cleanup_failed` before any entry is touched. An
entry that cannot be confirmed or removed fails the disconnect with a
retryable 503 `replicas_cleanup_failed` before the connection is deleted, so
an entry that cannot be removed never keeps compute running.

The removal lists the environment's entries first and deletes the recorded
entry only when it is still exactly this edition's: same name, transport
`http`, the same config and (when the provider reports them) the same
environment and organization. A recorded entry that is no longer listed is
already removed. An entry someone else edited (name, transport, config,
environment or organization changed) is theirs now: it is retained at the
provider, only the recorded id is cleared, and the step is audited as
`replicas.environment.mcp_retained` (the environment reports `disabled`; it
does not block a disconnect). A failed listing is a failed removal: the id
stays and the step is retried later.

When that cleanup can never succeed (for example the provider key was
revoked, so no entry can be read back or removed), an owner or admin
completes the disconnect explicitly with `DELETE
.../remote-agent-connections/replicas` and the JSON body
`{"abandon_environment_cleanup": true}` (any other field is 400
`invalid_request`). The order is:

1. the disable and the disconnect fence are committed as on every
   disconnect: every policy is disabled, the all-environments default is off
   and the bindings are released, so neither the sync sweep nor an identity
   call can register or admit anything while the disconnect is half done;
2. compute and Relay retirement run as on every disconnect (an unknown
   launch create still answers 409 `replicas_cleanup_failed`; nothing is
   bypassed); then no entry is confirmed or removed and no create or remove
   is sent;
3. only when that retirement succeeded, every recorded entry id and
   unconfirmed create is cleared, audited as
   `replicas.environment.cleanup_abandoned` (one per environment), in the
   same transaction that deletes the connection.

A failed retirement in step 2 keeps the connection and leaves the recorded
entries and intents untouched for a later retry. The abandoned entries stay
at the provider; the response is `{connection: null,
environment_cleanup_abandoned: true}` (the marker is omitted when nothing
was pending). A later connect reuses a matching entry it finds there instead
of creating another one.

An enrolled binding follows the replica's current environment, creator and
mode (`creator` or `principal`): when a replica of the same owner presents a
token for another enabled environment of the workspace, or its creator or
mode changed, the binding's environment and recorded creator and mode are
updated on that call, before it is served. A later disable, principal change
or creator-mapping change then retires the binding through the environment
it is in now, not the one it first enrolled in.

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
Releasing an older row while a newer live row of the same replica (same
tombstone key) exists in the workspace writes no tombstone, so it does not
fence that newer operation; releasing the newest row tombstones as usual.
A newer row whose release an admin revived counts the same way (the revive
stamps `revived_at` on it), so releasing an older row cannot undo the revive;
the replica is fenced again by releasing the row its next admitted call enrols.
Disconnecting Replicas disables every policy and releases its bindings first,
retires them, then removes the registered entries (or, on an explicit abandon,
leaves them at the provider; see above).

Policies, pending creators and the principal (migration 0067) are deleted
with their workspace. Tombstones are not: deleting a workspace tombstones
every environment-enrolled replica of it, live or retired (reason `workspace_deleted`)
and removes its environment-identity bindings in the same transaction, and
from migration 0069 a tombstone outlives its workspace with no workspace
attached, so those replicas stay refused, also when the organization is
connected in another workspace. A tombstone that outlived its workspace stays
in force: there is no in-product revive for it, matching the hosted
edition's tenant pin. A workspace with launch or bind records, released or
not, still answers 409 `in_use`. A replica is never reassigned
across workspaces: while any environment-identity record of it (in any state,
for example retired by a disconnect) exists in another workspace, admission
refuses it with 403 `replica_owned_elsewhere`; the workspace that enrolled it
first admits it again once it is re-connected. An API launch or bind that a
verified environment-MCP call reuses is pinned to its workspace the same way:
the first such call stamps the row with the token's issuer and organization
(never changed afterwards, kept through release and revive), so it counts as
that workspace's record for `replica_owned_elsewhere` and for the
`workspace_deleted` tombstone.

### Revoked provider access

When the provider answers 401 or 403 to any call made with the workspace's
Replicas key (discovery, the environment list, MCP entry listing or create,
replica get, create or history, sleep), Control sets an access-revoked latch
on the connection (migration 0070: `access_revoked_at`, kept from the first
refusal, and a Control-authored `access_error`; no provider body is stored).
A 5xx, a timeout or an unreadable answer proves nothing and changes nothing.
While the latch is set every token of the workspace is refused with 403
`replica_environment_not_enabled`. The latch clears on the next 2xx answer to
an environments list (a sync or `GET .../environments`) or on a successful
re-connect. Both are keyed to the stored key: a refusal latches only while
the stored key (its ciphertext) is still the one the refused call was made
with, and a 2xx clears the latch only for that key, so a late answer about a
key that a re-connect replaced neither latches nor clears the new one. The connection list (`GET .../remote-agent-connections`) and the
policy view report it as `accessRevoked: {since, error}`, and the policy view
shows each enabled environment as `access_revoked`, distinct from
`stale_connection` (a policy recorded for an earlier provider organization).

## Not yet covered

- Background history through the push-only producer/consumer contract.
- Webapp journeys and acceptance on an owned test instance.
