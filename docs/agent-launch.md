# Agent launches over MCP

With `launch` in `SELFHOST_FEATURES`, the shared-sessions MCP endpoint
(`/api/v1/mcp/shared-sessions`, also under `/cloud`) can start Codex, Claude
or any other harness a machine advertises, on **existing, live machines** in
the current workspace. It does not provision machines. The tools and their
arguments match hosted Agent Relay Cloud, so prompts and clients work
unchanged. The feature is off by default; with it off the tools are not
registered and `describe_capabilities` reports `can_launch: false` with the
setting that enables it.

## Who can launch

- A **current workspace owner or admin**. The role is read again on every MCP
  request, so a demotion takes effect on the next call. A member gets "Only
  current workspace owners and admins can manage agent launches."
- On a **person connection**: an Agent Relay CLI login (`cli:auth`), the
  dashboard session, or an Agent Relay Desktop provider credential. A
  managed Desktop chat, or a session linked with `join_relay desktop_address`,
  must still prove its Desktop identity or it launches nothing.
- An **OAuth MCP connection** may launch as the agent approved for its exact
  workspace grant, when the consenting person is currently an owner or admin.
  Grant revocation, credential expiry and demotion are checked on every call.
  Workspace API tokens and service tokens remain refused at admission.

Native launches are sent as the owner's **launcher** participant, a hosted relay
agent named `launcher-<hash of the user id>`. It is never a person, a Desktop
identity or another chat's participant, so relinking or leaving a chat does
not strand a launch. OAuth launches use the grant's immutable approved agent
instead; a different grant cannot inspect or release the old grant's launches.
`leave_relay` refuses to remove a participant that still
owns a launch that is not failed or released.

## Where a launch can go

Targets come from `GET /v1/nodes` on the install's Relaycast with **this
workspace's own Relaycast key**. A node enrolled in another workspace or
another installation is never listed and cannot be selected. Owners come from
`fleet_node_owners` rows for this workspace and its Relaycast workspace
(Agent Relay Desktop records them through `POST /api/v1/fleet/nodes/claim`
when its person signs in; on gate-only installs it claims by enrolled node
name, see
[relay-node-credential.md](relay-node-credential.md#claiming-the-node)).

| Node | Allowed |
|---|---|
| Yours (you claimed it) | yes |
| A teammate's claimed node | only when it advertises `metadata.configured.teammates: true` ("Allow teammates to spawn here" in Agent Relay Desktop) |
| An unclaimed desktop, or an unclaimed node that states no `node_kind` | no |
| An unclaimed broker (`node_kind: "broker"`) | yes |

`list_relay_spawn_targets` ranks allowed first, then yours, then desktop
before broker, then free capacity and measured load. With the memory policy
at `rank` or `enforce`, a target that would take the launch now (free slots
and memory) ranks above everything but permission; see [Free memory](#free-memory).

## Using the tools

1. `list_relay_spawn_targets`: choose an `allowed` `target_node` and one of its
   `harnesses`.
2. `spawn_relay_agent` with `name`, `cli`, `target_node` (a node id, or the
   name of exactly one live node; see [Target node input](#target-node-input)),
   `task` (at most
   8,192 UTF-8 bytes), optional `worker_cwd` (literal absolute path) and a
   stable `idempotency_key`. Optional `approval_profile` accepts `interactive`,
   `requester`, or `full_access`; omit it to preserve the node default. `accepted` means dispatch receipt, not readiness.
   Refusals (`spawn_target_not_allowed`, `spawn_target_offline`,
   `spawn_target_unavailable`, `spawn_harness_unavailable`,
   `spawn_capacity_exceeded`, `spawn_memory_low` (retryable; under the
   `enforce` memory policy only), and on gate-only installs `relaygate_denied`,
   `relaygate_classified` and `relaygate_unavailable`) carry up to three
   allowed `alternatives`. Only `relaygate_unavailable` of the relaygate
   codes is retryable; see [identity.md](identity.md), "Launch check".
   A launch made by a verified desktop-linked chat (a managed desktop call,
   or a session linked with `join_relay` `desktop_address`) also carries
   `requester_agent_id` and `requester_name`, the chat's own Relaycast
   identity, so the node treats that chat's DMs to the worker as native
   input alongside the launcher's; OAuth and unlinked sessions omit both.
3. `get_relay_spawn_status` until `ready` (with the agent's address),
   `failed` or `unknown`.
4. `release_relay_agent` stops exactly that worker by its immutable id.

## Target node input

`target_node` is free text: it is trimmed, then accepts 1 to 128 characters
with no control, format or line/paragraph separator characters (Unicode `Cc`,
`Cf`, `Zl`, `Zp`: bidi overrides, zero-width characters, U+2028/U+2029).

Relaycast keeps node names unique per workspace, and its spawn selector trims
the requested name and matches it exactly, case-sensitively, against stored
names of nodes in every state. This server always sends the stored name of the
node it resolved, so each node id seen in the page read reaches exactly one
machine.

- **Id first.** A value equal to a live node's id selects it; that launch never
  reads offline nodes. On a miss, nodes of every state are read: an offline
  node's id keeps its offline (or not-allowed) refusal and is never reread as
  another node's name. If that read is incomplete, a live name match is
  refused, since it might be an unseen node's id, and so is a value matching
  nothing (both still list the live ids and names):
  - the read failed, or answered anything but `{ nodes, next_cursor }`
    (including a bare array), logged as the counter-only
    `spawn_every_state_roster_failed`: `retryable: true`, try again or pass
    the node's id;
  - Relaycast reported another page (`next_cursor`): `retryable: false`, since
    the same roster gives the same answer; pass the node's id.
- **Past the live page.** A node that the every-state read shows as live but
  that is not on the live page (more than 100 live nodes) cannot be ranked or
  checked for capacity. By id or by name it is refused with
  `spawn_target_unavailable`, `retryable: true`: try again, or pass the id of
  a node from `list_relay_spawn_targets`.
- **Name fallback.** Otherwise the value is compared with node names of every
  state (Relaycast's selector matches stored names of every state), one entry
  per node id with the live page's view first, after trimming, NFC
  normalization, curly apostrophes (U+2018, U+2019, U+02BC) as a straight
  `'`, and lowercasing. It resolves only when exactly one node carries that
  key and the node is live (see the tiebreak below). Admission (permission,
  harness, capacity, memory) then runs on that node as it would for its id, and the receipt and
  journal record its id. A lone offline match keeps its offline (or
  not-allowed) refusal, so an offline node's own name never launches on a live
  look-alike; an offline node whose stored name is padded gets the
  padded-name refusal below instead.
- **Exact-name tiebreak.** When several nodes of any state share the key, the
  one whose stored name equals the trimmed value exactly (case-sensitive, byte
  for byte) is used if it is live: that is the node Relaycast's exact selector
  reaches. With a live `Studio` and an offline `studio`, `Studio` launches on
  the live node, while `studio` and `STUDIO` stay refused. The trade-off: a
  caller who types one variant's exact spelling gets that machine without
  being told a look-alike exists, in exchange for not refusing a value that
  names exactly one node to Relaycast. An exact match that is offline is never
  swapped for a live variant. If the every-state read is incomplete, a live
  exact match gets the could-not-read refusal above (retryable by its cause),
  not the ambiguity refusal.
- **Ambiguous names.** Otherwise several nodes of any state on that key are
  refused with `spawn_target_unavailable`, `retryable: false`, listing their
  `id (name)` pairs; pass one of those ids. Case or apostrophe variants are distinct
  machines to Relaycast, so a launch by either id is fine and live ones remain
  alternatives.
- **Padded names.** A node whose stored name has surrounding whitespace
  (`" lab "`) can never be reached by its own name, because the selector trims
  it. It is refused by id or by name, live or offline, `retryable: false`,
  asking the owner to rename it, and is never offered as an alternative.
- **No match.** Refused with `spawn_target_unavailable`, `retryable: false`,
  listing live ids and names in the message and in `valid_targets` (at most
  20, with an "(and N more; call list_relay_spawn_targets)" suffix; ambiguous
  matches are capped the same way).
- **Echoed text.** Node, machine and owner names and the ranking reason in
  refusal messages, `node`, `owner`, `alternatives`, `valid_targets` and
  `list_relay_spawn_targets` results come
  from the roster or user profiles, so control, format and separator
  characters in them are shown as `\u{...}` escapes. `node` is for display
  only: pass ids back as `target_node`.
- **Replayed failures.** Reusing the key of a failed launch returns its
  receipt with `alternatives` as of now, from the live read only (no
  every-state read), excluding the receipt's node by id however `target_node`
  was spelled. If that read fails, the receipt is returned without them.
- **Idempotency.** An `idempotency_key` covers the trimmed `target_node` as
  given, so reusing a key after switching from a node's name to its id (or to
  another spelling of its name) is refused as a different launch.
- **Limits.** Each roster read is one page of Relaycast's `GET /v1/nodes`.
  The live read (`status=online&limit=100`) sees at most 100 live nodes. The
  every-state read uses the paginated `history=true` contract (`{ nodes,
  next_cursor }`) at Relaycast's maximum `limit` of 500
  (`NODE_LIST_HISTORY_MAX_LIMIT`); a `next_cursor` means more nodes exist and
  the read is incomplete, as above. Relaycast has served that contract since
  `@relaycast/engine` 8.9.0; any other answer, including the older bare
  array, is treated as a failed read.
  Matching is only as complete as the page read: an id or name beyond it is
  not seen.

## Who can see and stop a launch

`get_relay_spawn_status`, `release_relay_agent` and a replayed
`idempotency_key` reach only launches you started:

- **Native connections** (CLI login, dashboard session, Desktop provider
  credential): a launch belongs to the person, the workspace, its Relaycast
  workspace and the person's launcher. It stays reachable from a later MCP
  session of the same person in the same workspace, so a client that restarts
  (and gets a new `Mcp-Session-Id`) can still check and stop the agents it
  started. Launches journaled before this rule, when ownership included the
  MCP session, are reachable the same way; no migration is needed. A client
  must still initialize MCP and keep `Mcp-Session-Id` within a session before
  it starts agents. Another person, even an owner or admin of the same
  workspace, another workspace and an OAuth connection get "This launch was
  not started by you in the current workspace." (native) or "This launch is
  not owned by this connection in the current workspace." (OAuth).
- **OAuth connections**: a launch belongs to the exact grant and its approved
  agent, and remains accessible after MCP reconnects within that grant. A new
  consent grant cannot recover it, and a native connection of the same person
  cannot reach it.

An `idempotency_key` reused from a later native session returns the earlier
receipt instead of sending a second launch, for launches made after this rule.
The key of a launch made before it is not recognised from a new session:
recover such a launch by its `spawn_id`, and do not resend it under the old
key. Without an `idempotency_key` the default key is per session and request,
so a new session never replays an earlier launch.

Release workers before disconnecting an OAuth grant. Revocation ends tool access immediately;
cleanup retains the launcher credentials while its journal has active or
unconfirmed launches. An operator must drain those workers and reconcile their
journal rows before the deferred cleanup can finish; it never marks a live
worker released merely because the grant was revoked.

## Free memory

Each relay node reports its free and total memory with every heartbeat.
`SELFHOST_SPAWN_MEMORY_POLICY` decides what that does (spec:
[specs/spawn-placement-memory.md](specs/spawn-placement-memory.md); the policy
is the shared `@agent-relay/spawn-placement` package, so Cloud judges memory
the same way):

| Mode | Effect |
|---|---|
| `off` | Today's behavior; targets carry no memory fields |
| `observe` (default) | Each target carries `memory` (tier, free, floor, need, agents that fit) and `admissible`; launches that `enforce` would refuse are logged as `spawn_memory_policy_shadow` (counts, no names) |
| `rank` | Also: a target that would take the launch ranks first, then by memory tier; alternatives only offer such targets |
| `enforce` | Also: a launch to a node without the memory is refused with `spawn_memory_low`, a memory snapshot and up to three alternatives (`retry_after_seconds` when there are none) |

A launch fits when the node's free memory, less launches still starting,
covers the harness's budget (claude and opencode 1.5 GiB, codex and grok
1 GiB, others 1.5 GiB) on top of a floor it keeps free (desktops: the larger
of 2 GiB and 10% of total; brokers: 1 GiB or 5%). A node with no agent limit
(`max_agents` 0) is full at `(total − floor) / 1 GiB` agents. A sample older
than 45 s, or none, never refuses a launch. Pass `harness` to
`list_relay_spawn_targets` to have memory judged for the harness you will
launch. A node itself enforcing memory at launch is a relay-node follow-up.

## Journal and failure handling

Each launch is written to `relay_spawns` before it is sent, bound to the
workspace, user, MCP authority, Relaycast workspace and launcher. The
authority is the OAuth grant on an OAuth connection and one fixed value on a
native one (it held the auth mode and the MCP session before launches survived
a restart);
native lookups do not compare it (see
[Who can see and stop a launch](#who-can-see-and-stop-a-launch)).
Repeating the same idempotency key returns the same receipt and never sends a
second launch; a key reused for a different request is refused. A lost or
5xx response leaves the row `unknown` rather than guessing. Readiness requires
the native invocation's caller and node to match and the registered worker's
`metadata.fleet` to name that invocation and node. Rows stay for audit after
failure or release. No upstream error text, token or workspace key is
returned by any tool.

## Enabling

Add `launch` to `SELFHOST_FEATURES` (chart: `selectedFeatures`). The install's
Relaycast must serve the native node and action API (relaycast-self-host
12.7.0 or later does). Desktops enroll their spawn node against that Relaycast
when their person signs in to this site.

### Approval profiles

Explicit profiles require a node release containing
[relay#2226](https://github.com/AgentWorkforce/relay/pull/2226) and the capability
advertisement from [relay#2270](https://github.com/AgentWorkforce/relay/pull/2270). Update the selected
nodes before relying on this field. Explicit profiles require the selected node
to advertise `relay:spawn-approval-profile:v1`; otherwise admission refuses with
`spawn_approval_profile_unsupported` before journaling or dispatch. Omitted profiles send no new field, preserve
the existing node default and keep pre-profile idempotency hashes unchanged.
Explicit profile changes under an existing key are refused as a different launch.

`interactive` excludes the spawning requester; the owner and independently
authorized workspace leaders retain access. `requester` also permits the
authenticated spawning agent to answer over Relay, subject to the node's
requester/native-input controls. `full_access` disables prompts only when the
machine owner enabled full access for that harness. The node enforces approval
authorization and competing answers; the control plane does not grant it.

On gate-only installs, an explicit `requester` launch also requires a verified
Desktop requester identity. Link it with `join_relay` and `desktop_address` first;
unlinked sessions are refused before reservation or dispatch. Existing receipts
remain recoverable and omitted profiles preserve the prior path.

The reservation audit and spawn/status receipts include `approval_profile`, or
`node_default` for omitted profiles and older rows. This records the requested
policy rather than proving what a node applied. A profile refusal from an older
or owner-restricted node is terminal for that receipt (`spawn_failed`,
`retryable: false`), with any allowed alternatives. Retain the original receipt
for investigation; only a new intentional launch uses a new key.

Hosted counterpart: [cloud#6421](https://github.com/AgentWorkforce/cloud/pull/6421).
