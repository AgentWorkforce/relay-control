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
2. `spawn_relay_agent` with `name`, `cli`, `target_node`, `task` (at most
   8,192 UTF-8 bytes), optional `worker_cwd` (literal absolute path) and a
   stable `idempotency_key`. `accepted` means dispatch receipt, not readiness.
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

Native clients must retain `Mcp-Session-Id`: their launches belong to that
session. OAuth launches belong to the exact grant and remain accessible after
MCP reconnects within that grant. A new consent grant cannot recover them.
Release workers before disconnecting. Revocation ends tool access immediately;
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
workspace, user, MCP session authority, Relaycast workspace and launcher.
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
