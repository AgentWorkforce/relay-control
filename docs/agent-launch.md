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
- **Not** over an OAuth MCP connection: the tools are not registered there and
  `describe_capabilities` says why. Workspace API tokens and service tokens are
  refused at admission as before.

Every launch is sent as the owner's **launcher** participant, a hosted relay
agent named `launcher-<hash of the user id>`. It is never a person, a Desktop
identity or another chat's participant, so relinking or leaving a chat does
not strand a launch. `leave_relay` refuses to remove a participant that still
owns a launch that is not failed or released.

## Where a launch can go

Targets come from `GET /v1/nodes` on the install's Relaycast with **this
workspace's own Relaycast key**. A node enrolled in another workspace or
another installation is never listed and cannot be selected. Owners come from
`fleet_node_owners` rows for this workspace and its Relaycast workspace
(Agent Relay Desktop records them through `POST /api/v1/fleet/nodes/claim`
when its person signs in).

| Node | Allowed |
|---|---|
| Yours (you claimed it) | yes |
| A teammate's claimed node | only when it advertises `metadata.configured.teammates: true` ("Allow teammates to spawn here" in Agent Relay Desktop) |
| An unclaimed desktop, or an unclaimed node that states no `node_kind` | no |
| An unclaimed broker (`node_kind: "broker"`) | yes |

`list_relay_spawn_targets` ranks allowed first, then yours, then desktop
before broker, then free capacity and measured load.

## Using the tools

1. `list_relay_spawn_targets`: choose an `allowed` `target_node` and one of its
   `harnesses`.
2. `spawn_relay_agent` with `name`, `cli`, `target_node`, `task` (at most
   8,192 UTF-8 bytes), optional `worker_cwd` (literal absolute path) and a
   stable `idempotency_key`. `accepted` means dispatch receipt, not readiness.
   Refusals (`spawn_target_not_allowed`, `spawn_target_offline`,
   `spawn_target_unavailable`, `spawn_harness_unavailable`,
   `spawn_capacity_exceeded`) carry up to three allowed `alternatives`.
3. `get_relay_spawn_status` until `ready` (with the agent's address),
   `failed` or `unknown`.
4. `release_relay_agent` stops exactly that worker by its immutable id.

Clients must retain `Mcp-Session-Id`: a launch belongs to the MCP session that
started it, and another session (even the same person's) cannot read or
release it.

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
