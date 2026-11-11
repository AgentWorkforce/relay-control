# Native Capy runtime port

Tracked by [Control #99](https://github.com/AgentWorkforce/relay-control/issues/99).

The first slice is `src/capy/runtime.ts`: a server-only Capy API transport
ported from Cloud `902c95ea1bf001d0bbd9b83bda75797a9c316004`,
`packages/web/lib/capy/client.ts`. It supports project discovery, thread lookup
and creation, transcript pages and idempotent message injection.

Requests use only `https://api.capy.ai/api/v1`, refuse redirects, bound decoded
responses to 2 MiB per operation and use one 15-second deadline across fetch,
body reads and the optional model fallback. A definitive missing-model 400 may
retry once with the original request/client key and the same deadline. Network
failures, malformed successful write replies and 5xx writes are uncertain
outcomes and never automatically replayed. Errors contain stable codes and
bounded retry hints, never provider bodies, tags or API keys.

This transport does not authenticate a person, resolve a workspace or look up
credentials. Its caller must do that. No public route, worker, binding or
runtime capability is enabled by adding it. Existing credential management
continues to use `remote-agent-connections`; there is no second key store or
user-configurable provider URL.

## Binding-owned identity registry (internal, not mounted)

`src/capy/bindings.ts` adds native person-side identity custody with migration
`0044_capy_bindings.sql`. It uses the existing encrypted connection and requires
the acting person to be its current owner and a live owner/admin. It proves
the key can see a thread before reserving that thread globally, then rechecks
the same key/Relay route before claiming a binding.

Registration intent is persisted before an external write. A lost response may
recover only the matching binding-owned immutable agent ID. An attempted
registration with no positive remote receipt stays unknown; it is never blindly
registered again or declared cleaned up from an absent roster entry alone.
The binding keeps its hosted token encrypted and never creates a participant
alias. `agentFor` rechecks live membership, key generation, Relay workspace,
immutable ID and ownership metadata before and after its remote check.
Remote verification outages return retryable errors rather than appearing as
missing or changed bindings. Measure this check's latency before mounting it.

Retirement increments the generation and clears usable identity credentials
before remote cleanup. Cleanup uses the live workspace admin key only while
the workspace still points to the original Relay route. Key rotation therefore
needs no per-binding credential copy. A moved route leaves a coded cleanup
obligation pending; cleanup never deletes a successor which reused the name.
The cleanup method is system-only; user entry points must call actor-scoped
retirement instead.
Lease expiry or a concurrent retirement/member/key change cannot finalize a
late registration. External waits are bounded; a timeout is not a claim that
the remote write was cancelled.

This registry is not mounted by the app and starts no worker. Runtime capability
remains false. Before mounting it, the delivery/lifecycle slice must add the
native `!managed && !oauth` resolver integration, member/workspace/key cleanup
hooks, routes, callback verification and durable delivery. In particular,
workspace deletion must drain retained identity-cleanup obligations before
removing referenced rows. No production caller writes binding rows yet.

OAuth `assertActor`/`pin` is unchanged. A future OAuth-bound Capy journey is a
separate admission/parity change, not an alias-table bypass in this registry.

## Required next slices

- Mount the person/workspace-scoped registry only with its complete native
  entry points, generation/revocation fences and cleanup integrations.
- Durable subscription/outbox delivery, explicit unknown-outcome reconciliation,
  disconnect/revocation fencing and partial cleanup.
- Native spawn, Relay/MCP entry points and Webapp controls using those services.
- History through the pipeline-owned background push-only grant, preserving
  membership/generation/erasure checks and upload cursors.
- Actual test-instance connect, bind, Relay round trip, history read, disconnect
  and cross-tenant denial. Offline transport tests are source proof only.
