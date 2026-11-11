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

## Required next slices

- Person/workspace-scoped bindings using the existing encrypted connection,
  current membership checks and immutable Relay identity.
- Durable subscription/outbox delivery, explicit unknown-outcome reconciliation,
  disconnect/revocation fencing and partial cleanup.
- Native spawn, Relay/MCP entry points and Webapp controls using those services.
- History through the pipeline-owned background push-only grant, preserving
  membership/generation/erasure checks and upload cursors.
- Actual test-instance connect, bind, Relay round trip, history read, disconnect
  and cross-tenant denial. Offline transport tests are source proof only.
