# Native Replicas transport

Tracked by [Control #99](https://github.com/AgentWorkforce/relay-control/issues/99).
The first slice is an internal server transport, ported from Cloud
`902c95ea1bf001d0bbd9b83bda75797a9c316004`,
`packages/web/lib/replicas/client.ts`. It does not enable a runtime capability,
register tools/routes, create compute, acquire a credential or start a worker.
The existing `remote-agent-connections` store remains the sole credential source.
The owning service must resolve current person/workspace authorization before
calling this transport.

`src/replicas/runtime.ts` supports identity, environments, create/list/get,
message, history, exec and sleep/wake. The origin is fixed and redirects are
refused; API version `2026-10-07` is sent on every request. API resource IDs use
the UUID grammar already required by the pinned Cloud service. This does not
constrain Relaycast identity IDs, which remain opaque text. Returned object
and page identity must match the request; UUID casing does not change identity.
Unknown provider status strings remain readable, and transcript event payloads
are preserved for the later history projection.

Fetch and every body read share a 45-second operation deadline (the provider
exec request has a 30-second command budget). A caller may choose a shorter
budget. Decoded responses are limited to 2 MiB, and an ignored abort cannot keep
the caller waiting or retain a late response. No raw body, header, API key or
transport exception enters an error. Definitive HTTP refusals retain their
status even when their body is empty, HTML, oversized or stalled.

Writes are never automatically retried. A network failure, timeout, 5xx or
malformed successful acknowledgement is an unknown outcome; callers need durable
intent and reconciliation before replay. The pinned API client establishes no
provider-side create/message idempotency contract, so a locally stable request
ID must not be advertised as one. A lifecycle 204 is a bodyless command
acknowledgement, not proof of final sleep/wake state. Read that state separately.

## Remaining runtime work

- Current key-owner/tenant admission and principal-bound launch/binding custody.
- Durable create/message intent, unknown-outcome recovery and cleanup, without
  blind retries or adopting a name match as proof of ownership.
- Native worker/reply capabilities and signed callback delivery, preserving
  revocation and exact immutable Relay identity. Add Replicas binding markers
  to the generic-adoption exclusion before any identity registration is mounted.
- Background history through the separately reviewed push-only producer/consumer
  contract, with erasure and cursor fences.
- Webapp journeys and normal owned test-instance acceptance: actual native
  send/reply, history read, disconnect, unknown cleanup and cross-tenant denial.

Offline transport and causal tests prove source behavior only. No account or
runtime acceptance follows from this slice.
