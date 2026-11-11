# Agent instructions — relay-control

## Service ownership

`relay-control` is the identity, session and workspace credential control plane.
Read the matching [relayfile-control boundary](../relayfile-control/AGENTS.md)
when a change touches Flows or provider ingestion.

| Responsibility | Canonical owner |
| --- | --- |
| People, organizations, workspaces, membership, device/browser login, user sessions, workspace API credentials and introspection | `relay-control` |
| Session-history access/handoff, Desktop/MCP session control, messaging and remote-agent connections, workspace configuration and canonical credential storage | `relay-control` |
| Credential-broker server, run-bound subscription/Relayfile credential issuance and revocation, workspace Relaycast binding | `relay-control` |
| Flow definitions and source validation; runs, steps, events, logs, artifacts and storage; Flows worker enrollment, assignment and lifecycle | `relayfile-control` |
| Provider webhook ingress, integration bindings, durable envelope intake, deduplication, queues, retries, backpressure, dead letters and replay | `relayfile-control` |
| Hosted dashboard/UI, integration setup and the provider-readiness aggregation currently implemented in Cloud | `cloud` (UI ports in `relay-webapp` where implemented) |

Flows service changes belong in `../relayfile-control`, including validation
before saving a definition or accepting new inline source. Do not add a second
implementation here merely because an older copy is still checked out.

## The HTTP boundary

- This repo serves `POST /internal/v1/auth/introspect`. Keep identity, tenant,
  workspace, role, scope, audience, expiry and revocation authority here.
- This repo serves `/internal/v1/flows/credentials/*` through
  `src/flows-broker.ts`. Those paths remain here despite containing `flows`:
  they are the credential authority, not the Flow definitions/run service.
- `relayfile-control` owns the public `/api/v1/flows`, `/api/v1/workers` and
  `/api/v1/workflows` route families and their `/cloud/api/v1/...` aliases.
- Communicate through the documented HTTP contracts. Do not import sibling
  application source or query/write another service's database directly.
  Each service owns its migrations. Preserve workspace/run/reference binding,
  least-privilege scopes, audience checks and refusal-versus-outage behavior.
- A broker or introspection contract change needs corresponding consumer
  updates and contract coverage. See [the broker contract](docs/flows-relayfile-credential.md)
  and [the consumer seams](../relayfile-control/README.md#seams).

Flows worker enrollment tokens and encrypted, scoped run-credential caches
are Flow-domain state in `relayfile-control`. They do not move canonical user
sessions, provider logins or workspace credential storage out of this repo.

## Legacy code is not ownership

Some 0.5.x builds still mount legacy `src/flows` routes here. Their presence
is not a reason to mirror new Flows features or fixes into both repos.
A legacy compatibility patch must be separately justified by a verified active
deployment and a tracked cutover/retirement plan; never add it automatically
for parity. Do not delete or disable live handlers just to match this document.
Ingress routing, data migration and deployment are separate cutover work;
follow the existing release authority and preserve users' persisted data.

Before changing code, identify the owning domain, read its existing contract
and check the caller on the other side. Put the implementation in its owner;
change consumers only when the contract requires it. Keep both repos' boundary
instructions consistent when an explicitly agreed service move changes ownership.
