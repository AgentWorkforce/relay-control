# Remote agent migration from Cloud

Cloud cannot be retired on the strength of provider cards or catalog entries.
The replacement must own keys, provider calls, Relay identities, callbacks,
durable deliveries and history uploads. No route here forwards to Cloud.

## Current replacement support

| Provider | Settings / credentials | Relay operations in Control | History in Control |
| --- | --- | --- | --- |
| Factory | Existing webapp #117 adds keys and explicit existing-computer/chat binding controls | Existing Control Factory module; separate #75/#76 extend MCP/enrollment | Deferred; no transcript-upload proof from the connection card |
| Amp | Webapp card, connect, discover threads, bind/unbind, inspect deliveries, disconnect | Existing `src/amp`, gated by `SELFHOST_AMP_ENABLED` and the Amp process transport | Existing scheduler/parser, **inactive** without a push-only sessions-pipeline credential issuer; see `amp.md` |
| Capy | Validate projects access, encrypted workspace key, masked summary, replace/disconnect | Not ported: thread bindings, subscriptions, injection and spawn | Not ported |
| Replicas | Validate organization identity, encrypted workspace key, masked summary, replace/disconnect | Not ported: durable launches, helper capabilities, delivery reconciliation and cleanup | Not ported |
| Devin | Validate org/session read and management permission, encrypted workspace key, masked summary, replace/disconnect | Not ported: session message adapter | Not ported |
| Cursor Cloud | Validate key identity, encrypted workspace key, masked summary, replace/disconnect | Not ported: principal-bound agent bindings, launch and cleanup | Not ported |

This is **connection-management parity**, not full provider/runtime parity.
The connection API reports `connectionManagement`, `relayBinding` and
`historySync` separately. The latter two stay false for these four providers.
Saving their keys does not start jobs, install subscriptions or upload content.
The provider catalog's `implemented/configured/enabled` still describes the
Relay runtime, not saved credentials. Amp probes derive from the mounted module via existing Control PR #78; this
change does not duplicate that wiring.

## Connection API

The Capy/Replicas UI is owned by existing webapp #117. The complementary
webapp #118 adds Amp/Devin/Cursor and is stacked on that PR, without duplicate
Capy/Replicas cards. Native Control runtime ports must consume this credential
store and preserve its validation/fencing; do not add a second competing key.

All paths also accept the `/cloud` prefix. All replies are `no-store`.

- `GET /api/v1/workspaces/{workspaceId}/remote-agent-connections`: members
  receive descriptors, capability states and masked connection summaries.
- `POST /api/v1/workspaces/{workspaceId}/remote-agent-connections/{provider}`:
  owner/admin person token (`cli:auth`) or same-origin cookie; JSON `{key}`,
  plus `{orgId}` for Devin. Check the actual provider before storing.
- `DELETE` on that item removes the key. No key or encrypted envelope is
  returned by any public operation.

The existing webapp contracts are also served directly: `GET/PUT/DELETE
/api/v1/workspaces/{workspaceId}/capy/connection` uses `{key}` with masked
snake-case summaries; `GET/POST/DELETE /api/v1/workspaces/{workspaceId}/replicas`
uses `{api_key}` and the nullable camel-case connection/organization summary.
Those aliases share this same storage and authority checks. They do not enable
the provider runtime probes.

Providers are exactly `capy`, `replicas`, `devin`, `cursor-cloud`. Origins are
fixed in server source. Redirects and arbitrary origin/body overrides are
refused. Both membership and the current stored key are rechecked after
external validation; revocation or a concurrent saved-key change cannot be
overwritten by a stale provider response. Provider response bodies never appear
in errors or audit records. Replicas/Cursor/Devin account changes require an
explicit disconnect first. Credentials use the Control encryption keyring.
Migration `0038_remote_agent_connections.sql` must run before the new API
image; 0037 is reserved by the existing Factory enrollment PR.

Validation calls preserve Cloud's source contract at `8865fe718`: Capy
`GET /api/v1/projects`; Replicas versioned `GET /v1/whoami`; Cursor
`GET /v1/me`; Devin `GET /v3/organizations/{org}/sessions?first=1`, then the
zero-session management-scope probe documented in Cloud's
`packages/web/lib/devin/connection.ts`. The probe does not target a real
customer session. Requests and response-body reads share a 15-second signal.

## Required before deprecating Cloud

1. Port the provider-specific runtime paths above. Preserve their explicit
   person/workspace binding, idempotency keys, immutable Relay agent identity,
   scoped reply capabilities, unknown-outcome handling and partial cleanup.
   Connecting/disconnecting a key must eventually share the same fencing and
   cleanup with those runtimes. A generic key store is not that implementation.
2. Establish the pipeline-owned push-only history credential contract. A
   background job must not reuse a person's long-lived token or gain read
   authority as a shortcut. Wire each provider's native parser, upload queue,
   membership/generation rechecks, retry and erasure behavior to that issuer.
3. Move existing encrypted connections/bindings through a reviewed migration;
   keys are encrypted with different keyrings. Do not copy ciphertext as if it
   were portable, expose keys in the browser or reconnect every retained thread
   implicitly. Preserve queued/unknown deliveries and upload cursors.
4. Verify each provider using an authorized real account: connect, discover,
   explicitly bind/launch, Relay round trip, history visible through the normal
   dashboard/MCP caller, revoke/disconnect, and no access from another tenant.
   Verify replacement ingress/worker scheduling and the deployed image/config.
   Offline API fixtures and a successful build do not establish these facts.
5. Switch dashboard/API/webhook traffic and document rollback only after those
   checks. Remove Cloud dependencies and retire Cloud in a later explicit
   release. This change does not alter any deployment or existing Cloud key.
