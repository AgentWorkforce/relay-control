# MCP OAuth protocol slice

`src/mcp/oauth/protocol.ts` ports the pure OAuth contract from Cloud
`1776499a2cd9a514809f86fd874ebf269fd0a6db`, `packages/web/lib/auth/mcp-oauth.ts`.
Companion design: [PR #25](https://github.com/AgentWorkforce/relay-control/pull/25).

The factory requires a configured public origin. `enabledResources` defaults to
empty; callers must list only the resources their modules actually serve. The
issuer remains `<origin>/cloud`, root `/mcp` stays at the root, and the Sessions
and Events resources keep their `/cloud/api/v1/mcp/…` audiences. Discovery and
consent use the same enabled-resource set. Only omitted scope gets baseline
access; an explicit scope with no supported resource permission fails with
`invalid_scope`, including `openid` alone. This factory does not mount routes
or alter `src/mcp/catalog.ts` or its four default tool groups.

`mountedEndpoints` separately declares which authorization, token, registration,
revocation and JWKS handlers are actually mounted; the default is none.
Discovery advertises only those endpoints and their associated capabilities.
`oidcEnabled` defaults to false and requires mounted authorization, token and
JWKS handlers plus caller-configured signing support. A discovery-only caller
cannot advertise unmounted OAuth endpoints, OIDC signing or identity scopes.
Protected-resource metadata names this issuer only when authorization and
token handlers are mounted. Caller-supplied configuration arrays are copied.

This slice covers public-client registration validation, PKCE S256, exact
client/redirect binding, resource scopes, optional OIDC scope/sector/nonce,
Grok name hints and continuation eligibility, authorization `iss`, and MCP
JSON-RPC bearer discovery/step-up challenges. A valid hint is a consent default;
grants retain the canonical audience without the hint. Eligibility for
continuation does not prove grant ownership; the store must check it.

Adaptations from Cloud: origin and enablement are explicit rather than global
edition/environment state; invalid/disabled resources fail closed; redirect
validation rejects even empty fragments and literal control characters;
registration accepts only public-client authentication; validation also checks
the supplied client's ID; challenge values are printable ASCII, with the
`Agent Relay` realm. Challenge URLs accept relative `IncomingMessage.url` values
against the configured origin and handle malformed URLs without throwing.
`/cloud/mcp` is not the canonical `/mcp` resource; transport rewrites must supply
the public path. Empty state is echoed, and nonce is evaluated only for granted
OIDC. OAuth response fields replace any stale callback values while unrelated
callback query parameters are preserved. Resource
canonicalization uses the same parser as consent so URL normalization cannot
turn a rejected hint/resource into an accepted token audience.

The module issues no tokens and does not authorize a user or tenant. OAuth
stores, consent routes, bearer admission, OIDC signing, pinned participants,
History delegation and the Events pump remain later integration work. Store
and route work waits for #20 and the multi-tenant access helpers; History uses
the separately agreed read-only `mcp-grant` proxy contract. No deployment or
client cutover is enabled by this slice.
