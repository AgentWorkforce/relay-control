# Changelog

Notable changes to the self-hosted control plane. Dates and versions are
assigned at release.

## Unreleased

- Self-host licensing is gone. Control no longer reads `SELFHOST_LICENSE`,
  `SELFHOST_LICENSE_FILE` or a licence key, and never answers
  `feature_not_licensed`. `SELFHOST_FEATURES` alone turns Flows, Relayfile and
  Chief on; a feature that is not selected answers 403 `feature_not_enabled`.
  `GET /api/v1/license` is replaced by `GET /api/v1/capabilities`, `/readyz`
  drops its `license` field, and `SELFHOST_OPERATOR_CONTROLS` drops the
  `licence` mode (which already behaved as `off`, and still does as an
  unrecognised value). See [docs/features.md](docs/features.md).
- Hosted MCP OAuth connectors are now **on by default**. Set
  `SELFHOST_MCP_OAUTH=off` (or `false`/`0`) to disable them; `on`/`true`/`1`
  enable them explicitly, and any other spelling stops start-up.
  `SELFHOST_MCP_EVENTS` and `SELFHOST_MCP_EVENTS_PUMP` stay off by default and
  accept the same spellings. See [docs/mcp-oauth.md](docs/mcp-oauth.md).
- **Upgrade note:** installs that relied on MCP OAuth being implicitly off must
  now set `SELFHOST_MCP_OAUTH=off`. On by default exposes anonymous dynamic
  client registration, the root `/mcp` resource for OAuth bearers and the
  consent, token and revocation endpoints; refresh tokens last 30 days. Start-up
  logs `[selfhost-api] hosted MCP OAuth active` with those paths and the off
  switch. `off` hides the routes but keeps existing grants and pending cleanup
  records; they drain, and unexpired sessions work again, when it is turned on.
- The consent page shows where the code returns (`Returns to: <host>`), labels
  the client name as self-reported and no longer suggests a shared agent name.
  Registration refuses the product's reserved client names and names over 100
  characters. Attaching a new connection to one of the person's existing agents
  needs `attach_existing: true` (otherwise `409 agent_name_in_use`), and an
  agent still being released after a disconnect cannot be rejoined until its
  cleanup completes. Authorization errors redirect to the client only for a
  signed-in account; otherwise they answer locally with 400.
- New unavailable mode: a partial or invalid OIDC key set, or a public URL that
  cannot be an OAuth issuer, no longer stops the server. Every OAuth route
  answers `501 {"error":"mcp_oauth_unavailable","reason":...}` (reasons
  `oidc_signing_key`, `public_url`), `mcp_at_` bearers are refused with `401`,
  no cleanup worker starts and the reason is logged once at start-up.
- Connector cleanup no longer holds tenant locks across Relaycast calls,
  retries with exponential backoff (60 s doubling, capped at one hour), and
  completes records that retrying cannot fix. Migration 0032 adds the retry
  columns. The operator-only
  `POST /api/v1/organizations/{organizationId}/workspaces/{workspaceId}/mcp-oauth/abandon-cleanup`
  abandons cleanup that can never finish (audit action
  `mcp_oauth.cleanup_abandoned`). With `?revoke_live=true` it also revokes the
  workspace's live connections in the same transaction, so a workspace can be
  deleted while the module is off or unavailable; without it live connections
  must still be disconnected first.
- A workspace key that does not decrypt is retried and logged; cleanup ends as
  `decrypt_failed` only after 8 attempts. On a database without migration 0032
  the worker logs one hint and retries every five minutes.
- Registered clients with no connection or pending code are deleted after 24
  hours. Token, refresh and revocation requests never count against the
  registration limit. An unreadable MCP OIDC `_FILE` now gives unavailable
  mode (`oidc_signing_key`, naming only the variable) instead of stopping
  start-up.
