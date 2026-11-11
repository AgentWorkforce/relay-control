# Changelog

Notable changes to the self-hosted control plane. Dates and versions are
assigned at release.

## Unreleased

- Added: owner-only People drill-down behind a new `usage_people` feature:
  `GET /api/v1/organizations/{org}/usage/people`, `.../usage/people/{userId}/sessions`
  (a member's sessions with their recorded titles and summaries; no new
  generation) and `.../usage/people/audit`. Every drill-down writes an
  organization-level `usage.people.viewed` audit row. Unlike the v1 counts,
  this view shows member names and emails. Migration `0042_usage_people.sql`.
- Changed: with `SELFHOST_FEATURES` unset, `usage` and `usage_people` are now
  selected by default. An explicit list (including `""`) is still exact.
- Added: shared-session read audit. Every MCP shared-session read
  (`open_shared_sessions`, `search_shared_sessions`, `get_shared_session`,
  `get_shared_session_context`, `list_session_timings`), successful or failed,
  writes one append-only row to `shared_session_read_audit` (migration 0042):
  caller, identity kind (Desktop, hosted, OAuth), calling native chat and
  whether a signed proof verified it, tool, bounded query text or requested
  session, result count, and the returned sessions with their recorded
  owners. No transcript content. An audit write failure is logged and never
  fails the read. Workspace owners and admins export it with
  `GET /api/v1/workspaces/{workspace}/shared-session-read-audit` (JSON or
  CSV, time range, cursor pages). Kept until an operator deletes rows. See
  docs/shared-session-read-audit.md.

- Added: agent launches over the shared-sessions MCP endpoint, behind
  `SELFHOST_FEATURES=launch` (off by default). Registers
  `list_relay_spawn_targets`, `spawn_relay_agent`, `get_relay_spawn_status` and
  `release_relay_agent`; `describe_capabilities` reports `can_launch`. Current
  workspace owners and admins on a person connection (CLI login, browser
  session or Agent Relay Desktop) only; OAuth connections are refused.
  Targets are this workspace's own Relaycast nodes, and placement follows
  hosted Cloud (yours, a teammate's with "Allow teammates to spawn here",
  unclaimed brokers; never an unclaimed desktop). Launches are journaled in
  `relay_spawns` (migration 0041) before they are sent. See docs/agent-launch.md.

- Fixed: Agent Relay Desktop's browser links ("View on web", workspace setup,
  Relaycast upgrade, downloads, Amp connections) 404'd when the dashboard has
  its own host, because Desktop builds them on the API origin. A browser
  GET/HEAD to `/cloud/dashboard/...` or `/dashboard/...` on the API host now
  answers 302 (no-store, no-referrer) to the matching dashboard route on
  `SELFHOST_DASHBOARD_URL`: `sessions/<id>` to `?session=<id>[&source=]`,
  `/cloud/dashboard/settings` to `#/settings/workspace`, `/dashboard/settings`
  to `#/settings/connections`, `downloads` to `/downloads`, anything else to the
  dashboard root. Nothing changes when the dashboard shares the API origin.

- Added: owner-only usage counts, `GET /api/v1/organizations/{org}/usage?days=7|30|90`,
  behind a new `usage` value in `SELFHOST_FEATURES` (off by default). Returns
  per-day and total active users, sessions uploaded, searches and session
  summaries for the dashboard Usage page. Counts only. Sessions and summaries
  come from the read API (`/v1/sessions/activity`; summaries are `null` until
  the read API serves `/v1/sessions/summaries/activity`). Active users and
  first-page searches are recorded by Control while the feature is on, with
  users stored as an HMAC under a per-install secret. Migration
  `0040_usage_counters.sql`. See docs/usage.md.
- Added: first-time setup without email. `SELFHOST_SETUP_KEY[_FILE]` is a
  one-time setup key for the bootstrap admin (no default; generate one per
  install). While that admin has never signed in, `/login` offers
  "First-time setup: enter setup key"; a valid key asks for the admin's
  password and only then signs in, and is then spent. It expires 24 hours
  after the server first records it, is stored only as a SHA-256 hash, and
  wrong keys are audited and rate-limited. `POST /api/v1/installation/setup-key`
  (bootstrap bearer) mints a fresh one. `POST /api/v1/auth/password/setup-key`
  is the JSON form; `login-config` adds `setup_key`. Migration 0041.
- Added: temporary passwords. Owners (any member) and admins (members only)
  set one with `POST /api/v1/organizations/{id}/memberships/{userId}/temporary-password`,
  `POST .../invitations/{id}/temporary-password`, or `temporaryPassword: true`
  on `POST .../invitations`. Generated, returned once, argon2id-hashed, never
  emailed, single use, 72 hours by default. Login with one answers 403
  `password_change_required` and no session; `POST /api/v1/auth/password/change`
  sets the person's own password and signs in.
- Changed: `SELFHOST_SIGNIN_METHODS=password` no longer requires SMTP. Without
  it, register and reset answer 404 `email_not_configured` and the sign-in
  page hides their links; `login-config` adds `password_self_service`. With
  SMTP configured, behaviour is unchanged. `email_link` still requires SMTP.

- Added: direct-to-S3 session upload credentials,
  `POST /api/v1/workspaces/{ws}/relayhistory/upload-credentials`, behind
  `SELFHOST_HISTORY_UPLOAD_DIRECT` (`off` by default, `allowlist`, `on`). A
  bearer client holding `rth:sync` gets STS session credentials scoped to its
  own upload inbox prefix (`<keyRoot>/.upload-inbox/<org>/v1/ws=<ws>/u=<userHash>/`,
  create-only SSE-KMS PutObject) or presigned PUT URLs for the keys it names,
  plus a signed `v1.` privacy witness and its `witnessSeq`. Both responses
  carry `contract: relay-upload-inbox-v1` as their first field; the witness
  key is base64url of at least 32 bytes.
  No AWS SDK: AssumeRole runs over the STS query API on the existing SigV4
  helper. See docs/sessions-read-api.md.

## 0.5.11 (2026-11-11)

- Added: Microsoft sign-in ("Continue with Microsoft") for Outlook.com, Hotmail
  and Live personal accounts and Entra ID work or school accounts, as a second
  browser provider beside the generic OIDC one. Configured with
  `SELFHOST_MICROSOFT_CLIENT_ID`, `SELFHOST_MICROSOFT_CLIENT_SECRET[_FILE]`,
  `SELFHOST_MICROSOFT_TENANT` (default `common`) and
  `SELFHOST_MICROSOFT_REDIRECT_URL`; served at `/login/microsoft/start` and
  `/login/microsoft/callback`. A Microsoft email is trusted only for the
  personal-account tenant or when `xms_edov` is true. Invites to Microsoft
  addresses redeem through the Microsoft button and a different account is
  refused with the invite kept. `/cloud/api/auth/microsoft/start` bounces to
  the Microsoft start when configured; it and `/cloud/api/auth/google/start`
  otherwise land on the `/login` chooser. `login-config` and `auth/methods`
  publish a `microsoft` entry.
- Added: the analytics collector registers the `session-brief` vocabulary
  (`session_brief.tick_completed`) and accepts `/v1/coordination/overlaps` on
  the session read route enum.
- Fixed: every broker-originated answer on `/relay-node/v1` uses the Relaycast
  envelope (`{ok: true, data}` / `{ok: false, error: {code, message}}`) so
  Relaycast SDKs can decode the workspace answer and broker errors.

## 0.5.10 (2026-11-10)

- Added: `relay-node` purpose for workspace API tokens (`sh_wk_`) bound to a
  node name with fixed read/enroll scopes and a bounded lifetime, accepted only
  by the new `/relay-node/v1` broker, which serves an allow-listed set of
  Relaycast routes with the stored workspace key so a node host no longer
  needs that key. Migration 0039.
- Fixed: the server-rendered `/login` stacks the co-brand lockup flush left and
  uses the Agent Relay palette.

## 0.5.9 (2026-11-10)

- Added: Factory acquisition enrollment (default off). With Factory on and
  `SELFHOST_ACQUISITION_ORIGIN` set, connecting a Factory key mints one
  encrypted, never-returned `acquisition-operator` workspace token for the
  acquisition origin. Disconnect, rotate, owner removal and workspace cleanup
  drain it, and the worker revokes it. Adds
  `POST .../factory/connection/acquisition/{rotate,revoke}` and an `acquisition`
  field on the connection summary. Startup fails unless the origin is in
  `SELFHOST_INTROSPECT_AUDIENCES` and `RELAYCONTROL_INTROSPECT_SECRET` is set.
  Migration 0037.
- Added: Factory MCP tools `list_factory_sessions`, `bind_factory_session` and
  `unbind_factory_session` (owner/admin, person connections only), and
  `as=<factory agent>` resolution for send and read of the caller's own bound
  Factory agents, only when `SELFHOST_FACTORY_ENABLED` is on.
- Added: shared-cookie remote provider connection settings for Capy, Replicas,
  Devin and Cursor Cloud (migration 0038). Keys are checked against the provider
  and encrypted with the Control keyring; members receive masked summaries,
  while owner/admin people manage keys. This ports connection management only;
  provider Relay runtimes/history remain separate deprecation blockers listed
  in [the parity matrix](docs/remote-agent-parity.md).

- Added: `SELFHOST_INTROSPECT_OUTAGE_HOLD_MS` (default off) lets
  `POST /internal/v1/auth/introspect` answer a Desktop `sh_at_` token from its
  last active verdict, marked `held: true` with `exp` clamped, while the
  database is unreachable, so uploads survive short outages. Connection errors
  only; machine claims are never held. `GET /readyz` reports
  `introspection.outageHoldMs`.
- Fixed: analytics collector startup restores private committed-segment
  permissions after volume remounts, and refuses to listen if recovery fails.
- Added: the analytics collector accepts registered session ingest, reader and
  consumer producers with closed event vocabularies, scoped attribution and
  separate producer tokens.
- Fixed: local Flows run completion, failure and cancellation revoke the run's Relayfile credential atomically; assignment issuance racing a terminal transition cannot leave a new credential active.

## 0.5.8 (2026-11-09)

- Added: per-run, path-scoped Relayfile credentials for Flows workers
  (migration 0036, `flow_run_relayfile_credentials`). The broker's new
  `POST /internal/v1/flows/credentials/relayfile` action mints an opaque
  `sh_fr_` token scoped to the run's mount paths, with one active credential
  per run, a lifetime set by `SELFHOST_FLOWS_RELAYFILE_CREDENTIAL_TTL_MS`
  (default 12 h) and revocation by the existing run-end `revoke` action.
  Relayfile verifies it through `POST /internal/v1/auth/introspect`. Worker
  assignment payloads no longer carry an empty `relayfileToken`: without a
  credential the field is omitted and the run records a
  `run.relayfile_credential_unavailable` event. See
  [docs/flows-relayfile-credential.md](docs/flows-relayfile-credential.md).
- Added: `GET /api/v1/workspaces/{id}/sessions/members` returns the organization's member display names (`{ id, name }`, no email) without a History read, so a dashboard that lists sessions straight from the session read API can still name teammates instead of showing "Unknown teammate".
- Added: hosted MCP `join_relay desktop_address` links an MCP session to the
  caller's synced Agent Relay Desktop identity (migration 0035,
  `desktop_relay_session_bindings`), ported from Cloud. A linked session sends
  DMs and channel posts as that identity, so replies reach the Desktop natively
  instead of a hosted inbox; `as` still selects a hosted participant. Hosted
  `join_relay name` and `leave_relay` unlink, the link is dropped when a
  Desktop re-sync no longer lists the identity, and identity sync now reports
  `linked_mcp` / `linked_at` for linked identities. OAuth connections cannot
  link.

## 0.5.7 (2026-11-09)

- Fixed: the desktop sign-in workspace picker and consent screens now name
  both browser origins (API and dashboard) in `form-action` beside `'self'`
  and the loopback origin. The form action stays path-only, so the post
  always targets the page's own origin whichever host served it, and the
  policy no longer depends on which of the two origins the page was reached
  on.
- Fixed: after Approve on the desktop sign-in consent screen the page stayed
  put in Chromium browsers. The screen's Content-Security-Policy allowed
  `form-action 'self'` only, and Chromium applies form-action to the 303
  that answers the form post, so the redirect to the app's loopback listener
  was blocked. The consent page now also allows the validated loopback
  origin of the sign-in's `redirect_uri`.
- Fixed: the desktop sign-in consent token is now a shared single-use database
  record, so the approve/deny post may reach any Control replica and survives
  a rolling restart; before, it lived in one process's memory and failed with
  403 "Consent token is missing, used, or for another sign-in" when another
  replica answered. Adds migration `0034_desktop_consent_tokens` (table
  `desktop_consent_tokens`, only the token's sha256 is stored).

## 0.5.6 (2026-11-09)

- Fixed: the desktop browser sign-in consent screen was sent with
  `referrer-policy: no-referrer`, so browsers posted the person's decision with
  `Origin: null` and Control refused it with 403 "Cross-origin consent
  refused" on every install. The page now uses `referrer-policy: same-origin`;
  the handoff redirect still carries `no-referrer`.

## 0.5.5 (2026-11-09)

- Removed: the legacy RelayHistory exchange and RelayAuth integration
  (`RELAYAUTH_URL`, `RELAYAUTH_API_KEY`, `RELAYHISTORY_READ_API_URL`,
  `RELAYHISTORY_BACKEND=legacy`); self-hosted installs serve history only
  through the sessions pipeline.
- **Upgrade note:** `SESSION_READ_API_URL`, `SESSION_READ_API_PUBLIC_URL`,
  `SESSION_READ_API_SECRET` (or `_FILE`) and `RELAYCONTROL_INTROSPECT_SECRET`
  are now required, and `SELFHOST_INTROSPECT_AUDIENCES` must include the public
  read API origin. `RELAYHISTORY_BACKEND` may be unset or `native`;
  `RELAYHISTORY_URL`/`RELAYHISTORY_PUBLIC_URL` are accepted only as aliases
  equal to the read API values. Start-up refuses the removed variables by
  name. `POST .../relayhistory/session` no longer answers 501
  `sync_not_served`: `mode=sync` returns the caller's own token for the ingest
  edge. See [docs/sessions-read-api.md](docs/sessions-read-api.md).
- Added `RELAYCHIEF_CONTROL_RELAY_SECRET` and `POST /internal/v1/chief/workspaces/{id}/relay-agents`, which registers a chief as a Relaycast agent for relaychief-control.
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
- Fixed: `send_relay_message` to an exact machine address no longer sends both
  `to` and `address` to Relaycast, which refused the body with 400; the
  diagnostic now names `invalid_request`.
