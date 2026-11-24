# Changelog

Notable changes to the self-hosted control plane. Dates and versions are
assigned at release.

## Unreleased

- Changed: `@agent-relay/events-shim` 18.14.0. `link_relay_wake` now refuses an `agent` that is not an Agent Relay agent name (the link is not made, and an existing link stays), where before Control stored such a name as null; the package also never shows a stored name that fails the check. The package allows at most 100 characters and Control's agent names 128, so a bound agent named with 101 to 128 characters links and works but its name shows as none. No migration.
- Changed: events-shim `events/stream` is bounded. One inbox may hold at most 4 open streams on a process; a fifth answers HTTP 429 with MCP Events' resource-exhausted JSON-RPC error (`-32025`, `retry-after: 30`), and `events/poll` is never limited by it. Streams carry `X-Accel-Buffering: no` so nginx passes frames through, and a write that fills the socket waits for it to drain for at most 30 s; a client that stops reading but keeps the connection open is then disconnected, so it can neither grow the buffer without bound nor hold a stream slot. docs/events-shim.md has the reverse-proxy settings. No migration.
- Added: an events-shim inbox's wake link keeps the Agent Relay agent name it was linked with (migration 0095, `events_shims.wake_agent`): the `agent` given to `link_relay_wake`, or the bound agent's name for an agent link. `watch_webhooks` and later calls now report `linked_agent`, a relink reports `replaced_agent`, and `GET /shims/current` reports `agent.wake_agent`, where before they were null after the linking call. A name that is not a valid agent name (letters, digits, dots, dashes, underscores; a leading @ dropped) is not kept. A link made without a valid name, or before 0095, still has none; unlinking clears it.
- Added: MCP Events (SEP-3415) on events-shim inboxes, from `@agent-relay/events-shim` 18.13.0 (relay#2250). An inbox's MCP URL answers `events/list`, `events/poll` and `events/stream`; `events/stream` responses are now written to the client as they come instead of buffered until the stream closes, and an open stream re-reads Postgres every 2 s. A new `mcp` webhook URL (`/h/<token>/mcp`) takes Standard Webhooks deliveries; `PUT /shims/current/secrets/mcp` with `{}` mints its `whsec_` secret. `GET /.well-known/mcp-webhook-receiver.json` at the origin root lists the webhook URL prefix while `events_shim` is selected (404 otherwise). Migration 0092 widens the `events_shim_events.mode` CHECK to allow `mcp`; without it every mcp delivery failed its insert. Same as hosted Cloud. Also from 18.11.0–18.12.0: `link_relay_wake` takes an optional `agent` (the Agent Relay name the link wakes) and answers `linked_agent` and, when it replaces another link, `replaced_agent`; `watch_webhooks` on a linked inbox names the linked agent instead of saying the inbox is set; `GET /shims/current` gains `agent.wake_agent`.
- Fixed: a native MCP connection (CLI login, dashboard session, Desktop provider credential) that restarted, and so got a new `Mcp-Session-Id`, could no longer check or stop the agents it had launched: `get_relay_spawn_status` and `release_relay_agent` answered "This launch is not owned by this connection in the current workspace." A native launch now belongs to the person, the workspace, its Relaycast workspace and the person's launcher, and stays reachable from a later session of the same person in the same workspace, including launches journaled before this change. New native rows store one fixed authority for every native auth mode. Another person (even an owner or admin of the same workspace), another workspace, another Relaycast workspace, another actor and any OAuth connection are still refused, now with "This launch was not started by you in the current workspace." on native connections. OAuth connections are unchanged: a launch belongs to the exact grant and approved agent, and idempotency keys hash exactly as before. A native `idempotency_key` reused from a later session returns the earlier receipt for launches made after this change; keys of launches made before it are not recognised from a new session (recover those by `spawn_id`). The invalid `spawn_id` refusal now reads "Use a spawn_id returned by spawn_relay_agent." No migration (docs/agent-launch.md).
- Added: Grok Bot routines can run Agent Relay Cloud's routine behaviour, behind `SELFHOST_GROK_ROUTINES_CLOUD_COPY` (default off; docs/grok-bot.md, "Cloud copy mode"). Cloud's routine prompt and reply policy are copied as is. Webhook and polling routines are supported, with an encrypted per-routine event log read through `get_event` and `get_recent_events`. A webhook routine gets one wake per direct message or channel mention. Behaviour is per routine: one saved before the flag keeps its inbox-batch wakes. Sender trust comes only from rows this service owns. Changed with the flag off too: every routine save now stores a hash of the routine URL, and saving a routine URL that another connection on this server already holds is refused. Migration 0093.
- Changed: when read token mints carry the reader kind (relaygate installs; docs/sessions-read-api.md, "Session access"), surfaces that name sessions show only sessions the caller may read. In MCP `list_team_activity` every agent stays listed, but an agent's declared `session_id`, `session_kind` and `session_attribution` are shown, to an owner, admin or member alike, only when the caller's own read token can read that session; otherwise they are null, the agent is not sampled for activity, and nothing says a claim was hidden. An OAuth assistant connection with `relay:history` sees the claims its person can read; one without it, or any other caller that does not read with a person's read token, sees none. At most 40 sessions are checked per call, 4 at a time, within the existing deadline. In the shared-session read audit export, an owner or admin who is a session access administrator gets the export unchanged; any other owner or admin gets session ids and owners only for sessions it can read, the rest null, with `restricted` on each record of such a page and a last `restricted` CSV column (at most 100 ids per page, 15 seconds). `GET /api/v1/capabilities` adds `session_access`, true when session access management is configured. Session hard delete is unchanged: its target and receipt carry no owner, title or content. Unchanged when mints do not carry the reader kind. No migration.
- Added: session access management on relaygate installs (docs/sessions-read-api.md, "Session access"). A session access administrator, as relaygate decides, can see and change who may read one session through the MCP tools `get_session_access`, `set_session_access`, `reset_session_access` and `get_session_access_history` (group `session_access`) and the dashboard routes `GET|PATCH /api/v1/workspaces/{ws}/sessions/{id}/access`, `POST .../access/reset` and `GET .../access/history` (also under `/cloud`). On only when read token mints carry the reader kind (`SESSION_READ_MINT_INCLUDE_READER_KIND=true`, or unset with `SELFHOST_RELAYGATE_PUBLIC_URL` set) and `SESSION_READ_API_MCP_READS=true`, with the session read API URL pointing at relaygate's sessions listener; otherwise the tools are not listed and the routes answer `404 session_access_not_configured`. Control forwards with the acting person's own read token and stores nothing. `members` and `groups` replace the current lists rather than merging; member emails resolve to current members of the organization and any unknown email refuses the whole change before anything is sent; only user ids go upstream. Every change and reset needs a `reason` and is version-checked: a stale version is a conflict, never retried, and a write whose answer was lost is reported as an unknown outcome (`504 session_access_outcome_unknown`). relaygate answers 403 to a caller who is not a session access administrator before it looks the session up, so 403 says nothing about whether the session exists; an administrator gets 404 only for an unknown session and may manage a session they cannot read. A former member's entry is shown as `member: false`. Each history row keeps relaygate's `actor_id` and `actor_name` and adds `actor`: the Control person when `actor_name` is `ctl:<userId>` (email and name for a current member, `member: false` otherwise), or null; user ids in `before` and `after` resolve the same way, and `before` is null on a session's first change. Not offered to OAuth connections, Desktop provider credentials, staff read grants or agent identity tokens. A cookie-carried change needs an allowed Origin. No migration.
- Added: optional `SESSION_READ_MINT_INCLUDE_READER_KIND` (`true` or `false`; anything else fails startup) decides whether read token mints carry `reader_kind`. Unset or empty keeps today's rule (sent exactly when `SELFHOST_RELAYGATE_PUBLIC_URL` is set); an explicit value wins in both directions. A site that routes only the internal session read API through relaygate, without a public relaygate URL, sets it to `true` so relaygate policy rules using `readerKinds` can match; without it such rules match nothing. The receiving service must accept or strip the field. No migration.
- Added: owner-named trusted delegates, the self-hosted twin of Cloud's surface (relay `docs/design/owner-trusted-delegates.md` §16; docs/owner-delegates.md). A person grants one of their bound agents (Desktop identity, hosted participant, ready spawn, or a bot bound through a 10-minute one-time claim code) the right to relay their approval for named action classes and targets until an expiry. Grant, claim, tier O approval, audit, policy and target-owner routes under `/api/v1/workspaces/{ws}/delegates` take only a browser session or a verified Agent Relay Desktop bearer (either is enough for every owner action; no step-up). `POST .../messaging/delegation` attests one approval in one message to one recipient: the sender id and approval come from Relaycast's by-message delivery proof, and the result is an Ed25519 JWS (300 s) verifiable against `/.well-known/relay-delegation-keys.json`. `.../delegation/redeem` consumes single-use approvals atomically and checks `not_before` conditions. `.../delegation/prompt-delegates` lists a session's `prompt_approval` delegates. Classes include `prompt_approval` (answer a core permission prompt) and `config_change` (one exact setting of the recipient's own session, single-use; never its delegation settings). No class needs an owner-minted approval by default. Agents redeem before every action, with single use counted per action. `DELETE .../delegates/approvals/{id}` lets an owner revoke one approval, and `POST .../messaging/delegation/withdraw` lets the delegate that sent it withdraw it. Signed claims carry the quote; the audit log keeps a keyed HMAC digest of it (`hmac-sha256:`, `SELFHOST_DELEGATION_QUOTE_KEY`, optional), and `POST .../delegates/quotes/redact` lets an owner redact one message's quote at any time, here and (with `RELAYCAST_INTERNAL_SECRET`) in Relaycast. Paged audit reads (`after_id`) hold back the last 30 seconds. Every failure is a `none` verdict with a reason code, and every step is audited. Paths, bodies, status codes and response shapes, including the `{error, code}` refusal body, match Cloud's. Quote text in the delegation audit log is redacted to its digest after the org's `quote_retention_days` (1 to 3650, default 90), set by org owners and admins with `GET`/`PUT /api/v1/orgs/{org}/delegation-policy`. No workspace can override it. Off by default: an admin sets `delegation_enabled`, and attestation needs `SELFHOST_DELEGATION_SIGNING_KEY` and `SELFHOST_DELEGATION_SIGNING_KID`. Code-owner standing for repo targets and the GitHub conditions (`ci_green`, `head_sha`, `reviews_approved`, `mergeable`) fail closed, because relay-control has no verified GitHub account links. Gate-only installs report the feature unavailable (migration 0088).
- Added: an MCP OAuth assistant connection (ChatGPT, Grok Bot, Muse, any OAuth MCP client) acting as its approved agent may create at most 5 relay channels per agent per clock hour with `subscribe_relay_channel` `create: true`, as in Cloud. An assistant can be talked into creating channels by the posts it reads. The sixth creation in an hour is refused with `<agent> has created too many channels recently, so #<channel> was not created. …`; when the counter cannot be read, creation is refused (fail closed). Joining an existing channel is never limited, and neither is a person's own MCP session or a linked Desktop identity (migration 0087 `relay_channel_creations`).
- Added: MCP `read_relay_channel` reads thread replies, with the same arguments and result fields as Cloud. `thread_id` reads one thread instead of the channel's top-level posts: its `post` and `replies`, oldest first, paged with `after` (the result's `more_after`); a reply's ID reads its whole thread. `include_replies: true` adds each listed post's first 10 replies, with `replies_truncated` on a longer thread; threads are read five at a time, and a thread that fails to load is marked `replies_unavailable: true` on its post while the rest of the page still returns. Agents such as Grok Bot and Muse answer channel posts in threads, which the top-level read showed only as a reply count. A thread's root must be a post in the named channel the caller subscribed to; a thread in another channel, a DM or a missing message is refused without its contents. Gated participants read through relaygate (Relaycast `GET /v1/messages/{id}/replies`). No migration.
- Fixed: the server built the Grok routines service without the relaygate client or the Cursor cloud run identity setting, because only the instance `createApp` builds itself had them. On a gate-only install a Grok routine participant enrolled through relaygate failed every wake-up scan with `identity_unavailable` and was never enrolled again, and with `SELFHOST_CURSOR_CLOUD_RUN_IDENTITY=required` a cursor-cloud grant could still start routine setup. The server and `createApp` now build the service from one shared function (`grokRoutinesOptions`), so a gate-only install wakes Grok routines and a required run identity refuses routine setup for cursor-cloud grants. No migration.
- Changed: MCP `spawn_relay_agent` `target_node` accepts the name of exactly one live node as well as a node id. The value is trimmed and may be free text of 1 to 128 characters without control, format or line/paragraph separator characters. Ids match first over live and offline nodes (an offline id keeps its offline refusal); on a miss, node names of every state are compared after NFC normalization, curly apostrophes as straight ones and lowercasing, and the value resolves only when exactly one node carries that key and it is live (a lone offline match keeps its offline refusal). When several nodes share the key, the one whose stored name equals the trimmed value exactly (case-sensitive) is used if live; otherwise they are refused as ambiguous (`retryable: false`, listing their ids); no match is refused with `valid_targets`, and is retryable only when the every-state read failed; when that read reports another page (`history=true` at Relaycast's maximum `limit` of 500, `next_cursor` set) a name match or a miss is refused permanently, asking for the node's id. Any other answer to that read, including a bare array, is treated as a failed read. A live node seen only in the every-state read (past the 100-node live page) is refused as retryable. Replaying a failed launch's key now returns current `alternatives` from the live read, excluding the receipt's node. A node whose stored name has surrounding whitespace is refused by id or by name, live or offline, and never offered as an alternative. Admission runs on the resolved node, receipts and the journal record its id, and an idempotency key covers the trimmed value as given, so switching between a name and an id is a different launch. Roster and profile text echoed in refusals, alternatives and `list_relay_spawn_targets` shows control and format characters as `\u{...}` escapes. No migration (docs/agent-launch.md).
- Added: workspace agent identity tokens (migration 0086; docs/identity.md). An owner or admin mints a `sh_wk_` token of purpose `agent-identity` with an `agentName` on the existing deployment-api-tokens route. It has the single scope `relay:agent` and always expires (1 to 365 days, default 90). The agent presents it as a header bearer on the shared-sessions MCP facade and reaches only the Relay messaging tools and `describe_capabilities`, as its own named agent, never as a person. Minting again with the same name rotates: the agent keeps its Relay participant and older tokens stay live until revoked. A name a person's participant, a linked Desktop agent or another agent on the workspace's Relaycast roster already uses is `409 name_taken`; the roster is read before the mint (not atomically with it; the agent's join refuses a name it does not own), a workspace without a Relaycast binding is bound by the route's owner/admin access check first (or answers `503 relaycast_not_ready` when it cannot be provisioned), and an unreadable roster is `503 relay_unavailable` with `Retry-After: 5` and writes nothing. A person's `join_relay` under an identity's name, in any letter case, is refused, and MCP OAuth consent reports that name as taken. Every other route and MCP path refuses the token. Gate-only installs do not support it yet.
- Added: optional `SELFHOST_EXTRA_SITES`, a comma-separated list (at most 8) of `<dashboard origin>|<API origin>` https pairs for more public host sets in front of the same deployment. Their origins join the browser origin allowlist (sign-in, consent and every cookie-authenticated write, including Amp and Replicas), Host-selected answers (Desktop/CLI `api_url`/`apiUrl`/`verification_uri`, emailed links) name the site the request arrived on, a device approval link or Desktop dashboard link opens that site's dashboard, and an integrations `returnTo` on its dashboard origin is accepted. A host may belong to one site only; startup fails otherwise. MCP OAuth issuer and resources, invite and citation links, the Flows run URL, the integrations OAuth callback and the session read API URL stay single-origin, and cookies stay host-only. Unset: unchanged. No migration.
- Fixed: MCP OAuth clients whose every redirect URI is a Google Connected Apps callback (`oauth-redirect`, `oauth-redirect-sandbox` or `oauth-redirect-test` on `googleusercontent.com`, single `/r/<id>` or `/a/<id>` segment) get the stable refresh token Google requires: refresh returns the presented refresh token, extends its expiry to 30 days after that refresh and issues the new access token as a linked session row, so earlier access tokens stay valid until their own expiry. Expired linked rows are deleted on the next refresh, and their tokens never refresh. Revoking the refresh token or the grant ends every linked access token; a replayed continuation code revokes its session and its linked rows, and continuation detection counts only code-issued sessions. Every other client keeps rotation. Each such refresh logs outcome `extended` (migration 0085 `mcp_oauth_sessions.parent_session_id`; docs/mcp-oauth.md).
- Fixed: hosted MCP Relaycast and relaygate calls made while the per-owner lock transaction is open (participant verification, registration, token recovery, and the releases when leaving or linking a Desktop identity) now share a 10-second budget per lock, counted from when the locks are held; a call started after the budget is spent is refused without being sent. A stalled upstream no longer holds the owner's locks, which blocked that user's OAuth token refresh and other relay calls. A timed-out write is reported with the existing wording: unknown outcome for joins and sends, and a retryable failure for `leave_relay` (the participant is kept and a retry completes the leave). Sends, inbox reads and launches run after the lock and are unchanged. A Relaycast answer whose body is lost mid-read is now reported as an unknown outcome instead of an unlabelled error. No migration.
- Fixed: an MCP OAuth refresh whose response never reached the client no longer revokes the connection when the client retries with its retired refresh token more than 30 seconds later. While the exact pair that token was rotated into has never been used as a bearer token, the server rotates that pair again and returns the new pair on the same grant and approved agent, for up to 36 hours after the first rotation and never past the retired token's own expiry; the re-issued pair keeps its refresh expiry. A retry within 30 seconds of a recovery is refused without revoking, like a retry within 30 seconds of the rotation. Reuse after the successor pair was used still revokes the grant. Bearer admission records first use of each pair (`mcp_oauth_sessions.current_pair_used_at`) and each rotation records its successor on the retired token. Revoking a retired refresh token at the revocation endpoint now ends its grant. Rotations made before the upgrade are not recoverable. Each refresh logs one `mcp_oauth_refresh` line with outcome, grant ID, reason and seconds since retirement, never a token, hash, user ID or agent name (migration 0084; docs/mcp-oauth.md).
- Added: optional `SELFHOST_ROUTED_SITE_URL` (an https origin) for a deployment reached through an edge router on another site origin. When a request carries exactly one `x-original-host` header naming that origin's host, the Desktop/CLI sign-in answers (browser handoff `api_url`, desktop session, workspace switch, device start `verification_uri`, device and enrollment token `api_url`, and refresh `apiUrl`) name it instead of the Host-selected origin, so a Desktop that signed in through that site accepts them. The header only selects the configured value and is never echoed; emailed links, OIDC redirect URIs, the MCP endpoint URL, cookies and browser origin checks are unchanged. The router must overwrite `x-original-host`. Unset: unchanged. No migration.
- Added: a session bridge for organizations moved from Agent Relay Cloud (migration 0083; docs/identity.md). Off by default (`SELFHOST_CLOUD_BRIDGE_ENABLED`); while off its routes answer 404. Cloud signs a short-lived, single-use Ed25519 assertion for a browser with a live Cloud session and posts it to `/cloud/api/v1/auth/cloud-bridge/consume`; this deployment verifies it against `SELFHOST_CLOUD_BRIDGE_PUBLIC_KEYS` and issues its own browser session for the existing user (matched by id, never email) in an organization the operator listed with a time-boxed window (`/api/v1/installation/cloud-bridge/organizations`, bootstrap bearer only). It creates nothing, accepts no Cloud token, and is refused after the person signs out here.
- Fixed: MCP repository-filtered session summaries apply the first 200 characters of a repo-only filter in the session directory before pagination, while still accepting a 512-character repo value and verifying the full returned repository URL. This requires a sessions read API whose session directory list applies `projectContains` as a case-insensitive substring of project ID, catalog project key or recorded repository URL (directory migration `20261105034000` or later). Exact verification can still produce a short or empty page with a cursor. Relay agent listings now link an exact roster agent ID to its already-synced Desktop native session when the agent has no validated Relaycast session declaration. The optional session join is failure-open: the roster still returns a null session ID and attribution with `session_unavailable_reason` set to `enrichment_failed` or `ambiguous_sync`; an independently recorded metadata session kind is preserved. No migration.
- Changed: MCP `list_amp_threads` now returns `{ threads, truncated }` instead of a bare thread array. Clients that parse the old array must read the `threads` field; `truncated` truthfully reports whether Amp returned more than the first 100 threads by requesting one lookahead row.
- Changed: MCP `list_relay_agents` now returns the first at most 100 matching agents in relay order and adds `total_matching` and `truncated`; it previously returned the whole matching roster.
- Changed: MCP `get_session_summary` now returns `summary: { status: "unsupported" }` as a normal result when the selected backend records that status; it previously returned a tool error.
- Added: every MCP `list_session_summaries` row now includes `transcript_status: "not_verified"`, because directory publication does not prove that the transcript index is readable yet.
- Changed: on a managed Desktop connection whose synced identity cannot be verified, MCP `describe_capabilities` keeps `relay_messaging` available for `list_relay_agents` and `get_relay_agent_card` while listing every actor-dependent tool in `restricted_tools`, with the safe refusal reason or retry guidance.
- Fixed: `check_relay_inbox` bounds sender-address enrichment to one second and still returns pending messages with a null address when the lookup fails or stalls.
- Fixed: MCP `list_relay_agents` now bounds its upstream roster read at 10 seconds, `describe_capabilities` bounds managed native-identity verification at 2 seconds, and `relay_status` bounds optional exact-name address enrichment at 1 second while returning the status with a null address on lookup failure or timeout.
- Added: Cursor cloud agents can join Agent Relay as their own runs (migration 0081; docs/cursor-cloud-agents.md). A Cursor cloud agent connects with the person's OAuth grant from cursor.com/agents. It proves which run it is with a Cursor-signed OIDC token, minted in its VM for this server's audience and the grant's nonce, and verified against api.cursor.com's keys, once. It then joins with `join_relay` `cursor_identity_token` as `cursor-cloud-<hash>` and acts with `as`. The Cursor account must first be linked to the person: they confirm a one-time link in the browser, or the operator trusts their Cursor team (`SELFHOST_CURSOR_CLOUD_TRUSTED_TEAMS`) and the token carries their own email. `SELFHOST_CURSOR_CLOUD_RUN_IDENTITY=required` refuses the connection's shared agent. Revoking the connection releases its runs.
- Changed: OAuth connections with a `cursor.com/agents` callback are now the `cursor-cloud` connector kind (cards, relaygate `clients`), not `grok-bot`; x.ai callbacks stay `grok-bot`. Grok Bot routines work for both kinds. **On gate-only installs**, a Cursor-hosted Grok Bot that relaygate admitted as `grok-bot` re-enrols as `cursor-cloud` on next use. Add `"cursor-cloud"` to the relaygate rule that allows `"grok-bot"`.
- Changed: the MCP endpoint's `[selfhost-mcp] native chat context refused` log
  line now carries the response's correlation id (`correlation_id`, the same
  value as the `x-correlation-id` header and the error's
  `data.correlation_id`), a `stage` (`claude_attestation`,
  `copilot_attestation` or `desktop_context`) in place of `check`, and a fixed
  `reason` code (for example `unknown_key`, `tool_use_mismatch`, `expired`,
  `conflicting_context`, or `unclassified` for a message without a code) in
  place of the verifier's message. Operators who grep the old `check` or
  `reason` values need the new ones. The response is unchanged (400, -32602
  "Invalid native chat context.") and an attestation store failure is still a
  server error, never a refusal.
- Changed: every agent returned by MCP `list_relay_agents` now has a fetchable card. Older Desktop and launched agents without a published card get an explicitly `inferred` coordination purpose and skill; agents with published skills but no card text are `mixed`, and complete cards are `published`. `get_relay_agent_card` reports the same `cardSource`, while `owner` and `is_mine` prefer Control's verified Desktop, hosted-participant and ready-launch records over agent-written metadata. Clients that used `has_card` to distinguish published cards from no card must now read `card_source`. Truncated session titles and personas are no longer presented as published card purposes. No migration.
- Fixed: `list_team_activity` no longer holds the request open when Relaycast or History stall. The roster read is bounded at 10 seconds, the optional presence read at 2 seconds (after which the roster is returned with `presence_source: "unavailable"`), and all activity reads at 20 seconds in total; an agent whose read did not finish in time is returned with `activity_status: "unavailable"`.
- Fixed: `list_session_timings` now sends `user_id` to RelayHistory and, when a filtered page comes back empty, reads up to five pages before answering, so a member's sessions are no longer hidden behind an empty page with a cursor. `sessions_scanned` counts every page read. Each row now retains a safe `timing_unavailable_reason` (`read_failed`, `invalid_response`, or `identity_mismatch`) instead of collapsing every timing failure to an unexplained unavailable value.
- Fixed: MCP `list_session_timings` now reads each selected session's timing
  from the same per-user sessions reader as transcript search, the session
  directory and exact-session transcript reads. A Reader-only desktop session
  therefore no longer disappears into the legacy History path at the timing
  step. No setting or migration.
- Fixed: the analytics collector accepts the sessions read API route `/v1/sessions/users`. The reader has reported it since that route shipped, and the collector refused any batch that contained it. It also accepts the patterns `/v1/coordination/advisories` and `/v1/coordination/advisories/:advisoryId/ack`, so the reader can start naming them without a refused batch. No setting or migration; analytics stays off unless configured.
- Added: memory-aware agent launches (docs/specs/spawn-placement-memory.md). `list_relay_spawn_targets` takes an optional `harness` and, unless `SELFHOST_SPAWN_MEMORY_POLICY=off`, reports each target's `memory` (tier, free, floor, the harness's need, agents that fit, sample age) and `admissible`, with a memory clause in `why`; `describe_capabilities` reports `workspace.spawn_memory_policy`. The default `observe` changes no ranking or admission and logs what `enforce` would refuse. `rank` puts targets that would take the launch first and filters alternatives to them; `enforce` also refuses with retryable `spawn_memory_low`. The policy is the shared `@agent-relay/spawn-placement` package, so Cloud judges memory the same way; its golden fixtures run in this repo's tests. Placement moved from `src/mcp/relay-spawn-placement.ts` to `src/mcp/spawn-placement/`. No migration.
- Added: `SELFHOST_DEFAULT_SHARING_MODE` (`all` | `new` | `selected`) sets a deployment sharing mode served to callers whose organization has not saved one, and `SELFHOST_SHARING_MODE_OVERRIDE_ROLES` (`owner` and/or `admin`) leaves callers with those roles unlocked: their v1 policy omits `sharing_mode` and `sharing_mode_since`, and the v2 document serves the effective mode as `sections.capture.defaults.sharing_mode`. The organization-saved mode always wins. Applied per caller on `access/me`, the enrollment key exchange, introspection `capture_policy` (staff read grants as a member) and the upload-credentials revision check. Nothing is stored, no revision moves, and the organization policy routes and fleet view still show only what is stored. Both unset (the default), every response is unchanged. See docs/capture-policy.md.
- Added: `relayfacts_list` and `relayfacts_get` on the Agent Relay MCP. They read the sessions pipeline read API's `GET /v1/relayfacts` (topics with counts) and `GET /v1/relayfacts/{topic}` (one page of a topic as markdown, `page` passed back as its cursor) through the same reader as the shared-session tools: `workspace` is always the credential's workspace, and a response without the workspace attestation returns nothing. They store and write nothing. Until the read API serves relayfacts (`READ_API_RELAYFACTS_ENABLED` off), every 501 is a successful `status: "disabled"` result ("relayfacts disabled") with the upstream reason. OAuth connections need `relay:history`; staff read grants do not get them. The per-user session reader now passes relayfacts cursors through unchanged and reports a 501's upstream reason.
- Security: on a gate-only install (`SELFHOST_RELAYGATE_PUBLIC_URL` set), every
  hosted MCP participant now enrols at relaygate and its traffic, reads
  included, goes through relaygate. That covers native MCP sessions and OAuth
  connectors such as ChatGPT, Grok Bot, Muse and Cursor cloud agents. Before,
  they were registered in Relaycast with the workspace key and messaged
  around relaygate's policy (migration 0079). Control mints a one-time `sh_ht_`
  hosted credential that relaygate introspects as `relay_hosted` with the
  participant's client. relaygate admits hosted participants only through
  rules naming the hosted kind, so **operators must add a relaygate
  `controlPrincipals` rule per allowed client** (relaygate's "Hosted
  participants"). Without one, `join_relay` fails and names the rule. Existing
  participants are re-enrolled through relaygate on next use and keep their
  upstream agent, so OAuth connections keep working. OAuth connections can no
  longer launch agents on a gate-only install. A session with no relay
  identity must `join_relay` before listing agents or channels there. A name
  another owner or a provider binding holds is refused before any credential
  is minted, and relaygate's answer must be the checked agent, the owner's,
  or one relaygate registered itself. Each participant records the hosted
  clients relaygate admitted it for (`admitted_clients`, migration 0079); a
  connection of another kind enrols it again at relaygate as that kind first,
  which re-applies that rule's groups and revokes the earlier token, and a
  refusal leaves the participant as it was. The client is the connection's
  admission kind, from the redirect URIs its authorization codes were
  delivered to (index `mcp_oauth_codes_grant_idx`, migration 0079): a client
  that registers a provider's callback beside its own enrols as `mcp`. Grok Bot routines whose token relaygate rejects
  enrol again as `grok-bot` and adopt the token only for the same relaygate
  and upstream agent. A stored participant is enrolled again only while its
  own upstream agent still holds the name. See docs/identity.md, "Hosted
  participants on gate-only installs".
- Fixed: a Replicas launch or bind that never got a Relay identity no longer sits in `preparing`/`binding` forever. After 7 days the sync sweep abandons it (`gone`, audited `replicas.spawn.abandoned`). A replica Relay launched is put to sleep first; an existing chat is left awake. A failed sleep is retried no sooner than one hour later, and not at all while the connection is latched as refused. Rows with a Relay identity and environment identities are untouched.
- Added: MCP `get_session_summary` can read recorded short or long summaries
  of the requested kind and return validated optional provenance. It enforces
  320/16000 Unicode code-point bounds, preserves empty/unsupported responses,
  and never substitutes another kind, reader or transcript after refusal.
  Reader selection and authorization are unchanged; the selected backend must
  support the requested kind. See docs/session-summaries.md.
- Added: `spawn_relay_agent` launches made by a verified desktop-linked chat
  (a managed desktop call, or a session linked with `join_relay`
  `desktop_address`) send `requester_agent_id` and `requester_name` (the
  chat's own Relaycast identity) on the spawn invocation beside the launcher
  caller, so the node treats that chat's DMs to the worker as native input.
  OAuth and unlinked hosted sessions omit both. The requester is not stored
  and does not change the launch's idempotency.
- Fixed: a webhook inbox no longer loses a post when the `wait_for_webhook` listener dies between claiming it and handing it over (migration 0078, `@agent-relay/events-shim` leases). With `auto_ack: false` the posts stay unread under a 2-minute lease and a `claim_token`; `ack_webhook_events` (or the next wait's `ack_ids`) marks them read, `release_webhook_events` gives them back at once, and posts neither acknowledged nor released are offered again when the lease ends. Only the claim's token settles a lease, and relay wake forwards in flight are never touched. While a relay wake link works, no wait takes posts.
- Fixed: a webhook inbox's relay identity is no longer lost when releasing it fails or the server stops mid-release (migration 0077). Unlinking, relinking or the sweep now queues the identity in the same transaction that removes or replaces its link, and it leaves the queue only once released. The sweep retries the least recently attempted releases first, so one failing Relaycast workspace cannot hold up the others.
- Added: a webhook inbox can wake a bound cloud agent (migration 0076). With `events_shim` selected, the Agent Relay MCP's `link_webhook_inbox` lets a current owner or admin link an inbox they created to their own bound Amp thread, Replica or Capy binding. Each post then reaches that agent as a relay DM from the inbox's own relay identity, framed as untrusted webhook data with `@mentions` neutralised. `unlink_webhook_inbox` undoes it. Every forward re-checks the inbox, the binding row and generation, the relay agent id, the name's current holder and the Relaycast workspace, and marks the link broken if any changed. The minute sweep releases a deleted inbox's identity on the Relaycast workspace it was registered on. Capy links wake the thread once native Capy delivery is mounted. See docs/events-shim.md.
- Fixed: Desktop identity sync no longer drops the installation's attestation
  key when the `attestation_key` field is omitted. Agent Relay Desktop syncs
  its chats on launch before its key is loaded, and that sync deleted the
  registered key, so Claude Code, Copilot and Cursor chat calls failed with an
  unknown key until the next sync re-added it about a minute later. An omitted
  key now means unchanged; an explicit key replaces it and an explicit `null`
  removes it. An empty identity list still clears the source, key included.
- Fixed: `describe_capabilities` now says that Relay Connect rooms are not
  available on this self-hosted installation, that no setting enables them
  and that joining a public hosted Connect invite from Agent Relay Desktop is
  separate; it no longer files them under "not part of the self-hosted
  edition". No tools or routes change.
- Fixed: MCP failures carry matching correlation IDs in protocol error data or
  tool error text, response headers and operator logs. Admission and storage
  failures return safe protocol errors. Successful transcript bodies are not
  decoded or copied for diagnostics; existing messages and access checks stay
  unchanged. Unexpected failures still reach configured error telemetry, and
  their logs include only an allowlisted error class and the correlation ID.
- Fixed: MCP relay sends, inbox polls, `relay_status` and agent card reads no
  longer list the whole Relaycast roster to resolve one agent name or address.
  They use the engine's bounded `GET /v1/agents?names=` lookup (one call per
  send for the recipient, one for the sender's own address, one batch per inbox
  poll for the senders), keep only rows with the exact requested name so
  engines without the filter keep working, and never fall back to a
  full-roster read when the lookup fails. The bound takes effect with Relaycast
  engine 12.4.0 or later; older engines still answer with the roster.
- Added: `GET /api/v1/organizations/{org}/fleet` (docs/fleet.md) for owners
  and admins: members, 200 per page, with their Desktop machines (host name,
  client version, platform, enrollment key, managed, last seen, status) and
  each machine's `policyMatch` (`current`, `stale`, `unknown` or `mismatch`)
  against the workspace policy revision, page totals and, with
  `usage_people`, per-member usage. Every read writes a `fleet.viewed` audit
  row. No migration.
- Added: member self-mint of desktop enrollment keys at
  `POST /api/v1/me/enrollment-keys` (also under `/cloud`). A signed-in member
  mints a single-use key for their own next machine; the body takes only
  `label` and `expiryDays` (default and ceiling
  `SELFHOST_ENROLLMENT_SELF_MINT_MAX_DAYS`, 7). `mcpConsent` and
  `policyConsent` are inherited from the key that provisioned the calling
  session and never raised. At most 5 unexchanged keys per person
  (`409 self_mint_limit`) and 10 self-mints per hour (`429 rate_limited`).
  `SELFHOST_ENROLLMENT_SELF_RENEWAL=false` turns it off
  (`403 self_mint_disabled`); capabilities and login-config answer
  `enrollment_self_mint`. Audited `enrollment_key.self_mint`. The member's
  key list adds `maxUses`, `useCount` and `policyConsent`.
- Fixed: gate-only desktop identity sync no longer skips an identity whose
  upstream Relaycast card lacks `metadata.relaygate.agent_id` (relaygate only
  stamps it on first registration); the field is compared only when present
  and relaygate's whoami remains the proof. Each skipped identity now logs
  `desktop identity skipped` with the agent name, reason and failed check
  (never the token).
- Added: workspace leaders. `GET /api/v1/workspaces/{id}/leaders` (any
  member) and `PUT` (workspace owner/admin, `{"patterns": [...]}`, `[]`
  clears) proxy the Relaycast engine's `/v1/workspace/leaders` setting with the
  workspace key and answer `{leaders: [{name, agent_id}], patterns}`. At most
  64 patterns, each trimmed to 1..128 characters with no control characters,
  duplicates collapsed; `*` and `?` are the only wildcards. Writes are audited
  as `workspace_leaders.set`; an unreachable or failing engine is `502
  workspace_leaders_unavailable`. Not gated by `SELFHOST_OPERATOR_CONTROLS`;
  nothing is stored and no migration. See docs/workspace-leaders.md.
- Fixed: on gate-only installs (`SELFHOST_RELAYGATE_PUBLIC_URL` set), desktop
  identities enrolled at relaygate now verify and sync, so Cursor, Claude Code
  and Copilot attestation keys are stored. Desktop identity sync and every MCP
  call check the identity's `rg_` token with relaygate's `GET /v1/whoami`
  (agent id and name, plus the enrolling user once relaygate reports
  `user_id`) and compare the upstream Relaycast agent's
  `metadata.relaygate.agent_id` when present. MCP messaging as a desktop identity
  goes through relaygate. Before, Relaycast refused the `rg_` token, every
  identity was skipped `unverified`, the attestation key was dropped and
  attested MCP calls failed with "unknown key". No migration.
- Added: per-person desktop enrollment keys (migration 0074). A
  `desktop-enrollment` key takes `maxUses` (default 1, ceiling
  `SELFHOST_ENROLLMENT_MAX_USES`, default 50) and is exchanged once per
  machine until spent; expiry ceilings `SELFHOST_ENROLLMENT_MAX_DAYS` (30,
  single-use) and `SELFHOST_ENROLLMENT_MULTI_USE_MAX_DAYS` (90). A key minted
  with `policyConsent: "admin"` provisions managed sessions: the exchange
  response, `access/me` and introspection answer `managed: true`, and the
  exchange response adds `policy_revision` and the `workspace_policy`
  document. Token records list `maxUses`, `useCount` and `policyConsent`;
  the exchange audit target adds the use number and Desktop client version.
- Changed: when the MCP route refuses a `tools/call` with `Invalid native
  chat context.` (a Claude Code, Cursor or Copilot call proof that does not
  verify, or conflicting desktop call headers), the server log now names
  the failed check (`[selfhost-mcp] native chat context refused` with
  `check`, `reason`, `method`, `tool`, `provider`, `auth_mode`,
  `workspace_id`, `user_id`). The response is unchanged and the log never
  carries the proof, the token or the arguments.
- Added: workspace API token purpose `enrollment-operator` (`sh_wk_`, scope
  `enrollment:mint`, migration 0073). An owner or admin mints one; an MDM
  script presents it to mint `desktop-enrollment` keys, list them
  (`?purpose=desktop-enrollment`, its own keys only) and revoke its own keys,
  without a device sign-in. Any other purpose is `403
  enrollment_operator_scope`, another key is `404`, every other admin route
  still answers `401`, and introspection still answers `wrong-kind`. Keys
  record `mintedByTokenId`; audit rows use actor kind `token`.
- Added: workspace policy v2 (migration 0072, docs/workspace-policy.md). One
  versioned document with `capture`, `spawn`, `join`, `delivery` and
  `analytics` sections, each with `locked` and `defaults` tiers, plus a
  person-only `consent` list and `managed: false`. Served on access/me as
  `workspace_policy` (with server-computed `delivery.locked.admin_senders`
  while `inbound_default` is set) and on
  `GET|PUT|DELETE /api/v1/organizations/{org}/workspace-policy` behind the
  operator controls switch. A separate `workspace_revision` moves on every
  write; the capture policy `revision` moves only when capture settings
  change. User-token introspection answers carry `workspace_policy.revision`
  and `managed: false`.
- Added: opt-in OAuth scope `relay:history` on the shared-sessions MCP
  resource. A connection whose person approved it (its own consent line, never
  in the baseline grant, refused without `relay:mcp`) reads shared sessions
  through the server-side History reader with reader kind `mcp`; the OAuth
  token is never forwarded and never gains `rth:read`. Admission narrows to the
  live grant on every request, so revocation or losing the scope ends reads.
  Reads are audited with `auth_mode` `oauth`.
- Added: the dashboard session catalog route passes relaygate's owning-group
  label (`relaygate: {gid, label}`, from relaygate's `groupLabels` policy)
  through when the session read API is relaygate; only those two validated
  fields pass. Session list items already carried it unchanged.
- Added: Replicas failure paths (migration 0070). The environment MCP create
  intent is persisted on the policy and, while it is set, every sync or
  enable (startup run, periodic sync, the sync and enable routes, a plain
  `PUT .../environments/{id}`) is read-only and never sends the create again;
  it clears when a complete listing finds the entry or a create is definitely
  rejected. Operator recovery is the explicit, admin-only `retry_registration:
  true` flag on `PUT .../environments/{id}`: it retries the unresolved write
  (a create whose outcome is unknown) once a complete listing shows no entry,
  which is the precondition for re-sending, not proof that the earlier create
  failed; the operator accepts a possible duplicate entry the provider may
  surface later (audited `replicas.environment.registration_retried`). A replica with an owned
  launch or bind in the workspace is reused before a creator mapping or VM
  principal is required. Removing
  a creator mapping releases that creator's creator-acting bindings, and the
  periodic sync retries unfinished cleanup of released bindings with
  exponential backoff (1 minute to 1 hour). A 401 or 403 from Replicas on the
  stored key sets an access-revoked latch on the connection that refuses
  admission until an environments list succeeds or the connection is
  re-connected (`accessRevoked` on the connection list and policy view). A
  complete discovery listing that no longer shows an enabled environment
  fences it (`discovery_missing`) until it is listed again, and releasing an
  older row no longer fences a newer live operation of the same replica, or
  one whose release was revived; workspace deletion tombstones retired
  environment identities too, and an identity enrolled in another workspace
  is refused `replica_owned_elsewhere`; an API launch or bind reused by a
  verified environment-MCP call is pinned to its workspace the same way (the
  first call stamps its issuer and organization on the row), and a repeat
  launch with the same request id after a release and revive, or after that
  stamp, returns the original operation instead of a 409 or a new create.
  - A creator mapped to a former member no longer blocks a replica with an
    owned launch or bind in the workspace: that launch or bind is reused as
    its owner first; without one the call is still refused
    `replica_creator_not_allowed` (never moved to the principal, never
    recorded as a pending creator).
  - The create intent carries a generation (`create_attempt`, migration
    0070): a run clears only the intent it set itself, so a registration
    whose relist fails after an operator recovery sent its own create in
    between keeps that recovery's intent (`registration_unconfirmed`) and
    never creates again.
- Changed: storing a subscription login (device-login completion and
  operator imports) takes the per-credential refresh lock before the
  workspace lock, so it no longer deadlocks with a concurrent write-back.
  If a login for the same account is created concurrently it retries, and
  after three attempts answers `409 login_busy` (retry the sign-in).
  Operator imports pass the version they read and get `409
  login_version_conflict`, with nothing written, if the login changed.

- Added: Replicas tombstone retention, periodic sync and setup errors.
  Releasing a per-launch replica (`release_replica`, `DELETE
  .../replicas/spawns/{id}`) now writes a tombstone in the revoke
  transaction, and `recover_replica_spawn` with `revive: true` revives it; a
  release of an already released replica is a no-op, so a repeated release
  does not undo a revive.
  Deleting a workspace tombstones its live environment-enrolled replicas
  (`workspace_deleted`) and removes their bindings in the same transaction
  (launch and bind records still answer 409 `in_use`); migration 0069 keeps tombstones after their workspace
  is deleted (nullable `workspace_id`, `ON DELETE SET NULL`), admission refuses
  any matching tombstone. A tombstone that outlived its workspace stays in
  force: there is no in-product revive for it, matching the hosted edition's
  tenant pin. Control runs the environment sync at startup and every
  `SELFHOST_REPLICAS_SYNC_INTERVAL_SECONDS` (default 60, minimum 30, `0` off)
  for every connection whose all-environments default is on. The Replicas
  connect response adds `provisioning_error` (`replica_environment_setup_failed`,
  stage `environment_setup`, `retryable`, `environments`) when environment
  setup failed; the status stays 200 and the connection is kept. The
  environment MCP of a replica already launched or bound through the API in
  the same workspace now acts as that binding and its owner instead of
  answering 409 `replica_already_bound`; when the owner leaves the
  organization it is refused with `replica_creator_not_allowed`, never moved
  to the principal. An environment MCP call for a provider organization
  connected in more than one workspace is refused with 403
  `organization_shared` (was `replica_environment_not_enabled`), as Cloud.
- Added: environment-level Replicas MCP. `POST /api/v1/replicas/mcp` accepts
  only a Replicas `workspace_identity` token (RS256, issuer
  `SELFHOST_REPLICAS_IDENTITY_ISSUER`, default `https://api.replicas.dev`) and
  admits a replica only when its environment is enabled, it was not released,
  and it acts as a current member: its mapped creator, or else (no or unmapped
  creator) the workspace's explicit VM principal, set with `PUT
  /replicas/environment-principal` or `principalUserId` on enable and never
  derived from an email or the owner. A provider organization connected in
  more than one workspace is refused and cannot be enabled
  (`organizationShared`, `organization_shared`). The first call enrols one
  Relay identity per replica; tools are pull-only. A fresh connect (also
  after a disconnect) discovers, enables and registers every environment of
  the organization by default; a re-connect over an existing connection (key
  rotation) keeps the default and every opt-out and runs the sync semantics
  (the connect response adds `environmentSetup`; a partial failure is a
  per-environment status, never a failed connect), and
  `POST /replicas/environments/sync` enables environments discovered later.
  Owners and admins see policies, the principal and pending (unmapped)
  creators at `/replicas/environment-policies` and opt out per environment
  (`PUT /replicas/environments/{id}` with `enabled: false`, or `DELETE
  /replicas/environment-mcp` with `environmentIds`, shown as `optedOut`);
  sync and a re-connect never re-enable an opted-out environment but retry a
  default enable that failed or was refused. `DELETE /replicas/environment-mcp`
  with `{all: true}` turns the default off (no opt-out) and `POST` with
  `{all: true}` turns it back on and clears every opt-out, from the dashboard
  or the CLI. A ship created by the provider with no creator is
  admitted only as the explicit VM principal, re-checked on every admission
  and call. Registration reads existing entries first, reuses a
  matching one, never overwrites a conflicting one, and reads the entry back
  after a create (`registration_failed`, `registration_unconfirmed`). Changing
  the principal or mapping a creator releases the affected bindings, and
  disabling releases the environment's bindings, all without a tombstone; a
  Relay agent left by such a release whose cleanup failed is cleaned up on
  the replica's next call instead of blocking it. Release writes a tombstone; `recover_replica_spawn` with
  `revive: true` lifts it. The endpoint is rate limited per IP and answers 503
  when the issuer cannot be read. Migration 0067 (`all_environments`
  defaults to true; `opted_out` per policy). See
  [Replicas](docs/replicas.md).
- Fixed: staff read grants (`sh_sr_`) introspect active only through the
  History audience fence (the workspace's own History origin, else the
  configured History URL); every other introspection audience, including
  `SELFHOST_INTROSPECT_AUDIENCES`, answers inactive `audience`. A device-code
  login started by Agent Relay Desktop can no longer mint or list grants.
- Added: `users.signup_source` (migration 0068), where an account was
  created: `teams`, `flows` or `desktop` (hosted Cloud's values; the
  identity import's carry lands in a follow-up) or `mcp`. Control records `mcp` when a new person
  signs in (OIDC or email link) on the way back to MCP OAuth consent
  (`/cloud/oauth/authorize`, e.g. ChatGPT's Agent Relay app). Set once at
  creation; a later sign-in never rewrites it. Password sign-ups have no
  return path and stay unattributed. Nullable; existing accounts are NULL.
- Added: Replicas agent bridge behind `SELFHOST_REPLICAS_ENABLED` (default
  off). Owners and admins spawn, recover, bind and release Replicas agents
  through six MCP tools or the `/api/v1/workspaces/{ws}/replicas` routes. Each
  bound replica gets its own Relay identity, a scoped Agent Relay MCP server
  and reply helper installed through the provider exec API, and signed
  delivery of messages addressed to it. Release revokes the capability before
  cleanup. Migration 0065 `replica_spawns`. See [Replicas](docs/replicas.md).
- Added: workspace deletes reach relayfile-control (migration 0052). With
  `RELAYFILE_CONTROL_URL` and a dedicated `RELAYFILE_CONTROL_WORKSPACE_DELETE_SECRET`,
  deleting a workspace queues `DELETE /internal/v1/flows/workspaces/{id}` in
  the same transaction; a worker sends it and retries with backoff (30 s
  doubling to 1 h) until relayfile-control confirms (a 200 naming the
  workspace, or an authenticated 404 `flows_not_enabled`). Refusals, a bare
  404 and outages keep the row. Unset, nothing is queued; the legacy local Flows rows
  still cascade as before.
- Added: staff read grants (migration 0061, table `staff_read_grants`). An
  owner of the operator organization, on its domains when it has any, mints a
  short-lived `sh_sr_` credential (scope `rth:read`, at most 90 days, no
  refresh) for one customer workspace with
  `POST /api/v1/workspaces/{id}/staff-read-grants`, lists grants with `GET`
  and revokes with `DELETE .../{grantId}`; every non-staff caller gets `404`.
  The credential works only as a bearer on `/api/v1/mcp/shared-sessions`,
  reaches only the shared-session read tools and `describe_capabilities` of
  that workspace, and re-checks revocation, expiry and the staff rule on every
  request. Mint and revoke are audited (`staff_read_grant.minted`,
  `staff_read_grant.revoked`); reads appear in the shared-session read audit
  with `auth_mode` `staff_read_grant`. Introspection answers it as a
  `desktop-user` pinned to the workspace. See
  [Staff read grants](docs/staff-read-grants.md).
- Changed: credential-refresh transactions (subscription-login auth files and
  integration-connection OAuth tokens) now set
  `SET LOCAL idle_in_transaction_session_timeout = '60s'` and
  `SET LOCAL lock_timeout = '30s'`, so a provider token exchange is not killed
  mid-refresh by a shorter server default and a concurrent refresher waits at
  most 30 s for the per-credential lock.
- Added: on gate-only installs a member's signed-in Agent Relay Desktop can
  mint, list and revoke its own relay-node token at
  `/api/v1/workspaces/{id}/relay-node/self-tokens` (also under
  `/cloud/api/v1`). Only a redeemed Desktop session may call it
  (`403 desktop_session_required`); `SELFHOST_RELAY_NODE_SELF_MINT=false`
  turns it off (`403 self_mint_disabled`, default on). A node name belongs to
  one person (`409 node_name_taken`), at most 3 live tokens per person
  (`409 too_many_tokens`), 10 mints per hour (`429 rate_limited`), expiry at
  most 90 days. Audited `relay_node.token.self_minted` and
  `relay_node.token.self_revoked` with the Desktop host name. No migration.
- Added: on gate-only installs (`SELFHOST_RELAYGATE_PUBLIC_URL` set), Agent
  Relay Desktop claims its relay node at `POST /api/v1/fleet/nodes/claim` with
  `{workspaceId, nodeName}`: the proof is the node's enrolment through this
  Control (`relay_node_credentials`, a relay-node token minted in the
  workspace and bound to that name), and Relaycast is not asked. A
  `nodeToken` is refused with 400; a name that never enrolled here is 403
  `node_claim_refused`. Claim rules and release are unchanged. Unset, nothing
  changes. See docs/relay-node-credential.md.
- Added: on gate-only installs (`SELFHOST_RELAYGATE_PUBLIC_URL` set), relay
  nodes no longer hold their Relaycast node token. `POST /relay-node/v1/nodes`
  stores it sealed (migration 0059 `relay_node_credentials`), answers the host
  without it and presents it itself on re-enrolment; the node connects to the
  new `GET /relay-node/v1/ws` bridge (Bearer relay-node token), which relays
  the Relaycast node socket, attaches each launch's one-time credential to its
  spawn invocation as `input.launch_credential`, and does not forward
  `deliver` frames. Audited as `relay_node.socket.opened`,
  `relay_node.socket.closed` and `relay_node.launch_credential.attached`.
  Unset, nothing changes. See docs/relay-node-credential.md.
- Added: on gate-only installs (`SELFHOST_RELAYGATE_PUBLIC_URL` set) every
  Sessions read-token mint names the reader kind (`browser`, `device` or
  `mcp`) from how the caller authenticated, so relaygate can tell a person's
  own reads from agent reads on their behalf. Other installs send the same
  mint body as before. See [Sessions read API](docs/sessions-read-api.md).
- Added: on gate-only installs (`SELFHOST_RELAYGATE_PUBLIC_URL` set), every
  agent launch through `spawn_relay_agent` mints a one-time `sh_lt_` launch
  credential (10 minutes, bound to the workspace, node, agent name and
  launching user; migration 0060 `relay_launch_credentials`). relaygate
  introspects it at `POST /internal/v1/auth/introspect`, which answers
  principal_type `relay_launch` with `node_name` and `scopes`
  `["relay:agent:enrol"]` and burns it on the first active answer. It is
  stored sealed and never sent to Relaycast; the relay-node socket bridge
  delivers it to the node. Audited as `relay_launch.credential.issued` and
  `relay_launch.credential.redeemed`. Unset, nothing changes. See
  docs/identity.md.
- Added: on gate-only installs, `spawn_relay_agent` first asks relaygate's
  `POST /v1/check` (op `w` on `node:<workspace>/<node>`, content the exact
  task) with a scopeless 60-second `sh_at_` minted for the launching person
  and revoked right after. A denial refuses the launch with `relaygate_denied`
  or `relaygate_classified`, no answer with retryable `relaygate_unavailable`,
  before anything is journaled or sent. Unset, nothing changes.
- Added: GitHub App installation credentials with `SELFHOST_GITHUB_APP_ID`
  and `SELFHOST_GITHUB_APP_PRIVATE_KEY_FILE`. Imported connections retain
  their installation IDs and mint replacement tokens without reconnecting.
  OAuth connect and callbacks remain available alongside imported App rows.
  Tokens are cached encrypted; short database leases serialize App refreshes
  without holding a transaction across GitHub requests. Installation ownership
  is bound to one organization and can be shared by its workspaces.
  See [GitHub App credentials](docs/github-app-connections.md).
- Changed: connection edit versions include auth mode and installation ID;
  existing clients must refresh their opaque connection version once after upgrading.
- Added: `SELFHOST_RELAYGATE_PUBLIC_URL` (unset by default) for gate-only
  installs, where relaygate is the only public way into Relaycast. When set,
  `GET /api/v1/workspaces/{id}/resolve` answers `urls.relaygateUrl` (the
  configured origin) next to `urls.relaycastUrl`, and omits
  `relaycastApiKey`: the workspace-wide key would bypass the gate's policy,
  so no device receives it, and no `workspace.relaycast_key.resolved` audit
  row is written; the call is audited as `workspace.relaycast_key.withheld`.
  Desktop and iPad builds that require the key fail closed and report that the
  workspace shared no key. The CLI reads only `cloudWorkspaceId` from resolve
  and is unaffected. The events-shim temporary workspace
  (`POST /t/<mcp token>/workspace`) is also withheld (`404 not_found`), so
  `events-shim setup` on a machine not signed in here cannot start its own
  core. The person credential
  (`POST /api/v1/workspaces/{id}/messaging/identity/credential`) answers
  `403 gate_only` with both urls, registers no person identity on Relaycast
  (the desktop enrols its own name at relaygate `/v1/register` with its device
  token) and is audited as `workspace.person_credential.withheld`; the
  relay-node broker's enrol (`POST /relay-node/v1/nodes`) keeps the node
  token in Control (see the relay-node entry above), so no node token leaves. MCP join
  and spawn are unchanged (their participant tokens stay server-side).
  Person identities Control newly registers server-side (messaging
  conversation sends, support reply notices) are named with the `control-`
  prefix, which relaygate reserves, while existing identities keep their
  names. Unset, all of these are byte-for-byte as before. See docs/identity.md
  ("Gate-only installs").
- Added: `send_relay_message` results include `recipient_card` when the
  recipient has an agent card (`has_card`): `{ description, skills, version, updated_at, note }`, where `description` is null
  without card text and `skills` lists skill names. The field name and shape
  match Cloud's hosted MCP. It is read from the recipient lookup the send
  already makes, so there is no extra read. It is omitted when there is no
  card and can never fail a send. Card contents are the peer's own
  description: untrusted data, not instructions.
- Added: Google Cloud Storage for Desktop feed assets
  (`SELFHOST_DESKTOP_FEED_STORAGE=gcs`, `SELFHOST_DESKTOP_FEED_GCS_BUCKET`,
  `SELFHOST_DESKTOP_FEED_GCS_PREFIX`). Credentials come from the metadata
  server only (GKE Workload Identity); no static keys are read. Objects stay
  private: downloads stream through the service or use V4 signed URLs signed
  with IAM Credentials `signBlob`, which needs
  `roles/iam.serviceAccountTokenCreator` on the service account itself.
  Signers, the canonical-size limits and S3 storage are unchanged.

- Added: a persistent mounted-secret Ed25519 Desktop feed signer (`file`),
  reporting and enforcing a 65,536-byte canonical manifest limit so a full
  platform asset set can include macOS headless bundles and its installer.
  Existing KMS signing and its 4,096-byte limit remain unchanged.

- Added: `get_relay_message_status` for sender-scoped software acceptance,
  acknowledgement, correlated replies and protocol read markers. Older
  engines return confirmation unavailable rather than inferring delivery.
- Changed: with `SELFHOST_FEATURES=launch`, an OAuth MCP connection consented
  by a current owner/admin can launch as its exact grant's approved agent.
  Launches survive MCP reconnects within that grant; other grants cannot
  inspect or release them. The `relay:mcp` consent label, "Use available MCP
  tools in this workspace", is unchanged. Disconnect revokes access at once
  and defers launcher cleanup while active or unconfirmed launches remain.

- Added: desktop enrollment keys (migration 0050). An owner or admin mints a
  one-time `sh_ek_` key for an employee by email through the workspace API
  token routes (`purpose: "desktop-enrollment"`, 1-30 days, default 7,
  optional `mcpConsent: "admin"`); a new address gets a user and `member`
  membership (`membership.provision`). The installer exchanges the key once
  at `POST /api/v1/auth/enrollment/token` for a device session (rate limited
  per client address, audited `enrollment_key.exchange` with the address and
  host). With admin consent the session is Desktop-verified. Whoami shows
  `provisioning`; the employee can list and revoke their keys at
  `/api/v1/me/enrollment-keys`; revoking a key ends its sessions; removing a
  member revokes their keys and the sessions those provisioned. Spent keys
  list as `exchanged`; the token list takes `?purpose=`. Discovery: `enrollment_keys: true` in
  capabilities and login-config. The key is refused by every other gate.

- Added: MCP `get_relay_agent_card` and `set_relay_agent_card` (A2A agent
  cards, matching Cloud). Get returns any listed workspace agent's A2A 0.3.0
  card, built from its Relaycast agent record (`metadata.card`,
  `metadata.skills`), or a minimal `hasCard: false` card. Set writes only the
  caller's own identity (a managed chat's or linked Desktop identity, else the
  session's joined hosted participant; no target parameter) with a
  `PATCH /v1/agents/:name` that sends only `skills`, `card`, `kind`
  (`relay-desktop`, `hosted`, or an OAuth connector kind such as `chatgpt` or
  `grok-bot`) and `owner_name`, which Relaycast merges, so other metadata is
  kept. `list_relay_agents` entries gain `skills`
  (names, at most 10) and `has_card`; the coordination guidance asks agents to
  read cards before delegating and keep their own current. Card fields match
  Relaycast's `GET /v1/agents/:name/card` (kind from `metadata.kind`, owner
  from `metadata.owner_name`, where from `metadata.where`). Hosted
  participants are now registered with `kind: "hosted"` and `owner_name`.

- Added: plain MCP `list_session_summaries` and `get_session_summary` tools
  for recorded summaries, workspace-scoped citations and owners. List pages
  are bounded to 50; summaries are never synthesized from task titles or
  transcripts. Missing list summary fields stay null with explicit unsupported
  status; list requests opt in with `includeShortSummary=recorded`. Readers
  with that extension disabled and long summaries report unsupported. Both
  tools join the read audit.

- Added: `POST /api/v1/events-shim/t/<mcp token>/workspace`, each webhook
  inbox's temporary Agent Relay workspace for `events-shim setup` to run its
  own core on: created through Relaycast's internal admin API with a 7-day
  deadline that posts, agent calls and asking for it move back; Relaycast
  deletes it at the deadline. Needs `RELAYCAST_INTERNAL_SECRET` and a Relaycast
  with `POST /internal/workspaces/:id/expiry`. Migration 0048.

- Added: `agent-relay-selfhost-relaycast-rekey` (`--dry-run`, `--workspace`,
  `--undo <run-id>`), a one-shot Job that replaces every legacy Relaycast
  credential Control stores (workspace keys, agent tokens, events-shim wake
  tokens) with an `ar_` one before Relaycast moves to durable actors. Old
  ciphertexts are kept in `relaycast_rekey_backups` (migration 0049). See
  README, "Re-keying Relaycast credentials".

- Added: `agent-relay-selfhost-relaycast-rekey --purge <run-id> [--confirm]`
  deletes a run's `relaycast_rekey_backups` after the cutover. Without
  `--confirm` it only reports counts (live, changed, gone, restored).
  Workspace key rotations hold a per-Relaycast-workspace advisory lock, undo
  is checked up front and restores all or nothing, backups are deleted with
  their workspace, and the image links every package command onto `PATH`.

## 0.5.20 (2026-11-12)

- Added: `SELFHOST_DESKTOP_RELEASES_REPO` (owner/repository, unset by default)
  and `GET /api/v1/desktop/releases`: the latest release of a public GitHub
  releases repo, in the downloads card's manifest shape, with checksums from
  each asset's `.sha256` sidecar. Fixed GitHub hosts only, bounded, cached 5
  minutes, `release: null` on any upstream failure. For installs without the
  signed Desktop feed. See docs/desktop-feed.md, "GitHub releases source".

- Added: events shim, a webhook inbox that wakes an agent, behind a new
  `events_shim` feature (off by default). `POST /api/v1/events-shim/shims`
  (signed-in person, 20 per person per hour) returns an MCP URL, webhook URLs
  and a manage token; each post is stored and forwarded to the agent's own
  Agent Relay session webhook (Relaycast inbound hook) so Desktop wakes the
  session; without it the agent long-polls `wait_for_webhook`. Logic comes
  from `@agent-relay/events-shim` 18.2.0; storage is migration 0047
  (`events_shims`, `events_shim_posts`, `events_shim_events`). Wake links are
  limited to `SELFHOST_EVENTS_SHIM_RELAY_ORIGINS` (default the
  `RELAYCAST_PUBLIC_URL` origin). See docs/events-shim.md.

- Fixed: the Usage People table reported sessions as unavailable against the
  native read API (it asked for pages of 500; the directory list serves at
  most 200). People totals are now bounded: the read API aggregate
  `/v1/sessions/users` when it is served (one call per workspace), otherwise
  newest-first list pages of at most 200; at most 3 read API calls and 2
  seconds per load, then `truncated` (lower bounds); cached for 5 minutes.
  Drill-down summaries share the 2-second budget.

- Added: capture policy upload check. `POST .../relayhistory/upload-credentials`
  compares the caller's `X-Agent-Relay-Capture-Policy-Revision` with the
  organization's policy revision when the policy sets any key:
  `SELFHOST_CAPTURE_POLICY_UPLOADS=report` (default) logs a missing or older
  revision, `enforce` refuses it 409 `capture_policy_stale`. The policy now
  carries `sharing_mode_since` (migration 0044) while `sharing_mode` is `new`,
  served by the capture-policy routes and introspection, so the sessions
  pipeline can refuse sessions started before it. See docs/capture-policy.md.

- Added: token introspection answers for user tokens carry `capture_policy`,
  the organization's served capture policy (`{version, revision, settings}`,
  as `GET .../capture-policy` returns it), read in the same query as the
  token. The sessions pipeline uses it to enforce the policy server-side
  (`user_retroactive_delete: false` refuses a member's own Cloud delete)
  without keeping its own copy. See docs/capture-policy.md.

- Added: owner-only People drill-down behind a new `usage_people` feature:
  `GET /api/v1/organizations/{org}/usage/people`, `.../usage/people/{userId}/sessions`
  (a member's sessions with their recorded titles and summaries; no new
  generation) and `.../usage/people/audit`. Every drill-down page writes an
  organization-level `usage.people.viewed` audit row. Unlike the v1 counts,
  this view shows member names and emails. Migration `0043_usage_people.sql`.
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
- Added: S3-compatible stores for direct session uploads (for example a
  bundled MinIO). `SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT` names the origin
  upload clients reach and `SELFHOST_HISTORY_UPLOAD_INTERNAL_ENDPOINT`
  (default: the public endpoint) the origin Control reads privacy journals
  through. With a public endpoint Control signs path-style presigned PUT URLs
  with the store's dedicated issuer keys,
  `SELFHOST_HISTORY_UPLOAD_ACCESS_KEY_ID` /
  `SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY` (or `_FILE`, required, used only
  by the upload issuer so the process-wide AWS credential chain is untouched;
  `kind: "sts"` answers 501 `unsupported_by_backend`), the response
  `endpoint` is the client origin, `SELFHOST_HISTORY_UPLOAD_ROLE_ARN` must be
  unset and `SELFHOST_HISTORY_UPLOAD_KMS_KEY_ARN` becomes an optional opaque
  key id: when unset, `kmsKeyId` is null and no SSE-KMS headers are signed.
  AWS S3 (no endpoint) is unchanged.

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
