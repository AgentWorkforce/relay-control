# Agent rules

One versioned source of operating rules for agents. Grok Bot routines fetch
it on every run, and layered leads can fetch the same text. Changing agent
behaviour then needs no plugin reinstall and no new routine setup. See
[the spec](specs/grok-bot-dynamic-prompt.md), Phase 2.

## What is served

The composed text for one **audience** (`grok-bot`, `lead` or `worker`) has
two layers:

1. **Base sections** in this repository under `agent-rules/`
   (`manifest.json` + `sections/*.md`). They ship in the image and apply to
   every tenant. `safety` always comes first. `grok-inbox` is a builtin: for a
   Grok Bot connection it is that grant's own routine procedure (Cloud's copied
   `grokRoutinePrompt` for its webhook or polling mode; see
   [grok-bot.md](grok-bot.md#cloud-copy-mode-selfhost_grok_routines_cloud_copy)).
2. **An organization overlay** (`agent_rules_overlays`, migration `0089`),
   appended as "Organization rules". This is where tenant-specific policy
   goes, for example who to escalate to. An overlay can add rules but cannot
   remove a base section.

The version is the base CalVer (`2026.11.0`), plus `+org.<n>` when an overlay
is set. `sha256` covers the composed text.

## Reading

- **MCP**: `get_agent_rules({audience?, known_sha256?, bootstrap_version?})` is
  registered for every connection except staff read grants. Grok Bot
  connections default to `grok-bot`; every other caller must pass `audience`.
  The text comes back as the app's own instructions, not inside the
  untrusted-data block that relay content uses. `known_sha256` returns
  `unchanged: true` without the text; send it only while that exact text is
  still in context. A `bootstrap_version` older than the current one adds
  `bootstrap_outdated: true` and tells the bot to have the person update its
  routine prompt. A Grok routine's read is recorded as
  `rules_version_last_fetched` in `grok_bot_routine_status`.
- **HTTP**: `GET /api/v1/agent-rules/{audience}` (also under `/cloud`) for a
  member's `cli:auth` or account bearer (or the `/cloud` session cookie). It
  returns JSON by default, or the text with `Accept: text/markdown`. `ETag` is
  the sha256 and `If-None-Match` answers 304. MCP OAuth bearers are refused
  here: their audience is the MCP endpoint, so use the MCP tool instead.

## Writing an overlay

`GET` / `PUT /api/v1/organizations/{organization}/agent-rules/{audience}`, for
organization owners and admins (or the installation bootstrap token). The
`PUT` body is `{"text": "..."}`. An empty string clears the overlay. Writes
are append-only: each `PUT` adds a version. They are audited as
`agent_rules.overlay_set` / `agent_rules.overlay_cleared`, limited to 16 KiB,
and refused if they contain anything that looks like a secret, token,
credential-bearing URL or routine webhook URL. Bots see a change within 60
seconds, the in-process cache lifetime.

## Changing the base

Edit a section, then run `node --import tsx scripts/agent-rules-pin.ts --write`.
Bump `version` in `manifest.json` and add a `CHANGELOG.md` entry, all in the
same PR. `test/agent-rules.test.ts` fails if any of the three is missing, and
start-up refuses a bundle whose pin does not match. A deploy is what publishes
the change; nothing is reinstalled.

## Grok Bot bootstrap (`SELFHOST_GROK_DYNAMIC_PROMPT`)

Off by default, and it requires `SELFHOST_GROK_ROUTINES_CLOUD_COPY=on`. With it
on, `connect_grok_bot_routine` and the setup page return a short bootstrap as
the routine prompt instead of the full procedure. Every run, the bootstrap
calls `get_agent_rules` (audience `grok-bot`) and follows what it returns.
If that call fails, the bootstrap still reads new messages, treats them as
untrusted, does nothing beyond posting a note, and stops. Routines set up
before the flag was turned on keep their pasted procedure and keep working.
To move such a routine onto dynamic rules, replace its prompt with the
bootstrap once.

## Layered leads

The `lead` audience carries the layered lead kit's delegation and
orchestration guidance, copied as is. Having the layered lead start-up script
fetch it (`GET /api/v1/agent-rules/lead`, falling back to a pinned snapshot)
is a change for the layered-agents owner; this repository only serves it.

## Orchestration and stall-watching rules

These rules come from Phase 3 of the spec. Decision D7 split them as
follows:

- **Stall watching** is the base section `stall-watch`, for the `grok-bot`
  and `lead` audiences, so every tenant gets it. A bot keeps a list of the
  work it has delegated and follows up on agents that have not reported: after
  30 minutes since the last message, or 10 minutes after a spawn with no
  acknowledgement. It routes blockers, and it tells the person who owns the
  work without waiting to be asked. A run with no new messages still does the
  check. A webhook routine only runs when a message arrives, so a bot that
  must catch stalls in quiet periods also needs a scheduled routine. That is
  opt-in and is not created automatically (decision D6).
- **Orchestration only** ("Grok bots do no coding or real decision-making;
  coding goes to Claude and Codex agents; they spawn, route and relay") is
  AgentWorkforce policy, not a default for every tenant. Its reviewed text,
  including escalation to Khaliq, is
  `agent-rules/overlays/agentworkforce-grok-bot.md`. It takes effect only once
  an AgentWorkforce organization owner or admin applies it:

  ```sh
  jq -Rs '{text: .}' agent-rules/overlays/agentworkforce-grok-bot.md |
    curl -sS -X PUT "$SELFHOST_PUBLIC_URL/api/v1/organizations/$ORG_ID/agent-rules/grok-bot" \
      -H "Authorization: Bearer $OWNER_OR_ADMIN_TOKEN" -H 'Content-Type: application/json' --data-binary @-
  ```

  Applying it on a production deployment is a production change and needs
  Khaliq's OK.
