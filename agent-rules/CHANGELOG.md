# Agent rules changelog

Each version is immutable. Bump `version` in `manifest.json` (CalVer
`YYYY.MM.N`) and add an entry here in the same PR as any section change;
`test/agent-rules.test.ts` fails otherwise.

## 2026.11.1

- Adds `stall-watch` for `grok-bot` and `lead`: track delegated work, follow
  up on agents that have not reported (30 minutes since the last message, 10
  minutes after a spawn with no acknowledgement), route blockers, and tell the
  person who owns the work without waiting to be asked. Runs with no new
  messages still do the check (docs/specs/grok-bot-dynamic-prompt.md, Phase 3).
- `overlays/agentworkforce-grok-bot.md` is the reviewed text for the
  AgentWorkforce organization's `grok-bot` overlay (orchestration only;
  escalate to Khaliq). It is not part of the base bundle and takes effect only
  once an organization admin PUTs it (docs/agent-rules.md).

## 2026.11.0

- First bundle (docs/specs/grok-bot-dynamic-prompt.md, Phase 2).
- `grok-inbox` is Cloud's `grokRoutinePrompt`, copied in Phase 1 and rendered
  for each grant's mode, so behaviour is unchanged on day one.
- `grok-delegation` and `show-ui` are copied from the Grok Bot plugin skill.
- `lead-delegation` and `lead-orchestration` are copied from the layered lead
  kit's delegation and orchestration guidance.
