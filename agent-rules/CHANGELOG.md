# Agent rules changelog

Each version is immutable. Bump `version` in `manifest.json` (CalVer
`YYYY.MM.N`) and add an entry here in the same PR as any section change;
`test/agent-rules.test.ts` fails otherwise.

## 2026.11.0

- First bundle (docs/specs/grok-bot-dynamic-prompt.md, Phase 2).
- `grok-inbox` is Cloud's `grokRoutinePrompt`, copied in Phase 1 and rendered
  for each grant's mode, so behaviour is unchanged on day one.
- `grok-delegation` and `show-ui` are copied from the Grok Bot plugin skill.
- `lead-delegation` and `lead-orchestration` are copied from layered-agents
  `kit/delegation.md` and `kit/orchestration.md`.
