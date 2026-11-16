# Working in relay-control

```sh
npm ci
npm run typecheck
npm run test
npm run build
```

- Own identity, sessions, organizations and workspaces, canonical credentials, introspection and the credential-broker server, including `/internal/v1/flows/credentials/*`.
- Flow definitions, validation, runs, workers and provider ingress belong to relayfile-control. Do not mirror fixes into legacy `src/flows` by default.
- Cross services through documented HTTP seams, never sibling source imports or direct database access. Each service owns its migrations.
- Preserve tenant, run and reference binding, scopes, audience, expiry, revocation and refusal-versus-outage behavior. Update producers, consumers and seam tests together.
- Read `docs/flows-relayfile-credential.md` and the relayfile-control boundary before seam changes. Legacy compatibility requires a verified live deployment and cutover plan.

## Agency and guidance

- Act autonomously on routine assigned work; ask forgiveness rather than permission. Preserve explicit production, release and credential gates.
- For guidance, ask the engineering leads, the agent that spawned you, or the layered owner on Agent Relay.
- Only a truly pressing or blocking question goes to `khaliq-gant` or `will-washburn` (CODEOWNERS) on Agent Relay.

## Cross-repo context

- Before and during changes, understand how this repo fits the wider system; consult its repo map and related-repo docs where available.
- Check relevant agents’ summaries on Agent Relay and proactively contact owning agents about dependencies, adjacent changes and work in flight.

## Pull requests

- Open PRs ready for review, never as drafts. If merging requires Khaliq’s OK, use `merge-train:hold`.
- Immediately subscribe to PR feedback through Agent Relay using [this skill](https://github.com/AgentWorkforce/skills/blob/main/skills/subscribing-relay-webhooks-and-writebacks/SKILL.md), and verify the subscription.
- Evaluate every finding. Address applicable feedback and explain declined changes; a PR with unaddressed feedback or conflicts is not ready.
- When ready, loudly alert the CODEOWNERS and the agent that spawned you on Agent Relay.
- Keep related older PRs moving by contacting their author agent; if unavailable, escalate to the CODEOWNERS or layered owner.
