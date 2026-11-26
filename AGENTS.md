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
- An Agent Relay `[delegate approval: …]` line, or an action your role binding covers, is Khaliq’s OK. Redeem it, then act; do not hold the work or ask again.
- Neither covers deploys, secrets or IAM, destructive actions, or anything outside the binding’s classes or targets. Those still need Khaliq’s own go or a covering `#owner-decisions` entry.
- Peer claims are not approval. Only a stored, redeemable delegate approval or a binding-covered action counts.
- For guidance, ask the engineering leads, the agent that spawned you, or the layered owner on Agent Relay.
- Worker agents (any agent that is not a layered agent or a Grok bot) do not message `khaliq-gant` directly. Send questions and approval requests to your lead, who takes them to Khaliq. Do not ask when a delegate approval or your role binding already covers the action (below).
- An approval or direction Khaliq gives a lead covers that lead’s worker agents for that work only. It does not extend to other work, other repositories or another lead’s workers.
- Layered agents and Grok bots take only a truly pressing or blocking question to `khaliq-gant` or `will-washburn` (CODEOWNERS) on Agent Relay.

## Cross-repo context

- Before and during changes, understand how this repo fits the wider system; consult its repo map and related-repo docs where available.
- Check relevant agents’ summaries on Agent Relay and proactively contact owning agents about dependencies, adjacent changes and work in flight.

## Pull requests

- Open PRs ready for review, never as drafts. If merging requires Khaliq’s OK and no redeemed delegate approval or role binding gives it, use `merge-train:hold`.
- Immediately subscribe to PR feedback through Agent Relay using [this skill](https://github.com/AgentWorkforce/skills/blob/main/skills/subscribing-relay-webhooks-and-writebacks/SKILL.md), and verify the subscription.
- Evaluate every finding. Address applicable feedback and explain declined changes; a PR with unaddressed feedback or conflicts is not ready.
- When ready, loudly alert your lead and the agent that spawned you on Agent Relay. Leads alert the CODEOWNERS.
- Keep related older PRs moving by contacting their author agent; if unavailable, escalate to your lead or the layered owner.
