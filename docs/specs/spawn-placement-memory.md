# Spec: memory-aware spawn placement

Status: proposed. This change is the spec only. Nothing here is implemented yet.
Scope: `list_relay_spawn_targets` and `spawn_relay_agent` in relay-control
(`src/mcp/relay-spawn-placement.ts`, `src/mcp/relay-spawn.ts`), parity with
Cloud's `packages/web/lib/mcp/relay-spawn-placement.ts` and
`relay-spawn-service.ts`, and the relay-node heartbeat that feeds both.

## 1. Problem

Placement ignores free memory. Today both control planes do the same thing:

- **Eligibility** (`eligible()`): the node is live, `handlersLive`, not
  `stale`, not `self`, its active count is not negative, it advertises a
  `spawn:` capability, and `maxAgents === 0` (unlimited) or
  `maxAgents > activeAgents + reservedAgents`.
- **Ranking** (`compareTargets()`): allowed first, then yours, then desktop
  before broker before hosted, then has room, then the lowest `loadScore`
  (`load_1m / cpus`, falling back to slot utilization), then more free slots.
- **Launch recheck** (`spawn()`): refuses with `spawn_target_not_allowed`,
  `spawn_target_offline`, `spawn_target_unavailable`,
  `spawn_harness_unavailable` or `spawn_capacity_exceeded`. Each refusal
  carries up to 3 alternatives that are allowed, offer the harness and have
  room, with nodes that share a repository listed first.

`memory_available_bytes` and `memory_total_bytes` reach `PlacedTarget.load`
but are only displayed. Neither control plane reads `metadata.live.observed_at`.
As a result:

- A 16 GB Mac mini with about 2.7 GB free ranks the same as a node with 30 GB
  free when their load is the same, and accepts the launch.
- A node with `maxAgents = 0` is never full, so it keeps taking agents until
  the machine swaps or the OOM killer starts ending processes.

### What the node reports

relay-node (`crates/relay-node/src/relay/spawn/resources.rs`, sampled for
every heartbeat, every 12 s) sets
`capabilities[spawn:*].metadata.live = { observed_at, slots{max, held, reserved, free, working, idle, waiting, unknown}, resources{cpus, load_1m, memory_total_bytes, memory_available_bytes} }`.

| OS | `memory_available_bytes` means | Bias |
|---|---|---|
| Linux | `/proc/meminfo` `MemAvailable` (the kernel's estimate of memory available without swapping) | Accurate on bare metal. **Wrong inside a container**: it reports the host's memory, not the cgroup limit |
| macOS | `(free + speculative + purgeable + file-backed external) × page size` | **Conservative.** It leaves out inactive anonymous pages and memory the compressor can reclaim, so a healthy Mac often reports only a few GB |
| Windows | `GlobalMemoryStatusEx` available, capped at total | Accurate enough |
| Other | `null` | Unknown |

## 2. Policy

All policy is in one pure function. It takes the target, the harness, the
policy settings and `now` as input, makes no I/O calls and reads no clock.

```ts
assessMemory(target: PlacementInput, harness: string | null, policy: MemoryPolicy, now: Date): MemoryAssessment

type MemoryAssessment = {
  tier: "ample" | "ok" | "tight" | "low" | "unknown";
  admissible: boolean;              // false only when tier === "low"
  reason: "available" | "density" | null;   // why low
  available_bytes: number | null;   // as reported
  projected_available_bytes: number | null; // after pending launches (2.3)
  total_bytes: number | null;
  available_fraction: number | null;
  floor_bytes: number | null;       // kept free for the machine / person
  need_bytes: number;               // this harness's launch budget
  agents_fit: number | null;        // more launches of this harness that fit now
  memory_cap: number | null;        // density cap (2.4)
  observed_at: string | null;
  age_seconds: number | null;
  fresh: boolean;
};
```

### 2.1 Freshness (`observed_at`)

- The sample is **fresh** when `-30 s ≤ now − observed_at ≤ 45 s`. 45 s covers
  three missed heartbeats plus some clock skew. The −30 s bound tolerates a
  node clock that runs ahead.
- When the sample is not fresh, or `observed_at` is missing or can't be
  parsed, memory is **unknown**. The policy never refuses based on unknown
  memory (fail open, as today). Relaycast's own `stale` flag still makes the
  node ineligible as it does today.
- `now` is the control plane's clock. If Relaycast later exposes when it
  received each heartbeat, use that time instead, which removes node clock
  skew. This is a follow-up and not needed now.
- If capabilities disagree (each `spawn:*` capability carries its own
  `live`), use the sample with the newest `observed_at`. Today the code reads
  the first non-null value.

### 2.2 Floor and per-harness launch budget

Memory is judged on two numbers: an absolute launch budget per harness, and a
floor kept free that is the larger of an absolute amount and a fraction of
total memory.

| Setting | Default | Rationale |
|---|---|---|
| `floor` (desktop) | `max(2 GiB, 10% of total)` | A desktop is a person's computer. Their browser, IDE and OS need room, and a desktop that swaps is a bad experience for that person |
| `floor` (broker, hosted) | `max(1 GiB, 5% of total)` | A dedicated machine only needs room for the OS and the node |
| `need[claude]` | 1.5 GiB | A Node CLI (~0.4–0.8 GiB RSS) plus MCP servers and the child processes it runs |
| `need[codex]` | 1.0 GiB | A lighter Rust core. The child processes it runs (builds, tests) take most of the memory |
| `need[opencode]` | 1.5 GiB | Bun/Node runtime, similar to claude |
| `need[grok]` | 1.0 GiB | |
| `need[*]` (default, and the value used when the tool call names no harness) | 1.5 GiB | Assume the cautious figure for a harness we have no measurements for |
| `ample_headroom` | 4 GiB **and** ≥ 25% of total still available after the launch | Room for several more launches or a large build |

These are budgets that reserve headroom at launch. They are not limits, and
the control plane does not enforce them on running agents. Shadow mode (§5)
is how we calibrate them before any refusal goes live. A follow-up adds
per-agent RSS to `metadata.live.agents` in relay-node, so the numbers can be
learned from real usage instead of guessed.

### 2.3 Projected availability (`activeAgents + reserved`)

A memory sample was taken before the most recent launches, and those launches
are still starting up and growing. Subtract the launches the sample cannot
reflect yet:

```
pending  = reservedAgents                                   // Relaycast places reserved, not yet held
         + journal launches to this node in state reserved|accepted
           created after observed_at                        // our own in-flight launches
projected_available = available − pending × need[default]
headroom            = projected_available − floor − need[harness]
```

When the journal count is not available (in Cloud, a cross-session read may
be too expensive), use `reservedAgents` alone. Either way, this stops a burst
of launches from all fitting into the same 12 s sample.

### 2.4 Density cap (a "full" for `maxAgents = 0`)

```
memory_cap = floor((total − floor) / per_agent_steady)      // per_agent_steady default 1 GiB
held       = activeAgents + reservedAgents
```

- When `maxAgents = 0`, `memory_cap` becomes the effective maximum. A node at
  `held ≥ memory_cap` is `low` with `reason: "density"`, even if its current
  sample looks fine. Idle agents can wake up and grow, and the
  sample-based check alone lets an unlimited node fill up.
- When `maxAgents > 0`, the effective maximum is `min(maxAgents, memory_cap)`.
  This only applies when `density_caps_configured` is on (default **off**). A
  person's explicit `maxAgents` is their decision. See open decision D4.
- `available_slots` keeps its current meaning: `null` means unlimited, so no
  existing client breaks. `agents_fit` and `memory_cap` are new fields
  alongside it.
- When total memory is unknown, there is no density cap.

### 2.5 Tiers

| Tier | Condition | Admissible |
|---|---|---|
| `low` | fresh, and `headroom < 0` or density cap reached | **no** |
| `tight` | fresh, `headroom ≥ 0`, below the ample threshold | yes |
| `ok` | fresh and above ample on one axis only (bytes or fraction) | yes |
| `ample` | fresh, `headroom ≥ 4 GiB` and `projected_available − need ≥ 25%` of total | yes |
| `unknown` | missing, stale, or `null` memory (Linux container, other OS) | yes (fail open) |

### 2.6 Ranking

```
allowed
→ admissible           (has slot room AND memory not low)      ← new position
→ yours
→ kind                 (desktop, broker, hosted)
→ memory tier          (ample, ok, unknown, tight)             ← new
→ loadScore            (load_1m / cpus, else slot utilization)
→ fewer held agents    (activeAgents + reservedAgents)         ← new
→ more agents_fit, then more free slots
→ Relaycast roster order (stable)
```

- **Admissible moves above "yours" and kind.** Today a full desktop of yours
  ranks above a broker with room, so the first entry may be a node that will
  refuse the launch. After this change, the first entry is always a node that
  would accept the launch now, if any node would (decision D3).
- `unknown` ranks between `ok` and `tight`. A node that reports nothing should
  not beat one we know is healthy, and should not lose to one we know is
  nearly out of memory.
- `loadScore` stays the main measure within a tier, so CPU still separates
  nodes whose memory is similar.

Worked example (a 16 GiB desktop with 2.5 GiB available, launching `claude`):
`floor = max(2, 1.6) = 2 GiB`, `headroom = 2.5 − 2 − 1.5 = −1.0 GiB`, so
**low**. It is refused with `spawn_memory_low` and ranked after every
admissible target. A 64 GiB desktop with 30 GiB free:
`floor = 6.4`, `headroom = 22.1 GiB`, and `(30 − 1.5) / 64 = 45%`, so
**ample**.

### 2.7 Refusal: `spawn_memory_low`

The order of checks in `spawn()`: not allowed → offline → unavailable →
harness unavailable → `spawn_capacity_exceeded` (slots) → **`spawn_memory_low`**.

```json
{
  "code": "spawn_memory_low",
  "message": "Node \"studio\" has 2.5 GB free; launching claude needs 1.5 GB on top of the 2 GB it keeps free.",
  "node": "studio", "harness": "claude",
  "retryable": true,
  "observed_at": "<refusal time>",
  "memory": { "reason": "available", "available_bytes": 2684354560, "projected_available_bytes": 2684354560,
              "total_bytes": 17179869184, "floor_bytes": 2147483648, "need_bytes": 1610612736,
              "memory_cap": 14, "held": 3, "sampled_at": "<node observed_at>" },
  "active": 3, "reserved": 0, "max": 0,
  "alternatives": [ ... ]
}
```

- `retryable: true`, because memory frees up. The message for
  `reason: "density"` says the node already runs N agents, the most its
  memory supports.
- Alternatives are filtered by `admissible` in addition to the current filter
  (allowed, offers the harness, has room). Nodes sharing a repository still
  come first, then ranked order, at most 3. The same filter applies to the
  alternatives attached to every other refusal code, so a refusal never
  suggests a node that would refuse too.
- When no alternatives qualify, the refusal includes `retry_after_seconds: 30`
  (about 2 heartbeats). The tool description says nothing is retried
  automatically, so this is a hint for the caller.
- Add the code to `SPAWN_CODES`, to the retryable list, to `failureMessage`,
  to `docs/agent-launch.md` and to the tool description.
- There is **no override flag** on `spawn_relay_agent` in this version.
  Callers who need to override it can raise the node's own settings (2.8).
  See D6.

### 2.8 Configuration

| Setting | relay-control env | Cloud | Default |
|---|---|---|---|
| Mode | `SELFHOST_SPAWN_MEMORY_POLICY=off\|observe\|rank\|enforce` | same values, Cloud feature flag `relay_spawn_memory_policy` | `observe` at first; `enforce` after the soak (§5) |
| Floor, absolute and fraction, per kind | `SELFHOST_SPAWN_MEMORY_FLOOR="desktop=2GiB/10%,broker=1GiB/5%,hosted=1GiB/5%"` | same string | as in 2.2 |
| Per-harness need | `SELFHOST_SPAWN_HARNESS_MEMORY="claude=1.5GiB,codex=1GiB,opencode=1.5GiB,grok=1GiB,*=1.5GiB"` | same string | as in 2.2 |
| Steady per-agent budget, density on finite max | `SELFHOST_SPAWN_AGENT_MEMORY=1GiB`, `SELFHOST_SPAWN_DENSITY_CAPS_CONFIGURED=false` | same | 1 GiB / off |
| Freshness | `SELFHOST_SPAWN_MEMORY_FRESH_SECONDS=45` | same | 45 |

- Parse the settings once at startup, in `src/config`, into a frozen
  `MemoryPolicy`. Invalid values fail startup, the same way other `SELFHOST_*`
  settings do. The policy package exports both the default policy and the
  parser, so both control planes read the same strings the same way.
- **Per-node override** (relay-node and Desktop follow-up): a node may
  advertise `metadata.configured.memory_floor_bytes` (Desktop setting: "Keep
  at least N GB free"). A node's setting can only **raise** its floor, never
  lower it, for the same reason a node's own claim can only narrow who may
  spawn there.

### 2.9 Modes

- `off`: today's behavior. The fields are not added.
- `observe`: adds `memory` to targets and logs or counts would-be refusals
  (`spawn_memory_policy_shadow{tier,reason,harness}`). Ranking and admission
  stay as they are today.
- `rank`: memory tier and admissibility affect ranking and the alternatives
  filter. No refusals.
- `enforce`: also refuses with `spawn_memory_low`.

## 3. Tool surface (relay-control)

### `list_relay_spawn_targets`

- New optional input `harness` (the same pattern as `cli`). When it is given,
  `admissible`, `memory.need_bytes`, `agents_fit` and the ranking use that
  harness's budget. When it is omitted, they use `need[*]`. Agents should
  pass the harness they intend to launch. The tool note says so.
- New fields on each `PlacedTarget` (in `observe` mode and above):
  `admissible: boolean`, `memory: MemoryAssessment` (the fields from §2), and
  a `why` sentence extended with a memory clause, for example "Only 2.5 GB
  free of 16 GB; it keeps 2 GB free and claude needs 1.5 GB."
- `load.memory_*` stays as it is for compatibility.
- The ineligible filter stays as it is. Memory-`low` targets are still
  **listed** (ranked last among allowed targets and marked
  `admissible: false`), so an agent can see why a node it expected is not
  usable.

### `spawn_relay_agent`

- No input change. The new refusal is in §2.7, and alternatives now follow
  the admissible filter.
- A refused-launch replay (the idempotency path, in Cloud) keeps computing
  alternatives as of now. That path is unchanged.

### `describe_capabilities`

- Reports `spawn_memory_policy: <mode>`, so clients and the parity checks can
  see which mode is active.

## 4. Where it lives in relay-control

Split today's `src/mcp/relay-spawn-placement.ts`, which mixes parsing,
permission, ranking and message text, into:

```
src/mcp/spawn-placement/
  index.ts          re-exports (relay-spawn.ts imports only this)
  parse.ts          spawnPlacement(raw): allowlisted fields, now including the newest live.observed_at
  permission.ts     who may spawn where (unchanged)
  messages.ts       why / notAllowedMessage / memory clauses (wording specific to this site)
  policy.ts         adapter: PlacedTarget ⇄ @agent-relay/spawn-placement input
src/config/spawn-memory.ts   env → MemoryPolicy (delegates parsing to the package)
```

The pure core is `assessMemory`, `compareTargets`, `rankTargets`,
`alternativesFor`, `DEFAULT_MEMORY_POLICY` and `parseMemoryPolicy`. It lives
in the shared package (§6). `relay-spawn.ts` then only changes in three
places:

1. It passes `policy`, `now` and the pending journal count to `rankTargets`.
2. It adds the `spawn_memory_low` check after the capacity check.
3. Its `eligible()` stays the same. Memory is never part of eligibility, so
   low nodes stay visible (§3).

The journal count comes from one indexed query per call:
`relay_spawns` rows for this workspace with state `reserved` or `accepted`,
`created_at > now() − 60s`, grouped by `node_id`. The existing
`(workspace, node)` columns are enough. **No migration.**

### Tests

- `test/spawn-placement-memory.test.ts` (new) covers: each tier boundary;
  freshness at −31 s, −30 s, 45 s and 46 s; missing or unparseable
  `observed_at`; `null` memory; the macOS and Linux sample fixtures; the
  density cap when `maxAgents = 0` and when it is finite with the flag on and
  off; pending launches pushing a node into `low`; a node override raising the
  floor and being ignored when it tries to lower it; and the 16 GiB versus
  64 GiB worked example.
- `test/spawn-placement-golden.test.ts` (new) runs the package's golden
  fixtures through this repo's adapter (§6).
- `test/mcp-launch.test.ts` (extended) covers: in `enforce` mode, a
  `spawn_memory_low` refusal with admissible alternatives and `retryable`
  set; in `observe` mode, no refusal but a recorded metric; in `rank` mode,
  the new order and no refusal; and in `off` mode, output identical to
  today's snapshot.
- `test/config.test.ts` (extended) covers env parsing and invalid values
  failing startup.

## 5. Rollout

1. **This spec**, then the decisions in §7.
2. **Package** `@agent-relay/spawn-placement` in `AgentWorkforce/relay`
   `packages/`, published on the same lockstep version as
   `@agent-relay/events-shim`, which both repos already pin. It has no
   runtime dependencies and ships its golden fixtures inside the package.
3. **relay-control** adopts it in `observe` mode, which is also the default
   for self-host. One release.
4. **Cloud** adopts the same package version in `observe` mode behind
   `relay_spawn_memory_policy`. This is a separate Cloud PR, outside this
   spec's scope.
5. **Soak for about 1 week**: compare the would-be-refusal rate per tier and
   harness in both control planes. Tune the defaults in the package, which is
   one change consumed by both. Targets: fewer than 2% would-be refusals on
   nodes that did not later swap or OOM.
6. **`rank`, then `enforce`**, in both control planes at the same time on the
   same package version, with a flag flip per environment. Self-host's default
   becomes `enforce` in the next minor release.
7. **relay-node follow-ups** (these don't block anything above):
   - cgroup v2 `memory.max` and `memory.current` inside containers;
   - macOS `kern.memorystatus_vm_pressure_level`, with `critical` meaning
     `low` and `warn` capping the tier at `tight`;
   - swap used;
   - per-agent RSS;
   - `configured.memory_floor_bytes`;
   - **node-side enforcement at `action.invoke`**: the node refuses with
     `spawn_memory_low` from its own fresh sample. That is the only atomic
     guard. The control-plane checks are an early, explainable refusal on top
     of it.

Rollback at any step is a flag flip to `off`, which gives byte-identical
output to today (covered by a snapshot test).

## 6. Keeping Cloud and relay-control in parity

**Recommendation: one shared pure package plus golden fixtures. Only the
adapters are duplicated.**

The two placement modules have already drifted:

- relay-control parses raw node JSON and has no `hosted` kind;
- Cloud's typed client pre-parses `placement` and does have `hosted`;
- the "claim this node" wording differs between the two.

Copying a new numeric policy into both repos would add a third source of
drift, and this one would be silent: two thresholds that differ slightly
produce different rankings with no error.

- **Shared** in `@agent-relay/spawn-placement`:
  - the `PlacementInput` type, which is normalized and includes
    `kind: "desktop" | "broker" | "hosted"`;
  - `assessMemory`, `compareTargets`, `rankTargets` and `alternativesFor`;
  - `DEFAULT_MEMORY_POLICY` and `parseMemoryPolicy`;
  - `fixtures/*.json`, each holding `{targets, owners, userId, harness, policy, now} → {ranking, assessments, refusal?}`.
- **Per repo**:
  - parsing raw or typed node data into `PlacementInput`;
  - permission rules, which differ because relay-control has no `hosted`;
  - message wording;
  - tool wiring.
- **Parity gate**: each repo's CI runs every package fixture through *its
  own* adapter, starting from raw heartbeat JSON (the fixtures include it),
  and asserts the package's expected output. Fixtures tagged `hosted` are
  skipped in relay-control. A package bump that changes any expected output
  must be adopted by both repos before step 6 of the rollout.
- Crossing repos through a published package is not the sibling-source import
  that `AGENTS.md` forbids. `@agent-relay/events-shim` already follows this
  pattern.
- **Fallback** if a package is not wanted (D1): duplicate the policy module in
  both repos and vendor the same `fixtures/` directory, with a CI check that
  compares the fixture directory's hash to a pinned value in the other repo.
  This is cheaper to start, but every threshold change then needs two PRs.
- When Cloud is retired (strangler cutover to relay-control plus relay-web),
  only the adapters change hands. The package and its fixtures stay as they
  are.

## 7. Open decisions for Khaliq

- **D1, the parity mechanism.** Options: a shared `@agent-relay/spawn-placement`
  package in the relay monorepo (recommended), or duplicated code with
  vendored fixtures.
- **D2, unknown or stale memory.** Options: fail open, meaning admit and rank
  between `ok` and `tight` (recommended), or fail closed.
- **D3, ranking order.** Should admissible rank above "yours" and kind
  (recommended), or keep today's order with admissible only above load?
- **D4, density cap on a finite `maxAgents`.** Off by default (recommended;
  it respects the person's explicit max), or on.
- **D5, default thresholds.** The desktop floor `max(2 GiB, 10%)`, the broker
  and hosted floor `max(1 GiB, 5%)`, the needs claude 1.5, codex 1.0,
  opencode 1.5, grok 1.0 and default 1.5 GiB, and the 45 s freshness window.
  Accept them for the soak, or set different values.
- **D6, caller override.** Should `spawn_relay_agent` accept an override such
  as `allow_low_memory: true` for owners spawning on their own node? This
  spec recommends not adding one in v1.
- **D7, node-side enforcement in relay-node.** In scope now, or a follow-up
  (recommended: a follow-up, but before self-host defaults to `enforce`)?
