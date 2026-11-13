---
name: parallel
description: Split the hunt across roles, not just across processes — Scout/Anomaly/Differential/Hunter/Attacker/Writer with one shared set of brakes. Usage: /parallel [--plan plan.json] [--roles scout,anomaly,differential]
---

# /parallel

More than one mind on the target at once. The leverage is in splitting by
**role**, not by count: N copies of the same hunter make the same blind spot.

## This is the default shape of a hunt (operator directive 2026-10-16)

Not a command to remember when the hunt feels slow — **every armed hunt runs this
way**: one agent orchestrates and never fires requests itself (it holds the plan,
the merge, `notes.md`, the vector ledger and the `/remember` calls), the workers do
the firing. The main session is that orchestrator by default, so fan out as soon as
`/pickup` has told you where you are, before the first request.

Default crew, unless `"hunt_agents"` in the engagement's `profile.json` says
otherwise: **Scout** (surface) · **Hunter** (the top-ranked vector with its `hunt-*`
skill) · **Freeroam** (told nothing — see below). Swap a role out when the target
says so (no identity yet → Scout + Freeroam + an identity worker), never to run
more than the cap below.

## Enforced, not requested (2026-10-21)

`scripts/crew-gate.py` denies the main thread every request-firing call while a hunt
is armed — `bbcurl`/`curl`/`httpx`/`ffuf`/`nomore403`/… and Caido/Playwright traffic.
The deny message carries the `Agent(...)` call to hand the request to a worker.
Subagents (`agent_id` in the hook input) and CLI workers (`CBH_AGENT_ROLE=worker`)
pass. One-off check the operator asked for: `# crew-gate: override <reason>` (audited).

## When this does NOT apply

- answering an operator question outside a hunt — the session is idle, no fan-out
- scope or identity still unknown — resolve that first; parallelism multiplies
  whatever you already have, including the mistakes
- one request would settle it — send it yourself, then fan out again

## The roles

| Role | Returns |
|---|---|
| **Scout** | new surface: manifest rebuild, `recon_delta`, JS/route mining |
| **Anomaly** | class-agnostic incoherences (`/anomaly`) |
| **Differential** | worked comparisons (`/oracle`), one axis at a time |
| **Hunter** | a confirmed divergence taken to a PoC |
| **Attacker** | a candidate killed, with the reason |
| **Writer** | a report built from `findings/` + `.result.json` only |
| **Freeroam** | the surfaces the methodology never looked at (`cbh freeroam`) |

**A role must return something that changes the next step.** "Surface looks
interesting" is activity, not work.

## Usage

```
/parallel
/parallel --plan recon/<target>/oracle-plan.json
/parallel --roles scout,anomaly
```

## Freeroam — the role that is told nothing

Every other role is a *skilled* role, which means they share one blind spot, and
the `hunt-*` taxonomy is survivorship bias by construction: a class has a skill
because it already paid, which is also why the program has a known-issues entry
for it.

So one agent gets the opposite treatment — the URL, the authorization, and nothing
else. No methodology, no class names, no payloads, no ranking:

```
cbh freeroam run https://api.target.com --out recon/<t>/naive.json
cbh freeroam merge <skilled-run>.json recon/<t>/naive.json
```

`skills_on=False` is what enforces it: `Skill` is absent from the worker's
`ALLOWED_TOOLS` and slash commands are off, so it *cannot* open a skill even if it
wanted to. The brakes are untouched — requests still leave through `bbcurl` and the
gated MCP servers.

The merge keys items by **surface**, not by wording (paraphrase cannot be matched
mechanically, and trying produced false disagreements). Read it in this order:

1. **naive-only** — the point of the whole exercise. Each is a lead: write it to
   `leads/`, fire the one request that settles it, and whatever survives goes into
   a `hunt-*` skill. That is how the taxonomy grows instead of repeating itself.
2. **same surface in both** — the strongest prior the pair produces.
3. **skilled-only** — what methodology bought you; worth keeping honest about.

## The brakes do not dilute

Every transport is already gated, which is exactly why this is safe:

- `bbcurl` / `poc_runtime` scope-check and pace every request
- the pacing budget is **global per engagement** — parallel agents queue on a
  `flock`, so N of them cannot blow the rate limit by being simultaneous
- `mcp-gate` covers Caido (every request in a batch) and Playwright
- `skill-gate` keeps Hunter from hand-rolling past its skill
- the audit log is shared and append-only

**Never "temporarily relax pacing" to make a fan-out faster.** Too slow means
fewer parallel hunters, not a bigger budget.

## Crew size: `cbh crew` — 3 at once by default (operator directive 2026-11-10)

Launch as many workers as `cbh crew` prints (3 by default on every engagement under Claude Code; **another client always 6**,
`"hunt_agents"` in `profile.json` overrides), **all in ONE message**, and refill each
slot from the queue the moment a worker hands back. Extra slots beyond Scout · Hunter ·
Freeroam (only with a `"hunt_agents"` override above 3) go to more Hunters on the next
ranked vectors (`cbh vectors next`).

Compaction risk with many workers is handled by the hand-back format, not by fewer
agents: each worker returns counts + verdict + file paths only (details live in
`hosts/*.md`, `findings/`, `primitives/`), and the orchestrator `/remember`s each
result as it lands. The orchestrator stays out of the request path.

## Splitting a plan

```
python3 engine/diff_matrix.py manifest.json --out plan.json
python3 engine/diff_matrix.py manifest.json --hosts api.target.com --out plan-api.json
python3 engine/diff_matrix.py manifest.json --axes auth-strip,principal-swap --out plan-authz.json
```

Merge on `operation_id`. **`/remember` as each result lands**, not at the end
of the batch — long sweeps die with the session.

## Background half (no target contact)

```
scripts/report-harvest.py --in <local reports> --source '…' --licence '…' --out docs/disclosed-reports/dataset.json
python3 engine/learn.py --format md --out learnings.md
```

## Close with a debrief

```
/debrief
```

Parallel work without a debrief is how "where did we leave off" becomes
unanswerable.

## Anti-patterns

- spawning agents instead of sending the one request that settles the question
- fan-out with no merge step
- asking the operator which role to run — pick it yourself
- using a subagent to bypass a gate — that is still gate-dodging
