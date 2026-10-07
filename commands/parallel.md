---
name: parallel
description: Split the hunt across roles, not just across processes — Scout/Anomaly/Differential/Hunter/Attacker/Writer with one shared set of brakes. Usage: /parallel [--plan plan.json] [--roles scout,anomaly,differential]
---

# /parallel

More than one mind on the target at once. The leverage is in splitting by
**role**, not by count: N copies of the same hunter make the same blind spot.

## When to Use

- a plan queue exists (`/oracle` output) and should be worked in parallel
- recon should keep running while you exploit
- you want a second opinion before a submit
- several hosts should be covered at once
- a background learning loop should run while you hunt

## Not for

- a single focused probe — just send it
- answering an operator question outside a hunt — the session is idle
- scope or identity still unknown — resolve that first; parallelism multiplies
  whatever you already have, including the mistakes

## The roles

| Role | Returns |
|---|---|
| **Scout** | new surface: manifest rebuild, `recon_delta`, JS/route mining |
| **Anomaly** | class-agnostic incoherences (`/anomaly`) |
| **Differential** | worked comparisons (`/oracle`), one axis at a time |
| **Hunter** | a confirmed divergence taken to a PoC |
| **Attacker** | a candidate killed, with the reason |
| **Writer** | a report built from `findings/` + `.result.json` only |

**A role must return something that changes the next step.** "Surface looks
interesting" is activity, not work.

## Usage

```
/parallel
/parallel --plan recon/<target>/oracle-plan.json
/parallel --roles scout,anomaly
```

## The brakes do not dilute

Every transport is already gated, which is exactly why this is safe:

- `bbcurl` / `poc_runtime` scope-check and pace every request
- the pacing budget is **global per engagement** — parallel agents queue on a
  `flock`, so N of them cannot blow the rate limit by being simultaneous
- `mcp-gate` covers Burp and Playwright
- `skill-gate` keeps Hunter from hand-rolling past its skill
- the audit log is shared and append-only

**Never "temporarily relax pacing" to make a fan-out faster.** Too slow means
fewer parallel hunters, not a bigger budget.

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
