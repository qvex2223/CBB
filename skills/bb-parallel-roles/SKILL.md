---
name: bb-parallel-roles
description: "TRIGGER — you want more than one mind on the target at once: a plan queue to fan out, recon to keep running while you exploit, a second opinion before a submit, several hosts to cover in parallel, or a background learning loop while you hunt. SKIP — you are doing a single focused probe (just do it); you are answering an operator question outside a hunt (the session is idle, no pipeline needed); scope or identity is still unknown (resolve that first — parallelism multiplies whatever you already have, including the mistakes)."
sources: operator
report_count: 0
---

# bb-parallel-roles — more than one mind, without more than one set of brakes

## The failure this fixes

One agent doing everything means every role competes for the same attention:
the one that is loudest wins, which is always "send another curl". Mapping gets
skipped, the second opinion never comes, and the session ends with a target
that was *touched* rather than *covered*.

The naive fix — spawn N copies of the same hunter — multiplies noise and rate
limit pressure, and all N make the same blind spot because they have the same
shape. **The leverage is in splitting by role, not by count.**

## The roles

| Role | Job | Explicitly not |
|---|---|---|
| **Scout** | grow the surface: `cbh api-manifest` from HAR/OpenAPI/APK, `recon_delta` against the last snapshot, JS/route mining | no exploitation requests |
| **Anomaly** | class-agnostic incoherence hunt (`hunt-anomaly`) | no report writing, no class names |
| **Differential** | work the comparison plan (`hunt-differential`), one axis at a time | no payload invention |
| **Hunter** | convert a confirmed divergence into a class and take it to a PoC | no surface mapping |
| **Attacker** | try to **kill** the candidate before it ships | never confirms |
| **Writer** | report from `findings/` + `.result.json` only | never hunts |

The rule that makes the split work: **a role must return something that
changes the next step.** An agent that returns "surface looks interesting" is
activity, not work.

## How to run this in Claude Code

- **Subagents for a specific unknown.** A fresh-context validator for a finding
  you are about to ship; a chain-builder on a confirmed anomaly; a narrow
  research question. Not for activity's own sake.
- **Teammates / background sessions for roles that run long.** Scout and
  Anomaly are the ones that belong in the background; they write into
  `Targets/<name>/notes.md` and `findings/`, not into chat.
- **Headless `claude -p` for the deterministic half.** Recon, manifest
  rebuilds, plan generation — those need no judgment and no skills. Note the
  honest limitation: a headless engine agent runs with **skills disabled**, so
  hand it mechanical work and keep the judgment calls in the interactive
  session.

## The brakes do not dilute — that is the whole point

This is why the pipeline is safe to parallelise. Every transport is already
gated:

- `bbcurl` / `poc_runtime` scope-check and pace before every request,
- the pacing budget is **global per engagement, not per host** — parallel
  agents queue behind each other on a `flock`, so N agents cannot blow the rate
  limit by being simultaneous,
- `mcp-gate` puts Burp and Playwright under the same policy,
- `skill-gate` keeps the *hunter* role from hand-rolling past its skill,
- the audit log is append-only and shared, so "who sent what" stays answerable.

Do **not** "temporarily relax pacing" to make a fan-out faster. If the fan-out
is too slow, the answer is fewer parallel hunters, not a bigger budget.

## Splitting a plan without splitting the discipline

`engine/diff_matrix.py` output is a queue of independent comparisons — the
cleanest thing to parallelise in this whole workspace.

```
python3 engine/diff_matrix.py manifest.json --out plan.json
# split by host or by axis
python3 engine/diff_matrix.py manifest.json --hosts api.target.com --out plan-api.json
python3 engine/diff_matrix.py manifest.json --axes auth-strip,principal-swap --out plan-authz.json
```

Hand each chunk to a role. Merge on `operation_id`. **Log with `/remember` as
each result lands**, not at the end of the batch — a batch that dies with the
session is exactly the failure the logging discipline exists to prevent (and
long sweeps really do die with the session: chunk the input).

## Parallel across engagements

The pacing budget is per-engagement, and the hunt-memory corpus is shared. So
two engagements can run at once without interfering — but:

- pin each session to its project (`CBH_PROJECT=<name> bbcurl`) or the
  scope gate may resolve the wrong engagement,
- `cbh program-quality` decides **where a spare thread is worth more**, by
  acceptance rate, duplicate rate and time-to-verdict,
- never carry a prior from one engagement into another. Not the stack
  conclusion, not the "this is hardened" verdict, not the identities.

## The background learning loop

While you hunt, a background pass can keep the map from going stale:

```
scripts/report-harvest.py --in <local reports> --source '…' --licence '…' --out docs/disclosed-reports/dataset.json
python3 engine/learn.py --format md --out learnings.md
```

`report-harvest` turns local disclosed reports into a `report_intel` dataset
plus a **novel-mechanics** extract — phrases this bundle's pattern table cannot
name. `learn.py` reads your own journal and reports what fits no class, plus
which techniques actually convert here. Both are offline. Neither touches a
target. Run them between hunts, or on a cron, not on the request path.

Provenance is not optional: `report-harvest` refuses a dataset that declares
no source and no licence, and `report_intel` refuses to search one. That is
correct — someone else's disclosures are someone else's work.

## Debrief is part of the pipeline

Parallel work without a debrief is how "where did we leave off" becomes
unanswerable. At the end of a pass:

```
python3 engine/session_debrief.py --project Targets/<name>
```

It appends full prose to `notes.md`: requests actually fired, findings logged,
rejections logged (those are results too), hosts touched, and every open vector
with its next mutation. Written in full sentences on purpose — `notes.md` is
read back by `/pickup` and `session-brief`, and a compressed note is a direct
loss to cross-session memory.

## Anti-patterns

- **Parallelism as procrastination.** Spawning agents instead of sending the
  one request that would settle the question. When the choice is "analyse more
  or send the request" — send it.
- **Fan-out with no merge step.** Ten agents, ten partial truths, no single
  view of the target. Merge on `operation_id` / host, and debrief once.
- **Asking the operator which role to run.** Pick it yourself. Blocked on
  identity? That thread is closed and logged in `blocked-tests/`, not raised
  as a question.
- **Using a subagent to bypass a gate.** Cross-session permission laundering
  is still gate-dodging. If a role cannot fire the request, neither can its
  helper.
