---
name: oracle
description: Differential oracle plan — compare two states of the same call instead of guessing payloads. Usage: /oracle [manifest.json] [--axes auth-strip,principal-swap] [--hosts h1,h2] [--limit 20]
---

# /oracle

Builds the comparison plan: for each operation, baseline-vs-probe pairs along
the axes where the application's beliefs can change. Fires nothing.

## When to Use

- you want a finding and the honest way is to move exactly one dimension
- the payload lists are exhausted and yielding nothing
- you need an answer to "what is left to test" that is a list, not a feeling
- you want a queue to parallelise (see `bb-parallel-roles`)

## Not for

- open-ended "what does not add up" → `/anomaly`
- a known class with a known bypass table → that `hunt-*` skill

## Step 1 — manifest

```
cbh api-manifest <inputs...> --out recon/<target>/manifest.json
```

## Step 2 — plan

```
python3 engine/diff_matrix.py recon/<target>/manifest.json --format md --out recon/<target>/oracle-plan.md
python3 engine/diff_matrix.py recon/<target>/manifest.json --out recon/<target>/oracle-plan.json --audit <mem>/audit.jsonl
```

`--audit` marks rows already fired, so the plan shrinks as you work it.

## Step 3 — work the rows

Load `hunt-differential` first. For each row, highest `priority` first
(authz and business-flow risk hints float up):

1. fire the **baseline** and the **probe** — both, through `bbcurl`/`poc_runtime`
2. judge the two answers against each other (`cbh diff <url> --fields` on big bodies)
3. **they disagree** → lead. Name the class, load the matching `hunt-*`, `/poc-run`
4. **they agree** → `/remember --result rejected` naming the axis

## Verdict hints that matter

- identical answer on `auth-strip` / `garbage-input` → the check is a stub;
  the finding is the **absence of a check**
- `hidden-field` / `value-boundary` → read the object back; the 200 is not it
- `param-pollution` → find which value the parser used, then aim with that one

## Negative space is the deliverable

The plan's `negative_space` section is the honest map of what was never varied.
When asked what is left, print that. Run `python3 engine/coverage.py
--engagement <name> --manifest recon/<target>/manifest.json --format md` to see
which axes were actually moved versus merely planned.

## Rules

- a plan row is a hypothesis — `not_a_finding_until` is literal
- impact decides the order: `--limit` and `--hosts` so you work the payable
  surface first, not the whole estate
- log rejections as they happen; a batch that dies with the session is lost
