---
name: learn
description: Close the learning loop — what fits no class, which techniques convert here, and what to do about it. Usage: /learn [target] [--reports <dir>]
---

# /learn

Reads what you already logged and reports the one thing pattern analytics
cannot see: **findings that fit no known class**. Those are the map's blind
spots, and they are the raw material for the next skill.

## When to Use

- after a session, or between hunts
- when the same class keeps yielding nothing and you want to know what does
- before writing a new `hunt-*` fragment — see if the material is already logged
- after harvesting disclosed reports

## Usage

```
/learn
/learn kcell
/learn --reports ~/reports/ozon-disclosed
```

## What It Reports

1. **Novel techniques** — journal rows whose technique/class matches no pattern
   in `technique_classifier` and no `hunt-*` skill. A find with no class is not
   a weak find, it is a stale map.
2. **Technique yield** — confirmed vs rejected per technique. Lead with what
   converts; stop leading with what has burned three attempts and converted zero.
3. **Stack signals** — what has worked on this exact stack before.
4. **Suggestions** — concrete next steps, ranked.

## The reports half

```
scripts/report-harvest.py --in <local dir> --source '…' --licence '…' \
    --out docs/disclosed-reports/dataset.json
```

Turns local disclosed reports into a `report_intel` dataset plus a
**novel-mechanics** extract — the mechanics this bundle's pattern table cannot
name. Offline only. Provenance (`--source`, `--licence`) is **not optional**:
a dataset nobody can check the terms of is a dataset nobody may use, and both
this script and `report_intel` refuse one that declares nothing.

Then search it when a lead looks like something you have seen before:

```
cbh report-intel docs/disclosed-reports/dataset.json --query "…"
```

## Acting on the output

- **novel** → draft a `TECHNIQUE_PATTERNS` entry and a `vectors.py` mutation,
  or a new `hunt-*` fragment if it is a whole class. Run the skill-lint chain
  after editing the bundle.
- **strong technique** → put it first in the rotate order for that stack
- **dead technique** → stop leading with it; it is in the ledger as rejected
  and that is a real result

## Rules

- this reads rows you logged with `/remember`. Feed it: confirmed **and**
  rejected. An empty corpus means the next session repeats dead moves.
- a technique forced into a nearby class teaches the classifier the wrong
  shape — log it `unclassified__<what-it-was>` instead
- nothing here touches a target; it is safe to run any time
