---
name: anomaly
description: Class-agnostic anomaly hunt — find what does not add up before naming a vuln class. Usage: /anomaly [target|manifest.json] [--hosts h1,h2]
---

# /anomaly

The second track. Looks for incoherences, beliefs the app does not verify, and
broken invariants — **before** any vulnerability class is named.

## When to Use

- the class-based sweep is done and the easy bugs are burned
- you want findings that no `hunt-*` skill will hand you
- the target has money, quota, roles or workflow state in it
- you feel boxed in by the taxonomy (that feeling is the signal)

## Not for

- a known class with a known payload list → use that `hunt-*` skill
- a single focused probe → just send it

## Step 1 — get a manifest

```
cbh api-manifest <openapi|har|postman|burp.xml|graphql> --out recon/<target>/manifest.json
```

No manifest? Build one from the response corpus and traffic you already have —
a manifest with 20 operations is enough. Do not go build a perfect one first.

## Step 2 — run the track

```
python3 engine/anomaly.py recon/<target>/manifest.json --format md --engagement <name>
```

Load the `hunt-anomaly` skill first — it is mandatory during analysis and it
carries what to do with each anomaly kind.

## Step 3 — work the output

Three artefacts, three different actions:

1. **anomalies** → pick by impact, fire the probe, read the state back
2. **assumptions** → invert them; start with `authz-before-lookup` and
   `identity-is-not-in-headers`, they convert most often
3. **invariants** → make it false, then read the ledger

## Step 4 — convert, don't report

- contradiction is real on the wire → name the class → load that `hunt-*`
  skill → `/poc-run` → `/remember --result confirmed` → `/chain`
- probe came back clean → `/remember --result rejected` with the axis named
- **fits no class** → `/remember --technique unclassified__<what-it-was>`
  so `cbh learn` can grow the map. Do not force it into a nearby class.

## Standing rules

- an anomaly row is an **open thread**, never a result
- a random UUID proves nothing for `authz-before-lookup` — you need a real
  foreign id; without one, log under `blocked-tests/`, do not close the thread
- never write a report from this step's output alone

## Where to write it

`Targets/<name>/notes.md`, full prose, as open threads. Chat is not durable.
