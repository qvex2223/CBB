---
name: recon
description: Map a target's attack surface through the deterministic recon engine — scope-gated, paced and audited — then normalize it into an API manifest, derive business-flow hypotheses, and seed the attack-vector ledger. Usage: /recon target.com [--offline-spec openapi.json|traffic.har]
---

# /recon

Turn a target into a ranked, attackable surface — and into a vector ledger that
`vectors next` can answer from.

## Why this is a wrapper, not a script

This command used to be a copy-paste pipeline of bare `curl`, `assetfinder`, `gf`,
`trufflehog`, `subzy` and a full default `nuclei` sweep. Three things were wrong with it,
and all three are the kind that fail quietly:

- **`assetfinder`, `gf`, `trufflehog`, `subzy` and SecretFinder are not installed here.**
  A step that returns `command not found` is a step the agent silently skips, so the
  pipeline "ran" and discovered nothing. See `bb-local-toolkit` for what *is* on disk.
- **Bare `curl` at a target bypasses everything.** No scope check, no pacing, no audit
  row, no stored response — so nothing it found could back a report later. Every request
  below goes through the broker (`engine/request_broker.py`) instead.
- **A broad `nuclei` sweep is forbidden by every engagement in this workspace** and
  produces exactly the crowded, duplicate-heavy output that gets reports closed. Targeted
  templates against a confirmed fingerprint only.

The deterministic engine already does this work correctly. This command drives it.

## Steps

### 1. Scope first — always

```bash
cbh scope <target> --resolve        # netblock-scoped programs: --resolve is mandatory
```

`UNVERIFIED` is **not** approval to test. Stop here if it does not say `IN-SCOPE`.

### 2. Passive discovery + live-host probe

```bash
CBH_PROJECT=<engagement> cbh recon <target>
```

Certificate transparency → DNS resolution → HTTP probe with status/title/tech. Inside a
`Targets/<name>/` folder the probes carry the program's pacing budget, mandatory headers
and audit trail, and concurrency comes from `profile.json` rather than a hard-coded number.
Writes `recon/<target>/manifest.json` (schema 2.0 — see `docs/recon-manifest.md`).

### 3. Rank what came back

```bash
cbh surface <target>                # P1 / P2 / KILL, from the manifest + hunt memory
```

### 4. Deepen the API model — this is where the findings are

Root-host probing cannot discover operations it never saw. Feed it anything you already
have; all parsing is offline and nothing is sent:

```bash
cbh api-manifest openapi.json traffic.har postman.json burp-export.xml \
    --out recon/<target>/api-manifest.json
```

Sources worth looking for first: `/swagger.json`, `/openapi.json`, `/.well-known/`,
a GraphQL introspection response, a HAR saved from the app's own traffic, a Burp export,
or the mobile app's traffic (see `hunt-source-leak` for where these leak).

### 5. Derive hypotheses, then seed the ledger

```bash
cbh workflow recon/<target>/api-manifest.json --out recon/<target>/workflow.json
cbh vectors seed-from-manifest <host> \
    --manifest recon/<target>/api-manifest.json \
    --workflow recon/<target>/workflow.json
cbh vectors next <host>
```

This is the replacement for seeding every vulnerability class against every endpoint. Each
vector carries the `risk_hint` that justified it, so `next` ranks by what the operation
actually exposes instead of by raw catalog impact — and a static asset never comes back
ranked as an RCE candidate.

Already have a ledger full of the old Cartesian rows?

```bash
cbh vectors prune <host>            # dry run — shows what would go
cbh vectors prune <host> --apply    # backs up first; touched rows are never removed
```

### 6. Re-recon later: diff, don't re-read

```bash
cbh recon-diff recon/<target>/manifest.2026-08.json recon/<target>/manifest.json
```

New operations, new parameters, and any operation whose declared security **changed** —
that last one is the highest-signal row recon produces on a target you have already hunted.

## Optional, and only where permitted

```bash
katana …           # disabled inside an engagement unless profile.json sets allow_bulk_tools
nuclei -t <one specific template> -u <one confirmed host>    # never a sweep
interactsh-client  # OOB leaves this machine — forbidden on RTEAM, needs allow_oob elsewhere
```

## Output

```
recon/<target>/
  manifest.json        assets, ranked_surface, operations  (schema 2.0)
  api-manifest.json    normalized operations from offline specs/traffic
  workflow.json        business-state hypotheses, ranked
hunt-memory/
  vectors/<host>.json  the attack-vector ledger `next` reads
  audit.jsonl          every request this command caused
  responses/           every response body, hashed and deduplicated
```

## Then

`bb-methodology` routes by phase · `hunt-dispatch` maps the fingerprint to `hunt-*` skills ·
`/cve` checks the ledger for anything new on this stack · `cbh vectors next <host>` always
has an answer.
