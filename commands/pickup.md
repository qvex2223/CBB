---
name: pickup
description: Pick up a previous hunt on a target — shows hunt history, untested endpoints, and memory-informed suggestions. Usage: /pickup target.com
---

# /pickup

Pick up where you left off on a target.

> **Renamed from `/resume`** — `/resume` is a reserved Claude Code command. Use `/pickup` to continue a previous hunt.

## What This Does

1. Reads the target profile from `hunt-memory/targets/<target>.json`
2. Shows hunt history (sessions, findings, payouts)
3. Lists untested endpoints from last recon
4. Lists parked findings — `findings/*.park.md`: proven primitives waiting on
   one named prerequisite. Each park file says what to try (acquisition plan) and
   what result kills it (stop condition). Resolve or kill them FIRST: a parked
   primitive with a fresh lead is the cheapest Medium+ in the session.
5. Suggests techniques based on tech stack + pattern DB
5a. **Refreshes the crit/high surfaces (2026-11-02):** `cbh census --project <eng> --seed`
   (offline: sibling interfaces, server-side fetchers, secret leads from manifests, the audit
   log and recon files), so `vectors.py next` ranks them like any other vector. Then
   `cbh corpus-gap` is NOT needed per target; it measures the toolkit, not the target.
6. Asks: continue hunting or re-run recon?

## Deterministic backing

```bash
cbh pickup target.com
```

Reads the profile written by `cbh remember` (`engine/memory.py`), cross-references
`recon/<target>/manifest.json` for surface that has *not* been tested yet, and
surfaces techniques confirmed on **other** targets that share this one's stack —
that cross-target carry-over is the entire reason memory exists.

## Usage

```
/pickup target.com
```

## Output

```
PICKUP: target.com
═══════════════════════════════════════

Hunt History:
  Sessions:    3
  Last hunt:   2026-03-24
  Total time:  2h 00m
  Findings:    1 confirmed (IDOR, $1500 paid)

Untested Surface:
  3 endpoints from last recon:
  1. /api/v2/users/{id}/export
  2. /api/v2/users/{id}/share
  3. /api/v2/users/{id}/history

Memory Suggestions:
  Tech stack [Next.js, GraphQL, PostgreSQL] matches 2 targets
  where you found auth bypass. Try introspection → mutation pattern.

Parked (one named prerequisite each):
  1. idor-orders-export.park.md — victim UUID delivery; plan: list/search, JS bundle;
     CONDITIONAL-HIGH

Actions:
  [r] Continue hunting untested endpoints
  [p] Work parked findings first (resolve or kill each park file)
  [n] Re-run recon first (surface may have changed)
  [s] Show full hunt journal for this target
```

## If No Previous Hunt

```
No previous hunt data for target.com.
Run /recon target.com first, then /hunt target.com.
```
