---
name: hunt-differential
description: "TRIGGER — you need a finding and the honest way to get one is to hold everything still and move exactly one dimension: role A vs role B, with auth vs without, /v2 vs /v1, declared vs observed, valid input vs garbage. SKIP — you are hunting a known class and already have a payload list (use that hunt-* skill); hunt-anomaly when the question is open-ended 'what does not add up', hunt-auth-bypass when the axis is specifically authentication, hunt-idor when the axis is specifically object ownership and the object is named."
sources: operator
report_count: 0
---

# hunt-differential — compare, don't guess a payload

## The idea

A differential is **falsifiable by construction**: both sides are the same
request with exactly one thing changed, so any difference is the finding, and
no difference is a real negative. That is the opposite of payload guessing,
where a miss is ambiguous — maybe the payload was wrong, maybe the sink is
safe, maybe the WAF ate it.

This is also the track that survives when the easy bugs are burned. Payloads go
stale. **Disagreements between two states of the same call do not**, because
they are about the application's own beliefs, not about a wordlist.

## The axes

Each axis is a belief, not a vulnerability class. The class comes after the
disagreement shows up.

| Axis | Belief under test | Healthy answer |
|---|---|---|
| **auth-strip** | the check is real | status/body change when credentials go away |
| **principal-swap** | ownership is enforced | B cannot see or mutate A's object |
| **identity-headers** | identity comes from the session | proxy-injected headers change nothing |
| **hidden-field** | only declared fields bind | an injected field does not persist |
| **path-version** | withdrawing on `/v2` withdrew it everywhere | `/v1` does not accept what `/v2` dropped |
| **value-boundary** | numbers are validated/clamped | 0 / negative / huge are rejected |
| **garbage-input** | a check is a check | garbage is rejected, not answered the same |
| **method-swap** | the router dispatches on method | an undeclared method is 405/404 |
| **content-type** | one parser, one validation | both formats validate the same |
| **param-pollution** | the parser picks one deterministically | and says which one |

## Running it

```
python3 engine/diff_matrix.py manifest.json --format md --out plan.md
python3 engine/diff_matrix.py manifest.json --out plan.json --audit <mem>/audit.jsonl
python3 engine/coverage.py --engagement <name> --manifest manifest.json --format md
```

`diff_matrix` builds the plan offline from the API manifest
(`cbh api-manifest` normalizes OpenAPI / HAR / Postman / Burp XML / GraphQL
introspection into it). `coverage.py` then says which axes were **actually**
varied — because a plan that exists is not coverage.

## How to run a comparison

1. Pick a row. `priority` ranks by belief weight, and risk hints on the
   operation push it further up — authz and business-flow first.
2. Fire the **baseline** and the **probe** through `bbcurl` / `poc_runtime`.
   Both. The comparison is the unit, not one request.
3. Judge on the two answers, not on one status code. Use `cbh diff <url>
   --fields` if the body is large: a changed body is not a changed answer.
4. Record both directions:
   - **they disagree** → this is a lead. Name the class, load the matching
     `hunt-*` skill for the bypass tables and the report shape, `/poc-run` it.
   - **they agree** → `/remember --result rejected`, naming the axis. That is a
     real result and it stops the next session redoing it.

## The verdict hints that actually matter

- **"an identical answer means the check is a stub"** — on `auth-strip` and
  `garbage-input`. If the answer does not move when the input does, the finding
  is the **absence of a check**, not a disclosure. That is frequently a Medium
  on its own, and it is invisible if you only look for a leak.
- **"read the object back"** — on `hidden-field`, `value-boundary`,
  `principal-swap`. A 200 on the write is not the finding. The state change is.
- **"whichever value it used is the one to attack with"** — on
  `param-pollution`. Discover the parser's choice first, then aim.

## Negative space is a deliverable

`diff_matrix` emits `negative_space`: for every operation, which axes were
never applicable and which were never varied. **"We did not test that" is the
honest map. "We found nothing" is not.** When the operator asks what is left,
the answer is this list, not a feeling.

Operations with almost nothing planned (static assets, health checks) are
fine. Operations with authz-shaped risk hints and one planned axis are where
the hunt is thin.

## Parallelising a plan

A plan is a queue. It parallelises cleanly because every row is independent:

- split `plan.json` by host or by axis across headless agents,
- keep every request on `bbcurl` so scope, pacing and audit still hold
  (the pacing budget is global per engagement on purpose — parallel agents
  queue behind each other rather than blowing the rate limit),
- merge results by `operation_id`, and log with `/remember` as they land,
  not at the end of the batch.

See `bb-parallel-roles` for how to split a plan across roles rather than just
across machines.

## What this is not

Not a scanner sweep. Not a reason to fire all 10 axes on all 500 operations in
one go — `--limit` and `--hosts` exist so impact decides the order. And not a
licence to call a plan row a finding: every row carries
`not_a_finding_until`, and it means it.
