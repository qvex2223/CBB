---
name: hunt-invariants
description: "TRIGGER — the target moves money, quota, entitlement or workflow state, and the question is whether you can make something impossible happen: a negative balance, a double-applied refund, a discount larger than the cart, a revoked share that still opens, a cancelled order that transitions again. SKIP — the bug is object access rather than object state (hunt-idor); the bug is a class with payloads (use that hunt-* skill); you are still mapping surface (bb-methodology)."
sources: operator
report_count: 0
---

# hunt-invariants — hunt the property, not the class

## Why this is where the business-logic money is

A class-based hunt asks "is there XSS here". An invariant hunt asks something
that pays better: **"can I make the application do something that must never
be true?"** Almost every high-payout business-logic bug is a broken invariant,
and none of them have a payload list, because they are properties of *this*
application's money and state.

The other reason: invariants are **falsifiable and non-ambiguous**. "Refund
exceeds payment" is either true of the ledger or it is not. There is no
"maybe the sink is safe" grey zone, which is exactly where Low-severity
reports get closed as N/A.

## The invariants

Generated for the surface at hand by `engine/anomaly.py`, filtered to what the
manifest actually shows. The complete list:

| Invariant | Statement | Probe |
|---|---|---|
| `balance-never-negative` | a balance is never driven below zero | concurrent or boundary debit; read balance back |
| `no-double-spend` | one-time value applies exactly once | replay the apply with the same idempotency key; verify ledger |
| `refund-le-payment` | refunded never exceeds paid | partial then full, or two partials past the total |
| `no-access-after-revoke` | revoking takes effect on the next request | reuse the old token/scope after revoke |
| `total-equals-lines` | total equals the sum of line items | mutate a line after the total is set; re-read |
| `discount-le-subtotal` | a discount never exceeds what it discounts | stack, negative or oversized discount |
| `terminal-state-is-terminal` | cancelled/refunded/settled do not move again | repeat the transition on a terminal object |
| `ownership-survives-mutation` | owner/tenant is never a client-side write | write `owner_id` on an update; read as the old owner |

## The probe shape, always the same

```
1. reach a known state          (create/read; note the ids and the balances)
2. attempt to break the invariant   (ONE thing — boundary, replay, reorder, race)
3. READ THE STATE BACK               ← this step is the point
4. if the invariant broke, capture the ledger/object evidence
```

Step 3 is where PoCs die. A 200 on step 2 proves nothing. If you cannot read
the state back, the finding is **unproven** and stays a draft — see the
"write-only API" rule: give triage exact ids and timestamps so they can verify
internally, or the report gets closed.

## Running it

```
python3 engine/anomaly.py manifest.json --format md --engagement <name>
```

Read the `invariants` section. Each row carries `not_a_finding_until`: the
state was read back after the probe and the invariant was actually violated.

For the money ones, `engine/workflow_graph.py` is the co-pilot — it derives the
business-state transitions and, with `--responses <engagement>`, attaches the
**real object ids** the target has already handed back. A hypothesis with real
material behind it outranks the same hypothesis with a `{{OBJECT_ID}}`
placeholder, because only one of them can be fired this session.

## Severity discipline (this is where inflation happens)

The safety floor is not a dial. An invariant that broke in a test mode, on a
sandbox amount, or that needs a second user's identity to demonstrate is
**not** automatically High.

- Rank by **victim impact**, not by what you managed to write. A proven
  unauth registry write that harms nobody is still not a High.
- "Primitive confirmed, impact inferred" stays unsubmittable. Pull data or
  perform an action that matters, or drop it.
- Never submit Low/Info — keep hunting instead.
- A boundary value that produced a weird number but no state change is an
  observation, not a finding.

## Races and concurrency

`no-double-spend` and `refund-le-payment` are the race-shaped ones. Rules that
keep a race report from being closed:

- the **smallest authorised parallel pair** — two requests, not two hundred.
  Anything else is DoS-shaped and out of policy.
- state the invariant first ("one redemption per voucher"), then show it
  applied twice, then the ledger showing both.
- rate-limit bypass and race without business impact are rejected by most
  programs; check `Targets/<name>/scope.md` before spending a session on one.

## Chaining

A broken invariant is often only half of a finding. `/chain` it:

- broken discount + missing auth on the checkout endpoint → unauth free order
- double-refund + webhook replay → money out of thin air
- terminal-state re-entry + a notification trigger → secondary fraud

Read `/chain`'s A→B table before closing the thread. A broken invariant found
and parked as Low is exactly the case that table exists for.

## What this is not

Not a licence to move real money, ship real goods, or affect other users.
Minimal PoC only — if a check could affect another user or availability, stop
and get program approval first. And not a substitute for the class skills once
the broken invariant has a class name.
