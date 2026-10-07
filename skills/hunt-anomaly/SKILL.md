---
name: hunt-anomaly
description: "TRIGGER — you need findings that no hunt-* class will name for you: the app believes a header, an older API still answers, a status is client-writable, a safe method fires an action, an answer never moves no matter the input. SKIP — you already know the class and it has a skill (use hunt-idor / hunt-sqli / hunt-ssrf …); hunt-differential once the question is specifically 'do these two states disagree', hunt-invariants once the question is specifically 'can I make money or state impossible'."
sources: operator
report_count: 0
---

# hunt-anomaly — the class-agnostic track

## Why this skill exists

Every other `hunt-*` skill is a map of **what already paid**. Hunting only
through that map is survivorship bias: by the time a bug has a class name, the
program has a known-issues entry for it, and the payout is gone. The bugs that
still pay almost never announce themselves as a class. They show up first as an
**incoherence** — something about the surface that does not add up.

So this skill deliberately refuses the taxonomy. You are not looking for XSS or
IDOR. You are looking for places where the application **holds a belief it does
not verify**. The class name comes afterwards, and only after.

## The discipline that makes this skill different

1. **Do not name a vulnerability class while hunting.** Naming it early makes
   you hunt the class instead of the contradiction. Call the thing an
   *anomaly*, a *belief*, an *invariant* — those are the words.
2. **An unfired request is not a result.** An anomaly that never went out is an
   open thread. It never enters a report, never gets called "good hygiene".
3. **Convert at the end.** Once a probe shows the contradiction is real on the
   wire, *then* name the class and load the matching `hunt-*` skill for the
   bypass tables and the report shape.
4. **A find that fits no class is not a weak find — it is a stale map.** Log it
   with `/remember` and a technique slug of `unclassified__<what-it-was>`, so
   `cbh learn` can grow the taxonomy instead of losing the row into `generic`.

## The three artefacts (engine/anomaly.py)

```
python3 engine/anomaly.py manifest.json --format md --engagement <name>
```

| Artefact | What it is | What it is not |
|---|---|---|
| **anomalies** | places where the surface contradicts itself | not a finding, not a severity |
| **assumptions** | beliefs the server probably holds, each with the probe that inverts it | not a checklist to tick without firing |
| **invariants** | things that must never be true (balance < 0, refund > payment, access after revoke) | not a business-logic essay |

## Anomaly kinds and what to do with each

### `client-supplied-identity`
A state-changing call accepts `user_id`, `tenant_id`, `owner_id`, `msisdn`,
`role`, `is_admin`, `email`… The server may be taking identity from the body.

**Probe:** write another principal's value into that field. **Then read the
object back** — the 200 is not the finding, the persisted write is.
**Convert to:** IDOR / mass assignment / privilege escalation, whichever it is.

### `client-driven-state-machine`
`status`, `state`, `step`, `approved`, `paid`, `refunded` are writable.

**Probe:** write the terminal state directly. Then attempt the transition that
should now be illegal. **Read state back.**
**Convert to:** business-logic / workflow bypass.

### `client-supplied-value`
`price`, `amount`, `discount`, `balance`, `quota` are accepted from the client.

**Probe:** 0, `-1`, `0.01`, and a boundary value. **Verify the ledger**, not
the response.
**Convert to:** business-logic / financial fraud. Rank by victim impact.

### `safe-method-on-action-path` / `write-on-read-path`
GET on `/delete`, POST on `/list`. Either CSRF-shaped or the router is not
checking the method at all.

**Probe:** fire it with no session and in a cross-site shape. Read state back.
**Convert to:** CSRF, or authz bypass if it fires unauthenticated.

### `internal-looking-surface`
`/admin`, `/internal`, `/worker`, `/actuator`, `/debug` published on the same
origin.

**Probe:** unauthenticated; then with `X-Original-URL` / `Host` override.
**Convert to:** auth bypass. Often the highest-impact thing on the estate.

### `version-skew`
`/v1` and `/v2` of the same operation disagree on fields.

**Probe:** call the older one with the fields that only exist on the newer.
Diff the bodies **field by field** — a changed body is not a changed answer.
**Convert to:** the class of whatever the withdrawn field protected.

### `identity-header-oracle`
Path names a principal-owned object.

**Probe:** `X-MSISDN`, `X-Forwarded-User`, `X-Original-URL`, `X-Subscriber-Id`.
Whose data comes back?
**Convert to:** auth bypass / IDOR. This is the shape that found the Kcell
`X-MSISDN` class of bugs.

### `answer-never-moved`
The response corpus says a decisive field was constant across many different
requests.

**Probe:** give it a second, genuinely different input and read the same field.
**A field that does not react to input is a stub.** The finding is the absence
of a check, not a disclosure. (`cbh diff <url> --fields` is the tool.)

## Assumptions to invert (run these even when nothing above fired)

| Belief | Invert it by |
|---|---|
| an id in the path is always mine | substitute a real foreign id and read the object back |
| authz runs before the lookup | compare a **real** foreign id against a random UUID |
| status only moves forward | replay the terminal transition; skip to it directly |
| money is computed server-side | send 0 / negative / boundary; verify the ledger |
| this host is internal | reach it unauthenticated and via Host / `X-Original-URL` |
| only the declared method routes | send the other methods on the same path |
| identity is not in headers | add the proxy-injected headers and see who you become |
| the old version is gone | call `/v1` of a `/v2` operation and diff fields |
| one parser, one validation | resend as form-encoded and as XML |
| delete is final | read it back; retry the create with the same key |

**The 404 differential warning (standing rule):** a random-UUID probe proves
nothing when the backend looks up before it authorizes. To test
`authz-before-lookup` you need a **real object id that is not yours**. If you
cannot get one, the thread is `blocked`, not `rejected` — log it under
`Targets/<name>/blocked-tests/` with the command ready to run.

## Invariants (where the money bugs live)

Engine-generated list, filtered to what this surface actually shows. The probe
is always the same shape: **make the invariant false, then read the state back.**

- an account balance is never driven below zero
- one-time value is applied exactly once (voucher, bonus, top-up, refund)
- total refunded never exceeds total paid
- revoking a session/role/share takes effect on the next request
- an order total equals the sum of its line items
- a discount never exceeds what it discounts
- cancelled/refunded/settled objects do not transition again
- changing an object's owner is never a client-side write

## The output shape

Write anomalies to `Targets/<name>/notes.md` as open threads, full prose:

```
### OPEN — anomaly: client-supplied-identity on POST /api/v1/orders
Signal: body accepts owner_id. Probe not yet fired: write another principal's
owner_id, then GET the order back. Not a finding until that read shows it stuck.
Convert-to class once confirmed: IDOR / mass assignment.
```

Then fire it. If it holds: `hunt-*` of the converted class → `/poc-run` →
`/remember --result confirmed` → `/chain`. If it breaks: `/remember
--result rejected` — that is a real result, it stops the next session repeating
the dead move.

## What this skill is not

Not a scanner. Not a reason to skip the class skills once the class is known.
Not permission to write a report from an anomaly row. It is the track that runs
*beside* the taxonomy so the taxonomy cannot box the hunt in.
