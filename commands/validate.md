---
name: validate
description: Validate a finding — runs 7-Question Gate + 4-gate checklist. Kills weak findings before report writing. Prevents N/A submissions that hurt validity ratio. Usage: /validate
---

# /validate

Run full validation on the current finding before writing a report.

## Before the gate: try to kill it

`/refute <finding>` fires the controls whose PASS means the finding is wrong —
credentials stripped, the attack value swapped for your own, the exploit step
deleted. A KILLED or MIS-FRAMED verdict makes `cbh evidence` report **REFUTED**,
which outranks the exploit's own PASS, and the gate below then has nothing to
validate. Run it first; it is cheaper than a closed-as-N/A report.

**Enforced since 2026-11-02:** `cbh triage` answers `PASS-PENDING-REFUTE` (exit 3) for a
7/7 finding with no `<finding>.refute.json`, or with one whose value controls were SKIPPED.
Run `cbh refute <finding>` and triage again. `--no-refute` exists for drafts only.

## What This Does

0. **Checks the finding is backed by a fired PoC** — `cbh evidence <finding.md>`
   (engine/evidence.py) looks for the `.result.json` that `poc_runtime` writes.
   Q1 ("demonstrable right now") and Q6 ("impact proved") are answered from that
   artifact, not from how confidently the finding is worded. No artifact = those
   questions fail. Fire the spec first:
   `python3 engine/poc_runtime.py <spec>.json --md scope.md`
0a. **Wire-level claims need wire-level evidence.** If the finding talks about a
   redirect, a session, or a cookie, a single-request artifact does not answer Q6 —
   the status code you saw may belong to `/login`. `evidence.py` returns
   WIRE-UNPROVEN until one of these exists:
   - a multi-step `steps` spec re-fired through `poc_runtime` (captures the chain,
     the final URL and every `Set-Cookie`), or
   - the exchange captured in the proxy — Caido (docs/caido.md), then save
     request+response beside the finding as `<finding>.caido.txt`
     (`.caido.json` / `.har`, and the older `.burp.*` names, also count), or
   - the response-corpus `sha256` of a capture whose header block is stored, quoted
     in the finding text itself. `bbcurl` keeps every body under
     `hunt-memory/responses/<engagement>/<sha>.txt`; `cbh diff <url>` shows what was
     recorded. The citation must be explicit — matching a capture to a finding by
     URL alone would hand today's report yesterday's evidence, and a stored body
     with no headers proves nothing about the wire.
0aa. **The class of the claim names the oracle.** A PASS proves the request flew and
   matched its `expect`; for several classes that is the sink, not the effect, and
   `evidence.py` returns CLASS-UNPROVEN until the class's own oracle sits in the
   finding's folder:
   - **xss** — a browser or proxy artifact: a screenshot, a console/CDP record, a
     Caido/`.har` export. The script that drives the proof (`*-proof.sh`, `.mjs`) is
     not the proof. A reflected marker is a sink; execution is what the report claims.
   - **sqli** — a delta between two arms of ONE spec (>= 2000 ms apart and >= 3x), or
     the driver's own error (`SQLSTATE[...]`, `syntax error at or near`). The app's
     own 500 page is not a database.
   - **ssrf / xxe** — an OOB hit log beside the finding. The effect is a request the
     TARGET makes, and the response that triggered it cannot witness it. Run
     `python3 scripts/oob-responder.py --port <p> --log <dir>/oob.jsonl` on a host the
     target can reach, and check the programme permits OOB first.
   - **rce** — command output in the body (`uid=33(www-data)`) or an OOB hit. A
     timeout is not execution.
   - **lfi** — the file's own bytes. A differently-shaped 404 is a traversal oracle,
     which is a `primitives/` entry.
   - **idor** — two identities in one spec: two credentials, or a credential and none.
   - **csrf** — an `.html` PoC on another origin. A curl that carries the cookie
     deliberately is not a forged cross-site request.
   - **open-redirect** — a hop whose host is not the host we asked.
   Declare the class as `**Class:** idor` on its own line so the gate grades the right
   question instead of guessing from the title. A class with no rule prints
   `not checked`, which is reported, never counted as a pass.
   `python3 engine/class_proof.py <finding.md>` answers it on its own.

0b. **A boolean is only a disclosure if it reacts.** If the finding rests on an
   endpoint answering true/false about data the caller should not know, run
   `cbh diff <url> --fields` first. A verdict field that is identical across every
   capture is a stub, not an oracle, and the report writes itself into a N/A.

1. Runs 7-Question Gate (one wrong answer = kill it)
2. Checks against the always-rejected list
3. Runs 4 pre-submission gates
4. Outputs: PASS (write the report) or KILL (move on)

## Usage

```
/validate
```

Describe the finding when prompted. Include:
- The endpoint
- The bug class
- What the PoC shows
- The target program

## The 7-Question Gate

Answer each. ONE wrong answer = STOP.

### Q1: Can I demonstrate this step-by-step RIGHT NOW?

Write this out:
```
1. Setup:   I need [own account / another user's ID / no account]
2. Request: [exact HTTP method, URL, headers, body]
3. Result:  Response shows [exact data / action completed]
4. Impact:  Real consequence is [account takeover / PII exposed / money stolen]
5. Cost:    Time: [X min], Capital: [$0 / $X]
```

If step 2 is "I need to look at the code more" → KILL IT.

### Q2: Is the impact accepted by this program?

Check program scope page. Is your bug class listed? Is it excluded?

### Q3: Is the vulnerable asset in scope?

Exact domain in scope? Not staging/dev? Not a third-party service?

### Q4: Does it need admin or privileged access that an attacker can't get?

"Admin can do X" → KILL IT.
"Regular user can do X that only admin should" → valid.
Cross-account finding? The victim's identifier is a second precondition — owning
both test accounts proves the mechanic, not the delivery. See the Owned-Account
Trap in `triage-validation`: sequential/leaked ID = delivered; high-entropy UUID
with sources exhausted = KILL; one named untested source = PARK.

### Q5: Is this known or documented behavior?

Search disclosed reports + changelog + API docs.

### Q6: Can you prove impact beyond "technically possible"?

- XSS → actual cookie value in exfil request, not just alert()
- SSRF → response body from internal service, not just DNS callback
- IDOR → actual other-user's private data in response, not just 200 status

### Q7: Is this on the never-submit list?

```
Missing headers, GraphQL introspection alone, clickjacking without PoC,
self-XSS, open redirect alone, SSRF DNS-only, logout CSRF, banner disclosure,
rate limit on non-critical forms (UNLESS unthrottled guessing itself extracts
value — low-entropy codes, password/OTP oracle — then it stands alone),
missing cookie flags alone...
```

If yes → KILL IT unless you have a chain.

## Check: Conditionally Valid?

If it's on the never-submit list, can you chain it?

| You Have | Chain Available? |
|---|---|
| Open redirect | + OAuth code theft → ATO? |
| SSRF DNS-only | + internal service data? |
| Clickjacking | + sensitive action + PoC? |
| CORS wildcard | + credentialed data exfil? |
| Prompt injection | + IDOR → other user's data? |

If no chain → KILL IT. If chain confirmed → report both together.

## 4 Gates — All Must Pass

**Gate 0 (30 sec):**
```
[ ] Confirmed with real HTTP requests (not just code reading)
[ ] In scope (checked program page)
[ ] Reproducible from scratch
[ ] Evidence captured
```

**Gate 1 — Impact (2 min):**
```
[ ] Can answer "What does attacker walk away with?"
[ ] More than "sees non-sensitive data"
[ ] Real victim exists
[ ] No unlikely preconditions
```

**Gate 2 — Dedup (5 min):**
```
[ ] Searched HackerOne Hacktivity for endpoint + bug class
[ ] Searched GitHub issues
[ ] Read 5 most recent disclosed reports
[ ] Not in changelog as known issue
[ ] Same-run dedup: `cbh dedup <finding.md>` against every OTHER finding of
    this engagement (exit 1 = likely duplicate, 2 = needs review) — identity
    is root cause + fix, not title: same root cause + same fix = duplicate
    even on a different endpoint; different backend control/tenant boundary/
    fix = distinct even on the same endpoint. Unsure → treat as possible
    duplicate and merge contexts.
```

**Gate 3 — Report quality (10 min):**
```
[ ] Title formula: [Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps have exact HTTP request
[ ] Evidence shows actual impact
[ ] CVSS calculated
[ ] Fix: 1-2 concrete sentences
```

## Output

**PASS:** "All 7 questions pass. All 4 gates pass. Proceed to /report."

**PARK:** "Primitive proven, one named prerequisite unresolved (e.g. victim
identifier delivery), conditional Medium+. Write `<finding>.park.md` with
prerequisite / acquisition plan / stop condition / conditional severity /
evidence, and move on. Re-triage when the prerequisite resolves — never report
while parked."

**KILL:** "Q[N] fails because [reason]. Kill this finding. Reason: [explanation]. Move on."

**DOWNGRADE:** "Q6 only shows technical possibility. Downgrade from High to Medium. Requires showing actual data exfil in PoC."
