---
name: validate
description: Validate a finding — runs 7-Question Gate + 4-gate checklist. Kills weak findings before report writing. Prevents N/A submissions that hurt validity ratio. Usage: /validate
---

# /validate

Run full validation on the current finding before writing a report.

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
   - the exchange captured in Burp — `Claude-BugHunter/scripts/burp-mcp.sh start`,
     then save request+response beside the finding as `<finding>.burp.txt`
     (`.burp.json` / `.har` also count), or
   - the response-corpus `sha256` of a capture whose header block is stored, quoted
     in the finding text itself. `bbcurl` keeps every body under
     `hunt-memory/responses/<engagement>/<sha>.txt`; `cbh diff <url>` shows what was
     recorded. The citation must be explicit — matching a capture to a finding by
     URL alone would hand today's report yesterday's evidence, and a stored body
     with no headers proves nothing about the wire.
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
rate limit on non-critical forms, missing cookie flags alone...
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

**KILL:** "Q[N] fails because [reason]. Kill this finding. Reason: [explanation]. Move on."

**DOWNGRADE:** "Q6 only shows technical possibility. Downgrade from High to Medium. Requires showing actual data exfil in PoC."
