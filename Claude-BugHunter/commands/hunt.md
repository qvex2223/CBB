---
name: hunt
description: Active web app vulnerability hunting (WAPT). Hands off to hunt-dispatch skill and sibling commands. Usage: /hunt target.com | /hunt *.target.com | /hunt targets.txt [--vuln-class X] [--source-code P] [--chrome]
---

# /hunt

slim web app pentest dispatcher. one box question, delegate. never asks about SOW — invoking `/hunt` implies SOW is signed.

## step 0 — parse

```
target.com               single target
*.target.com             wildcard — /recon <base> first, then hunt each live host
targets.txt              multi-target — mode question once, applied per line
--vuln-class <X>         skip mode question, load only hunt-<X>
--source-code <p|url>    static + dynamic
--chrome                 browser MCP mode
```

wildcard handler: if `$TARGET` begins with `*.`, strip prefix and invoke `/recon <base>` before continuing.

## step 1 — SOW hygiene

do not prompt the operator to paste a SOW, scope-of-work, or engagement-letter
**document** — that is sensitive client data and must not be ingested or persisted.
This is a data-hygiene rule, NOT an authorization bypass: scope is still enforced by
`/scope` (deterministic, deny-wins) and the `triage-validation` 7-Question Gate before
any finding ships. Authorization is assumed to be established out-of-band; the bundle
verifies in-scope, it does not collect proof-of-authorization paperwork.

## step 2 — box dispatcher

skipped if `--vuln-class` is set.

```
question: "black box or grey box?"
header:   "test mode"
options:
  1. Black Box   — no credentials, external perspective
  2. Grey Box    — test credentials provided (or skip)
```

grey box → NEVER open with "give me creds". order: (1) `Targets/<name>/identity.json` if present; (2) self-provision with `cbh identity new <url>` and self-register via Playwright; (3) ask the operator for creds ONLY if self-service is exhausted or the flow needs their real account/phone/ID. if the operator supplies creds directly (now or later, "now grey box with X/Y"), capture them, do NOT re-fire the mode question; operator-supplied creds live in session memory only — never written, never logged.

```
mode: wapt / {blackbox|greybox}
severity gate: all owasp-relevant
report: report-writing  (bugcrowd-reporting if target on bugcrowd)
```

invoke `hunt-dispatch` skill with `box=blackbox|greybox`.

## step 3 — sibling delegation

```
before any HTTP touch    →  /scope     (mandatory pre-flight)
recon empty | wildcard   →  /recon <target>
tech stack detected      →  pattern-analytics (auto-recommend techniques)
5+ live hosts surfaced   →  /surface   (P1/P2/Kill list)
confirmed finding        →  /chain     (A→B table lives here, NOT in /hunt)
before any report        →  /validate  (7-Question Gate)
findings ready           →  /report    (suggest, never auto)
session end              →  /remember  (silent, auto-classifies technique)
no progress ~5 min       →  cbh vectors rotate <class>   (next mutation, same vector)
vector exhausted         →  cbh vectors next <host>      (impact-ranked untried)
out of ideas             →  cbh vectors revisit <host>   (old findings, new methods)
redirect/cookie confusion→  scripts/burp-mcp.sh start    (see the wire, not a guess)
finding looks real       →  poc_runtime spec with steps  (login → exploit → verify)
browser/SPA/OAuth UI work →  Playwright MCP yourself     (never the operator's browser)
needs an account         →  cbh identity new <url>       (throwaway email/SMS, self-register; blocked by CAPTCHA/ID-gate → log blocked-tests, keep hunting; ask the operator ONLY after self-service is exhausted or the flow needs their real data)
same answer twice+       →  cbh diff <url>               (distinct bodies, or one wall)
boolean looks like leak  →  cbh diff <url> --fields      (did the verdict field ever move?)
request already fired    →  cbh spec <url> --steps       (spec from the wire, not retyped)
before /validate         →  cbh evidence <finding.md>    (is a fired PoC behind it?)
```

**Pattern analytics trigger:** After `hunt-dispatch` fingerprints the stack, automatically run `python3 scripts/pattern-analytics.py --stack "<detected_stack>" --recommendations` to show which techniques historically work on this exact stack before you start probing.

## step 3.5 — the skill gate (enforced during a hunt, silent outside one)

armed by this command. `/hunt`, `/autopilot`, `/recon`, `/pickup`, `/chain`, `/surface`, or any `hunt-*` skill puts the session in analysis mode; until then the gate allows everything, so operator questions get answered directly instead of with "load a skill first". `/validate`, `/triage`, `/report`, `/remember`, `/scope` are neutral and never arm it. state: `python3 engine/hunt_mode.py status --session <id>`.

once armed, `scripts/skill-gate.py` runs as a **PreToolUse** hook and **denies** any request-firing Bash command whose surface has an unloaded skill:

```
/graphql                          → hunt-graphql
/payment /order /invoice /tariff  → hunt-business-logic
/external /internal /worker /admin→ hunt-auth-bypass
/login /register /auth            → hunt-auth-bypass
/otp /verify /2fa                 → hunt-mfa-bypass
/upload /attachment               → hunt-file-upload
?redirect= ?url= ?callback=       → hunt-ssrf
/user/<id> /export /pdf           → hunt-idor
/api/v[0-9]                       → hunt-api-misconfig
.js .map robots.txt               → hunt-source-leak   (advisory, never blocked)
```

load the skill, re-send the identical command. genuinely inapplicable → append `# skill-gate: override <reason>` (logged to `audit.jsonl`). full table: `engine/skill_signals.py`.

## step 3.6 — proving it (the last mile)

a described PoC is not a fired one. before any report:

```
python3 engine/poc_runtime.py <spec>.json --md scope.md   # fires, captures, judges
cbh evidence findings/<finding>.md                        # DEMONSTRATED, or it isn't
```

`cbh spec <url> --steps` seeds that spec from a request already in the corpus — method, headers, body and an `expect` block built from the bytes the server actually returned. Redacted auth headers come back as placeholders to fill in by hand.

multi-step specs (`steps`) carry the chain: login → exploit → **verify the state
changed**. one cookie jar, `capture` → `{{placeholders}}`, first failing step stops
the chain. redirects are captured, and a pass on a followed redirect stays
INCONCLUSIVE until the spec asserts `final_url_contains` — "it returned 200" from
`/login` is the classic dead report.

reach for Burp (`scripts/burp-mcp.sh start`, MCP on 8181) when the wire itself is
the question: redirect chains, session state across a flow, replaying a captured
request. it bypasses `bbcurl`, so scope-check first and land the proof in a spec.

## step 3.7 — you do not get to stop empty-handed

`scripts/hunt-stop-gate.py` (Stop hook) refuses to end a hunt that has produced no
finding of **severity ≥ medium with a fired PoC behind it**. It is not advice: the
stop is blocked and the refusal lists the closest unproven finding, the untried
vectors from the host's ledger, and the rotation ladder.

Two ways out, both real:

```
1. finish one    write the spec, fire it, `cbh evidence <finding.md>` says DEMONSTRATED
2. prove it dry  every vector class marked dead WITH requests fired, rejects logged
                 via /remember --result rejected, then say so plainly
```

Not a way out: calling a Low a Medium. Check state any time with
`python3 engine/stop_gate.py` inside the engagement.

## step 4 — active testing

hand off to the loaded `hunt-*` skills. each skill has its own probes, payloads, validation. do not duplicate that logic here. on every confirmed finding, invoke `/chain` to check the A→B signal table.

## modes

`--source-code <path|url>` — adds hardcoded-secret grep, route mapping, dangerous-function scan before live testing.
`--chrome` — browser MCP for SPA / OAuth / DOM-XSS / WebSocket / file upload.
`--vuln-class <X>` — load only `hunt-<X>`, skip mode question.

## pacing & rotation — rotate signals, not stop signals

every ~5 min ask "am i making progress?" no → **rotate, do not stop**.

rotate signals: 403 everywhere · 20+ payloads identical response · 5+ preconditions · 10+ min on one endpoint.

"identical response" is not a judgement call any more — every body is hashed. `cbh diff <url>` prints how many distinct answers that endpoint has ever given, and the nudge fires **IDENTICAL RESPONSES** on its own when most of the last ten requests came back byte-identical. One distinct body across a burst means nothing you send reaches anything that decides the answer: rotate the *shape* (method, content-type, auth, version, path normalization), not the payload.

Bodies that all differ can still be one answer: `cbh diff <url> --fields` compares
field by field, and the nudge fires **ANSWER NEVER MOVED** when the verdict field
(`match`, `valid`, `exists`, `allowed`, …) is identical across every capture while
the inputs varied. Before reporting any boolean as a disclosure, find one input
that changes it.

what "rotate" means, in order — never "close the host":

```
1. next mutation on the same vector   python3 engine/vectors.py rotate <class>
     method swap · /v2->/v1 · auth strip · auth downgrade · content-type swap ·
     param pollution · path normalization · X-Original-URL / X-Forwarded-* ·
     case+encoding · sibling routes in the same controller · mobile/partner surface
2. next vector on the same host       python3 engine/vectors.py next <host>
3. old findings, new methods          python3 engine/vectors.py revisit <host>
4. /chain A->B table                  what does this finding unlock
5. only then: another host
```

a vector is `dead` only when every mutation is burned **and** requests were actually fired — `vectors.py mark … dead` enforces both and refuses otherwise. log the rejected attempts with `/remember --result rejected`; that is what stops the next session repeating them.

`scripts/hunt-nudge.py` (PostToolUse hook) fires this sequence at you automatically after ~12 requests with nothing logged, and names the `hunt-*` skill matching whatever URL you are probing.

one session per target. for `targets.txt`, mode question fires once; findings scoped per-target in hunt memory.

## privacy

never prompt for, log, or echo SOW / scope-of-work / engagement-letter content. never persist grey box credentials to disk. client data lives only in `.gitignore`d `targets/<target>/SESSION.md`.

at session end, invoke `/remember` silently (non-fatal).
