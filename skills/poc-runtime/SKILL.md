---
name: poc-runtime
description: "TRIGGER — a manual curl/browser PoC just confirmed a candidate finding and Q1/Q6 of the 7-Question Gate need a captured, re-playable artifact instead of a remembered response; before /validate on anything status-code- or body-content-dependent. SKIP — triage-validation for the gate questions themselves (this only produces the evidence one of them needs); evidence-hygiene once the artifact needs screenshot/HAR redaction rather than a raw HTTP capture; hunt-race-condition or hunt-brute-force once the goal is genuinely concurrent/high-volume requests, not single-shot validation."
---

# POC RUNTIME — deterministic single-shot exploit validation

> Inspired by usestrix/strix's exploit-validation runtime: don't just claim a PoC
> works, execute it and capture the real bytes. Kept inside this repo's
> constraints — curl-first, scope-gated, no autonomous agent firing requests on
> its own, no retries/hammering by default.

The core problem this closes: a finding gets triaged against a *remembered*
curl output ("I ran this earlier and got a 200 with the other user's data") —
but memory drifts, sessions expire, and Q1/Q6 of `triage-validation` deserve a
request/response pair captured **right now**, not recalled.

`engine/poc_runtime.py` fires ONE HTTP request from a small JSON spec, checks
it against an `expect` block in code (not LLM judgment on whether the bytes
matched), and writes a `<spec>.result.json` artifact with the verdict.

---

## When to reach for this vs. just running curl

- **Quick recon / exploration** → keep using raw curl. This isn't a replacement
  for the curl-first workflow, it's the last step before a finding goes into
  `/validate`.
- **A candidate finding is ready for the 7-Question Gate** → write the spec,
  run it once, attach the result to the finding file. This is what Q1 ("can
  you write step 2 as a real HTTP request") and Q6 ("prove impact beyond
  technically possible") are actually asking for.
- **Re-verifying a finding before submission** (sessions/tokens rotate,
  patches land) → re-run the same spec file; the diff between two
  `.result.json` runs is itself useful evidence of drift.

## Starting from a request that already flew

`cbh spec <url-substring> [--steps] [--out f.json]` reconstructs a spec from the
response corpus `bbcurl` keeps (`hunt-memory/responses/<engagement>/<sha>.txt`).
It fills in method, headers, body and an `expect` block from the recorded
response. Two things it deliberately does not do: guess a credential (redacted at
capture, emitted as a placeholder), and guess the assertion that states the *bug*
rather than that the endpoint is alive — that judgement stays yours.

## Workflow

1. Confirm scope first — `/scope <asset>` or have `scope.md` filled. The
   runtime refuses to fire without a scope source unless `--no-scope-check`
   is passed explicitly (localhost/lab targets only).
2. Write the spec next to the finding draft, e.g.
   `Targets/<name>/findings/idor-users.poc.json`:

   ```json
   {
     "note": "IDOR — victim id 124 while authenticated as own id 123",
     "method": "GET",
     "url": "https://api.example.com/v1/users/124",
     "headers": {"Cookie": "session=<own-account-session>"},
     "expect": {
       "status": 200,
       "body_contains": ["\"id\":124"],
       "body_not_contains": ["\"id\":123"],
       "final_url_contains": "/v1/users/124"
     }
   }
   ```

   **The last-mile keys.** Redirects are where PoCs die: urllib follows a 302
   silently, so an exploit that bounced to `/login` comes back as the login
   page's `200` and a spec expecting `200` passes. Every hop is now captured
   (`redirects`, `final_url`, per-hop `Set-Cookie`), and a pass on a *followed*
   redirect is downgraded to INCONCLUSIVE unless the spec asserts where it
   landed. Available:
   - `"final_url_contains"` — where the response must end up.
   - `"no_redirect": true` — the attacked endpoint must answer directly.
   - `"follow_redirects": false` (top level) — capture the raw 3xx instead,
     for `Location`/`Set-Cookie` evidence.
   - `"set_cookie_contains"` — state-change proof (session issued, killed,
     privilege cookie set). All `Set-Cookie` values are kept, not just the last.

3. Run it once:

   ```bash
   python3 engine/poc_runtime.py Targets/<name>/findings/idor-users.poc.json \
     --md Targets/<name>/scope.md
   ```

4. Read the verdict:
   - **PASS** — request fired, response matched `expect`. Use the
     `.result.json` request/response as the report's Step 2/Result, not a
     paraphrase.
   - **FAIL** — request completed but didn't match. Do not report this as
     confirmed; either the bug isn't there, the session died, or the spec is
     wrong. Fix and re-run, don't guess.
   - **ERROR** — the request itself didn't complete (network/timeout/DNS).
     Not a verdict on the bug either way.
   - **INCONCLUSIVE** — either no `expect` block, or the response was
     redirected and the spec never said where it should land. Evidence
     captured, no judgment. "It returned 200" is not a result when the 200
     came from a different URL than the one attacked.
5. Confirm the finding is actually backed: `cbh evidence <finding.md>` (or
   `python3 engine/evidence.py <finding.md>`). DEMONSTRATED means a passing
   artifact exists *for this finding's endpoint*; anything else means the report
   is not ready. `cbh triage` runs the same check for Q1/Q6.
6. Feed the artifact into `/validate` (Q1 quotes the request, Q6 quotes the
   diff between expected and actual victim data).

## Design constraints (why this isn't Strix's autonomous runner)

- **Single shot by default.** `--repeat` exists (race-condition timing,
  flake-checking) but hard-caps at 5 — this validates, it doesn't load-test.
  Rate-limit pacing for the program still lives in `Targets/<name>/CLAUDE.md`;
  this tool doesn't know or enforce those numbers beyond the cap.
- **No payload generation.** The human decides what request to send — same
  division of labor as curl-first testing. This only removes the
  "did I remember the response correctly" step, not the "what should I try"
  step.
- **Scope-gated in code**, same `engine/scope.py` deny-wins/default-deny logic
  the rest of the engine uses — not a judgment call this skill makes at
  invocation time.
- **Never destructive by policy** — nothing in the runtime prevents sending a
  destructive request if the spec contains one; the universal safety floor
  (own accounts/data only, no availability-affecting checks without approval)
  still applies to what you put IN the spec. This tool doesn't add a second
  safety layer beyond the scope gate.

## Related Skills & Chains

- **`triage-validation`** — this skill produces the artifact Q1/Q6 need;
  `triage-validation` is where the gate itself runs.
- **`evidence-hygiene`** — once a PASS is confirmed, redact cookies/PII from
  the `.result.json` before it goes anywhere near a report attachment.
- **`bb-methodology`** — Phase 4 (exploit/validate) is where this fits before
  handing off to Phase 5's `/validate`.
