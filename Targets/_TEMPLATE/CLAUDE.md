# <PROJECT> engagement — local rules (READ FIRST)

Authorized bug bounty (<PLATFORM>). Full scope + reward bands in `scope.md`.

> New engagement: fill every `<...>` below from THIS program's scope. Do NOT copy findings,
> host lists, priors, or "this stack is hardened"-type conclusions from any other project —
> start clean so you see what's actually here.

## Bounds — enforce every action
- **Test ONLY:** `<in-scope hosts / IP ranges>`. Everything else = OUT, don't touch even if the domain matches.
  - Wildcard scope? Resolve each subdomain, confirm the IP is in-range BEFORE testing. Log the in/out verdict in `recon/`.
- **No automated vuln scanners** (Acunetix/Qualys/nuclei-broad). Recon enum (subfinder/dnsx/httpx/katana) OK, gentle, **≤ <N> threads**.
- **Automation ≤ <N> threads/concurrency** (program rule — set from scope.md).
- **Minimal PoC only.** If a check could affect other users or availability → STOP, get program approval first.
- **Never** access other users' accounts/data — own accounts only.
- No DoS, no MITM, no social engineering, no physical. No public disclosure pre-fix.

## Pacing — set from THIS program's tolerance
- **Set the number in `profile.json`, not here.** `min_interval_seconds` is a GLOBAL budget across the whole active perimeter, not per host; start conservative and tune only once this program's tolerance is known. Also fill `required_headers` if the program mandates a header on every request. `bbcurl` and `poc_runtime.py` enforce both — you do not hand-throttle.
- If a previously-reachable host suddenly times out → STOP, don't retry-loop; check 1-2 other in-scope hosts once, then wait for user input. (That judgment the gate can't make for you.)

## Approach
- **`bbcurl`-first** — same arguments as `curl`, but scope-gated, paced and audit-logged. Bare `curl` bypasses all of it; use it only for non-target requests. No Burp. Browser automation available for SPA/DOM/OAuth.
- Wildcard scope → subdomain enum first, THEN targeted manual hunting on confirmed in-scope hosts. Don't mass-scan once enumerated.

## Reward focus (Critical/High = the money — confirm bands in scope.md)
ATO, auth bypass, SQLi/RCE/SSRF/SSTI, server-side XSS (not self), business logic w/ real impact, significant IDOR (must demo criticality), 1-day on perimeter WITH working exploit.
Deprioritize (mostly unpaid): headers, clickjacking, host-header-injection, low CSRF, self-XSS, user-enum, misconfig-without-impact, TLS nits.

## Report requirements (per `scope.md`)
One vuln / one linked chain per report. Must have: description, repro steps, severity analysis, vulnerable URL, vuln type, screenshots/video. Track in `submissions.txt`.

## Evidence hygiene
Redact cookies + other-user PII BEFORE screenshots. Evidence → `evidence/` (never share raw).

## Recon log discipline (MANDATORY)
**Start of session: read `notes.md` Open threads FIRST — continue those, don't start recon from scratch.**
After any request to a host: append a scan-log row to `hosts/<host>.md` — `date · what ran (exact cmd/path) · result summary · next hook`. Findings (stack/versions/endpoints/params/auth/leaks) verbatim where cheap; dead ends too. Check the host file BEFORE re-running anything. `notes.md` = cross-host status + leads; per-host detail in `hosts/<host>.md`.

## Layout
- `scope.md` — program scope + rules + reward bands
- `recon/` — enum output, scope-verification log
- `hosts/` — per-host notes (one file per confirmed in-scope host)
- `findings/` — draft findings
- `evidence/` — screenshots/PoC (sensitive)
- `notes.md` — running notes, leads, dead ends, where we stopped
- `submissions.txt` — submitted report tracker
