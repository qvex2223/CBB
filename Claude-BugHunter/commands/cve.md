---
name: cve
description: Standing CVE digest — what new CVEs landed on which in-scope hosts, ranked, then verify the version on the host and start hunting the ones that survive. Usage: /cve [project] [--min-cvss N] [--since YYYY-MM-DD]
---

# /cve

Answers "что там по CVE" — and then acts on it.

`cve_watch.py` runs nightly per engagement and appends every NVD keyword match to
`Targets/<name>/notes.md` (prose) and `Targets/<name>/recon/cve-ledger.jsonl`
(records). This command reads the ledgers, prints the ranked host-grouped
digest, and moves straight into verification.

## What This Does

1. **Print the digest** — `python3 scripts/cve-digest.py [--project X] [--min-cvss N] [--since DATE]`
   Grouped by host, ranked by CVSS, `new` leads only by default.
   A daily snapshot also sits at `Targets/CVE-DIGEST.md` (regenerated 07:45 and at boot).
2. **Scope-check first.** Every host in the digest goes through `/scope <host> --resolve`
   before it is touched. A netblock-scoped program returns `UNVERIFIED` without
   `--resolve`, and **`UNVERIFIED` is not approval to test**.
3. **Confirm the running version.** This is the whole point — a ledger row is a
   *watchlist keyword match against NVD*, not a finding. The version recorded in
   `recon/cve-watchlist.txt` may be months stale. Fingerprint the live host with
   `bbcurl` (banner, `Server:`/`X-Powered-By`, error-page markers, static asset
   hashes) before believing any row.
4. **Route to the skill.** `hunt-dispatch`'s signal table maps the confirmed
   fingerprint to the matching `hunt-*` skill — Tomcat/Spring to `hunt-springboot`,
   Next.js to `hunt-nextjs`, WordPress upload paths to `hunt-file-upload`, Keycloak
   to `hunt-oauth`/`hunt-auth-bypass`. Load it before firing at that surface; the
   skill gate enforces this while hunt mode is armed.
5. **Fire a real request.** `/poc-run` with a spec, so there is a `.result.json`
   behind whatever gets claimed. An unfired CVE lead is a hypothesis and stays an
   open thread.
6. **Close the loop.** Mark each lead as it resolves:
   ```
   python3 scripts/cve-digest.py --mark CVE-2026-65637 --status checked   --note "Tomcat 9.0.85, not in affected range"
   python3 scripts/cve-digest.py --mark CVE-2026-65640 --status dismissed --note "no /wp-admin, WP is a static export"
   ```
   Then `/remember` the result — confirmed *and* rejected both count.

## Usage

```
/cve                          # every engagement, unchecked leads
/cve kcell                    # one engagement
/cve --min-cvss 9.0           # criticals only
/cve --since 2026-08-20       # what landed since a date
```

## Rules That Still Apply

- **Never test a version you have not confirmed live.** Reporting a CVE off a
  stale watchlist entry is exactly how an N/A submission happens.
- Pacing and mandatory headers are enforced by `engine/pacing.py` — use `bbcurl`,
  not bare `curl`, so the request is scoped, paced and audited.
- No Low/Info submissions. A confirmed-but-unexploitable CVE is a logged
  rejection, not a report.
- `nuclei` only as a single targeted template against one confirmed finding,
  never as a sweep.
