---
name: hunt-source-aware-sast
description: "TRIGGER — `/hunt` runs with `--source-code <path>` (repository available, not just the live endpoint). Covers the coordinated static-triage baseline (semgrep + ast-grep + gitleaks/trufflehog + trivy fs) that ranks source for dynamic follow-up, plus dependency/lockfile CVE scanning (SCA) as a documented exception to the dynamic-PoC rule. SKIP — bb-local-toolkit for a single tool's install path/flags in isolation; this skill is the coordinated white-box workflow, not a tool reference. hunt-* class skills still own the actual exploitation once static triage points at a candidate."
sources: "ported from usestrix/strix (Apache-2.0), strix/skills/coordination/source_aware_whitebox.md + custom/source_aware_sast.md + custom/dependency_cve_scanning.md — merged and adapted for Claude-BugHunter"
report_count: 0
---

# HUNT-SOURCE-AWARE-SAST — White-Box Static Triage + Dependency CVE Scanning

Use this skill whenever repository source is available (`/hunt ... --source-code
<path>`). Static and structural signals should **guide** dynamic testing, not
replace it — the one documented exception is a known-CVE dependency, which is
reportable on scanner output + advisory alone (see below). Everything else
static stays a hypothesis until a live PoC confirms it.

## Objective

Increase white-box coverage by combining source-aware triage with dynamic
validation. When source is available, running this baseline is the default,
not an optional extra.

## Recommended Workflow

1. Build a quick source map before deep exploitation: at least one AST
   structural pass (`ast-grep`/`sg` or `tree-sitter`) scoped to relevant paths.
2. Run first-pass static triage (semgrep) to rank high-risk paths.
3. Use triage output to prioritize dynamic PoC validation with the matching
   `hunt-*` class skill.
4. Keep findings evidence-driven — static output alone is never a report,
   except the dependency-CVE case below.

## Fast Start

Run everything from the repo root; keep scanner output in one scratch dir so
it's easy to grep back through during triage:
```bash
ART=./.bughunter-sast
mkdir -p "$ART"
```

## Baseline Coverage Bundle

Run once per repository before narrowing further:
```bash
ART=./.bughunter-sast
mkdir -p "$ART"

# Security-first triage pass — see bb-local-toolkit for install
semgrep scan --config p/default --config p/security-audit --config p/secrets \
  --metrics=off --json --output "$ART/semgrep.json" .

# Derive a bounded AST-scan target list from semgrep's own scope instead of
# guessing paths — reuses whatever semgrep already walked.
python3 - <<'PY'
import json
from pathlib import Path

art = Path("./.bughunter-sast")
data = json.loads((art / "semgrep.json").read_text(encoding="utf-8"))
scanned = data.get("paths", {}).get("scanned") or sorted({
    r.get("path") for r in data.get("results", [])
    if isinstance(r, dict) and isinstance(r.get("path"), str)
})
bounded = scanned[:4000]
(art / "sg-targets.txt").write_text("".join(f"{p}\n" for p in bounded))
print(f"sg-targets: {len(bounded)}")
PY

# Structural pass over that bounded list (ruleless — no sgconfig.yml required)
xargs -r -n 200 sg run --pattern '$F($$$ARGS)' --json=stream \
  < "$ART/sg-targets.txt" > "$ART/ast-grep.json" 2> "$ART/ast-grep.log" || true

# Secrets — working tree + history, two engines for coverage
gitleaks detect --source . --report-format json --report-path "$ART/gitleaks.json" || true
trufflehog filesystem --no-update --json --no-verification . > "$ART/trufflehog.json" || true

# Dependency + misconfig + license (secrets already covered above)
trivy fs --scanners vuln,misconfig --timeout 30m --offline-scan \
  --format json --output "$ART/trivy-fs.json" . || true
```

If diff-scoping is active (reviewing a specific PR/commit range, not the whole
repo), restrict the semgrep pass to changed files first and only expand to the
full baseline if the diff doesn't explain the surface being tested.

## Semgrep First Pass

```bash
semgrep scan --config p/default --config p/security-audit --config p/secrets \
  --metrics=off --json --output ./.bughunter-sast/semgrep.json .

# Targeted rulesets when the stack is known (faster than the broad pass)
semgrep --config=p/javascript ./src/
semgrep --config=p/python .
semgrep --config=p/golang .
semgrep --config=p/php .
semgrep --config=p/jwt .
semgrep --config=p/sql-injection .

# Custom pattern example — find raw SQL concatenation in Python
semgrep --pattern 'cursor.execute("..." + $X)' --lang python .
```
(`--config auto` works too but do not combine it with `--metrics=off` — auto
mode requires telemetry to fetch the registry ruleset.)

## AST-Grep Structural Mapping

Use `sg` for pattern-shape hunting that a text-based grep misses (matches
across formatting/whitespace variation, understands the language's grammar):
```bash
xargs -r -n 200 sg run --pattern '$F($$$ARGS)' --json=stream \
  < ./.bughunter-sast/sg-targets.txt \
  > ./.bughunter-sast/ast-grep.json 2> ./.bughunter-sast/ast-grep.log || true
```
High-value structural patterns to target manually:
- missing auth checks near route-handler definitions
- dynamic command/query construction (string-built SQL, `exec`/`eval`, shell-out)
- unsafe deserialization or template-execution call sites
- file/path operations fed by request-controlled input

## Tree-Sitter Assisted Repo Mapping

```bash
tree-sitter parse -q <file>
```
Use when grep-level mapping gets noisy — syntax-aware parsing improves
route/symbol/sink extraction for large or unfamiliar codebases before the
targeted scans above.

## Secret Coverage

```bash
gitleaks detect --source . --report-format json --report-path ./.bughunter-sast/gitleaks.json
trufflehog filesystem --json . > ./.bughunter-sast/trufflehog.json
```
`gitleaks` and `trufflehog` overlap but catch different things — gitleaks is
faster on working-tree scans, trufflehog's verified-credential mode
(`--no-verification` skips this — drop the flag when live-verifying a hit
against the actual provider is in scope and authorized) confirms a secret is
still active rather than just pattern-shaped.

## JavaScript-Side Coverage

For frontends and Node services, layer these on top of the language-agnostic
passes above:
```bash
retire --path . --outputformat json --outputpath ./.bughunter-sast/retire.json || true
eslint --no-config-lookup --rule '{"no-eval":2,"no-implied-eval":2}' \
  -f json -o ./.bughunter-sast/eslint.json . || true
```
On a minified bundle, run `js-beautify <file>` for a readable view before
grepping, or `jshint --reporter=unix <file>` as a lighter syntax check when
ESLint is over-eager. `bb-local-toolkit`'s JS-mining tools are the right next
step to pull endpoint candidates out of a beautified bundle.

## Converting Static Signals Into Exploits

1. Rank candidates by impact and exploitability.
2. Trace source-to-sink flow for the top candidates.
3. Build a dynamic PoC that reproduces the suspected issue against the live target.
4. Route the confirmed finding to `triage-validation` → `report-writing` like
   any other finding — static output alone does not skip the gate.

---

## Dependency / Supply-Chain CVE Scanning (SCA) — the one documented exception

A vulnerable dependency pinned in a lockfile (e.g. `lodash@4.17.4` with a known
prototype-pollution CVE) usually **cannot be dynamically PoC'd from outside**
— the vulnerable code path may not even be reachable from a running endpoint.
The normal "no report without a dynamic PoC" rule would silently drop these.
For this class specifically, the proof is the **lockfile entry + scanner
output + published advisory** — report it, don't discard it for lack of a
live exploit.

This is scanning **lockfiles/manifests for known-CVE package versions** — a
different input than `hunt-dispatch`'s live version-banner fingerprinting
(SharePoint build number, WordPress plugin version in a `generator` meta tag,
etc.). Both feed the same `/intel`/CVE-lookup step; this one only fires when
source is actually available.

### Scan procedure

```bash
ART=./.bughunter-sast
mkdir -p "$ART"

# Record the vuln DB age so a stale DB reads as a visible caveat, not a silent
# clean scan.
trivy version --format json 2>/dev/null | tee "$ART/trivy-version.json"

# Try a DB refresh first (best results if the sandbox has egress); fall back
# to the cached DB rather than failing the whole scan.
trivy fs --scanners vuln --timeout 30m --offline-scan \
  --format json --output "$ART/trivy-sca.json" . \
  || trivy fs --scanners vuln --timeout 30m --offline-scan --skip-db-update \
       --format json --output "$ART/trivy-sca.json" . \
  || true
```
Trivy reads `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`,
`requirements.txt`, `Pipfile.lock`, `go.mod`/`go.sum`, `Gemfile.lock`,
`pom.xml`/`gradle.lockfile`, `Cargo.lock`, `composer.lock`, and similar.

If `.VulnerabilityDB.UpdatedAt` (in `trivy-version.json`) is more than a few
weeks stale — no egress to refresh it — note that explicitly as a scan
limitation rather than silently trusting a clean result. A stale DB that still
returns *some* CVEs won't trip a "zero results" red flag, so its age is the
only signal you get for staleness.

If trivy returns **zero** vulnerabilities on a repo that clearly has
dependencies, treat that as suspicious — confirm the vuln DB is actually
present and that lockfiles were found at all before concluding "clean."

### Interpreting results

For each entry under `.Results[].Vulnerabilities[]` in `trivy-sca.json`, collect:
- `VulnerabilityID` — prefer the CVE if both CVE and GHSA are present
- `PkgName` / `InstalledVersion` — the affected package + pinned version
- `FixedVersion` — the version that resolves it
- `Target` — the lockfile path it came from (repo-relative, no leading slash)
- `.Results[].Type` (`npm`, `pip`, `gomod`, `pom`, `gemspec`, `cargo`, ...) —
  normalize to the lowercase registry name (`npm`, `pypi`, `go`, `maven`,
  `rubygems`, `cargo`, `composer`, `nuget`)
- `CVSS` — the published advisory base score
- `PrimaryURL`/references — to verify the advisory before reporting

Deduplicate by `(CVE, PkgName, InstalledVersion)`. **One report per CVE — do
not batch multiple CVEs into a single write-up.**

### Reachability is a confidence modifier, not a gate

Do not suppress or downgrade a known CVE just because you couldn't prove the
vulnerable code path is reachable from a live request. Report it with the
advisory's own CVSS score, and note the reachability caveat explicitly in the
write-up (e.g. "the vulnerable `template()` API does not appear to be imported
in application code — practical exploitability unconfirmed"). If reachability
*can* be shown, or the bug chains into a working dynamic exploit, do that and
report it as a normal dynamically-validated finding instead — this exception
only covers the case where no live PoC is possible at all.

### Reporting

There's no dedicated "dependency report" tool in this bundle — route the
finding through the normal `triage-validation` → `report-writing` pipeline,
but treat Q1 of the 7-Question Gate ("can an attacker use this right now, step
by step") as satisfied by **advisory + lockfile evidence** instead of a live
HTTP request for this class only. In the report body, always include:
- Package name + installed version + fixed version + lockfile path (no
  leading slash) so the finding is traceable in the repo
- The verified `CVE-YYYY-NNNNN` id — if only a GHSA exists, resolve it to the
  mapped CVE first; if there's genuinely no CVE, this exception doesn't apply
  — don't report a CVE-less dependency finding through this path
- The relevant trivy output excerpt as technical evidence
- Severity taken directly from the advisory's published CVSS — never guess a
  score, and never cap it at Low just because there's no dynamic reproduction
- The CWE if the advisory names one
- Verify the CVE with a web search before reporting — never guess or
  hallucinate a CVE id

### Anti-patterns

- Reporting a dependency CVE without a verified CVE id
- Batching multiple CVEs into one report
- Guessing or omitting the advisory CVSS score
- Silently dropping a known CVE for lack of a dynamic PoC — that's the exact
  failure this exception exists to prevent
- Downgrading advisory severity just because there's no live reproduction

## Coverage Target Per Repository

- one `semgrep` pass
- one AST structural pass (`sg` and/or `tree-sitter`)
- one secrets pass (`gitleaks` and/or `trufflehog`)
- one `trivy fs` pass (vuln + misconfig)

## Anti-Patterns (General SAST)

- Treating scanner output as final truth
- Spending full cycles on low-signal pattern matches instead of ranking by impact
- Reporting a source-only finding without dynamic validation evidence (the
  dependency-CVE exception above is the sole carve-out)

## Related Skills & Chains

- **`bb-local-toolkit`** — Local install paths/flags for semgrep, gitleaks,
  trufflehog individually; this skill is the coordinated baseline that strings
  them together plus the AST/trivy layers, not a substitute for that reference.
- **`hunt-dispatch`** — Live version-banner fingerprinting feeds the same
  CVE-lookup step as this skill's lockfile scan; run both when source and a
  live target are both available — they catch different vulnerable-version cases.
- **`triage-validation`** — Every static-only candidate (except the documented
  dependency-CVE exception) must clear the 7-Question Gate with a live PoC
  before it's reportable.
- **`report-writing`** — Dependency-CVE findings still go through the normal
  report format; only the PoC-evidence requirement in Q1 is substituted.
