# `cbh` — claude-bughunter CLI

> **Secondary interface — slash commands are primary.** Inside a Claude Code conversation, use the slash commands (`/recon`, `/hunt`, `/triage`, `/report`, `/validate`, `/chain`, `/autopilot`, `/scope`, etc.) — they leverage the full skill content and the LLM's judgment.
>
> `cbh` is the **terminal-native deterministic runner** — use it when you're outside Claude Code, automating in CI/CD, running scheduled recon, or verifying labs reproducibly. Same skills, different execution model.
>
> **Availability — three ways to run `cbh`:**
> 1. **From a git clone** (no install): `python3 scripts/cbh.py <cmd>` — uses the live `skills/` + `docs/disclosed-reports/`.
> 2. **Installed standalone** (works without the repo): `pipx install git+https://github.com/elementalsouls/Claude-BugHunter` (or `pip install .` from a clone). Gives you a global `cbh` backed by a bundled skill index; recon output goes to `./recon/` (override with `--out`), and skill/report pointers link to GitHub.
> 3. It does **not** ship with the plugin — the plugin provides skills + slash commands only.
>
> Regenerate the bundled index after editing skills: `python3 scripts/gen_skill_index.py`.

## When to use `cbh` vs slash commands

| Use case | Use this |
|---|---|
| Hunting a new target conversationally, applying judgment | **Slash commands** in Claude Code (`/hunt`, `/triage`, etc.) |
| Building a chain across multiple primitives | **Slash commands** — LLM keeps state across the conversation |
| Scheduled / CI / scripted runs | **`cbh`** — deterministic exit codes, identical output across runs |
| Bulk passive recon (hundreds of subdomains) | **`cbh recon`** — real `subfinder`/`dig`/`curl`, no LLM in the loop |
| Verifying labs / reproducing claims | **`cbh`** — every Phase 2 doc's curls work via `cbh` too |
| Reading skills without Claude Code installed | **`cbh`** + browsing `skills/` and `docs/disclosed-reports/` |
| Triage gate at PR time / pre-submit linting | **`cbh triage`** — deterministic keyword-match against the 7-Question Gate |

The two interfaces consume the same content (`skills/` + `docs/disclosed-reports/`). They produce different outputs because they execute differently. Pick by context, not by preference.

## Operating modes for the CLI

> Stdlib + optional `subfinder` for richer recon. No build step.
>
> **Two HTTP-routing modes** within the CLI — pick what fits your setup:
> 1. **Curl-only (default)** — stdlib HTTP, no Burp dependency. Works on any laptop with Python 3.10+.
> 2. **Burp Suite integration** — `--burp` flag routes everything through Burp's proxy (default `127.0.0.1:8080`). Requests + responses land in Proxy → HTTP history; you can send any of them to Repeater/Intruder/Scanner/Collaborator. Pairs with the **Burp MCP server** (port 8181) for Claude-Code-conversational hunting.

## Install

```bash
# Symlink the script to PATH (Linux / macOS)
chmod +x scripts/cbh.py
ln -sf "$(pwd)/scripts/cbh.py" /usr/local/bin/cbh

# Verify
cbh --help
```

Or run inline from a repo checkout:

```bash
scripts/cbh.py --help
```

## Operating modes

### Mode 1 — Curl-only (default)

Works out of the box. All HTTP goes via Python `urllib`. No Burp required.

```bash
cbh recon hackerone.com
cbh classify "https://api.target.com/v1/users/42?next=..."
```

### Mode 2 — Burp Suite Pro integration

Two integration points:

**A. `--burp` flag — proxy routing.** Routes every HTTP request `cbh` makes through Burp's proxy. Every request + response shows up in Burp Proxy → HTTP history with full reqs/resps captured for replay.

```bash
# Start Burp Suite Pro, ensure Proxy listener is on 127.0.0.1:8080
cbh recon hackerone.com --burp
cbh classify "https://target.com/api/users/42" --burp

# Or use a custom proxy URL (Burp on a different port, mitmproxy, ZAP, etc.)
cbh recon hackerone.com --proxy http://127.0.0.1:8081

# Or set the env var once
export CBH_BURP_PROXY=http://127.0.0.1:8080
cbh recon target.com   # auto-detected
```

What happens after: every host `cbh recon` probes appears in Burp's Target → Site map. Each title-extracted live host is one click from Repeater. You drive the actual attacks from Burp; `cbh` did the bulk discovery + classification.

**B. Burp MCP — conversational hunting via Claude Code.** If you've installed the Burp MCP server BApp extension (typical port `127.0.0.1:8181`) and registered it with Claude Code via `claude mcp add burp -s user -- java -jar ~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar`, you can do the hunt loop entirely in a Claude conversation:

```
You:  cbh classified /api/users/42 as IDOR-prone. Send it to Burp Repeater
      with X-User-Id: 99 swapped in.
LLM:  [uses Burp MCP tool calls: get last response, send to Repeater with
       header swap, returns the new response]
You:  Looks like cross-tenant read. Apply triage-validation 7-Question Gate.
LLM:  [reads hunt-idor + triage-validation skills, runs 7Q against the
       captured req/resp pair, returns PASS/DOWNGRADE/KILL]
```

This mode is the most ergonomic — the LLM drives Burp via MCP while consulting the skill content. `cbh` and Burp MCP are complementary: `cbh` is fast at bulk classification + structured triage; Burp MCP is fast at deep individual-request analysis.

### When to use which mode

| Phase | Curl-only | Burp proxy | Burp MCP |
|---|---|---|---|
| Recon (bulk subdomain + HTTP probe of 50+ hosts) | ✓ fastest | ✓ + audit trail | overkill |
| Single-URL classification | ✓ | ✓ + traffic captured | ✓ (conversational) |
| Detailed request manipulation (header swap, body fuzz, Intruder) | painful | ✓ (Repeater/Intruder) | ✓ (LLM-driven) |
| Triage + report drafting | ✓ | ✓ | ✓ |
| Discipline-rule enforcement (OOB gate, marker discipline, body-diff) | manual | manual | ✓ (LLM can apply the rules) |

**Operator default:** `--burp` mode if Burp Suite Pro is open; curl-only mode otherwise. Burp MCP mode for engagements where you want maximum LLM-driven workflow inside Claude Code.

---

## Subcommands

### `cbh recon <target>` — passive recon + live-host probe

```bash
cbh recon hackerone.com
```

Pipeline (in order):

1. **Passive subdomain enumeration** — `crt.sh` certificate transparency (always, no key needed) + `subfinder` (if installed) merged + deduplicated.
2. **DNS resolution** — stdlib `socket.getaddrinfo()` to dodge the `dnsx` segfault issue documented on macOS arm64 (per `web2-recon` Operator Notes).
3. **HTTP probe** — concurrent (10 threads) `urllib.request` → status code, Server header, X-Powered-By, X-Drupal-Cache, and `<title>` extraction.
4. **Summary** — writes `recon/<target>/RECON_SUMMARY.md` with the live-host table and a "Suggested next moves" pointer to `classify`.

Outputs:
- `recon/<target>/subdomains.txt`
- `recon/<target>/resolved.txt`
- `recon/<target>/live-hosts.json`
- `recon/<target>/RECON_SUMMARY.md`
- `recon/<target>/manifest.json` — the **recon→hunt handoff contract** ([`docs/recon-manifest.md`](recon-manifest.md))

### `cbh surface <target>` — ranked attack surface from the recon manifest

```bash
cbh surface hackerone.com
```

Reads `recon/<target>/manifest.json` and prints the ranked **P1 / P2 / Kill** surface
(api/auth/admin hosts → P1; static/CDN → Kill). The same manifest is what `hunt <target>`
ingests to seed `scope.md` + `notes.md`, and what the `web2-recon` / `hunt-source-leak`
skills append secrets / service data to. This is the deterministic backing for the `/surface`
slash command. See [`docs/recon-manifest.md`](recon-manifest.md) for the full contract.

### `cbh classify <url>` — pattern-match URL → hunt-* skills

```bash
cbh classify "https://api.target.com/v1/users/42?next=https://evil.com"
```

Two-stage matcher:

1. **URL-pattern triggers** (high confidence) — 18 hand-curated regexes mapping URL shapes to `hunt-*` skill names. Examples:
   - `[?&](url|next|redirect|return)=` → `hunt-ssrf`
   - `/api/users/{id}` → `hunt-idor` + `hunt-api-misconfig`
   - `/graphql` → `hunt-graphql`
   - `/oauth/(authorize|token|callback)` → `hunt-oauth`
   - `/_layouts/15/` or `/_vti_bin/` → `hunt-sharepoint`
   - `/functionRouter` → `hunt-rce` + `hunt-ssti` (Spring Cloud Function CVE-2022-22963)
   - `/cli` or `/jnlpJars` → `hunt-rce` (Jenkins CVE-2024-23897)
2. **Description-keyword match** (lower confidence) — keyword overlap against each skill's `description:` frontmatter.

Output includes a pointer to the matched skill's Pattern Library doc in `docs/disclosed-reports/<skill>.md` when one exists.

### `cbh diff <url-substring>` — did the answer ever change?

```bash
cbh diff /api/v1/camunda-workers/external
```

Reads the response corpus `bbcurl` writes (every body, hashed, headers included).
Prints how many requests hit that surface, how many **distinct** bodies came back,
and a unified diff of the two most recent distinct ones. A burst with one distinct
body is a rotate signal: nothing being sent reaches anything that decides the
answer.

#### `--fields` — did the *answer* move, or only the bytes?

```bash
cbh diff /api/lookup2 --fields
```

Groups the corpus by path and reports each JSON field as CONSTANT (same value in
every capture) or varies (with the values seen). Ends with a PHANTOM ORACLE line
when a decisive field never moved across genuinely different requests — the shape
that gets a stub reported as an information disclosure.

### `cbh spec <url-substring>` — a PoC spec from a request already fired

```bash
cbh spec /api/v1/users/124 --steps --vuln-class idor --out findings/idor.poc.json
```

Rebuilds a `poc_runtime` spec from the corpus: method, headers, body, and an
`expect` block from the recorded response. Credentials were redacted at capture
time and come back as placeholders. `--steps` emits a chain skeleton whose second
step is an explicit `REPLACE ME` verify step.

### `cbh triage <finding.md>` — 7-Question Gate

```bash
cbh triage findings/idor-2026-05-15.md
```

Runs all 7 questions from the `triage-validation` skill against the finding text. Returns:

- **PASS** — all 7 answered with evidence. Eligible for `cbh report`.
- **DOWNGRADE** — failed Q2 (severity) or Q5 (duplication) only. Continue with tempered severity claim.
- **KILL** — failed multiple questions OR Q7 matched the never-submit list (self-XSS, missing security headers, etc.). Per `triage-validation` discipline: do not draft the report.

The gate matches keyword signals per question; absence-of-evidence is treated as "not answered". This catches the most common Phase 2D-verified FP shapes:

- Q1 missing curl/POST/GET → finding wasn't actually tested
- Q6 missing "leaked / exfiltrated / oob callback" → impact is "technically possible" only
- Q7 hit on "self-xss / rate-limit only / clickjacking" → automatic KILL

### `cbh report <finding.md> [--platform h1|bugcrowd|intigriti|immunefi] [--out path]`

```bash
cbh report findings/idor-2026-05-15.md --platform bugcrowd --out submissions/h1-draft.md
```

Parses the finding's YAML frontmatter + section headings, emits a platform-specific draft:

- **H1** — common template; CVSS optional.
- **Bugcrowd** — adds VRT mapping + severity-request paragraph (per `bugcrowd-reporting` skill).
- **Intigriti** — common template + CVSS 3.1 vector slot.
- **Immunefi** — Foundry-PoC-required structure; `forge test --match-test` invocation pre-filled.

The draft will have `(fill in)` placeholders wherever the finding text didn't include the relevant section. **The CLI never invents content** — the operator owns each placeholder.

### `cbh api-manifest <inputs...> --out <file>` — normalize API descriptions and traffic

```bash
cbh api-manifest openapi.json traffic.har postman.json burp-export.xml \
    --out recon/target.com/api-manifest.json
```

Offline parsing of OpenAPI/Swagger JSON, HAR, Postman collections, Burp XML, GraphQL
introspection, and existing CBH manifests. Nothing is sent anywhere.

Every source collapses onto one **operation** per `(method, host, canonical path)`. Numeric
ids, UUIDs and OpenAPI path variables all normalize to `{id}`, so `/v1/orders/42` from a HAR
and `/v1/orders/{orderId}` from a spec merge into a single row instead of looking like two
endpoints. Each operation carries its parameters, schema fields, declared security, and
`risk_hints` derived from its own shape — see `docs/recon-manifest.md` for the hint table.

### `cbh workflow <manifest> --out <file>` — business-state hypotheses

```bash
cbh workflow recon/target.com/api-manifest.json --out recon/target.com/workflow.json
```

Groups operations into entities, derives the action each one performs, and emits ranked
hypotheses: replay, step-skip, cross-principal, hidden-field, value-boundary, and race
(the last only for operations whose names imply one-time value — coupon, refund, transfer).
These are the questions worth asking about a flow, not a payload list.

### `cbh vectors seed-from-manifest <host> --manifest <f> [--workflow <f>]`

```bash
cbh vectors seed-from-manifest api.target.com \
    --manifest recon/target.com/api-manifest.json \
    --workflow recon/target.com/workflow.json
cbh vectors next api.target.com
```

Seeds the attack-vector ledger from evidence instead of from the Cartesian product. The old
`cbh vectors seed` created every vulnerability class for every endpoint — a ledger nobody can
finish, ranked on raw catalog impact, which is how a static asset ends up recommended as an
RCE candidate. Each vector here carries the `risk_hint` that justified it and a priority
blended from that hint and the operation's own risk.

```bash
cbh vectors prune api.target.com            # dry run: what would go
cbh vectors prune api.target.com --apply    # backs up the ledger first
```

`prune` removes **only** untouched legacy rows — still `untried`, zero requests fired, no
mutation burned, no note written. Anything anyone invested in stays.

### `cbh recon-diff <old-manifest> <new-manifest>` — what changed since last time

```bash
cbh recon-diff recon/target.com/manifest.2026-08.json recon/target.com/manifest.json
```

Added/removed assets and operations, newly appearing parameters and fields, and — the highest
signal row it produces — any operation whose **declared security changed**. On a target you
have already hunted, the delta is the surface, not the whole manifest.

### `cbh authz-matrix` — plan principal/object/action checks

```bash
cbh authz-matrix plan recon/target.com/api-manifest.json principals.json \
    --out authz-plan.json
cbh authz-matrix evaluate --help        # scoring a captured pair of responses
```

Builds the cross-user / cross-tenant comparison matrix that access-control bugs actually live
in. Two rules it enforces rather than suggests: a principals file that contains an inline
token, cookie or `Authorization` value is **refused** — use environment-variable *names* — and
a cross-user write is not reported as a violation until a verified state change proves it, so
"the POST returned 200" cannot become a finding on its own.

`--emit-specs <dir>` writes one `poc_runtime` skeleton per test, so the plan does not stop
at a list somebody still has to hand-type into curl:

```bash
cbh authz-matrix plan api-manifest.json principals.json \
    --out authz-plan.json --emit-specs findings/authz/ --limit 20
```

Each skeleton asserts the **finding** condition, not the correct behaviour — a spec that
PASSed when the server correctly denied would hand every hardened endpoint a green
artifact, and `engine/evidence.py` and the stop gate both read PASS as "demonstrated".
Writes get a `verify` step that reads the state back **as the owner**, because verifying
with the attacker's own credentials proves nothing: the same broken authorization that
allowed the write would also show it. Object ids stay `{{OBJECT_ID}}` placeholders — the
matrix does not know which order belongs to which account, and inventing one would mean
firing at a stranger's data.

The module plans, emits and evaluates; it never fires. Execution goes through
`poc_runtime` like everything else.

### `cbh poc-minimize <spec.json> <result.json>` — the reproduction a triager will run

```bash
cbh poc-minimize findings/idor.poc.json findings/idor.poc.result.json \
    --out findings/idor-repro.md
```

Both halves are required on purpose: the spec says what was *meant* to happen, the
`.result.json` says what the server actually returned. A repro written from the spec alone
is a plan, not evidence.

Reduces a multi-step spec to its capture dependencies, the explicit login/control steps, and
the final verification step, then renders a short Markdown reproduction: impact, steps,
expected proof, observed status, and a pointer to the machine-readable artifact. A technically
valid finding still gets closed when the repro is twenty steps long — this is the fix for that,
and the verbose artifact stays attached as the appendix.

### `cbh report-intel <query>` — search a local disclosed-report dataset

```bash
cbh report-intel ~/datasets/disclosed-reports.json \
    "idor order refund cross-tenant" --limit 5
```

Scores title, weakness, CWE, impact, program and bounty overlap against a **local** JSON
dataset and returns at most ten compact matches. Bounded retrieval on purpose: loading a
whole report corpus into context costs more than it returns. Point it at a dataset you are
authorized to hold; none ships with the bundle.

### `cbh memory-migrate` — normalize the hunt-memory schema

```bash
cbh memory-migrate                              # dry run: counts, hashes, per-field changes
cbh memory-migrate --apply                      # backs every file up first
cbh memory-migrate --rollback 20260915T101500Z  # restore
```

Normalizes vulnerability classes and techniques through `memory.py`'s own functions, and
backfills `locally_confirmed` / `platform_outcome` on old rows. A journal row with no result
is left **unannotated** rather than assumed successful — that assumption is the bug this
separation exists to remove. Append-only semantics hold: rows are rewritten in place, never
reordered or dropped, and a row-count mismatch aborts the write.

## Composition example — full engagement loop

```bash
# Day 1 — intake
cbh recon target.com
# → recon/target.com/RECON_SUMMARY.md

# Day 1b — deepen the API model and seed the ledger
cbh api-manifest swagger.json traffic.har --out recon/target.com/api-manifest.json
cbh workflow recon/target.com/api-manifest.json --out recon/target.com/workflow.json
cbh vectors seed-from-manifest api.target.com \
    --manifest recon/target.com/api-manifest.json \
    --workflow recon/target.com/workflow.json

# Day 2 — hunt
cbh vectors next api.target.com          # impact-ranked, never empty
cbh classify "https://api.target.com/v1/users/42?token=abc"
# → matches hunt-idor + hunt-api-misconfig + hunt-ssrf
# → read docs/disclosed-reports/hunt-idor.md for the IDOR pattern library
cbh diff /v1/users                       # did the answer ever move? if not, rotate
cbh vectors rotate idor                  # the next mutation, not the next host

# Day 3 — validate
# Wrote the finding up as a markdown
cbh triage findings/idor.md
# → PASS — eligible for report drafting

# Day 4 — submit
cbh poc-minimize findings/idor.poc.json findings/idor.poc.result.json \
    --out findings/idor-repro.md         # short human repro
cbh report findings/idor.md --platform h1 --out drafts/h1-draft.md
# Review the draft, fill in placeholders, attach evidence, submit

# Later — re-recon by delta, not by re-reading
cbh recon target.com
cbh recon-diff recon/target.com/manifest.prev.json recon/target.com/manifest.json
```

## What the CLI does NOT do

- **Does not auto-attack.** It surfaces candidates and applies discipline rules. `cbh recon` probes live hosts and `poc_runtime` fires PoC specs, but nothing here sweeps a target or escalates on its own — and every request that does go out is scope-verified, paced, and audited by `engine/request_broker.py`.
- **Does not execute the authorization matrix.** `cbh authz-matrix` plans and evaluates; firing it is a `poc_runtime` job, on purpose.
- **Does not invent finding content.** Sections without source text become `(fill in)` placeholders.
- **Does not bypass platform rules.** The Bugcrowd VRT mapping is left to the operator — the CLI emits the structural slot, not the choice.
- **Does not replace the skill content.** The CLI is a router into the skill content; the skills are still where the operator-grade depth lives.

## Why this exists

Every other bug-bounty toolchain is either (a) a payload list with no methodology, or (b) a methodology PDF with no runner. This CLI bridges the two: it consumes the repo's skill content and produces engagement-stage outputs. The `recon → classify → triage → report` flow mirrors the 6-phase workflow that `bb-methodology` describes, with the discipline rules from `triage-validation` enforced programmatically at the triage gate.

For senior pentesters: a productivity multiplier that does the boring orchestration so you stay in the interesting parts.

For junior researchers: a guardrail that prevents the top three N/A-submission classes (no real HTTP test, no concrete impact, finding on never-submit list).

**Choice not dogma:** operators with no Burp run curl-only; operators with Burp Pro route via `--burp`; operators with Burp + MCP drive everything from a Claude Code conversation. All three are first-class supported.
