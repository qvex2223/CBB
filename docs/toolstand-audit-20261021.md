# Tool-stand audit + awesome-bugbounty-tools harvest — 2026-10-21

Source reviewed: `https://github.com/vavkamil/awesome-bugbounty-tools` (README, 630 lines,
~40 sections). This file records what was taken, what was deliberately left, and the gaps
that are still open. `CLAUDE.md` "Tool stand" carries the short version.

## 1. The finding that mattered most was not in the repo — it was drift here

`CLAUDE.md` claimed `amass` `gowitness` `nuclei` `dalfox` installed (audit 2026-08-10).
All four were **gone** on 2026-10-21 (`~/.local/bin` had been rebuilt; only the 12
ProjectDiscovery/tomnomnom binaries survived). Our own rule says a skill whose command
returns `command not found` is a skill the agent silently abandons — so four skills had
been quietly degraded for an unknown number of hunts, with nothing logging it.

A static scan of fenced `bash` blocks in `skills/` + `commands/` for referenced binaries
that are not on PATH ranked the gaps by call-site count:

| calls | binary | status now |
|---|---|---|
| 31 | `semgrep` | still MISSING — no pip/pipx/docker on this box |
| 11 | `grpcurl` | installed |
|  9 | `nuclei` | installed (policy-restricted) |
|  5 | `trufflehog` | still MISSING — `go install` refuses it |
|  3 | `trivy` | installed |
|  3 | `assetfinder` | installed |
|  3 | `nmap` | deliberately absent (out of web-app scope) |

**Follow-up worth doing:** fold that scan into `engine/workspace_check.py` so
`cbh doctor` fails on a referenced-but-missing binary. Tool drift is exactly the class of
failure the doctor exists to catch, and right now it does not look at PATH at all.

## 2. Installed from the repo (all local, zero requests at any target)

Install path on this box: `GOPATH=~/security-research/tools/gopath GOBIN=~/.local/bin go install`
(go 1.27.2 at `~/security-research/tools/go/bin`). Release tarballs and `curl | sh` are
blocked by the sandbox classifier, so anything not `go install`-able or `npm`-able did not
land.

**JS comprehension — the biggest capability gain:**
- `jsluice` (BishopFox) — tree-sitter AST. Extracts URLs/paths/secrets by *how a value is
  used*, not by regex: a URL built as `B+"/users/"+i+"/invoice"` comes back as structured
  fragments with query/body params and headers, and secrets come back classified
  (`{"kind":"gcpKey","severity":"low"}`). Verified on a fixture.
- `wakaru` (`@wakaru/cli` 1.14.0 via npm; symlinked into `~/.local/bin`) — decompiles
  webpack/esbuild/Metro bundles into readable per-module source, and `wakaru extract`
  recovers originals from a `.map`'s `sourcesContent`.

Why these two and not something else: **three of this workspace's recorded misreads are
bundle misreads** — `framework-sinks-compile-to-runtime-helpers`,
`one-call-name-is-not-a-reader-census`, `server-load-code-is-not-in-the-client-bundle`.
All three are grep-over-minified-chunks failures, and both tools attack exactly that.
Wired into `skills/hunt-source-leak/SKILL.md` as **Phase 7b — AST, not grep**, with the
rule: a sink/reader census taken over minified chunks is a sample, and must be reported as
one.

**Recon/DNS:** `assetfinder` `alterx` (permutation wordlists) `tlsx` (cert/SAN harvest)
`asnmap` (ASN -> netblocks) `mapcidr`. `asnmap` is the one with a direct existing consumer:
`engine/scope.py --resolve` already gates netblock-scoped programmes, and `asnmap` is how
you get the netblock list without hand-reading whois.

**Bypass / takeover:** `nomore403` (the 403/40X matrix as a binary — the same ladder
`vectors.py rotate` prints in prose), `subzy` + the `can-i-take-over-xyz` fingerprint DB.

**Secrets / SCA:** `gitleaks`, `trivy`.

**Restored:** `amass` `gowitness` `nuclei` `dalfox` (the last two stay policy-restricted:
single targeted template/payload only, never a sweep).

**Plumbing:** `gf` (14 patterns in `~/.gf` from 1ndianl33t/Gf-Patterns), `unfurl`.

**Reference data, `~/security-research/tools/data/`:**
- `keyhacks.md` — per-provider instructions for *validating* a leaked key. This is the
  lead -> demonstrated-impact step. Our own rule says a secret with no demonstrated
  consequence belongs in `primitives/`; keyhacks is how it gets promoted honestly.
- `takeover-fingerprints.json` — `can-i-take-over-xyz`.
- `bt-hackerone.json` / `bt-bugcrowd.json` / `bt-intigriti.json` — `bounty-targets-data`
  hourly scope dumps. **A second, platform-published source to check a scope claim
  against.** We have a recorded incident of a worker inventing a scope change; `scope.md`
  plus a worker's summary was the only source of truth until now.

## 3. Deliberately NOT taken

- **Burp extensions** (`turbo-intruder`, `param-miner`, `http-request-smuggler`,
  `nowafpls`, `bypass-bot-detection`) — Burp is not installed here. `caido_race_window_send`
  already covers the single-packet attack that `turbo-intruder` is wanted for.
- **Scanner-shaped tools** (`toxicache`, `jaeles`, broad `nuclei` sweeps) — every project
  file forbids broad automated scanning, and they bypass `bbcurl`'s scope/pacing/audit.
  Where one encodes useful knowledge, take the **payload table** into a `hunt-*` skill, not
  the binary. `nomore403` is the borderline case: kept, but it must be pointed at a single
  confirmed 403 path, not a list.
- **`sqlmap`, `nmap`** — unchanged policy.
- **Subdomain-enum long tail** (~40 entries: Sublist3r, Findomain, puredns, shuffledns,
  massdns, bbot, …) — `subfinder` + `dnsx` + `amass` + `alterx` + `assetfinder` already
  cover passive + permutation + resolve. More enumerators is coverage theatre; the
  measured bottleneck here is **what we do with a host**, not how many hosts we find.
- **AI-agent entries** (`shannon`, `Darkmoon`, `PentestGPT`, `RedAmon`,
  `Awarexone/Agentic-Bug-Hunter`) — heavy overlap with this bundle at the skill/command
  layer and **none of them has the enforcement layer**, which is where our value actually
  is (scope resolution gate, `flock`'d global pacing, audit, response corpus, `refute`,
  stop gate, evidence verdicts). Two specific ideas are worth stealing later, named in §4.

## 4. Gaps still open after this pass

1. **`semgrep` unavailable** — `hunt-source-aware-sast`'s static-triage baseline (31 call
   sites) does not run on this box. Substitute `gitleaks` + `trivy fs` + `jsluice`, and
   **say so in the write-up** rather than implying a SAST pass happened.
2. **No hidden-parameter discovery.** `arjun`/`paramspider` (no pip), `x8` (no cargo,
   tarball blocked). Substitute: `ffuf` against a param wordlist, `katana` + `qsreplace`,
   `unfurl keys | anew`. This is a genuine capability hole, not a tooling preference.
3. **`notify` is installed but not wired.** Continuous mode means nobody is watching the
   terminal; `notify` is the only tool here that can reach the operator mid-run. Natural
   hook: a confirmed Medium+ landing in `findings/`, and `stop_gate` standing down at its
   push cap.
4. **`bounty-targets-data` is on disk but not wired into `engine/scope.py`.** Highest-value
   next build: a `--cross-check` that compares an engagement's `scope.md` against the
   platform-published dump and prints the delta. Turns "a worker said scope changed" into a
   file you can diff.
5. **`cbh doctor` does not check PATH** — see §1. Cheapest fix on this list.
6. **No GraphQL engine fingerprint.** `graphw00f` is viable (`requests` is the only
   third-party python module present), but needs ~6 raw files fetched individually since
   tarballs are blocked. Alternative: embed its fingerprint table in `hunt-graphql`.
7. **JS change monitoring.** `jsmon`'s idea — watch bundles for change, because a new
   endpoint appears in the bundle before it appears anywhere else. We have
   `engine/recon_delta.py` and `scripts/recon-snapshot.py`, but
   `install-recon-snapshot.sh` is still uninstalled. The repo entry is the argument for
   installing it.
8. **`cvemap`** (ProjectDiscovery) — EPSS/KEV-aware CVE search, a plausible upgrade to
   `scripts/refresh-cve-index.py`'s CISA-KEV-only feed. Not installed; low priority while
   the current pipeline fires.

## 5. Verification

- `cbh doctor`: 9/9 hooks, skills+commands in sync, reward verdicts OK, every CLAUDE.md
  under 60 KB (57.9 KB).
- `scripts/lint_skills.py`: 66 skills, 0 errors, 0 warnings.
- `jsluice urls|secrets`, `gf ssrf`, `unfurl keys` smoke-tested on a local fixture.
- Backups: `CLAUDE.md.bak-20261021-toolstand`.
- No request was sent at any live target during this pass.

---

## 6. Second pass, same day — "are these actually wired in, or just sitting there?"

Operator's question. Answer: **mostly sitting there, and one case was worse than idle.**
A reference census over `skills/` + `commands/` (word-boundary, excluding this audit's own
files and `engine/workspace_check.py`'s list, which is self-referential):

| Tool | named by skills/commands before this pass |
|---|---|
| `unfurl` `alterx` `tlsx` `asnmap` `mapcidr` | **0** — invisible, never reached for |
| `notify` | **0** (the one apparent hit was prose: `/api/v*/notify` as an endpoint) |
| `wakaru` `nomore403` `grpcurl` `gowitness` | 1 each |
| `trivy` | 2 |
| `jsluice` | 4 |
| `gitleaks` `assetfinder` `dalfox` | 5 |
| `subzy` | 6 |
| `gf` `nuclei` `subfinder` `httpx` `ffuf` | 10-16 |

**The case worse than idle:** `skills/bb-local-toolkit/SKILL.md` — the skill whose entire
job is "can I run this here, and where does it live" — listed `gf`, `assetfinder`,
`gitleaks` and `subzy` under **"Not installed — use the substitute, do not write the
command"**, and gave moved paths for `subfinder` `httpx` `katana` `amass` `ffuf` `nuclei`
(`/usr/bin/...`, `/usr/local/bin/...`; all are under `~/.local/bin/`). A stale *installed*
row costs one `command not found`. A stale *not installed* row is a standing instruction
not to use a tool we have.

**And the hooks saw almost none of it.** `engine/skill_signals.py::SENDER_RE` — the single
table every hook uses to decide "does this command fire a request" — still held the
2026-08 set. Ten network tools were outside it: `subfinder` `dnsx` `amass` `assetfinder`
`asnmap` `tlsx` `subzy` `nomore403` `grpcurl` `interactsh-client`. They reached live
targets with skill-gate, hunt-nudge, hunt-recall and mcp-gate all blind. `nomore403` is
the one that matters: a single invocation is dozens of bypass requests at one path, it does
not go through `bbcurl`, and therefore carries **no pacing, no audit row and no
`X-Bug-Bounty` header**. That is still true — being in `SENDER_RE` makes it *visible*, not
*throttled*.

### Fixed in this pass

1. **`SENDER_RE`** now covers all ten (`engine/skill_signals.py`, backup
   `.bak-20261021`). Offline tools (`jsluice` `wakaru` `gf` `unfurl` `mapcidr` `alterx`
   `gitleaks` `trivy`) deliberately stay out.
2. **`scripts/gen_toolstand.py`** (new) renders `bb-local-toolkit`'s three tool tables
   from live `shutil.which`, between `<!-- TOOLSTAND:BEGIN/END -->` markers. `--write`
   refreshes, `--check` exits 1 when stale. 2873 bytes of hand-written, drifted table
   deleted. Policy text (nuclei/dalfox/katana/interactsh/nomore403/notify rules) moved into
   the generator's `RESTRICTED` dict so it is carried, not re-typed.
3. **The six orphans wired into `skills/web2-recon/SKILL.md`** as a runnable sequence —
   `tlsx` SAN harvest, `asnmap`/`mapcidr` netblocks feeding `cbh scope --resolve`,
   `alterx` permutations into `dnsx`, `assetfinder` siblings, and `unfurl keys` as the
   param census that stands in for the absent `arjun`/`paramspider`/`x8`. With the warning
   that all of them bypass `bbcurl`.
4. **`hunt-nudge` now names tools, not only skills.** New `_bundle_grep`: when a command
   greps a fetched `.js`/`.map`, the hook prints the `jsluice`/`wakaru` commands and points
   at `hunt-source-leak` Phase 7b. Silent when `jsluice`/`wakaru` are already in the
   command, silent on unrelated greps. This is the hook pointed straight at the three
   recorded bundle misreads.
5. **`notify` added to `TOOLS_REQUIRED`** and documented as a publishing tool: findings
   text only, never response bodies or subscriber identity.
6. **Tests — `tests/test_tool_stand.py`, now 15 cases.** Three new classes fail the build
   on: a declared tool named by no skill/command (the orphan check — the operator's
   question as a test), a `bb-local-toolkit` row calling an installed tool missing, a
   network tool absent from `SENDER_RE`, and the generated block disagreeing with PATH.

Suite: **521 tests OK**. `cbh doctor` 6/6. `lint_skills` 66 skills, 0 errors. Copies
resynced to `~/.claude/`. Backups: `scripts/hunt-nudge.py.bak-20261021`,
`engine/skill_signals.py.bak-20261021`, `engine/workspace_check.py.bak-20261021`.

### Still not wired, deliberately

`notify` has no caller — it is documented and PATH-checked, but nothing pipes a finding
into it. Wiring it means choosing a webhook and an event (`findings/` gaining a Medium+,
`stop_gate` hitting its push cap), and it **publishes to an external service**, so it waits
for the operator's call.
