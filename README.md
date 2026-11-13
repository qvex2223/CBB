# BugHunter

Working copy of the web application bug-hunting toolkit that drives this
workspace: a skill bundle, a deterministic engine, and the gates that stand
between an agent and a target. **The tool lives in this repository; engagement
data never does.** Targets, findings, evidence and captured responses stay
outside it — see [Layout](#layout).

68 skills · 55 per-class `hunt-*` skills · 22 slash commands · 25 per-class
disclosed-report digests · a deterministic engagement engine under `engine/`.

It is written for Claude Code and reads the same doctrine file from any agent
CLI: what differs between clients is one capability row in `engine/client.py`,
which `cbh client` prints. Everything that binds — scope, pacing, the audit log,
the response corpus — binds in `engine/`, below whichever client is driving.

---

## Layout

| Path | What it is | In git? |
|---|---|---|
| this repository | the toolkit itself: skills, commands, `engine/`, `scripts/`, gates | yes |
| `Targets/<platform>/<program>/` | one folder per engagement: `scope.md`, `profile.json`, `findings/`, `primitives/`, `leads/`, `hosts/`, `recon/`, `notes.md` | **no** |
| `Targets/_TEMPLATE/` | the skeleton every new engagement is copied from | yes |
| `Targets/_*-CANDIDATES/` | program briefs + normalized `programs/<key>/` per platform | **no** |
| `~/.claude/{skills,commands,agents}/` | the installed copy Claude Code actually loads | n/a |
| `hunt-memory/` (here) or `~/.cbh/hunt-memory/` | persistent memory: audit log, patterns, pacing, response corpus | README only |

`engine/memory.py` resolves memory to a workspace-local `hunt-memory/` when one
exists, otherwise `~/.cbh/hunt-memory/`. `.gitignore` keeps `evidence/`, HARs
and screenshots out of the repository regardless of where they land.

---

## Install

```bash
bash scripts/install.sh            # skills + commands + hunt.sh → ~/.claude/
bash scripts/install.sh --burp-mcp # also wire the existing Burp MCP server in
```

Existing files are moved to `~/.claude/install-backups/<timestamp>/` so backups
never load as duplicate skills, and a manifest is written to
`~/.claude/.skill-manifests/` for a clean uninstall. Skills co-owned with a
sibling bundle are left alone.

→ [`INSTALL.md`](INSTALL.md) for Burp MCP wiring and the optional regenerator.

---

## Two ways to drive it

**Slash commands in Claude Code — primary.** Skills also load by topic: describe
what is being tested and the matching `hunt-*` skill loads without being named.

| Phase | Commands |
|---|---|
| Open / resume | `/scope` `/recon` `/surface` `/pickup` `/intel` `/cve` |
| Hunt | `/hunt` `/anomaly` `/oracle` `/parallel` `/chain` `/poc-run` |
| Close | `/triage` `/validate` `/report` `/remember` `/debrief` `/learn` |
| Housekeeping | `/view` `/autopilot` `/memory-gc` |

**`cbh` — secondary.** The same engine without a model in the loop, for CI,
scripted runs and deterministic verification (`scripts/cbh.py` is the same entry
point by path):

```bash
cbh recon <target>
cbh leads --project <platform>/<program>     # the work queue, ranked by payout + staleness
cbh crew --project <platform>/<program>      # how many workers this engagement's pacing can feed
cbh autohunt --project <platform>/<program>  # the next wave of worker briefs, from its own state
cbh oracle recon/<target>/manifest.json --axes auth-strip,principal-swap
cbh coverage --engagement <project>
cbh doctor                                   # workspace self-check: hooks, skills in sync, routing
```

→ [`docs/cbh-cli.md`](docs/cbh-cli.md) · [`USAGE.md`](USAGE.md)

---

## Brakes are code, not prose

An agent told ten times to be careful and once to be aggressive resolves every
ambiguous moment the wrong way, so the limits are enforced in modules rather
than written in instructions:

- **`engine/scope.py`** — default-deny host gate. Anything not matched by an
  in-scope pattern is refused, including assets a program publishes as full
  URLs (`https://host/path` normalizes to its host).
- **`engine/pacing.py`** — per-target request pacing.
- **`engine/request_broker.py`** — the single egress path: scope, pacing,
  mandatory headers, audit log and response corpus all apply to every request.
- **`engine/responses.py`** — scrubs identity fields and credential *values*
  before anything reaches disk: `<owner>_`-prefixed PII keys (`company_email`),
  query/JSON/header spellings, and OAuth token bodies
  (`access_token`, `refresh_token`, `client_secret`).
- **`engine/stop_gate.py`** — refuses to keep hammering a dead host.
- **`engine/class_proof.py`** — per-class proof rules: a class whose own oracle
  was never captured grades `CLASS-UNPROVEN`, so an unproven impact cannot be
  filed as a finding.
- **`engine/funnel.py`** — one definition of a funnel item (`leads/` →
  `primitives/` → `findings/`), read by the queue and by the stop gate, so both
  count the same work.
- **`scripts/*-gate.py`** — `PreToolUse` hooks under Claude Code: the
  orchestrator may not fire requests while a hunt is armed (`crew-gate`), a
  class payload needs its skill loaded (`skill-gate`), a worker may not write
  controls (`control-guard`), browser and proxy calls are scoped and paced
  (`mcp-gate`).

`scripts/bbcurl` is the hand-driven front end to the same broker. Tests:
`python3 -m unittest tests.test_responses`, and `engine/scope.py` carries its
own self-test.

---

## The second track: find what does not add up

The `hunt-*` taxonomy is a map of what already paid, so hunting only through it
is survivorship bias — by the time a bug has a class name the program has a
known-issues entry for it. These modules exist to work the other side:

| Module | Question it answers |
|---|---|
| `engine/anomaly.py` | what in these responses does not add up, before naming a class |
| `engine/diff_matrix.py` | which two states of the same call should disagree |
| `engine/sweep.py` | fires that plan through the broker and reports only anomalies |
| `engine/coverage.py` | which dimension of a request was ever actually varied (a sweep of 200s is not coverage — it was an SPA fallback) |
| `engine/recall.py` | what this route has already been asked, before the next request goes out |
| `engine/vectors.py` | what to rotate to instead of closing a host on a hunch |
| `engine/learn.py` | which findings fit no existing class, so the taxonomy keeps growing |
| `engine/session_debrief.py` | what was actually done, written down on the way out |
| `engine/program_quality.py` | time-to-verdict, duplicate and N/A rates — is this program worth the next week |

---

## Program triage

Intigriti briefs store `assetsCollection` and `bountyTables` as **lists of
dated revisions, oldest first — only the last one is live**. Building a scope
from the union of all revisions puts assets a program dropped years ago back in
scope. Every script here keeps that discipline and treats `bountyTierId == 5`
as out of scope:

```bash
python3 scripts/intigriti-scope-truth.py <brief-key> [<brief-key> ...]   # live scope block
python3 scripts/intigriti-scope-audit.py               # STALE / PHANTOM / TIER5 / MISSING per project
python3 scripts/intigriti-validate.py --project <p> --finding <f.md>
python3 scripts/program-scaffold.py --all               # normalized folder per program
python3 scripts/standoff-scaffold.py                    # same, Standoff 365
```

`intigriti-validate.py` asks the question generic `/validate` does not — *would
this program reject it on sight* — reading the program's own brief. Exit 1 on
any blocker.

---

## Standing CVE digest

`scripts/cve-refresh-daily.sh` + `cve-refresh.{service,timer}` keep
[`docs/cve-coverage.md`](docs/cve-coverage.md) and each project's CVE ledger
current; `scripts/cve-digest.py` reports what landed on in-scope hosts, and
`/cve` ranks it and verifies the version on the host before anything is hunted.

```bash
bash scripts/install-cve-automation.sh
python3 scripts/cve-digest.py
```

---

## Git

`origin` is SSH and pinned to its own deploy key in this repository's config:

```
origin            git@github.com:qvex2223/CBB.git
core.sshCommand   ssh -i ~/.ssh/id_ed25519_cbb -o IdentitiesOnly=yes
```

Branch: `main` — the toolkit at the repository root, published as one commit.
History is not a changelog of engagements: it is rewritten whenever the tool is
republished, so clone it, don't chase its commits.

`runtime/` and `.claude/` are ignored, with
`settings.local.json.example` force-added as the only exception.

---

## Authorization

For assets owned or covered by written authorization — in-scope bounty assets,
pentest engagement letters, CTFs, own infrastructure. `triage-validation`'s
7-Question Gate asks the scope and accepted-impact questions before a report is
written, and the bundle carries no post-exploitation, persistence, evasion or
mass-targeting tooling. See [`SECURITY.md`](SECURITY.md).

> Anthropic's models apply real-time cyber safeguards that block offensive
> security tooling development by default, so authorized in-scope work can still
> hit a refusal that is not this bundle's doing. The
> [Cyber Verification Program](https://claude.com/form/cyber-use-case) exists to
> get them adjusted for legitimate dual-use work.

---

## Docs

| Doc | Contents |
|---|---|
| [`INSTALL.md`](INSTALL.md) | full setup, Burp MCP, skill regenerator |
| [`USAGE.md`](USAGE.md) | workflow walkthrough · worked engagement |
| [`docs/architecture.md`](docs/architecture.md) | phase architecture · skill-to-phase map |
| [`docs/skills.md`](docs/skills.md) | searchable catalog of all 68 skills |
| [`docs/cbh-cli.md`](docs/cbh-cli.md) | every `cbh` subcommand |
| [`docs/cve-coverage.md`](docs/cve-coverage.md) | CISA KEV coverage snapshot |
| [`CLAUDE.md`](CLAUDE.md) | the workspace's own operating rules |
| [`FROZEN.md`](FROZEN.md) · [`RESTORE.md`](RESTORE.md) | what must not drift · how to rebuild |
| [`SECURITY.md`](SECURITY.md) | authorized-use posture · what is excluded |

---

## Credits

BugHunter is an MIT fork of
[elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
(web surface only — the AD, cloud/infra, red-team, Web3, mobile and OSINT skills
are removed by design), which vendors
[shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)
for methodology, validation and reporting. Per-skill attribution in
[`docs/credits.md`](docs/credits.md).

Tooling leaned on: [Burp Suite + MCP server](https://portswigger.net/burp) ·
[ProjectDiscovery](https://github.com/projectdiscovery) (subfinder · dnsx ·
httpx · katana · nuclei) · [SecLists](https://github.com/danielmiessler/SecLists) ·
[Assetnote wordlists](https://wordlists.assetnote.io/).

License: [MIT](LICENSE).
