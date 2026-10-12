# claude-bughunter

Working copy of the web application bug-hunting skill bundle that drives this
workspace. **The tool lives in this repository; engagement data never does.**
Targets, findings, evidence and captured responses stay outside it — see
[Layout](#layout).

66 skills · 55 per-class `hunt-*` skills · 21 slash commands · 24 per-class
disclosed-report digests · a deterministic engagement engine under `engine/`.

---

## Layout

| Path | What it is | In git? |
|---|---|---|
| `/opt/Claude-BugHunter` | this repository — the bundle itself | yes |
| `/opt/Claude/Targets/<project>/` | one folder per engagement: `scope.md`, `profile.json`, `findings/`, `hosts/`, `recon/`, `notes.md`, `submissions.txt` | **no** |
| `Targets/_TEMPLATE/` | the skeleton every new engagement is copied from | yes |
| `/opt/Claude/Targets/_INTIGRITI-CANDIDATES/` | program briefs + normalized `programs/<key>/` | **no** |
| `/opt/Claude/Targets/_STANDOFF-CANDIDATES/` | same, for Standoff 365 | **no** |
| `~/.claude/{skills,commands}/` | the installed copy Claude Code actually loads | n/a |
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

**`scripts/cbh.py` — secondary.** The same engine without a model in the loop,
for CI, scripted runs and deterministic verification:

```bash
python3 scripts/cbh.py recon <target>
python3 scripts/cbh.py oracle recon/<target>/manifest.json --axes auth-strip,principal-swap
python3 scripts/cbh.py sweep  recon/<target>/manifest.json --dry-run
python3 scripts/cbh.py coverage --engagement <project>
python3 scripts/cbh.py program-quality --target <project>
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

Branches: `main` (this layout — the bundle at the repository root) ·
`main-backup` (the earlier workspace-shaped snapshot, tool nested under
`Claude-BugHunter/`) · `tooling-root`.

`runtime/` and `.claude/` are ignored, with the bridge sources and
`settings.local.json.example` force-added as the only exceptions.

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
| [`docs/skills.md`](docs/skills.md) | searchable catalog of all 66 skills |
| [`docs/cbh-cli.md`](docs/cbh-cli.md) | every `cbh` subcommand |
| [`docs/cve-coverage.md`](docs/cve-coverage.md) | CISA KEV coverage snapshot |
| [`CLAUDE.md`](CLAUDE.md) | the workspace's own operating rules |
| [`FROZEN.md`](FROZEN.md) · [`RESTORE.md`](RESTORE.md) | what must not drift · how to rebuild |
| [`SECURITY.md`](SECURITY.md) | authorized-use posture · what is excluded |

---

## Credits

MIT fork of [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
(web surface only — the AD, cloud/infra, red-team, Web3, mobile and OSINT
skills are removed by design), which vendors
[shuvonsec/claude-bug-bounty](https://github.com/shuvonsec/claude-bug-bounty)
for methodology, validation and reporting. Per-skill attribution in
[`docs/credits.md`](docs/credits.md).

Tooling leaned on: [Burp Suite + MCP server](https://portswigger.net/burp) ·
[ProjectDiscovery](https://github.com/projectdiscovery) (subfinder · dnsx ·
httpx · katana · nuclei) · [SecLists](https://github.com/danielmiessler/SecLists) ·
[Assetnote wordlists](https://wordlists.assetnote.io/).

License: [MIT](LICENSE).
