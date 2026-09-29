# CBB — web bug-bounty operator workspace

The tooling half of a web-application bug-bounty workspace: the `Claude-BugHunter`
skill bundle plus the workspace glue that makes it run (agent rules, MCP servers,
engagement template, memory layout).

**No client data is in this repository.** Engagement folders, hunt memory, evidence,
response corpora and request logs stay on the operator's machine.

## Layout

```
CLAUDE.md                  operating manual the agent reads every session
.mcp.json                  Burp MCP + isolated headless Playwright servers
.claude/settings.local.json  permissions + enabled MCP servers
Targets/_TEMPLATE/         blank engagement folder — copy per program
hunt-memory/               cross-session corpus (structure only, see its README)
Claude-BugHunter/          the bundle
├── engine/                enforcement layer: scope, pacing, poc_runtime, vectors,
│                          stop_gate, hunt_mode, evidence, responses, memory
├── scripts/               bbcurl, cbh, hooks (skill-gate, hunt-nudge, hunt-stop-gate),
│                          session-brief, cve_watch, cve-digest, pattern-analytics
├── skills/                62 skills — hunt-* vuln classes, framework, recon, reporting
├── commands/              16 slash commands (/hunt /recon /cve /validate /poc-run …)
├── cbh/                   CLI package behind `cbh`
├── docs/                  architecture, CLI reference, CVE coverage, recon manifest
├── eval/                  tier-2/tier-3 harness + recorded runs
├── tests/                 regression suite for the enforcement layer
└── runtime/               MCP wrappers (burp-bridge, playwright-mcp, health)
```

## Why the engine matters

The bundle is not just prompts. Brakes *and* pushes are enforced in code:

- `engine/scope.py` — deny-wins, default-deny, DNS-resolution gate for netblock-scoped
  programs. `UNVERIFIED` is not approval to test.
- `engine/pacing.py` — per-engagement request budget from `profile.json`, `flock`'d
  across processes, injects each program's mandatory headers.
- `scripts/bbcurl` — curl-first transport: scope check, pacing, headers, audit log,
  response corpus. Bare `curl` bypasses all of it.
- `engine/poc_runtime.py` — fires a JSON PoC spec, follows the full redirect chain,
  captures every `Set-Cookie`, supports multi-step login→exploit→verify chains, and
  writes a `.result.json`. A remembered curl output is not evidence.
- `engine/vectors.py` — impact-ranked untried vectors, mutation matrix, revisit list.
  A vector cannot be marked dead with zero requests fired.
- `engine/stop_gate.py` + `scripts/hunt-stop-gate.py` — refuses the agent's own decision
  to stop while untried vectors remain. Never met by inflating severity.
- `engine/responses.py` — `scrub_text()` masks subscriber identity (iin, msisdn, phone,
  passport, email …) on every write path; the body hash is still taken over the
  original bytes, so dedup and `cbh diff` keep working.

## Setup on a new machine

1. Clone somewhere stable, e.g. `/opt/Claude`. Paths in `.mcp.json`, `scripts/cve-boot-catchup.sh`
   and the cron entries are absolute — fix them to the clone path.
2. Register the bundle as a Claude Code plugin:
   ```
   claude plugin marketplace add <clone>/Claude-BugHunter
   claude plugin install claude-bughunter@elementalsouls
   ```
3. Put `cbh` and `bbcurl` on PATH:
   ```
   ln -s <clone>/Claude-BugHunter/scripts/cbh.py  ~/.local/bin/cbh
   ln -s <clone>/Claude-BugHunter/scripts/bbcurl  ~/.local/bin/bbcurl
   ```
4. MCP deps: `cd Claude-BugHunter/runtime && npm install` (node_modules is not versioned).
5. Recon tool stand (not versioned, install separately): `subfinder dnsx httpx katana
   amass ffuf gau waybackurls anew qsreplace gowitness jq`.
6. Verify: `cbh tools doctor`, `python3 Claude-BugHunter/engine/scope.py --selftest`,
   `python3 Claude-BugHunter/engine/pacing.py --selftest`,
   `python3 -m unittest discover -s Claude-BugHunter/tests`.
7. New engagement: `cp -r Targets/_TEMPLATE Targets/<name>`, then fill `scope.md`,
   `profile.json` (pacing + mandatory headers) and `CLAUDE.md` from the program's own rules.

`RESTORE.md` has the longer Windows-laptop rebuild. `FROZEN.md` records the state of the
original workspace this was taken from.

## Deliberately not here

`Targets/<client>/` (scope, notes, hosts, findings, evidence, submissions), the project
index, hunt-memory contents, `hunt-memory/audit.jsonl`, response corpora,
`runtime/*.cjs` (one-off engagement browser scripts), `runtime/node_modules`, logs.
