---
name: bb-local-toolkit
description: "TRIGGER — need the exact local binary path, install command, venv activate line, or wordlist location for a tool already decided on (ffuf, httpx, subfinder, katana, gau, bbcurl, cbh, Burp MCP, SecLists, …), or need to know whether a tool is installed here at all before writing a command around it. SKIP — bug-bounty when the question is 'what should I test' (bug-class routing), not 'where is the tool on disk'; web2-recon when the ask is the recon pipeline sequence itself rather than one tool's path."
---

# Local toolkit — what is on this machine, and what policy still forbids

Answers one question: **can I run this command here, and where does it live?**

A skill that names a tool the box does not have is worse than a skill that names none —
`command not found` goes to stderr, the step is silently skipped, and the hunt continues
as if the check had been run. That failure is documented in this workspace's own history,
and it is the reason this file lists absence as loudly as presence.

> Audited on this machine 2026-09-15 with `command -v`. Re-run the audit block at the
> bottom after any workspace move or rebuild rather than trusting this table.

## Installed — free to use

| Tool | Path | Use |
|---|---|---|
| `bbcurl` | `~/.local/bin/bbcurl` | **the request path** — scope-gated, paced, audited curl |
| `cbh` | `~/.local/bin/cbh` | the CLI: recon, surface, vectors, triage, report, memory |
| `subfinder` | `/usr/bin/subfinder` | passive subdomain enum |
| `dnsx` | `/usr/bin/dnsx` | DNS resolution |
| `httpx` | `/usr/local/bin/httpx` | live-host probe, status/title/tech |
| `katana` | `/usr/local/bin/katana` | crawler — **see the bulk-tool gate below** |
| `amass` | `/usr/bin/amass` | subdomain enum (heavier than subfinder) |
| `ffuf` | `/usr/bin/ffuf` | fuzzer — also the stand-in for `arjun`/`paramspider` |
| `gau` | `~/.local/bin/gau` | known URLs |
| `waybackurls` | `~/.local/bin/waybackurls` | archive URLs |
| `anew` | `~/.local/bin/anew` | dedup append |
| `qsreplace` | `~/.local/bin/qsreplace` | replace param values |
| `gowitness` | `~/.local/bin/gowitness` | screenshots |
| `jq` | `/usr/bin/jq` | JSON |
| `whois` | `/usr/bin/whois` | netblock ownership (`cbh scope --whois`) |

## Installed, but availability is not permission

| Tool | Path | The rule |
|---|---|---|
| `nuclei` | `/usr/bin/nuclei` | **No sweeps.** Every engagement here forbids broad automated scanning. One targeted template against one already-fingerprinted host, or not at all. |
| `dalfox` | `~/.local/bin/dalfox` | Same rule. A single confirmed injection point, never a crawl. |
| `interactsh-client` | `~/.local/bin/interactsh-client` | The OOB channel resolves through a **public third-party server**, so callback data leaves this machine. **Forbidden outright on `*.rteam.kz`.** Elsewhere it needs `"allow_oob": true` in the engagement's `profile.json` — `scripts/mcp-gate.py` enforces the same rule for Burp Collaborator. |
| `katana` | `/usr/local/bin/katana` | Disabled inside an engagement unless `profile.json` sets `allow_bulk_tools: true`; when enabled it takes concurrency and rate from that profile, not from its own defaults. |

## Not installed — use the substitute, do not write the command

| Missing | Why | Instead |
|---|---|---|
| `sqlmap` | automated SQLi scanner; RTEAM additionally requires email pre-approval before any SQLi | `hunt-sqli` by hand — boolean pair first, then timing |
| `nmap` | port scanning is outside web-app scope on these programs | — |
| `arjun`, `paramspider` | no `pip` on this box | `ffuf` against a param wordlist, or `katana` + `qsreplace` |
| `gf` | — | `grep -E` with the pattern you want; the `gf` pattern set is just regexes |
| `assetfinder` | — | `subfinder` + `amass` |
| `trufflehog`, `gitleaks` | — | `hunt-source-leak` — grep the bundles and `.map` files directly |
| `subzy` | — | `hunt-subdomain` — resolve the CNAME and check the fingerprint by hand |
| `semgrep`, `kiterunner` | — | `hunt-source-aware-sast` / `ffuf` with an API wordlist |

## Burp + MCP

```bash
Claude-BugHunter/scripts/burp-mcp.sh start     # Xvfb + Burp + BurpMCP, then switch on
Claude-BugHunter/scripts/burp-mcp.sh status|stop|logs|screenshot
cbh tools doctor --start                       # verifies the real tools/list handshake
```

Stack lives in `/opt/Claude/tools/burp`. MCP endpoint `http://localhost:8181/mcp/sse`
(declared in `/opt/Claude/.mcp.json`), proxy on `8080`. Community Edition has **no
Collaborator**.

Burp is for the **last mile** — redirect chains, cookie/session state across a flow,
replaying and mutating a captured request. Not for recon, where `bbcurl` is strictly
better because it carries scope, pacing and audit. Burp and Playwright reach the network
themselves, so `scripts/mcp-gate.py` applies the same scope/pacing/audit contract to their
send and navigate calls.

## Wordlists and payload sources

- [SecLists](https://github.com/danielmiessler/SecLists) — general wordlists
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — per-class payloads
- [DefaultCreds](https://github.com/ihebski/DefaultCreds-cheat-sheet) — default credentials

## Re-audit after any workspace move or rebuild

```bash
for t in bbcurl cbh subfinder dnsx httpx katana amass ffuf gau waybackurls anew \
         qsreplace gowitness jq whois nuclei dalfox interactsh-client; do
  printf '%-20s %s\n' "$t" "$(command -v $t || echo '— NOT INSTALLED')"
done
python3 -m unittest discover -s Claude-BugHunter/tests   # the enforcement layer
python3 Claude-BugHunter/engine/pacing.py --selftest
python3 Claude-BugHunter/engine/scope.py --selftest
```

## Related

- **`bug-bounty`** — what to test (bug-class routing). This skill only answers where the tool is.
- **`web2-recon`** — the recon pipeline sequence; this skill is the parts list, not the order.
- **`security-arsenal`** — payload content for a class already chosen.
- `references/inherited-methodology.md` — archive only. Until 2026-09-15 this skill's body
  was a verbatim copy of the `bug-bounty` orchestrator (1548 identical lines), so it never
  answered its own description's question. Kept in case a section exists only there; the
  canonical copy is `bug-bounty/SKILL.md` + its `references/`.
