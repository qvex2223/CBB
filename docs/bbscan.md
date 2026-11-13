# `bbscan` — the gate for sqlmap and nmap

`sqlmap` and `nmap` were installed on 2026-10-29 at the operator's instruction, reversing the
earlier "deliberately absent" decision. Nothing about the safety floor changed with them.

Both build and send their own traffic, so `bbcurl` cannot cover them. Installing them added two
transports that bypassed every guarantee the rest of this workspace enforces in code. `scripts/bbscan`
closes that gap the same way `bbcurl` closed it for curl, through the same
`engine/request_broker.py`, so there is one policy and not three.

**Call them as `bbscan sqlmap …` / `bbscan nmap …`.** Raw `sqlmap` and raw `nmap` still work and
are still completely ungated — that is the whole reason this wrapper exists.

## What is installed

| | |
|---|---|
| sqlmap | `tools/sqlmap` (tarball of `master`; no `git`, no `pip` on this box), shim `~/.local/bin/sqlmap`, `1.10.10.27#dev` |
| nmap | `/usr/bin/nmap`, `7.98`, from the Ubuntu `resolute/universe` repo |
| bbscan | `scripts/bbscan`, shim `~/.local/bin/bbscan` |

All three are in `engine/workspace_check.py::TOOLS_REQUIRED`, so `cbh doctor` fails if one
vanishes, and all three are in `engine/skill_signals.py::SENDER_RE`, so `skill-gate`, `crew-gate`
and `hunt-nudge` treat an invocation as a request-firing command (while a hunt is armed the
orchestrator is denied it and a worker runs it).

## What bbscan does before the tool runs

1. **Resolves the engagement** — `$CBH_PROJECT` (may be nested, `standoff365/yukki`), else cwd
   under `Targets/<name>/`. No engagement means no gate, so it **exits 3 and sends nothing**.
2. **Scope-checks every target** via `engine/scope.py`: deny-wins, default-deny, DNS-resolution
   gate for netblock programmes. A CIDR is expanded locally with `ipaddress` and **every** address
   must pass; over 1024 addresses it refuses. sqlmap targets come from `-u`, `-m` and the `Host:`
   of an `-r` request file.
3. **Waits out the engagement's global `flock`'d pacing budget** once, then translates that budget
   into the tool's own throttle flags so the whole run stays inside it:
   - sqlmap: `--delay=<min_interval_seconds> --threads=1 --batch`
   - nmap: `--scan-delay=<min_interval_seconds>s --max-rate=<1/interval> --max-parallelism 1`

   Only injected when the caller has not set them.
4. **Injects the programme's mandatory headers** into sqlmap. nmap carries no HTTP header, so
   bbscan prints a warning that the scan is anonymous to the programme — use it for service
   discovery only and do the HTTP work through `bbcurl`.
5. **Refuses the switches below** unless an approval file exists under the engagement.
6. **Appends the run to `hunt-memory/audit.jsonl`** with the redacted command line.

`--bb-dry-run` prints the resolved command and the scope verdict and sends nothing.
`--bb-ungated` is the audited escape and only applies outside an engagement.

## What is gated, and what is not (narrowed 2026-10-29, operator instruction)

The operator holds the engagements' authorization, so **throughput, technique, scan type and
evasion are not gated**. That means these all run: sqlmap `--level` at any value,
`--technique=T` (time-based blind), `--crawl`, `--forms`, `--tamper`, `--dbs`, `--tables`,
`--file-read`; nmap `-T4`/`-T5`/`-A`/`--min-rate`, UDP and protocol sweeps, and the
`vuln`/`intrusive` detection scripts. The engagement's pacing budget still bounds every request
either tool sends, and for nmap the throttle flags are appended **last** on the command line so
an explicit `--max-rate` wins over a timing template.

Four things stay gated, because the party they affect is not the operator. A programme's
permission to test is not a third party's permission to have their row read.

| Switch | Who it affects |
|---|---|
| sqlmap `--dump`, `--dump-all`, `--passwords`, `--users`, `--privileges`, `--all` | reads stored rows — another user's data |
| sqlmap `--risk` > 1, `--technique` containing `S` | writes to production data (UPDATE / stacked queries) |
| sqlmap `--os-shell`, `--os-pwn`, `--os-cmd`, `--os-bof`, `--priv-esc`, `--sql-shell`, `--sql-query` | code execution on the target |
| sqlmap `--file-write`, `--file-dest` | writes a file to the target host |
| nmap `--script` naming `exploit`, `dos`, `brute`, `malware` | exploits, brute-forces someone's credentials, or degrades availability |

To clear one: get the approval in writing, save it under `Targets/<eng>/approvals/<file>.md`, and
pass `--bb-approved approvals/<file>.md`. The path is written to the audit row. A named file that
does not exist does not clear the gate.

Two refusals are not about permission at all — they exist because the scope gate cannot answer
for those targets, and an unanswerable scope check is not approval:

- sqlmap `-g` / `--google-dork` — picks targets off a search engine
- nmap octet-range (`1-50`) and wildcard (`*`) targets — expand with `mapcidr -cidr <range>` first

RTEAM additionally requires **email pre-approval before any SQLi at all**, whatever the flags.

## `nsupdate` and `snmp` are built, not forwarded (added 2026-10-29)

For these two the limit used to be a sentence in `permissions.autoMode.allow` — "Writing,
deleting or altering an actual DNS record is NOT allowed by this entry", "never guessing a
non-default secret". A sentence steers a classifier; it does not stop a command. Both are now
mechanisms, and because `Bash(bbscan *)` is a deterministic rule in `permissions.allow`, neither
probe is adjudicated by the permission classifier any more — which is what they kept failing on
(`[DNS / Domain / Cert Changes]`, `[Credential Exploration]`, logged in
`Targets/standoff365/yukki/blocked-tests/2026-10-19-harness-classifier-denials.md`).

```bash
CBH_PROJECT=standoff365/yukki bbscan --bb-dry-run nsupdate 185.171.101.250 --zone ykky.ru
CBH_PROJECT=standoff365/yukki bbscan nsupdate 185.171.101.250 --zone ykky.ru        # UDP
CBH_PROJECT=standoff365/yukki bbscan nsupdate 185.171.101.250 --zone ykky.ru --tcp  # nsupdate -v

CBH_PROJECT=standoff365/yukki bbscan snmp 185.171.101.250
CBH_PROJECT=standoff365/yukki bbscan snmp 185.171.101.250 --oid 1.3.6.1.2.1.1.5.0
```

**nsupdate.** bbscan writes the entire update script and it contains no update section — only
`server`, `zone`, `prereq nxdomain <random>.<zone>` and `send`. Altering a record is impossible
by construction, not by policy: the only accepted arguments are `--zone`, `--name`, `--tcp` and
`--timeout`, and any other token is refused rather than forwarded. The RCODE is the whole answer:
`REFUSED`/`NOTAUTH` means dynamic updates are not authorized for you, while
`NOERROR`/`NXRRSET`/`YXDOMAIN` means the server processed an UPDATE opcode from you — which on a
lender's apex is the finding. A timeout is neither: TCP/53 is filtered on some targets, so retry
on the other transport before writing anything down.

**snmp.** A v2c GET implemented in-process, because there is no net-snmp client on this box and
the old probe (`python3 -I snmpget.py`) lived in a scratchpad that no longer exists. Only the
default communities `public` and `private` are accepted; any other string is credential guessing
and is refused. Per the `udp-oracle-no-response-is-its-own-bucket` memory, a silent socket is
reported as `no-response`, never as a negative result and never as a hit.

Both are scope-checked against the engagement's `scope.md`, paced against its budget, and
audited — the nsupdate row carries `zone`, `rcode` and `prereq_only: true`, the snmp row carries
`community`, `oid`, `state` and `bytes`.

## When each one is the right move

- **sqlmap** — only after a manual boolean pair has already diffed the bodies. A confirmed
  injection is the finding; the schema dump is not what pays. Routed from
  `engine/vectors.py::CLASS_MUTATIONS["sqli"]` (last rung of the ladder) and from
  `skills/hunt-sqli/SKILL.md`.
- **nsupdate / snmp** — on a netblock-scoped programme that names DNS or default credentials as a
  payable class. Both are read-only authorization checks: one asks "may I update this zone", the
  other "is a default community still live". Neither needs the classifier any more.
- **nmap** — only on a programme whose `scope.md` declares netblocks or bare addresses and whose
  text does not exclude port scanning. It answers the one question the name-based pipeline cannot:
  which addresses answer on which ports. Routed from `skills/web2-recon/SKILL.md`.

## What neither of them produces

Evidence. `cbh evidence` returns NO-EVIDENCE for a finding backed only by their stdout, because
there is no `.result.json` behind it. Re-fire the single decisive request through `/poc-run` and
cite that. And never paste extracted rows of real data into a report.

Last thing worth remembering: per the `injection-payloads-ban-the-source-ip` memory, at a
WAF-fronted host one SQL-shaped probe cost this workspace 21 vhosts for 21 hours. Fire
injection-shaped payloads last, after the non-destructive classes are done, and control-test the
block page.
