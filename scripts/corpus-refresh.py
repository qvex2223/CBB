#!/usr/bin/env python3
"""corpus-refresh.py — weekly: learn from NEW disclosed crit/high reports, unattended.

The 2026-11-02 learning pass (docs/disclosed-reports/HIGH-CRIT-LESSONS-2026-11.md)
was a one-off. This keeps it going without the operator:

  1. Skips unless the last successful refresh is older than 7 days (stamp
     logs/stamps/corpus-refresh). `--force` ignores the stamp.
  2. Runs ONE headless research worker (engine/agent.py::run_agent, tools limited
     to WebSearch/WebFetch/Read/Write/Glob/Grep, so no request tool exists) that
     reads public disclosed reports and write-ups published since the newest
     corpus, skips every source_url already in an older corpus.json, and writes
     docs/disclosed-reports/corpus-<date>/corpus.json in the same schema.
  3. Runs corpus_gap on it and writes GAP.md: the reports the toolkit would NOT
     have found. Those are the backlog the next session closes (a mutation, a
     signal row, a consumer entry).

Never touches a programme's assets: the brief forbids it, and the worker has no
bbcurl, curl or MCP tool. Called from scripts/cve-boot-catchup.sh; safe to run by hand.

    python3 scripts/corpus-refresh.py            # no-op if fresh
    python3 scripts/corpus-refresh.py --force --dry-run   # print the brief only
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))
STAMP = REPO / "logs" / "stamps" / "corpus-refresh"
DOCS = REPO / "docs" / "disclosed-reports"
MAX_AGE = 7 * 86400
TOOLS = "WebSearch WebFetch Read Write Glob Grep"

BRIEF = """\
Research task, read-only public web. You may ONLY read publishing pages (hackerone.com/reports/<id>
and its .json, github.com, portswigger.net, write-up blogs, platform blogs). NEVER send any request to
a bug bounty programme's own assets. You have no HTTP tool other than WebFetch/WebSearch — keep it that way.

Goal: find Critical/High WEB-application vulnerability reports and write-ups PUBLISHED AFTER {since}
(disclosed HackerOne reports, Bugcrowd/Intigriti/YesWeHack disclosures, hunter write-ups, research
posts). Skip mobile binaries, smart contracts, social engineering. Skip every URL listed in {known}.
Read each one in FULL before recording it; aim for 30-60 new records. Do not invent: null when a field
is not stated.

Write {out} as JSON with exactly this shape:
{{"meta": {{"source": "public disclosures and write-ups (URL per record)", "licence": "public disclosure; facts summarised, no text copied", "retrieved": "{today}", "notes": "corpus-refresh.py weekly run"}},
 "reports": [{{"id": "r-001", "source_url": "...", "set": "hackerone|writeup|research", "severity": "critical|high|medium|unknown", "bounty": "... or null", "classes": ["..."], "first_signal": "...or null", "mechanic": "one sentence", "chain": ["..."], "impact_proof": "...", "keywords": ["3-8 concrete lowercase technique terms"], "lesson": "composition|body-not-status|sibling-interface|server-side-fetcher|parser-differential|oracle|patch-bypass|secret-validation|client-supplied-field|filter-operator|multi-identity|framework-internals|other"}}]}}

classes use: rce, missing_authorization, idor, business-logic, ssrf, sqli, auth-bypass, race-condition,
graphql, file-upload, deserialization, ssti, xxe, api-misconfig, xss, cors, host-header, cache-poison,
csrf, open-redirect, info-leak, sibling-interface, secret-exposure, filter-injection, parser-differential,
oauth, saml, lfi, request-smuggling, cspt, other.
Validate the file parses as JSON before you finish. Reply with the record count.
"""


def stale() -> bool:
    return not STAMP.exists() or time.time() - STAMP.stat().st_mtime > MAX_AGE


def known_urls() -> list:
    urls = []
    for c in sorted(DOCS.glob("corpus-*/corpus.json")):
        try:
            urls += [r.get("source_url") for r in json.loads(c.read_text())["reports"] if r.get("source_url")]
        except (OSError, ValueError, KeyError):
            continue
    return sorted(set(urls))


def newest_date() -> str:
    """Search window start: the newest corpus date, but never narrower than 14 days.

    The first refresh ran one day after the seed corpus and its 1-day window was empty
    (the worker said so and fell back to recent material); a minimum window keeps the
    brief satisfiable while the known-URL list still prevents re-adding old records.
    """
    floor = time.strftime("%Y-%m-%d", time.localtime(time.time() - 14 * 86400))
    dirs = sorted(d.name for d in DOCS.glob("corpus-*") if d.is_dir())
    if not dirs:
        return floor
    tail = dirs[-1].replace("corpus-", "")
    newest = tail if len(tail) == 10 else tail + "-01"
    return min(newest, floor)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="print the brief and exit")
    ap.add_argument("--timeout", type=int, default=3000)
    ap.add_argument("--max-turns", type=int, default=120)
    a = ap.parse_args(argv)
    if not a.force and not stale():
        print("corpus-refresh: fresh (stamp < 7 days), nothing to do")
        return 0
    today = time.strftime("%Y-%m-%d")
    out_dir = DOCS / f"corpus-{today}"
    known = out_dir / "known-urls.txt"
    task = BRIEF.format(since=newest_date(), known=known, out=out_dir / "corpus.json", today=today)
    if a.dry_run:
        print(task)
        return 0
    out_dir.mkdir(parents=True, exist_ok=True)
    known.write_text("\n".join(known_urls()) + "\n", encoding="utf-8")
    import agent as A  # type: ignore
    r = A.run_agent(task, skills_on=False, max_turns=a.max_turns, timeout=a.timeout,
                    tools=TOOLS, cwd=str(REPO))
    (out_dir / "worker-result.txt").write_text(str(r.get("result") or r.get("error") or "")[:20000],
                                              encoding="utf-8")
    corpus = out_dir / "corpus.json"
    try:
        n = len(json.loads(corpus.read_text())["reports"])
    except (OSError, ValueError, KeyError) as e:
        print(f"corpus-refresh: worker produced no valid corpus.json ({e}); stamp NOT updated", file=sys.stderr)
        return 1
    import corpus_gap as G  # type: ignore
    rep = G.run(corpus)
    (out_dir / "GAP.md").write_text(G.render_md(rep), encoding="utf-8")
    STAMP.parent.mkdir(parents=True, exist_ok=True)
    STAMP.touch()
    print(f"corpus-refresh: {n} new reports -> {corpus}; technique coverage {rep['technique_coverage_pct']}%, "
          f"{len(rep['gaps'])} gap(s) in GAP.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
