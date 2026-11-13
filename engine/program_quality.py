#!/usr/bin/env python3
"""
program_quality.py — is this program worth your next hunt?

Technique analytics answer "what works". They cannot answer the question that decides
where a researcher spends a week, because the answer lives on the program's side of the
submission: how long it sits before anyone looks at it, how much of your work comes back
duplicate, how often a High is accepted as a Low, and whether anything actually pays.

That data is already in hunt memory — `journal.jsonl` carries a `platform_outcome` per
row since the schema split local confirmation from the program's verdict — and nothing
read it. This does.

Everything here is derived from rows the operator logged with `/remember`. It invents
nothing, and a metric with no rows behind it prints as unknown rather than as zero: a
program you have never submitted to is not a program with a 0% acceptance rate.

    python3 engine/program_quality.py                 # all programs
    python3 engine/program_quality.py --target kcell  # one
    python3 engine/program_quality.py --format json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from memory import Memory, PLATFORM_RESULTS  # noqa: E402

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
TERMINAL = {"accepted", "paid", "na", "downgraded", "duplicate"}


def _parse_ts(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _finding_key(row: dict) -> tuple:
    """Rows about the same finding, so a submission can be paired with its verdict."""
    endpoint = row.get("endpoint")
    if isinstance(endpoint, list):
        endpoint = ",".join(endpoint)
    return (row.get("target", ""), row.get("vuln_class", ""), endpoint or "")


def _pct(part: int, whole: int) -> Optional[float]:
    return round(part / whole * 100, 1) if whole else None


def analyze(rows: List[dict]) -> Dict[str, dict]:
    by_target: Dict[str, List[dict]] = defaultdict(list)
    for row in rows:
        if row.get("target"):
            by_target[row["target"]].append(row)

    out: Dict[str, dict] = {}
    for target, target_rows in by_target.items():
        judged = [r for r in target_rows
                  if (r.get("platform_outcome") or r.get("result")) in TERMINAL]
        submitted = [r for r in target_rows
                     if (r.get("platform_outcome") or r.get("result")) in PLATFORM_RESULTS]
        counts = defaultdict(int)
        payout = 0
        severities = defaultdict(int)
        for row in judged:
            outcome = row.get("platform_outcome") or row.get("result")
            counts[outcome] += 1
            payout += row.get("payout") or 0
            sev = str(row.get("severity") or "").lower()
            if sev in SEVERITY_ORDER:
                severities[sev] += 1

        # Response time: pair each `submitted` row with the first terminal row that
        # follows it for the same finding. Unpaired submissions are still open, and an
        # open submission is itself the signal — it is counted, not dropped.
        waits, still_open = [], 0
        events: Dict[tuple, List[dict]] = defaultdict(list)
        for row in target_rows:
            events[_finding_key(row)].append(row)
        for series in events.values():
            series.sort(key=lambda r: str(r.get("timestamp") or ""))
            pending = None
            for row in series:
                outcome = row.get("platform_outcome") or row.get("result")
                ts = _parse_ts(row.get("timestamp"))
                if outcome == "submitted" and ts:
                    pending = ts
                elif outcome in TERMINAL and pending and ts:
                    waits.append((ts - pending).total_seconds() / 86400.0)
                    pending = None
            if pending:
                still_open += 1

        total_judged = len(judged)
        accepted = counts["accepted"] + counts["paid"]
        out[target] = {
            "target": target,
            "logged_rows": len(target_rows),
            "submitted": len(submitted),
            "judged": total_judged,
            "open_submissions": still_open,
            "accepted": accepted,
            "paid": counts["paid"],
            "duplicate": counts["duplicate"],
            "na": counts["na"],
            "downgraded": counts["downgraded"],
            "accepted_rate": _pct(accepted, total_judged),
            "duplicate_rate": _pct(counts["duplicate"], total_judged),
            "na_rate": _pct(counts["na"], total_judged),
            "downgrade_rate": _pct(counts["downgraded"], total_judged),
            "total_payout": payout,
            "payout_per_accepted": round(payout / accepted, 2) if accepted else None,
            "median_days_to_verdict": (round(sorted(waits)[len(waits) // 2], 1)
                                       if waits else None),
            "accepted_severities": dict(severities),
        }
    return out


def rank(stats: Dict[str, dict]) -> List[dict]:
    """Programs worth more of your time first.

    Realized value leads, because it is the only number that cannot be argued with. A
    program with no judged submissions ranks last rather than first — an empty record is
    not a perfect one.
    """
    def key(row: dict):
        if not row["judged"]:
            return (1, 0.0)
        quality = (row["accepted_rate"] or 0) - (row["duplicate_rate"] or 0) \
            - (row["na_rate"] or 0)
        return (0, -(row["total_payout"] / 100.0 + quality))
    return sorted(stats.values(), key=key)


def render(stats: Dict[str, dict]) -> str:
    if not stats:
        return ("No submission outcomes in hunt memory yet.\n"
                "These numbers come from /remember rows whose result is submitted / "
                "accepted / paid / na / downgraded / duplicate — log the verdict when a "
                "program answers, and this becomes answerable.")
    lines = [f"{'program':<22}{'judged':>7}{'acc%':>7}{'dup%':>7}{'n/a%':>7}"
             f"{'down%':>7}{'days':>7}{'payout':>10}  open"]
    lines.append("-" * 82)
    for row in rank(stats):
        def fmt(value, suffix=""):
            return f"{value}{suffix}" if value is not None else "—"
        lines.append(
            f"{row['target'][:21]:<22}{row['judged']:>7}"
            f"{fmt(row['accepted_rate']):>7}{fmt(row['duplicate_rate']):>7}"
            f"{fmt(row['na_rate']):>7}{fmt(row['downgrade_rate']):>7}"
            f"{fmt(row['median_days_to_verdict']):>7}"
            f"{row['total_payout']:>10}  {row['open_submissions']}")
    lines += ["", "Rows are keyed by whatever /remember recorded as `target`. This workspace",
              "logs per HOST, so one program can appear as several rows — read them together",
              "when judging a program rather than a single host.",
              "", "acc% / dup% / n/a% / down% are shares of JUDGED submissions.",
              "days = median calendar days from submitted to verdict.",
              "open = submissions with no verdict logged yet — a long tail here is a",
              "       program-quality signal in its own right."]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--memdir", default=None)
    ap.add_argument("--target", default=None, help="one program")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    args = ap.parse_args(argv)

    mem = Memory(args.memdir)
    stats = analyze(mem.read("journal.jsonl"))
    if args.target:
        stats = {k: v for k, v in stats.items() if k == args.target}
    if args.format == "json":
        print(json.dumps({"programs": rank(stats)}, indent=2, ensure_ascii=False))
    else:
        print(render(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
