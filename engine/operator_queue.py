#!/usr/bin/env python3
"""operator_queue — everything that is waiting on the operator, in one ranked file.

Written 2026-10-20. Two konsol reports passed the 7-Question Gate with fired PoCs
and sat unsubmitted for two days, and the same operator-only blockers (a second
account, an egress, a programme approval) were scattered across ~70 blocked-tests
files in six engagements. The agent cannot clear any of these; the operator can,
but only if they are visible.

Rewritten 2026-11-11 after measuring what this file actually surfaced. A six-day
wildberries hunt (session a0053cc0: 138 subagents, 8400 requests) produced three files
that are the most valuable thing it made —
`blocked-tests/OPERATOR-DECISION-digital-next-image-sharp-rce-all-preconditions-measured.md`
("unauthenticated Critical RCE on a trusted origin, ALL THREE preconditions measured,
nothing has been sent"), `OPERATOR-DECISION-order-flags-tier-bit-is-the-1m-scenario-request.md`
(the 1 000 000 RUB scenario, one decisive request) and `OPERATOR-DECISION-one-post-to-mint-an-esia-state.md`
— and none of them was visible. Three reasons, all fixed here:
  * section 2 ranked by the ENGAGEMENT's maximum payout, so 195 rows tied at 1 000 000 and
    sorted alphabetically by filename. A measured Critical ranked below "needs a buyer account";
  * a decision carried no weight at all: `OPERATOR-DECISION-*` was just another blocked test;
  * closures were read from the first 6 lines only and case-sensitively, so a file whose
    header says "Unblocked 2026-11-11 — drove as leads/... (closed-exhausted)" stayed in the
    queue, and a worker's closure appended at the END of the file was never seen. Closure
    detection now goes through lead_queue, which learned the five house banner forms.

Four sections, all read from files (no network):
  0. DECISIONS       — blocked-tests/OPERATOR-DECISION-*.md, or any whose status banner says
     it waits on the operator: one request away from an answer, ranked by their OWN severity.
  1. READY TO SUBMIT — findings/*.md that are not in submissions.txt, ranked by
     evidence verdict (DEMONSTRATED first) then severity.
  2. NEEDS YOU       — open blocked-tests/*.md whose text names an operator-only action,
     ranked by the item's OWN claimed severity, then the engagement's maximum payout.
  3. CHAIN UNLOCKS   — operator-only capabilities the chain graph says unblock most primitives.

Writes Targets/OPERATOR-QUEUE.md. `brief_line()` is what session-brief prints.

usage: operator_queue.py [--print] [--no-write]
       operator_queue.py resolve <blocked-test.md> --as approved|refused|asked-programme [--note "..."]
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

DOC_PREFIXES = ("SUBMIT-", "REPORT-", "ANNEX-")
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
# CLASS-UNPROVEN ranks with WIRE-UNPROVEN: the request is proven, the effect is not,
# so it is one artifact away from reportable and outranks a MISMATCH.
EV_RANK = {"DEMONSTRATED": 3, "WIRE-UNPROVEN": 2, "CLASS-UNPROVEN": 2, "MISMATCH": 1}
OPERATOR = re.compile(
    r"(operator|оператор|programme approval|program approval|approval|разрешени|egress|"
    r"\bsms\b|phone|телефон|relogin|re-login|needs a session|needs an? (account|identity|employee)|"
    r"credential|legal entity|юрлиц|ИНН|login wall|@intigriti\.me|second principal|второй)",
    re.I)
# re.I matters: the row that sat at the top of this queue said "Unblocked 2026-11-11 — drove
# as `leads/cloud-own-file-idor.md` (closed-exhausted)", and a case-sensitive pattern read it
# as open. The words are checked against the file's own header lines, not the whole body,
# because "if unblocked we could ..." in prose must not close anything.
CLOSED = re.compile(r"\b(CLOSED|RESOLVED|SUPERSEDED|UNBLOCK(?:ED)?|DONE|ANSWERED|"
                    r"NO LONGER BLOCKED|VERIFIED NEGATIVE)\b", re.I)
POLICY = re.compile(r"prohibits? (any )?AI agents", re.I)
# A decision is a file that says, in its own words, that nothing will move until the operator
# (or the programme) answers. Both spellings exist in the corpus: the filename prefix the
# hunters adopted, and a status banner.
DECISION_NAME = re.compile(r"^OPERATOR[-_ ]?DECISION", re.I)
DECISION_TEXT = re.compile(r"(?:^|\n)[ \t>#*]*(?:\*{0,2}status\*{0,2}[ \t]*[:\u2014\u2013-][ \t]*)?"
                           r"(?:waiting on the operator|operator decision|awaiting the operator|"
                           r"ждет оператора|ждёт оператора)", re.I)
HEADER_LINES = 8


def _targets():
    from paths import targets_root
    return targets_root()


def _engagements(root):
    for scope in sorted(root.glob("**/scope.md")):
        d = scope.parent
        if "_TEMPLATE" not in d.parts:
            yield d


def _max_payout(d: Path) -> int:
    """Largest RUB/$ figure in the engagement's reward block — a ranking key, not a promise."""
    t = (d / "scope.md").read_text(encoding="utf-8", errors="replace")
    m = re.search(r"## Reward (model|bands).*?(?=\n## (?!#)|\Z)", t, re.S)
    block = "\n".join(l for l in (m.group(0) if m else "").splitlines()
                      if not l.startswith("Platform stats"))
    nums = [int(re.sub(r"[^0-9]", "", n)) for n in re.findall(r"\d[\d ,\u00a0]{2,}\d", block)]
    return max([n for n in nums if n < 100_000_000] or [0])


def _submitted(d: Path):
    p = d / "submissions.txt"
    if not p.is_file():
        return []
    rows = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            rows.append([c.strip().lower() for c in line.split("|")])
    return rows


def _is_submitted(stem: str, rows) -> bool:
    s = stem.lower()
    for cols in rows:
        if s in " ".join(cols):
            return True
        host = cols[1] if len(cols) > 1 else ""
        if host and host in s:
            return True
    return False


def _title(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("#"):
            return line.lstrip("# ").strip()[:140]
    return ""


def ready_reports(root=None):
    import evidence
    from stop_gate import severity_of
    root = root or _targets()
    out = []
    for d in _engagements(root):
        fdir = d / "findings"
        if not fdir.is_dir():
            continue
        rows = _submitted(d)
        # flat (legacy) + one folder per finding: findings/<slug>/<slug>.md
        cands = sorted(list(fdir.glob("*.md")) + list(fdir.glob("*/*.md")))
        drafts = [p.name for p in cands if p.name.startswith(("SUBMIT-", "REPORT-"))]
        for f in cands:
            if f.name.startswith(DOC_PREFIXES) or _is_submitted(f.stem, rows):
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            try:
                ev = evidence.check(f)["status"]
            except Exception:  # noqa: BLE001
                ev = "UNCHECKED"
            sev = severity_of(text) or "unrated"
            out.append({"engagement": str(d.relative_to(root)), "file": str(f.relative_to(root)),
                        "title": _title(text), "severity": sev, "evidence": ev,
                        "drafts": drafts})
    out.sort(key=lambda r: (-EV_RANK.get(r["evidence"], 0), -SEV_RANK.get(r["severity"], 0)))
    return out


def _is_resolved(path: Path, text: str) -> bool:
    """Has this blocked test already been answered?

    Two readings, because the corpus writes closures both ways: a keyword in the file's own
    header lines, and a status banner anywhere in the file. The banner reading goes through
    lead_queue, which learned that workers append `## Status — **CLOSED ...**` at the END of a
    file — reading six lines from the top missed every one of those.
    """
    if CLOSED.search("\n".join(text.splitlines()[:HEADER_LINES])):
        return True
    try:
        import lead_queue
        return lead_queue._is_closed(text)
    except Exception:  # noqa: BLE001
        return False


def _is_decision(path: Path, text: str) -> bool:
    return bool(DECISION_NAME.match(path.name)
                or DECISION_TEXT.search("\n".join(text.splitlines()[:25])))


# A decision or blocked-test file rarely carries a `Severity:` label. It carries its claim
# in the heading — "an unauthenticated Critical RCE on a trusted origin" — so the headings
# are read as a second source after the labelled forms. Body prose is NOT read: "critical
# path" and "Low-consequence as far as I can tell" would both set a severity the author
# never claimed, and in a ranked queue a wrong severity is worse than no severity.
HEADING_RE = re.compile(r"^#{1,3}[ \t]+(.+)$", re.M)
BARE_SEV_RE = re.compile(r"\b(critical|high|medium|low|критическ\w+|высок\w+|средн\w+|"
                         r"низк\w+)\b", re.I)


def _own_severity(text: str) -> str:
    """The severity THIS file claims, not its engagement's ceiling."""
    try:
        from stop_gate import severity_of, SEVERITY_ORDER, _sev_from_word
    except Exception:  # noqa: BLE001
        return "unrated"
    best = severity_of(text)
    for heading in HEADING_RE.findall(text):
        for m in BARE_SEV_RE.finditer(heading):
            sev = _sev_from_word(m.group(1))
            if sev and (best is None
                        or SEVERITY_ORDER.index(sev) > SEVERITY_ORDER.index(best)):
                best = sev
    return best or "unrated"


def _scan_blocked(root):
    """Every open blocked test, split into decisions and the rest. One pass, one read each."""
    decisions, blocks = [], []
    for d in _engagements(root):
        bdir = d / "blocked-tests"
        if not bdir.is_dir():
            continue
        pay = _max_payout(d)
        for f in sorted(bdir.glob("*.md")):
            text = f.read_text(encoding="utf-8", errors="replace")
            if _is_resolved(f, text) or POLICY.search("\n".join(text.splitlines()[:HEADER_LINES])):
                continue
            row = {"engagement": str(d.relative_to(root)), "file": str(f.relative_to(root)),
                   "title": _title(text) or f.stem, "max_payout": pay,
                   "severity": _own_severity(text)}
            if _is_decision(f, text):
                row["why"] = "waiting on the operator"
                decisions.append(row)
                continue
            m = OPERATOR.search("\n".join(text.splitlines()[:25]))
            if not m:
                continue
            row["why"] = m.group(0)
            blocks.append(row)
    # Own severity first in both lists: a measured Critical must not sort below "needs a
    # buyer account" because both sit in a 1 000 000 programme. Filename last, for a stable
    # order between runs.
    key = lambda r: (-SEV_RANK.get(r["severity"], 0), -r["max_payout"], r["file"])  # noqa: E731
    decisions.sort(key=key)
    blocks.sort(key=key)
    return decisions, blocks


def operator_decisions(root=None):
    return _scan_blocked(root or _targets())[0]


def operator_blocks(root=None):
    return _scan_blocked(root or _targets())[1]


def chain_operator_caps(root=None):
    """Operator-only capabilities the chain graph says would unblock primitives."""
    import chain_graph as cg
    root = root or _targets()
    out = []
    for d in _engagements(root):
        try:
            res = cg.analyse(cg.load(d))
        except Exception:  # noqa: BLE001
            continue
        for m in res["missing"]:
            if cg.OPERATOR_CAP.match(m["cap"]):
                out.append({"engagement": str(d.relative_to(root)), "cap": m["cap"],
                            "unblocks": len(m["reach"]), "max_payout": _max_payout(d)})
    out.sort(key=lambda r: (-r["unblocks"], -r["max_payout"]))
    return out


def render(reports, blocks, caps=(), decisions=()) -> str:
    L = ["# Operator queue", "",
         "_Generated by `engine/operator_queue.py` from findings/, submissions.txt and blocked-tests/. "
         "Do not edit by hand — fix the source file and it regenerates (`cbh queue`, and every session start)._", ""]
    # Section 0 is first because of what being last cost: three decisions, one of them a
    # measured unauthenticated Critical, sat inside a 195-row table sorted by the ENGAGEMENT's
    # payout. A decision is one answer away from either a report or a dead end.
    L += [f"## 0. Decisions waiting on you — {len(decisions)}", "",
          "Each of these has its preconditions measured and **nothing sent**. One answer from you "
          "(or from the programme) moves it. Ranked by the severity the file itself claims.", ""]
    if decisions:
        L += ["| Severity | Engagement | Decision | Max payout |", "|---|---|---|---|"]
        for r in decisions:
            L.append(f"| {r['severity']} | {r['engagement']} | `{r['file']}` — {r['title']} | "
                     f"{r['max_payout']:,} |".replace(",", " "))
        L += ["", "Answer one with `cbh queue resolve <file> --as approved|refused|asked-programme "
              "--note \"...\"`, which writes the verdict into the file so it leaves this queue.", ""]
    else:
        L += ["None. No lane is waiting on an answer from you.", ""]
    L += [f"## 1. PoC passed, not yet submitted — {len(reports)} (impact and programme exclusions still to check)", ""]
    if reports:
        L += ["| Evidence | Severity | Engagement | Finding | Submit drafts |", "|---|---|---|---|---|"]
        for r in reports:
            L.append(f"| {r['evidence']} | {r['severity']} | {r['engagement']} | "
                     f"`{r['file']}` — {r['title']} | {', '.join(r['drafts']) or '—'} |")
        L += ["", "DEMONSTRATED only means a fired PoC passed for this finding's endpoint. It does NOT mean "
              "the impact is shown or that the programme pays for the class — read the finding's impact "
              "section against the programme's exclusions before submitting.", ""]
    else:
        L += ["Nothing unsubmitted in any `findings/`.", ""]
    L += [f"## 2. Needs you — {len(blocks)} open blocked tests that name an operator-only action", "",
          "Ranked by the severity each file claims for itself, then the engagement's maximum "
          "payout. `matched` is the phrase that put it here — read the file before acting; a "
          "keyword match is a pointer, not a verdict.", ""]
    if blocks:
        L += ["| Severity | Max payout | Engagement | Blocked test | matched |", "|---|---|---|---|---|"]
        for b in blocks:
            L.append(f"| {b['severity']} | {b['max_payout']:,} | {b['engagement']} | "
                     f"`{b['file']}` — {b['title']} | {b['why']} |".replace(",", " "))
    else:
        L += ["None."]
    L += ["", f"## 3. Operator actions that unblock chains — {len(caps)}", "",
          "From `**Chain:**` lines (`cbh chain-graph`): one approval here unblocks several primitives at once.", ""]
    if caps:
        L += ["| Unblocks | Engagement | Capability needed | Max payout |", "|---|---|---|---|"]
        for c in caps:
            L.append(f"| {c['unblocks']} | {c['engagement']} | `{c['cap']}` | {c['max_payout']:,} |".replace(",", " "))
    else:
        L += ["None annotated."]
    return "\n".join(L) + "\n"


def build(write=True, root=None):
    root = root or _targets()
    decisions, blocks = _scan_blocked(root)
    reports = ready_reports(root)
    try:
        caps = chain_operator_caps(root)
    except Exception:  # noqa: BLE001
        caps = []
    if write:
        (root / "OPERATOR-QUEUE.md").write_text(
            render(reports, blocks, caps, decisions), encoding="utf-8")
    return reports, blocks, caps, decisions


def brief_line(engagement_rel: str | None = None, root=None) -> str:
    """One line for session-brief. It NAMES the top decision instead of counting it.

    The old line said "N block(s) waiting on you" and nothing else, so the operator read a
    number where the queue held a measured Critical RCE. A count is not a surfacing.
    """
    reports, blocks, _caps, decisions = build(write=root is None, root=root)
    demo = [r for r in reports if r["evidence"] == "DEMONSTRATED"]
    if not reports and not blocks and not decisions:
        return ""
    mine = ""
    if engagement_rel:
        m = [r for r in demo if r["engagement"] == engagement_rel]
        if m:
            mine = f" — {len(m)} of them HERE"
    head = ""
    if decisions:
        top = decisions[0]
        here = [r for r in decisions if r["engagement"] == engagement_rel] if engagement_rel else []
        top = here[0] if here else top
        head = (f"DECISION WAITING ({len(decisions)} total): [{top['severity']}] "
                f"{top['file']} — {top['title']}\n")
    return (head
            + f"OPERATOR QUEUE: {len(demo)} finding(s) with a passing PoC not yet submitted "
              f"(check impact){mine}, {len(blocks)} block(s) waiting on you "
              f"→ Targets/OPERATOR-QUEUE.md")


RESOLUTION = {"approved": "RESOLVED — APPROVED BY OPERATOR",
              "refused": "RESOLVED — REFUSED BY OPERATOR",
              "asked-programme": "RESOLVED — ASKED THE PROGRAMME, WAITING ON THEM"}


def resolve(path: str, verdict: str, note: str = "") -> int:
    """Record the operator's answer in the file itself, so the item leaves this queue.

    Without this, an answered decision is answered only in a chat window: the file still says
    it is waiting, the next session surfaces it again, and the real decisions sink under the
    repeats. The banner is written at the top in the house form, which `_is_resolved` reads.
    """
    f = Path(path)
    if not f.is_absolute():
        root = _targets()
        f = (root / path) if (root / path).exists() else f
    if not f.exists() or f.parent.name != "blocked-tests":
        print(f"not a blocked-tests file: {path}", file=sys.stderr)
        return 2
    label = RESOLUTION[verdict]
    banner = (f"**Status:** {label} ({dt.date.today().isoformat()})"
              + (f" — {note}" if note else ""))
    text = f.read_text(encoding="utf-8")
    lines = text.splitlines()
    at = 1 if lines and lines[0].startswith("#") else 0
    f.write_text("\n".join(lines[:at] + ["", banner] + lines[at:]) + "\n", encoding="utf-8")
    print(f"{label}: {f}")
    return 0


def main(argv=None):
    argv = list(argv if argv is not None else sys.argv[1:])
    if argv and argv[0] == "resolve":
        ap = argparse.ArgumentParser(
            prog="cbh queue resolve",
            description="Record your answer to a decision so it leaves the operator queue.")
        ap.add_argument("file")
        ap.add_argument("--as", dest="verdict", required=True, choices=sorted(RESOLUTION))
        ap.add_argument("--note", default="")
        a = ap.parse_args(argv[1:])
        return resolve(a.file, a.verdict, a.note)
    reports, blocks, caps, decisions = build(write="--no-write" not in argv)
    if "--print" in argv:
        print(render(reports, blocks, caps, decisions))
    else:
        print(brief_line() or "operator queue empty")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
