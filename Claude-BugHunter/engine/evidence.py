#!/usr/bin/env python3
"""
evidence.py — does this finding have a fired request behind it, or a memory?

The 7-Question Gate asks "can I demonstrate this right now?" (Q1) and "can you
prove impact?" (Q6), and until now both were answered by grepping the finding
text for words like "poc" and "response". A finding that *says* "PoC: curl ...
returns 200" passes that check whether or not the request was ever sent.

`poc_runtime.py` already writes a `.result.json` next to every spec it fires:
real bytes, redirect chain, cookies, a verdict computed in code. This module is
the other half — it looks for that artifact and refuses to call a finding
demonstrated without one.

Rules, deliberately blunt:
  * a PASS artifact whose URL appears in the finding text   -> demonstrated
  * a PASS artifact for some other URL                      -> mismatch, not proof
    (this catches the copy-paste of last week's evidence onto today's bug)
  * FAIL / ERROR / INCONCLUSIVE                             -> not proof
  * nothing at all                                          -> not proof

CLI:
    python3 engine/evidence.py <finding.md | dir | result.json>
exit 0 = a PASS artifact backs it, 1 = artifacts exist but none prove it,
2 = no artifact found at all.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

MAX_SCAN = 200  # result files to consider; an engagement with more has other problems

# Claims that live on the wire, not in a single status code. A report that says
# "redirects to /login", "the session dies", "Set-Cookie carries the token" is
# describing behaviour that a one-shot curl cannot show and memory routinely gets
# wrong — the whole reason poc_runtime now records chains and cookies.
WIRE_CLAIM_RE = re.compile(
    r"redirect|302|301|303|307|location:|set-cookie|cookie|session|logout|log out|"
    r"sso|oauth|saml|csrf|token refresh|"
    r"редирект|перенаправ|сесси|кук|вход|выход|авториз",
    re.I)

# A Burp-captured request/response saved next to the finding counts as wire
# evidence: the proxy saw the real exchange, chain included.
BURP_SUFFIXES = (".burp.txt", ".burp.json", ".burp.har", ".har")

# `bbcurl` now keeps every response body, headers included, under a sha256 in the
# response corpus. A finding that cites one of those hashes is pointing at bytes
# the transport actually received — so a stored 302 with its Location and
# Set-Cookie lines is wire evidence in exactly the way a remembered one is not.
# The citation has to be explicit: matching a corpus entry to a finding by URL
# alone would quietly hand today's report yesterday's capture.
CORPUS_SHA_RE = re.compile(r"\b([0-9a-f]{64})\b")
WIRE_HEADER_RE = re.compile(r"^(location|set-cookie):", re.I | re.M)
HTTP_STATUS_RE = re.compile(r"^HTTP/\d", re.M)


def _load(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _urls(doc: dict) -> List[str]:
    """Every URL the artifact actually hit, chain steps included."""
    out: List[str] = []
    for run in doc.get("runs") or []:
        for step in run.get("steps") or []:
            if step.get("url"):
                out.append(step["url"])
        res = run.get("result") or {}
        if res.get("final_url"):
            out.append(res["final_url"])
    spec = doc.get("spec_file")
    if not out and spec:
        out.append("")
    return out


def _age_days(doc: dict) -> Optional[float]:
    ts = doc.get("timestamp")
    if not ts:
        return None
    try:
        when = datetime.fromisoformat(ts)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return round((datetime.now(timezone.utc) - when).total_seconds() / 86400, 1)
    except Exception:  # noqa: BLE001
        return None


def _endpoint_tokens(url: str) -> List[str]:
    """Bits of a URL worth searching a finding for: host, and the path."""
    try:
        p = urllib.parse.urlsplit(url)
    except Exception:  # noqa: BLE001
        return []
    toks = []
    if p.hostname:
        toks.append(p.hostname)
    if p.path and p.path != "/":
        toks.append(p.path)
    return toks


def _burp_files(where: Path) -> List[Path]:
    if not where or not where.is_dir():
        return []
    out: List[Path] = []
    for q in where.rglob("*"):
        if q.is_file() and str(q).lower().endswith(BURP_SUFFIXES):
            out.append(q)
    return sorted(out)


def _corpus_rows(text: str) -> List[Dict]:
    """Response-corpus entries the finding cites by hash."""
    rows: List[Dict] = []
    if not text:
        return rows
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import responses  # type: ignore
    except Exception:  # noqa: BLE001
        return rows
    for sha in dict.fromkeys(CORPUS_SHA_RE.findall(text)):
        path = responses.path_for("", sha)
        if not path:
            continue
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8000]
        except Exception:  # noqa: BLE001
            continue
        rows.append({
            "file": str(path),
            "verdict": "CORPUS-CAPTURE",
            "urls": [],
            "age_days": None,
            "matches_finding": True,
            "steps": 0,
            # Headers are what make it wire evidence. A body captured with the
            # caller's own -o has no header block, and proves nothing about hops.
            "wire": bool(WIRE_HEADER_RE.search(head) or HTTP_STATUS_RE.search(head)),
        })
    return rows


def _wire_captured(doc: dict) -> bool:
    """Did this artifact actually record wire state — a chain, hops, or cookies?"""
    for run in doc.get("runs") or []:
        steps = run.get("steps") or []
        if len(steps) > 1:
            return True
        for r in [run.get("result") or {}] + [st.get("result") or {} for st in steps]:
            if r.get("redirects") or r.get("set_cookie"):
                return True
    return False


def collect(target: Path) -> List[Path]:
    """Find candidate .result.json artifacts for a finding file or directory."""
    if target.is_file() and target.name.endswith(".result.json"):
        return [target]
    if target.is_file():
        # a finding: its own sibling artifacts first, then the engagement's
        sibling = target.with_name(target.stem + ".result.json")
        found = [sibling] if sibling.exists() else []
        for d in (target.parent, target.parent.parent):
            if not d or not d.is_dir():
                continue
            found += sorted(q for q in d.rglob("*.result.json") if q not in found)
            if found:
                break
        return found[:MAX_SCAN]
    if target.is_dir():
        return sorted(target.rglob("*.result.json"))[:MAX_SCAN]
    return []


def _check(text: str, artifacts: List[Path], where: Path) -> Dict:
    """Core verdict logic: finding text (already lowercased), candidate artifacts and
    the directory to scan for Burp captures."""
    rows = []
    # Wire evidence that did not come from poc_runtime: corpus entries the finding
    # cites by hash, and Burp captures saved next to it.
    rows += _corpus_rows(text)
    for bp in _burp_files(where):
        rows.append({"file": str(bp), "verdict": "BURP-CAPTURE", "urls": [],
                     "age_days": None, "matches_finding": True, "steps": 0,
                     "wire": True})
    for path in artifacts:
        doc = _load(path)
        if doc is None:
            continue
        verdict = doc.get("final_verdict", "?")
        urls = _urls(doc)
        # No finding text to match against (dir mode) means every artifact counts.
        if text:
            matched = any(
                all(tok.lower() in text for tok in _endpoint_tokens(u) if tok)
                for u in urls if u
            )
        else:
            matched = True
        rows.append({
            "file": str(path),
            "verdict": verdict,
            "urls": urls,
            "age_days": _age_days(doc),
            "matches_finding": matched,
            "steps": len((doc.get("runs") or [{}])[-1].get("steps") or []),
            "wire": _wire_captured(doc),
        })
    return _verdict(text, rows)


def _verdict(text: str, rows: List[Dict]) -> Dict:
    proving = [r for r in rows if r["verdict"] == "PASS" and r["matches_finding"]]
    claims_wire = bool(text and WIRE_CLAIM_RE.search(text))
    wire_backed = any(r.get("wire") for r in rows)

    if proving and claims_wire and not wire_backed:
        # The finding talks about redirects/session/cookies; the evidence is a
        # single request with no chain and no cookies recorded. That gap is where
        # "it returned 200" reports come from — the 200 belonged to /login.
        status, reason = "WIRE-UNPROVEN", (
            "the finding describes redirect/session/cookie behaviour, but the only evidence "
            "is a single request with no redirect chain and no Set-Cookie recorded")
    elif proving:
        status, reason = "DEMONSTRATED", "a fired PoC passed for this finding's endpoint"
    elif not rows:
        status, reason = "NO-EVIDENCE", (
            "no .result.json artifact — nothing was fired, or it was fired outside "
            "poc_runtime and left no evidence")
    elif any(r["verdict"] == "PASS" for r in rows):
        status, reason = "MISMATCH", (
            "the only passing artifacts hit endpoints this finding never mentions")
    else:
        status, reason = "NOT-PROVEN", (
            "artifacts exist but none passed: "
            + ", ".join(sorted({r["verdict"] for r in rows})))
    return {"status": status, "reason": reason, "artifacts": rows}


def check(target: Path) -> Dict:
    """Verdict on whether `target` is backed by a fired, passing PoC."""
    artifacts = collect(target)
    text = ""
    if target.is_file() and not target.name.endswith(".result.json"):
        try:
            text = target.read_text(encoding="utf-8", errors="replace").lower()
        except Exception:  # noqa: BLE001
            text = ""
    where = target.parent if target.is_file() else target
    return _check(text, artifacts, where)


def check_blob(text: str, where: Path) -> Dict:
    """Same verdict for in-memory finding text (an engine candidate) whose artifacts
    live under directory `where`. An empty or unreadable directory is NO-EVIDENCE —
    absence of proof must never read as proof."""
    if not where.is_dir():
        return {"status": "NO-EVIDENCE",
                "reason": f"artifact directory {where} is missing — nothing was fired",
                "artifacts": []}
    return _check(text.lower(), collect(where), where)


def gate_line(report: Dict) -> str:
    """One line for the 7-Question Gate's Q1/Q6."""
    return {
        "DEMONSTRATED": "Q1/Q6 backed by a fired PoC (.result.json = PASS).",
        "NO-EVIDENCE": "Q1/Q6 unanswerable: run `python3 engine/poc_runtime.py <spec.json>` "
                       "and attach the .result.json. A described PoC is not a fired one.",
        "MISMATCH": "Q1/Q6 not backed: the passing evidence is for a different endpoint. "
                    "Fire a spec against THIS finding's endpoint.",
        "NOT-PROVEN": "Q1/Q6 not backed: the PoC ran and did not pass. Fix the spec or drop "
                      "the finding — do not report an unconfirmed bug.",
        "WIRE-UNPROVEN": "Q6 not backed for a wire-level claim. Two ways to fix it, both real: "
                         "(a) re-fire as a multi-step `steps` spec so the chain, the final URL and "
                         "every Set-Cookie land in the artifact; or (b) capture the exchange in "
                         "Burp (`scripts/burp-mcp.sh start`, then save request+response next to the "
                         "finding as <finding>.burp.txt). A status code alone cannot show a "
                         "redirect or a dead session.",
    }.get(report["status"], "")


def main(argv: List[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: evidence.py <finding.md | dir | result.json>")
        return 2
    target = Path(args[0])
    if not target.exists():
        print(f"not found: {target}")
        return 2

    rep = check(target)
    print(f"evidence for {target}")
    for r in rep["artifacts"]:
        mark = "*" if r["verdict"] == "PASS" and r["matches_finding"] else " "
        age = f"{r['age_days']}d ago" if r["age_days"] is not None else "age unknown"
        chain = f", {r['steps']}-step chain" if r["steps"] else ""
        chain += "" if r.get("wire") else "  [no chain/cookies recorded]"
        link = "" if r["matches_finding"] else "  [endpoint not mentioned in the finding]"
        print(f" {mark} {r['verdict']:<12} {age}{chain}  {r['file']}{link}")
        for u in r["urls"][:4]:
            if u:
                print(f"       {u}")
    if not rep["artifacts"]:
        print("   (none)")
    print()
    print(f"{rep['status']}: {rep['reason']}")
    print(gate_line(rep))
    return {"DEMONSTRATED": 0, "MISMATCH": 1, "NOT-PROVEN": 1,
            "WIRE-UNPROVEN": 1, "NO-EVIDENCE": 2}[rep["status"]]


if __name__ == "__main__":
    sys.exit(main())
