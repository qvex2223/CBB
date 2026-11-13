#!/usr/bin/env python3
"""
dedup.py — same-run duplicate check: vulnerability identity, not writing similarity.

Gate 2 of `/validate` dedupes against the OUTSIDE world (Hacktivity, GitHub,
changelogs). The duplicate that actually costs money is the one against
YOURSELF: two findings of the same engagement describing the same broken
control, submitted separately, merged by the platform — the validity ratio
takes the hit and one payout disappears.

This module surfaces the candidates mechanically so none is missed:

    cbh dedup Targets/<p>/<t>/findings/<finding>.md

It compares the finding against every sibling finding (and the endpoints in
`submissions.txt`) on three extracted signals — normalized endpoints, bug
class keywords, CWE — and emits LIKELY_DUPLICATE / POSSIBLE_DUPLICATE /
NOT_DUPLICATE per candidate. The identity decision itself (same root cause +
same fix = duplicate; different backend control / tenant boundary / fix =
distinct) stays with the operator: endpoints and classes are evidence, not a
verdict. Uncertainty routes to POSSIBLE, never to a clean NOT_DUPLICATE —
mirroring the rule in `report-writing` § same-run deduplication.

Exit codes: 0 no overlap · 2 possible duplicates need review · 1 likely duplicate.

CLI:
    cbh dedup <finding.md> [--dir <findings-dir>] [--json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

SCHEMA_VERSION = "1.0"

# Ordered by specificity: the first keyword hit names the class. Short tokens
# are word-bounded — "rce" must not fire inside "resources".
CLASS_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"\bidor\b|broken object|object.level access|bola", "idor"),
    (r"authz|function.level access|access control|privilege|forbidden action|role bypass", "authz"),
    (r"auth bypass|authentication bypass|preauth|unauth(enticated)? access", "auth-bypass"),
    (r"account takeover|\bato\b", "ato"),
    (r"open redirect|\bredirect\b|перенаправл|редирект", "redirect"),
    (r"\bssrf\b", "ssrf"),
    (r"\bxss\b|cross.site scripting", "xss"),
    (r"\bsqli\b|sql injection|\bnosql\b", "sqli"),
    (r"\brce\b|remote code execution|\bssti\b|template injection", "rce"),
    (r"deserial", "deserialization"),
    (r"\bxxe\b", "xxe"),
    (r"\blfi\b|path traversal|directory traversal", "lfi"),
    (r"file upload|upload bypass", "upload"),
    (r"race condition|toctou|double.spend|idempoten", "race"),
    (r"business logic|price|discount|checkout|workflow bypass|mass assignment", "logic"),
    (r"\bgraphql\b", "graphql"),
    (r"cache deception|cache poison", "cache"),
    (r"\bcsrf\b", "csrf"),
    (r"\boauth\b|\bsaml\b|\boidc\b|\bsso\b", "oauth"),
    (r"\bjwt\b|session|token", "session"),
    (r"secret|api.?key|credential|source leak|source map|\.git\b|\.env\b", "secret-leak"),
    (r"takeover|dangling|cname", "takeover"),
    (r"rate.?limit|brute|lockout|throttl", "rate-limit"),
    (r"smuggl|request smuggl|\bcl\.te\b|\bte\.cl\b", "smuggling"),
    (r"websocket|cswsh", "websocket"),
    (r"header injection|host header|crlf", "header-injection"),
    (r"\bcors\b", "cors"),
    (r"info(disclosure|rmation)|\bleak\b|exposure|\bpii\b|утечк", "info-leak"),
)

HTTP_LINE = re.compile(
    r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/[^\s`]+)", re.IGNORECASE)
URL_TOKEN = re.compile(r"https?://[^\s`\"')<>]+")
BACKTICK_PATH = re.compile(r"`(/[A-Za-z0-9_\-./{}]+)`")
CWE_TOKEN = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
VERSION_SEG = re.compile(r"/v\d+(?=/|$)")
TITLE_HEADING = re.compile(r"^#\s+(.+)$", re.MULTILINE)
TITLE_SECTION = re.compile(r"^##\s+Title\s*\n+([^\n]+)", re.MULTILINE | re.IGNORECASE)


def classify_text(text: str) -> Optional[str]:
    """First class keyword hit over title+lead of the description."""
    probe = " ".join((text or "").split())[:600]
    for pattern, name in CLASS_PATTERNS:
        if re.search(pattern, probe, re.IGNORECASE):
            return name
    return None


def normalize_path(raw: str) -> str:
    """Lowercase path, strip query/fragment, collapse version segments."""
    p = raw.split("?", 1)[0].split("#", 1)[0]
    p = VERSION_SEG.sub("/v*", p)
    p = re.sub(r"/{2,}", "/", p)
    return p.rstrip("/").lower() or "/"


def host_of(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def is_killed(text: str) -> bool:
    """A draft whose triage block already says KILL is a documented negative —
    it must not compete with live findings as a duplicate candidate."""
    m = re.search(r"Decision:\s*KILL\b", text, re.IGNORECASE)
    return m is not None


def extract(finding_path: Path) -> Dict:
    """Pull the comparable signals out of one finding file."""
    text = finding_path.read_text(encoding="utf-8", errors="replace")

    m = TITLE_SECTION.search(text) or TITLE_HEADING.search(text)
    title = m.group(1).strip() if m else finding_path.stem

    paths: Set[str] = set()
    hosts: Set[str] = set()
    for url in URL_TOKEN.findall(text):
        hosts.add(host_of(url))
        after = url.split("://", 1)[1]
        slash = after.find("/")
        if slash != -1:
            paths.add(normalize_path(after[slash:]))
    for _, path in HTTP_LINE.findall(text):
        paths.add(normalize_path(path))
    for path in BACKTICK_PATH.findall(text):
        paths.add(normalize_path(path))
    # A bare path with no segments ("/", "/api") matches everything — drop it.
    paths = {p for p in paths if p.count("/") >= 2 or len(p) > 6}

    cwe = CWE_TOKEN.search(text)
    return {
        "file": finding_path.name,
        "title": title,
        "class": classify_text(text),
        "cwe": cwe.group(0).upper() if cwe else None,
        "paths": sorted(paths),
        "hosts": sorted(hosts),
    }


def submissions_rows(submissions: Path) -> List[Dict]:
    """Endpoint + vuln columns of submissions.txt, if the file is there."""
    rows: List[Dict] = []
    if not submissions.is_file():
        return rows
    for line in submissions.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [c.strip() for c in line.split("|")]
        if len(parts) < 3:
            continue
        rows.append({
            "file": f"submissions.txt: {parts[0]}",
            "title": parts[2] if len(parts) > 2 else "",
            "class": classify_text(" ".join(parts[2:])),
            "cwe": None,
            "paths": [normalize_path(parts[1])] if "/" in parts[1] else [],
            "hosts": [parts[1].lower()] if "/" not in parts[1] else [],
        })
    return rows


def _overlap(target_paths: List[str], cand_paths: List[str]) -> Tuple[bool, List[str]]:
    """Exact matches, plus strict one-segment-prefix pairs (`/o/1` vs `/o/1/export`
    is the same resource with a sub-action — endpoint-family overlap)."""
    hits = [p for p in target_paths if p in cand_paths]
    for tp in target_paths:
        for cp in cand_paths:
            if cp.startswith(tp + "/") and cp.count("/") - tp.count("/") == 1:
                hits.append(f"{tp} ~ {cp}")
            elif tp.startswith(cp + "/") and tp.count("/") - cp.count("/") == 1:
                hits.append(f"{cp} ~ {tp}")
    return bool(hits), sorted(set(hits))


def compare(target: Dict, cand: Dict) -> Dict:
    shared_paths_hit, shared_paths = _overlap(target["paths"], cand["paths"])
    shared_hosts = sorted(set(target["hosts"]) & set(cand["hosts"]))
    same_class = bool(target["class"] and target["class"] == cand["class"])
    same_cwe = bool(target["cwe"] and target["cwe"] == cand["cwe"])

    if shared_paths_hit and (same_class or same_cwe):
        verdict, reason = "LIKELY_DUPLICATE", (
            f"same endpoint(s) {', '.join(shared_paths[:3])} and same class "
            f"({target['class'] or target['cwe']}) — same root cause + same fix is now the question")
    elif shared_paths_hit or (same_class and shared_hosts):
        verdict, reason = "POSSIBLE_DUPLICATE", (
            "overlap is real but identity is unresolved — "
            + ("same endpoint family, class differs: different backend control?" if shared_paths_hit
               else "same class on the same host: same broken control?"))
    elif same_class or same_cwe:
        verdict, reason = "POSSIBLE_DUPLICATE", (
            f"same class ({target['class'] or target['cwe']}) elsewhere on the target — "
            "duplicate only if one fix covers both; otherwise distinct reports")
    else:
        verdict, reason = "NOT_DUPLICATE", "no shared endpoint, class, or CWE signal"
    return {
        "candidate": cand["file"],
        "title": cand["title"][:90],
        "verdict": verdict,
        "shared_paths": shared_paths,
        "shared_hosts": shared_hosts,
        "class": cand["class"],
        "reason": reason,
    }


def run(finding: Path, directory: Optional[Path] = None) -> Dict:
    directory = directory or finding.parent
    target = extract(finding)

    candidates: List[Dict] = []
    for other in sorted(directory.glob("*.md")):
        if other.resolve() == finding.resolve() or other.name.endswith(".park.md"):
            continue
        if is_killed(other.read_text(encoding="utf-8", errors="replace")[:2000]):
            continue
        candidates.append(extract(other))
    candidates.extend(submissions_rows(directory.parent / "submissions.txt"))

    results = [compare(target, c) for c in candidates]
    worst = ("NOT_DUPLICATE", "POSSIBLE_DUPLICATE", "LIKELY_DUPLICATE")
    verdict = max((r["verdict"] for r in results), key=worst.index, default="NOT_DUPLICATE")
    return {
        "schema_version": SCHEMA_VERSION,
        "finding": str(finding),
        "class": target["class"],
        "cwe": target["cwe"],
        "checked": len(results),
        "verdict": verdict,
        "matches": [r for r in results if r["verdict"] != "NOT_DUPLICATE"],
    }


GUIDANCE = """
identity rules (report-writing § same-run deduplication):
  same root cause + same fix        → ONE report, even on different endpoints
  different control/tenant/fix      → TWO reports, even on the same endpoint
  regression after a fix            → reopen the original, not a duplicate
  overlap found                     → fold unique facts into the canonical first;
                                      they may raise ITS severity
  unsure                            → lean duplicate and self-merge — a platform
                                      merge costs more than a self-merge
"""


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="cbh dedup",
        description="same-run duplicate check: compare a finding against its "
                    "engagement siblings by vulnerability identity signals")
    ap.add_argument("finding", help="path to the finding .md")
    ap.add_argument("--dir", help="findings directory (default: the finding's own)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    finding = Path(args.finding)
    if not finding.is_file():
        print(f"dedup: no such finding: {finding}", file=sys.stderr)
        return 2
    out = run(finding, Path(args.dir) if args.dir else None)

    if args.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"DEDUP {out['finding']}")
        print(f"  class={out['class'] or '?'} cwe={out['cwe'] or '—'} "
              f"checked={out['checked']}")
        if not out["matches"]:
            print("  no overlap signals — clean")
        for m in out["matches"]:
            print(f"  [{m['verdict']}] {m['candidate']}")
            print(f"      {m['title']}")
            print(f"      {m['reason']}")
        print(GUIDANCE)
    return {"LIKELY_DUPLICATE": 1, "POSSIBLE_DUPLICATE": 2}.get(out["verdict"], 0)


if __name__ == "__main__":
    sys.exit(main())
