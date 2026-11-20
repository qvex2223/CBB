#!/usr/bin/env python3
"""
handback_verify.py — do the citations in a worker's hand-back actually exist?

`agents/roles/*.md` already require it: "Every citation must EXIST in `audit.jsonl` or the
response corpus — check before you write it" (`refuter.md:36-37`, `deep-hunter.md:70`,
`scout.md:35`). Nothing checked. This does, and it is the cheap half of the lesson a public
comparison taught at someone else's expense: PentAGI shipped a group of findings tagged
`confirmed-with-PoC` whose proof fingerprint existed only as a hardcoded constant inside its own
report generator, so the PoC had never run (habr.com/ru/articles/1107742, 14 Nov 2026).

    cbh handback-verify < handback.txt
    cbh handback-verify path/to/handback.md
    cbh handback-verify --engagement bizone/sberfactoring < handback.txt

Exit 0 when every citation resolves, 1 when any does not, 2 on a usage error. It reads only; it
sends nothing and writes nothing.

What it checks, and what each answer means:

  url        a claimed URL against every `urls` entry in audit.jsonl and its rotations.
             NOT IN AUDIT means no request to it was recorded — through this workspace that
             means it was never sent, or it was sent through a channel that does not audit.
  sha256     a claimed body hash against the audit rows AND the response corpus
             (`responses.path_for`, which already falls back across engagement folders).
  path       a claimed file path, relative to the repo or to Targets/. The cheapest
             fabrication to make and the cheapest to catch.

Four things this CANNOT tell you, printed with the result so nobody over-reads it:

  * Existence is not authorship. Concurrent lanes share one corpus, so a worker can cite a real
    artifact another lane created. This proves the artifact exists, not that the citing lane
    produced it.
  * A stored body over 262144 bytes is truncated on the way into the corpus, and the recorded
    `body_sha256` is over the ORIGINAL response. A hash that resolves in the audit but whose
    corpus copy is short is consistent, not suspicious.
  * `bbcurl` stores a gzip body unless `--compressed` was passed, so a hash can be of compressed
    bytes.
  * `-b` values are redacted in the audit, so a cited cookie value can never be confirmed here.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import responses  # noqa: E402  store_root / path_for, so the corpus layout has ONE definition

URL_RE = re.compile(r"https?://[^\s'\"`<>)\]},]+")
SHA_RE = re.compile(r"\b[0-9a-f]{64}\b")
# Paths a hand-back cites: a corpus-relative or repo-relative markdown/json artifact. Anchored on
# a known tier or on Targets/ so ordinary prose containing a slash is not read as a path.
PATH_RE = re.compile(
    r"\b((?:Targets/|hunt-memory/)[^\s'\"`<>)\]},]+"
    r"|(?:findings|leads|primitives|blocked-tests|hosts|recon)/[^\s'\"`<>)\]},]+)")
AUDIT_FILES = ("audit.jsonl", "audit.jsonl.1", "audit.jsonl.2", "audit.jsonl.3")


def _memdir(memdir: Optional[Path] = None) -> Path:
    return memdir or responses._memdir()  # noqa: SLF001 - one definition of the memory dir


def audit_rows(memdir: Optional[Path] = None) -> List[Dict]:
    """Every audit row, live log and rotations. No limit: an older citation is still a citation."""
    out: List[Dict] = []
    base = _memdir(memdir)
    for name in AUDIT_FILES:
        f = base / name
        if not f.is_file():
            continue
        with f.open(encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:  # noqa: BLE001 - a malformed row is not a citation
                    continue
    return out


def _urls_of(row: Dict) -> List[str]:
    # `urls`, PLURAL — the singular key does not exist, and a lookup on `url` finds nothing on
    # every row in the log.
    out = [str(u) for u in (row.get("urls") or [])]
    eff = row.get("url_effective")
    if eff:
        out.append(str(eff))
    return out


def extract(text: str) -> Dict[str, List[str]]:
    """The citations in a hand-back, de-duplicated, in the order they appear."""
    def uniq(seq):
        seen, out = set(), []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return {
        "url": uniq(m.group(0).rstrip(".,;:") for m in URL_RE.finditer(text)),
        "sha256": uniq(m.group(0) for m in SHA_RE.finditer(text)),
        "path": uniq(m.group(1).rstrip(".,;:") for m in PATH_RE.finditer(text)),
    }


def check_url(url: str, rows: List[Dict]) -> Tuple[str, str]:
    for r in rows:
        for u in _urls_of(r):
            if u == url:
                return "FOUND", f"{r.get('timestamp', '?')[:19]} {r.get('engagement', '?')}"
    # A prefix match is reported separately: it is weaker evidence and must not read as exact.
    for r in rows:
        for u in _urls_of(r):
            if u.startswith(url) or url.startswith(u):
                return "PREFIX-ONLY", (f"no exact row; closest {u[:70]} "
                                       f"({r.get('timestamp', '?')[:19]})")
    return "NOT IN AUDIT", "no request to this url is recorded"


def check_sha(digest: str, rows: List[Dict], engagement: str,
              memdir: Optional[Path] = None) -> Tuple[str, str]:
    in_audit = next((r for r in rows if r.get("body_sha256") == digest), None)
    stored = responses.path_for(engagement, digest, memdir)
    if in_audit and stored:
        return "FOUND", f"audit + corpus {stored.parent.name}/{stored.name}"
    if in_audit:
        return "AUDIT ONLY", ("recorded on the wire, no corpus copy — storage was off, the body "
                              "was empty, or it was pruned")
    if stored:
        return "CORPUS ONLY", (f"{stored.parent.name}/{stored.name} exists, but no audit row "
                               "carries this hash")
    return "NOT IN AUDIT", "no audit row and no corpus file carry this hash"


def check_path(rel: str) -> Tuple[str, str]:
    for base in (REPO, responses._memdir().parent):  # noqa: SLF001
        p = (base / rel)
        if p.exists():
            return "FOUND", str(p.relative_to(base)) if base == REPO else str(p)
    return "NOT FOUND", "no such file under the repo or the memory dir"


OK_VERDICTS = ("FOUND", "AUDIT ONLY", "CORPUS ONLY", "PREFIX-ONLY")


def verify(text: str, engagement: str = "", memdir: Optional[Path] = None) -> Dict:
    rows = audit_rows(memdir)
    cites = extract(text)
    results = []
    for url in cites["url"]:
        v, why = check_url(url, rows)
        results.append({"kind": "url", "value": url, "verdict": v, "why": why})
    for digest in cites["sha256"]:
        v, why = check_sha(digest, rows, engagement, memdir)
        results.append({"kind": "sha256", "value": digest, "verdict": v, "why": why})
    for rel in cites["path"]:
        v, why = check_path(rel)
        results.append({"kind": "path", "value": rel, "verdict": v, "why": why})
    misses = [r for r in results if r["verdict"] not in OK_VERDICTS]
    return {"rows": len(rows), "results": results, "misses": misses}


def render(rep: Dict) -> str:
    L = [f"handback-verify · {len(rep['results'])} citation(s) against {rep['rows']} audit row(s)",
         ""]
    if not rep["results"]:
        L.append("  no url, sha256 or path cited — there is nothing here to check, which is")
        L.append("  itself the finding: a hand-back with no citation cannot be spot-checked.")
    for r in rep["results"]:
        mark = " " if r["verdict"] in OK_VERDICTS else "!"
        L.append(f" {mark} {r['verdict']:<13} {r['kind']:<6} {r['value'][:66]}")
        L.append(f"                  {r['why'][:92]}")
    L += ["", f"{len(rep['misses'])} citation(s) do not resolve." if rep["misses"]
          else "every citation resolves.",
          "",
          "Existence is not authorship: concurrent lanes share one corpus, so a real artifact may",
          "have been created by another lane. A truncated corpus copy (over 262144 bytes) is",
          "consistent with an audit hash taken over the ORIGINAL response, `bbcurl` stores gzip",
          "unless `--compressed` was passed, and `-b` values are redacted in the audit."]
    return "\n".join(L)


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cbh handback-verify",
                                 description=__doc__.strip().splitlines()[0])
    ap.add_argument("file", nargs="?", help="hand-back text file (default: stdin)")
    ap.add_argument("--engagement", default="",
                    help="engagement the lane ran on, for the corpus folder")
    a = ap.parse_args(list(sys.argv[1:] if argv is None else argv))
    if a.file:
        p = Path(a.file)
        if not p.is_file():
            print(f"not found: {p}", file=sys.stderr)
            return 2
        text = p.read_text(encoding="utf-8", errors="ignore")
    else:
        text = sys.stdin.read()
    rep = verify(text, a.engagement)
    print(render(rep))
    return 1 if rep["misses"] else 0


if __name__ == "__main__":
    sys.exit(main())
