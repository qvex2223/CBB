#!/usr/bin/env python3
"""js-advisory-check.py — advisories for a JS/npm (or any OSV ecosystem) package version.

WHY THIS EXISTS. `scripts/refresh-cve-index.py` populates `docs/cve-coverage.md` from **CISA KEV
only**, scoped to Apache/Atlassian/GitLab/Jenkins/SharePoint-Exchange/WebLogic/ColdFusion/
WordPress/Drupal/Joomla. A Next.js / Node / npm advisory therefore *cannot* appear in it, and
neither can it appear in a project's `recon/cve-ledger.jsonl`. An empty result there is a blind
spot, not a negative — and on Wildberries (2026-11-05) that blind spot hid seven in-range
advisories on a Tier 1 host fingerprinted 16 days earlier, including an unauthenticated Critical
9.5 RCE. This closes the gap without touching the cron-wired KEV refresher.

Source is OSV.dev: documented, free, no API key, and it carries the GitHub advisory data for npm.
It answers the question that matters — "is THIS version affected" — rather than handing back a list
to eyeball.

The judgement call this tool cannot make for you, and that cost a wrong conclusion on Wildberries:
a version being in range is **not** the same as the vulnerability being instantiated. Several of
those seven were router- or config-conditional (Pages vs App Router, a `rewrites()` rule with a
dynamic hostname, a `beforeInteractive` script that passes content rather than a `src`). Resolve
that on the host before writing anything down, and note that a maintained-branch check matters more
than a high patch number: 14.2.35 looks current but the 14.2.x line receives no further security
backports, so there was nothing to catch up to inside it.

Usage:
    python3 scripts/js-advisory-check.py next 14.2.35
    python3 scripts/js-advisory-check.py next 14.2.35 --json
    python3 scripts/js-advisory-check.py react 18.3.1 --ecosystem npm
    python3 scripts/js-advisory-check.py --selftest
Exit: 0 = no advisory affects this version, 1 = at least one does, 2 = lookup failed.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

OSV_QUERY = "https://api.osv.dev/v1/query"
TIMEOUT = 20

# Severity words that are worth shouting about in a one-line summary.
_LOUD = ("CRITICAL", "HIGH")


def query(name: str, version: str, ecosystem: str = "npm") -> dict:
    body = json.dumps({"package": {"name": name, "ecosystem": ecosystem},
                       "version": version}).encode()
    req = urllib.request.Request(
        OSV_QUERY, data=body,
        headers={"Content-Type": "application/json",
                 # A generic client name. Never put the operator's address here: a site asking
                 # automated clients for contact details is not a reason to hand one over.
                 "User-Agent": "js-advisory-check/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _severity(v: dict) -> str:
    """Best-effort severity label. OSV puts it in several places depending on the source."""
    for s in v.get("severity") or []:
        if s.get("score"):
            return str(s["score"])
    db = v.get("database_specific") or {}
    if db.get("severity"):
        return str(db["severity"]).upper()
    for aff in v.get("affected") or []:
        ds = aff.get("database_specific") or {}
        if ds.get("severity"):
            return str(ds["severity"]).upper()
    return "?"


def _fixed_versions(v: dict, name: str) -> list[str]:
    out: list[str] = []
    for aff in v.get("affected") or []:
        pkg = (aff.get("package") or {}).get("name")
        if pkg and pkg != name:
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    out.append(ev["fixed"])
    return sorted(set(out))


def summarise(doc: dict, name: str, version: str) -> list[dict]:
    rows = []
    for v in doc.get("vulns") or []:
        aliases = v.get("aliases") or []
        cve = next((a for a in aliases if a.startswith("CVE-")), "")
        rows.append({
            "id": v.get("id", ""),
            "cve": cve,
            "severity": _severity(v),
            "summary": (v.get("summary") or "").strip(),
            "fixed": _fixed_versions(v, name),
            "withdrawn": bool(v.get("withdrawn")),
        })
    # Loudest first, then by id so the output is stable between runs.
    rows.sort(key=lambda r: (0 if any(w in r["severity"].upper() for w in _LOUD) else 1, r["id"]))
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("package", nargs="?")
    ap.add_argument("version", nargs="?")
    ap.add_argument("--ecosystem", default="npm")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)

    if a.selftest:
        # Offline: the parsing is what regresses, not the network.
        doc = {"vulns": [{
            "id": "GHSA-xxxx", "aliases": ["CVE-2026-0001"],
            "summary": "example", "severity": [{"score": "CRITICAL"}],
            "affected": [{"package": {"name": "next"},
                          "ranges": [{"events": [{"introduced": "0"}, {"fixed": "15.5.28"}]}]}]}]}
        rows = summarise(doc, "next", "14.2.35")
        assert rows and rows[0]["cve"] == "CVE-2026-0001", rows
        assert rows[0]["fixed"] == ["15.5.28"], rows
        print("selftest: PASS")
        return 0

    if not a.package or not a.version:
        ap.error("package and version are required (or pass --selftest)")

    try:
        doc = query(a.package, a.version, a.ecosystem)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        print(f"lookup FAILED for {a.package}@{a.version} ({a.ecosystem}): {e}", file=sys.stderr)
        print("NOT MEASURED — a failed lookup is not a clean bill of health.", file=sys.stderr)
        return 2

    rows = [r for r in summarise(doc, a.package, a.version) if not r["withdrawn"]]
    if a.json:
        print(json.dumps({"package": a.package, "version": a.version,
                          "ecosystem": a.ecosystem, "affected_by": rows}, indent=2))
        return 1 if rows else 0

    head = f"{a.package}@{a.version} ({a.ecosystem})"
    if not rows:
        print(f"{head}: no advisory in OSV affects this version.")
        print("  Coverage note: OSV, not an exhaustive read of the vendor's own advisory list.")
        return 0
    print(f"{head}: {len(rows)} advisory(ies) affect this version.\n")
    for r in rows:
        ident = " / ".join(x for x in (r["id"], r["cve"]) if x)
        fixed = ", ".join(r["fixed"]) or "no fixed version listed"
        print(f"  [{r['severity']}] {ident}")
        if r["summary"]:
            print(f"      {r['summary']}")
        print(f"      fixed in: {fixed}")
    print("\n  IN RANGE IS NOT INSTANTIATED. Several advisories are router- or config-conditional;")
    print("  resolve that on the host before recording it. And check whether the deployed minor")
    print("  line still receives backports — a high patch number on an unmaintained branch means")
    print("  there is nothing to catch up to.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
