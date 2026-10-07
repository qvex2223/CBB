#!/usr/bin/env python3
"""
cve_watch.py — per-engagement CVE watcher.

Reads a watchlist of fingerprinted products/versions for one bug-bounty
engagement (Targets/<name>/recon/cve-watchlist.txt), queries the NVD API for
CVEs published/modified since the last run, and appends genuinely NEW hits
(never seen on a previous run) to that engagement's notes.md — under the
existing recon-log discipline, NOT into the assistant's cross-session memory.

This is independent of Claude-BugHunter/scripts/refresh-cve-index.py, which is
scoped to the fork's own skill-coverage vendors (KEV feed, hunt-* mapped
products only). This script watches whatever is actually fingerprinted live on
a target's estate, regardless of whether a matching hunt-* skill exists.

Usage:
    scripts/cve_watch.py --project kcell
    scripts/cve_watch.py --project kcell-main --days 14   # override lookback on first run
    scripts/cve_watch.py --project kcell --dry-run        # print, don't write notes.md

Watchlist format (Targets/<name>/recon/cve-watchlist.txt), pipe-delimited:
    # comments start with #
    Product Name | version-or-blank | host-ref | free-text note

State file (Targets/<name>/recon/cve-watch-state.json) tracks last_run and
every CVE ID already surfaced, so a CVE is only ever appended once.

Exit codes:
    0 — ran clean (0 or more new hits printed/appended)
    1 — a watchlist entry's NVD query failed after retries (rest still ran)
    2 — fatal (no watchlist found, bad project path)
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "Claude-BugHunter-CVE-Watch/1.0 (authorized bug-bounty engagement tooling)"
REQUEST_GAP_SECONDS = 6.5  # stay under NVD's unauth 5-req/30s rolling limit
MAX_RETRIES = 3

TARGETS_ROOT = Path(__file__).resolve().parents[2] / "Targets"


def log(msg: str) -> None:
    print(f"[cve_watch] {msg}", file=sys.stderr)


def parse_watchlist(path: Path) -> list[dict]:
    entries = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3:
            log(f"watchlist line {lineno} malformed (need >=3 '|'-fields), skipping: {raw!r}")
            continue
        product, version, host_ref = parts[0], parts[1], parts[2]
        note = parts[3] if len(parts) > 3 else ""
        entries.append({"product": product, "version": version, "host_ref": host_ref, "note": note})
    return entries


def load_state(path: Path) -> dict:
    if not path.exists():
        return {"last_run": None, "seen_cve_ids": []}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def iso(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def query_nvd(keyword: str, pub_start: datetime.datetime, pub_end: datetime.datetime) -> list[dict]:
    params = {
        "keywordSearch": keyword,
        "pubStartDate": iso(pub_start),
        "pubEndDate": iso(pub_end),
        "resultsPerPage": 50,
    }
    url = f"{NVD_ENDPOINT}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
            return data.get("vulnerabilities", [])
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                log(f"  NVD 429 rate-limited, backing off ({attempt}/{MAX_RETRIES})")
                time.sleep(REQUEST_GAP_SECONDS * attempt)
                continue
            log(f"  NVD HTTP {e.code} for {keyword!r}: {e}")
            break
        except (urllib.error.URLError, TimeoutError) as e:
            last_err = e
            log(f"  network error for {keyword!r} ({attempt}/{MAX_RETRIES}): {e}")
            time.sleep(REQUEST_GAP_SECONDS)
    if last_err:
        raise last_err
    return []


def extract_cve(vuln_wrapper: dict) -> dict:
    cve = vuln_wrapper["cve"]
    cve_id = cve["id"]
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    cvss = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss = metrics[key][0]["cvssData"].get("baseScore")
            break
    return {
        "id": cve_id,
        "published": cve.get("published", ""),
        "desc_full": desc,
        "desc": desc[:280],
        "cvss": cvss,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def is_probably_relevant(product: str, desc_full: str) -> bool:
    """Heuristic precision filter.

    NVD keywordSearch is a bag-of-words OR/AND over the full description, so a
    single-word product like "Next.js" or "Strapi" also matches any CVE for an
    unrelated product whose description merely name-drops it in passing (e.g.
    "9Router ... under Next.js API routes"). GHSA-derived NVD descriptions
    consistently name the actual affected product as the subject of the first
    sentence ("Strapi is an open source...", "Next.js is a React framework...")
    — require the product's first word to appear near the start of the
    description as a proxy for "this CVE is actually about that product."
    Errs toward dropping ambiguous multi-word products (Microsoft, Oracle,
    HCL) less aggressively since the NVD query already AND-ed every word.
    """
    first_word = product.split()[0].lower()
    window = desc_full[:40].lower()
    return first_word in window





def append_ledger(path: Path, hits: list[tuple[dict, dict]], now: datetime.datetime) -> None:
    """Append each hit as one JSON record.

    notes.md gets the human-readable block, but it is prose — you cannot ask it
    "what is still unchecked on web.kcell.kz" without re-reading it by eye, and
    the state file only keeps CVE *ids*, so the host mapping was unrecoverable
    once the run ended. This ledger is the queryable copy that `cve-digest.py`
    reads. `status` starts at "new"; triage moves it to checked/dismissed.
    """
    with path.open("a", encoding="utf-8") as f:
        for entry, cve in hits:
            f.write(json.dumps({
                "cve_id": cve["id"],
                "cvss": cve["cvss"],
                "published": cve["published"][:10],
                "product": entry["product"],
                "version": entry["version"],
                "hosts": [h.strip() for h in entry["host_ref"].split(",") if h.strip()],
                "desc": cve["desc"],
                "url": cve["url"],
                "first_seen": now.strftime("%Y-%m-%d"),
                "status": "new",
            }, ensure_ascii=False) + "\n")


def run(project: str, days_override: int | None, dry_run: bool, min_cvss: float) -> int:
    project_dir = TARGETS_ROOT / project
    watchlist_path = project_dir / "recon" / "cve-watchlist.txt"
    state_path = project_dir / "recon" / "cve-watch-state.json"
    ledger_path = project_dir / "recon" / "cve-ledger.jsonl"
    notes_path = project_dir / "notes.md"

    if not watchlist_path.exists():
        log(f"FATAL: no watchlist at {watchlist_path}")
        return 2
    if not notes_path.exists():
        log(f"FATAL: no notes.md at {notes_path}")
        return 2

    entries = parse_watchlist(watchlist_path)
    if not entries:
        log("watchlist is empty, nothing to do")
        return 0

    state = load_state(state_path)
    seen = set(state.get("seen_cve_ids", []))

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    if state.get("last_run"):
        pub_start = datetime.datetime.fromisoformat(state["last_run"])
    else:
        pub_start = now - datetime.timedelta(days=days_override or 90)
    # NVD caps pubStartDate/pubEndDate range at 120 days apart
    if (now - pub_start).days > 119:
        pub_start = now - datetime.timedelta(days=119)

    new_hits: list[tuple[dict, dict]] = []  # (watchlist entry, cve dict)
    had_error = False

    for i, entry in enumerate(entries):
        keyword = entry["product"] + (f" {entry['version']}" if entry["version"] else "")
        log(f"[{i+1}/{len(entries)}] querying NVD: {keyword!r}")
        try:
            vulns = query_nvd(keyword, pub_start, now)
        except Exception as e:  # noqa: BLE001 - log and keep going, one bad entry shouldn't kill the run
            log(f"  giving up on {keyword!r}: {e}")
            had_error = True
            vulns = []

        single_word_product = len(entry["product"].split()) == 1
        filtered_noise = 0
        for wrapper in vulns:
            cve = extract_cve(wrapper)
            if cve["id"] in seen:
                continue
            seen.add(cve["id"])  # mark seen regardless — don't re-litigate noise on future runs
            if single_word_product and not is_probably_relevant(entry["product"], cve["desc_full"]):
                filtered_noise += 1
                continue
            if min_cvss > 0 and cve["cvss"] is not None and cve["cvss"] < min_cvss:
                filtered_noise += 1
                continue
            new_hits.append((entry, cve))
        if filtered_noise:
            log(f"  filtered {filtered_noise} low-confidence match(es) for {keyword!r}")

        if i < len(entries) - 1:
            time.sleep(REQUEST_GAP_SECONDS)

    if not new_hits:
        log("no new CVEs since last run")
    else:
        log(f"{len(new_hits)} new CVE(s) found")
        today = now.strftime("%Y-%m-%d")
        block_lines = [f"\n## CVE Watch (auto, {today}) — cve_watch.py, unverified, needs manual /intel confirm\n"]
        for entry, cve in new_hits:
            cvss_str = f"CVSS {cve['cvss']}" if cve["cvss"] is not None else "CVSS n/a"
            product_str = f"{entry['product']} {entry['version']}".strip()
            block_lines.append(
                f"- **{cve['id']}** ({cvss_str}, published {cve['published'][:10]}) — "
                f"matched watchlist entry `{product_str}` "
                f"({entry['host_ref']}). {cve['desc']} [{cve['url']}]"
            )
        block = "\n".join(block_lines) + "\n"
        print(block)
        if dry_run:
            log("dry-run: not writing to notes.md or state file")
        else:
            with notes_path.open("a", encoding="utf-8") as f:
                f.write(block)
            log(f"appended {len(new_hits)} hit(s) to {notes_path}")
            append_ledger(ledger_path, new_hits, now)
            log(f"appended {len(new_hits)} record(s) to {ledger_path}")

    if not dry_run:
        state["last_run"] = iso(now)
        state["seen_cve_ids"] = sorted(seen)
        save_state(state_path, state)

    return 1 if had_error else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True, help="Targets/<project> folder name, e.g. kcell, kcell-main")
    ap.add_argument("--days", type=int, default=None, help="lookback window in days on first run (default 90)")
    ap.add_argument("--dry-run", action="store_true", help="print hits, don't write notes.md/state")
    ap.add_argument("--min-cvss", type=float, default=0.0,
                    help="drop scored hits below this CVSS (unscored CVEs always kept, default 0 = no filter)")
    args = ap.parse_args()
    return run(args.project, args.days, args.dry_run, args.min_cvss)


if __name__ == "__main__":
    sys.exit(main())
