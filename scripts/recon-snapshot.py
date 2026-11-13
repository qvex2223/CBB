#!/usr/bin/env python3
"""
recon-snapshot.py — rotate a target's recon manifest and queue only what changed.

Re-running recon on a hunted target produces a manifest that is 95% what you already
read. The delta is the surface: an operation that appeared since last month, a parameter
that was added, and above all an operation whose declared security *changed*. Reading the
whole manifest again to find those three rows is how re-recon gets skipped entirely.

So: snapshot the current manifest, diff it against the previous snapshot, and write the
high-risk rows into the engagement's hunt queue — `recon/<target>/hunt-queue.md`, plus
vector-ledger rows for anything that clears the threshold, so `cbh vectors next` surfaces
new surface without anybody re-reading a manifest.

    python3 scripts/recon-snapshot.py --target api.acme.com --manifest recon/api.acme.com/manifest.json
    python3 scripts/recon-snapshot.py --project Targets/kcell --all

This performs NO requests. It reads manifests that recon already produced. Schedule the
recon run itself separately — `scripts/install-recon-snapshot.sh` wires a daily pass and
is opt-in, because a scheduled job that touches a live program is the operator's decision,
not a default.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

QUEUE_THRESHOLD = 75      # risk_score at or above this goes into the queue
KEEP_SNAPSHOTS = 10


def _stamp() -> str:
    return f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"


def snapshots(snap_dir: Path):
    return sorted(snap_dir.glob("manifest.*.json"))


def rotate(manifest: Path, snap_dir: Path, keep: int = KEEP_SNAPSHOTS) -> Path:
    """Store the current manifest as a snapshot. Returns the path written."""
    snap_dir.mkdir(parents=True, exist_ok=True)
    target = snap_dir / f"manifest.{_stamp()}.json"
    target.write_text(manifest.read_text(encoding="utf-8"), encoding="utf-8")
    for old in snapshots(snap_dir)[:-keep]:
        old.unlink()
    return target


def queue_lines(delta: dict, threshold: int = QUEUE_THRESHOLD) -> list[str]:
    """Only rows worth somebody's attention. A quiet delta must produce no queue."""
    lines: list[str] = []
    for item in delta.get("operations_changed") or []:
        if not item.get("security_changed"):
            continue
        op = item["operation"]
        # The highest-signal row recon produces on a hunted target: an endpoint that
        # used to declare authentication and no longer does (or the reverse).
        lines.append(f"- **SECURITY CHANGED** `{op['method']} {op['path']}` on {op['host']} "
                     f"— declared security is now `{op.get('secured')}`. "
                     f"Re-test authorization on it before anything else.")
    for op in delta.get("operations_added") or []:
        if op.get("risk_score", 0) < threshold:
            continue
        hints = ", ".join(op.get("risk_hints") or []) or "no hints"
        lines.append(f"- NEW `{op['method']} {op['path']}` on {op['host']} "
                     f"(risk {op['risk_score']}: {hints})")
    for item in delta.get("operations_changed") or []:
        if item.get("security_changed") or item.get("risk_score", 0) < threshold:
            continue
        op = item["operation"]
        added = (item.get("fields_added") or []) + (item.get("parameters_added") or [])
        if added:
            lines.append(f"- CHANGED `{op['method']} {op['path']}` on {op['host']} "
                         f"— new input(s): {', '.join(added[:8])}")
    for asset in delta.get("assets_added") or []:
        lines.append(f"- NEW HOST `{asset.get('host')}` "
                     f"({asset.get('status')} {asset.get('title') or ''})".rstrip() + "  "
                     "— scope-check it before touching it.")
    return lines


def write_queue(path: Path, target: str, lines: list[str], previous: Path | None) -> bool:
    """Write the queue file. Returns False when there was nothing to queue."""
    if not lines:
        return False
    header = [f"# Hunt queue — {target}", "",
              f"Generated {datetime.now(timezone.utc).isoformat()} by recon-snapshot.",
              f"Compared against `{previous.name if previous else 'no previous snapshot'}`.",
              "", "Only high-risk deltas are listed. Everything else in the manifest is "
              "surface you have already seen.", ""]
    path.write_text("\n".join(header + lines) + "\n", encoding="utf-8")
    return True


def seed_vectors(target: str, delta: dict, threshold: int = QUEUE_THRESHOLD) -> int:
    """Put the new high-risk operations into the vector ledger, so `next` finds them."""
    try:
        import vectors as V  # type: ignore
    except Exception:  # noqa: BLE001
        return 0
    ops = [op for op in (delta.get("operations_added") or [])
           if op.get("risk_score", 0) >= threshold]
    ops += [i["operation"] for i in (delta.get("operations_changed") or [])
            if i.get("security_changed")]
    if not ops:
        return 0
    ledger = V.seed_from_manifest(target, {"operations": ops})
    V.save(ledger)
    return ledger.get("last_seed_added", 0)


def process(target: str, manifest: Path, threshold: int = QUEUE_THRESHOLD) -> dict:
    import recon_delta as RD  # type: ignore
    snap_dir = manifest.parent / "snapshots"
    previous = snapshots(snap_dir)[-1] if snapshots(snap_dir) else None
    result = {"target": target, "manifest": str(manifest), "previous": None,
              "queued": 0, "vectors_added": 0, "first_snapshot": previous is None}
    if previous is None:
        rotate(manifest, snap_dir)
        return result                     # nothing to diff against yet
    delta = RD.compare(json.loads(previous.read_text()), json.loads(manifest.read_text()))
    lines = queue_lines(delta, threshold)
    queue_path = manifest.parent / "hunt-queue.md"
    if write_queue(queue_path, target, lines, previous):
        result["queued"] = len(lines)
        result["queue_file"] = str(queue_path)
        result["vectors_added"] = seed_vectors(target, delta, threshold)
    elif queue_path.exists():
        # A stale queue from last week reads as today's work. Clear it.
        queue_path.unlink()
    result["previous"] = str(previous)
    result["counts"] = delta["counts"]
    rotate(manifest, snap_dir)
    return result


def discover(project: Path) -> list[tuple[str, Path]]:
    out = []
    for manifest in sorted((project / "recon").glob("*/manifest.json")):
        out.append((manifest.parent.name, manifest))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target")
    ap.add_argument("--manifest", type=Path)
    ap.add_argument("--project", type=Path, help="engagement dir; use with --all")
    ap.add_argument("--all", action="store_true", help="every recon/<target>/manifest.json")
    ap.add_argument("--threshold", type=int, default=QUEUE_THRESHOLD)
    args = ap.parse_args(argv)

    jobs: list[tuple[str, Path]] = []
    if args.all:
        if not args.project:
            ap.error("--all needs --project")
        jobs = discover(args.project)
    elif args.manifest:
        jobs = [(args.target or args.manifest.parent.name, args.manifest)]
    else:
        ap.error("pass --manifest, or --project with --all")

    if not jobs:
        print("no recon manifests found")
        return 0
    for target, manifest in jobs:
        result = process(target, manifest, args.threshold)
        if result["first_snapshot"]:
            print(f"{target}: first snapshot stored — nothing to compare yet")
        elif result["queued"]:
            print(f"{target}: {result['queued']} high-risk delta(s) -> "
                  f"{result['queue_file']}"
                  + (f", +{result['vectors_added']} vector(s)" if result["vectors_added"] else ""))
        else:
            print(f"{target}: no high-risk change since {Path(result['previous']).name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
