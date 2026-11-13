#!/usr/bin/env python3
"""
memory_migrate.py — reversible normalization of an existing hunt-memory corpus.

`engine/memory.py` changed shape: vulnerability classes and techniques are now
normalized to bounded identifiers, and a row records local confirmation separately
from the program's verdict. New writes use the new schema. The corpus on disk is
older than that, so analytics has to interpret two shapes at once — and every
"interpret the old shape" branch is a place for the two to drift apart.

This migrates the old rows forward. The rules it follows are the ones the data
itself justifies:

  * patterns.jsonl was success-only by construction, so a pattern row with no
    `result` really was `confirmed`, and `locally_confirmed` is true for all of them.
  * a journal row with no `result` is an *unknown attempt*, not a success. It is
    left alone rather than guessed at — that guess is exactly the bug this whole
    change exists to remove.
  * `vuln_class` and `technique` are normalized through memory.py's own functions,
    so the migration cannot drift from the writer.
  * `locally_confirmed` / `platform_outcome` are derived from `result` only where
    they are absent. An explicit value the operator wrote always wins.

Safety, because this rewrites the only long-term memory the workspace has:

  * dry run is the default, and prints before/after counts plus a sha256 per file;
  * `--apply` copies every file to `<file>.pre-migration-<UTC stamp>` first;
  * append-only semantics are preserved: rows are rewritten in place, never
    reordered, merged, or dropped. Row counts must match or the write is aborted;
  * `--rollback <stamp>` restores from those backups.

    python3 engine/memory_migrate.py                 # dry run, prints the diff
    python3 engine/memory_migrate.py --apply
    python3 engine/memory_migrate.py --rollback 20260915T101500Z
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from memory import (  # noqa: E402
    LOCAL_CONFIRM_RESULTS, PLATFORM_RESULTS, normalize_technique, normalize_vuln_class,
    resolve_dir,
)

MIGRATED_FILES = ("journal.jsonl", "patterns.jsonl")
BACKUP_SUFFIX = ".pre-migration-"


def _stamp() -> str:
    return f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"


def sha256(path: Path) -> str:
    if not path.exists():
        return "-"
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def migrate_row(row: dict, *, is_pattern: bool) -> tuple[dict, list[str]]:
    """Return the migrated row and the list of fields this migration touched."""
    out = dict(row)
    changed: list[str] = []

    if out.get("vuln_class"):
        new = normalize_vuln_class(out["vuln_class"])
        if new != out["vuln_class"]:
            out["vuln_class"] = new
            changed.append("vuln_class")

    if "technique" in out:
        new = normalize_technique(out.get("technique"))
        if new != out.get("technique"):
            out["technique"] = new
            changed.append("technique")

    # patterns.jsonl held confirmed rows only; a missing result there is not unknown.
    if is_pattern and not out.get("result"):
        out["result"] = "confirmed"
        changed.append("result")

    result = str(out.get("result") or "").lower()
    if "locally_confirmed" not in out:
        if is_pattern:
            out["locally_confirmed"] = True
            changed.append("locally_confirmed")
        elif result:
            out["locally_confirmed"] = result in LOCAL_CONFIRM_RESULTS
            changed.append("locally_confirmed")
        # a journal row with no result stays unannotated — see module docstring

    if "platform_outcome" not in out and result:
        out["platform_outcome"] = result if result in PLATFORM_RESULTS else None
        changed.append("platform_outcome")

    return out, changed


def plan(memdir: Path) -> dict:
    report = {"dir": str(memdir), "files": []}
    for name in MIGRATED_FILES:
        path = memdir / name
        is_pattern = name == "patterns.jsonl"
        rows_in, rows_out, touched, malformed, changed_rows = 0, [], {}, 0, 0
        if path.exists():
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    rows_in += 1
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        malformed += 1
                        rows_out.append(line)      # preserved verbatim, never dropped
                        continue
                    migrated, changed = migrate_row(row, is_pattern=is_pattern)
                    if changed:
                        changed_rows += 1
                    for field in changed:
                        touched[field] = touched.get(field, 0) + 1
                    rows_out.append(json.dumps(migrated, ensure_ascii=False))
        report["files"].append({
            "name": name, "path": path, "rows": rows_in, "malformed": malformed,
            "changed_rows": changed_rows, "fields_touched": touched,
            "sha_before": sha256(path), "lines": rows_out,
        })
    return report


def apply(report: dict, stamp: str) -> list[str]:
    actions = []
    for item in report["files"]:
        path: Path = item["path"]
        if not path.exists():
            continue
        backup = path.with_name(path.name + BACKUP_SUFFIX + stamp)
        shutil.copy2(path, backup)
        tmp = path.with_name(path.name + ".migrating")
        tmp.write_text("\n".join(item["lines"]) + ("\n" if item["lines"] else ""),
                       encoding="utf-8")
        # Row counts must match exactly: this migration rewrites fields, never rows.
        written = sum(1 for x in tmp.read_text(encoding="utf-8").splitlines() if x.strip())
        if written != item["rows"]:
            tmp.unlink()
            raise SystemExit(f"ABORT {path.name}: {item['rows']} rows in, {written} out. "
                             f"Nothing written. Backup kept at {backup}")
        tmp.replace(path)
        item["sha_after"] = sha256(path)
        actions.append(f"{path.name}: {item['rows']} rows, backup -> {backup.name}")
    return actions


def rollback(memdir: Path, stamp: str) -> list[str]:
    actions = []
    for name in MIGRATED_FILES:
        backup = memdir / (name + BACKUP_SUFFIX + stamp)
        if not backup.exists():
            continue
        shutil.copy2(backup, memdir / name)
        actions.append(f"restored {name} from {backup.name}")
    if not actions:
        raise SystemExit(f"no backups with stamp {stamp} in {memdir}")
    return actions


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--memdir", type=Path, default=None,
                    help="hunt-memory directory (default: resolved like memory.py does)")
    ap.add_argument("--apply", action="store_true", help="write (backs up first)")
    ap.add_argument("--rollback", metavar="STAMP", help="restore from a migration backup")
    args = ap.parse_args(argv)

    memdir = args.memdir or resolve_dir()
    if args.rollback:
        for line in rollback(memdir, args.rollback):
            print(line)
        return 0

    report = plan(memdir)
    print(f"hunt-memory: {memdir}")
    total_changes = 0
    for item in report["files"]:
        touched = item["fields_touched"]
        total_changes += sum(touched.values())
        detail = ", ".join(f"{k}={v}" for k, v in sorted(touched.items())) or "nothing to change"
        print(f"  {item['name']:16s} {item['rows']:6d} rows "
              f"({item['changed_rows']} to change)  sha={item['sha_before']}  {detail}")
        if item["malformed"]:
            print(f"  {'':16s} {item['malformed']} malformed line(s) preserved verbatim")

    if not args.apply:
        print(f"\nDRY RUN — {total_changes} field update(s) across "
              f"{sum(i['rows'] for i in report['files'])} rows. Re-run with --apply.")
        return 0

    stamp = _stamp()
    for line in apply(report, stamp):
        print(line)
    print("\nafter:")
    for item in report["files"]:
        if item.get("sha_after"):
            print(f"  {item['name']:16s} sha {item['sha_before']} -> {item['sha_after']}")
    print(f"\nrollback with:  python3 engine/memory_migrate.py --rollback {stamp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
