"""The CVE digest must see engagements that nest under a platform hub.

Engagements are not flat: a platform folder holds one folder per program
(`Targets/standoff365/konsol/`, `Targets/intigriti/<handle>/`). `ledgers()` walked
`TARGETS_ROOT.iterdir()` one level deep, so it found none of them and printed
"Ledger empty or every hit already triaged" while 70 standoff365 programs plus 10
intigriti ones had ledgers on disk — and the daily 07:45 snapshot was written from
that same empty read. `--mark` failed the same way: a CVE in a nested ledger came
back "not found in any ledger" unless the full `platform/program` path was passed.

This is the workspace's recurring failure shape: a discovery that resolves to nothing,
reports success, and hides a gap. `cve-boot-catchup.sh` already searched to depth 4;
this pins the digest to the same depth and pins the project NAME to the path relative
to Targets/, because that is the string `--project` has to round-trip.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]


def _load_digest(targets_root: Path):
    sys.path.insert(0, str(REPO / "engine"))
    spec = importlib.util.spec_from_file_location(
        "cve_digest_under_test", REPO / "scripts" / "cve-digest.py")
    mod = importlib.util.module_from_spec(spec)
    with mock.patch.dict("os.environ", {"CBH_TARGETS_ROOT": str(targets_root)}):
        spec.loader.exec_module(mod)
    mod.TARGETS_ROOT = targets_root
    return mod


class CveDigestNestedEngagementTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.row = {"cve_id": "CVE-2026-10819", "cvss": 6.5, "status": "new",
                    "hosts": ["chat.example.team"], "product": "Mattermost 11.8.1",
                    "description": "x", "first_seen": "2026-10-17"}

    def _write(self, rel: str):
        d = self.tmp / rel / "recon"
        d.mkdir(parents=True, exist_ok=True)
        (d / "cve-ledger.jsonl").write_text(json.dumps(self.row) + "\n", encoding="utf-8")

    def test_a_nested_engagement_ledger_is_discovered(self):
        self._write("standoff365/konsol")
        mod = _load_digest(self.tmp)
        found = dict(mod.ledgers(None))
        self.assertIn("standoff365/konsol", found,
                      "a platform/program engagement must be discovered without --project")

    def test_flat_and_deeper_layouts_both_still_work(self):
        self._write("ozon")                       # flat, the old layout
        self._write("standoff365/konsol")         # platform hub
        self._write("a/b/c")                      # one deeper
        mod = _load_digest(self.tmp)
        names = {n for n, _ in mod.ledgers(None)}
        self.assertEqual(names, {"ozon", "standoff365/konsol", "a/b/c"})

    def test_the_discovered_name_round_trips_through_project(self):
        self._write("standoff365/konsol")
        mod = _load_digest(self.tmp)
        name = dict(mod.ledgers(None))
        self.assertEqual(len(mod.ledgers("standoff365/konsol")), 1,
                         "--project must accept the exact name discovery reports")
        self.assertIn("standoff365/konsol", name)

    def test_records_carry_the_nested_project_name(self):
        self._write("standoff365/konsol")
        mod = _load_digest(self.tmp)
        recs = mod.load(None)
        self.assertEqual([r["_project"] for r in recs], ["standoff365/konsol"])


if __name__ == "__main__":
    unittest.main()
