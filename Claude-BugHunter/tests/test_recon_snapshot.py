#!/usr/bin/env python3
"""Re-recon by delta, not by re-reading.

A second recon pass on a hunted target produces a manifest that is almost entirely what
you already read. The three rows that matter — a new operation, a new parameter, and above
all an operation whose declared security changed — are the ones that get skipped when
finding them means re-reading the whole file.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "scripts"))

import api_manifest as AM  # noqa: E402
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "recon_snapshot", ROOT / "scripts" / "recon-snapshot.py")
RS = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(RS)


def manifest(ops):
    return {"schema_version": "2.0", "operations": ops}


ORDER = AM.make_operation("GET", "https://api.acme.com/v1/orders/{id}", "openapi",
                          parameters=["id"], secured=True)
ORDER_UNSECURED = dict(ORDER, secured=False)
ADMIN = AM.make_operation("POST", "https://api.acme.com/internal/admin/users",
                          "openapi", fields=["role"])
BORING = AM.make_operation("GET", "https://api.acme.com/assets/logo.png", "crawl")


class Snapshots(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.dir = self.root / "recon" / "api.acme.com"
        self.dir.mkdir(parents=True)
        self.manifest = self.dir / "manifest.json"
        self._env = dict(os.environ)
        os.environ["CBH_MEMORY_DIR"] = str(self.root / "hunt-memory")
        (self.root / "hunt-memory").mkdir()
        self.addCleanup(self._restore)

    def _restore(self):
        os.environ.clear(); os.environ.update(self._env); self.tmp.cleanup()

    def _write(self, ops):
        self.manifest.write_text(json.dumps(manifest(ops)))

    def _run(self):
        return RS.process("api.acme.com", self.manifest)

    def test_first_run_stores_a_snapshot_and_queues_nothing(self):
        self._write([ORDER])
        result = self._run()
        self.assertTrue(result["first_snapshot"])
        self.assertEqual(result["queued"], 0)
        self.assertFalse((self.dir / "hunt-queue.md").exists())

    def test_a_security_change_is_the_top_queue_row(self):
        self._write([ORDER]); self._run()
        self._write([ORDER_UNSECURED])
        self._run()
        queue = (self.dir / "hunt-queue.md").read_text()
        self.assertIn("SECURITY CHANGED", queue)
        self.assertLess(queue.index("SECURITY CHANGED"), len(queue) // 2 + 200)

    def test_a_new_high_risk_operation_is_queued(self):
        self._write([ORDER]); self._run()
        self._write([ORDER, ADMIN]); self._run()
        self.assertIn("/internal/admin/users", (self.dir / "hunt-queue.md").read_text())

    def test_a_low_risk_addition_is_not_queued(self):
        self._write([ORDER]); self._run()
        self._write([ORDER, BORING])
        result = self._run()
        self.assertEqual(result["queued"], 0, "a static asset should not enter the queue")

    def test_an_unchanged_manifest_queues_nothing(self):
        self._write([ORDER]); self._run()
        self._run()
        self.assertEqual(self._run()["queued"], 0)

    def test_a_stale_queue_is_cleared_when_the_delta_goes_quiet(self):
        """Last week's queue read as today's work — that is worse than no queue."""
        self._write([ORDER]); self._run()
        self._write([ORDER, ADMIN]); self._run()
        self.assertTrue((self.dir / "hunt-queue.md").exists())
        self._run()          # nothing new this time
        self.assertFalse((self.dir / "hunt-queue.md").exists())

    def test_queued_operations_reach_the_vector_ledger(self):
        self._write([ORDER]); self._run()
        self._write([ORDER, ADMIN])
        result = self._run()
        self.assertGreater(result["vectors_added"], 0)
        import vectors as V
        eps = {v["endpoint"] for v in V.load("api.acme.com")["vectors"]}
        self.assertIn("POST /internal/admin/users", eps)

    def test_snapshots_are_capped(self):
        self._write([ORDER])
        for _ in range(RS.KEEP_SNAPSHOTS + 5):
            self._run()
        self.assertLessEqual(len(RS.snapshots(self.dir / "snapshots")), RS.KEEP_SNAPSHOTS)

    def test_discover_finds_every_target_in_an_engagement(self):
        (self.root / "recon" / "b.acme.com").mkdir()
        (self.root / "recon" / "b.acme.com" / "manifest.json").write_text(json.dumps(manifest([])))
        self._write([ORDER])
        self.assertEqual([t for t, _ in RS.discover(self.root)],
                         ["api.acme.com", "b.acme.com"])

    def test_a_new_host_is_flagged_for_a_scope_check(self):
        old = {"assets": [], "operations": []}
        new = {"assets": [{"host": "new.acme.com", "status": 200}], "operations": []}
        import recon_delta as RD
        lines = RS.queue_lines(RD.compare(old, new))
        self.assertTrue(any("scope-check" in x for x in lines),
                        "a newly discovered host must not be presented as ready to test")


if __name__ == "__main__":
    unittest.main()
