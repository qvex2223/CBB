#!/usr/bin/env python3
"""End-to-end mock flow: recon -> manifest -> workflow -> vectors -> rank -> map ->
hunt -> validate -> report, plus resume.

The new API-model modules were each unit-tested in isolation, which is exactly how
a pipeline breaks silently: every part works and the signatures between them do
not. This walks the whole chain on mock data with no network.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import vectors as V  # noqa: E402


class EngineMockFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.memdir = self.root / "hunt-memory"
        self.memdir.mkdir()
        self._env = dict(os.environ)
        os.environ["CBH_MEMORY_DIR"] = str(self.memdir)
        self.scope_file = self.root / "engagement.json"
        self.scope_file.write_text(json.dumps({
            "name": "e2e-local", "in_scope": ["localhost", "127.0.0.1"],
            "out_of_scope": ["admin.localhost"], "seeds": ["http://localhost:3002"]}))
        self.addCleanup(self._restore)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)
        self.tmp.cleanup()

    def _engine(self, phases):
        import engine as E
        with contextlib.redirect_stdout(io.StringIO()):
            eng = E.Engine(str(self.scope_file), str(self.root / "runs"), model="mock",
                           max_hunts=5, max_turns=3, timeout=10, mock=True)
            eng.run(phases)
        return eng

    def test_full_mock_flow_produces_every_artifact(self):
        eng = self._engine(["recon", "rank", "map", "hunt", "validate", "report"])
        d = Path(eng.eng.dir)
        for name in ("state.json", "arsenal.md", "report.md",
                     "api-manifest.json", "workflow.json"):
            self.assertTrue((d / name).is_file(), f"{name} was not written")
        state = json.loads((d / "state.json").read_text())
        self.assertEqual(state["phase"], "done")
        self.assertTrue(state["surface"], "recon produced no surface")
        self.assertTrue(any(s.get("priority") for s in state["surface"]),
                        "rank never assigned a priority")

    def test_recon_only_then_resume_later_phases(self):
        first = self._engine(["recon", "rank"])
        d = Path(first.eng.dir)
        surface = json.loads((d / "state.json").read_text())["surface"]
        second = self._engine(["map", "hunt", "validate", "report"])
        self.assertEqual(Path(second.eng.dir), d, "resume started a second engagement dir")
        state = json.loads((d / "state.json").read_text())
        self.assertEqual(len(state["surface"]), len(surface),
                         "resume re-ran recon and duplicated the surface")
        self.assertTrue((d / "report.md").is_file())

    def test_scope_is_enforced_on_recon_output(self):
        eng = self._engine(["recon"])
        state = json.loads((Path(eng.eng.dir) / "state.json").read_text())
        for item in state["surface"]:
            self.assertTrue(eng.scope.in_scope_host(item["url"]),
                            f"out-of-scope item survived recon: {item['url']}")

    def test_manifest_feeds_vector_seeding(self):
        """The handoff's point: the manifest must be usable as the vector source."""
        eng = self._engine(["recon"])
        d = Path(eng.eng.dir)
        manifest = json.loads((d / "api-manifest.json").read_text())
        workflow = json.loads((d / "workflow.json").read_text())
        self.assertTrue(manifest["operations"], "manifest has no operations")
        ledger = V.seed_from_manifest("localhost", manifest, workflow)
        V.save(ledger)
        self.assertTrue(ledger["vectors"], "manifest seeded no vectors")
        # every seeded vector must carry the hint that justified it
        for vec in ledger["vectors"]:
            self.assertEqual(vec["origin"], "manifest")
            self.assertTrue(vec["reason"], f"{vec['id']} has no justification")
        self.assertTrue(V.next_vectors("localhost", 3), "next returned nothing after seeding")


class ManifestSeeding(unittest.TestCase):
    """Seeding must be evidence-driven, not the old (endpoint x every class) product."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.memdir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _manifest(self):
        sys.path.insert(0, str(ROOT / "engine"))
        import api_manifest as AM
        ops = [
            AM.make_operation("GET", "https://api.acme.com/v1/orders/{id}", "openapi",
                              parameters=["id"]),
            AM.make_operation("POST", "https://api.acme.com/v1/orders/{id}/refund", "openapi",
                              fields=["amount", "status"]),
            AM.make_operation("GET", "https://api.acme.com/assets/logo.png", "crawl"),
        ]
        return {"schema_version": AM.SCHEMA_VERSION, "operations": ops}

    def test_seeding_is_narrower_than_the_cartesian_product(self):
        m = self._manifest()
        ledger = V.seed_from_manifest("acme", m, memdir=self.memdir)
        cartesian = len(m["operations"]) * len(V.CATALOG)
        self.assertLess(len(ledger["vectors"]), cartesian,
                        "manifest seeding produced the full Cartesian product")

    def test_risk_hints_pick_the_class(self):
        ledger = V.seed_from_manifest("acme", self._manifest(), memdir=self.memdir)
        by_ep = {}
        for v in ledger["vectors"]:
            by_ep.setdefault(v["endpoint"], set()).add(v["class"])
        self.assertIn("idor", by_ep["GET /v1/orders/{id}"])
        self.assertIn("business-logic", by_ep["POST /v1/orders/{id}/refund"])
        self.assertIn("api-misconfig", by_ep["POST /v1/orders/{id}/refund"],
                      "sensitive schema fields did not produce a mass-assignment vector")
        self.assertNotIn("rce", by_ep.get("GET /assets/logo.png", set()),
                         "a static asset should not be seeded with RCE")

    def test_workflow_hypotheses_raise_priority_and_carry_the_test(self):
        import workflow_graph as WG
        m = self._manifest()
        wf = WG.build(m)
        ledger = V.seed_from_manifest("acme", m, wf, memdir=self.memdir)
        refund = [v for v in ledger["vectors"]
                  if v["endpoint"] == "POST /v1/orders/{id}/refund"]
        self.assertTrue(any(v["class"] == "race-condition" for v in refund),
                        "refund did not get the race hypothesis")
        notes = " ".join(v.get("notes", "") for v in refund)
        self.assertIn("workflow:", notes, "hypothesis test text was not carried over")

    def test_seeding_twice_is_idempotent(self):
        m = self._manifest()
        V.save(V.seed_from_manifest("acme", m, memdir=self.memdir), memdir=self.memdir)
        first = len(V.load("acme", self.memdir)["vectors"])
        V.save(V.seed_from_manifest("acme", m, memdir=self.memdir), memdir=self.memdir)
        self.assertEqual(len(V.load("acme", self.memdir)["vectors"]), first)

    def test_seeding_never_resets_existing_progress(self):
        m = self._manifest()
        V.save(V.seed_from_manifest("acme", m, memdir=self.memdir), memdir=self.memdir)
        vid = V.vector_id("idor", "GET /v1/orders/{id}")
        V.mark("acme", vid, "active", mutation="method swap", requests=4, memdir=self.memdir)
        V.save(V.seed_from_manifest("acme", m, memdir=self.memdir), memdir=self.memdir)
        vec = next(v for v in V.load("acme", self.memdir)["vectors"] if v["id"] == vid)
        self.assertEqual(vec["status"], "active")
        self.assertEqual(vec["requests_fired"], 4)
        self.assertEqual(vec["mutations_tried"], ["method swap"])


class LedgerPrune(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.memdir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        V.save(V.seed("acme", ["/a", "/b"], memdir=self.memdir), memdir=self.memdir)

    def test_dry_run_writes_nothing(self):
        before = V._path("acme", self.memdir).read_text()
        rep = V.prune("acme", apply=False, memdir=self.memdir)
        self.assertGreater(rep["prunable"], 0)
        self.assertFalse(rep["applied"])
        self.assertEqual(V._path("acme", self.memdir).read_text(), before)

    def test_touched_rows_are_never_pruned(self):
        vid = V.vector_id("idor", "/a")
        V.mark("acme", vid, "active", requests=2, memdir=self.memdir)
        V.prune("acme", apply=True, memdir=self.memdir)
        remaining = [v["id"] for v in V.load("acme", self.memdir)["vectors"]]
        self.assertEqual(remaining, [vid])

    def test_a_note_alone_protects_a_row(self):
        vid = V.vector_id("ssrf", "/b")
        V.mark("acme", vid, "untried", note="param only reachable after login",
               memdir=self.memdir)
        V.prune("acme", apply=True, memdir=self.memdir)
        self.assertIn(vid, [v["id"] for v in V.load("acme", self.memdir)["vectors"]])

    def test_apply_backs_up_first(self):
        rep = V.prune("acme", apply=True, memdir=self.memdir)
        self.assertTrue(rep["backup"], "prune wrote without a backup")
        self.assertTrue(Path(rep["backup"]).is_file())

    def test_manifest_rows_are_never_pruned(self):
        import api_manifest as AM
        m = {"operations": [AM.make_operation("GET", "https://acme.com/a", "openapi",
                                              parameters=["id"])]}
        V.save(V.seed_from_manifest("acme", m, memdir=self.memdir), memdir=self.memdir)
        V.prune("acme", apply=True, memdir=self.memdir)
        kept = V.load("acme", self.memdir)["vectors"]
        self.assertTrue(kept, "prune removed manifest-derived vectors")
        self.assertTrue(all(v["origin"] == "manifest" for v in kept))


if __name__ == "__main__":
    unittest.main()
