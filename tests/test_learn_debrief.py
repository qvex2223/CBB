#!/usr/bin/env python3
"""The learning loop and the closing debrief.

Both exist so the map grows from what actually happened and the next session
opens on facts. What must hold: a find with no class is reported as novelty
rather than filed as `generic`, and a debrief writes full prose — notes.md is
read back, so compression there is a direct loss.
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import learn as LE  # noqa: E402
import session_debrief as SD  # noqa: E402


def _now():
    return datetime.now(timezone.utc).isoformat()


class LearnLoop(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.mem = Path(self.tmp.name) / "hunt-memory"
        self.mem.mkdir()
        self._env = dict(os.environ)
        self.addCleanup(self._restore)
        os.environ["CBH_MEMORY_DIR"] = str(self.mem)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)

    def _journal(self, rows):
        with open(self.mem / "journal.jsonl", "w", encoding="utf-8") as fh:
            for r in rows:
                r.setdefault("ts", _now())
                fh.write(json.dumps(r) + "\n")

    def test_novel_technique_is_reported_not_bucketed(self):
        self._journal([
            {"target": "acme", "endpoint": "/api/orders",
             "technique": "unclassified__header-supplied-identity",
             "vuln_class": "unclassified", "result": "confirmed", "notes": "X-MSISDN trusted"},
            {"target": "acme", "endpoint": "/api/users",
             "technique": "id_swap", "vuln_class": "idor", "result": "confirmed",
             "notes": "known shape"},
        ])
        result = LE.analyze(self.mem, target="acme")
        self.assertEqual(result["counts"]["novel"], 1)
        self.assertIn("unclassified__header-supplied-identity", result["novel"][0]["technique"])

    def test_empty_corpus_offers_to_feed_it(self):
        result = LE.analyze(self.mem, target="acme")
        kinds = {s["kind"] for s in result["suggestions"]}
        self.assertIn("feed-the-corpus", kinds)

    def test_strong_technique_raises_a_mutation_order_suggestion(self):
        self._journal([
            {"target": "acme", "technique": "auth_strip_on_admin",
             "vuln_class": "auth-bypass", "result": "confirmed", "notes": "x"} for _ in range(3)
        ])
        result = LE.analyze(self.mem, target="acme")
        kinds = {s["kind"] for s in result["suggestions"]}
        self.assertIn("mutation-order", kinds)

    def test_dead_technique_is_named(self):
        self._journal([
            {"target": "acme", "technique": "cors_reflect",
             "vuln_class": "cors", "result": "rejected", "notes": "x"} for _ in range(3)
        ])
        result = LE.analyze(self.mem, target="acme")
        kinds = {s["kind"] for s in result["suggestions"]}
        self.assertIn("stop-repeating", kinds)

    def test_target_filter(self):
        self._journal([
            {"target": "acme", "technique": "t1", "vuln_class": "x", "result": "confirmed"},
            {"target": "other", "technique": "t2", "vuln_class": "y", "result": "confirmed"},
        ])
        self.assertEqual(LE.analyze(self.mem, target="acme")["counts"]["journal_rows"], 1)
        self.assertEqual(LE.analyze(self.mem, target="other")["counts"]["journal_rows"], 1)
        self.assertEqual(LE.analyze(self.mem, target="")["counts"]["journal_rows"], 2)

    def test_markdown_points_at_the_map(self):
        self._journal([{"target": "acme", "technique": "unclassified__weird",
                        "vuln_class": "unclassified", "result": "confirmed"}])
        text = LE.to_markdown(LE.analyze(self.mem, target="acme"))
        self.assertIn("blind spot", text.lower())
        self.assertIn("unclassified__weird", text)


class SessionDebrief(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.mem = root / "hunt-memory"
        self.mem.mkdir()
        self.project = root / "Targets" / "acme"
        (self.project / "findings").mkdir(parents=True)
        (self.project / "hosts").mkdir()
        (self.project / "notes.md").write_text("# notes\n", encoding="utf-8")
        self._env = dict(os.environ)
        self.addCleanup(self._restore)
        os.environ["CBH_MEMORY_DIR"] = str(self.mem)

    def _restore(self):
        os.environ.clear()
        os.environ.update(self._env)

    def _write(self, name, rows):
        with open(self.mem / name, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    def test_debrief_counts_what_actually_fired(self):
        self._write("audit.jsonl", [
            {"url": "https://acme.example.com/a", "method": "GET",
             "engagement": "acme", "ts": _now(), "host": "acme.example.com"},
            {"url": "https://acme.example.com/b", "method": "POST",
             "engagement": "acme", "ts": _now(), "host": "acme.example.com"},
        ])
        self._write("journal.jsonl", [
            {"target": "acme", "endpoint": "/a", "vuln_class": "idor",
             "result": "confirmed", "notes": "shown", "ts": _now()},
            {"target": "acme", "endpoint": "/b", "vuln_class": "xss",
             "result": "rejected", "notes": "dead move", "ts": _now()},
        ])
        data = SD.collect(self.project, since_minutes=60, memdir=self.mem)
        self.assertEqual(data["counts"]["requests_fired"], 2)
        self.assertEqual(data["counts"]["findings_logged"], 1)
        self.assertEqual(data["counts"]["rejections_logged"], 1)
        self.assertIn("acme.example.com", data["hosts"])

    def test_debrief_is_full_prose(self):
        self._write("audit.jsonl", [
            {"url": "https://acme.example.com/a", "method": "GET",
             "engagement": "acme", "ts": _now()}])
        prose = SD.to_prose(SD.collect(self.project, since_minutes=60, memdir=self.mem))
        self.assertIn("Session debrief", prose)
        self.assertIn("не было", prose.lower())
        self.assertIn("запросов", prose.lower())
        # prose, not a scoreboard: real sentences, not just numbers
        self.assertGreater(len(prose.split()), 60)

    def test_debrief_lists_open_vectors_when_present(self):
        self._write("audit.jsonl", [
            {"url": "https://acme.example.com/a", "method": "GET",
             "engagement": "acme", "ts": _now()}])
        self._write("vectors.json", {
            "target": "acme",
            "vectors": [
                {"id": "idor:/a", "class": "idor", "endpoint": "/a",
                 "status": "open", "requests_fired": 0,
                 "mutations_tried": []},
                {"id": "xss:/b", "class": "xss", "endpoint": "/b",
                 "status": "dead", "requests_fired": 9, "mutations_tried": ["a"]},
            ],
        })
        # vectors.py stores under vectors/<target>.json — write both shapes so
        # the test stays honest about where the ledger lives.
        vdir = self.mem / "vectors"
        vdir.mkdir()
        (vdir / "acme.json").write_text(json.dumps({
            "target": "acme",
            "vectors": [
                {"id": "idor:/a", "class": "idor", "endpoint": "/a",
                 "status": "open", "requests_fired": 0, "mutations_tried": []},
                {"id": "xss:/b", "class": "xss", "endpoint": "/b",
                 "status": "dead", "requests_fired": 9, "mutations_tried": ["a"]},
            ],
        }), encoding="utf-8")
        data = SD.collect(self.project, since_minutes=60, memdir=self.mem)
        self.assertEqual(data["counts"]["open_vectors"], 1)
        self.assertEqual(data["open_vectors"][0]["id"], "idor:/a")
        self.assertIsNotNone(data["open_vectors"][0]["next_mutation"])

    def test_debrief_appends_to_notes(self):
        self._write("audit.jsonl", [
            {"url": "https://acme.example.com/a", "method": "GET",
             "engagement": "acme", "ts": _now()}])
        rc = SD.main(["--project", str(self.project), "--since-minutes", "60",
                      "--dir", str(self.mem)])
        self.assertEqual(rc, 0)
        text = (self.project / "notes.md").read_text(encoding="utf-8")
        self.assertIn("Session debrief", text)

    def test_debrief_print_does_not_write(self):
        self._write("audit.jsonl", [
            {"url": "https://acme.example.com/a", "method": "GET",
             "engagement": "acme", "ts": _now()}])
        rc = SD.main(["--project", str(self.project), "--since-minutes", "60",
                      "--dir", str(self.mem), "--print"])
        self.assertEqual(rc, 0)
        self.assertEqual((self.project / "notes.md").read_text(encoding="utf-8"),
                         "# notes\n")


if __name__ == "__main__":
    unittest.main()
