"""cbh adoption (2026-11-17): did a registered vector class actually get used?

The three questions the module exists to answer, and the trap under each:
  * is the class registered at all — and is it ROUTABLE (in lead_queue.known_classes()),
    because an unroutable name makes `**Class:** <name>` silently dropped;
  * was it fired — read from audit.jsonl, NEVER from the ledger's own status, since a
    ledger marked `untried` is a record of what someone wrote, not of what was sent;
  * did anything close — a class that fires and closes nothing has no oracle.
"""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine"))
import adoption as AD  # noqa: E402
import lead_queue as LQ  # noqa: E402


def _mem(tmp, ledgers, audit_urls_per_row):
    """A fake hunt-memory: one ledger per host, one audit row per url list."""
    mem = Path(tmp) / "hunt-memory"
    (mem / "vectors").mkdir(parents=True)
    for host, vecs in ledgers.items():
        (mem / "vectors" / f"{host}.json").write_text(
            json.dumps({"target": host, "vectors": vecs}), encoding="utf-8")
    rows = []
    for urls in audit_urls_per_row:
        rows.append(json.dumps({"source": "bbcurl", "engagement": "p/prog", "urls": urls,
                                "http_code": 200, "timestamp": "2026-11-16T00:00:00+00:00"}))
    (mem / "audit.jsonl").write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
    return mem


def _corpus(tmp, files):
    root = Path(tmp) / "Targets"
    e = root / "p" / "prog"
    for tier in ("findings", "leads", "primitives"):
        (e / tier).mkdir(parents=True, exist_ok=True)
    (e / "scope.md").write_text("x")
    for rel, text in files.items():
        (e / rel).write_text(text, encoding="utf-8")
    return root


class Registration(unittest.TestCase):
    def test_unregistered_class_is_flagged_and_unroutable(self):
        """A ledger class in no table can be seeded yet route nowhere.

        This is not hypothetical: `business_logic` and `open_redirect` (underscored) carried
        19 real vectors on 2026-11-17 while being absent from every table.
        """
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, {"h1.example": [
                {"id": "x", "class": "made_up_class", "endpoint": "/a",
                 "status": "untried", "requests_fired": 0}]}, [])
            root = _corpus(t, {})
            with mock.patch.object(LQ, "_targets_root", lambda: root), \
                 mock.patch.object(AD.vectors, "resolve_dir", lambda *a, **k: mem):
                rs = AD.rows()
            row = next(r for r in rs if r["class"] == "made_up_class")
            self.assertEqual([], row["tables"])
            self.assertFalse(row["routable"])
            self.assertIn("registered 0", " ".join(AD.flags(row)))

    def test_registered_class_with_no_ledger_is_seeded_zero(self):
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, {}, [])
            root = _corpus(t, {})
            with mock.patch.object(LQ, "_targets_root", lambda: root), \
                 mock.patch.object(AD.vectors, "resolve_dir", lambda *a, **k: mem):
                rs = AD.rows()
            row = next(r for r in rs if r["class"] == "idor")
            self.assertIn("catalog", row["tables"])
            self.assertTrue(row["routable"])
            self.assertEqual(0, row["seeded"])
            self.assertIn("seeded 0", " ".join(AD.flags(row)))


class Firing(unittest.TestCase):
    def test_untried_ledger_with_a_real_audit_row_still_counts_as_fired(self):
        """The whole point: `untried` is a marking, not evidence nothing was sent."""
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, {"h1.example": [
                {"id": "idor:/a", "class": "idor", "endpoint": "/a",
                 "status": "untried", "requests_fired": 0}]},
                [["https://h1.example/a"], ["https://h1.example/a?x=1"]])
            root = _corpus(t, {})
            with mock.patch.object(LQ, "_targets_root", lambda: root), \
                 mock.patch.object(AD.vectors, "resolve_dir", lambda *a, **k: mem):
                rs = AD.rows()
            row = next(r for r in rs if r["class"] == "idor")
            self.assertEqual(1, row["seeded"])
            self.assertEqual(1, row["offered"])
            self.assertEqual(0, row["ledger_fired"])
            self.assertEqual(2, row["host_req"])
            # It was fired, so it must NOT be reported as offered-but-never-fired.
            self.assertNotIn("never fired", " ".join(AD.flags(row)))

    def test_offered_and_never_fired_is_flagged(self):
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, {"quiet.example": [
                {"id": "idor:/a", "class": "idor", "endpoint": "/a",
                 "status": "untried", "requests_fired": 0}]}, [])
            root = _corpus(t, {})
            with mock.patch.object(LQ, "_targets_root", lambda: root), \
                 mock.patch.object(AD.vectors, "resolve_dir", lambda *a, **k: mem):
                rs = AD.rows()
            row = next(r for r in rs if r["class"] == "idor")
            self.assertIn("never fired", " ".join(AD.flags(row)))

    def test_ledger_claim_with_no_audit_row_is_flagged_not_asserted(self):
        """`LEDGER?` names rotation as a cause: the log rotates, so the claim may be honest."""
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, {"old.example": [
                {"id": "idor:/a", "class": "idor", "endpoint": "/a",
                 "status": "dead", "requests_fired": 79}]}, [])
            root = _corpus(t, {})
            with mock.patch.object(LQ, "_targets_root", lambda: root), \
                 mock.patch.object(AD.vectors, "resolve_dir", lambda *a, **k: mem):
                rs = AD.rows()
            row = next(r for r in rs if r["class"] == "idor")
            msg = " ".join(AD.flags(row))
            self.assertIn("LEDGER?", msg)
            self.assertIn("rotation", msg)

    def test_host_req_alone_never_claims_a_missing_funnel_item(self):
        """`host-req` counts every request to a host, so it must not drive that flag.

        Without this, any class seeded on a busy host read as "fired with no funnel item".
        """
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, {"busy.example": [
                {"id": "ssti:/a", "class": "ssti", "endpoint": "/a",
                 "status": "dead", "requests_fired": 0}]},
                [["https://busy.example/unrelated"]] * 50)
            root = _corpus(t, {})
            with mock.patch.object(LQ, "_targets_root", lambda: root), \
                 mock.patch.object(AD.vectors, "resolve_dir", lambda *a, **k: mem):
                rs = AD.rows()
            row = next(r for r in rs if r["class"] == "ssti")
            self.assertEqual(50, row["host_req"])
            self.assertNotIn("no funnel item", " ".join(AD.flags(row)))


class Funnel(unittest.TestCase):
    def test_declared_class_counts_open_and_closed_separately(self):
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, {}, [])
            root = _corpus(t, {
                "leads/a-lead.md": "# Open one\n\n**Class:** `idor`\n**Status:** lead\n",
                "leads/b-lead.md": "# Done one\n\n**Class:** `idor`\n**Status:** REFUTED (2026-11-01)\n",
            })
            with mock.patch.object(LQ, "_targets_root", lambda: root), \
                 mock.patch.object(AD.vectors, "resolve_dir", lambda *a, **k: mem):
                rs = AD.rows()
            row = next(r for r in rs if r["class"] == "idor")
            self.assertEqual(1, row["open"])
            self.assertEqual(1, row["closed"])
            self.assertEqual(1, row["refuted"])

    def test_folder_form_item_is_not_counted_as_readme(self):
        """`funnel.item_name`, never `Path.stem`, or a folder-form item is named README."""
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, {}, [])
            root = _corpus(t, {})
            d = root / "p" / "prog" / "findings" / "sqli-on-search"
            d.mkdir(parents=True)
            (d / "README.md").write_text("# Folder form\n\n**Class:** `sqli`\n**Status:** finding\n")
            with mock.patch.object(LQ, "_targets_root", lambda: root), \
                 mock.patch.object(AD.vectors, "resolve_dir", lambda *a, **k: mem):
                rs = AD.rows()
            self.assertEqual(1, next(r for r in rs if r["class"] == "sqli")["open"])
            self.assertFalse(any(r["class"] == "readme" for r in rs))


class Render(unittest.TestCase):
    def test_lint_exits_nonzero_when_something_is_wrong(self):
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, {"h.example": [
                {"id": "x", "class": "made_up_class", "endpoint": "/a",
                 "status": "untried", "requests_fired": 0}]}, [])
            root = _corpus(t, {})
            with mock.patch.object(LQ, "_targets_root", lambda: root), \
                 mock.patch.object(AD.vectors, "resolve_dir", lambda *a, **k: mem), \
                 redirect_stdout(io.StringIO()) as buf:
                rc = AD.main(["--lint"])
            self.assertEqual(1, rc)
            # Captured, not printed: the module writes its whole table, and unredirected it
            # buried the suite's own verdict line in a `tail` of the test output.
            self.assertIn("made_up_class", buf.getvalue())

    def test_footer_states_the_retained_audit_window(self):
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, {}, [["https://h.example/a"]])
            root = _corpus(t, {})
            with mock.patch.object(LQ, "_targets_root", lambda: root), \
                 mock.patch.object(AD.vectors, "resolve_dir", lambda *a, **k: mem):
                text = AD.render(AD.rows(), False)
            self.assertIn("retained audit window: 2026-11-16", text)


if __name__ == "__main__":
    unittest.main()
