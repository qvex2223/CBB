import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
from stop_gate import severity_of  # noqa: E402
import operator_queue as oq  # noqa: E402


class SeverityParenthetical(unittest.TestCase):
    def test_claimed_parenthetical_is_read(self):
        # konsol finding, 2026-10-20: this line read as "unrated", so the stop gate
        # never counted a passing Medium.
        self.assertEqual(severity_of("- **Severity (claimed):** **Medium.** See below"), "medium")
        self.assertEqual(severity_of("- **Severity (proposed):** Low"), "low")

    def test_plain_forms_unchanged(self):
        self.assertEqual(severity_of("Severity: High"), "high")
        self.assertEqual(severity_of("Критичность: В"), "high")
        self.assertIsNone(severity_of("## Severity honesty"))


class Queue(unittest.TestCase):
    def _eng(self, root, name, scope_extra=""):
        d = Path(root) / "plat" / name
        for sub in ("findings", "blocked-tests"):
            (d / sub).mkdir(parents=True)
        (d / "scope.md").write_text("## In scope\n- `a.example`\n\n## Reward model (RUB)\n"
                                    "| critical | 0 | 500 000 |\n"
                                    "Platform stats: paid 99 999 999 ₽\n" + scope_extra)
        return d

    def test_payout_ignores_platform_stats(self):
        with tempfile.TemporaryDirectory() as t:
            d = self._eng(t, "p")
            self.assertEqual(oq._max_payout(d), 500000)

    def test_submitted_findings_and_closed_blocks_drop_out(self):
        with tempfile.TemporaryDirectory() as t:
            d = self._eng(t, "p")
            (d / "findings" / "x-a.example.md").write_text("# X\nSeverity: High\n")
            (d / "findings" / "SUBMIT-x.md").write_text("# draft\n")
            (d / "blocked-tests" / "open.md").write_text("# BLOCKED — needs programme approval\n")
            (d / "blocked-tests" / "done.md").write_text("# ANSWERED — needs programme approval\n")
            (d / "blocked-tests" / "ai.md").write_text("# Blocked: program prohibits AI agents\noperator\n")
            (d / "blocked-tests" / "tech.md").write_text("# BLOCKED — needs a websocket step\n")
            reports = oq.ready_reports(Path(t))
            self.assertEqual([r["title"] for r in reports], ["X"])
            self.assertEqual(reports[0]["severity"], "high")
            blocks = oq.operator_blocks(Path(t))
            self.assertEqual([Path(b["file"]).name for b in blocks], ["open.md"])
            (d / "submissions.txt").write_text("# h\n2026 | a.example | x | high | submitted | —\n")
            self.assertEqual(oq.ready_reports(Path(t)), [])

class OwnSeverity(unittest.TestCase):
    """2026-11-11: six decisions rendered `unrated`, so severity-first ranking was inert."""

    def test_score_straight_after_the_word_is_a_score_not_a_version(self):
        # The wildberries sharp RCE file says "(**SVG**, CVSS 9.5, affected ...)". The
        # version heuristic read 9.5 as the spec version and left no score.
        self.assertEqual(severity_of("GHSA-2464-fhr4-w9xw (**SVG**, CVSS 9.5, affected"), "critical")
        self.assertEqual(severity_of("CVSS v4.0 score 8.1"), "high")

    def test_known_spec_version_is_still_dropped(self):
        self.assertEqual(severity_of("CVSS 3.1 `AV:N/AC:L` = **8.2**"), "high")
        self.assertEqual(severity_of("CVSS 3.1: `AV:N` = **5.3**"), "medium")

    def test_a_heading_claim_counts(self):
        self.assertEqual(
            oq._own_severity("# OPERATOR DECISION — an unauthenticated Critical RCE on a "
                             "trusted origin now has ALL THREE preconditions measured\n"), "critical")

    def test_body_prose_does_not_set_a_severity(self):
        self.assertEqual(oq._own_severity("# A decision\n\nIt creates state. Low-consequence "
                                          "as far as I can tell, on the critical path.\n"), "unrated")

    def test_the_label_still_wins_over_a_weaker_heading(self):
        self.assertEqual(oq._own_severity("# A Low thing\n\nSeverity: High\n"), "high")


class Decisions(unittest.TestCase):
    def _eng(self, root, name):
        d = Path(root) / "plat" / name
        for sub in ("findings", "blocked-tests"):
            (d / sub).mkdir(parents=True)
        (d / "scope.md").write_text("## In scope\n- `a.example`\n\n## Reward model (RUB)\n"
                                    "| critical | 0 | 500 000 |\n")
        return d

    def test_a_decision_leaves_the_block_list_and_ranks_by_its_own_severity(self):
        with tempfile.TemporaryDirectory() as t:
            d = self._eng(t, "p")
            bt = d / "blocked-tests"
            (bt / "OPERATOR-DECISION-rce.md").write_text(
                "# OPERATOR DECISION — an unauthenticated Critical RCE, nothing sent\n"
                "Needs the operator to approve one request.\n")
            (bt / "OPERATOR-DECISION-esia.md").write_text(
                "# OPERATOR DECISION — one POST would decide the chain\noperator approval\n")
            (bt / "plain.md").write_text("# BLOCKED — needs programme approval\n")
            decisions = oq.operator_decisions(Path(t))
            self.assertEqual([Path(x["file"]).name for x in decisions],
                             ["OPERATOR-DECISION-rce.md", "OPERATOR-DECISION-esia.md"])
            self.assertEqual(decisions[0]["severity"], "critical")
            self.assertEqual([Path(b["file"]).name for b in oq.operator_blocks(Path(t))],
                             ["plain.md"])

    def test_a_mixed_case_unblocked_header_drops_out(self):
        with tempfile.TemporaryDirectory() as t:
            d = self._eng(t, "p")
            (d / "blocked-tests" / "OPERATOR-DECISION-x.md").write_text(
                "# OPERATOR DECISION — x\n\nUnblocked 2026-11-11 — drove as "
                "`leads/y.md` (closed-exhausted). Needs the operator.\n")
            self.assertEqual(oq.operator_decisions(Path(t)), [])

    def test_a_closure_banner_at_the_end_of_the_file_drops_out(self):
        with tempfile.TemporaryDirectory() as t:
            d = self._eng(t, "p")
            (d / "blocked-tests" / "OPERATOR-DECISION-y.md").write_text(
                "# OPERATOR DECISION — y\n\nNeeds programme approval.\n" + ("filler\n" * 30)
                + "\n## Status — **CLOSED**\nRefused by the operator.\n")
            self.assertEqual(oq.operator_decisions(Path(t)), [])

    def test_resolve_writes_the_verdict_and_the_item_leaves_the_queue(self):
        with tempfile.TemporaryDirectory() as t:
            d = self._eng(t, "p")
            f = d / "blocked-tests" / "OPERATOR-DECISION-z.md"
            f.write_text("# OPERATOR DECISION — z\n\nNeeds the operator to approve a POST.\n")
            self.assertEqual(len(oq.operator_decisions(Path(t))), 1)
            self.assertEqual(oq.resolve(f, "refused", "moves money"), 0)
            self.assertIn("REFUSED BY OPERATOR", f.read_text())
            self.assertIn("moves money", f.read_text())
            self.assertEqual(oq.operator_decisions(Path(t)), [])

    def test_the_brief_line_names_the_top_decision(self):
        with tempfile.TemporaryDirectory() as t:
            d = self._eng(t, "p")
            (d / "blocked-tests" / "OPERATOR-DECISION-rce.md").write_text(
                "# OPERATOR DECISION — an unauthenticated Critical RCE, nothing sent\n"
                "Needs the operator.\n")
            line = oq.brief_line(root=Path(t))
            self.assertIn("DECISION WAITING", line)
            self.assertIn("critical", line.lower())
            self.assertIn("OPERATOR-DECISION-rce.md", line)


if __name__ == "__main__":
    unittest.main()
