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
            # Operator directive 2026-11-14: a row waits on the operator only when the file
            # DECLARES one of `cbh autonomy`'s reasons. "needs programme approval" no longer
            # is one, so `open.md` declares `availability` to stay a block, and `approval.md`
            # keeps the old wording to prove it unparks.
            (d / "blocked-tests" / "open.md").write_text(
                "# BLOCKED — the operator must decide\n\n**Park:** availability\n")
            (d / "blocked-tests" / "approval.md").write_text("# BLOCKED — needs programme approval\n")
            (d / "blocked-tests" / "done.md").write_text("# ANSWERED — needs programme approval\n")
            (d / "blocked-tests" / "ai.md").write_text("# Blocked: program prohibits AI agents\noperator\n")
            (d / "blocked-tests" / "tech.md").write_text("# BLOCKED — needs a websocket step\n")
            reports = oq.ready_reports(Path(t))
            self.assertEqual([r["title"] for r in reports], ["X"])
            self.assertEqual(reports[0]["severity"], "high")
            blocks = oq.operator_blocks(Path(t))
            self.assertEqual([Path(b["file"]).name for b in blocks], ["open.md"])
            unparked = [Path(u["file"]).name for u in oq.operator_unparked(Path(t))]
            self.assertIn("approval.md", unparked)
            self.assertIn("tech.md", unparked)
            self.assertNotIn("open.md", unparked)
            self.assertNotIn("done.md", unparked)   # already answered
            self.assertNotIn("ai.md", unparked)     # programme prohibits AI agents
            (d / "submissions.txt").write_text("# h\n2026 | a.example | x | high | submitted | —\n")
            self.assertEqual(oq.ready_reports(Path(t)), [])

class UnparkedSection(unittest.TestCase):
    """Operator directive 2026-11-14: nothing waits on the operator without a declaration."""

    def _eng(self, root, name):
        d = Path(root) / "plat" / name
        for sub in ("findings", "blocked-tests"):
            (d / sub).mkdir(parents=True)
        (d / "scope.md").write_text("## In scope\n- `a.example`\n")
        return d

    def test_the_old_block_wordings_all_unpark(self):
        with tempfile.TemporaryDirectory() as t:
            d = self._eng(t, "p")
            for i, body in enumerate((
                    "# BLOCKED — needs programme approval\n",
                    "# BLOCKED — needs a buyer account nobody holds\n",
                    "# BLOCKED — needs a POST; writes are forbidden\n",
                    "# BLOCKED — bbcurl cannot reach the product\n",
                    "# OPERATOR DECISION — waiting on the operator\n")):
                (d / "blocked-tests" / f"b{i}.md").write_text(body)
            self.assertEqual(oq.operator_blocks(Path(t)), [])
            self.assertEqual(oq.operator_decisions(Path(t)), [])
            self.assertEqual(len(oq.operator_unparked(Path(t))), 5)

    def test_the_render_lists_them_so_nothing_is_silently_dropped(self):
        with tempfile.TemporaryDirectory() as t:
            d = self._eng(t, "p")
            (d / "blocked-tests" / "b.md").write_text("# BLOCKED — needs programme approval\n")
            out = oq.render([], [], (), (), oq.operator_unparked(Path(t)))
            self.assertIn("## 4. Unparked", out)
            self.assertIn("b.md", out)


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
                "Needs the operator to approve one request.\n\n**Park:** availability\n")
            (bt / "OPERATOR-DECISION-esia.md").write_text(
                "# OPERATOR DECISION — one POST would decide the chain\noperator approval\n"
                "\n**Park:** other-user-data\n")
            (bt / "plain.md").write_text(
                "# BLOCKED — needs programme approval\n\n**Park:** human-inbox\n")
            # Same file without a declaration: a decision no longer, since 2026-11-14.
            (bt / "OPERATOR-DECISION-undeclared.md").write_text(
                "# OPERATOR DECISION — one POST would decide the chain\noperator approval\n")
            decisions = oq.operator_decisions(Path(t))
            self.assertEqual([Path(x["file"]).name for x in decisions],
                             ["OPERATOR-DECISION-rce.md", "OPERATOR-DECISION-esia.md"])
            self.assertEqual(decisions[0]["severity"], "critical")
            self.assertEqual([Path(b["file"]).name for b in oq.operator_blocks(Path(t))],
                             ["plain.md"])
            self.assertEqual([Path(u["file"]).name for u in oq.operator_unparked(Path(t))],
                             ["OPERATOR-DECISION-undeclared.md"])

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
            f.write_text("# OPERATOR DECISION — z\n\nMoves money for other users.\n"
                         "\n**Park:** availability\n")
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
                "Needs the operator.\n\n**Park:** availability\n")
            line = oq.brief_line(root=Path(t))
            self.assertIn("DECISION WAITING", line)
            self.assertIn("critical", line.lower())
            self.assertIn("OPERATOR-DECISION-rce.md", line)


if __name__ == "__main__":
    unittest.main()
