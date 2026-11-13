import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import chain_graph as cg  # noqa: E402


def _w(root, rel, chain):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"# {p.stem}\n\n**Chain:** {chain}\n")


class Graph(unittest.TestCase):
    def test_hub_ranks_first_and_transitive_reach_counts(self):
        with tempfile.TemporaryDirectory() as t:
            _w(t, "primitives/cors-a.md", "needs `origin` · gives `read-a`")
            _w(t, "primitives/cors-b.md", "needs `origin` · gives `read-b`")
            _w(t, "primitives/ns.md", "needs `approval` · gives `origin`")
            _w(t, "leads/other.md", "needs `token`")
            res = cg.analyse(cg.load(Path(t)))
            top = res["missing"][0]
            self.assertEqual(top["cap"], "approval")
            self.assertEqual(len(top["reach"]), 3)
            origin = [m for m in res["missing"] if m["cap"] == "origin"][0]
            self.assertEqual(origin["suppliers"], ["primitives/ns.md"])

    def test_met_needs_become_have(self):
        with tempfile.TemporaryDirectory() as t:
            _w(t, "findings/xss.md", "gives `origin`")
            _w(t, "primitives/cors.md", "needs `origin` · gives `read`")
            res = cg.analyse(cg.load(Path(t)))
            self.assertEqual(res["missing"], [])
            self.assertEqual(res["have"], ["origin", "read"])

    def test_operator_caps_are_named_as_operator_actions(self):
        self.assertIn("operator action", cg._no_supplier("programme-approval-x"))
        self.assertIn("next hunt", cg._no_supplier("xss-on-subdomain"))


if __name__ == "__main__":
    unittest.main()


class NoNeedSpellings(unittest.TestCase):
    """`needs `nothing`` is this workspace's convention for a closed item. It was being counted
    as a capability nobody supplies: on yukki-lk the literal `nothing` ranked third in the hub,
    "unblocking" three closed leads and pushing real blockers down the list."""

    def test_nothing_does_not_become_a_missing_capability(self):
        needs, gives = cg._parse("needs `nothing` · gives `a-closed-answer`")
        self.assertEqual(needs, [])
        self.assertEqual(gives, ["a-closed-answer"])

    def test_other_no_need_spellings_also_parse_empty(self):
        for spelling in ("none", "nothing-further", "nothing-we-do-not-have", "n-a"):
            needs, _ = cg._parse("needs `%s` · gives `x`" % spelling)
            self.assertEqual(needs, [], spelling)

    def test_a_real_capability_is_still_counted(self):
        needs, _ = cg._parse("needs `a-gosuslugi-esia-account-we-control` · gives `y`")
        self.assertEqual(needs, ["a-gosuslugi-esia-account-we-control"])
