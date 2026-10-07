#!/usr/bin/env python3
"""Documentation must not drift from the tree.

Every number in this repo's docs was hand-written and every one of them went stale:
54 vs 62 skills, 14 vs 17 commands, Burp MCP on 9876 vs 8181, Python 3.9 vs the
3.10 the code's `X | None` annotations actually require. A count nobody can
regenerate goes wrong again, so the generator is the source of truth and this test
is what notices.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

GEN = ROOT / "scripts" / "gen_inventory.py"


def _load_gen():
    import importlib.util
    spec = importlib.util.spec_from_file_location("gen_inventory", GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class DocsConsistency(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gen = _load_gen()
        cls.inv = cls.gen.inventory()

    def test_no_doc_contradicts_the_tree(self):
        problems = self.gen.check(self.inv)
        self.assertEqual(problems, [], "stale documentation:\n  " + "\n  ".join(problems))

    def test_inventory_json_is_current(self):
        path = ROOT / "docs" / "inventory.json"
        self.assertTrue(path.is_file(), "run: python3 scripts/gen_inventory.py --write")
        stored = json.loads(path.read_text())
        for key in ("skills", "commands", "burp_mcp_port", "manifest_schema_version",
                    "requires_python"):
            self.assertEqual(stored[key], self.inv[key],
                             f"docs/inventory.json is stale on {key} — re-run "
                             f"`python3 scripts/gen_inventory.py --write`")

    def test_check_mode_exits_nonzero_when_something_is_stale(self):
        """The test above is only worth anything if --check can actually fail."""
        problems = self.gen.check({**self.inv, "skills": self.inv["skills"] + 1})
        self.assertTrue(problems, "--check cannot detect a wrong skill count")

    def test_cli_check_runs_clean(self):
        r = subprocess.run([sys.executable, "-B", str(GEN), "--check"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_every_command_file_is_a_real_command(self):
        for name in self.inv["command_names"]:
            body = (ROOT / "commands" / f"{name}.md").read_text(encoding="utf-8")
            self.assertTrue(body.strip(), f"commands/{name}.md is empty")

    def test_packaging_floor_matches_the_syntax_the_code_uses(self):
        """`X | None` in annotations is 3.10+. Claiming 3.9 installs a broken tool."""
        pyproject = (ROOT / "pyproject.toml").read_text()
        self.assertIn('requires-python = ">=3.10"', pyproject)

    def test_hunt_skill_subcount_is_generated_not_guessed(self):
        """docs/architecture.md states a hunt-* sub-count; it must match the tree."""
        doc = (ROOT / "docs" / "architecture.md").read_text(encoding="utf-8")
        self.assertIn(f"{self.inv['hunt_skills']}-skill `hunt-*` sub-stack", doc)

    def test_every_cbh_subcommand_in_the_docs_exists(self):
        """`cbh <cmd> --help` must succeed for every command docs/cbh-cli.md shows.

        Three documented invocations were written against interfaces the modules do
        not have (wrong flags, missing positional). A doc that does not run is worse
        than no doc: the operator debugs their own typing.
        """
        import re
        doc = (ROOT / "docs" / "cbh-cli.md").read_text(encoding="utf-8")
        commands = sorted(set(re.findall(r"^cbh ([a-z][a-z-]+)", doc, re.M)))
        self.assertTrue(commands, "no cbh invocations found in the docs")
        for cmd in commands:
            r = subprocess.run([sys.executable, "-B", str(ROOT / "cbh" / "cli.py"), cmd, "--help"],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0,
                             f"docs show `cbh {cmd}` but it does not run:\n{r.stderr}")

    def test_manifest_schema_version_matches_its_documentation(self):
        doc = (ROOT / "docs" / "recon-manifest.md").read_text(encoding="utf-8")
        self.assertIn(self.inv["manifest_schema_version"], doc,
                      "docs/recon-manifest.md does not mention the current schema version")


if __name__ == "__main__":
    unittest.main()
