#!/usr/bin/env python3
"""Layout resolution, because getting it wrong is silent.

The workspace moved off /opt/Claude and eleven scripts kept the old layout written
into them. Not one of them crashed: they resolved paths under a root that does not
exist and reported an empty workspace, so the scheduled jobs that depended on them
were no-ops that logged success. These tests pin the resolver that replaced them.
"""
import os
import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))

import paths  # noqa: E402


class Resolution(unittest.TestCase):
    def test_this_workspace_resolves_inside_the_bundle(self):
        self.assertEqual(paths.targets_root(), ROOT / "Targets")
        self.assertTrue(paths.targets_root().is_dir())

    def test_memory_dir_is_the_shared_corpus(self):
        env = os.environ.pop("CBH_MEMORY_DIR", None)
        self.addCleanup(lambda: os.environ.__setitem__("CBH_MEMORY_DIR", env) if env else None)
        self.assertEqual(paths.memory_dir(), ROOT / "hunt-memory")

    def test_env_override_wins_over_everything(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["CBH_TARGETS_ROOT"] = tmp
            self.addCleanup(os.environ.pop, "CBH_TARGETS_ROOT", None)
            self.assertEqual(paths.targets_root(), Path(tmp))

    def test_the_fallback_is_in_the_bundle_never_in_opt(self):
        """With no layout present a caller creating an engagement must not write to /opt."""
        os.environ["CBH_TARGETS_ROOT"] = ""
        self.addCleanup(os.environ.pop, "CBH_TARGETS_ROOT", None)
        self.assertTrue(str(paths.targets_root()).startswith(str(ROOT)))

    def test_the_template_lives_under_the_resolved_root(self):
        self.assertEqual(paths.template_dir(), paths.targets_root() / "_TEMPLATE")
        self.assertTrue(paths.template_dir().is_dir())


class NoStalePaths(unittest.TestCase):
    def test_no_script_hard_codes_the_old_workspace(self):
        """A literal /opt/Claude path in executable code is the bug this class guards."""
        offenders = []
        for f in sorted((ROOT / "scripts").glob("*.py")) + sorted((ROOT / "engine").glob("*.py")):
            if f.name == "paths.py":        # documents the historical layout on purpose
                continue
            for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("#", 1)[0]
                if '"/opt/Claude' in code or "'/opt/Claude" in code:
                    offenders.append(f"{f.relative_to(ROOT)}:{n}")
        self.assertEqual(offenders, [], "hard-coded /opt/Claude paths: " + ", ".join(offenders))


if __name__ == "__main__":
    unittest.main()
