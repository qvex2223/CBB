"""The tool-stand check: PATH vs what CLAUDE.md declares installed.

Written 2026-10-21, after four binaries the tool stand declared (amass, gowitness,
nuclei, dalfox) had silently disappeared from ~/.local/bin and no check looked at PATH.
A skill whose command returns `command not found` is a skill the agent abandons without
logging it, so this drift has to fail the doctor, not a hunt.
"""
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import workspace_check as wc  # noqa: E402


class ToolStandCheck(unittest.TestCase):
    def test_a_missing_declared_binary_fails(self):
        res = wc.check_tool_stand(required=["jq", "definitely-not-a-real-binary-xyz"],
                                  absent=[])
        self.assertEqual("FAIL", res[0]["status"])
        self.assertIn("definitely-not-a-real-binary-xyz", res[0]["detail"])
        self.assertTrue(res[0]["fix"], "a FAIL must name how to fix it")

    def test_all_present_is_ok(self):
        res = wc.check_tool_stand(required=["jq"], absent=[])
        self.assertEqual("OK", res[0]["status"])

    def test_a_documented_absent_binary_that_appears_is_reported(self):
        res = wc.check_tool_stand(required=["jq"], absent=["jq"])
        self.assertEqual("OK", res[0]["status"])
        self.assertEqual("WARN", res[1]["status"])
        self.assertIn("jq", res[1]["detail"])

    def test_known_absent_binaries_never_fail_the_doctor(self):
        res = wc.check_tool_stand(required=["jq"],
                                  absent=["definitely-not-a-real-binary-xyz"])
        self.assertEqual(1, len(res))
        self.assertEqual("OK", res[0]["status"])

    def test_the_real_stand_is_wired_into_run_all(self):
        names = {r["check"] for r in wc.run_all()}
        self.assertIn("tool-stand", names)

    def test_declared_and_known_absent_do_not_overlap(self):
        overlap = set(wc.TOOLS_REQUIRED) & set(wc.TOOLS_KNOWN_ABSENT)
        self.assertEqual(set(), overlap,
                         f"a binary cannot be both declared and documented absent: {overlap}")


if __name__ == "__main__":
    unittest.main()


class ToolsAreActuallyReachable(unittest.TestCase):
    """An installed tool no skill names is an installed tool the agent never runs.

    Asked by the operator on 2026-10-21 — "are these wired into hooks/context or do they
    just sit there?" The answer was: six of them sat there (`unfurl` `alterx` `tlsx`
    `asnmap` `mapcidr` `notify` were referenced by no skill and no command), and
    `bb-local-toolkit` listed four installed tools under "Not installed". Both failures
    are now tests.
    """

    # Entry points documented in CLAUDE.md rather than inside a skill body.
    DOC_ONLY = {"heavy-run"}

    @classmethod
    def setUpClass(cls):
        cls.corpus = {}
        for d in ("skills", "commands"):
            for p in (REPO / d).rglob("*.md"):
                cls.corpus[p] = p.read_text(encoding="utf-8", errors="replace")

    def _named_in_corpus(self, tool):
        import re
        pat = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(tool)}(?![A-Za-z0-9_-])")
        return [p for p, t in self.corpus.items() if pat.search(t)]

    def test_every_declared_tool_is_named_by_some_skill_or_command(self):
        orphans = [t for t in wc.TOOLS_REQUIRED
                   if t not in self.DOC_ONLY and not self._named_in_corpus(t)]
        self.assertEqual([], orphans,
                         "declared but named by no skill/command, so never reached for: "
                         + " ".join(orphans))

    def test_bb_local_toolkit_never_calls_an_installed_tool_missing(self):
        import shutil
        md = (REPO / "skills" / "bb-local-toolkit" / "SKILL.md").read_text(encoding="utf-8")
        head = "## Not installed — use the substitute, do not write the command"
        self.assertIn(head, md)
        section = md.split(head, 1)[1].split("\n## ", 1)[0]
        import re
        listed = re.findall(r"^\| `([^`]+)` \|", section, re.M)
        self.assertTrue(listed, "the absent-tools table parsed empty — did its shape change?")
        wrong = [t for t in listed if shutil.which(t)]
        self.assertEqual([], wrong,
                         "listed as NOT installed while on PATH — that is a standing "
                         "instruction not to use a tool we have: " + " ".join(wrong)
                         + " — fix: python3 scripts/gen_toolstand.py --write")

    def test_the_generated_block_matches_live_path(self):
        import subprocess
        r = subprocess.run([sys.executable, str(REPO / "scripts" / "gen_toolstand.py"),
                            "--check"], capture_output=True, text=True, cwd=REPO)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


class NetworkToolsAreVisibleToTheGate(unittest.TestCase):
    """SENDER_RE is how every hook knows a command fires a request.

    Ten network tools were installed on 2026-10-21 while this regex still held the
    2026-08 set, so they reached live targets with the gate blind to them.
    """

    SENDS = ["subfinder -d x.kz", "dnsx -l hosts.txt", "amass enum -d x.kz",
             "assetfinder --subs-only x.kz", "asnmap -d x.kz", "tlsx -u x.kz",
             "subzy run --targets hosts.txt", "nomore403 -u https://x.kz/admin",
             "grpcurl -plaintext x.kz:50051 list", "interactsh-client -v",
             "bbcurl https://x.kz/", "httpx -l hosts.txt"]
    OFFLINE = ["jsluice urls /tmp/b.js", "wakaru /tmp/b.js -o out/",
               "mapcidr -cidr r.txt", "alterx -l subs.txt", "unfurl keys",
               "gf ssrf", "gitleaks detect --no-git -s /tmp/r",
               "trivy fs /tmp/r", "echo https://x.kz", "jq .url out.json"]
    # NOTE deliberately not asserted: `grep -rn curl skills/` matches SENDER_RE because
    # the word is there. Harmless — the gate then finds no URL and no signal, so it does
    # not block. Narrowing the regex to exclude it would risk missing a real sender.

    @classmethod
    def setUpClass(cls):
        import skill_signals
        cls.ss = skill_signals

    def test_network_tools_count_as_senders(self):
        blind = [c for c in self.SENDS if not self.ss.sends_request(c)]
        self.assertEqual([], blind, "fires requests but the gate cannot see it: " + str(blind))

    def test_offline_tools_are_not_gated(self):
        noisy = [c for c in self.OFFLINE if self.ss.sends_request(c)]
        self.assertEqual([], noisy, "gated although it sends nothing: " + str(noisy))


class BundleGrepNudge(unittest.TestCase):
    """The hook has to name jsluice/wakaru at the moment a bundle grep is written.

    A tool nobody is pointed at is a tool nobody runs: that was the operator's question
    on 2026-10-21, and `hunt-nudge` named skills but never tools.
    """

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "hunt_nudge", REPO / "scripts" / "hunt-nudge.py")
        cls.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mod)

    def test_fires_on_a_grep_over_a_fetched_bundle(self):
        msg = self.mod._bundle_grep(
            'curl -s https://x.kz/_next/static/chunks/main-abc.js | grep -oE "innerHTML"')
        self.assertIn("jsluice", msg)
        self.assertIn("wakaru", msg)
        self.assertIn("hunt-source-leak", msg)

    def test_fires_on_a_source_map(self):
        self.assertTrue(self.mod._bundle_grep(
            "bbcurl https://x.kz/static/js/app.js.map | grep secret"))

    def test_silent_when_already_using_the_right_tool(self):
        self.assertEqual("", self.mod._bundle_grep(
            "jsluice urls app.js | grep -o '/api'"))
        self.assertEqual("", self.mod._bundle_grep(
            "wakaru https://x.kz/a.js -o out/ && grep -rn innerHTML out/"))

    def test_silent_on_unrelated_greps(self):
        for cmd in ("grep -rn innerHTML skills/",
                    "bbcurl https://x.kz/api/users | jq .",
                    "curl -s https://x.kz/robots.txt | grep -i disallow"):
            self.assertEqual("", self.mod._bundle_grep(cmd), cmd)
