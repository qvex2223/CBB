"""The programme-mandated cookie reaches the wire without dropping a session jar.

hh.ru's programme text asks for an `X_Bug_Bounty` COOKIE on every request. The obvious
place for it is `required_headers`, and that is a trap: `Engagement.apply_headers` merges
by header NAME, `bbcurl` emits the result as `-H "Cookie: ..."`, and curl lets an explicit
`-H Cookie:` REPLACE the header it would otherwise have built from `-b`. So a mandatory
cookie expressed as a header silently de-authenticates every lane carrying a session jar.
`required_cookie` exists so it is merged into `-b` instead, adding only what is missing.

Measured 2026-11-14: 1 of 1823 requests in a live hunt went out without the cookie while
every lane was carrying it by hand.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import pacing  # noqa: E402


def _load_bbcurl():
    """bbcurl has no .py suffix, so spec_from_file_location alone returns no loader."""
    name = "bbcurl_under_test"
    spec = importlib.util.spec_from_loader(
        name, SourceFileLoader(name, str(REPO / "scripts" / "bbcurl")))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


BBC = _load_bbcurl()


class FakeEngagement:
    """Only the one method bbcurl calls, so these tests do not need a real engagement."""

    def __init__(self, required: dict, raises: bool = False):
        self.required, self.raises = required, raises

    def apply_cookies(self, present):
        if self.raises:
            raise pacing.MissingRequiredCookie("t: required cookie(s) X have no value")
        have = {str(k).lower() for k in (present or {})}
        return {k: v for k, v in self.required.items() if k.lower() not in have}


REQ = {"X_Bug_Bounty": "qvex"}


class ProfilePlumbing(unittest.TestCase):
    def _eng(self, profile: dict):
        return pacing.Engagement(Path("/tmp/t"), profile=profile)

    def test_required_cookies_reads_the_profile(self):
        self.assertEqual(self._eng({"required_cookie": REQ}).required_cookies, REQ)

    def test_no_required_cookie_key_is_empty_not_an_error(self):
        self.assertEqual(self._eng({}).required_cookies, {})

    def test_a_non_dict_required_cookie_is_ignored_rather_than_crashing_a_lane(self):
        self.assertEqual(self._eng({"required_cookie": ["X=1"]}).required_cookies, {})

    def test_only_the_missing_pairs_come_back_so_the_caller_merges(self):
        eng = self._eng({"required_cookie": {"A": "1", "B": "2"}})
        self.assertEqual(eng.apply_cookies({"a": "whatever"}), {"B": "2"})

    def test_a_placeholder_value_blocks_instead_of_sending_the_word_TODO(self):
        eng = self._eng({"required_cookie": {"X_Bug_Bounty": "TODO"}})
        self.assertEqual(eng.missing_cookie_values(), ["X_Bug_Bounty"])
        with self.assertRaises(pacing.MissingRequiredCookie):
            eng.apply_cookies({})


class CookieMerge(unittest.TestCase):
    """Every spelling curl accepts for -b, plus the one shape that cannot be merged."""

    def _merge(self, argv, required=REQ, raises=False):
        return BBC._merge_required_cookies(argv, FakeEngagement(required, raises))

    def test_with_no_b_at_all_one_is_added(self):
        argv, extra, note = self._merge(["https://h/"])
        self.assertEqual(extra, ["-b", "X_Bug_Bounty=qvex"])
        self.assertEqual(argv, ["https://h/"])
        self.assertEqual(note, "")

    def test_a_session_jar_is_appended_to_never_replaced(self):
        for given, want in (
            (["-b", "sess=abc", "https://h/"],
             ["-b", "sess=abc; X_Bug_Bounty=qvex", "https://h/"]),
            (["-bsess=abc", "https://h/"],
             ["-bsess=abc; X_Bug_Bounty=qvex", "https://h/"]),
            (["--cookie", "sess=abc", "https://h/"],
             ["--cookie", "sess=abc; X_Bug_Bounty=qvex", "https://h/"]),
            (["--cookie=sess=abc", "https://h/"],
             ["--cookie=sess=abc; X_Bug_Bounty=qvex", "https://h/"]),
        ):
            with self.subTest(given=given):
                argv, extra, note = self._merge(given)
                self.assertEqual(argv, want)
                self.assertEqual(extra, [])
                self.assertEqual(note, "")
                self.assertIn("sess=abc", " ".join(argv),
                               "the lane's own jar must survive")

    def test_a_cookie_already_on_the_line_is_not_sent_twice(self):
        for given in (["-b", "sess=a; X_Bug_Bounty=qvex", "https://h/"],
                      ["-bX_Bug_Bounty=qvex", "https://h/"],
                      ["-b", "x_bug_bounty=qvex", "https://h/"]):  # name compare is casefolded
            with self.subTest(given=given):
                argv, extra, note = self._merge(given)
                self.assertEqual(argv, given)
                self.assertEqual(extra, [])

    def test_a_b_pointing_at_a_FILE_warns_and_still_fires(self):
        argv, extra, note = self._merge(["-b", "/tmp/jar.txt", "https://h/"])
        # Merging text into a cookie file is impossible, and this runs in the live request
        # path of an armed hunt: refusing would kill working lanes over a cookie the jar may
        # already hold. So it warns, names what could not be merged, and lets the request go.
        self.assertEqual(argv, ["-b", "/tmp/jar.txt", "https://h/"])
        self.assertEqual(extra, [])
        self.assertIn("X_Bug_Bounty", note)
        self.assertTrue(note.startswith("WARNING"), note)
        self.assertFalse(note.startswith("BLOCKED"), "a jar must never block a lane")

    def test_the_cookie_jar_OUTPUT_flag_is_not_mistaken_for_an_input(self):
        argv, extra, note = self._merge(["-c", "/tmp/out.txt", "https://h/"])
        self.assertEqual(extra, ["-b", "X_Bug_Bounty=qvex"])

    def test_with_a_file_and_an_inline_string_the_string_carries_the_cookie(self):
        argv, extra, note = self._merge(
            ["-b", "/tmp/jar.txt", "-b", "sess=abc", "https://h/"])
        self.assertEqual(argv[3], "sess=abc; X_Bug_Bounty=qvex")
        self.assertEqual(note, "")

    def test_nothing_is_touched_when_the_programme_mandates_no_cookie(self):
        given = ["-b", "sess=abc", "https://h/"]
        argv, extra, note = self._merge(list(given), required={})
        self.assertEqual((argv, extra, note), (given, [], ""))

    def test_a_placeholder_value_blocks_the_request(self):
        argv, extra, note = self._merge(["https://h/"], raises=True)
        self.assertTrue(note.startswith("BLOCKED"), note)
        self.assertEqual(extra, [])


class NeverAsAHeader(unittest.TestCase):
    def test_bbcurl_never_builds_an_H_Cookie_from_the_required_cookie(self):
        """The whole point: an explicit -H Cookie: replaces what -b would have sent."""
        src = (REPO / "scripts" / "bbcurl").read_text()
        where = src.index("def _merge_required_cookies")
        body = src[where:src.index("\ndef ", where + 10)]
        q = '"""'
        body = body[:body.index(q)] + body[body.index(q, body.index(q) + 3) + 3:]
        self.assertNotIn("Cookie:", body,
                         "a required cookie must go into -b, never -H Cookie:")
        self.assertNotIn('"-H"', body)

    def test_EVERY_curl_command_bbcurl_builds_carries_the_cookie(self):
        """bbcurl builds the command TWICE, and the second build dropped the cookie.

        `cmd` is assembled once normally and again when the caller brought no `-w` (so
        bbcurl can capture write-out stats) — which is almost every request. The second
        assembly omitted `cookie_args`, so the mandatory cookie went out only on the rare
        request that carried its own `-w`. A source-level invariant, because the failure
        mode is a future rebuild forgetting it again, not the logic being wrong.
        """
        import ast
        src = (REPO / "scripts" / "bbcurl").read_text()
        tree = ast.parse(src)
        main = next(n for n in tree.body
                    if isinstance(n, ast.FunctionDef) and n.name == "main")
        builds = [n for n in ast.walk(main)
                  if isinstance(n, ast.Assign)
                  and any(getattr(t, "id", "") == "cmd" for t in n.targets)
                  and isinstance(n.value, ast.List)]
        self.assertGreaterEqual(len(builds), 2, "expected both assemblies")
        for node in builds:
            starred = [e.value.id for e in node.value.elts
                       if isinstance(e, ast.Starred) and isinstance(e.value, ast.Name)]
            with self.subTest(line=node.lineno):
                self.assertIn("cookie_args", starred,
                              f"the curl command built at line {node.lineno} would go out "
                              f"without the programme-mandated cookie")
                self.assertIn("header_args", starred)

    def test_the_audit_row_describes_the_request_that_was_actually_sent(self):
        """A `-b` this wrapper ADDED lives in cookie_args, not argv."""
        src = (REPO / "scripts" / "bbcurl").read_text()
        self.assertIn('entry["req"] = responses.redact([*cookie_args, *argv])', src)

    def test_the_live_hh_engagement_carries_the_cookie_in_the_right_field(self):
        prof = REPO / "Targets" / "standoff365" / "hh" / "profile.json"
        if not prof.is_file():  # Targets/ is git-ignored
            self.skipTest("hh engagement not present in this checkout")
        p = json.loads(prof.read_text())
        self.assertEqual(p.get("required_cookie"), {"X_Bug_Bounty": "qvex"})
        self.assertNotIn("X_Bug_Bounty", json.dumps(p.get("required_headers") or {}),
                         "as a header it would replace the lane's own Cookie header")


if __name__ == "__main__":
    unittest.main()
