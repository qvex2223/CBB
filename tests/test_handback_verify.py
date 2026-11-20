"""`cbh handback-verify` (2026-11-17, wave 3 item 11).

The role files already demand it — "Every citation must EXIST in `audit.jsonl` or the response
corpus" (`refuter.md:36-37`, `deep-hunter.md:70`, `scout.md:35`) — and nothing checked. The cost
of not checking, from a public comparison: PentAGI shipped findings tagged `confirmed-with-PoC`
whose proof fingerprint was a hardcoded constant inside its own report generator, so the PoC had
never run.

Every test here has both arms. A verifier that only ever says FOUND is as useless as one that only
ever says NOT FOUND.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine"))
import handback_verify as HV  # noqa: E402
import responses as RS  # noqa: E402

URL = "https://api.example.test/v1/me"
SHA = "a" * 64
OTHER_SHA = "b" * 64


def _mem(tmp, rows, corpus=()):
    mem = Path(tmp) / "hunt-memory"
    mem.mkdir(parents=True)
    (mem / "audit.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + ("\n" if rows else ""), encoding="utf-8")
    for engagement, digest in corpus:
        d = mem / "responses" / engagement
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{digest}.txt").write_text("body", encoding="utf-8")
    return mem


def _row(url, digest=None, engagement="p/prog", ts="2026-11-16T10:00:00+00:00"):
    r = {"source": "bbcurl", "engagement": engagement, "urls": [url],
         "http_code": 200, "timestamp": ts}
    if digest:
        r["body_sha256"] = digest
    return r


class _Mem:
    """Point both this module and `responses` at a fake memory dir."""

    def __init__(self, mem):
        self.mem = mem

    def __enter__(self):
        self._p = [mock.patch.object(HV, "_memdir", lambda memdir=None: self.mem),
                   mock.patch.object(RS, "_memdir", lambda memdir=None: self.mem)]
        for q in self._p:
            q.start()
        return self

    def __exit__(self, *exc):
        for q in self._p:
            q.stop()
        return False


class Extraction(unittest.TestCase):
    def test_it_finds_urls_shas_and_paths_and_strips_trailing_punctuation(self):
        got = HV.extract(f"Fired {URL}, hash {SHA}. See Targets/p/prog/findings/x.md.")
        self.assertEqual([URL], got["url"])
        self.assertEqual([SHA], got["sha256"])
        self.assertEqual(["Targets/p/prog/findings/x.md"], got["path"])

    def test_a_40_char_hex_string_is_not_a_sha256(self):
        self.assertEqual([], HV.extract("commit " + "c" * 40)["sha256"])

    def test_ordinary_prose_with_a_slash_is_not_a_path(self):
        got = HV.extract("the read/write split and the and/or case")
        self.assertEqual([], got["path"])

    def test_each_citation_is_reported_once(self):
        got = HV.extract(f"{URL} and again {URL}")
        self.assertEqual(1, len(got["url"]))


class Urls(unittest.TestCase):
    def test_a_recorded_url_resolves_and_names_when_and_where(self):
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, [_row(URL)])
            with _Mem(mem):
                rep = HV.verify(f"fired {URL}")
            self.assertEqual("FOUND", rep["results"][0]["verdict"])
            self.assertIn("p/prog", rep["results"][0]["why"])
            self.assertEqual([], rep["misses"])

    def test_an_unrecorded_url_is_a_miss(self):
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, [_row(URL)])
            with _Mem(mem):
                rep = HV.verify("fired https://invented.test/x")
            self.assertEqual("NOT IN AUDIT", rep["results"][0]["verdict"])
            self.assertEqual(1, len(rep["misses"]))

    def test_a_near_miss_is_reported_as_prefix_only_not_as_found(self):
        """Weaker evidence must not read as exact: the lane may have hit a different path."""
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, [_row(URL + "/extra")])
            with _Mem(mem):
                rep = HV.verify(f"fired {URL}")
            self.assertEqual("PREFIX-ONLY", rep["results"][0]["verdict"])

    def test_the_rotations_are_read_too(self):
        """A citation from three weeks ago is still a citation."""
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, [])
            (mem / "audit.jsonl.2").write_text(json.dumps(_row(URL)) + "\n", encoding="utf-8")
            with _Mem(mem):
                rep = HV.verify(f"fired {URL}")
            self.assertEqual("FOUND", rep["results"][0]["verdict"])

    def test_the_plural_key_is_what_is_read(self):
        """`urls`, not `url`: a row written with the singular key carries nothing."""
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, [{"engagement": "p/prog", "url": URL, "timestamp": "2026-11-16"}])
            with _Mem(mem):
                rep = HV.verify(f"fired {URL}")
            self.assertEqual("NOT IN AUDIT", rep["results"][0]["verdict"])


class Hashes(unittest.TestCase):
    def test_audit_plus_corpus_is_the_strongest_answer(self):
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, [_row(URL, SHA)], corpus=[("p_prog", SHA)])
            with _Mem(mem):
                rep = HV.verify(f"hash {SHA}", engagement="p/prog")
            self.assertEqual("FOUND", rep["results"][0]["verdict"])
            self.assertIn("corpus", rep["results"][0]["why"])

    def test_audit_only_is_not_a_miss(self):
        """Storage can be off or the body empty; the wire record still stands."""
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, [_row(URL, SHA)])
            with _Mem(mem):
                rep = HV.verify(f"hash {SHA}")
            self.assertEqual("AUDIT ONLY", rep["results"][0]["verdict"])
            self.assertEqual([], rep["misses"])

    def test_corpus_only_is_not_a_miss_but_is_named(self):
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, [], corpus=[("p_prog", SHA)])
            with _Mem(mem):
                rep = HV.verify(f"hash {SHA}", engagement="p/prog")
            self.assertEqual("CORPUS ONLY", rep["results"][0]["verdict"])

    def test_the_corpus_is_found_across_engagement_folders(self):
        """`responses.path_for` falls back by globbing, so a renamed project still resolves."""
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, [_row(URL, SHA)], corpus=[("some_other_name", SHA)])
            with _Mem(mem):
                rep = HV.verify(f"hash {SHA}", engagement="p/prog")
            self.assertEqual("FOUND", rep["results"][0]["verdict"])

    def test_an_invented_hash_is_a_miss(self):
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, [_row(URL, SHA)])
            with _Mem(mem):
                rep = HV.verify(f"hash {OTHER_SHA}")
            self.assertEqual("NOT IN AUDIT", rep["results"][0]["verdict"])
            self.assertEqual(1, len(rep["misses"]))


class Paths(unittest.TestCase):
    def test_a_real_repo_path_resolves(self):
        with tempfile.TemporaryDirectory() as t:
            with _Mem(_mem(t, [])):
                rep = HV.verify("see hunt-memory/README.md")
            self.assertEqual("FOUND", rep["results"][0]["verdict"])

    def test_an_invented_path_is_a_miss(self):
        with tempfile.TemporaryDirectory() as t:
            with _Mem(_mem(t, [])):
                rep = HV.verify("see Targets/nope/nothing/findings/fake.md")
            self.assertEqual("NOT FOUND", rep["results"][0]["verdict"])


class TheReportItself(unittest.TestCase):
    def test_a_handback_with_no_citation_says_so(self):
        """Nothing to check is itself the finding: the hand-back cannot be spot-checked."""
        with tempfile.TemporaryDirectory() as t:
            with _Mem(_mem(t, [])):
                text = HV.render(HV.verify("I looked at the login flow and found nothing."))
        self.assertIn("nothing here to check", text)

    def test_the_report_states_that_existence_is_not_authorship(self):
        with tempfile.TemporaryDirectory() as t:
            with _Mem(_mem(t, [_row(URL)])):
                text = HV.render(HV.verify(f"fired {URL}"))
        self.assertIn("Existence is not authorship", text)
        self.assertIn("262144", text)
        self.assertIn("redacted", text)

    def test_exit_code_is_nonzero_only_on_a_miss(self):
        with tempfile.TemporaryDirectory() as t:
            mem = _mem(t, [_row(URL)])
            with _Mem(mem):
                self.assertEqual(0, HV.main([str(self._tmpfile(t, f"fired {URL}"))]))
                self.assertEqual(1, HV.main([str(self._tmpfile(
                    t, "fired https://invented.test/x", "bad.txt"))]))

    @staticmethod
    def _tmpfile(t, text, name="hb.txt"):
        p = Path(t) / name
        p.write_text(text, encoding="utf-8")
        return p

    def test_a_missing_input_file_is_a_usage_error(self):
        self.assertEqual(2, HV.main(["/nonexistent/handback.txt"]))


if __name__ == "__main__":
    unittest.main()
