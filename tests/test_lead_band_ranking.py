"""Why these exist.

`cbh leads` is the file the orchestrator picks lanes from, so a wrong band is not a cosmetic
bug: it decides which lead a worker spends its budget on. Two real mis-rankings on
2026-11-13 motivated every test below.

1. `Targets/standoff365/mail_vk/profile.json` had no `reward_by_class` at all, so every item
   fell back to `DEFAULT_WEIGHTS` - generic relative weights with no relation to the
   programme. A 125 000 RUB LFR lead printed as `[lead/other <=50,000]` while an IDOR item
   printed as `<=300,000`, above that programme's published 250 000 maximum.
2. The class table is inferred from a file's NAME and TITLE, but lead files already state
   their band in prose ("**Reward band if it lands:** 125 000 RUB") because the author looked
   it up in the programme's table. That statement was never read.

`LFR` also was not a class word. The programme's own reward table spells the class that way,
so a lead titled LFR classified as "other" and was ranked at the default.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import lead_queue as L  # noqa: E402


class TestDeclaredBand(unittest.TestCase):
    def test_space_grouped_rubles(self):
        self.assertEqual(L.declared_band("**Reward band if it lands:** 125 000 ₽"), 125000)

    def test_thin_and_nbsp_grouping(self):
        self.assertEqual(L.declared_band("**Band:** 125 000"), 125000)
        self.assertEqual(L.declared_band("**Band:** 125 000"), 125000)

    def test_comma_grouped(self):
        self.assertEqual(L.declared_band("**Band:** 100,000"), 100000)

    def test_up_to_and_range_prefixes(self):
        self.assertEqual(L.declared_band("**Payout:** up to 250 000 RUB"), 250000)
        self.assertEqual(L.declared_band("**Reward band:** 0 – 15 000"), 15000)

    def test_currency_word_is_not_a_multiplier(self):
        self.assertEqual(L.declared_band("**Band:** 100 000 rub"), 100000)

    def test_multiplier_suffix_is_rejected_not_truncated(self):
        # The bug this guards: a lookahead inside the pattern let the greedy digit group
        # backtrack, so "12k" matched "1" and returned 1 - a band that looks real.
        self.assertEqual(L.declared_band("**Band:** 12k"), 0)
        self.assertEqual(L.declared_band("**Band:** 250 тыс"), 0)

    def test_absent_band_is_zero_so_the_class_table_still_applies(self):
        self.assertEqual(L.declared_band("# a lead with no band line"), 0)
        self.assertEqual(L.declared_band(""), 0)

    def test_malformed_number_does_not_raise(self):
        self.assertEqual(L.declared_band("**Band:** 1234567890123"), 0)

    def test_band_line_must_be_a_bold_label_not_prose(self):
        self.assertEqual(L.declared_band("it would probably pay 125 000 RUB"), 0)


class TestLfrClassWord(unittest.TestCase):
    def test_lfr_is_the_lfi_class(self):
        self.assertEqual(L._class_of("mail-ru-apex-vj-lfr", "LFR on the apex static location"), "lfi")

    def test_lfi_and_traversal_still_classify(self):
        self.assertEqual(L._class_of("x", "path-traversal in the include param"), "lfi")
        self.assertEqual(L._class_of("x", "LFI via ?page="), "lfi")

    def test_lfr_inside_a_word_does_not_match(self):
        # \blfr\b, not bare "lfr" - the same trap that made "Domain=ozon.ru" classify a
        # session-fixation lead as xss.
        self.assertNotEqual(L._class_of("selfreport", "selfreporting counters"), "lfi")


class TestDeclaredBandWinsOverClassTable(unittest.TestCase):
    def test_band_beats_the_inferred_class(self):
        """A file whose name says nothing and whose band says 125 000 must rank on 125 000."""
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as td:
            # scan() reports the engagement path relative to the Targets root, so the fake
            # engagement has to look like it lives there.
            root = Path(td)
            eng = root / "platform" / "program"
            eng.mkdir(parents=True)
            self.enterContext(mock.patch.object(L, "_targets_root", lambda: root))
            (eng / "leads").mkdir()
            (eng / "primitives").mkdir()
            (eng / "leads" / "a-quiet-name.md").write_text(
                "# a lead whose name carries no class word\n\n"
                "**Reward band if it lands:** 125 000 ₽\n\n**Status:** OPEN\n",
                encoding="utf-8")
            q = L.scan(eng)
            rows = [r for r in q["open"] if r["file"].endswith("a-quiet-name.md")]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["reward"], 125000)
            self.assertEqual(rows[0]["class"], "other")  # class still inferred, band overrides


if __name__ == "__main__":
    unittest.main()
