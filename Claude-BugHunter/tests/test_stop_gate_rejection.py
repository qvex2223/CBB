"""Regression: a CVSS vector must not read as 'rejected'.

Every CVSS 3.1 vector ends in ".../I:N/A:N", which contains the substring "n/a".
The old substring check therefore treated every properly scored finding as rejected,
so the stop gate ignored it and kept refusing to let a real hunt end (2026-09-14).
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "engine"))
import stop_gate  # noqa: E402


class RejectionParsingTest(unittest.TestCase):
    def test_cvss_vector_is_not_a_rejection(self):
        text = ("## 4. Критичность\nС (Medium). CVSS 3.1 **5.3** — "
                "`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`.\n")
        self.assertFalse(stop_gate._rejected(text))
        self.assertEqual(stop_gate.severity_of(text), "medium")

    def test_real_rejection_still_detected(self):
        self.assertTrue(stop_gate._rejected("# X\nSTATUS: rejected by triage, N/A\n"))
        self.assertTrue(stop_gate._rejected("# X\nОтчёт закрыт триажем\n"))

    def test_plain_na_still_detected(self):
        self.assertTrue(stop_gate._rejected("# X\nTriage said N/A, no impact\n"))


if __name__ == "__main__":
    unittest.main()
