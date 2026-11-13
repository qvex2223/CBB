import sys, unittest, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "engine"))
import responses


class PhoneEmailSuffixForms(unittest.TestCase):
    def test_camel_and_suffix_forms_masked(self):
        for key in ("phoneMobile", "phone_mobile", "mobilePhone", "emailAddress", "userEmail", "msisdnMain"):
            out = responses.scrub_text('{"%s":"79990001122"}' % key)
            self.assertNotIn("79990001122", out, key)

    def test_counters_and_lookalikes_unmasked(self):
        out = responses.scrub_text('{"ordersCount":22,"tokenType":"Bearer","accountType":"buyer"}')
        self.assertIn("22", out)
        self.assertIn("Bearer", out)


if __name__ == "__main__":
    unittest.main()
