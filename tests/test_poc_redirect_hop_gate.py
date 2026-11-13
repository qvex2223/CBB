"""A followed redirect must be scope-gated like any other request.

Incident 2026-11-12: a two-step spec on `support.biz.mail.ru` followed its OIDC
bounce and fetched `https://tech.mail.ru` once. That host is not declared in the
programme's scope (`mail.ru` is apex-only), `RequestBroker.validate()` had only
ever seen the URLs written in the spec, and the hop left no audit row. The gate
now runs again on every `Location` target before the request is sent.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import poc_runtime as pr  # noqa: E402


class _Hdrs:
    def get_all(self, _name):
        return []


class _Req:
    full_url = "https://support.biz.mail.ru/api/auth/oidc/external-portal"


def _gate(url):
    if "support.biz.mail.ru" in url:
        return None
    return f"OUT-OF-SCOPE {url}: matches no in-scope rule (default deny)"


class RedirectHopGate(unittest.TestCase):
    def test_an_undeclared_hop_is_recorded_and_not_followed(self):
        redir = pr._RecordingRedirect(follow=True, gate=_gate)
        out = redir.redirect_request(_Req(), None, 302, "Found", _Hdrs(),
                                     "https://tech.mail.ru/oauth")
        self.assertIsNone(out, "a refused hop must not produce a new request")
        self.assertEqual([h["to"] for h in redir.blocked], ["https://tech.mail.ru/oauth"])
        self.assertIn("OUT-OF-SCOPE", redir.hops[0]["blocked"])

    def test_a_refused_hop_can_never_be_a_pass(self):
        redir = pr._RecordingRedirect(follow=True, gate=_gate)
        redir.redirect_request(_Req(), None, 302, "Found", _Hdrs(),
                               "https://tech.mail.ru/oauth")
        verdict, reasons = pr.evaluate(
            {"ok": True, "status": 302, "redirects_blocked": redir.blocked},
            {"status": 302},
        )
        self.assertEqual(verdict, "INCONCLUSIVE")
        self.assertIn("refused by the scope gate", reasons[0])

    def test_an_in_scope_hop_is_not_blocked(self):
        redir = pr._RecordingRedirect(follow=True, gate=_gate)
        with self.assertRaises(AttributeError):
            # reaches the stdlib handler, which needs a real fp — getting that far
            # is the assertion: the gate did not stop an in-scope hop.
            redir.redirect_request(_Req(), None, 302, "Found", _Hdrs(),
                                   "https://support.biz.mail.ru/api/x")
        self.assertEqual(redir.blocked, [])

    def test_no_gate_means_the_old_behaviour(self):
        redir = pr._RecordingRedirect(follow=False, gate=None)
        self.assertIsNone(redir.redirect_request(_Req(), None, 302, "Found", _Hdrs(),
                                                 "https://tech.mail.ru/oauth"))
        self.assertEqual(redir.blocked, [])
        self.assertNotIn("blocked", redir.hops[0])


if __name__ == "__main__":
    unittest.main()
