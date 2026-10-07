"""recall: route collapsing, burned/untried shapes, silence on new ground."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import recall  # noqa: E402


def row(url, method="GET", code=200, auth=False, sha="a"):
    req = ["-X", method, url] + (["-H", "Authorization: Bearer x"] if auth else [])
    return {"urls": [url], "method": method, "http_code": code, "body_sha256": sha, "req": req}


class Recall(unittest.TestCase):
    def test_ids_collapse(self):
        self.assertEqual(recall.route_of("https://a.b/x/123/y"), recall.route_of("https://a.b/x/456/y"))
        self.assertNotEqual(recall.route_of("https://a.b/x/foo"), recall.route_of("https://a.b/x/bar"))

    def test_summary_lists_untried(self):
        s = recall.summarise([row("https://a.b/x/1"), row("https://a.b/x/2", "POST", 403)])
        self.assertEqual(s["methods"]["POST"]["statuses"], {403: 1})
        self.assertIn("method DELETE", s["untried"])
        self.assertNotIn("method GET", s["untried"])
        self.assertIn("with auth", s["untried"])

    def test_auth_sent_only_suggests_strip(self):
        s = recall.summarise([row("https://a.b/x", auth=True), row("https://a.b/x", auth=True)])
        self.assertIn("auth stripped", s["untried"])

    def test_new_ground_is_none(self):
        self.assertIsNone(recall.recall("https://nowhere.invalid/zzz", memdir=Path("/nonexistent")))

    def test_render_mentions_route(self):
        s = recall.summarise([row("https://a.b/x"), row("https://a.b/x")])
        s.update(route="a.b/x", constant_fields={"match": "false"})
        out = recall.render(s)
        self.assertIn("match=false", out)
        self.assertIn("a.b/x", out)


if __name__ == "__main__":
    unittest.main()
