"""A run killed at --max-turns must still hand back the turns it did emit.

Two freeroam runs were lost to this: 41+71 turns on 2026-10-17 and 68 turns /
$2.88 / 564 s on 2026-10-20, the second one with the raised hard cap already in
place. The cap cannot be the fix, because an agent can overrun any cap; keeping
the streamed turns is the fix, and this test is what stops it regressing.
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engine"))

from agent import _parse_stream, extract_json


def _assistant(text):
    return json.dumps({"type": "assistant",
                       "message": {"content": [{"type": "text", "text": text}]}})


class ParseStream(unittest.TestCase):
    def test_completed_run_uses_the_closing_result_event(self):
        out = "\n".join([
            _assistant("thinking out loud"),
            json.dumps({"type": "result", "result": "FINAL", "total_cost_usd": 1.5,
                        "num_turns": 7}),
        ])
        d = _parse_stream(out)
        self.assertEqual(d["result"], "FINAL")
        self.assertEqual(d["num_turns"], 7)
        self.assertEqual(d["total_cost_usd"], 1.5)
        self.assertFalse(d["partial"])

    def test_killed_run_salvages_the_assistant_turns(self):
        out = "\n".join([_assistant("turn one"), _assistant("turn two")])
        d = _parse_stream(out)
        self.assertEqual(d["result"], "turn one\n\nturn two")
        self.assertTrue(d["partial"], "a salvaged run must be marked partial")

    def test_a_json_block_emitted_mid_run_survives_the_kill(self):
        out = "\n".join([
            _assistant("here is what I have so far"),
            _assistant('```json\n[{"surface": "/x", "fired": true}]\n```'),
        ])
        items = extract_json(_parse_stream(out)["result"])
        self.assertEqual(items, [{"surface": "/x", "fired": True}])

    def test_non_json_noise_does_not_discard_the_rest(self):
        out = "\n".join(["not json at all", _assistant("kept"), "{broken"])
        d = _parse_stream(out)
        self.assertEqual(d["result"], "kept")
        self.assertTrue(d["partial"])

    def test_empty_stream_is_not_partial(self):
        d = _parse_stream("")
        self.assertEqual(d["result"], "")
        self.assertFalse(d["partial"])

    def test_single_blob_json_is_still_read(self):
        """The old --output-format json shape must keep working if it ever arrives."""
        d = _parse_stream(json.dumps({"result": "ok", "num_turns": 2,
                                      "total_cost_usd": 0.1}))
        self.assertEqual(d["result"], "ok")
        self.assertEqual(d["num_turns"], 2)
        self.assertFalse(d["partial"])


if __name__ == "__main__":
    unittest.main()
