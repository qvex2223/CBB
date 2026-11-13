"""The WebSocket step in poc_runtime.

Why these exist: a `101 Switching Protocols` only proves the transport upgraded.
The question that decides an authorization finding on a notification hub is what
the *first protocol frame* gets back, and before this step that frame could only
be sent by a raw client — which bypasses the scope gate, the pacing budget and
`audit.jsonl`, so the permission layer refused it and the finding stayed
unprovable. These tests pin the three things that made it unprovable:

1. the handshake is real (the server's `Sec-WebSocket-Accept` is verified, so a
   plain 101 from something that is not a WebSocket does not read as upgraded);
2. client frames are masked, as RFC 6455 §5.3 requires — an unmasked client
   frame is dropped by every compliant server, which would look like "the hub
   rejected us" and produce a false negative;
3. frames land in `body`, so the existing `expect` assertions judge a socket
   exactly like an HTTP response.
"""
from __future__ import annotations

import base64
import hashlib
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))

import poc_runtime as p  # noqa: E402

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class _Hub:
    """A minimal server that completes the handshake and sends one text frame.

    `accept` controls whether it computes a correct `Sec-WebSocket-Accept`, which
    is how the "101 but not actually a WebSocket" case gets tested.
    """

    def __init__(self, accept: bool = True, payload: bytes = b'{"hello":"hub"}') -> None:
        self.accept = accept
        self.payload = payload
        self.client_frame: bytes | None = None
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            key = ""
            for line in data.decode("latin-1").split("\r\n"):
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
            token = base64.b64encode(
                hashlib.sha1((key + GUID).encode()).digest()).decode()
            if not self.accept:
                token = "wrong-accept-token"
            conn.sendall(
                ("HTTP/1.1 101 Switching Protocols\r\n"
                 "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                 f"Sec-WebSocket-Accept: {token}\r\n\r\n").encode())
            conn.settimeout(2)
            try:
                self.client_frame = conn.recv(4096)
            except (TimeoutError, socket.timeout, OSError):
                pass
            conn.sendall(bytes([0x81, len(self.payload)]) + self.payload)
            time.sleep(0.2)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class WebSocketStepTests(unittest.TestCase):
    def test_upgrade_and_frame_land_in_body_so_expect_judges_them(self):
        hub = _Hub()
        self.addCleanup(hub.close)
        spec = {
            "url": f"http://127.0.0.1:{hub.port}/notifications",
            "ws": True,
            "ws_send": ['{"protocol":"json","version":1}'],
            "ws_max_frames": 2,
            "expect": {"status": 101, "body_contains": ["hello"]},
        }
        result = p.fire_once(spec, timeout=5)
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(101, result["status"])
        self.assertTrue(result["ws"]["upgraded"])
        self.assertTrue(result["ws"]["accept_valid"])
        self.assertIn("hello", result["body"])
        verdict, reasons = p.evaluate(result, spec["expect"])
        self.assertEqual("PASS", verdict, reasons)

    def test_wrong_accept_token_is_not_an_upgrade(self):
        hub = _Hub(accept=False)
        self.addCleanup(hub.close)
        result = p.fire_once(
            {"url": f"http://127.0.0.1:{hub.port}/notifications", "ws": True}, timeout=5)
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(101, result["status"])
        self.assertFalse(result["ws"]["accept_valid"])
        self.assertFalse(result["ws"]["upgraded"])
        # No frames are read when the handshake did not verify: continuing would
        # read bytes from something that is not speaking this protocol.
        self.assertEqual(0, result["ws"]["frames_read"])

    def test_client_frames_are_masked(self):
        hub = _Hub()
        self.addCleanup(hub.close)
        p.fire_once({
            "url": f"http://127.0.0.1:{hub.port}/notifications",
            "ws": True,
            "ws_send": ["ping-from-test"],
        }, timeout=5)
        for _ in range(20):
            if hub.client_frame:
                break
            time.sleep(0.1)
        self.assertIsNotNone(hub.client_frame, "server never received a client frame")
        frame = hub.client_frame
        self.assertEqual(0x81, frame[0], "expected a final text frame")
        self.assertTrue(frame[1] & 0x80, "client frame must set the MASK bit")
        length = frame[1] & 0x7F
        mask = frame[2:6]
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(frame[6:6 + length]))
        self.assertEqual(b"ping-from-test", payload)

    def test_ws_scheme_url_also_dispatches_to_the_socket_path(self):
        # A spec that writes ws:// instead of https:// + "ws": true still works,
        # but the scope gate only understands http(s), so https:// stays preferred.
        hub = _Hub()
        self.addCleanup(hub.close)
        result = p.fire_once({"url": f"ws://127.0.0.1:{hub.port}/notifications"}, timeout=5)
        self.assertTrue(result["ok"], result.get("error"))
        self.assertTrue(result["ws"]["upgraded"])

    def test_a_dead_port_is_an_error_not_a_silent_pass(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        result = p.fire_once(
            {"url": f"http://127.0.0.1:{port}/notifications", "ws": True}, timeout=3)
        self.assertFalse(result["ok"])
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
