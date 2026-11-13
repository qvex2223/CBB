#!/usr/bin/env python3
"""oob-responder.py — self-hosted OOB endpoint for SSRF escalation (run on YOUR server).

Two disclosed-corpus techniques need infrastructure you control
(docs/disclosed-reports/HIGH-CRIT-LESSONS-2026-11.md):

  * **redirect loop** — a blind SSRF often becomes readable when the fetcher is
    walked through 301 -> 302 -> 303 -> 307 -> 308 -> ... and finally lands on a
    harmless page: many apps print the chain, the final body or the last status.
    `/loop/<marker>/<n>` answers hop n with the next status in LOOP_STATUSES, then
    redirects to `/final/<marker>`, which returns a small body carrying the marker.
    `/redirect/<marker>?to=<url>` is a single 302 for allowlist checks (only to
    targets YOU are authorised to test).
  * **outbound fingerprint** — every hit is logged as one JSON line (method, path,
    User-Agent, client address, headers). `User-Agent: curl/…` or
    `python-requests/…` says the backend shells out or proxies (a $10k write-up
    started exactly there).

Unlike `interactsh-client`, nothing leaves for a third-party server: the log stays
on the box you run this on. Policy still applies: RTEAM forbids OOB exfiltration
outright, and other programmes must permit OOB.

    python3 scripts/oob-responder.py --port 8088 --log logs/oob.jsonl
    # SSRF target to hand the app:  http://<your-host>:8088/loop/<marker>/0
    # read hits:                    python3 scripts/oob-responder.py --show logs/oob.jsonl
"""
from __future__ import annotations

import argparse
import http.server
import json
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

LOOP_STATUSES = [301, 302, 303, 307, 308, 301, 302, 303, 307, 308]


class Handler(http.server.BaseHTTPRequestHandler):
    log_path: Path = Path("oob.jsonl")
    server_version = "cbh-oob/1"

    def _log(self, status: int):
        row = {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "client": self.client_address[0],
               "method": self.command, "path": self.path, "status": status,
               "user_agent": self.headers.get("User-Agent", ""),
               "headers": {k: v for k, v in self.headers.items() if k.lower() not in ("cookie", "authorization")}}
        try:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def _send(self, status: int, body: bytes = b"", headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self._log(status)

    def do_GET(self):  # noqa: N802
        sp = urlsplit(self.path)
        parts = [p for p in sp.path.split("/") if p]
        if len(parts) >= 3 and parts[0] == "loop":
            marker, n = parts[1], int(parts[2]) if parts[2].isdigit() else 0
            if n < len(LOOP_STATUSES):
                nxt = f"/loop/{marker}/{n + 1}"
                return self._send(LOOP_STATUSES[n], b"", {"Location": nxt})
            return self._send(302, b"", {"Location": f"/final/{marker}"})
        if len(parts) >= 2 and parts[0] == "final":
            return self._send(200, f"cbh-oob-final {parts[1]}\n".encode(), {"Content-Type": "text/plain"})
        if len(parts) >= 2 and parts[0] == "redirect":
            to = (parse_qs(sp.query).get("to") or [""])[0]
            if to.startswith(("http://", "https://")):
                return self._send(302, b"", {"Location": to})
            return self._send(400, b"to= must be an absolute http(s) URL\n")
        return self._send(200, f"cbh-oob {sp.path}\n".encode(), {"Content-Type": "text/plain"})

    do_HEAD = do_GET
    do_POST = do_GET

    def log_message(self, *a):  # quiet stderr; the JSONL log is the record
        pass


def show(path: Path) -> int:
    if not path.exists():
        print(f"no log at {path}")
        return 1
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        ua = r.get("user_agent", "")
        flag = "  <- backend client" if any(k in ua.lower() for k in ("curl", "python", "go-http", "java",
                                                                        "okhttp", "axios", "node-fetch",
                                                                        "wget", "libwww", "guzzle")) else ""
        print(f"{r['at']} {r['client']:15s} {r['method']:5s} {r['status']} {r['path']}  UA={ua[:60]}{flag}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--log", type=Path, default=Path("oob.jsonl"))
    ap.add_argument("--show", type=Path, help="print a hit log and exit")
    a = ap.parse_args(argv)
    if a.show:
        return show(a.show)
    Handler.log_path = a.log
    a.log.parent.mkdir(parents=True, exist_ok=True)
    srv = http.server.ThreadingHTTPServer((a.bind, a.port), Handler)
    print(f"cbh-oob listening on {a.bind}:{a.port}, log {a.log}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
