#!/usr/bin/env python3
"""Shared outbound-request policy for all Claude-BugHunter transports.

The broker chooses no payloads and performs no retries. It supplies the common
contract: scope validation, netblock verification, mandatory headers, global
engagement pacing, response capture, and append-only audit records.
"""
from __future__ import annotations

import tempfile
import urllib.parse
from pathlib import Path
from typing import Dict, Iterable, Optional

from memory import Memory
from pacing import Engagement, MissingRequiredHeader
from scope import Scope, _scope_from_md


class RequestBlocked(RuntimeError):
    pass


def is_local_url(url: str) -> bool:
    host = urllib.parse.urlsplit(url if "://" in url else "//" + url).hostname or ""
    return host in {"localhost", "127.0.0.1", "::1", ""} or host.endswith(".local")


class RequestBroker:
    def __init__(self, engagement: Optional[Engagement] = None,
                 scope: Optional[Scope] = None, source: str = "request_broker",
                 allow_ungated: bool = False, allow_writes: Optional[bool] = None):
        self.engagement = engagement or Engagement.detect()
        self.scope = scope or self._project_scope()
        self.source = source
        self.allow_ungated = allow_ungated
        self.allow_writes = (self.engagement.allow_write_probes if allow_writes is None
                             else bool(allow_writes))

    @classmethod
    def detect(cls, start: Optional[Path] = None, scope: Optional[Scope] = None,
               source: str = "request_broker", allow_ungated: bool = False,
               allow_writes: Optional[bool] = None):
        return cls(Engagement.detect(start), scope=scope, source=source,
                   allow_ungated=allow_ungated, allow_writes=allow_writes)

    def _project_scope(self) -> Optional[Scope]:
        if not self.engagement.project_dir:
            return None
        path = self.engagement.project_dir / "scope.md"
        return _scope_from_md(str(path)) if path.is_file() else None

    def validate(self, urls: Iterable[str], pins: Optional[Dict[str, str]] = None) -> list[dict]:
        urls = [u for u in urls if u]
        remote = [u for u in urls if not is_local_url(u)]
        if self.scope is None:
            if remote and not self.allow_ungated:
                raise RequestBlocked("no authoritative scope is available for remote request(s)")
            return []
        results = []
        pins = {k.lower(): v for k, v in (pins or {}).items()}
        for url in urls:
            reason = self.scope.reject_reason(url)
            if reason is not None:
                raise RequestBlocked(f"OUT-OF-SCOPE {url}: {reason}")
            if self.scope.ip_scope:
                host = urllib.parse.urlsplit(url).hostname or ""
                target = pins.get(host.lower()) or url
                verdict = self.scope.verify(target, resolve=True)
                if verdict["verdict"] != "IN-SCOPE":
                    raise RequestBlocked(f"{verdict['verdict']} {url}: {verdict['reason']}")
                verdict["url"] = url
                verdict["pinned"] = pins.get(host.lower())
                results.append(verdict)
        return results

    def prepare_headers(self, headers: Optional[dict]) -> dict:
        return self.engagement.apply_headers(headers)

    def wait_turn(self) -> float:
        return self.engagement.wait_turn()

    def before_request(self, url: str, headers: Optional[dict] = None) -> tuple[dict, float]:
        self.validate([url])
        merged = self.prepare_headers(headers)
        return merged, self.wait_turn()

    def audit(self, record: dict) -> None:
        row = dict(record)
        row.setdefault("source", self.source)
        if self.engagement.name:
            row.setdefault("engagement", self.engagement.name)
        Memory().audit(row)

    def record_response(self, url: str, method: str, status: int, body,
                        headers: Optional[dict] = None, elapsed_ms: Optional[float] = None) -> dict:
        import responses
        raw = body if isinstance(body, bytes) else str(body or "").encode("utf-8", "replace")
        body_path = header_path = None
        entry = {"source": self.source, "urls": [url], "method": method.upper(),
                 "http_code": status, "elapsed_ms": elapsed_ms}
        try:
            with tempfile.NamedTemporaryFile(prefix="cbh-body-", delete=False) as fh:
                fh.write(raw)
                body_path = Path(fh.name)
            if headers:
                with tempfile.NamedTemporaryFile(prefix="cbh-headers-", mode="w",
                                                 encoding="utf-8", delete=False) as fh:
                    fh.write(f"HTTP/1.1 {status}\r\n")
                    for key, value in headers.items():
                        fh.write(f"{key}: {value}\r\n")
                    fh.write("\r\n")
                    header_path = Path(fh.name)
            if not responses.disabled():
                entry.update(responses.save(self.engagement.name or "adhoc", body_path, header_path))
            self.audit(entry)
            return entry
        finally:
            for path in (body_path, header_path):
                if path:
                    try:
                        path.unlink()
                    except OSError:
                        pass


__all__ = ["RequestBroker", "RequestBlocked", "MissingRequiredHeader", "is_local_url"]
