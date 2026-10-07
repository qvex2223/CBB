"""recall — what this endpoint has already been asked, before the next request goes out.

The response corpus records every body, but across the tier-3 eval the agent never
consulted it. This turns the corpus into something that arrives by itself: for a URL
about to be fired, summarise prior traffic to the same *route* (numeric ids and UUIDs
collapsed), the shapes already burned (methods, auth stripped, content types), the
shapes still untried, and any decisive field that never moved.

Pure functions over audit rows so the hook and the tests share one code path.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional
from urllib.parse import urlsplit

import responses

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
AUTH_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token")

_ID_SEG = re.compile(
    r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24,64})$", re.I)


def route_of(url: str) -> str:
    """host + path with id-looking segments collapsed to `{id}`."""
    try:
        p = urlsplit(url)
    except ValueError:
        return ""
    segs = ["{id}" if _ID_SEG.match(s) else s for s in p.path.split("/")]
    return (p.hostname or "").lower() + "/".join(segs)


def _headers(req: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for i, a in enumerate(req or []):
        if a in ("-H", "--header") and i + 1 < len(req) and ":" in req[i + 1]:
            k, v = req[i + 1].split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


def _method(row: Dict) -> str:
    if row.get("method"):
        return str(row["method"]).upper()
    req = row.get("req") or []
    for i, a in enumerate(req):
        if a in ("-X", "--request") and i + 1 < len(req):
            return req[i + 1].upper()
    return "POST" if any(a in ("-d", "--data", "--data-raw", "--data-binary", "-F") for a in req) else "GET"


def _status(row: Dict) -> Optional[int]:
    for k in ("http_code", "status"):
        v = row.get(k)
        if isinstance(v, int) and v > 0:
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
    return None


def history(url: str, engagement: str = "", memdir=None, limit: int = 4000) -> List[Dict]:
    """Prior audit rows that hit the same route as `url`."""
    want = route_of(url)
    if not want:
        return []
    host = want.split("/", 1)[0]
    out = []
    for r in responses.rows(host, engagement, limit=limit, memdir=memdir):
        if any(route_of(u) == want for u in (r.get("urls") or [])):
            out.append(r)
    return out


def summarise(rows_: List[Dict]) -> Dict:
    methods: Dict[str, Dict] = {}
    auth_stripped = auth_sent = 0
    ctypes = set()
    for r in rows_:
        m = _method(r)
        d = methods.setdefault(m, {"n": 0, "statuses": {}, "bodies": set()})
        d["n"] += 1
        st = _status(r)
        if st:
            d["statuses"][st] = d["statuses"].get(st, 0) + 1
        if r.get("body_sha256"):
            d["bodies"].add(r["body_sha256"])
        h = _headers(r.get("req") or [])
        if any(k in h for k in AUTH_HEADERS):
            auth_sent += 1
        else:
            auth_stripped += 1
        if h.get("content-type"):
            ctypes.add(h["content-type"].split(";")[0].lower())
    untried = []
    for m in METHODS:
        if m not in methods:
            untried.append(f"method {m}")
    if auth_sent and not auth_stripped:
        untried.append("auth stripped")
    if auth_stripped and not auth_sent:
        untried.append("with auth")
    if len(ctypes) < 2 and any(m in methods for m in ("POST", "PUT", "PATCH")):
        untried.append("content-type swap (json/form/xml)")
    return {
        "requests": len(rows_),
        "methods": {m: {"n": d["n"], "statuses": d["statuses"], "distinct_bodies": len(d["bodies"])}
                    for m, d in methods.items()},
        "auth_stripped": auth_stripped,
        "auth_sent": auth_sent,
        "untried": untried,
    }


def recall(url: str, engagement: str = "", memdir=None, min_requests: int = 2) -> Optional[Dict]:
    """Summary for the route `url` belongs to, or None when it is new ground."""
    rows_ = history(url, engagement, memdir)
    if len(rows_) < min_requests:
        return None
    s = summarise(rows_)
    s["route"] = route_of(url)
    try:
        var = responses.field_variance(rows_, memdir)
        s["constant_fields"] = {
            k: v["values"][0] for k, v in var["fields"].items()
            if v["constant"] and v["seen"] >= 3 and responses.DECISIVE_RE.search(k)}
    except Exception:  # noqa: BLE001
        s["constant_fields"] = {}
    return s


def render(s: Dict) -> str:
    lines = [f"RECALL {s['route']}: {s['requests']} earlier requests."]
    for m, d in sorted(s["methods"].items()):
        st = ", ".join(f"{k}x{v}" for k, v in sorted(d["statuses"].items())) or "status n/a"
        lines.append(f"  {m}: {d['n']} sent, {st}, {d['distinct_bodies']} distinct bodies")
    if s["constant_fields"]:
        cf = ", ".join(f"{k}={v}" for k, v in list(s["constant_fields"].items())[:3])
        lines.append(f"  never moved: {cf} - a boolean that ignores input is a stub, not an oracle")
    if s["untried"]:
        lines.append("  not tried here yet: " + "; ".join(s["untried"][:5]))
    lines.append("  repeat only if the request below differs in one of those.")
    return "\n".join(lines)
