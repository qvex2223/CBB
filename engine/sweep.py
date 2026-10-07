#!/usr/bin/env python3
"""
sweep.py — fire the differential plan and judge it, with no model in the loop.

`diff_matrix.plan()` already says what to compare (baseline vs probe per axis) but
nothing executed it, so every comparison cost a model turn and most never happened.
This runs the rows through `RequestBroker` — scope, pacing, mandatory headers, audit
and the response corpus all apply, same as bbcurl — then classifies each pair with
fixed rules. The model reads only the anomalies.

Safety, in order of strictness:
  * scope and pacing come from the broker; an out-of-scope URL raises, never fires
  * a probe whose method can change state (anything but GET/HEAD/OPTIONS) is skipped
    unless the engagement profile sets `allow_write_probes: true`; destructive-looking
    paths (delete/remove/revoke/...) are skipped even then
  * rows with unresolved `{{PLACEHOLDER}}`s are listed under `needs_input`, never sent
    with the literal braces; credentials come from env `CBH_<NAME>` (`{{TOKEN_A}}` ->
    `CBH_TOKEN_A`)
  * hard cap on rows per run (`--limit`, default 40), stops on 3 consecutive transport
    failures

CLI:
    python3 engine/sweep.py manifest.json [--axes a,b] [--hosts h1,h2] [--limit 40] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import diff_matrix  # noqa: E402
from request_broker import RequestBlocked, RequestBroker  # noqa: E402

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PLACEHOLDER = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
MAX_BODY = 256 * 1024
ERROR_MARKERS = re.compile(
    r"(?i)(traceback \(most recent|stack trace|at [\w.$]+\([\w.]+\.java:\d+\)|"
    r"sqlstate|syntax error at|ora-\d{4,5}|you have an error in your sql|"
    r"unhandled exception|nullpointerexception|internal server error.{0,40}(file|line))")
DESTRUCTIVE = diff_matrix.ACTION_WORDS


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):  # a 302 is an answer, not a detour
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)
_INSECURE_OPENER = None


def _opener(insecure: bool):
    """Verified TLS by default. `--insecure` is per-run and still scope-gated: the broker
    rejects an out-of-scope URL before any socket opens."""
    global _INSECURE_OPENER
    if not insecure:
        return _OPENER
    if _INSECURE_OPENER is None:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _INSECURE_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    return _INSECURE_OPENER


def resolve(spec: dict, env=None) -> tuple[Optional[dict], List[str]]:
    """Substitute {{NAME}} from CBH_NAME. Returns (spec or None, missing names)."""
    env = os.environ if env is None else env
    missing: List[str] = []

    def sub(text):
        def one(m):
            val = env.get("CBH_" + m.group(1))
            if val is None:
                missing.append(m.group(1))
                return m.group(0)
            return val
        return PLACEHOLDER.sub(one, text) if isinstance(text, str) else text

    out = {"method": spec["method"], "url": sub(spec["url"]),
           "headers": {k: sub(v) for k, v in (spec.get("headers") or {}).items()},
           "body": sub(spec.get("body"))}
    return (None if missing else out), sorted(set(missing))


def fire(broker: RequestBroker, spec: dict, timeout: float = 25.0, insecure: bool = False) -> dict:
    headers, _ = broker.before_request(spec["url"], spec.get("headers"))
    body = spec.get("body")
    data = body.encode() if isinstance(body, str) else None
    req = urllib.request.Request(spec["url"], data=data, method=spec["method"], headers=headers)
    t0 = time.time()
    try:
        with _opener(insecure).open(req, timeout=timeout) as r:
            status, rh, raw = r.status, dict(r.headers), r.read(MAX_BODY)
    except urllib.error.HTTPError as e:
        status, rh, raw = e.code, dict(e.headers), e.read(MAX_BODY)
    elapsed = (time.time() - t0) * 1000
    try:
        broker.record_response(spec["url"], spec["method"], status, raw, rh, elapsed)
    except Exception:  # noqa: BLE001 - capture failing must not lose the observation
        pass
    return {"status": status, "headers": rh, "body": raw.decode("utf-8", "replace"),
            "bytes": len(raw), "ms": round(elapsed)}


def _keys(body: str) -> set:
    try:
        doc = json.loads(body)
    except Exception:  # noqa: BLE001
        return set()
    out: set = set()

    def walk(o, p=""):
        if isinstance(o, dict):
            for k, v in o.items():
                out.add(f"{p}.{k}" if p else k)
                walk(v, f"{p}.{k}" if p else k)
        elif isinstance(o, list) and o:
            walk(o[0], p + "[]")
    walk(doc)
    return out


def classify(axis: str, base: dict, probe: dict) -> Optional[dict]:
    """A finding-candidate for this pair, or None. Rules are deliberately blunt."""
    bs, ps = base["status"], probe["status"]
    same_body = base["body"] == probe["body"]
    ok = lambda s: 200 <= s < 300  # noqa: E731
    if ERROR_MARKERS.search(probe["body"]) and not ERROR_MARKERS.search(base["body"]):
        return {"kind": "ERROR-DISCLOSURE", "why": "probe body carries a stack trace / SQL / exception marker the baseline did not"}
    if ps >= 500 and bs < 500:
        return {"kind": "SERVER-ERROR", "why": f"probe 5xx ({ps}) where baseline was {bs}: input reached code that did not expect it"}
    if axis == "auth-strip" and ok(ps) and (ok(bs) or same_body):
        return {"kind": "AUTH-NOT-ENFORCED", "why": f"same call without credentials answered {ps}"
                + (" with the identical body" if same_body else "")}
    if axis == "method-swap" and ok(ps) and ps not in (204,):
        return {"kind": "UNEXPECTED-METHOD", "why": f"{probe.get('method','alt')} on a {base.get('method','declared')} route answered {ps}"}
    if axis == "path-version" and ok(ps) and not ok(bs):
        return {"kind": "OLD-VERSION-REACHABLE", "why": f"older API version answered {ps}; current answered {bs}"}
    if axis in ("identity-headers", "principal-swap") and ok(ps) and not same_body and ok(bs):
        return {"kind": "IDENTITY-CHANGED-ANSWER", "why": "injected identity/principal changed the body of an otherwise identical call"}
    if axis == "hidden-field" and ok(ps) and _keys(probe["body"]) - _keys(base["body"]):
        return {"kind": "FIELD-ACCEPTED", "why": "extra field changed the response shape: " +
                ", ".join(sorted(_keys(probe["body"]) - _keys(base["body"]))[:5])}
    if axis in ("content-type", "param-pollution", "garbage-input", "value-boundary") and ok(ps) and not ok(bs):
        return {"kind": "VALIDATION-BYPASS", "why": f"probe accepted ({ps}) where baseline was rejected ({bs})"}
    return None


AUTH_PLACEHOLDERS = {"TOKEN", "SESSION"}
HTML_RE = re.compile(r"(?is)^\s*(<!doctype html|<html)")


def _control_url(url: str) -> str:
    from urllib.parse import urlsplit, urlunsplit
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "/cbh-nx-" + str(abs(hash(p.netloc)) % 99991), "", ""))


def classify_unauth(probe: dict, control: Optional[dict]) -> Optional[dict]:
    """Credential-free call that answered with data. The control is a random sibling
    path: if it returns the same body, the host serves a catch-all shell, not data."""
    if not 200 <= probe["status"] < 300 or probe["bytes"] < 20:
        return None
    if HTML_RE.match(probe["body"]):
        return None
    if control is not None and (control["body"] == probe["body"] or control["status"] == probe["status"] and
                                abs(control["bytes"] - probe["bytes"]) < 8):
        return None
    ctype = (probe["headers"].get("Content-Type") or probe["headers"].get("content-type") or "").lower()
    if "json" not in ctype and not probe["body"].lstrip().startswith(("{", "[")):
        return None
    return {"kind": "UNAUTH-DATA", "why": f"no credentials, {probe['status']}, {probe['bytes']}B of JSON; "
            "a random sibling path on the same host answered differently, so this is not a catch-all"}


def classify_options(allow: str, declared: str) -> Optional[dict]:
    extra = sorted(m for m in ("PUT", "PATCH", "DELETE", "POST") if m in allow.upper() and m != declared)
    if declared == "GET" and extra:
        return {"kind": "METHODS-ADVERTISED", "why": f"OPTIONS Allow lists {', '.join(extra)} on a GET-declared route "
                "(write probe not fired: profile allow_write_probes is off)"}
    return None


SKIP_PATH = re.compile(r"(?i)camunda|sim\b|esim|utm|subscri|payment|topup|charge|otp|sms|\bpin\b|"
                       r"delete|register|logout|reset|checkout|order")
APIISH = re.compile(r"(?i)/(api|v\d+|rest|graphql)(/|$)")


def manifest_from_audit(engagement: str, memdir=None, limit: int = 60) -> dict:
    """Operations seen on the wire, each with the method it was actually sent with.

    Building from traffic rather than assuming GET is what keeps `method-swap` honest:
    an endpoint observed answering POST is not a GET route that "also allows POST".
    Query-string URLs, non-API paths and money/SIM/OTP-looking paths are left out.
    """
    import recall
    import responses
    from urllib.parse import urlsplit
    ops: Dict[tuple, dict] = {}
    for r in responses.rows("", engagement, memdir=memdir):
        code = r.get("http_code")
        if not r.get("urls") or (code and code >= 500):
            continue
        url = r["urls"][0]
        p = urlsplit(url)
        if p.query or not APIISH.search(p.path) or SKIP_PATH.search(p.path):
            continue
        method = recall._method(r)
        key = (method, recall.route_of(url))
        op = ops.get(key)
        if op is None:
            op = ops[key] = {"id": f"a{len(ops)}", "method": method, "url": url, "host": p.hostname,
                             "path": p.path, "secured": None, "risk_hints": [], "fields": [],
                             "parameters": [], "source": "audit"}
        req = r.get("req") or []
        for i, a in enumerate(req):
            if a in ("-d", "--data", "--data-raw") and i + 1 < len(req):
                try:
                    doc = json.loads(req[i + 1])
                    if isinstance(doc, dict):
                        op["fields"] = sorted(set(op["fields"]) | set(doc))
                except Exception:  # noqa: BLE001
                    pass
    return {"schema_version": "2.0", "target": engagement, "operations": list(ops.values())[:limit]}


def run(manifest: dict, *, axes=None, hosts=None, limit: int = 40, dry_run: bool = False,
        broker: Optional[RequestBroker] = None, audit_urls=None, fire_fn=None, insecure: bool = False) -> dict:
    broker = broker or RequestBroker.detect(source="sweep")
    fire_fn = fire_fn or (lambda spec: fire(broker, spec, insecure=insecure))
    pl = diff_matrix.plan(manifest, axes=axes, only_hosts=hosts, audit_urls=audit_urls)
    out = {"planned": len(pl["comparisons"]), "fired": 0, "anomalies": [], "negatives": 0,
           "skipped": [], "needs_input": [], "errors": []}
    consecutive_fail = 0
    controls: Dict[str, dict] = {}
    for row in pl["comparisons"]:
        if row.get("already_fired"):
            out["skipped"].append({"op": row["operation_id"], "axis": row["axis"], "why": "already fired"})
            continue
        if out["fired"] >= limit:
            break
        probe_m = row["probe"]["method"]
        if probe_m not in SAFE_METHODS and (not broker.allow_writes or DESTRUCTIVE.search(row["path"])):
            if row["axis"] == "method-swap" and not dry_run:
                try:
                    o = fire_fn({"method": "OPTIONS", "url": row["probe"]["url"], "headers": {}, "body": None})
                    out["fired"] += 1
                    hit = classify_options(o["headers"].get("Allow") or o["headers"].get("allow") or "",
                                           row["baseline"]["method"])
                    if hit:
                        out["anomalies"].append({"op": row["operation_id"], "axis": "method-swap", "host": row["host"],
                                                 "path": row["path"], "url": row["probe"]["url"],
                                                 "baseline_status": "-", "probe_status": o["status"],
                                                 "baseline_bytes": 0, "probe_bytes": o["bytes"],
                                                 "priority": row["priority"], **hit,
                                                 "next": "reproduce with bbcurl, then /validate; a sweep hit is a lead, not a finding"})
                    else:
                        out["negatives"] += 1
                    continue
                except RequestBlocked as e:
                    out["skipped"].append({"op": row["operation_id"], "axis": row["axis"], "why": str(e)})
                    continue
                except Exception as e:  # noqa: BLE001
                    out["errors"].append({"op": row["operation_id"], "axis": "method-swap", "error": str(e)[:200]})
                    continue
            out["skipped"].append({"op": row["operation_id"], "axis": row["axis"],
                                   "why": f"{probe_m} probe can change state (profile allow_write_probes off or destructive path)"})
            continue
        base, miss_b = resolve(row["baseline"])
        probe, miss_p = resolve(row["probe"])
        # No credentials to build the authenticated side: the unauthenticated half is
        # still a real question ("does this answer with data for nobody?").
        if (row["axis"] == "auth-strip" and probe is not None and base is None
                and set(miss_b) <= AUTH_PLACEHOLDERS and row["probe"]["method"] in SAFE_METHODS):
            if dry_run:
                out["fired"] += 1
                continue
            try:
                p = fire_fn(probe)
                ctl = controls.get(probe["url"].split("/", 3)[2])
                if ctl is None:
                    ctl = controls[probe["url"].split("/", 3)[2]] = fire_fn(
                        {"method": "GET", "url": _control_url(probe["url"]), "headers": {}, "body": None})
                out["fired"] += 1
                hit = classify_unauth(p, ctl)
                if hit:
                    out["anomalies"].append({"op": row["operation_id"], "axis": "auth-strip", "host": row["host"],
                                             "path": row["path"], "url": probe["url"], "baseline_status": "-",
                                             "probe_status": p["status"], "baseline_bytes": 0, "probe_bytes": p["bytes"],
                                             "priority": row["priority"], **hit,
                                             "next": "reproduce with bbcurl, then /validate; confirm the data is not public by design"})
                else:
                    out["negatives"] += 1
            except RequestBlocked as e:
                out["skipped"].append({"op": row["operation_id"], "axis": row["axis"], "why": str(e)})
            except Exception as e:  # noqa: BLE001
                out["errors"].append({"op": row["operation_id"], "axis": "auth-strip", "error": str(e)[:200]})
            continue
        if base is None or probe is None:
            out["needs_input"].append({"op": row["operation_id"], "axis": row["axis"],
                                       "env": ["CBH_" + n for n in sorted(set(miss_b + miss_p))]})
            continue
        if dry_run:
            out["fired"] += 1
            continue
        try:
            b = fire_fn(base)
            p = fire_fn(probe)
            consecutive_fail = 0
        except RequestBlocked as e:
            out["skipped"].append({"op": row["operation_id"], "axis": row["axis"], "why": str(e)})
            continue
        except Exception as e:  # noqa: BLE001
            consecutive_fail += 1
            out["errors"].append({"op": row["operation_id"], "axis": row["axis"], "error": str(e)[:200]})
            if consecutive_fail >= 3:
                out["errors"].append({"stopped": "3 consecutive transport failures"})
                break
            continue
        out["fired"] += 1
        b["method"], p["method"] = base["method"], probe["method"]
        hit = classify(row["axis"], b, p)
        if hit is None:
            out["negatives"] += 1
            continue
        out["anomalies"].append({
            "op": row["operation_id"], "axis": row["axis"], "host": row["host"], "path": row["path"],
            "url": probe["url"], "baseline_status": b["status"], "probe_status": p["status"],
            "baseline_bytes": b["bytes"], "probe_bytes": p["bytes"],
            "priority": row["priority"], **hit,
            "next": "reproduce with bbcurl, then /validate; a sweep hit is a lead, not a finding"})
    out["anomalies"].sort(key=lambda a: -a["priority"])
    return out


def seed_ledger(result: dict, target: str) -> int:
    """Put each anomaly in the vector ledger so `vectors next` ranks it."""
    import vectors
    ledger = vectors.load(target)
    known = {v["id"] for v in ledger["vectors"]}
    cls = {"AUTH-NOT-ENFORCED": "missing_authorization", "UNEXPECTED-METHOD": "auth-bypass",
           "OLD-VERSION-REACHABLE": "api-misconfig", "IDENTITY-CHANGED-ANSWER": "idor",
           "FIELD-ACCEPTED": "api-misconfig", "VALIDATION-BYPASS": "api-misconfig",
           "ERROR-DISCLOSURE": "sqli", "SERVER-ERROR": "sqli"}
    added = 0
    for a in result["anomalies"]:
        c = cls.get(a["kind"], "api-misconfig")
        vid = vectors.vector_id(c, a["path"])
        if vid in known:
            continue
        v = vectors._new_vector(c, a["path"], origin="sweep", reason=f"{a['kind']}: {a['why']}")
        ledger["vectors"].append(v)
        known.add(vid)
        added += 1
    if added:
        vectors.save(ledger)
    return added


def load_env_file(path: Path) -> List[str]:
    """KEY=VALUE lines from the engagement's `.sweep-env` into CBH_<KEY> (never overriding
    the real environment). The file holds live session tokens, so a group/world-readable
    one is refused rather than read."""
    if not path.is_file():
        return []
    if path.stat().st_mode & 0o077:
        raise SystemExit(f"{path}: holds credentials but is readable by others - chmod 600 it")
    names = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().upper().removeprefix("CBH_")
        os.environ.setdefault("CBH_" + k, v.strip().strip("\"'"))
        names.append("CBH_" + k)
    return names


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("manifest", nargs="?", help="manifest.json, or audit:<engagement> to build it from traffic already sent")
    ap.add_argument("--from-audit", metavar="ENGAGEMENT", help="build the manifest from requests already sent")
    ap.add_argument("--axes", default="")
    ap.add_argument("--hosts", default="")
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed in-scope hosts)")
    ap.add_argument("--seed", metavar="TARGET", help="add anomalies to this target's vector ledger")
    ap.add_argument("--out", help="write full JSON result here")
    a = ap.parse_args(argv)
    if a.manifest and a.manifest.startswith("audit:"):  # `cbh sweep audit:kcell` — a leading flag breaks the CLI passthrough
        a.from_audit, a.manifest = a.manifest[6:], None
    if a.from_audit:
        manifest = manifest_from_audit(a.from_audit)
    elif a.manifest:
        manifest = json.loads(Path(a.manifest).read_text())
    else:
        ap.error("give a manifest or --from-audit ENGAGEMENT")
    try:
        from pacing import find_project_dir
        proj = find_project_dir()
        if proj:
            got = load_env_file(Path(proj) / ".sweep-env")
            if got:
                print(f"credentials loaded: {', '.join(got)}")
    except ImportError:
        pass
    res = run(manifest, axes=[x for x in a.axes.split(",") if x] or None,
              hosts=[x for x in a.hosts.split(",") if x] or None,
              limit=a.limit, dry_run=a.dry_run, insecure=a.insecure)
    if a.seed and not a.dry_run:
        res["seeded"] = seed_ledger(res, a.seed)
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"planned {res['planned']}  fired {res['fired']}  anomalies {len(res['anomalies'])}  "
          f"clean {res['negatives']}  skipped {len(res['skipped'])}  needs_input {len(res['needs_input'])}")
    for x in res["anomalies"]:
        print(f"  [{x['kind']}] {x['axis']} {x['url']}  {x['baseline_status']}->{x['probe_status']}  {x['why']}")
    for x in res["needs_input"][:5]:
        print(f"  needs {', '.join(x['env'])} for {x['axis']} {x['op']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
