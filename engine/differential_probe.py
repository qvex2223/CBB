#!/usr/bin/env python3
"""differential_probe.py — detection-only parser-differential census for ONE URL.

Two components reading one string differently (CDN vs origin, proxy vs app,
router vs filesystem) produced every Critical in the 2024-26 research corpus
(docs/disclosed-reports/HIGH-CRIT-LESSONS-2026-11.md). This fires a small,
fixed set of GET variants through `scripts/bbcurl` (scope, pacing, mandatory
headers, audit, response corpus all apply), compares each against a baseline
and an impossible-path control, and reports only the variants that diverge from
BOTH. It never sends a body, never desyncs, never changes state.

Axes:
  * header: X-Forwarded-Host / X-Original-URL / X-Rewrite-URL / Host trailing dot
    (a random marker; an echo of it is a host-header / routing lead)
  * path:   ;suffix, /..;/, %2f, //, .json, uppercase, trailing slash
  * layer:  `Server` / `Via` / cache headers changing between variants means a
    different component answered: that is the differential.

    cbh diffprobe https://app.example.com/account          # engagement from cwd/$CBH_PROJECT
    cbh diffprobe --project ozon https://www.ozon.ru/my/ --json

Fires ~14 requests; at the engagement's pacing that is the whole cost.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

HERE = Path(__file__).resolve().parent
BBCURL = HERE.parent / "scripts" / "bbcurl"
LAYER_HEADERS = ("server", "via", "x-cache", "cf-cache-status", "age", "x-served-by",
                 "x-powered-by", "x-backend", "x-upstream", "location", "cache-control")


def variants(url: str, marker: str) -> List[Dict]:
    sp = urlsplit(url)
    path = sp.path or "/"
    base = path.rstrip("/") or ""

    def u(p: str) -> str:
        return urlunsplit((sp.scheme, sp.netloc, p, sp.query, ""))
    host = sp.hostname or ""
    v = [
        {"name": "baseline", "url": url, "headers": []},
        {"name": "baseline-repeat", "url": url, "headers": []},
        {"name": "control-impossible-path", "url": u(f"{base}/{marker}-nope"), "headers": [], "control": True},
        {"name": "hdr:x-forwarded-host", "url": url, "headers": [f"X-Forwarded-Host: {marker}.invalid"]},
        {"name": "hdr:x-original-url", "url": url, "headers": [f"X-Original-URL: /{marker}"]},
        {"name": "hdr:x-rewrite-url", "url": url, "headers": [f"X-Rewrite-URL: /{marker}"]},
        {"name": "hdr:host-trailing-dot", "url": url, "headers": [f"Host: {host}."]},
        {"name": "path:semicolon", "url": u(f"{path};{marker}"), "headers": []},
        {"name": "path:dotdot-semicolon", "url": u(f"{base}/..;/{path.lstrip('/')}"), "headers": []},
        {"name": "path:encoded-slash", "url": u(f"{base}%2f{marker}"), "headers": []},
        {"name": "path:double-slash", "url": u(f"/{path}" if path.startswith("/") else f"//{path}"), "headers": []},
        {"name": "path:json-suffix", "url": u(f"{base}.json"), "headers": []},
        {"name": "path:uppercase", "url": u(path.upper()), "headers": []},
        {"name": "path:trailing-slash-flip", "url": u(base if path.endswith("/") else f"{path}/"), "headers": []},
    ]
    return v


def _parse_headers(raw: str) -> Dict[str, str]:
    """Headers of the LAST response block (curl -D writes every hop)."""
    blocks = [b for b in raw.replace("\r\n", "\n").split("\n\n") if b.strip().startswith("HTTP/")]
    out: Dict[str, str] = {}
    if not blocks:
        return out
    lines = blocks[-1].split("\n")
    out[":status-line"] = lines[0].strip()
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


def fire(v: Dict, env: Dict) -> Dict:
    with tempfile.TemporaryDirectory(prefix="cbh-diffprobe-") as d:
        hdr, body = Path(d) / "h.txt", Path(d) / "b.bin"
        cmd = [str(BBCURL), "-s", "-g", "--path-as-is", "--max-time", "20", "-D", str(hdr),
               "-o", str(body), "-w", "%{http_code}"]
        for h in v["headers"]:
            cmd += ["-H", h]
        cmd.append(v["url"])
        t0 = time.time()
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
            code, rc, err = p.stdout.strip()[-3:], p.returncode, p.stderr.strip()[-300:]
        except subprocess.TimeoutExpired:
            code, rc, err = "000", 124, "timeout"
        data = body.read_bytes() if body.exists() else b""
        headers = _parse_headers(hdr.read_text(errors="replace")) if hdr.exists() else {}
    return {**{k: v[k] for k in ("name", "url", "headers")}, "control": bool(v.get("control")),
            "status": code, "exit": rc, "bytes": len(data),
            "sha": hashlib.sha256(data).hexdigest()[:16], "elapsed": round(time.time() - t0, 2),
            "layer": {k: headers[k] for k in LAYER_HEADERS if k in headers},
            "marker_echo": False if not data else None, "_body": data, "stderr": err if rc else ""}


def judge(results: List[Dict], marker: str) -> Dict:
    base = next(r for r in results if r["name"] == "baseline")
    rep = next((r for r in results if r["name"] == "baseline-repeat"), base)
    ctrl = next((r for r in results if r.get("control")), None)
    stable = base["sha"] == rep["sha"]
    flags = []
    if ctrl is not None:  # does even the impossible path echo the marker? then echo is no signal
        ctrl_body = ctrl.get("_body", b"")
        ctrl["marker_echo"] = marker.encode() in ctrl_body or marker in ctrl["layer"].get("location", "")
    echo_is_noise = bool(ctrl and ctrl.get("marker_echo"))
    for r in results:
        body = r.pop("_body", b"")
        loc = r["layer"].get("location", "")
        r["marker_echo"] = marker.encode() in body or marker in loc
        if r["name"] in ("baseline", "baseline-repeat") or r.get("control"):
            continue
        if r["exit"] not in (0,) or r["status"] in ("000", ""):
            r["verdict"] = "NOT-MEASURED"
            continue
        same_base = r["status"] == base["status"] and (r["sha"] == base["sha"] or
                                                       (not stable and abs(r["bytes"] - base["bytes"]) < 64))
        same_ctrl = ctrl is not None and r["status"] == ctrl["status"] and abs(r["bytes"] - ctrl["bytes"]) < 64
        layer_moved = any(r["layer"].get(k) != base["layer"].get(k)
                          for k in ("server", "via", "x-served-by", "x-backend", "x-upstream"))
        why = []
        if r["marker_echo"] and not echo_is_noise:
            why.append("random marker echoed (body/Location): the value reached a component that uses it")
        if layer_moved:
            why.append("a different layer answered (Server/Via changed)")
        if not same_base and not same_ctrl:
            why.append(f"diverges from baseline ({base['status']}/{base['bytes']}b) AND from the impossible-path "
                       f"control ({ctrl['status'] if ctrl else '?'}/{ctrl['bytes'] if ctrl else '?'}b)")
        r["verdict"] = "LEAD" if why else ("same-as-baseline" if same_base else "same-as-control")
        r["why"] = why
        if why:
            flags.append(r)
    return {"baseline_stable": stable, "echo_is_noise": echo_is_noise,
            "leads": [f["name"] for f in flags], "results": results,
            "next": ("each LEAD is a parser-differential hypothesis, not a finding: name the two components, "
                     "then prove an effect (an auth check skipped, a cache entry written, a route reached) "
                     "with a control (hunt-differential / hunt-header-injection / hunt-cache-poison). "
                     "No desync without programme approval.") if flags else
                    "no divergence on these axes — log the vector as tried with this file, rotate"}


def run(url: str, project: Optional[str] = None, out_dir: Optional[Path] = None) -> Dict:
    env = dict(os.environ)
    if project:
        env["CBH_PROJECT"] = project
    marker = "cbh" + secrets.token_hex(4)
    results = [fire(v, env) for v in variants(url, marker)]
    rep = {"url": url, "marker": marker, "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **judge(results, marker)}
    refused = [r for r in rep["results"] if r["exit"] == 3]
    if refused and len(refused) == len(rep["results"]):
        rep["refused"] = "bbcurl refused every request (scope/engagement gate) — " + refused[0]["stderr"]
    # a run where nothing actually flew must never read as "no divergence": any
    # non-zero exit or empty status means the variant was not measured, and a report
    # of all-unmeasured variants is a refusal, not a negative result.
    unmeasured = [r for r in rep["results"] if r["exit"] != 0 or r["status"] in ("000", "")]
    if not rep.get("refused") and unmeasured and len(unmeasured) == len(rep["results"]):
        rep["refused"] = ("no variant was measured (every request failed or returned no status) — "
                          + (unmeasured[0]["stderr"] or "see exit codes in results"))
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        host = urlsplit(url).hostname or "host"
        dest = out_dir / f"{host}-{time.strftime('%Y%m%d-%H%M%S')}.json"
        dest.write_text(json.dumps(rep, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        rep["written"] = str(dest)
    return rep


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="diffprobe", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--project", help="engagement (platform/program or bare name)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    project = a.project
    out_dir = None
    try:
        sys.path.insert(0, str(HERE))
        from surface_census import project_dir  # type: ignore
        pdir = project_dir(project)
        if pdir:
            # the engagement name bbcurl understands is the path RELATIVE TO Targets/,
            # i.e. "ncste" or "standoff365/ozon" — never "Targets/ncste", which
            # Engagement.detect() cannot resolve and which made every variant exit 3.
            from paths import targets_root  # type: ignore
            try:
                project = str(pdir.resolve().relative_to(targets_root().resolve()))
            except Exception:  # noqa: BLE001
                project = pdir.name
            out_dir = pdir / "recon" / "differential"
    except Exception:  # noqa: BLE001
        pass
    rep = run(a.url, project, out_dir)
    if a.json:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0
    if rep.get("refused"):
        print(rep["refused"], file=sys.stderr)
        return 3
    print(f"diffprobe {rep['url']}  marker={rep['marker']}  baseline stable={rep['baseline_stable']}")
    for r in rep["results"]:
        lay = r["layer"].get("server", "")
        print(f"  {r.get('verdict', '-'):17s} {r['name']:26s} {r['status']} {r['bytes']:>7}b  "
              f"{r['sha']}  {lay[:24]}" + (f"  <- {'; '.join(r.get('why', []))}" if r.get("why") else ""))
    print(f"\n{rep['next']}")
    if rep.get("written"):
        print(f"written: {rep['written']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
