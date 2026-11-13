#!/usr/bin/env python3
"""surface_census.py — find the three surfaces disclosed crit/high reports keep using.

Offline. It reads what the engagement already has (API manifests, the audit log of
fired URLs, the response corpus, downloaded recon files) and sends nothing.

  1. **sibling interfaces**: one resource reachable through two or more interfaces
     (REST, GraphQL, mobile/partner host, Next.js Server Action, websocket, legacy
     version). The authorization check usually lives on only one of them; this was
     the most frequent crit/high root cause in 2025-26 write-ups.
  2. **server-side fetchers**: parameters and routes that make the server fetch or
     render a URL or file (url=, webhook, import, preview, pdf, screenshot, avatar).
     These are SSRF, and the payout depends on reaching a credentials read.
  3. **secret leads**: vendor-prefixed credentials in recon files (raw), or in the
     response corpus (masked there, but the location survives). Validation plus a
     scope map is the finding; the two top payouts in the H1 corpus were exactly this.

`--seed` writes each item into the vector ledger (`sibling-interface`, `ssrf` with
reason `server-side-fetcher`, `secret-exposure`), so `vectors.py next` ranks them like
any other vector and the hunt picks them up without the operator.

    cbh census                       # engagement from cwd / $CBH_PROJECT
    cbh census --project ozon --seed
    cbh census --json

Source: docs/disclosed-reports/HIGH-CRIT-LESSONS-2026-11.md
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

FETCH_PARAM_RE = re.compile(
    r"(?i)^(url|uri|link|src|source|href|callback(_url)?|webhook(_url)?|hook|endpoint|target|"
    r"dest(ination)?_url|feed|rss|import(_url)?|fetch|proxy|image(_url)?|img(_url)?|avatar(_url)?|"
    r"logo(_url)?|icon(_url)?|picture|photo_url|file_url|document_url|pdf(_url)?|template_url|"
    r"remote(_\w+)?_url|site|domain|host|server|preview(_url)?|oembed|unfurl|redirect_to_fetch|"
    r"\w+_url|\w+Url|\w+_uri|\w+Uri)$")
# common non-fetching *_url params that would drown the list
FETCH_PARAM_DENY = re.compile(r"(?i)^(return_?url|redirect_?url|redirect_?uri|next_?url|back_?url|"
                              r"success_?url|cancel_?url|fail(ure)?_?url|continue_?url|login_?url|"
                              r"logout_?url|post_logout_redirect_uri|referr?er_?url|canonical_?url)$")
# A route alone counts only when its name says it fetches or renders. `webhook` is
# deliberately absent: a webhook RECEIVER takes inbound calls; only a webhook *test*
# or a url-shaped parameter makes the server fetch (field test 2026-11-02).
FETCH_PATH_RE = re.compile(
    r"(?i)/(import-?url|fetch|proxy|preview|render|pdf|screenshot|snapshot|thumbnail|"
    r"webhooks?/test|test-?webhook|oembed|unfurl|link-?preview|crawl|scrape|download-?url|url-?to|"
    r"html-?to|export-?pdf|url-?import|remote-?fetch)(/|$|\?)")

INTERFACE_HOST_RE = re.compile(r"(?i)^(m|mobile|app|api-?m|ios|android|partner|partners|b2b|"
                               r"internal|admin|backoffice|staff|corp)[.-]")
VERSION_RE = re.compile(r"(?i)^v\d+(\.\d+)?$")
ID_SEG_RE = re.compile(r"^(\{[^}]+\}|:\w+|\d+|[0-9a-f]{8,}|[0-9a-f-]{32,36})$", re.I)
STOP_SEGS = {"api", "rest", "graphql", "gql", "public", "private", "internal", "external",
             "mobile", "app", "web", "service", "services", "svc", "rpc", "json", "ajax", "_next",
             "data", "action", "actions", "", "me", "my", "self", "current"}
VERBS = ("get", "list", "fetch", "find", "search", "create", "add", "new", "update", "edit",
         "set", "patch", "delete", "remove", "upsert", "save", "query", "mutation", "all", "by")
SINGULAR = re.compile(r"(ies|ses|s)$")


# ---------------------------------------------------------------------------
# engagement + inputs
# ---------------------------------------------------------------------------
def project_dir(name: Optional[str] = None) -> Optional[Path]:
    if name and "/" not in name:
        # nested engagements are platform/program; accept the bare program name
        try:
            from paths import targets_root  # type: ignore
            root = targets_root()
            hits = [p.parent for p in root.glob(f"*/{name}/scope.md")] + \
                   [p.parent for p in root.glob(f"{name}/scope.md")]
            if len(hits) == 1:
                name = str(hits[0].relative_to(root))
        except Exception:  # noqa: BLE001
            pass
    if name:
        os.environ["CBH_PROJECT"] = name
    try:
        from pacing import find_project_dir  # type: ignore
        return find_project_dir()
    except Exception:  # noqa: BLE001
        return None


def load_manifests(pdir: Path) -> List[Dict]:
    ops: List[Dict] = []
    seen = set()
    recon = pdir / "recon"
    if not recon.is_dir():
        return ops
    for p in sorted(recon.rglob("*.json")):
        if "manifest" not in p.name or p.stat().st_size > 50_000_000:
            continue
        try:
            doc = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        for op in (doc.get("operations") or []) if isinstance(doc, dict) else []:
            key = op.get("id") or (op.get("method"), op.get("url"))
            if key in seen:
                continue
            seen.add(key)
            ops.append(op)
    return ops


def audit_urls(engagement: str, memdir: Optional[Path] = None) -> List[Tuple[str, str]]:
    """(method, url) pairs this engagement actually fired, from audit.jsonl."""
    try:
        from responses import _memdir, _tail_jsonl  # type: ignore
        rows = _tail_jsonl(_memdir(memdir) / "audit.jsonl", 200_000)
    except Exception:  # noqa: BLE001
        return []
    out = []
    want = engagement.split("/")[-1]
    for r in rows:
        if str(r.get("engagement") or "").split("/")[-1] != want:
            continue
        for u in r.get("urls") or []:
            out.append((str(r.get("method") or "GET").upper(), u))
    return out


# ---------------------------------------------------------------------------
# 1. sibling interfaces
# ---------------------------------------------------------------------------
def _singular(w: str) -> str:
    return SINGULAR.sub("", w) if len(w) > 4 else w


def _camel_tokens(name: str) -> List[str]:
    parts = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name).replace("_", " ").replace("-", " ").lower()
    return [p for p in parts.split() if p and p not in VERBS]


def interface_of(op: Dict) -> str:
    path = str(op.get("path") or urlsplit(str(op.get("url") or "")).path).lower()
    host = str(op.get("host") or urlsplit(str(op.get("url") or "")).hostname or "").lower()
    meta = json.dumps(op.get("metadata") or {}).lower()
    if "graphql" in path or "gql" in path.split("/") or op.get("operation_name") and "graphql" in meta:
        return "graphql"
    if "next-action" in meta or "server-action" in meta or "server_action" in meta:
        return "server-action"
    if str(op.get("url") or "").startswith(("ws://", "wss://")) or "websocket" in meta:
        return "websocket"
    if INTERFACE_HOST_RE.match(host) or "/mobile/" in path or "/m/" in path[:4]:
        return "mobile/partner:" + host.split(".")[0] if INTERFACE_HOST_RE.match(host) else "mobile"
    segs = [s for s in path.split("/") if s]
    ver = next((s for s in segs if VERSION_RE.match(s)), "")
    return f"rest{(':' + ver) if ver else ''}"


def resource_of(op: Dict) -> str:
    name = str(op.get("operation_name") or "")
    if name:
        toks = _camel_tokens(name)
        if toks:  # refundOrder / getOrderById -> the object noun is last: order
            toks = [t for t in toks if t not in ("id", "ids")] or toks
            return _singular(toks[-1])
    path = str(op.get("path") or urlsplit(str(op.get("url") or "")).path)
    raw = [s for s in path.split("/") if s]
    # the noun right before an id is the object: /v2/orders/{id}/refund -> order
    for i in range(len(raw) - 1, 0, -1):
        if ID_SEG_RE.match(raw[i]) and raw[i - 1].lower() not in STOP_SEGS \
                and not VERSION_RE.match(raw[i - 1]):
            return _singular(re.sub(r"[^a-z0-9]", "", raw[i - 1].lower()) or raw[i - 1].lower())
    segs = [s.lower() for s in raw
            if not ID_SEG_RE.match(s) and not VERSION_RE.match(s) and s.lower() not in STOP_SEGS]
    if not segs:
        return ""
    return _singular(re.sub(r"[^a-z0-9]", "", segs[-1]) or segs[-1])


def sibling_interfaces(ops: Iterable[Dict]) -> List[Dict]:
    groups: Dict[str, Dict[str, List[Dict]]] = defaultdict(lambda: defaultdict(list))
    for op in ops:
        res = resource_of(op)
        if not res or len(res) < 3:
            continue
        groups[res][interface_of(op)].append(op)
    out = []
    for res, by_iface in groups.items():
        if len(by_iface) < 2:
            continue
        ops_all = [o for lst in by_iface.values() for o in lst]
        privileged = [o for o in ops_all
                      if str(o.get("method", "GET")).upper() in ("POST", "PUT", "PATCH", "DELETE")
                      or {"function-authorization", "object-authorization", "property-authorization"}
                      & set(o.get("risk_hints") or [])]
        if not privileged:
            continue
        out.append({
            "resource": res,
            "hosts": sorted({str(o.get("host") or urlsplit(str(o.get("url") or "")).hostname or "")
                             for o in ops_all} - {""}),
            "interfaces": {k: sorted({f"{o.get('method', 'GET')} {o.get('url') or o.get('path')}"
                                      for o in v})[:6] for k, v in sorted(by_iface.items())},
            "privileged_ops": len(privileged),
            "next": "fire the same privileged operation on this resource through EVERY interface listed "
                    "with the low-priv identity; read the state back (hunt-differential, vector "
                    "sibling-interface)",
        })
    # a REST-vs-REST version pair is a downgrade lead; a different interface kind is
    # the pattern that paid, so it ranks first
    def kinds(x):
        return len({k.split(":")[0] for k in x["interfaces"]})
    for x in out:
        x["cross_kind"] = kinds(x) > 1
    out.sort(key=lambda x: (-kinds(x), -len(x["interfaces"]), -x["privileged_ops"], x["resource"]))
    return out


# ---------------------------------------------------------------------------
# 2. server-side fetchers
# ---------------------------------------------------------------------------
def _fetch_params(names: Iterable[str]) -> List[str]:
    return sorted({n for n in names if n and FETCH_PARAM_RE.match(n) and not FETCH_PARAM_DENY.match(n)})


def fetchers(ops: Iterable[Dict], fired: Iterable[Tuple[str, str]]) -> List[Dict]:
    found: Dict[str, Dict] = {}

    def add(method: str, url: str, params: List[str], why: str):
        sp = urlsplit(url)
        key = f"{method} {sp.scheme}://{sp.netloc}{sp.path}"
        cur = found.setdefault(key, {"endpoint": key, "params": set(), "why": set()})
        cur["params"].update(params)
        cur["why"].add(why)

    for op in ops:
        url = str(op.get("url") or op.get("path") or "")
        if not urlsplit(url).netloc and op.get("host"):
            url = f"https://{op['host']}{op.get('path') or urlsplit(url).path}"
        names = list(op.get("parameters") or []) + list(op.get("fields") or [])
        hit = _fetch_params(names)
        if hit:
            add(str(op.get("method", "GET")).upper(), url, hit, "manifest-param")
        if FETCH_PATH_RE.search(urlsplit(url).path or url):
            add(str(op.get("method", "GET")).upper(), url, hit, "manifest-route")
    for method, url in fired:
        sp = urlsplit(url)
        hit = _fetch_params(k for k, _ in parse_qsl(sp.query, keep_blank_values=True))
        if hit:
            add(method, url, hit, "fired-query-param")
        if FETCH_PATH_RE.search(sp.path or ""):
            add(method, url, hit, "fired-route")
    out = []
    for v in found.values():
        out.append({"endpoint": v["endpoint"], "params": sorted(v["params"]), "why": sorted(v["why"]),
                    "next": "point it at your own redirect-loop responder first (does the app show the "
                            "chain/final body?), then metadata/internal targets; the payout is a "
                            "credentials READ, not a callback (hunt-ssrf)"})
    out.sort(key=lambda x: (-len(x["params"]), x["endpoint"]))
    return out


# ---------------------------------------------------------------------------
# 3. secret leads
# ---------------------------------------------------------------------------
PROVIDERS = [
    ("sk-ant-", "Anthropic"), ("sk-proj-", "OpenAI"), ("sk-", "OpenAI/Stripe-style"),
    ("ghp_", "GitHub"), ("gho_", "GitHub OAuth"), ("ghs_", "GitHub App"), ("github_pat_", "GitHub"),
    ("glpat-", "GitLab"), ("xoxb-", "Slack"), ("xoxp-", "Slack"), ("xoxa-", "Slack"), ("xoxr-", "Slack"),
    ("xoxs-", "Slack"), ("AKIA", "AWS"), ("ASIA", "AWS (temporary)"), ("AIza", "Google API"),
    ("npm_", "npm"), ("dop_v1_", "DigitalOcean"), ("rk_live_", "Stripe"), ("sk_live_", "Stripe"),
    ("pk_live_", "Stripe publishable (low)"),
]
MASKED_RE = re.compile(r"((?:sk-proj-|sk-ant-|sk-|ghp_|gho_|ghs_|github_pat_|xox[baprs]-|AKIA|ASIA|AIza|"
                       r"glpat-|npm_|dop_v1_|rk_live_|sk_live_|pk_live_)[A-Za-z0-9_\-]{0,6})<redacted-(\d+)-chars>")


def provider_of(prefix: str) -> str:
    for p, name in PROVIDERS:
        if prefix.startswith(p):
            return name
    return "unknown"


def secret_leads(pdir: Path, engagement: str, memdir: Optional[Path] = None) -> List[Dict]:
    out: Dict[str, Dict] = {}
    try:
        from responses import _PRIVATE_KEY_RE, _SECRET_TOKEN_RE, store_root  # type: ignore
    except Exception:  # noqa: BLE001
        return []

    def add(prefix: str, where: str, kind: str):
        key = f"{prefix}@{where}"
        out.setdefault(key, {"prefix": prefix, "provider": provider_of(prefix), "where": where,
                             "kind": kind,
                             "next": "validate with ONE read-only identity call per "
                                     "~/security-research/tools/data/keyhacks.md, then map scope "
                                     "read-only; prove access by hash/count (hunt-source-leak, "
                                     "vector secret-exposure)"})

    recon = pdir / "recon"
    if recon.is_dir():
        for p in recon.rglob("*"):
            if not p.is_file() or p.stat().st_size > 20_000_000 or p.suffix in (".png", ".jpg", ".gif", ".woff", ".woff2"):
                continue
            try:
                data = p.read_bytes()
            except OSError:
                continue
            text = data.decode("utf-8", "replace")
            for m in _SECRET_TOKEN_RE.finditer(text):
                add(m.group(1)[:8] + "…", str(p.relative_to(pdir)), "raw-in-recon-file")
            if _PRIVATE_KEY_RE.search(data):
                add("PRIVATE KEY", str(p.relative_to(pdir)), "raw-in-recon-file")
    try:
        corpus = store_root(engagement.split("/")[-1], memdir)
    except Exception:  # noqa: BLE001
        corpus = None
    if corpus and corpus.is_dir():
        for p in corpus.glob("*.txt"):
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in MASKED_RE.finditer(text):
                add(m.group(1) + "…", f"responses/{p.name}", "masked-in-response-corpus")
    return sorted(out.values(), key=lambda x: (x["provider"] == "Stripe publishable (low)", x["where"]))


# ---------------------------------------------------------------------------
# seeding + CLI
# ---------------------------------------------------------------------------
def seed(report: Dict, memdir: Optional[Path] = None) -> Dict[str, int]:
    import vectors as V  # type: ignore
    added: Dict[str, int] = defaultdict(int)

    def bare(endpoint: str) -> str:
        """`GET /x` and `/x` are the same vector: compare without the method."""
        parts = endpoint.split(" ", 1)
        return parts[1] if len(parts) == 2 and parts[0].isupper() else endpoint

    def put(host: str, vclass: str, endpoint: str, reason: str):
        if not host:
            return
        ledger = V.load(host, memdir)
        if any(v["class"] == vclass and bare(v["endpoint"]) == bare(endpoint) for v in ledger["vectors"]):
            return  # already in the ledger, possibly worked: never re-add it as untried
        vec = V._new_vector(vclass, endpoint, origin="census", reason=reason)
        # evidence-backed, so it ranks with manifest-derived rows rather than below
        # every cartesian missing_authorization row (field test: rank 112 of 220)
        vec["priority"] = V.CATALOG.get(vclass, {}).get("impact", 60) + 15
        ledger["vectors"].append(vec)
        V.save(ledger, memdir)
        added[host] += 1

    default_host = report.get("default_host") or ""
    for s in report["sibling_interfaces"]:
        hosts = list(s.get("hosts") or []) + \
            [urlsplit(e.split(" ", 1)[-1]).hostname for lst in s["interfaces"].values() for e in lst]
        host = next((h for h in hosts if h), "") or default_host
        put(host, "sibling-interface", f"resource:{s['resource']}",
            "census: " + " + ".join(s["interfaces"]))
    for f in report["fetchers"]:
        url = f["endpoint"].split(" ", 1)[-1]
        put(urlsplit(url).hostname or "", "ssrf", f["endpoint"].replace(urlsplit(url).scheme + "://" +
            (urlsplit(url).netloc), ""), "server-side-fetcher: " + ",".join(f["params"] or f["why"]))
    for s in report["secret_leads"]:
        put(default_host, "secret-exposure", f"{s['provider']}:{s['prefix']}@{s['where']}", s["kind"])
    return dict(added)


def census(pdir: Path, memdir: Optional[Path] = None) -> Dict:
    engagement = str(pdir.relative_to(pdir.parent.parent)) if pdir.parent.parent else pdir.name
    ops = load_manifests(pdir)
    fired = audit_urls(pdir.name, memdir)
    hosts = [urlsplit(u).hostname for _, u in fired if urlsplit(u).hostname]
    default_host = max(set(hosts), key=hosts.count) if hosts else ""
    return {
        "engagement": engagement,
        "inputs": {"manifest_operations": len(ops), "fired_urls": len(fired)},
        "default_host": default_host,
        "sibling_interfaces": sibling_interfaces(ops),
        "fetchers": fetchers(ops, fired),
        "secret_leads": secret_leads(pdir, pdir.name, memdir),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="census", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", help="engagement name (default: cwd / $CBH_PROJECT)")
    ap.add_argument("--seed", action="store_true", help="write items into the vector ledger")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-write", action="store_true", help="do not write recon/census/surface-census.json")
    a = ap.parse_args(argv)
    pdir = project_dir(a.project)
    if not pdir:
        print("census: no engagement resolved — run inside Targets/<name>/ or pass --project", file=sys.stderr)
        return 3
    rep = census(pdir)
    if not a.no_write:
        out = pdir / "recon" / "census" / "surface-census.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(rep, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        rep["written"] = str(out)
    if a.seed:
        rep["seeded"] = seed(rep)
    if a.json:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0
    print(f"census {rep['engagement']}: {rep['inputs']['manifest_operations']} manifest ops, "
          f"{rep['inputs']['fired_urls']} fired URLs")
    print(f"\nSIBLING INTERFACES ({len(rep['sibling_interfaces'])}) — same resource, ≥2 interfaces:")
    for s in rep["sibling_interfaces"][:10]:
        print(f"  {s['resource']:18s} {' | '.join(s['interfaces'])}  ({s['privileged_ops']} privileged ops)")
    print(f"\nSERVER-SIDE FETCHERS ({len(rep['fetchers'])}):")
    for f in rep["fetchers"][:10]:
        print(f"  {f['endpoint']}  params={','.join(f['params']) or '-'}  [{','.join(f['why'])}]")
    print(f"\nSECRET LEADS ({len(rep['secret_leads'])}):")
    for s in rep["secret_leads"][:10]:
        print(f"  {s['provider']:22s} {s['prefix']:14s} {s['where']}  ({s['kind']})")
    if rep.get("seeded") is not None:
        print(f"\nseeded into the vector ledger: {rep['seeded'] or 'nothing new'}")
    elif rep["sibling_interfaces"] or rep["fetchers"] or rep["secret_leads"]:
        print("\nnext: `cbh census --seed` puts these into `vectors.py next`")
    if rep.get("written"):
        print(f"written: {rep['written']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
