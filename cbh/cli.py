#!/usr/bin/env python3
"""
cbh — claude-bughunter CLI.

Bridges the repo's skill content into a real runner. Five subcommands compose
the engagement loop:

  cbh recon <target>           passive subdomain enum + live-host probe + URL
                               classification. Writes recon/<target>/ including
                               manifest.json (the recon→hunt handoff contract).
  cbh surface <target>         read recon/<target>/manifest.json and print the
                               ranked P1/P2/Kill attack surface. See
                               docs/recon-manifest.md.
  cbh classify <url>           pattern-match a single URL against hunt-* skill
                               descriptions; print the matched skills + ranked
                               attack candidates from docs/disclosed-reports/.
  cbh triage <finding.md>      run the triage-validation 7-Question Gate
                               against a finding file. Output: PASS / DOWNGRADE
                               / KILL with reason.
  cbh report <finding.md>      emit a report draft (H1 / Bugcrowd / Intigriti /
                               Immunefi templates) based on finding metadata.
  cbh view <project-dir>       read a Targets/<name>/ project's findings/,
                               hosts/, notes.md and write a local, offline
                               dashboard.html summary (never uploaded).

Stdlib + optional `requests`. No build step. Drop on PATH:

    ln -s $(pwd)/scripts/cbh.py /usr/local/bin/cbh

Or run inline:

    scripts/cbh.py recon target.com
"""
from __future__ import annotations
import argparse
import datetime
import html
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO_ROOT / "skills"
REPORTS_DIR = REPO_ROOT / "docs" / "disclosed-reports"

# Clone mode = the live repo is present (skills/ on disk). Otherwise we're
# pip-installed and fall back to the bundled cbh/data/skill_index.json.
CLONE_MODE = SKILLS_DIR.is_dir() and any(SKILLS_DIR.iterdir()) if SKILLS_DIR.exists() else False
REPO_URL = "https://github.com/elementalsouls/Claude-BugHunter"

_BUNDLED_INDEX: dict | None = None


def _bundled_index() -> dict:
    """Load the packaged skill/report index (installed mode). Cached."""
    global _BUNDLED_INDEX
    if _BUNDLED_INDEX is None:
        try:
            from importlib.resources import files
            raw = (files("cbh") / "data" / "skill_index.json").read_text(encoding="utf-8")
        except Exception:
            # Last-resort: read alongside this file.
            p = Path(__file__).resolve().parent / "data" / "skill_index.json"
            raw = p.read_text(encoding="utf-8") if p.exists() else '{"skills":{},"reports":[]}'
        _BUNDLED_INDEX = json.loads(raw)
    return _BUNDLED_INDEX


# ============================================================
# Shared utilities
# ============================================================
def color(s: str, c: str) -> str:
    if not sys.stdout.isatty():
        return s
    codes = {"red": 31, "green": 32, "yellow": 33, "blue": 34, "cyan": 36, "bold": 1, "dim": 2}
    return f"\033[{codes.get(c, 0)}m{s}\033[0m"


def say(s: str = ""):
    print(s)


def section(title: str):
    say()
    say(color("=" * 70, "blue"))
    say(color(title, "bold"))
    say(color("=" * 70, "blue"))


def has_cmd(name: str) -> bool:
    return subprocess.call(["which", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def run_cmd(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not found"


_HTTP_OPENER: urllib.request.OpenerDirector | None = None


def configure_http_proxy(proxy_url: str | None = None) -> tuple[bool, str]:
    """Configure urllib to route through a proxy (typically Burp Suite at
    127.0.0.1:8080). Returns (configured, message) — message describes the mode.

    Resolution order:
      1. explicit proxy_url argument
      2. CBH_BURP_PROXY env var
      3. HTTPS_PROXY / HTTP_PROXY env vars
      4. fallback: auto-detect default Burp on http://127.0.0.1:8080 (only if --burp flag)
    """
    global _HTTP_OPENER
    if not proxy_url:
        proxy_url = os.environ.get("CBH_BURP_PROXY") or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    if not proxy_url:
        _HTTP_OPENER = None
        return False, "direct (no proxy)"

    # Disable TLS verification when going through Burp (its CA isn't typically trusted)
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    # WARNING: TLS verification is disabled for Burp proxy traffic.
    # Use --proxy only in isolated lab environments — not on production targets.
    ctx.verify_mode = ssl.CERT_NONE
    print("[warning] TLS certificate verification is DISABLED — proxy mode active. "
          "Use only in isolated lab environments, not on production targets.", flush=True)

    proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    _HTTP_OPENER = urllib.request.build_opener(proxy_handler, https_handler)
    return True, f"via proxy {proxy_url}"


def detect_burp() -> str | None:
    """Return Burp proxy URL if responsive on default port, else None."""
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/", timeout=1) as r:
            # Burp's proxy returns a help page; just confirming it's listening
            if r.status == 200:
                return "http://127.0.0.1:8080"
    except Exception:
        pass
    return None


def http_get(url: str, timeout: int = 5, headers: dict | None = None) -> tuple[int, dict, str]:
    """Stdlib HTTP GET returning (status_code, headers_dict, body_str). Routes
    through the configured proxy (e.g. Burp) if `configure_http_proxy()` was
    called. Returns (0, {}, error_msg) on failure."""
    req = urllib.request.Request(url, headers=headers or {})
    opener = _HTTP_OPENER if _HTTP_OPENER is not None else urllib.request
    try:
        if _HTTP_OPENER is not None:
            with _HTTP_OPENER.open(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", errors="replace")
                return r.status, dict(r.headers), body
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body
    except Exception as e:
        return 0, {}, str(e)


# ============================================================
# recon — passive subdomain enum + DNS + HTTP probe
# ============================================================
def recon_subdomains_via_crtsh(target: str) -> set[str]:
    """crt.sh certificate transparency — passive, no API key needed."""
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    status, _, body = http_get(url, timeout=20)
    if status != 200 or not body:
        return set()
    try:
        rows = json.loads(body)
    except Exception:
        return set()
    subs = set()
    for r in rows:
        nv = (r.get("name_value") or "").lower()
        for line in nv.split("\n"):
            line = line.strip()
            if line and "*" not in line:
                subs.add(line)
    return subs


def recon_subdomains_via_subfinder(target: str) -> set[str]:
    if not has_cmd("subfinder"):
        return set()
    _, out, _ = run_cmd(["subfinder", "-d", target, "-silent"], timeout=60)
    return {line.strip().lower() for line in out.splitlines() if line.strip()}


def recon_resolve(host: str) -> list[str]:
    """Resolve A records using socket.getaddrinfo (stdlib). Avoids the
    dnsx/httpx segfault issue documented on macOS arm64."""
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        return sorted(set(i[4][0] for i in infos))
    except Exception:
        return []


def recon_http_probe(host: str, broker=None) -> dict | None:
    """Fast HTTP probe — try https:// first, fall back to http://. Returns
    a record with code/server/title or None if unreachable."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        request_headers = {}
        if broker is not None:
            try:
                request_headers, _ = broker.before_request(url, request_headers)
            except Exception:
                continue
        started = datetime.datetime.now(datetime.timezone.utc)
        code, headers, body = http_get(url, timeout=4, headers=request_headers)
        if broker is not None:
            try:
                elapsed = (datetime.datetime.now(datetime.timezone.utc) - started).total_seconds() * 1000
                broker.record_response(url, "GET", code, body, headers, elapsed)
            except Exception:
                pass
        if code == 0:
            continue
        title = ""
        m = re.search(r"<title[^>]*>([^<]*)</title>", body[:8192], re.I)
        if m:
            title = m.group(1).strip()[:80]
        return {
            "url": url,
            "code": code,
            "server": headers.get("Server", ""),
            "title": title,
            "powered_by": headers.get("X-Powered-By", ""),
            "drupal_cache": headers.get("X-Drupal-Cache", ""),
        }
    return None


def configure_proxy_from_args(args: argparse.Namespace) -> None:
    """If --burp or --proxy was passed, set up the urllib opener accordingly.
    Print the mode banner so the operator knows where traffic is going."""
    proxy_url = None
    if getattr(args, "proxy", None):
        proxy_url = args.proxy
    elif getattr(args, "burp", False):
        proxy_url = detect_burp() or "http://127.0.0.1:8080"
    configured, mode = configure_http_proxy(proxy_url)
    if configured:
        say(color(f"  HTTP routing: {mode}", "yellow"))
        say(color(f"  Tip: requests will appear in Burp Proxy → HTTP history.", "dim"))


def cmd_recon(args: argparse.Namespace) -> int:
    target = args.target
    # Inside an engagement, recon belongs to that engagement: Targets/<name>/recon/.
    # Otherwise clone mode writes under the repo and installed mode under the CWD
    # (never into site-packages). Override with --out.
    #
    # Without the engagement branch, running from the workspace root scattered
    # output into a second top-level recon/ directory while every project also
    # kept its own — two roots, and no way to tell which held the current map.
    recon_root = None
    project = None
    if getattr(args, "out", None):
        recon_root = Path(args.out).resolve()
    else:
        try:
            sys.path.insert(0, str(REPO_ROOT / "engine"))
            from pacing import find_project_dir  # noqa: PLC0415 - optional sibling module
            project = find_project_dir()
            if project is not None:
                recon_root = project / "recon"
        except Exception:  # noqa: BLE001 - engagement detection is a convenience, not a requirement
            pass
    if recon_root is None:
        recon_root = REPO_ROOT / "recon" if CLONE_MODE else Path.cwd() / "recon"
    out_dir = recon_root / target
    resolved = out_dir.resolve()
    safe = recon_root.resolve()
    # Real containment check — `startswith` is bypassable by a sibling that
    # shares the prefix (e.g. recon-evil vs recon), so test ancestry properly.
    if resolved != safe and safe not in resolved.parents:
        print(f"[error] invalid target: {target}", file=sys.stderr); return 1
    out_dir = resolved
    out_dir.mkdir(parents=True, exist_ok=True)

    section(f"recon — {target}")
    configure_proxy_from_args(args)

    # Step 1 — passive subdomain enumeration
    say(color("[1/4] passive subdomain enumeration", "cyan"))
    subs = set()
    subs |= recon_subdomains_via_crtsh(target)
    say(f"  crt.sh: {len(subs)} candidates")
    sf = recon_subdomains_via_subfinder(target)
    if sf:
        before = len(subs)
        subs |= sf
        say(f"  subfinder: {len(sf)} candidates (new: {len(subs) - before})")
    else:
        say(f"  subfinder: {color('not installed', 'dim')}")
    if not subs:
        subs.add(target)
    subs.add(target)
    (out_dir / "subdomains.txt").write_text("\n".join(sorted(subs)) + "\n")
    say(f"  Total unique: {color(str(len(subs)), 'bold')}")

    # Step 2 — DNS resolution
    say()
    say(color("[2/4] DNS resolution", "cyan"))
    resolved = {}
    for s in sorted(subs):
        ips = recon_resolve(s)
        if ips:
            resolved[s] = ips
    (out_dir / "resolved.txt").write_text(
        "\n".join(f"{h}|{','.join(ips)}" for h, ips in sorted(resolved.items())) + "\n"
    )
    say(f"  Resolved: {color(str(len(resolved)), 'bold')} / {len(subs)}")

    # Step 3 — HTTP probe (concurrent via thread pool)
    say()
    say(color("[3/4] HTTP probe", "cyan"))
    from concurrent.futures import ThreadPoolExecutor, as_completed
    broker = None
    workers = 1
    if project is not None:
        try:
            sys.path.insert(0, str(REPO_ROOT / "engine"))
            from request_broker import RequestBroker
            broker = RequestBroker.detect(project, source="cbh-recon")
            workers = broker.engagement.max_concurrency
        except Exception as e:
            print(f"[error] engagement request policy unavailable: {e}", file=sys.stderr)
            return 2
    live = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(recon_http_probe, h, broker): h for h in resolved}
        for f in as_completed(futures):
            host = futures[f]
            rec = f.result()
            if rec:
                rec["host"] = host
                live.append(rec)
    (out_dir / "live-hosts.json").write_text(json.dumps(live, indent=2))
    say(f"  HTTP-live: {color(str(len(live)), 'bold')} / {len(resolved)}")

    # Step 4 — summary report
    say()
    say(color("[4/4] writing recon summary", "cyan"))
    summary_path = out_dir / "RECON_SUMMARY.md"
    write_recon_summary(target, subs, resolved, live, summary_path)
    say(f"  {summary_path}")

    # recon→hunt handoff contract — see docs/recon-manifest.md
    manifest = build_manifest(target, subs, resolved, live)
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    say(f"  {manifest_path}  {color('(recon→hunt manifest)', 'dim')}")

    section("SUMMARY")
    say(f"  Target:            {target}")
    say(f"  Subdomains:        {len(subs)}")
    say(f"  Resolved:          {len(resolved)}")
    say(f"  HTTP-live:         {len(live)}")
    say(f"  Output:            {out_dir}")
    say()
    say(f"  Next: {color('cbh classify <url>', 'bold')} for fast pattern-match, or {color('/hunt <target>', 'bold')} in Claude Code for full LLM-driven hunting")
    return 0


def write_recon_summary(target: str, subs: set[str], resolved: dict, live: list, out: Path):
    lines = [f"# Recon — {target}",
             "",
             f"_Generated by `cbh recon {target}` at {datetime.datetime.now().isoformat(timespec='seconds')}._",
             "",
             "## Attack-surface snapshot",
             "",
             f"- Subdomains discovered (passive): **{len(subs)}**",
             f"- DNS-resolved: **{len(resolved)}**",
             f"- HTTP-live: **{len(live)}**",
             "",
             "## Live hosts",
             "",
             "| Host | URL | Code | Server | Title |",
             "|---|---|---|---|---|",
            ]
    for r in sorted(live, key=lambda x: x["host"]):
        title = (r.get("title") or "").replace("|", "\\|")[:50]
        lines.append(f"| `{r['host']}` | {r['url']} | {r['code']} | {r.get('server','')} | {title} |")
    lines += [
        "",
        "## Suggested next moves",
        "",
        "- For each live host, run `cbh classify https://<host>/<path>?<params>` to surface attack candidates.",
        "- Cross-TLD pivot: check JS bundles for sister-domain references (per `web2-recon` Operator Notes).",
        "- For `mta-sts.*` / `*.github.io` hosts, fingerprint against `hunt-subdomain` takeover table.",
        "",
    ]
    out.write_text("\n".join(lines))


# ============================================================
# recon→hunt manifest (the integration handoff contract)
# ============================================================
PRODUCER = "cbh-recon/2.1.0"

# subdomain keywords → triage priority + rationale for ranked_surface
_P1_HINTS = ("api.", "api-", "graphql", "auth.", "sso.", "login.", "account.",
             "admin.", "internal.", "intranet.", "staging.", "stage.", "dev.",
             "test.", "uat.", "qa.", "gateway.", "gw.", "vpn.", "portal.")
_KILL_HINTS = ("cdn.", "static.", "assets.", "img.", "images.", "media.", "fonts.")


def _rank_host(host: str) -> tuple[str, str]:
    h = host.lower()
    if any(k in h for k in _P1_HINTS):
        return "P1", "high-value surface (api/auth/admin/non-prod)"
    if any(h.startswith(k) for k in _KILL_HINTS):
        return "KILL", "static/CDN host — low yield"
    return "P2", "standard web surface"


def build_manifest(target: str, subs: set, resolved: dict, live: list) -> dict:
    """Assemble the recon→hunt manifest. cbh fills assets + ranked_surface; the
    offensive-osint skill's deeper probes append secrets[] and identity_fabric{}."""
    live_by_host = {r["host"]: r for r in live}
    assets = []
    for host in sorted(live_by_host):
        r = live_by_host[host]
        assets.append({
            "host": host, "ips": resolved.get(host, []), "url": r.get("url"),
            "status": r.get("code"), "server": r.get("server", ""),
            "title": r.get("title", ""), "tech": r.get("tech", []),
            "source": "crtsh+httpx",
        })
    for host in sorted(resolved):                      # DNS-only (resolved, not HTTP-live)
        if host not in live_by_host:
            assets.append({
                "host": host, "ips": resolved[host], "url": None, "status": None,
                "server": "", "title": "", "tech": [], "source": "crtsh+dns",
            })

    ranked = []
    for host in sorted(live_by_host):
        r = live_by_host[host]
        prio, why = _rank_host(host)
        bug_classes = sorted(classify_url(r["url"])["matches"].keys()) if r.get("url") else []
        ranked.append({"url": r.get("url"), "host": host, "bug_classes": bug_classes,
                       "priority": prio, "rationale": why})
    _order = {"P1": 0, "P2": 1, "KILL": 2}
    ranked.sort(key=lambda x: (_order.get(x["priority"], 9), x["host"]))

    try:
        sys.path.insert(0, str(REPO_ROOT / "engine"))
        from api_manifest import make_operation
        operations = [make_operation("GET", r["url"], "cbh-recon-root") for r in live if r.get("url")]
    except Exception:
        operations = []
    return {
        "schema_version": "2.0",
        "target": target,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "producers": [PRODUCER],
        "counts": {"subdomains": len(subs), "resolved": len(resolved), "live": len(live)},
        "assets": assets,
        "ranked_surface": ranked,
        # Filled in by the offensive-osint skill's deeper probes (see docs/recon-manifest.md):
        "secrets": [],            # {pattern, severity, category, source}  ← secret_scan.py
        "identity_fabric": {},    # {idp, tenant, domains, ...}            ← identity-fabric probes
        "operations": operations,
    }


# ============================================================
# classify — pattern-match URL against skill descriptions + reports
# ============================================================
SKILL_DESC_CACHE: dict[str, str] = {}


def load_skill_descriptions() -> dict[str, str]:
    """Read the `description:` frontmatter of each SKILL.md."""
    if SKILL_DESC_CACHE:
        return SKILL_DESC_CACHE
    if not CLONE_MODE:
        # Installed mode: read descriptions from the bundled index.
        SKILL_DESC_CACHE.update(_bundled_index().get("skills", {}))
        return SKILL_DESC_CACHE
    for skill_dir in SKILLS_DIR.iterdir():
        if not skill_dir.is_dir():
            continue
        sm = skill_dir / "SKILL.md"
        if not sm.exists():
            continue
        try:
            text = sm.read_text(encoding="utf-8")
        except Exception:
            continue
        m = re.search(r"^description:\s*(.+?)(?=\n[a-z_]+:|^---|\Z)",
                      text, re.M | re.S)
        if m:
            desc = m.group(1).strip().strip('"').strip("'").strip()
            SKILL_DESC_CACHE[skill_dir.name] = desc[:2000]
    return SKILL_DESC_CACHE


# A small, hand-curated trigger map. Augments the description-matcher
# with high-confidence URL-pattern → skill associations.
URL_PATTERN_TO_SKILLS = [
    (r"[?&](url|next|redirect|return|callback|target|destination|continue)=", ["hunt-ssrf"]),
    (r"[?&](id|user|userid|user_id|uid|pid|post|order|invoice|account)=\d", ["hunt-idor"]),
    (r"/(api|rest|v[0-9])/", ["hunt-api-misconfig", "hunt-idor"]),
    (r"/graphql", ["hunt-graphql"]),
    (r"/(login|signin|signup|register|forgot|reset)", ["hunt-auth-bypass", "hunt-ato"]),
    (r"/oauth/(authorize|token|callback)", ["hunt-oauth"]),
    (r"/saml/(acs|sso|metadata)", ["hunt-saml"]),
    (r"/_layouts/15/|/_vti_bin/|/_api/(web|contextinfo)", ["hunt-sharepoint"]),
    (r"/(file|upload|attachment|avatar|document|media)", ["hunt-file-upload"]),
    (r"/search\?", ["hunt-xss", "hunt-sqli"]),
    (r"[?&]q=|[?&]query=|[?&]s=", ["hunt-xss"]),
    (r"\.(php|aspx?|cgi|jsp)", ["hunt-rce", "hunt-aspnet"]),
    (r"/(admin|management|debug|test|staging|dev|internal)", ["hunt-auth-bypass"]),
    (r"/jenkins|jnlpJars|/cli", ["hunt-rce"]),  # CVE-2024-23897
    (r"/functionRouter|/uppercase|/lowercase", ["hunt-rce", "hunt-ssti"]),  # Spring Cloud Function
    (r"/(2fa|mfa|otp|verify)", ["hunt-mfa-bypass"]),
    (r"/(coupon|promo|cart|checkout)", ["hunt-business-logic", "hunt-race-condition"]),
    (r"/(webhook|callback/event)", ["hunt-business-logic"]),
    (r"/parse-xml|/import-xml|\.xml", ["hunt-xxe"]),
]


def classify_url(url: str) -> dict:
    """Return matched skills with rationale + pointers to disclosed-reports library."""
    skills = load_skill_descriptions()
    matches: dict[str, list[str]] = {}

    parsed = urllib.parse.urlparse(url)
    raw = url

    # Pattern triggers
    for pattern, skill_names in URL_PATTERN_TO_SKILLS:
        if re.search(pattern, raw, re.I):
            for s in skill_names:
                matches.setdefault(s, []).append(f"URL matches /{pattern}/")

    # Description keyword match (lighter signal)
    keywords = re.findall(r"[a-z]{4,}", raw.lower())
    for skill, desc in skills.items():
        # Look for the same keywords in the description
        if skill in matches:
            continue
        score = 0
        hits = []
        for kw in set(keywords):
            if re.search(rf"\b{re.escape(kw)}\b", desc.lower()):
                score += 1
                hits.append(kw)
                if score >= 2:
                    break
        if score >= 2:
            matches[skill] = [f"description keywords: {hits}"]

    return {
        "url": url,
        "matches": matches,
        "available_reports": ([p.name for p in REPORTS_DIR.glob("hunt-*.md")]
                              if REPORTS_DIR.exists() else _bundled_index().get("reports", [])),
    }


def cmd_classify(args: argparse.Namespace) -> int:
    result = classify_url(args.url)
    section(f"classify — {args.url}")
    if getattr(args, "burp", False) or getattr(args, "proxy", None):
        proxy_url = args.proxy if getattr(args, "proxy", None) else (detect_burp() or "http://127.0.0.1:8080")
        say(color(f"  Burp proxy ready at {proxy_url} — pipe candidate requests through it.", "yellow"))
        say()
    if not result["matches"]:
        say("  No high-confidence matches. Try:")
        say(f"    {color('cbh recon <target>', 'bold')} to map attack surface first.")
        return 1
    say()
    for skill, reasons in sorted(result["matches"].items()):
        say(color(f"  → {skill}", "green"))
        for r in reasons:
            say(f"      • {r}")
        report_name = f"{skill}.md"
        local_report = REPORTS_DIR / report_name
        if local_report.exists():
            say(f"      📖 Pattern Library: {color(str(local_report), 'cyan')}")
        elif report_name in _bundled_index().get("reports", []):
            say(f"      📖 Pattern Library: {color(f'{REPO_URL}/blob/main/docs/disclosed-reports/{report_name}', 'cyan')}")
        skill_path = SKILLS_DIR / skill / "SKILL.md"
        if skill_path.exists():
            say(f"      📋 Skill:           {color(str(skill_path), 'cyan')}")
        elif not CLONE_MODE:
            say(f"      📋 Skill:           {color(f'{REPO_URL}/blob/main/skills/{skill}/SKILL.md', 'cyan')}")
        say()
    say(color("Next moves:", "bold"))
    say(f"  1. Read the Pattern Library docs for each matched skill")
    say(f"  2. Pick the highest-confidence attack from the Pattern Library")
    say(f"  3. Apply OOB-Or-It-Didn't-Happen Gate before claiming success")
    say(f"  4. {color('cbh triage <finding.md>', 'bold')} once you have a candidate finding")
    say()
    say(color("Need richer context? In a Claude Code conversation:", "dim"))
    say(color(f"   /hunt <url>     — full hunt-dispatch routing with LLM judgment", "dim"))
    say(color(f"   /chain          — build A→B→C exploit chains", "dim"))
    return 0


# ============================================================
# triage — run the 7-Question Gate against a finding markdown
# ============================================================
TRIAGE_QUESTIONS = [
    ("Q1", "Can an attacker use this RIGHT NOW with a real HTTP request?",
     ["curl ", "POST ", "GET ", "HTTP/1.1", "PUT ", "DELETE ", "PATCH "]),
    ("Q2", "Is the impact on the program's accepted-impact list?",
     ["impact:", "severity:", "p1", "p2", "p3", "p4", "critical", "high", "medium", "low"]),
    ("Q3", "Is the asset in scope?",
     ["scope", "in-scope", "in scope", "target:", "asset:"]),
    ("Q4", "Does it work without privileged access an attacker can't get?",
     ["attacker", "unauthenticated", "user-role", "low-priv", "any user", "session"]),
    ("Q5", "Is this not already known or documented behavior?",
     ["disclosed-reports", "h1 hacktivity", "not duplicate", "novel", "first reported", "previously unknown", "previously"]),
    ("Q6", "Can impact be proved beyond 'technically possible'?",
     ["leaked", "exfiltrated", "rce", "data:", "credential", "session-id", "cookie:",
      "admin email", "production", "oob callback", "interactsh"]),
    ("Q7", "Is this not on the never-submit list?",
     ["self-xss", "rate-limit only", "click-jacking", "csrf on logout", "missing security headers"]),
]



def _responses_mod():
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
    import responses  # type: ignore
    return responses


def cmd_diff(args: argparse.Namespace) -> int:
    """Did the target's answer ever change? — the question a request count cannot answer.

    Twenty probes that come back byte-identical are not twenty probes, they are one
    probe sent twenty times. The corpus knows, because every body was hashed.
    """
    import difflib
    responses = _responses_mod()
    rows = responses.rows(args.url, args.engagement or "", memdir=None)
    section(f"responses — {args.url or 'all'}")
    if not rows:
        say(color("  no stored responses match that.", "yellow"))
        say(color("  Either nothing was fired at it, or the requests predate the response "
                  "corpus / ran with --bb-no-store.", "dim"))
        return 1

    stats = responses.identical_run(rows)
    say(f"  {stats['requests']} requests, {stats['distinct']} distinct response bodies")

    if args.fields:
        return _diff_fields(responses, rows, args)

    by_hash = {}
    for r in rows:
        by_hash.setdefault(r["body_sha256"], []).append(r)
    for h, group in sorted(by_hash.items(), key=lambda kv: -len(kv[1])):
        codes = sorted({str(g.get("http_code")) for g in group})
        say(f"    {h[:12]}  x{len(group):<3} status {','.join(codes)}  "
            f"{group[-1].get('body_bytes')} bytes  last {group[-1].get('timestamp', '')[:19]}")

    if stats["distinct"] == 1 and stats["requests"] >= 3:
        say()
        say(color(f"  {stats['requests']} requests, ONE distinct body — this endpoint is not "
                  "reacting to input at all.", "red"))
        say(color("  That is a rotate signal, not persistence: change the method, the "
                  "content-type, the auth, or the vector.", "dim"))
        return 0

    hashes = responses.distinct(rows)
    a_h, b_h = hashes[-2], hashes[-1]
    a = responses.load(args.engagement or "", a_h).splitlines()
    b = responses.load(args.engagement or "", b_h).splitlines()
    say()
    say(color(f"  diff {a_h[:12]} -> {b_h[:12]} (two most recent distinct bodies)", "cyan"))
    shown = 0
    for line in difflib.unified_diff(a, b, fromfile=a_h[:12], tofile=b_h[:12], lineterm="", n=1):
        if shown >= args.max_lines:
            say(color(f"  … truncated at {args.max_lines} lines (--max-lines to see more)", "dim"))
            break
        colour = "green" if line.startswith("+") else "red" if line.startswith("-") else "dim"
        say("  " + color(line[:300], colour))
        shown += 1
    return 0


def _diff_fields(responses, rows, args) -> int:
    """Per-field movement, because a body that changed is not an answer that changed.

    A response can differ in every byte and still be saying the same thing — echoed
    parameters move, the verdict does not. This is the view that catches a boolean
    being mistaken for an oracle.
    """
    groups = {}
    for r in rows:
        for u in (r.get("urls") or []):
            groups.setdefault(responses._path_of(u), []).append(r)
            break
    for path, rs in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        var = responses.field_variance(rs, memdir=None)
        say()
        say(color(f"  {path}", "cyan"))
        say(f"    {len(rs)} captures, {var['parsed']} JSON-parsed, "
            f"{var['distinct_requests']} distinct request URLs")
        if not var["parsed"]:
            say(color("    no JSON bodies here — use the body diff above", "dim"))
            continue
        for name, f in var["fields"].items():
            if f["constant"]:
                say(f"    {color('CONSTANT', 'yellow')} {name:28s} = {f['values'][0]}"
                    f"   (all {f['seen']})")
            else:
                shown = ", ".join(f["values"][:4]) + (" …" if f["distinct"] > 4 else "")
                say(f"    {color('varies  ', 'green')} {name:28s} {f['distinct']} values: {shown}")

    alert = responses.constant_field_alert(args.url, args.engagement or "")
    if alert and alert["decisive_fields"]:
        say()
        say(color(f"  PHANTOM ORACLE: {alert['path']} answered "
                  f"{alert['responses']} different requests and "
                  f"{', '.join(alert['decisive_fields'])} never moved.", "red"))
        say(color("  A field that is constant across varied input is not an answer — it is a "
                  "stub. Prove it reacts before calling it a disclosure.", "dim"))
    return 0


def cmd_spec(args: argparse.Namespace) -> int:
    """Turn a request that already flew into a poc_runtime spec.

    The last mile used to start from a blank file even though the request, its
    headers and its exact response were already on disk. Credentials are NOT in the
    corpus (they are redacted at write time), so any auth header comes back as a
    placeholder the operator has to fill in deliberately.
    """
    responses = _responses_mod()
    rows = [r for r in responses.rows(args.url, args.engagement or "") if r.get("req")]
    if not rows:
        say(color("  no stored request matches that URL.", "yellow"))
        say(color("  `cbh diff <url>` shows what the corpus does have.", "dim"))
        return 1
    row = rows[-1]
    argv = row["req"]

    method = (row.get("method") or "GET").upper()
    headers, body, url = {}, None, ""
    i = 0
    placeholders = []
    while i < len(argv):
        a, nxt = argv[i], argv[i + 1] if i + 1 < len(argv) else None
        if a in ("-H", "--header") and nxt:
            name, _, value = nxt.partition(":")
            value = value.strip()
            if value == responses.REDACTED:
                placeholders.append(name.strip())
                value = "<FILL IN BY HAND — redacted at capture time>"
            headers[name.strip()] = value
            i += 2
            continue
        if a in ("-d", "--data", "--data-raw", "--data-binary") and nxt:
            body = nxt
            if method == "GET":
                method = "POST"
            i += 2
            continue
        if a in ("-X", "--request") and nxt:
            method = nxt.upper()
            i += 2
            continue
        if a.startswith("http://") or a.startswith("https://"):
            url = a
        i += 1
    url = url or (row.get("urls") or [""])[0] or row.get("url_effective", "")

    expect = {"status": int(row.get("http_code") or 0) or 200, "no_redirect": True}
    stored = responses.load(args.engagement or "", row.get("body_sha256", ""))
    marker = _spec_marker(stored)
    if marker:
        expect["body_contains"] = [marker]

    spec = {
        "note": (f"Generated by `cbh spec` from the request fired at "
                 f"{row.get('timestamp', '')[:19]} (engagement: {row.get('engagement')}). "
                 "Assertions come from what the server actually returned that time — "
                 "check they state the BUG, not merely that the endpoint is alive."),
        "vuln_class": args.vuln_class or "unspecified",
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "expect": expect,
    }
    if args.steps:
        spec = {"note": spec["note"], "vuln_class": spec["vuln_class"],
                "steps": [{"name": "captured", **{k: spec[k] for k in
                          ("method", "url", "headers", "body", "expect")}},
                          {"name": "verify — REPLACE ME: prove the state actually changed",
                           "method": "GET", "url": url, "expect": {"status": 200}}]}

    text = json.dumps(spec, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        say(color(f"  wrote {args.out}", "green"))
    else:
        print(text)
    if placeholders:
        say(color(f"  headers redacted at capture, fill them in: {', '.join(placeholders)}",
                  "yellow"))
    say(color("  then: python3 engine/poc_runtime.py <spec>.json --md scope.md", "dim"))
    return 0


def _spec_marker(stored: str) -> str:
    """A short string from the captured body worth asserting on."""
    body = stored.split("\n\n", 1)[-1].strip()
    if not body:
        return ""
    try:
        doc = json.loads(body)
    except Exception:  # noqa: BLE001
        return ""
    if isinstance(doc, dict) and doc:
        return f'"{sorted(doc.keys())[0]}"'
    return ""


def cmd_evidence(args: argparse.Namespace) -> int:
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
    from evidence import main as evidence_main  # type: ignore
    return evidence_main([args.path])


def cmd_triage(args: argparse.Namespace) -> int:
    finding_path = Path(args.finding)
    if not finding_path.exists():
        say(color(f"  finding not found: {finding_path}", "red"))
        return 2
    text = finding_path.read_text(encoding="utf-8").lower()

    section(f"triage — {finding_path.name}")
    say(color("Running 7-Question Gate (triage-validation skill)", "cyan"))
    say()

    # Q1 ("can I demonstrate this right now") and Q6 ("can you prove impact")
    # used to be answered by grepping the finding for words like "poc". A finding
    # that *describes* a curl passed that check whether or not it was ever sent.
    # engine/evidence.py answers them from the .result.json poc_runtime writes.
    evidence = None
    if not getattr(args, "no_evidence", False):
        try:
            import sys as _sys
            _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
            from evidence import check as _evidence_check, gate_line as _gate_line  # type: ignore
            evidence = _evidence_check(finding_path)
        except Exception:  # noqa: BLE001
            evidence = None

    answers = []
    for qid, question, signals in TRIAGE_QUESTIONS:
        # Q7 is INVERTED: presence of a "never-submit" signal = answer is "NO" (kill)
        hit = any(s in text for s in signals)
        if qid == "Q7":
            answer = "NO — finding matches never-submit category" if hit else "YES"
            ok = not hit
        elif qid in ("Q1", "Q6") and evidence is not None:
            ok = evidence["status"] == "DEMONSTRATED"
            answer = (f"YES — fired PoC, {evidence['status'].lower()}" if ok
                      else f"NO — {evidence['reason']}")
        else:
            answer = "YES — evidence found" if hit else "NO — no supporting evidence in finding"
            ok = hit
        answers.append((qid, question, answer, ok))
        marker = color("✓", "green") if ok else color("✗", "red")
        say(f"  {marker} {color(qid, 'bold')}: {question}")
        say(f"      → {answer}")
        say()

    if evidence is not None:
        say(color("evidence check (engine/evidence.py)", "cyan"))
        for r in evidence["artifacts"][:5]:
            say(f"      {r['verdict']:<12} {r['file']}")
        if not evidence["artifacts"]:
            say(color("      no .result.json artifact found for this finding", "dim"))
        say(color(f"      {_gate_line(evidence)}", "dim"))
        say()

    fail_qs = [q[0] for q in answers if not q[3]]
    say(color("=" * 70, "blue"))
    if not fail_qs:
        say(color("VERDICT: PASS — all 7 questions answered with evidence.", "green"))
        say(color("Eligible for report drafting via `cbh report <finding.md>`.", "dim"))
        return 0
    if len(fail_qs) == 1 and fail_qs[0] in ("Q2", "Q5"):
        say(color(f"VERDICT: DOWNGRADE — failed {fail_qs[0]} (severity / duplication concerns).", "yellow"))
        say(color("Continue but tone down the severity claim.", "dim"))
        return 1
    say(color(f"VERDICT: KILL — failed {','.join(fail_qs)}.", "red"))
    say(color("Per triage-validation discipline: do not draft the report.", "dim"))
    say(color("Address the failing question(s) or move on.", "dim"))
    return 2


# ============================================================
# report — emit a report draft based on finding metadata
# ============================================================
def parse_finding_metadata(text: str) -> dict:
    """Best-effort parse of YAML-ish frontmatter + section content."""
    md = {"title": "", "severity": "Medium", "asset": "", "endpoint": "",
          "summary": "", "steps": "", "impact": "", "remediation": ""}
    # YAML frontmatter
    m = re.match(r"^---\n(.*?)\n---\n(.*)", text, re.S)
    body = text
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                md[k.strip().lower()] = v.strip().strip('"').strip("'")
        body = m.group(2)
    # Section grabbers
    for key, pat in [
        ("summary", r"##\s*(?:summary|description)\s*\n(.+?)(?=\n##|\Z)"),
        ("steps", r"##\s*(?:steps|reproduction|reproduce|poc)\s*\n(.+?)(?=\n##|\Z)"),
        ("impact", r"##\s*impact\s*\n(.+?)(?=\n##|\Z)"),
        ("remediation", r"##\s*(?:remediation|fix|mitigation)\s*\n(.+?)(?=\n##|\Z)"),
    ]:
        m = re.search(pat, body, re.I | re.S)
        if m and not md.get(key):
            md[key] = m.group(1).strip()
    # First line as title if missing
    if not md["title"]:
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("# "):
                md["title"] = line[2:].strip()
                break
    return md


def render_report(md: dict, platform: str) -> str:
    """Render a report draft using the report-writing + bugcrowd-reporting style.
    Built with plain string concatenation to avoid textwrap.dedent issues with
    multi-line interpolated content."""
    title = md.get("title") or "Untitled finding"
    severity = md.get("severity") or "Medium"
    summary = md.get("summary") or "(fill in)"
    steps = md.get("steps") or "(fill in — curl commands per step)"
    impact = md.get("impact") or "(fill in — concrete dollar / PII / state impact)"
    remediation = md.get("remediation") or "(fill in)"
    asset = md.get("asset") or md.get("endpoint") or "(fill in)"
    user = os.environ.get('USER', 'researcher')
    today = datetime.date.today().isoformat()

    if platform == "bugcrowd":
        return f"""# {title}

**Bug type (VRT):** _to be filled in — pick the closest match from VRT 1.x and include the manual override paragraph below if defaults underrate impact._
**Severity:** {severity}
**Asset:** {asset}
**Date:** {today}

## Severity request

The closest VRT category for this finding is _<VRT-path>_, which Bugcrowd defaults to **<default-severity>**. **I am requesting evaluation at {severity}** for the following reasons:

1. _<concrete impact reason>_
2. _<exploit complexity reason>_
3. _<chained-finding cross-reference if applicable>_

## Summary
{summary}

## Steps to reproduce
{steps}

## Impact
{impact}

## Suggested remediation
{remediation}

## Researcher account
- Bugcrowd handle: _<your-handle>_
- Test account email: _<your-alias>@bugcrowdninja.com_
"""

    if platform == "immunefi":
        slug = re.sub(r"[^a-z0-9]+", "_", title.lower())
        return f"""# {title}

**Severity:** {severity}
**Chain ID / Contract:** {asset}
**Date:** {today}

## Summary
{summary}

## Vulnerability Details
{impact}

## Steps to reproduce (Foundry PoC required)
```bash
forge test --match-test test_{slug} -vvv
```
{steps}

## Proof of Concept
_Attach the Foundry test file producing the exploit._

## Suggested remediation
{remediation}
"""

    common = f"""# {title}

**Severity:** {severity}
**Asset:** {asset}
**Reporter:** {user}
**Date:** {today}

## Summary
{summary}

## Steps to reproduce
{steps}

## Impact
{impact}

## Suggested remediation
{remediation}
"""

    if platform == "intigriti":
        return common + "\n## CVSS 3.1 vector\n`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (fill in)\n"

    # Default: H1
    return common


def _minimal_repro(finding_path: Path) -> tuple[str, str]:
    """Build the short human reproduction from the finding's own fired PoC.

    A technically valid finding still gets closed when the reproduction is twenty
    steps long or never shows a final state change. `engine/poc_minimize.py` already
    solved that; until now nothing called it from the report path, so the verbose
    artifact was all a triager ever saw.

    Only the finding's OWN sibling artifact is used — never a scan of the engagement.
    `evidence.collect()` walks up and rglobs for any `*.result.json`, which is right for
    *asking* whether evidence exists (it reports MISMATCH), and wrong for building a
    report body: it will happily paste a different bug's reproduction steps under this
    finding's title. That is the exact failure `cbh triage` exists to catch, and a report
    generator must not create it.

    Returns (markdown, note). Both empty when there is no fired PoC to minimize —
    a draft with no evidence is still a legitimate draft, `cbh triage` is what says so.
    """
    try:
        sys.path.insert(0, str(REPO_ROOT / "engine"))
        from poc_minimize import render  # type: ignore
    except Exception:  # noqa: BLE001
        return "", ""
    stem = finding_path.stem
    candidates = [finding_path.with_name(f"{stem}.poc.result.json"),
                  finding_path.with_name(f"{stem}.result.json")]
    for result_path in candidates:
        spec_path = result_path.with_name(result_path.name[:-len(".result.json")] + ".json")
        if not (result_path.is_file() and spec_path.is_file()):
            continue
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
            spec = json.loads(spec_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        # Only a PASS belongs in a report body. A FAIL/INCONCLUSIVE artifact rendered
        # as "reproduction steps" is how a draft claims proof it does not have.
        if result.get("final_verdict") != "PASS":
            return "", (f"  {color('note', 'yellow')}: nearest PoC artifact "
                        f"({result_path.name}) is {result.get('final_verdict')}, not PASS — "
                        f"no reproduction embedded. Fire it green first.")
        body = render(spec, result, title="Minimal reproduction")
        return body, f"  Reproduction built from {result_path.name}"
    return "", ("  " + color("note", "yellow") +
                f": no {stem}.poc.result.json beside this finding — the draft carries no "
                "reproduction. Fire the spec with `cbh poc-run` before submitting. "
                "(Only this finding's own artifact is used; evidence from elsewhere in the "
                "engagement is never pasted in.)")


def cmd_report(args: argparse.Namespace) -> int:
    finding_path = Path(args.finding)
    if not finding_path.exists():
        say(color(f"  finding not found: {finding_path}", "red"))
        return 2
    md = parse_finding_metadata(finding_path.read_text(encoding="utf-8"))
    draft = render_report(md, args.platform)
    repro, repro_note = ("", "") if args.no_repro else _minimal_repro(finding_path)
    if repro:
        # The short path first, the machine-readable artifact after it as an appendix:
        # the triager reads top-down and should not have to find the three lines that
        # matter inside a full request/response dump.
        draft = (draft.rstrip() + "\n\n---\n\n"
                 + repro.replace("# Minimal reproduction", "## Minimal reproduction", 1).rstrip()
                 + "\n\n---\n\n## Full evidence (appendix)\n\n"
                   "The verbose request/response artifact stays attached; the steps above are "
                   "the shortest path a triager can follow to see the same result.\n")
    if args.out:
        out_path = Path(args.out).resolve()
        cwd = Path.cwd().resolve()
        # Ancestry check, not str.startswith (which a `<cwd>-evil` sibling bypasses).
        if cwd not in out_path.parents:
            print("[error] --out path must be within cwd", file=sys.stderr); return 1
        out_path.write_text(draft)
        section(f"report — {args.platform}")
        say(f"  Draft written: {color(str(out_path), 'bold')}")
        say()
        say(color("Next:", "bold"))
        say("  • Review the draft — every (fill in) needs operator content")
        say("  • Apply evidence-hygiene before attaching screenshots")
        say(f"  • Submit on {args.platform}")
        if repro_note:
            say(repro_note)
    else:
        print(draft)
    return 0


# ============================================================
# view — local HTML dashboard over a project's findings/hosts/notes
#
# Strix has a browsable local dashboard (`strix view`) over its run output;
# this is the equivalent for the markdown-native engagement layout under
# Targets/<name>/ — findings/, hosts/, notes.md. Read-only, local file only,
# never uploaded anywhere (engagement notes can be sensitive client data).
# ============================================================
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium",
                  "low": "Low", "info": "Info", "informational": "Info"}

_TITLE_RE = re.compile(r"^#\s+(.+)$", re.M)
_SEVERITY_RE = re.compile(r"severity[^:\n]{0,20}:\s*\**\s*(critical|high|medium|low|informational|info)", re.I)
_STATUS_RE = re.compile(r"^status:\s*\**\s*([^\n*]+)", re.I | re.M)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_DATE_RE = re.compile(r"\b(20\d{2}-\d{2}-\d{2})\b")
_HOST_DATE_RE = re.compile(r"^##.*?[—\-]\s*(20\d{2}-\d{2}-\d{2})", re.M)
_FINAL_STATUS_RE = re.compile(r"final status[^\n]*?[:\-—]\s*(.+)", re.I)
# Tolerate the decoration real notes.md files carry — "## Open threads (priority
# order)", "## ★ Open threads". Anchoring on the bare heading matched none of the
# live projects, so the dashboard reported zero open threads everywhere.
_OPEN_THREADS_RE = re.compile(r"^##[^\n]*?\bopen threads?\b[^\n]*$", re.I | re.M)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _collect_findings(findings_dir: Path) -> list[dict]:
    out = []
    if not findings_dir.is_dir():
        return out
    for p in sorted(findings_dir.glob("*.md")):
        text = _read_text(p)
        title_m = _TITLE_RE.search(text)
        sev_m = _SEVERITY_RE.search(text)
        status_m = _STATUS_RE.search(text)
        cve_m = _CVE_RE.search(text)
        dates = _DATE_RE.findall(text)
        sev = sev_m.group(1).lower() if sev_m else ""
        out.append({
            "file": p.name,
            "title": title_m.group(1).strip() if title_m else p.stem,
            "severity": SEVERITY_LABEL.get(sev, "Unknown"),
            "severity_rank": SEVERITY_ORDER.get(sev, 9),
            "status": status_m.group(1).strip() if status_m else "Draft",
            "cve": cve_m.group(0) if cve_m else "",
            "last_date": max(dates) if dates else "",
        })
    out.sort(key=lambda f: (f["severity_rank"], f["title"]))
    return out


def _collect_hosts(hosts_dir: Path) -> list[dict]:
    out = []
    if not hosts_dir.is_dir():
        return out
    for p in sorted(hosts_dir.glob("*.md")):
        text = _read_text(p)
        if not text:
            continue
        title_m = _TITLE_RE.search(text)
        dates = _HOST_DATE_RE.findall(text) or _DATE_RE.findall(text)
        final_m = _FINAL_STATUS_RE.search(text)
        out.append({
            "file": p.name,
            "title": title_m.group(1).strip() if title_m else p.stem,
            "last_touched": max(dates) if dates else "",
            "lines": text.count("\n") + 1,
            "final_status": final_m.group(1).strip()[:140] if final_m else "",
        })
    out.sort(key=lambda h: h["last_touched"], reverse=True)
    return out


_THREAD_ITEM_RE = re.compile(r"^\s*(?:[-*]|\d+[.)])\s+(.*)$")
# A struck-through item, or one whose text announces its own closure, is done.
_THREAD_CLOSED_RE = re.compile(r"^~~|\bCLOSED\b|\bDONE\b|\bDEAD END\b", re.I)


def _has_open_threads_section(notes_path: Path) -> bool:
    return bool(_OPEN_THREADS_RE.search(_read_text(notes_path)))


def _collect_open_threads(notes_path: Path) -> list[str]:
    """Items under the notes' open-threads heading, minus the ones already closed.

    Real notes use `1.` as often as `-`, wrap onto continuation lines, and mark
    finished work with `~~strikethrough~~` in place rather than deleting it.
    """
    text = _read_text(notes_path)
    m = _OPEN_THREADS_RE.search(text)
    if not m:
        return []
    rest = text[m.end():]
    end = re.search(r"^##\s", rest, re.M)
    body = rest[:end.start()] if end else rest

    out = []
    for line in body.splitlines():
        item = _THREAD_ITEM_RE.match(line)
        if not item:
            continue  # continuation line of the previous item
        head = item.group(1).strip()
        if head and not _THREAD_CLOSED_RE.search(head):
            out.append(head)
    return out


def render_dashboard(project: str, findings: list[dict], hosts: list[dict], threads: list[str]) -> str:
    esc = html.escape
    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    sev_rows = "\n".join(
        f'<tr><td><span class="badge sev-{f["severity"].lower()}">{esc(f["severity"])}</span></td>'
        f'<td>{esc(f["title"])}</td><td>{esc(f["status"])}</td>'
        f'<td>{esc(f["cve"])}</td><td>{esc(f["last_date"])}</td>'
        f'<td class="dim">{esc(f["file"])}</td></tr>'
        for f in findings
    ) or '<tr><td colspan="6" class="dim">no findings/*.md yet</td></tr>'

    host_rows = "\n".join(
        f'<tr><td>{esc(h["title"])}</td><td>{esc(h["last_touched"] or "—")}</td>'
        f'<td>{h["lines"]}</td><td>{esc(h["final_status"] or "—")}</td>'
        f'<td class="dim">{esc(h["file"])}</td></tr>'
        for h in hosts
    ) or '<tr><td colspan="5" class="dim">no hosts/*.md yet</td></tr>'

    thread_items = "\n".join(f"<li>{esc(t)}</li>" for t in threads) or '<li class="dim">none parsed from notes.md (## Open Threads)</li>'

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    stat_tiles = "\n".join(
        f'<div class="tile"><div class="tile-n">{n}</div><div class="tile-l">{esc(s)}</div></div>'
        for s, n in sorted(sev_counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0].lower(), 9))
    ) or '<div class="tile"><div class="tile-n">0</div><div class="tile-l">Findings</div></div>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{esc(project)} — hunt dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {{ color-scheme: light dark; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       margin: 0; padding: 2rem; background: #f7f7f8; color: #1a1a1a; }}
h1 {{ font-size: 1.4rem; margin-bottom: .2rem; }}
.meta {{ color: #666; font-size: .85rem; margin-bottom: 1.5rem; }}
.tiles {{ display: flex; gap: .75rem; flex-wrap: wrap; margin-bottom: 2rem; }}
.tile {{ background: #fff; border: 1px solid #e2e2e6; border-radius: 10px;
        padding: .75rem 1.25rem; min-width: 90px; text-align: center; }}
.tile-n {{ font-size: 1.6rem; font-weight: 700; }}
.tile-l {{ font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; color: #888; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; font-size: .88rem;
        background: #fff; border-radius: 10px; overflow: hidden; }}
th, td {{ text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #eee;
         overflow-wrap: anywhere; }}
th {{ background: #eee; font-size: .75rem; text-transform: uppercase; letter-spacing: .03em; }}
.dim {{ color: #999; }}
.badge {{ display: inline-block; padding: .15rem .55rem; border-radius: 999px;
         font-size: .75rem; font-weight: 600; color: #fff; white-space: nowrap; }}
.sev-critical {{ background: #b91c1c; }}
.sev-high {{ background: #c2410c; }}
.sev-medium {{ background: #a16207; }}
.sev-low {{ background: #4b5563; }}
.sev-info, .sev-unknown {{ background: #6b7280; }}
h2 {{ font-size: 1.05rem; margin: 2rem 0 .75rem; }}
li {{ margin-bottom: .3rem; }}
@media (prefers-color-scheme: dark) {{
  body {{ background: #16161a; color: #e8e8ea; }}
  table, .tile {{ background: #1e1e24; border-color: #2c2c34; }}
  th {{ background: #26262e; }}
  tr:nth-child(even) {{ background: #212127; }}
  th, td {{ border-color: #2c2c34; }}
  .dim {{ color: #8a8a94; }}
}}
</style>
</head>
<body>
<h1>{esc(project)}</h1>
<div class="meta">generated {generated} by <code>cbh view</code> · local file, never uploaded anywhere</div>

<div class="tiles">
{stat_tiles}
</div>

<h2>Findings</h2>
<table>
<tr><th>Severity</th><th>Title</th><th>Status</th><th>CVE</th><th>Last date seen</th><th>File</th></tr>
{sev_rows}
</table>

<h2>Hosts</h2>
<table>
<tr><th>Host</th><th>Last touched</th><th>Lines</th><th>Final status</th><th>File</th></tr>
{host_rows}
</table>

<h2>Open threads (from notes.md)</h2>
<ul>
{thread_items}
</ul>
</body>
</html>
"""


def cmd_view(args: argparse.Namespace) -> int:
    project = Path(args.project).resolve()
    if not project.is_dir():
        print(f"[error] not a directory: {project}", file=sys.stderr)
        return 1

    findings = _collect_findings(project / "findings")
    hosts = _collect_hosts(project / "hosts")
    threads = _collect_open_threads(project / "notes.md")

    section(f"view — {project.name}")
    say(f"  {len(findings)} finding(s) · {len(hosts)} host file(s) · {len(threads)} open thread(s)")
    if not _has_open_threads_section(project / "notes.md"):
        say(color("  ⚠ notes.md has no '## Open threads' section — nothing can track "
                  "where you stopped. Add one.", "yellow"))
    for f in findings:
        say(f'  {color(f["severity"], "yellow")}  {f["status"][:28]:<28}  {f["title"]}')

    out_path = Path(args.out) if args.out else project / "dashboard.html"
    try:
        out_path.write_text(render_dashboard(project.name, findings, hosts, threads), encoding="utf-8")
    except OSError as e:
        print(f"[error] could not write {out_path}: {e}", file=sys.stderr)
        return 1
    say()
    say(f"  Dashboard: {color(str(out_path), 'bold')}")
    return 0


# ============================================================
# surface — consume a recon manifest, print the ranked surface
# ============================================================
def _memory(args: argparse.Namespace):
    """Import engine/memory.py and build a Memory bound to the requested dir."""
    sys.path.insert(0, str(REPO_ROOT / "engine"))
    try:
        from memory import Memory  # noqa: PLC0415 - optional, repo-local
    except ImportError:
        say(color("  engine/memory.py not found — run cbh from a full clone", "red"))
        return None
    return Memory(getattr(args, "dir", None),
                  max_mb=getattr(args, "max_mb", None) or 10)


def cmd_remember(args: argparse.Namespace) -> int:
    m = _memory(args)
    if m is None:
        return 2
    entry = {
        "target": args.target, "vuln_class": args.vuln_class, "endpoint": args.endpoint,
        "result": args.result, "severity": args.severity, "payout": args.payout,
        "technique": args.technique, "notes": args.notes,
        "tags": [t.strip() for t in (args.tags or "").split(",") if t.strip()],
        "tech_stack": [t.strip() for t in (args.tech or "").split(",") if t.strip()],
    }
    try:
        written = m.remember(entry)
    except ValueError as e:
        say(color(f"  {e}", "red"))
        return 2
    section(f"remembered — {args.target}")
    say(f"  {args.vuln_class} @ {args.endpoint}  ·  {args.result}")
    say(f"  journal:  {written['journal']}")
    if written["pattern"]:
        say(color(f"  pattern:  {written['pattern']}  (reusable across targets)", "green"))
    say(f"  profile:  {written['profile']}")
    return 0


def _engagement_dir() -> Path | None:
    """The Targets/<name>/ folder the session is sitting in, or None."""
    try:
        sys.path.insert(0, str(REPO_ROOT / "engine"))
        from pacing import find_project_dir  # noqa: PLC0415 - optional sibling module
        return find_project_dir()
    except Exception:  # noqa: BLE001 - engagement detection is advisory
        return None


def _manifest_path(target: str, explicit: str | None = None) -> Path | None:
    """Locate a recon manifest for `target`.

    `cbh recon` writes into the engagement (`Targets/<name>/recon/<target>/`), so
    that is checked first — looking only at REPO_ROOT/recon meant pickup never
    found a manifest at all. The older roots stay as fallbacks.
    """
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None
    roots = []
    project = _engagement_dir()
    if project is not None:
        roots.append(project / "recon")
    roots += [Path.cwd() / "recon", REPO_ROOT / "recon"]
    for base in roots:
        cand = base / target / "manifest.json"
        if cand.exists():
            return cand
    return None


def _say_engagement_state() -> None:
    """Report what the engagement folder itself knows.

    hunt-memory and `Targets/<name>/` are two separate records, and the JSONL one
    is the newer and thinner of the two. A project with 38 host files and 8
    findings used to print "no previous hunt data" purely because nobody had
    called /remember on it.
    """
    project = _engagement_dir()
    if project is None:
        return
    hosts = _collect_hosts(project / "hosts")
    findings = _collect_findings(project / "findings")
    threads = _collect_open_threads(project / "notes.md")
    say(color(f"  engagement {project.name}", "bold") +
        f"  ·  {len(hosts)} host file(s)  ·  {len(findings)} finding(s)  ·  "
        f"{len(threads)} open thread(s)")
    recent = [h for h in hosts if h["last_touched"]][:3]
    if recent:
        say(color("    last touched: " + ", ".join(
            f"{h['file'].removesuffix('.md')} ({h['last_touched']})" for h in recent), "dim"))
    if not _has_open_threads_section(project / "notes.md"):
        say(color("    ⚠ notes.md has no '## Open threads' section — add one, or "
                  "nothing here can tell you where you stopped.", "yellow"))
    for t in threads[:5]:
        say(f"    ▸ {t[:150]}")
    if len(threads) > 5:
        say(color(f"    … {len(threads) - 5} more in notes.md", "dim"))
    say()


def cmd_pickup(args: argparse.Namespace) -> int:
    m = _memory(args)
    if m is None:
        return 2
    untested = []
    mpath = _manifest_path(args.target)
    if mpath is not None:
        try:
            man = json.loads(mpath.read_text(encoding="utf-8"))
            untested = [r.get("url") or r.get("host")
                        for r in man.get("ranked_surface", []) if r.get("priority") != "KILL"]
        except Exception:  # noqa: BLE001 - manifest is advisory here
            pass
    p = m.pickup(args.target, untested=untested)

    section(f"pickup — {args.target}")
    _say_engagement_state()
    if not p["known"]:
        say(color(f"  no hunt-memory entries for {args.target}", "dim"))
        say(f"  Run: {color('cbh recon ' + args.target, 'bold')}, "
            f"then /hunt {args.target}")
        return 0
    say(f"  sessions {p['sessions']}  ·  last hunt {p['last_hunt']}  ·  "
        f"{p['journal_entries']} journal entrie(s)")
    if p["tech_stack"]:
        say(f"  stack: {', '.join(p['tech_stack'])}")
    if p["findings"]:
        say()
        say(color("  Confirmed findings", "bold"))
        for f in p["findings"]:
            say(f"    {f['vuln_class']} @ {f['endpoint']}  "
                f"[{f.get('severity') or '?'}]  {f.get('payout') or 0}")
        say(f"    total payout: {p['total_payout']}")
    if p["untested_endpoints"]:
        say()
        say(color(f"  Untested surface ({len(p['untested_endpoints'])})", "bold"))
        for u in p["untested_endpoints"][:15]:
            say(f"    {u}")
    if p["tested_endpoints"]:
        say()
        say(color(f"  Already tested ({len(p['tested_endpoints'])}) — do not re-burn", "dim"))
        for t in p["tested_endpoints"][:10]:
            say(color(f"    {t}", "dim"))
    if p["suggestions"]:
        say()
        say(color("  Memory suggestions (confirmed on an overlapping stack elsewhere)", "cyan"))
        for s in p["suggestions"]:
            say(f"    {s['vuln_class']} — {s.get('technique') or 'see journal'}  "
                f"(from {s['from']}, shares {', '.join(s['shared_stack'])})")
    say()
    say(f"  Next: {color('/hunt ' + args.target, 'bold')} or "
        f"{color('cbh surface ' + args.target, 'bold')}")
    return 0


def cmd_vectors(args: argparse.Namespace) -> int:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent / "engine"))
    from vectors import main as vectors_main  # type: ignore
    return vectors_main(args.rest)


def cmd_engine_tool(args: argparse.Namespace) -> int:
    """Passthrough to one offline engine module while keeping cbh as the entry point."""
    sys.path.insert(0, str(REPO_ROOT / "engine"))
    modules = {
        "api-manifest": "api_manifest", "authz-matrix": "authorization_matrix",
        "workflow": "workflow_graph", "recon-diff": "recon_delta",
        "report-intel": "report_intel", "poc-minimize": "poc_minimize",
        "memory-migrate": "memory_migrate", "program-quality": "program_quality",
        "identity": "identity",
        "oracle": "diff_matrix", "sweep": "sweep", "anomaly": "anomaly", "coverage": "coverage",
        "debrief": "session_debrief", "learn": "learn",
    }
    module = __import__(modules[args.command], fromlist=["main"])
    rest = ["--help"] if getattr(args, "tool_help", False) else args.rest
    return module.main(rest)


def cmd_memory_gc(args: argparse.Namespace) -> int:
    m = _memory(args)
    if m is None:
        return 2
    section(f"hunt memory — {m.dir}")
    rows = m.stats()
    say(f"  {'file':<18}{'live':>12}{'total':>12}{'backups':>9}  status")
    for r in rows:
        status = color("OVER CAP", "red") if r["over_cap"] else color("ok", "dim")
        say(f"  {r['file']:<18}{r['live_bytes'] / 1e6:>11.2f}M"
            f"{r['total_bytes'] / 1e6:>11.2f}M{r['backup_count']:>9}  {status}")
    responses = _responses_mod()
    cstat = responses.corpus_stats()
    say()
    say(f"  response corpus: {cstat['files']} bodies, {cstat['bytes'] / 1e6:.2f}M "
        f"across {len(cstat['engagements'])} engagement(s)")
    say(color(f"  {cstat['root']} — captured response bodies, other users' data by nature. "
              "Working cache, not an archive.", "dim"))
    if args.prune_responses:
        res = responses.prune(args.prune_responses, dry_run=not args.rotate)
        verb = "would remove" if res["dry_run"] else "removed"
        say(color(f"  {verb} {res['removed']} bodies older than {args.prune_responses}d "
                  f"({res['bytes'] / 1e6:.2f}M)" + ("  — add --rotate to act" if res["dry_run"] else ""),
                  "yellow"))

    if args.rotate or args.purge_backups:
        actions = m.gc(do_rotate=args.rotate, purge_backups=args.purge_backups)
        say()
        for a in actions or ["nothing to do"]:
            say(f"  {a}")
    else:
        say()
        say(color(f"  report only — cap {m.max_mb}MB. "
                  f"Use --rotate / --purge-backups to act.", "dim"))
    return 0

def cmd_tools(args: argparse.Namespace) -> int:
    sys.path.insert(0, str(REPO_ROOT / "engine"))
    from tool_runtime import main as tool_main
    return tool_main(args.rest)


def cmd_surface(args: argparse.Namespace) -> int:
    target = args.target
    mpath = _manifest_path(target, getattr(args, "manifest", None))
    if mpath is None:
        print(f"[error] no recon manifest for {target}. Run:  cbh recon {target}", file=sys.stderr)
        return 1
    try:
        m = json.loads(mpath.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[error] could not parse {mpath}: {e}", file=sys.stderr)
        return 1

    section(f"surface — {m.get('target', target)}")
    c = m.get("counts", {})
    say(f"  {c.get('live', '?')} live / {c.get('resolved', '?')} resolved / "
        f"{c.get('subdomains', '?')} subdomains   ·   {mpath}")
    ranked = m.get("ranked_surface", [])
    colors = {"P1": "green", "P2": "yellow", "KILL": "dim"}
    for prio, label in (("P1", "Priority 1 — start here"),
                        ("P2", "Priority 2 — after P1"),
                        ("KILL", "Kill list — skip")):
        items = [r for r in ranked if r.get("priority") == prio]
        if not items:
            continue
        say()
        say(color(label, "bold"))
        for r in items:
            classes = ", ".join(r.get("bug_classes", [])) or color("no class match", "dim")
            say(f"  {color(r.get('url') or r.get('host'), colors.get(prio, 'cyan'))}")
            say(f"      {classes}   ·   {r.get('rationale', '')}")
    secrets = m.get("secrets", [])
    idf = m.get("identity_fabric", {})
    if secrets:
        say()
        say(color(f"  ⚠ {len(secrets)} secret(s) flagged in manifest", "red"))
    if idf:
        say(color(f"  identity fabric: {', '.join(idf.keys())}", "cyan"))
    say()
    say(f"  Next: {color('/hunt ' + target, 'bold')} in Claude Code, "
        f"or {color('cbh classify <url>', 'bold')} for a single URL")
    return 0


# ============================================================
# Main dispatcher
# ============================================================
def main() -> int:
    parser = argparse.ArgumentParser(
        prog="cbh",
        description=("claude-bughunter CLI — terminal-native deterministic runner.\n"
                     "SECONDARY interface; slash commands (/hunt, /recon, /triage, /report) "
                     "in Claude Code are PRIMARY. Use cbh for CI/CD, scripted runs, "
                     "deterministic verification, or when not in a Claude Code session."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              cbh recon hackerone.com
              cbh recon target.com --burp                  # route via Burp proxy
              cbh classify "https://api.target.com/v1/users/42?next=https://evil.com"
              cbh triage findings/idor-2026-05-15.md
              cbh report findings/idor-2026-05-15.md --platform bugcrowd --out draft.md
              cbh view ~/Targets/acme                       # local dashboard.html

            For LLM-driven hunting with full skill context, use the slash commands
            inside Claude Code: /hunt /recon /triage /report /validate /chain /autopilot
            See docs/cbh-cli.md for the "when to use which" matrix.
            """),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_proxy_args(p):
        p.add_argument("--burp", action="store_true",
                       help="Route HTTP through Burp Suite proxy (auto-detects 127.0.0.1:8080)")
        p.add_argument("--proxy", help="Explicit proxy URL (overrides --burp)")

    p_recon = sub.add_parser("recon", help="passive recon + live-host probe + summary")
    p_recon.add_argument("target", help="root domain, e.g. hackerone.com")
    p_recon.add_argument("--out", help="output directory for recon/<target>/ "
                         "(default: repo recon/ in a clone, ./recon/ when installed)")
    _add_proxy_args(p_recon)
    p_recon.set_defaults(func=cmd_recon)

    p_surface = sub.add_parser("surface", help="rank a target's attack surface from its recon manifest")
    p_surface.add_argument("target", help="target whose recon/<target>/manifest.json to read")
    p_surface.add_argument("--manifest", help="explicit path to a manifest.json")
    p_surface.set_defaults(func=cmd_surface)

    p_class = sub.add_parser("classify", help="pattern-match URL to hunt-* skills")
    p_class.add_argument("url", help="single URL to classify")
    _add_proxy_args(p_class)
    p_class.set_defaults(func=cmd_classify)

    p_triage = sub.add_parser("triage", help="run 7-Question Gate on a finding")
    p_triage.add_argument("finding", help="path to finding markdown file")
    p_triage.add_argument("--no-evidence", action="store_true",
                          help="answer Q1/Q6 from the finding text instead of a fired "
                               "PoC artifact (weaker; for drafts only)")
    p_triage.set_defaults(func=cmd_triage)

    p_ev = sub.add_parser("evidence", help="is a finding backed by a fired PoC (.result.json)?")
    p_ev.add_argument("path", help="finding markdown, engagement dir, or a .result.json")
    p_ev.set_defaults(func=cmd_evidence)

    p_diff = sub.add_parser("diff", help="did the target's answer ever change? (response corpus)")
    p_diff.add_argument("url", nargs="?", default="", help="substring of the URL to look at")
    p_diff.add_argument("--engagement", default="", help="limit to one engagement")
    p_diff.add_argument("--max-lines", type=int, default=60, help="diff lines to print")
    p_diff.add_argument("--fields", action="store_true",
                        help="per-field movement across captures: which fields ever changed, "
                             "and which answered every request the same way")
    p_diff.set_defaults(func=cmd_diff)

    p_spec = sub.add_parser("spec", help="generate a poc_runtime spec from a request already fired")
    p_spec.add_argument("url", help="substring of the URL to rebuild")
    p_spec.add_argument("--engagement", default="", help="limit to one engagement")
    p_spec.add_argument("--vuln-class", default="", help="vuln_class to stamp on the spec")
    p_spec.add_argument("--steps", action="store_true",
                        help="emit a multi-step chain skeleton instead of a single shot")
    p_spec.add_argument("--out", default="", help="write the spec here instead of stdout")
    p_spec.set_defaults(func=cmd_spec)

    p_report = sub.add_parser("report", help="emit a report draft")
    p_report.add_argument("finding", help="path to finding markdown file")
    p_report.add_argument("--platform", default="h1",
                          choices=["h1", "bugcrowd", "intigriti", "immunefi"])
    p_report.add_argument("--out", help="write draft to this path (else print to stdout)")
    p_report.add_argument("--no-repro", action="store_true",
                          help="skip the minimized reproduction section")
    p_report.set_defaults(func=cmd_report)

    p_view = sub.add_parser("view", help="generate a local HTML dashboard from a project's findings/hosts/notes")
    p_view.add_argument("project", help="path to the engagement project dir (e.g. ~/Targets/acme)")
    p_view.add_argument("--out", help="output HTML path (default: <project>/dashboard.html)")
    p_view.set_defaults(func=cmd_view)

    # ---- hunt memory (backs /remember, /pickup, /memory-gc) ----
    p_rem = sub.add_parser("remember", help="log a finding/attempt to persistent hunt memory")
    p_rem.add_argument("--target", required=True)
    p_rem.add_argument("--vuln-class", required=True, dest="vuln_class",
                       help="e.g. idor, ssrf, business-logic")
    p_rem.add_argument("--endpoint", required=True)
    p_rem.add_argument("--result", required=True,
                       choices=["confirmed", "rejected", "partial", "informational",
                                "duplicate", "submitted", "accepted", "paid", "na",
                                "downgraded"])
    p_rem.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"])
    p_rem.add_argument("--payout", type=float, default=0)
    p_rem.add_argument("--technique", help="short slug, e.g. numeric_id_swap_on_put")
    p_rem.add_argument("--tech", help="comma-separated stack, e.g. 'Next.js,GraphQL'")
    p_rem.add_argument("--tags", help="comma-separated tags")
    p_rem.add_argument("--notes")
    p_rem.add_argument("--dir", help="hunt-memory directory (default: $CBH_MEMORY_DIR)")
    p_rem.set_defaults(func=cmd_remember)

    p_pick = sub.add_parser("pickup", help="resume view for a target: history, untested surface")
    p_pick.add_argument("target")
    p_pick.add_argument("--dir", help="hunt-memory directory (default: $CBH_MEMORY_DIR)")
    p_pick.set_defaults(func=cmd_pickup)

    p_gc = sub.add_parser("memory-gc", help="report or rotate hunt-memory JSONL files")
    p_gc.add_argument("--rotate", action="store_true", help="rotate files at/over the cap")
    p_gc.add_argument("--purge-backups", action="store_true", dest="purge_backups")
    p_gc.add_argument("--max-mb", type=int, default=10, dest="max_mb")
    p_gc.add_argument("--dir", help="hunt-memory directory (default: $CBH_MEMORY_DIR)")
    p_gc.add_argument("--prune-responses", type=float, metavar="DAYS", default=0,
                      help="drop stored response bodies older than DAYS (needs --rotate to act)")
    p_gc.set_defaults(func=cmd_memory_gc)

    # vectors — the anti-dead-end ledger. Passthrough so there is exactly one
    # implementation (engine/vectors.py) and `cbh` stays the single entry point.
    p_vec = sub.add_parser(
        "vectors",
        help="attack-vector ledger: seed-from-manifest / next / rotate / revisit / prune / stuck")
    p_vec.add_argument("rest", nargs=argparse.REMAINDER,
                       help="subcommand + args, e.g. `next web.example.com -n 5`")
    p_vec.set_defaults(func=cmd_vectors)

    p_tools = sub.add_parser("tools", help="local MCP/tool runtime diagnostics")
    p_tools.add_argument("rest", nargs=argparse.REMAINDER)
    p_tools.set_defaults(func=cmd_tools)

    for name, help_text in (
        ("api-manifest", "normalize OpenAPI/HAR/Postman/Burp/GraphQL inputs"),
        ("authz-matrix", "plan or evaluate principal/object/action checks"),
        ("workflow", "derive business-state hypotheses from an API manifest"),
        ("recon-diff", "compare recon/API snapshots"),
        ("report-intel", "search a local disclosed-report dataset"),
        ("poc-minimize", "render a short triager-facing reproduction"),
        ("memory-migrate", "normalize the hunt-memory schema (dry-run by default)"),
        ("program-quality", "acceptance/duplicate/N-A rates and time-to-verdict per program"),
        ("identity", "self-provision a throwaway test identity (temp email/phone)"),
        ("oracle", "differential oracle plan: baseline-vs-probe comparisons from a manifest"),
        ("sweep", "FIRE the oracle plan (scope/pacing gated, writes off by default) and report only anomalies"),
        ("anomaly", "class-agnostic anomalies, assumptions to invert, invariants"),
        ("coverage", "negative space: which request dimensions were ever varied"),
        ("debrief", "append a full-prose session debrief to the engagement's notes.md"),
        ("learn", "novel techniques + technique yield + suggestions from hunt memory"),
    ):
        p = sub.add_parser(name, help=help_text, add_help=False)
        p.add_argument("-h", "--help", action="store_true", dest="tool_help")
        p.add_argument("rest", nargs=argparse.REMAINDER)
        p.set_defaults(func=cmd_engine_tool)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
