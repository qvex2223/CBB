#!/usr/bin/env python3
"""bbradar.io watcher: report newly listed programs that fit the web-app stack.

First run baselines silently (every current id is marked seen). Later runs list
only ids not seen before, filtered and ranked, and append them to
Targets/BBRADAR-NEW.md. Stdlib only.

  bbradar-watch.py                 poll, print + write digest, send `notify` if present
  bbradar-watch.py --baseline      mark everything seen, print nothing
  bbradar-watch.py --all           ignore seen state, show every matching program
  bbradar-watch.py --dry-run       do not touch state or digest
Platforms: HackerOne, BI.ZONE, Standoff365, Intigriti only. Eligibility per platform (BI.ZONE RF-only,\nStandoff open-to-foreigners + AI-ban list). Tier A = stack hints sum >= min_stack_score (loud); tier B = web-fit, no stack match (quiet section).

Key: $BBRADAR_API_KEY or ~/.config/bbradar/key (chmod 600). Never printed.
Filters: ~/.config/bbradar/filter.json overrides DEFAULT_FILTER key by key.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
try:
    from engine.paths import memory_dir, targets_root
except Exception:  # fall back to repo layout
    memory_dir = lambda: ROOT / "hunt-memory"
    targets_root = lambda: ROOT / "Targets"

API = "https://bbradar.io/api/v1/pro/programs"
CONF_DIR = Path.home() / ".config" / "bbradar"

DEFAULT_FILTER = {
    # program must expose at least one of these scope tags (web-app surface)
    "need_any_tags": ["domain", "wildcard", "api"],
    # ...and a program whose only surface is one of these is dropped (web3/mobile/binary)
    "web3_tags": ["smart contract", "solidity", "web3", "blockchain-dlt", "rust", "move",
                  "cairo", "clarity", "vyper", "yul", "bitcoin script", "multi chain",
                  "rwa", "concordium", "wemix3.0"],
    "drop_if_only_web3": True,
    "paid_only": True,            # drops VDP / no-reward programs
    "web_only": True,             # keep only programs with domain/wildcard/api scope (our tool stand)
    "stack_filter": True,         # rank/mark programs whose targets match our frameworks (passive hints)
    "min_bounty_max": 0,
    "platforms": ["HackerOne", "BI.ZONE", "Standoff365", "Intigriti"],   # the only four we work on
    "exclude_platforms": ["Immunefi", "Cantina", "Sherlock", "CertiK", "AuditOne", "Code4rena", "Remedy", "HackenProof-Web3"],  # web3 audit platforms
    "exclude_competition": [],    # e.g. ["High"]
    "min_in_scope_targets": 1,
    "min_stack_score": 4,         # tier A = stack hints sum to at least this
    "max_age_days": 3,            # launched within this many days; older programs newly seen in the catalog are ignored
    "hint_max": 60,              # bbradar calls per run (one per candidate, best base score first)
}


def load_key():
    k = os.environ.get("BBRADAR_API_KEY", "").strip()
    if not k:
        p = CONF_DIR / "key"
        if p.exists():
            k = p.read_text().strip()
    if not k:
        sys.exit("no key: set BBRADAR_API_KEY or write ~/.config/bbradar/key")
    return k


def load_filter():
    f = dict(DEFAULT_FILTER)
    p = CONF_DIR / "filter.json"
    if p.exists():
        f.update(json.loads(p.read_text()))
    return f


def get(key, params, url=API):
    url = url + "?" + urllib.parse.urlencode(params)
    for attempt in range(5):
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}",
                                                   "User-Agent": "cbh-bbradar-watch/1"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (429, 503):
                time.sleep(int(e.headers.get("Retry-After", "5")))
                continue
            if e.code == 401:
                sys.exit("401: key rejected")
            raise
        except urllib.error.URLError:
            time.sleep(2 ** attempt)
    sys.exit("bbradar unreachable")


def fetch_all(key):
    out, page = {}, 1
    while True:
        d = get(key, {"page": page, "page_size": 100})
        for p in d["programs"]:      # the live catalog shifts between pages, so one program can appear twice
            out[p["id"]] = p
        if not d["meta"].get("has_more"):
            return list(out.values())
        page += 1


def fits(p, f):
    if not p.get("is_active", True) or p.get("program_status", "active") != "active":
        return False
    tags = {t.lower() for t in p.get("scope_tags") or []}
    if not tags & set(f["need_any_tags"]):
        return False
    web3 = set(f["web3_tags"])
    if f["drop_if_only_web3"] and tags and tags <= (web3 | {"source code", "other"}):
        return False
    if f["paid_only"] and (p.get("program_kind") != "bounty" or p.get("reward_status") == "none"
                           or not (p.get("bounty_max") or 0) > 0):
        return False
    if (p.get("bounty_max") or 0) < f["min_bounty_max"]:
        return False
    if f["platforms"] and p["platform"] not in f["platforms"]:
        return False
    if p["platform"] in f["exclude_platforms"]:
        return False
    if p.get("competitionRisk") in f["exclude_competition"]:
        return False
    if (p.get("target_counts") or {}).get("in_scope", 0) < f["min_in_scope_targets"]:
        return False
    return True


# Passive stack hints. Matched against what bbradar says about a program (target
# identifiers, display names, language tags, program name); no request ever goes
# to a program host. Labels and weights come from our own hunt-memory (what we
# actually tested/confirmed): SPA/SSR JS frameworks, Rails, grpc-gateway/Envoy/Go,
# ASP.NET Core, Strapi, GraphQL, Keycloak/OIDC SSO. "biz" labels are weak context.
STACK_HINTS = [
    (r"nuxt|svelte|sveltekit|next\.?js|_next|vercel\.app|netlify\.app|\bvue\b|\breact\b|remix|astro", "js-spa/ssr", 4),
    (r"rails|\brack\b|\.rb\b", "rails", 4),
    (r"grpc|envoy|istio|golang", "go/grpc/envoy", 3),
    (r"asp\.net|signalr|\bc#|sharepoint|\.aspx?\b|\.asmx|\.ashx|azurewebsites", "aspnet", 3),
    (r"strapi|directus|payload ?cms", "headless-cms", 4),
    (r"graphql|apollo|hasura", "graphql", 3),
    (r"keycloak|oidc|openid|oauth|\bsso\b|\bidp\b|auth0|okta|saml", "sso/oauth", 3),
    (r"laravel|symfony|\.php\b|\bphp\b", "php", 2),
    (r"spring|actuator|\.jsp\b|tomcat|jenkins|jira|confluence", "java", 2),
    (r"express|nodejs|node\.js|koa|nestjs|herokuapp|onrender\.com", "node", 2),
    (r"lang:(javascript|typescript)", "js-lang", 1),
    (r"lang:ruby", "lang-ruby", 2),
    (r"lang:go\\b", "lang-go", 2),
    (r"lang:c#", "lang-c#", 2),
]
BIZ_HINTS = [  # context only: sectors our past programs came from; never enough alone
    (r"bank|fintech|\bpay|payment|kyc|lending|leasing|factoring|invoice|accounting|payroll|\bhr\b|saas|marketplace|shop|store|ecommerce|e-commerce", "biz-fit", 1),
]
PLATFORM_BONUS = {"Intigriti": 2}  # platforms we already run engagements on


def program_blob(p, targets):
    parts = [p.get("name") or "", p.get("handle") or "", p.get("link") or ""]
    parts += [f"lang:{t}" for t in p.get("scope_tags") or []]
    for t in targets:
        parts += [t.get("identifier") or "", t.get("display_name") or ""]
        parts += [f"lang:{x}" for x in (t.get("language_tags") or [])]
    return " ".join(parts).lower()


def stack_hints(key, p):
    """Fetch the program's targets from bbradar (not from the program) and match hints."""
    import re
    path = urllib.parse.quote(p["id"], safe=":/")
    try:
        d = get(key, {"page_size": 500, "include_out_of_scope": "false"},
                url=API + "/" + path + "/targets")
    except Exception:
        return []
    tg = [t for t in d.get("targets", []) if t.get("in_scope", True)]
    p["_targets"] = tg
    blob = program_blob(p, tg)
    return [(lab, w) for rx, lab, w in STACK_HINTS + BIZ_HINTS if re.search(rx, blob)]


STRONG_LABELS = {"js-spa/ssr", "rails", "go/grpc/envoy", "aspnet", "headless-cms", "graphql"}


def stack_score(p):
    """Weak labels (sso/oauth, java, node, php, cms, lang-*) only count once a strong framework label is present."""
    h = [(lab, w) for lab, w in p.get("_hints", []) if lab != "biz-fit"]
    if not any(lab in STRONG_LABELS for lab, _ in h):
        return 0
    return sum(w for _, w in h)


def score(p):
    tags = {t.lower() for t in p.get("scope_tags") or []}
    tc = p.get("target_counts") or {}
    s = min((p.get("bounty_max") or 0) / 1000, 30)
    s += sum(b for _, b in p.get("_hints", []))
    s += PLATFORM_BONUS.get(p.get("platform"), 0)
    s += 8 if "wildcard" in tags else 0
    s += 4 if "api" in tags else 0
    s += min(tc.get("in_scope", 0), 20) / 4
    s += {"Low": 6, "Medium": 2, "High": -4}.get(p.get("competitionRisk"), 0)
    return round(s, 1)


def line(p):
    tc = p.get("target_counts") or {}
    return (f"[{score(p):>5}] {p['platform']:<12} {p['name'][:42]:<42} "
            f"${int(p.get('bounty_min') or 0)}-{int(p.get('bounty_max') or 0)} "
            f"tags={','.join(p.get('scope_tags') or [])} "
            f"scope={tc.get('in_scope', 0)}/wild={tc.get('wildcard', 0)} "
            f"stack={','.join(h for h, _ in p.get('_hints', [])) or '-'} "
            f"risk={p.get('competitionRisk', '?')} launched={p.get('date_launched')} {p.get('link')}")


def tg_creds():
    t, c = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    f = CONF_DIR / "telegram.json"
    if (not t or not c) and f.exists():
        d = json.loads(f.read_text())
        t, c = d.get("bot_token"), d.get("chat_id")
    return t, c


def tg_send(text, html=False):
    t, c = tg_creds()
    if not (t and c):
        return False
    f = CONF_DIR / "telegram.json"
    m = json.loads(f.read_text()).get("mention") if f.exists() else None
    if m:
        text = f"{m}\n{text}"
    fields = {"chat_id": c, "text": text[:4000], "disable_web_page_preview": "true"}
    if html:
        fields["parse_mode"] = "HTML"
    data = urllib.parse.urlencode(fields).encode()
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"https://api.telegram.org/bot{t}/sendMessage", data=data), timeout=20).read()
        return True
    except Exception as e:  # token is in the URL: never print the exception text
        print(f"telegram send failed: {type(e).__name__}", file=sys.stderr)
        return False


# Where to start, per stack label. Each entry is (what to check, hunt-* skill).
# Taken from what paid or got confirmed in our own hunt-memory, not from theory.
VECTORS = {
    "js-spa/ssr": ("бандлы и source map, SSR-payload (__NEXT_DATA__/__NUXT__), CSPT и postMessage", "hunt-source-leak, hunt-cspt, hunt-dom"),
    "rails": ("маршруты без before_action, разница 401/404 как оракул существования", "hunt-idor, hunt-auth-bypass"),
    "go/grpc/envoy": ("grpc-gateway: HEAD/метод-оракул маршрутов, reflection", "hunt-grpc, hunt-api-misconfig"),
    "aspnet": ("SignalR-хабы, NTLM-info, ASP.NET auth-обходы", "hunt-aspnet, hunt-ntlm-info"),
    "headless-cms": ("публичный API CMS, учётки админов в ответах, /admin", "hunt-api-misconfig, hunt-nodejs"),
    "graphql": ("introspection, node()/batch, мутации без авторизации", "hunt-graphql"),
    "sso/oauth": ("redirect_uri, state, привязка аккаунтов, открытый редирект", "hunt-oauth, hunt-open-redirect"),
    "php": ("include/файловые параметры, Laravel debug", "hunt-laravel, hunt-lfi"),
    "java": ("/actuator, Spring-эндпоинты, CVE по версии", "hunt-springboot"),
    "node": ("prototype pollution, SSRF в URL-параметрах", "hunt-nodejs, hunt-ssrf"),
}
HOT_HOST = ("api", "auth", "sso", "login", "id.", "admin", "graphql", "gateway", "bff", "cabinet", "lk.", "partner")


NON_WEB_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "apps.apple.com", "play.google.com",
                 "npmjs.com", "pypi.org", "hub.docker.com", "crates.io", "rubygems.org")
HOSTNAME_RE = r"^(https?://)?(\*\.)?[a-z0-9][a-z0-9.\[\]-]*\.[a-z]{2,}(:\d+)?(/\S*)?$"


def web_target(t):
    """True only for something we can recon: a host/wildcard/API URL, not a repo, app, or prose."""
    import re
    ident = (t.get("identifier") or "").strip().lower()
    if not ident or " " in ident or any(h in ident for h in NON_WEB_HOSTS):
        return False
    if t.get("target_type") in ("source code", "mobile", "hardware", "executable", "ai", "smart contract"):
        return False
    return bool(re.match(HOSTNAME_RE, ident))


def start_plan(p):
    """Passive: ranks bbradar's own target rows; nothing is sent to the program."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)

    def rank(t):
        ident = (t.get("identifier") or "").lower()
        sc = 3 if t.get("wildcard") else 0
        sc += 2 if any(h in ident for h in HOT_HOST) else 0
        try:
            added = datetime.fromisoformat((t.get("added_at") or "").replace("Z", "+00:00"))
            sc += 2 if now - added < timedelta(days=30) else 0
        except ValueError:
            pass
        return sc

    tg = sorted((t for t in p.get("_targets") or [] if web_target(t)), key=rank, reverse=True)
    hosts = [t["identifier"] for t in tg if t.get("identifier") and rank(t) > 0][:3] or \
            [t["identifier"] for t in tg[:3] if t.get("identifier")]
    vec = [VECTORS[h] for h, _ in p.get("_hints", []) if h in VECTORS][:3]
    return hosts, vec


# Eligibility: can OUR operator (Kazakhstan, EAEU) actually take part? Checked per platform,
# from the platform's own public data. Returns (ok, warning). ok=False drops the program.
import re as _re
BIZONE_API = "https://bugbounty.bi.zone/api/bug-bounty/companies/"
BIZONE_RF_ONLY = _re.compile(r"только\s+(дееспособные\s+)?граждан\w*\s+Российской", _re.I)
STANDOFF_HUB = ROOT / "Targets" / "standoff365"


def _plain_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


STANDOFF_BASE = "https://bugbounty.standoff365.com"


def standoff_listing():
    """Programs open to any citizenship, as the platform lists them. Newest local snapshot if fresh,
    else fetched live (cached 6 h next to the seen-state), so the script needs no repo around it."""
    snaps = sorted((STANDOFF_HUB / "raw").glob("programs-*/_listing.json"))
    if snaps and time.time() - snaps[-1].stat().st_mtime < 36 * 3600:
        return json.loads(snaps[-1].read_text())
    cache = Path(memory_dir()) / "standoff-listing.json"
    if cache.exists() and time.time() - cache.stat().st_mtime < 6 * 3600:
        return json.loads(cache.read_text())
    try:
        hdr = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) bbradar-watch"}
        rq = lambda u: urllib.request.urlopen(urllib.request.Request(u, headers=hdr), timeout=30).read()
        html = rq(f"{STANDOFF_BASE}/en-US/programs/?allowedCountries=true").decode("utf-8", "replace")
        build = _re.search(r'"buildId":"([^"]+)"', html).group(1)
        out, page, pages = [], 1, 1
        while page <= pages:
            d = json.loads(rq(f"{STANDOFF_BASE}/_next/data/{build}/en-US/programs.json"
                              f"?allowedCountries=true&page={page}"))["pageProps"]
            pages = int(d.get("total") or 1)
            out += d.get("programs") or []
            page += 1
            time.sleep(1)
        out = [x for x in out if x.get("status") == "published"]
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(out))
        return out
    except Exception as ex:
        print(f"standoff listing unavailable: {type(ex).__name__}", file=sys.stderr)
        return json.loads(snaps[-1].read_text()) if snaps else None


def standoff_open_slugs():
    """Slugs of Standoff programs open to any citizenship, or None if the listing cannot be had."""
    lst = standoff_listing()
    return None if lst is None else {x.get("slug") for x in lst}


def standoff_ai_banned():
    """Kept for callers. Empty: VK/MAX/RuStore folders no longer carry an AI-ban avatar."""
    return set()


def standoff_published():
    """slug -> publishedAt (ISO)."""
    lst = standoff_listing()
    return {} if lst is None else {x.get("slug"): x.get("publishedAt") for x in lst}


def launch_iso(p, ctx=None):
    """Real launch date (YYYY-MM-DD) or ''. bbradar added_at is the catalog date, so it is never used."""
    iso = (p.get("launch_at") or p.get("date_launched") or "")[:10]
    if not iso and p.get("platform") == "Standoff365" and ctx:
        iso = (ctx["standoff_pub"].get(p.get("handle")) or "")[:10]
    return iso


def eligibility(p, ctx):
    plat, handle = p["platform"], p.get("handle") or ""
    if plat == "BI.ZONE":
        try:
            rules = _plain_get(BIZONE_API + urllib.parse.quote(handle) + "/").get("rules") or ""
        except Exception:
            return True, "допуск BI.ZONE не проверен (API недоступен)"
        if BIZONE_RF_ONLY.search(rules):
            return False, "только граждане РФ"
        return True, None
    if plat == "Standoff365":
        if ctx["standoff_open"] is None:
            return True, "допуск Standoff не проверен (нет снимка)"
        if handle not in ctx["standoff_open"]:
            return False, "Standoff: не открыта для иностранцев"
        return True, None
    return True, None


RISK_ICON = {"Low": "🟢", "Medium": "🟡", "High": "🔴"}
MEDALS = ["🥇", "🥈", "🥉"]


def stack_line(p):
    """Short 'what is this program made of': scope kinds + frameworks seen in its targets."""
    kinds = [t for t in (p.get("scope_tags") or []) if t.lower() in
             ("domain", "wildcard", "api", "web", "mobile", "ip", "cidr", "source code", "other")]
    fw = [h for h, _ in p.get("_hints", []) if h not in ("biz-fit", "js-lang") and not h.startswith("lang-")]
    return ", ".join(dict.fromkeys(kinds[:4] + fw[:3]))


def fmt_program(i, p):
    from html import escape as e
    bmax = int(p.get("bounty_max") or 0)
    reward = f"${int(p.get('bounty_min') or 0):,}–${bmax:,}".replace(",", " ") if bmax > 0 else "без выплат"
    iso = p.get("_launch") or launch_iso(p)
    launched = ".".join(reversed(iso.split("-"))) if len(iso) == 10 else "дата неизвестна"
    out = (f"<b>{e(p['name'])}</b> · {e(p['platform'])}\n"
           f"📅 запущена {launched} · 💰 {reward}\n")
    sl = stack_line(p)
    if sl:
        out += f"🧩 {e(sl)}\n"
    out += f'🔗 <a href="{e(p.get("link") or "", quote=True)}">{e(p.get("link") or "")}</a>'
    if p.get("_warn"):
        out += f"\n⚠️ {e(p['_warn'])}"
    return out


def send_alert(tier_a, tier_b):
    """Telegram (HTML) if configured, else ProjectDiscovery `notify`. Program data only."""
    progs = list(tier_a) + list(tier_b)
    body = "\n\n".join(fmt_program(i, p) for i, p in enumerate(progs[:10]))
    msg = f"🆕 <b>Новые программы: {len(progs)}</b>\n\n{body}"
    if len(progs) > 10:
        msg += f"\n\n➕ ещё {len(progs) - 10} в <code>Targets/BBRADAR-NEW.md</code>"
    if tg_send(msg, html=True):
        return
    if shutil.which("notify"):
        subprocess.run(["notify", "-silent"], input=_re.sub(r"<[^>]+>", "", msg), text=True, timeout=20)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--test-telegram", action="store_true", help="send a test message and exit")
    a = ap.parse_args()

    if a.test_telegram:
        print("sent" if tg_send("bbradar-watch: telegram test OK") else "not sent (no creds or API error)")
        return
    key, flt = load_key(), load_filter()
    progs = fetch_all(key)
    state_p = Path(memory_dir()) / "bbradar-seen.json"
    state_p.parent.mkdir(parents=True, exist_ok=True)
    seen = set(json.loads(state_p.read_text())) if state_p.exists() else None

    ids = {p["id"] for p in progs}
    if a.baseline or (seen is None and not a.all):
        if not a.dry_run:
            state_p.write_text(json.dumps(sorted(ids)))
        print(f"baseline: {len(ids)} programs marked seen; next run reports only new ones")
        return

    new = [p for p in progs if a.all or p["id"] not in (seen or set())]
    ctx = {"standoff_open": standoff_open_slugs(), "standoff_ai": standoff_ai_banned(),
           "standoff_pub": standoff_published()}
    on_platform = [p for p in new if p["platform"] in flt["platforms"] and p.get("is_active", True)
                   and p.get("program_status", "active") == "active"]
    def launched_recently(p):
        iso = launch_iso(p, ctx)
        p["_launch"] = iso
        try:
            d = datetime.fromisoformat(iso).replace(tzinfo=timezone.utc)
        except ValueError:
            return False
        return (datetime.now(timezone.utc) - d).days <= flt["max_age_days"]

    on_platform = [p for p in on_platform if launched_recently(p)]
    paid = [p for p in on_platform if not flt["paid_only"] or
            (p.get("program_kind") == "bounty" and p.get("reward_status") != "none" and (p.get("bounty_max") or 0) > 0)]
    def targets_unknown(p):   # brand-new listing: bbradar has not loaded its scope yet, so no filter can judge it
        return (p.get("target_counts") or {}).get("total", 0) == 0

    cands = [p for p in paid if not flt["web_only"] or fits(p, flt) or targets_unknown(p)]
    eligible, dropped = [], []
    for p in cands:
        ok, warn = eligibility(p, ctx)
        (eligible if ok else dropped).append(p)
        if ok and targets_unknown(p):
            warn = (warn + "; " if warn else "") + "цели в bbradar ещё не загружены, смотри scope на странице"
        p["_warn"] = warn if ok else None
        p["_drop"] = None if ok else warn
    eligible.sort(key=lambda p: p.get("_launch") or "", reverse=True)
    for p in eligible[:flt["hint_max"]]:   # info only: frameworks seen in the program's own target list
        p["_hints"] = stack_hints(key, p) if flt["stack_filter"] else []
        time.sleep(0.15)
    tier_a, tier_b = [], eligible
    print(f"{len(progs)} listed, {len(new)} new, {len(on_platform)} on our platforms, "
          f"{len(dropped)} dropped (eligibility), {len(tier_a) + len(tier_b)} to report")
    for p in dropped:
        print(f"  dropped: {p['platform']} {p['name']} ({p['_drop']})")
    for p in tier_a + tier_b:
        print(("A " if p in tier_a else "- ") + line(p) + (f"  WARN: {p['_warn']}" if p.get("_warn") else ""))

    if not a.dry_run:
        state_p.write_text(json.dumps(sorted(ids | (seen or set()))))
        if tier_a or tier_b:
            stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            digest = Path(targets_root()) / "BBRADAR-NEW.md"
            digest.parent.mkdir(parents=True, exist_ok=True)
            with digest.open("a") as fh:
                fh.write(f"\n## {stamp}\n\n" + "\n".join(f"- {line(p)}" for p in tier_a + tier_b) + "\n")
            send_alert(tier_a, tier_b)



if __name__ == "__main__":
    main()
