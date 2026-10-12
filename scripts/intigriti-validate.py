#!/usr/bin/env python3
"""Intigriti-specific pre-submission gate.

Generic /validate asks "is the bug real". This asks the other question:
"would THIS program reject it on sight". It reads the program's own brief
(last revision of every section) and the engagement's profile.json, and
scores a finding file against them.

  python3 intigriti-validate.py --project simscale --finding findings/x.md
  python3 intigriti-validate.py --project port-of-antwerp --finding f.md --json

Exit 0 = no blockers. Exit 1 = at least one BLOCKER. Exit 2 = usage/data error.

A BLOCKER means the program's own text says this class is not accepted, or
the asset is not in the paid scope. A WARN means it is accepted but something
about the submission is likely to cost you the reward or the validity point.
"""
import argparse, json, os, re, sys, datetime, html as H

ROOT   = "/opt/Claude/Targets"
BRIEFS = os.path.join(ROOT, "_INTIGRITI-CANDIDATES", "briefs")

# project -> brief key. Keep in sync with the scope.md "Program URL" line.
PROJECT_BRIEF = {
    "port-of-antwerp": "portofantwerp__portofantwerp",
    "nexuzhealth":     "nexuzhealth__nexuzhealth",
    "water-link":      "waterlink__water-link",
    "delen":           "delenprivatebank__privatebankdelen",
    "capitalcom":      "capitalcom__capitalcom",
    "exoscale":        "exoscale__excoscalebugbounty",
    "simscale":        "simscale__simscale",
    "watson":          "aswatson__superdrug",
    "dpg-media":       "dpgm__tweakers",
}

# Rejection classes Intigriti programs state in prose, with the phrasing they use
# and the words a finding uses when it IS that class. Both sides must hit.
CLASSES = [
    ("rate-limit",      r"rate.?limit",
                        r"rate.?limit|no throttl|unlimited attempts|brute.?forc|без (?:огранич|рейт)"),
    ("user-enumeration",r"(username|email|user).{0,20}enumerat",
                        r"enumerat|oracle|valid vs invalid|existing account|user.?enum|перебор(?:ом)? (?:id|пользоват)"),
    ("self-xss",        r"self.?xss",
                        r"self.?xss"),
    ("missing-headers", r"missing security headers",
                        r"missing (?:security )?header|csp (?:is )?(?:missing|absent)|x-frame-options"),
    ("cookie-flags",    r"missing cookie flags",
                        r"httponly|samesite|secure flag"),
    ("clickjacking",    r"clickjacking",
                        r"clickjack|iframe (?:the|a) (?:login|page)"),
    ("csrf-low",        r"cross.?site request forgery with (?:no|low)",
                        r"\bcsrf\b"),
    ("blind-ssrf",      r"blind ssrf",
                        r"blind ssrf|pingback|dns (?:callback|interaction) only"),
    ("banner-version",  r"(banner grabbing|version disclosure)",
                        r"version disclosure|outdated (?:version|software)|banner"),
    ("cors-nonsens",    r"cors misconfiguration on non.?sensitive",
                        r"\bcors\b|access-control-allow-origin"),
    ("session-invalid", r"sessions? not being invalidated",
                        r"session (?:is )?not invalidated|logout does not"),
    ("preauth-ato",     r"pre.?auth account takeover|oauth squatting",
                        r"pre.?auth|unregistered email|account squatting"),
    ("theoretical",     r"theoretical security issues",
                        r"theoretical|could potentially|if production|may allow|предполож"),
    ("no-poc",          r"without a proof.?of.?concept",
                        r"not (?:tested|verified)|untested"),
    ("api-key-noimpact",r"api key disclosure without proven business impact",
                        r"api key|apikey|api_key"),
    ("host-header",     r"host header injection without proven",
                        r"host header"),
    ("smuggling-noimp", r"http request smuggling without any proven impact",
                        r"smuggl"),
    ("upload-noproof",  r"arbitrary file upload without proof",
                        r"file upload"),
    ("subdomain-td",    r"subdomain takeover without taking over",
                        r"subdomain takeover|dangling (?:cname|dns)"),
]

def flat(v, out):
    if isinstance(v, str): out.append(v)
    elif isinstance(v, list):
        for x in v: flat(x, out)
    elif isinstance(v, dict):
        for x in v.values(): flat(x, out)

def section_text(section):
    if not section: return ""
    rev = section[-1] if isinstance(section, list) else section
    parts = []; flat(rev.get("content", rev), parts)
    t = H.unescape("\n".join(p for p in parts if isinstance(p, str)))
    t = re.sub(r"<[^>]+>", " ", t)
    return re.sub(r"\s+", " ", t)

def load_brief(key):
    with open(os.path.join(BRIEFS, key + ".json"), encoding="utf-8") as fh:
        return json.load(fh)

def live_assets(brief):
    """{normalised asset name: bountyTierId} from the LAST revision only."""
    rev = (brief.get("assetsCollection") or [None])[-1]
    out = {}
    for a in (rev or {}).get("content", {}).get("assetsAndGroups", []):
        n = (a.get("name") or "").strip().lower()
        n = re.sub(r"^https?://", "", n).rstrip("/")
        if n: out[n] = a.get("bountyTierId")
    return out

def paid_tiers(brief):
    rev = (brief.get("bountyTables") or [None])[-1]
    return {r.get("bountyTierId") for r in (rev or {}).get("content", {}).get("bountyRows", [])}

# Hosts that are illustrative, not targets. Never scope-check these.
PLACEHOLDER = re.compile(r"^(?:localhost|example\.(?:com|org|net)|evil\.example|attacker\.(?:com|tld)"
                         r"|burpcollaborator\.net|oastify\.com|.*\.oastify\.com|.*\.intigriti\.me"
                         r"|go\.intigriti\.com|app\.intigriti\.com|intigriti\.com|cwe\.mitre\.org"
                         r"|nvd\.nist\.gov|owasp\.org)$", re.I)

def glob_to_re(pat):
    """Intigriti asset globs: *.x.com, *.x.*, *affiliates.x.com, x.com/path."""
    base = pat.split("/")[0]
    rx = "".join(".*" if ch == "*" else re.escape(ch) for ch in base)
    return re.compile(r"^" + rx + r"$", re.I)

def asset_matches(host, assets):
    """Return (asset, tier) for the most specific live asset covering host."""
    host = host.lower().rstrip("/")
    best = None
    for a, tier in assets.items():
        base = a.split("/")[0]
        if base == host:
            return a, tier
        if "*" in base and glob_to_re(a).match(host):
            # prefer the longest literal part = most specific asset
            weight = len(base.replace("*", ""))
            if best is None or weight > best[2]:
                best = (a, tier, weight)
    return (best[0], best[1]) if best else (None, None)

# A host the report actually SENT a request to, vs one it merely mentions
# (an upstream IdP, a Location header, a vendor doc link). Only the first kind
# is a scope question; blocking on the second is how a validator cries wolf.
SENT = re.compile(r"(?:\bcurl\b[^\n]*?|\b(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+|"
                  r"^\s*(?:endpoint|url|target|host)\s*[:=]\s*)[\"'<\s|]*https?://([a-z0-9][a-z0-9.-]*\.[a-z]{2,})",
                  re.I | re.M)

# A line that is nothing but a URL is the Endpoint field / a target bullet.
BARE_URL = re.compile(r"^[\s`'\"*\-|>]*https?://([a-z0-9][a-z0-9.-]*\.[a-z]{2,})[^\s`'\"|]*"
                      r"[\s`'\"|]*$", re.I | re.M)

def hosts_in(text):
    """-> (sent_to, merely_mentioned), both lists of hostnames."""
    sent, seen = [], set()
    for m in BARE_URL.finditer(text):
        h = m.group(1).lower()
        if h not in seen: seen.add(h); sent.append(h)
    for m in SENT.finditer(text):
        h = m.group(1).lower()
        if h not in seen: seen.add(h); sent.append(h)
    mentioned = []
    for m in re.finditer(r"https?://([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", text, re.I):
        h = m.group(1).lower()
        if h not in seen: seen.add(h); mentioned.append(h)
    return sent, mentioned

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--finding", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    key = PROJECT_BRIEF.get(a.project)
    if not key:
        print("no brief mapped for project %r.\nGated programs have no brief on disk — "
              "their rules cannot be checked here, review by hand." % a.project, file=sys.stderr)
        return 2
    try:
        brief = load_brief(key)
    except FileNotFoundError:
        print("brief %s.json missing" % key, file=sys.stderr); return 2

    path = a.finding
    if not os.path.isabs(path):
        cand = os.path.join(ROOT, a.project, path)
        path = cand if os.path.exists(cand) else path
    try:
        finding = open(path, encoding="utf-8").read()
    except OSError as e:
        print("cannot read finding: %s" % e, file=sys.stderr); return 2
    low = finding.lower()

    oos   = section_text(brief.get("outOfScopes")).lower()
    ins   = section_text(brief.get("inScopes"))
    inslow= ins.lower()
    assets, paid = live_assets(brief), paid_tiers(brief)

    blockers, warns, notes = [], [], []

    # --- 1. asset scope + tier ------------------------------------------------
    sent_hosts, mentioned_hosts = hosts_in(finding)
    found = [h for h in sent_hosts if not PLACEHOLDER.match(h)]
    mentioned = [h for h in mentioned_hosts if not PLACEHOLDER.match(h)]
    if not found:
        warns.append("no host appears in a request line (curl / GET / Endpoint:) — Intigriti's "
                     "endpoint field wants a full URL, and triage reads that field first")
    for h in mentioned:
        asset, tier = asset_matches(h, assets)
        if asset is None:
            notes.append("%s is mentioned but never requested — not treated as a scope question; "
                         "make sure the report says why it appears" % h)
        else:
            notes.append("%s is mentioned (not in a request line) -> asset `%s`, tier %s"
                         % (h, asset, tier))
    for h in found:
        asset, tier = asset_matches(h, assets)
        if asset is None:
            blockers.append("%s matches NO asset in the live revision — out of scope" % h)
        elif tier == 5:
            blockers.append("%s -> asset `%s` is bountyTierId 5 = OUT OF SCOPE" % (h, asset))
        elif tier not in paid:
            warns.append("%s -> asset `%s` (tier %s) has NO bounty row = unpaid, in scope only"
                         % (h, asset, tier))
        else:
            notes.append("%s -> asset `%s`, tier %s (paid)" % (h, asset, tier))

    # --- 2. program's own rejection list -------------------------------------
    # A finding often NAMES these classes to say it is not one of them, usually
    # inside a validation table. Only an occurrence that is neither negated nor
    # inside a markdown table row counts as the finding being that class.
    NEG = re.compile(r"(?:\bnot\b|\bno\b|\bn't\b|\bneither\b|\bwithout\b|\bunlike\b"
                     r"|\bне\b|\bкроме\b|\bне является\b)[^.\n]{0,60}$")
    scan_lines = [l for l in low.split("\n") if not l.lstrip().startswith("|")]
    scan = "\n".join(scan_lines)

    def really_is(pat):
        for m in re.finditer(pat, scan):
            before = scan[max(0, m.start() - 70):m.start()]
            if NEG.search(before):
                continue
            return True
        return False

    # Where the class word sits decides how loud we are: in the title or the
    # opening summary it IS the finding; buried in the body it is usually the
    # mechanism ("an attacker who enumerates a userId...") and only worth a nudge.
    head = "\n".join(scan.split("\n")[:12])[:900]
    for name, oos_pat, fnd_pat in CLASSES:
        if not re.search(oos_pat, oos):
            continue
        if not really_is(fnd_pat):
            continue
        if re.search(fnd_pat, head):
            blockers.append("program lists '%s' as out of scope and the finding LEADS with it "
                            "— rebut it in the report or do not file" % name)
        else:
            warns.append("'%s' is out of scope for this program and the words appear in the body. "
                         "Likely just the mechanism, not the class — check the report cannot be "
                         "read as that class" % name)

    # --- 3. shared codebase = duplicate --------------------------------------
    if re.search(r"share the same codebase|shared code|another .{0,40}website", inslow):
        warns.append("program counts a bug on shared code across its sites as a DUPLICATE — "
                     "check it was not already reported on a sibling brand/domain")

    # --- 4. money reality -----------------------------------------------------
    if re.search(r"swag will be awarded|swag", inslow) and not paid:
        warns.append("program advertises SWAG only — no cash for this report")
    elif re.search(r"swag will be awarded", inslow):
        warns.append("program page says SWAG for valid High+; the EUR table in the brief data "
                     "may not be what they actually pay")
    acc = brief.get("acceptedSubmissionCount")
    sub = brief.get("submissionCount")
    if acc == 0 and (sub or 0) > 50:
        warns.append("%s submissions filed, %s accepted — this program accepts almost nothing"
                     % (sub, acc))

    # --- 5. third-party product rule -----------------------------------------
    if re.search(r"third.?party product", inslow) and re.search(r"\bcve-\d{4}-\d+", low):
        warns.append("finding cites a CVE and this program does not pay for generic vendor "
                     "issues — state why THEIR configuration/integration is what makes it work")

    # --- 6. evidence ----------------------------------------------------------
    stem = re.sub(r"\.md$", "", path)
    if not any(os.path.exists(stem + s) for s in (".poc.result.json", ".result.json")):
        warns.append("no .result.json beside the finding — a fired PoC is what answers 'did this "
                     "actually happen'")

    # --- 7. engagement obligations -------------------------------------------
    prof = os.path.join(ROOT, a.project, "profile.json")
    if os.path.exists(prof):
        p = json.load(open(prof, encoding="utf-8"))
        for hk, hv in (p.get("required_headers") or {}).items():
            if not hv or str(hv).upper() == "TODO":
                blockers.append("profile.json requires header %s but its value is unset" % hk)
    if re.search(r"intigriti\.me", inslow) and re.search(r"@(?!.*intigriti\.me)[a-z0-9.-]+\.[a-z]{2,}",
                                                         low):
        warns.append("program mandates @intigriti.me test accounts — make sure no other address "
                     "appears in the evidence")

    # --- 8. the by-design question -------------------------------------------
    if not re.search(r"by design|as intended|intended behaviour|intended behavior|working as|"
                     r"почему.{0,40}существует|не задуман|задуманное поведение|штатн\w*\s+(?:механик|"
                     r"поведени|работ)", low):
        warns.append("the finding never says why the endpoint/flow exists for the product. "
                     "Answer it before submitting — that is what sank the Port of Antwerp VAT "
                     "report (see port-of-antwerp/submissions.txt)")

    result = {"project": a.project, "brief": key, "finding": path,
              "blockers": blockers, "warnings": warns, "scope_notes": notes,
              "verdict": "BLOCK" if blockers else "OK"}
    if a.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("=" * 68)
        print(" intigriti-validate · %s · %s" % (a.project, os.path.basename(path)))
        print(" brief: %s   checked: %s" % (key, datetime.date.today()))
        print("=" * 68)
        for n in notes:    print("  scope   %s" % n)
        for w in warns:    print("  WARN    %s" % w)
        for b in blockers: print("  BLOCK   %s" % b)
        if not blockers and not warns: print("  nothing to flag.")
        print("-" * 68)
        print(" VERDICT: %s  (%d blocker(s), %d warning(s))"
              % (result["verdict"], len(blockers), len(warns)))
        if blockers:
            print(" A blocker is the program's own text. Rebut it in the report or do not file.")
    return 1 if blockers else 0

if __name__ == "__main__":
    sys.exit(main())
