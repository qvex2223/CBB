#!/usr/bin/env python3
"""
scope.py — deterministic scope safety for the engagement engine.

The engine may run unattended, so scope is enforced in CODE, not by trusting an
LLM. Every host/URL is checked here before any agent is allowed to touch it.
Deny wins: an out-of-scope match excludes even if an in-scope pattern also matches.
Default deny: anything not matching an in-scope pattern is out of scope.

Pattern forms (matched against the URL's host):
  example.com        -> the apex AND any subdomain (example.com, api.example.com)
  *.example.com      -> any subdomain (NOT the bare apex)
  api.example.com    -> that exact host
  10.0.0.0/8         -> any IP in the CIDR (IPv4)
  re:^staging[0-9]+\\.example\\.com$   -> explicit regex (prefix re:)

IP-range scope (the "resolves inside our netblocks" class of program):
  Some programs scope by *where the host resolves*, not by DNS name — a
  `*.example.com` subdomain that resolves outside the program's netblocks is
  out of scope even though the name matches. Name-only matching silently
  passes those hosts, and the resulting report gets closed as out-of-scope.

  Any in-scope pattern that parses as an IP rule (CIDR, single IP, or a
  `a.b.c.d-e.f.g.h` / `a.b.c.d-N` last-octet range, with `-`, `–` or `—`) is
  collected into `ip_scope` as well. When `ip_scope` is non-empty, `verify()`
  with `resolve=True` requires the host to RESOLVE into one of those ranges,
  not merely match by name.

  When `ip_scope` is empty the program has no netblock list, so IP-level
  membership cannot be decided in code; `verify()` returns UNVERIFIED and
  points at `--whois` for the operator's host-ownership judgement.
"""
import ipaddress
import json
import re
import shutil
import socket
import time
import subprocess
from urllib.parse import urlparse

# Verdicts returned by Scope.verify()
IN_SCOPE = "IN-SCOPE"
OUT_OF_SCOPE = "OUT-OF-SCOPE"
UNVERIFIED = "UNVERIFIED"

_DASHES = "-–—"          # ASCII hyphen, en dash, em dash
_IP_CHARS = set("0123456789.:/abcdefABCDEF" + _DASHES)


def _host_of(target):
    t = target.strip()
    if "://" not in t:
        t = "//" + t
    host = (urlparse(t).hostname or "").lower().rstrip(".")
    return host


def _match(pattern, host):
    p = pattern.strip().lower()
    if not p or not host:
        return False
    if p.startswith("re:"):
        try:
            return re.search(p[3:], host) is not None
        except re.error:
            return False
    if "/" in p and p.replace(".", "").replace("/", "").isdigit():  # CIDR
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(p, strict=False)
        except ValueError:
            return False
    # Dash-range netblock (`195.47.255.208-255`, en/em dash too) written as an
    # in-scope pattern. `parse_ip_rule` already understands every form the
    # resolution gate accepts; without this branch a literal in-range IP passed
    # as the target fell through to the name rules and was denied by default.
    if host[0].isdigit():
        rule = parse_ip_rule(p)
        if rule:
            try:
                return rule[0] <= ipaddress.ip_address(host) <= rule[1]
            except ValueError:
                return False
    if p.startswith("*."):
        base = p[2:]
        return host.endswith("." + base)
    # bare domain: apex or any subdomain; or exact host
    return host == p or host.endswith("." + p)


def parse_ip_rule(pattern):
    """Parse an IP scope rule into (first_ip, last_ip), or None if not an IP rule.

    Accepted forms:
      2.78.58.0/24              CIDR
      185.2.224.7               single address
      195.47.255.64-195.47.255.127   explicit range
      195.47.255.208-255        last-octet shorthand (as programs usually write it)
    Any of `-`, `–` (en dash), `—` (em dash) works as the range separator, because
    scope pages are copy-pasted from HTML and rarely use a plain hyphen.
    """
    p = (pattern or "").strip()
    if not p or not set(p) <= _IP_CHARS:
        return None
    try:
        if "/" in p:
            net = ipaddress.ip_network(p, strict=False)
            return (net.network_address, net.broadcast_address)
        for dash in _DASHES:
            if dash in p:
                lo_s, hi_s = (x.strip() for x in p.split(dash, 1))
                lo = ipaddress.ip_address(lo_s)
                if "." not in hi_s and ":" not in hi_s:
                    # last-octet shorthand: 195.47.255.208-255
                    hi_s = lo_s.rsplit(".", 1)[0] + "." + hi_s
                hi = ipaddress.ip_address(hi_s)
                if hi.version != lo.version or int(hi) < int(lo):
                    return None
                return (lo, hi)
        ip = ipaddress.ip_address(p)
        return (ip, ip)
    except ValueError:
        return None


def _ip_in_rules(ip, rules):
    """True if `ip` (str or ip_address) falls inside any (first, last) rule."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    for lo, hi in rules:
        if lo.version == addr.version and int(lo) <= int(addr) <= int(hi):
            return True
    return False


_RESOLVE_ATTEMPTS = 4
_RESOLVE_BACKOFF = 0.4


def resolve_host(host, timeout=5):
    """Resolve a host to its A/AAAA addresses. Returns [] on any failure.

    DNS only — this sends nothing to the target and is safe to run before the
    scope gate has approved the asset.
    """
    try:
        ipaddress.ip_address(host)
        return [host]                      # already an address
    except ValueError:
        pass
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    # Retry a few times: a flaky forwarder (WSL's 10.255.255.254 is one) fails
    # intermittently, and one transient gaierror must not read as NXDOMAIN —
    # that would turn a live in-scope host into UNVERIFIED and block the gate.
    infos = None
    try:
        for attempt in range(_RESOLVE_ATTEMPTS):
            try:
                infos = socket.getaddrinfo(host, None)
                break
            except (socket.gaierror, OSError):
                if attempt == _RESOLVE_ATTEMPTS - 1:
                    return []
                time.sleep(_RESOLVE_BACKOFF)
    finally:
        socket.setdefaulttimeout(old)
    if not infos:
        return []
    seen, out = set(), []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


def ip_owner(ip, timeout=8):
    """Best-effort netblock ownership lookup for the host-belongs-to-the-program check.

    Prefers the local `whois` binary; falls back to RDAP over HTTPS. Returns a dict
    with whatever of {netname, org, country, asn, source} could be extracted, or
    {"error": ...}. Never raises.

    NOTE: this queries a registry (whois server or rdap.org), not the target. It is
    still an outbound request to a third party, so it only runs when explicitly asked
    for (`--whois`).
    """
    if shutil.which("whois"):
        try:
            out = subprocess.run(["whois", str(ip)], capture_output=True, text=True,
                                 timeout=timeout).stdout
        except (subprocess.TimeoutExpired, OSError) as e:
            out, err = "", str(e)
        else:
            err = None
        if out:
            got = {"source": "whois"}
            fields = {"netname": r"^netname:\s*(.+)$",
                      "org": r"^(?:org-name|orgname|organization|descr|owner):\s*(.+)$",
                      "country": r"^country:\s*(.+)$",
                      "asn": r"^(?:origin|originas|aut-num):\s*(.+)$"}
            for key, pat in fields.items():
                m = re.search(pat, out, re.I | re.M)
                if m:
                    got[key] = m.group(1).strip()
            if len(got) > 1:
                return got
        if err:
            return {"error": err}
    # RDAP fallback — stdlib only
    import urllib.request
    try:
        req = urllib.request.Request(f"https://rdap.org/ip/{ip}",
                                     headers={"Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:                       # noqa: BLE001 - advisory lookup only
        return {"error": f"{type(e).__name__}: {e}"}
    got = {"source": "rdap"}
    if d.get("name"):
        got["netname"] = d["name"]
    if d.get("country"):
        got["country"] = d["country"]
    for ent in d.get("entities") or []:
        for item in (ent.get("vcardArray") or [None, []])[1]:
            if item and item[0] == "fn":
                got["org"] = item[3]
                break
        if "org" in got:
            break
    return got


class Scope:
    def __init__(self, in_scope, out_of_scope=None, seeds=None, name="engagement",
                 ip_scope=None):
        self.in_scope = [p for p in (in_scope or []) if p.strip()]
        self.out_of_scope = [p for p in (out_of_scope or []) if p.strip()]
        self.seeds = seeds or []
        self.name = name
        # IP rules the program listed as in-scope netblocks. Explicit `ip_scope`
        # wins; otherwise derive from any in-scope pattern that parses as an IP rule.
        raw_ip = ip_scope if ip_scope is not None else self.in_scope
        self.ip_scope = [r for r in (parse_ip_rule(p) for p in raw_ip) if r]
        raw_out = out_of_scope or []
        self.ip_out_of_scope = [r for r in (parse_ip_rule(p) for p in raw_out) if r]

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        return cls(d.get("in_scope", []), d.get("out_of_scope", []),
                   d.get("seeds", []), d.get("name", "engagement"),
                   ip_scope=d.get("ip_scope"))

    def in_scope_host(self, target):
        host = _host_of(target)
        if not host:
            return False
        if any(_match(p, host) for p in self.out_of_scope):
            return False          # deny wins
        return any(_match(p, host) for p in self.in_scope)

    def reject_reason(self, target):
        """Return None if in scope, else a human reason (for logging).

        Name-level only — see verify() for the DNS-resolution gate.
        """
        host = _host_of(target)
        if not host:
            return "could not parse host"
        if any(_match(p, host) for p in self.out_of_scope):
            return f"{host} matches an out-of-scope rule"
        if not any(_match(p, host) for p in self.in_scope):
            return f"{host} matches no in-scope rule (default deny)"
        return None

    def verify(self, target, resolve=False, whois=False):
        """Full scope decision, including the DNS-resolution gate.

        Returns a dict:
          {host, verdict, reason, ips, in_range_ips, owners}
        verdict is IN-SCOPE / OUT-OF-SCOPE / UNVERIFIED.

        UNVERIFIED means "the name matches but code cannot prove the host belongs
        to the program" — either resolution was not requested, DNS failed, or the
        program published no netblock list. It is NOT an approval to test.
        """
        host = _host_of(target)
        res = {"host": host, "target": target, "verdict": OUT_OF_SCOPE,
               "reason": "", "ips": [], "in_range_ips": [], "owners": {}}
        name_reason = self.reject_reason(target)
        if name_reason:
            res["reason"] = name_reason
            return res

        if not resolve:
            if self.ip_scope:
                res["verdict"] = UNVERIFIED
                res["reason"] = (f"{host} matches an in-scope name rule, but this program "
                                 f"scopes by netblock ({len(self.ip_scope)} range(s)) — "
                                 f"re-run with --resolve to check where it resolves")
            else:
                res["verdict"] = IN_SCOPE
                res["reason"] = f"{host} matches an in-scope name rule"
            return res

        ips = resolve_host(host)
        res["ips"] = ips
        if not ips:
            res["verdict"] = UNVERIFIED
            res["reason"] = f"{host} did not resolve (NXDOMAIN or DNS failure) — cannot verify"
            return res

        denied = [ip for ip in ips if _ip_in_rules(ip, self.ip_out_of_scope)]
        if denied:
            res["reason"] = (f"{host} resolves to {', '.join(denied)}, inside an "
                             f"out-of-scope netblock (deny wins)")
            return res

        if whois:
            res["owners"] = {ip: ip_owner(ip) for ip in ips}

        if not self.ip_scope:
            res["verdict"] = UNVERIFIED
            res["reason"] = (f"{host} matches by name and resolves to {', '.join(ips)}, but the "
                             f"program published no in-scope netblocks — confirm the host is "
                             f"genuinely program-operated infra (--whois) before testing")
            return res

        in_range = [ip for ip in ips if _ip_in_rules(ip, self.ip_scope)]
        res["in_range_ips"] = in_range
        if in_range:
            res["verdict"] = IN_SCOPE
            res["reason"] = (f"{host} resolves to {', '.join(in_range)}, inside the program's "
                             f"in-scope netblocks")
        else:
            res["reason"] = (f"{host} matches an in-scope name rule but resolves to "
                             f"{', '.join(ips)} — OUTSIDE every in-scope netblock. Name match "
                             f"alone is not scope.")
        return res


def _selftest():
    s = Scope(in_scope=["example.com", "*.test.example.com", "10.0.0.0/8",
                        "re:^lab[0-9]+\\.acme\\.io$"],
              out_of_scope=["admin.example.com", "internal.example.com"])
    ok = lambda t: s.in_scope_host(t)
    assert ok("https://example.com/login")           # apex
    assert ok("http://api.example.com/x")            # subdomain of bare domain
    assert ok("https://a.test.example.com")          # wildcard
    assert ok("https://10.1.2.3:8080/")              # CIDR
    assert ok("https://lab42.acme.io")               # regex
    assert not ok("https://admin.example.com")       # out-of-scope (deny wins)
    assert not ok("https://internal.example.com/x")  # out-of-scope
    assert ok("https://test.example.com")            # in scope via bare example.com rule
    assert not ok("https://evil.com")                # default deny
    assert not ok("https://notexample.com")          # suffix-confusion guard
    assert not ok("https://example.com.evil.com")    # suffix-confusion guard
    assert not ok("https://11.0.0.1")                # outside CIDR
    assert s.reject_reason("https://evil.com")
    assert s.reject_reason("https://example.com") is None
    # wildcard depth: *.test.example.com needs a label deeper than test.example.com
    s2 = Scope(in_scope=["*.test.example.com"])
    assert s2.in_scope_host("a.test.example.com")
    assert not s2.in_scope_host("test.example.com")

    # ---- IP rule parsing ----
    assert parse_ip_rule("2.78.58.0/24") == (ipaddress.ip_address("2.78.58.0"),
                                             ipaddress.ip_address("2.78.58.255"))
    assert parse_ip_rule("185.2.224.7") == (ipaddress.ip_address("185.2.224.7"),) * 2
    # last-octet shorthand with an en dash, as programs actually publish it
    assert parse_ip_rule("195.47.255.208–255") == (ipaddress.ip_address("195.47.255.208"),
                                                   ipaddress.ip_address("195.47.255.255"))
    assert parse_ip_rule("10.0.0.5-10.0.0.9") == (ipaddress.ip_address("10.0.0.5"),
                                                  ipaddress.ip_address("10.0.0.9"))
    assert parse_ip_rule("example.com") is None
    assert parse_ip_rule("10.0.0.9-10.0.0.5") is None      # inverted range
    s3 = Scope(in_scope=["*.example.com", "10.0.0.0/24", "195.47.255.208–255"])
    assert len(s3.ip_scope) == 2
    assert _ip_in_rules("10.0.0.7", s3.ip_scope)
    assert _ip_in_rules("195.47.255.209", s3.ip_scope)
    assert not _ip_in_rules("195.47.255.207", s3.ip_scope)
    assert not _ip_in_rules("11.0.0.7", s3.ip_scope)

    # ---- markdown token cleaning (real scope.md files wrap patterns in backticks) ----
    assert _clean_token("`*.example.com`") == "*.example.com"
    assert _clean_token("**api.example.com**") == "api.example.com"
    assert _clean_token("`10.0.0.0/8`,") == "10.0.0.0/8"
    assert _is_pattern("*.example.com")
    assert _is_pattern("2.78.58.0/24")
    assert not _is_pattern("IP")             # prose bullet ("- IP ranges (...):")
    assert not _is_pattern("Android/iOS")

    # ---- verify(): name match must not pass as scope when the program is netblock-scoped
    s4 = Scope(in_scope=["*.example.com", "10.0.0.0/24"])
    v = s4.verify("https://a.example.com")                  # no --resolve
    assert v["verdict"] == UNVERIFIED, v
    s5 = Scope(in_scope=["*.example.com"])                  # no netblocks published
    assert s5.verify("https://a.example.com")["verdict"] == IN_SCOPE
    assert s5.verify("https://evil.com")["verdict"] == OUT_OF_SCOPE
    print("scope.py self-test: PASS")


def _clean_token(tok):
    """Strip markdown decoration a hand-written scope.md wraps patterns in.

    Real scope files write bullets as ``- `*.example.com` — only subdomains that…``
    or ``- **api.example.com**``. Without this, the pattern keeps its backticks and
    matches nothing, which silently turns every check into a default-deny (or, worse,
    makes the operator stop trusting the gate and eyeball scope by hand).
    """
    t = (tok or "").strip()
    for _ in range(4):                      # e.g. **`host`** needs several passes
        before = t
        t = t.strip("`_").strip()
        t = t.rstrip(",;:.").strip()
        # bold: only strip `*` when it brackets BOTH ends, so the leading `*` of a
        # `*.example.com` wildcard survives
        if t.startswith("**") and t.endswith("**") and len(t) > 4:
            t = t[2:-2]
        elif t.endswith("**"):
            t = t[:-2]
        if t == before:
            break
    return t.strip()


def _is_pattern(tok):
    """Reject prose words that happen to start a bullet ('IP', 'Android/iOS', 'Any')."""
    if not tok or tok.startswith("(") or tok.startswith("["):
        return False                        # placeholder text, not a real pattern
    if tok.startswith("re:"):
        return True
    if parse_ip_rule(tok):
        return True
    if "." not in tok:
        return False                        # a bare word is prose, not a host pattern
    # a host pattern's last label must look like a TLD
    return re.match(r"^[*a-z0-9._-]+$", tok, re.I) is not None


def _scope_from_md(path):
    """Build a Scope from a scaffolded scope.md (the `hunt` template).

    Collects bullet items under an '## In scope' / '## Out of scope' heading.
    Takes the first whitespace token of each bullet (so '- api.example.com — note'
    yields 'api.example.com'), strips markdown decoration, and drops bullets whose
    first token is prose rather than a pattern.

    Tokens that parse as IP rules also populate `ip_scope`, which is what turns on
    the resolve-gate in verify().
    """
    in_scope, out_scope, section = [], [], None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            low = line.strip().lower()
            if low.startswith("#"):
                hashes = len(low) - len(low.lstrip("#"))
                if "out of scope" in low or "out-of-scope" in low:
                    section = "out"
                elif "in scope" in low or "in-scope" in low:
                    section = "in"
                elif hashes <= 2:
                    section = None     # a peer-level section (## Focus areas, etc.)
                # deeper sub-headings (### Web, #### APIs) keep the current section
                continue
            s = line.strip()
            if section and (s.startswith("- ") or s.startswith("* ")):
                tok = s[2:].strip().split()[0:1]
                if not tok:
                    continue
                pat = _clean_token(tok[0])
                if not _is_pattern(pat):
                    continue
                (in_scope if section == "in" else out_scope).append(pat)
    return Scope(in_scope=in_scope, out_of_scope=out_scope, name=path)


def _main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="scope.py",
        description="Deterministic in-scope check (deny wins, default deny).")
    ap.add_argument("targets", nargs="*", help="hosts/URLs to check")
    ap.add_argument("--md", help="path to a scaffolded scope.md")
    ap.add_argument("--scope-file", help="path to an engagement scope.json")
    ap.add_argument("--in-scope", action="append", default=[], metavar="PATTERN",
                    help="in-scope pattern (repeatable)")
    ap.add_argument("--out-of-scope", action="append", default=[], metavar="PATTERN",
                    help="out-of-scope pattern (repeatable)")
    ap.add_argument("--resolve", action="store_true",
                    help="resolve each host and require its IP to fall inside the "
                         "program's in-scope netblocks (DNS only, target is not touched)")
    ap.add_argument("--whois", action="store_true",
                    help="with --resolve: look up netblock ownership (whois, else RDAP) "
                         "so a name-matching host on a third party's infra is visible")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero on UNVERIFIED too — use to gate automation")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--selftest", action="store_true", help="run the built-in self-test")
    args = ap.parse_args(argv)

    if args.selftest:
        _selftest()
        return 0

    if args.md:
        scope = _scope_from_md(args.md)
    elif args.scope_file:
        scope = Scope.load(args.scope_file)
    elif args.in_scope or args.out_of_scope:
        scope = Scope(in_scope=args.in_scope, out_of_scope=args.out_of_scope)
    else:
        ap.error("provide --md, --scope-file, or --in-scope/--out-of-scope patterns")

    if not args.targets:
        ap.error("no targets given")

    if args.whois and not args.resolve:
        ap.error("--whois requires --resolve")

    results = [scope.verify(t, resolve=args.resolve, whois=args.whois) for t in args.targets]

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        if scope.ip_scope and not args.resolve:
            print(f"note: {len(scope.ip_scope)} in-scope netblock(s) declared — "
                  f"re-run with --resolve to check where these hosts actually resolve\n")
        for r in results:
            label = {IN_SCOPE: "IN-SCOPE    ", OUT_OF_SCOPE: "OUT-OF-SCOPE",
                     UNVERIFIED: "UNVERIFIED  "}[r["verdict"]]
            print(f"{label}  {r['target']}  ({r['reason']})")
            for ip, info in (r.get("owners") or {}).items():
                if "error" in info:
                    print(f"                 owner {ip}: lookup failed ({info['error']})")
                else:
                    bits = [f"{k}={v}" for k, v in info.items() if k != "source"]
                    print(f"                 owner {ip}: {', '.join(bits)}")

    if any(r["verdict"] == OUT_OF_SCOPE for r in results):
        return 1
    if args.strict and any(r["verdict"] == UNVERIFIED for r in results):
        return 2
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
