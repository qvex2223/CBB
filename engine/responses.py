#!/usr/bin/env python3
"""
responses.py — the response corpus: what the target actually said back.

Until this existed, `bbcurl` logged the URL, the status code and the timings, and
threw the body away. Three things were impossible as a direct consequence:

  * **Telling grinding from probing.** The stuck detector counted *requests*. Twenty
    payloads that all come back byte-identical read as "work in progress" — which is
    exactly the state the operator needs to be pulled out of.
  * **Proving anything later.** At `/validate` time the evidence had to be re-fired,
    because nothing kept what the request returned the first time.
  * **Generating a PoC spec.** The request had already flown; its shape was known;
    the operator still hand-wrote the spec from scratch.

So every response body is hashed and kept. Identical bodies collapse onto one file
(the hash *is* the identity), which makes "did this change anything?" a string
comparison instead of a memory of what the screen looked like ten minutes ago.

Privacy: bodies from live programs contain other users' data by nature — that is
frequently the whole finding. The corpus lives in `hunt-memory/responses/`, which is
.gitignore'd like `Targets/*/evidence/`, and request lines are stored **redacted**
(Authorization, Cookie, tokens, `-u user:pass`) so a replay spec never carries a
credential to disk. Opt out per-request with `bbcurl --bb-no-store`, or globally
with `CBH_NO_RESPONSE_STORE=1`.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

MAX_STORE = int(os.environ.get("CBH_RESPONSE_MAX_BYTES", 256 * 1024))
READ_CHUNK = 64 * 1024

# Header names whose value never reaches disk. Matched against `-H name: value`.
SECRET_HEADER_RE = re.compile(
    r"^(authorization|cookie|set-cookie|proxy-authorization|x-api-key|x-auth-token|"
    r"x-access-token|x-csrf-token|api-key|token|secret|x-session|session|"
    # any header whose name ends in -token or -tokens is a credential by convention
    # (ozon-id-token on univer.ozon.ru reached audit.jsonl verbatim before this, 2026-10-16;
    # the plural was still uncovered, and `ozonid-auth-tokens` is a real header on this
    # estate's composer surface — a suffix rule that misses the plural misses the one we
    # already know the name of)
    r"[a-z0-9_-]+-tokens?)$", re.I)
REDACTED = "<redacted>"

# Identity / PII-shaped keys. These are NOT credentials, so the credential rules above
# never matched them — and that was a real hole: an audit row for
# `…/oauth2/link?iin=<national id>&contact_phone=<number>` landed on disk verbatim, and
# the *response* to that call repeats both inside the returned URL. On a live telecom
# program those two fields are a subscriber's identity, so they are masked everywhere a
# request line, a body or a stored response is written down.
# An optional `<owner>_` prefix is part of the key set: `company_email` and
# `telephone_number` are the same PII as `email` and `phone`, and the anchored
# list missed both. A real person's work address and phone reached
# hunt-memory/responses/ and a findings/*.md through `company_email` on
# register-accpt.portofantwerpbruges.com before this was widened (2026-10-08).
# Suffix/camelCase forms (`phoneMobile`, `emailAddress`, `mobilePhone`) are covered for the
# phone/email family only: `phoneMobile` put an operator's own number into a stored
# napi.wildberries.ru body on 2026-11-10. Other keys keep exact matching so counters stay readable.
_PII_KEY_CORE = (
    r"(?:[a-z0-9]{1,24}[_-])?(?:iin|personiin|donoriin|msisdn|simmsisdn|telephone|telephonenumber|telephone_number|phone|phonenumber|phone_number|contactphone|contact_phone|contactnumber|contact_number|passport|imsi|icc|iccid|login|email|password|passwd|pass|secret|secret_key|apikey|api_key|access_key|private_key|token|birthdate|birth_date|publishedby|published_by|createdby|created_by|updatedby|updated_by|modifiedby|modified_by|authoredby|authored_by|owner|ownerlogin|owner_login|username|user_name|account|accountname|account_name|userid|user_id|uid|wbuserid|wb_user_id|globaluserid|global_user_id|subscriberid|subscriber_id|user|(?:phone|telephone|email|msisdn)[a-z0-9_]{1,24}|[a-z0-9]{1,24}(?:phone|email))"
)
PII_KEY_RE = re.compile(r"^" + _PII_KEY_CORE + r"$", re.I)

# The value stops at a backslash as well as at a quote. scrub_text is applied to the
# FINISHED json.dumps output (poc_runtime.py line ~999), so inside an escaped JSON string
# a value sitting just before \" ended with the escape backslash: redacting
# `content=\"telephone=no\">` ate the backslash and produced a .result.json that no longer
# parsed, which made `cbh evidence` report NO-EVIDENCE for a finding whose PoC had in fact
# fired (www.wildberries.ru, 2026-11-03). A real identity value does not contain a
# backslash, so excluding it costs no coverage.
_PII_QUERY_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(" + _PII_KEY_CORE + r")=([^&;#\s\"\'\\]*)")
_PII_JSON_RE = re.compile(
    r"(?i)(\"" + _PII_KEY_CORE + r"\"\s*:\s*)(\"[^\"]*\"|-?\d+)")
_PII_HEADERLINE_RE = re.compile(
    r"(?im)^((?:x-)?" + _PII_KEY_CORE + r"\s*:\s*)(.+)$")

# Credential-shaped VALUES, wherever they appear in free text. SECRET_HEADER_RE above only
# ever matched a header *name* on a command line, so a secret quoted inside a response body
# walked straight past it — which is exactly how a live OpenAI key had to be masked by hand
# after `m.egov.kz` echoed its own outbound `Authorization` header back to an anonymous
# caller. A short prefix survives so the owner can still tell WHICH key to rotate; the
# entropy does not.
_SECRET_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])"
    r"((?:sk-proj-|sk-ant-|sk-|ghp_|gho_|ghs_|github_pat_|xox[baprs]-|AKIA|ASIA|AIza|"
    r"glpat-|npm_|dop_v1_|rk_live_|sk_live_|pk_live_)[A-Za-z0-9_\-]{6})"
    r"([A-Za-z0-9_\-]{14,})")
_BEARER_RE = re.compile(
    r"(?i)(bearer\s+)([A-Za-z0-9._\-]{6})([A-Za-z0-9._\-]{14,})")

# Token-bearing JSON keys in a RESPONSE BODY. The patterns above only ever matched a
# header name, a `Bearer ` prefix, or a known vendor prefix (`sk-`, `ghp_`, ...), so an
# OAuth token endpoint answering
#     {"access_token":"eyJ...","refresh_token":"eyJ...","scope":"..."}
# walked straight past all of them. That is how a live Atlassian refresh token, valid for
# ~90 days, landed in hunt-memory/responses/ unmasked on 2026-10-09 while proving the
# Capital.com MCP scope-inflation finding. The key survives so the shape of the response
# is still readable; the value does not.
_TOKEN_JSON_RE = re.compile(
    r"(?i)(\"(?:access_token|refresh_token|id_token|session_token|auth_token|"
    r"client_secret|authorization_code)\"\s*:\s*)(\"[^\"]*\"|-?\d+)")

# Token-bearing keys in a QUERY STRING. `_TOKEN_JSON_RE` above only matches a JSON body and
# `_PII_QUERY_RE`'s key set has no `token`, so a credential carried as a URL parameter walked
# past both — which is how a live `fa-gateway` Ozon ID auth-request JWT (743 chars, TTL 600)
# and an `sso.ozon.ru/auth/ozonid-lite?token=` navigation landed in hunt-memory/audit.jsonl
# in full, twice, on 2026-10-28/29. Same failure shape as the `company_email` and
# `access_token` widenings above: found only because a worker read its own audit rows back.
# The key survives so a replay spec still shows which field to fill in deliberately.
_TOKEN_QUERY_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(token|jwt|access_token|refresh_token|id_token|session_token|"
    r"auth_token|authorization_code|client_secret|id_token_hint)=([^&;#\s\"\']*)")

# OAuth/OIDC AUTHORIZATION CODES and bare passwords in a QUERY STRING or a form body.
# `_TOKEN_QUERY_RE` above lists `authorization_code` but NOT the parameter the RFC actually
# names, `code=` -- and `pwd=` was in no pattern at all. bbcurl logs its full argv into
# hunt-memory/audit.jsonl, so an audited credentialed request wrote both one-time IDM codes
# of the mail_vk VK Teams lane (48 hex each, `?code=` and `&code=`) plus a consumed
# yoomoney oauth code and a Russian ESIA authorization code from two other engagements into
# the log in cleartext -- 28 occurrences across two generations, found on 2026-11-13 only
# because the lane that minted the codes reported its own exposure. Nothing was published
# (hunt-memory/ is git-ignored) and every code was dead, but the next one need not be: a
# code on an endpoint that actually exchanges is a live credential for its whole TTL.
#
# A WORKSPACE MARKER IS EXEMPT ON PURPOSE. Our own invented values (`cbhmk...`, `qvex...`)
# are the load-bearing evidence of which control a refute lane fired -- `cbh refute`
# requires the attack value to be visible, so a scrubber that ate `code=qvexnope4417`
# would destroy the record it is meant to protect. Real codes never carry those tokens.
# Known limit: a marker spliced onto a real code (`cbhmk9t4x07` + real tail) is exempted
# by this rule and stays readable; the 2026-11-13 pass redacted those by exact bytes.
# `code=` is length-gated at 10 so a country/error code (`code=ru`, `code=404`) survives,
# which keeps a response-shape row readable; `pwd=` is masked at any length because a
# 6-digit OTP is a credential (the VK Teams `auth/clientLogin` second leg posts one).
_OAUTH_CODE_QUERY_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(code)=(?![^&;#\s\"\']*(?:cbh|qvex))([A-Za-z0-9_.\-]{10,})")
_PWD_QUERY_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(pwd)=([^&;#\s\"\'\]\}\\]+)")

# Credential-shaped COOKIE values in a stored header block. `SECRET_HEADER_RE` masks a
# header by NAME, which covers `set-cookie:` on a command line — but a stored response's
# header block is scrubbed as free text, so the cookie NAME inside a `Set-Cookie` line
# never matched and the value survived. That is how two corpus files kept
# `__Secure-access-token=` / `__Secure-refresh-token=` in cleartext (2026-10-16; the jar
# was an anonymous subject-0 one, so nobody's session was exposed — the next one would not
# be). Matches any cookie whose name ends in -token/-tokens or is a session handle,
# with or without a `__Secure-`/`__Host-` prefix. The name survives, the value does not.
# NOTE on the shape: one lazy run plus a fixed suffix set, never a nested quantifier over
# an overlapping class. The first version of this pattern had `[a-z0-9_-]*` in front of
# `[a-z0-9_]*-tokens?`, which backtracks exponentially and hung the whole test suite on a
# long header block — a scrubber that can be stalled by its own input is a scrubber that
# fails open.
# The value class must exclude JSON punctuation. scrub_text() runs over an already
# serialized audit line (memory._append), so a class that only stopped at `;`/`,`/space
# swallowed the closing `"]` of `"urls": ["...?auth_token=XYZ"]` and wrote an unparseable
# row — evidence silently destroyed on the way to disk. 5 rows were lost that way
# (konsol, 2026-10-17) before this was caught.
_COOKIE_VALUE_RE = re.compile(
    r"(?i)([A-Za-z0-9_\-]{1,60}?(?:-tokens?|_tokens?|-sid|_sid|-session|_session))"
    r"=([^;\s,\"'\]\}\\]{8,})")


def scrub_text(text: str) -> str:
    """Mask identity fields AND credential values wherever they appear.

    Identity: query string, JSON body, header line. Credentials: any recognisable API-key
    or bearer token in free text, including one quoted inside a response body.

    Applied to request lines, request bodies and stored response bodies. The value is
    replaced, the key is kept, so a stored exchange stays readable and a replay spec
    still shows which field has to be filled in deliberately.
    """
    if not text:
        return text
    out = _PII_QUERY_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", text)
    out = _PII_JSON_RE.sub(lambda m: f'{m.group(1)}"{REDACTED}"', out)
    out = _TOKEN_JSON_RE.sub(lambda m: f'{m.group(1)}"{REDACTED}"', out)
    out = _TOKEN_QUERY_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", out)
    out = _OAUTH_CODE_QUERY_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", out)
    out = _PWD_QUERY_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", out)
    out = _PII_HEADERLINE_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", out)
    out = _COOKIE_VALUE_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", out)
    out = _SECRET_TOKEN_RE.sub(
        lambda m: f"{m.group(1)}<redacted-{len(m.group(1)) + len(m.group(2))}-chars>", out)
    out = _BEARER_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}<redacted-{len(m.group(2)) + len(m.group(3))}-chars>",
        out)
    return out


def _memdir(memdir: Optional[Path] = None) -> Path:
    if memdir:
        return Path(memdir)
    try:
        from memory import resolve_dir  # type: ignore
        return resolve_dir()
    except Exception:  # noqa: BLE001
        return Path(__file__).resolve().parent.parent.parent / "hunt-memory"


def store_root(engagement: str = "", memdir: Optional[Path] = None) -> Path:
    d = _memdir(memdir) / "responses"
    if engagement:
        d = d / re.sub(r"[^A-Za-z0-9_.-]", "_", engagement)[:60]
    return d


def disabled() -> bool:
    return os.environ.get("CBH_NO_RESPONSE_STORE", "").strip() not in ("", "0", "false")


# --------------------------------------------------------------------------- save
def sha256_file(path: Path) -> tuple[str, int]:
    """(hex digest, byte count) over the whole file — not just the stored slice."""
    h = hashlib.sha256()
    n = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(READ_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def save(engagement: str, body_path: Path, headers_path: Optional[Path] = None,
         memdir: Optional[Path] = None) -> Dict:
    """Hash the body, keep the first MAX_STORE bytes once per distinct body.

    Returns the facts worth putting in the audit row. Never raises: a corpus that
    can break a request is worse than no corpus.
    """
    out: Dict = {}
    try:
        body_path = Path(body_path)
        if not body_path.exists():
            return out
        digest, total = sha256_file(body_path)
        out = {"body_sha256": digest, "body_bytes": total}
        if disabled():
            out["body_stored"] = False
            return out
        d = store_root(engagement, memdir)
        d.mkdir(parents=True, exist_ok=True)
        dest = d / f"{digest}.txt"
        if not dest.exists():
            # The digest identifies the response as the server sent it (hashed over the
            # original bytes above, so dedup and `cbh diff` keep working). What lands on
            # disk is a PII-scrubbed rendering of it: bodies on a telecom program carry
            # subscriber identity, and a corpus file is not the place for it. When the
            # scrub changes anything the file says so, so nobody mistakes the stored text
            # for a byte-exact capture.
            head = b""
            if headers_path and Path(headers_path).exists():
                head = Path(headers_path).read_bytes().rstrip() + b"\n\n"
            with body_path.open("rb") as src:
                raw = src.read(MAX_STORE)
            text = (head + raw).decode("utf-8", errors="replace")
            scrubbed = scrub_text(text)
            with dest.open("wb") as dst:
                if scrubbed != text:
                    dst.write(b"[bbcurl: identity fields masked before storage - "
                              b"body_sha256 is over the ORIGINAL response]\n\n")
                dst.write(scrubbed.encode("utf-8", errors="replace"))
                if total > MAX_STORE:
                    dst.write(f"\n\n[bbcurl: truncated — stored {MAX_STORE} of {total} bytes]\n"
                              .encode())
        out["body_stored"] = True
        out["truncated"] = total > MAX_STORE
    except Exception:  # noqa: BLE001
        pass
    return out


def path_for(engagement: str, digest: str, memdir: Optional[Path] = None) -> Optional[Path]:
    if not digest:
        return None
    p = store_root(engagement, memdir) / f"{digest}.txt"
    if p.exists():
        return p
    # Engagement folder may differ (renamed project, request fired from elsewhere).
    root = store_root("", memdir)
    if root.is_dir():
        for cand in root.glob(f"*/{digest}.txt"):
            return cand
    return None


def load(engagement: str, digest: str, memdir: Optional[Path] = None) -> str:
    p = path_for(engagement, digest, memdir)
    return p.read_text(encoding="utf-8", errors="replace") if p else ""


# ----------------------------------------------------------------------- redaction
def redact(argv: List[str]) -> List[str]:
    """Strip credentials out of a curl command line before it is written down."""
    out: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else None
        if a in ("-H", "--header") and nxt is not None:
            name = nxt.split(":", 1)[0].strip()
            hide = SECRET_HEADER_RE.match(name) or PII_KEY_RE.match(name.replace("-", "_"))
            out += [a, f"{name}: {REDACTED}" if hide else scrub_text(nxt)]
            i += 2
            continue
        if a in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
                 "--data-urlencode", "-F", "--form", "--form-string") and nxt is not None:
            out += [a, scrub_text(nxt)]
            i += 2
            continue
        if a == "--url" and nxt is not None:
            out += [a, scrub_text(nxt)]
            i += 2
            continue
        if a in ("-u", "--user", "-b", "--cookie", "-E", "--cert", "--key") and nxt is not None:
            out += [a, REDACTED]
            i += 2
            continue
        if a.startswith("--user=") or a.startswith("--cookie="):
            out.append(a.split("=", 1)[0] + "=" + REDACTED)
            i += 1
            continue
        out.append(scrub_text(a) if ("://" in a or a.startswith("--data")
                                     or a.startswith("--form")) else a)
        i += 1
    return out


# --------------------------------------------------------------------------- reads
def _tail_jsonl(path: Path, n: int) -> List[Dict]:
    if not path.exists():
        return []
    rows: List[Dict] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:  # noqa: BLE001
                    continue
    except Exception:  # noqa: BLE001
        return []
    return rows[-n:]


def rows(url_substr: str = "", engagement: str = "", limit: int = 4000,
         memdir: Optional[Path] = None) -> List[Dict]:
    """Audit rows that carry a response hash, newest last."""
    out = []
    for r in _tail_jsonl(_memdir(memdir) / "audit.jsonl", limit):
        if not r.get("body_sha256"):
            continue
        if engagement and r.get("engagement") != engagement:
            continue
        if url_substr:
            urls = " ".join(r.get("urls") or []) + " " + str(r.get("url_effective") or "")
            if url_substr.lower() not in urls.lower():
                continue
        out.append(r)
    return out


def distinct(rows_: List[Dict]) -> List[str]:
    seen: List[str] = []
    for r in rows_:
        h = r.get("body_sha256")
        if h and h not in seen:
            seen.append(h)
    return seen


def identical_run(rows_: List[Dict]) -> Dict:
    """How much of this burst was the same answer over and over?"""
    if not rows_:
        return {"requests": 0, "distinct": 0, "identical_ratio": 0.0}
    d = distinct(rows_)
    return {
        "requests": len(rows_),
        "distinct": len(d),
        "identical_ratio": round(1 - (len(d) / len(rows_)), 2),
        "top_hash": max(d, key=lambda h: sum(1 for r in rows_ if r.get("body_sha256") == h)),
    }


# ---------------------------------------------------------------- field variance
# The whole-body hash answers "did anything change?". It cannot answer the question
# that actually decides a finding: "did the part that *decides* change?" Measured
# 2026-09-09 in the tier-3 eval — an agent called a constant boolean an ownership
# oracle after storing 18 captures in which `match` was `false` every time. The
# bodies all differed, because they echoed the varying phone/id back, so no
# hash-level check could have caught it. Compare fields, not files.
HEADER_START_RE = re.compile(r"^HTTP/\d")


def body_of(stored: str) -> str:
    """Strip the stored header block, if the capture has one."""
    if not stored:
        return ""
    if HEADER_START_RE.match(stored):
        parts = re.split(r"\r?\n\r?\n", stored, maxsplit=1)
        return parts[1] if len(parts) > 1 else ""
    return stored


def _flatten(obj, prefix: str = "", out: Optional[Dict] = None, depth: int = 0) -> Dict:
    """{"a": {"b": 1}} -> {"a.b": "1"}. Lists collapse to one key per position-free
    element set, because `results[0].id` differing is not the same signal as
    `match` differing."""
    out = {} if out is None else out
    if depth > 6:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten(v, f"{prefix}.{k}" if prefix else str(k), out, depth + 1)
    elif isinstance(obj, list):
        out.setdefault(f"{prefix}[]len", set()).add(json.dumps(len(obj)))
        for item in obj[:20]:
            _flatten(item, f"{prefix}[]", out, depth + 1)
    else:
        out.setdefault(prefix or "<root>", set()).add(json.dumps(obj, ensure_ascii=False))
    return out


def field_variance(rows_: List[Dict], memdir: Optional[Path] = None) -> Dict:
    """Which fields moved across these captures, and which never did.

    Returns {"parsed": n, "fields": {name: {"values": [...], "constant": bool,
    "seen": n}}, "distinct_requests": n}. Only JSON bodies are considered; a
    non-JSON corpus falls back to the whole-body comparison that already exists.
    """
    fields: Dict[str, set] = {}
    seen_counts: Dict[str, int] = {}
    parsed = 0
    requests = set()
    for r in rows_:
        for u in (r.get("urls") or []):
            requests.add(u)
        text = body_of(load(r.get("engagement", ""), r.get("body_sha256", ""), memdir))
        if not text.strip():
            continue
        try:
            doc = json.loads(text)
        except Exception:  # noqa: BLE001
            continue
        parsed += 1
        flat = _flatten(doc)
        for k, vals in flat.items():
            fields.setdefault(k, set()).update(vals)
            seen_counts[k] = seen_counts.get(k, 0) + 1
    out = {"parsed": parsed, "distinct_requests": len(requests), "fields": {}}
    for k, vals in sorted(fields.items()):
        out["fields"][k] = {
            "values": sorted(vals)[:6],
            "distinct": len(vals),
            "constant": len(vals) == 1,
            "seen": seen_counts.get(k, 0),
        }
    return out


DECISIVE_RE = re.compile(
    r"(^|[._-])(match|matched|valid|exists|found|allowed|success|ok|result|status|"
    r"is[A-Z_]|has[A-Z_]|can[A-Z_])", re.I)


def constant_field_alert(url_substr: str = "", engagement: str = "", min_responses: int = 6,
                         memdir: Optional[Path] = None) -> Optional[Dict]:
    """The path whose answers never actually varied, if there is one.

    Fires on the shape that produces a phantom oracle: many requests to one path,
    the inputs plainly different, and the field that would carry the answer the
    same in every capture.
    """
    grouped: Dict[str, List[Dict]] = {}
    for r in rows(url_substr, engagement, memdir=memdir):
        for u in (r.get("urls") or []):
            grouped.setdefault(_path_of(u), []).append(r)
            break
    best = None
    for path, rs in grouped.items():
        if len(rs) < min_responses:
            continue
        var = field_variance(rs, memdir)
        if var["parsed"] < min_responses or var["distinct_requests"] < 2:
            continue
        constant = {k: v for k, v in var["fields"].items()
                    if v["constant"] and v["seen"] >= min_responses}
        if not constant:
            continue
        decisive = [k for k in constant if DECISIVE_RE.search(k)]
        cand = {
            "path": path,
            "responses": var["parsed"],
            "distinct_requests": var["distinct_requests"],
            "constant_fields": {k: constant[k]["values"][0] for k in sorted(constant)},
            "decisive_fields": sorted(decisive),
            "engagement": rs[-1].get("engagement", ""),
            "url": (rs[-1].get("urls") or [""])[0],
        }
        # A constant *decision* field is the finding-killer; prefer it over a
        # constant `Server` header echo.
        rank = (1 if decisive else 0, cand["responses"])
        if best is None or rank > best[0]:
            best = (rank, cand)
    return best[1] if best else None


def _path_of(url: str) -> str:
    try:
        from urllib.parse import urlsplit
        u = urlsplit(url)
        return f"{u.scheme}://{u.netloc}{u.path}"
    except Exception:  # noqa: BLE001
        return url


def corpus_stats(memdir: Optional[Path] = None) -> Dict:
    """Size of the corpus on disk — bodies are kept until someone prunes them."""
    root = store_root("", memdir)
    files = list(root.glob("*/*.txt")) if root.is_dir() else []
    return {
        "root": str(root),
        "files": len(files),
        "bytes": sum(f.stat().st_size for f in files if f.exists()),
        "engagements": sorted({f.parent.name for f in files}),
    }


def prune(days: float, memdir: Optional[Path] = None, dry_run: bool = True) -> Dict:
    """Drop stored bodies older than `days`.

    Bodies are other people's data as often as not, so the corpus is a working
    cache with an expiry, never an archive. Evidence that matters belongs in the
    engagement's own `evidence/` folder, cited by hash in the finding.
    """
    import time
    root = store_root("", memdir)
    cutoff = time.time() - days * 86400
    removed, freed = [], 0
    for f in (root.glob("*/*.txt") if root.is_dir() else []):
        try:
            st = f.stat()
        except OSError:
            continue
        if st.st_mtime >= cutoff:
            continue
        removed.append(str(f))
        freed += st.st_size
        if not dry_run:
            try:
                f.unlink()
            except OSError:
                pass
    return {"removed": len(removed), "bytes": freed, "dry_run": dry_run}


def repeat_alert(window: int = 10, min_repeat: int = 5,
                 memdir: Optional[Path] = None) -> Optional[Dict]:
    """Is the last burst of requests getting one answer over and over?

    This is the signal a request *count* cannot carry. Firing ten payloads at an
    endpoint that returns the same bytes each time feels like testing and is not:
    nothing in the input is reaching anything that decides the output. Reported as
    soon as it happens, not after the stuck threshold, because the cheap moment to
    rotate is before another twenty go the same way.
    """
    recent = rows(limit=200, memdir=memdir)[-window:]
    if len(recent) < min_repeat:
        return None
    counts: Dict[str, int] = {}
    for row in recent:
        h = row["body_sha256"]
        counts[h] = counts.get(h, 0) + 1
    top, n = max(counts.items(), key=lambda kv: kv[1])
    if n < min_repeat:
        return None
    same = [row for row in recent if row["body_sha256"] == top]
    hosts = {_host_of(u) for row in same for u in (row.get("urls") or [])}
    return {
        "hash": top,
        "repeats": n,
        "window": len(recent),
        "status": same[-1].get("http_code"),
        "bytes": same[-1].get("body_bytes"),
        "hosts": sorted(h for h in hosts if h),
        "urls": [u for row in same for u in (row.get("urls") or [])][-3:],
        "engagement": same[-1].get("engagement", ""),
    }


def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlsplit
        return urlsplit(url).hostname or ""
    except Exception:  # noqa: BLE001
        return ""


# ---------------------------------------------------------------------------
# Wire signals — cheap checks on ONE response that disclosed crit/high reports
# keep turning on (docs/disclosed-reports/HIGH-CRIT-LESSONS-2026-11.md):
#   * a 3xx that still carries a page body (execution-after-redirect: the handler
#     rendered the protected page, then redirected, without returning);
#   * a refusal (4xx) whose body still carries data — a 422 that serialized the
#     object, a "valid": false next to the token;
#   * a vendor-prefixed secret in a body — the top payouts in the corpus were a
#     leaked credential plus a careful validation of what it can do.
# Advisory only: computed on the RAW body before scrubbing (the stored copy has
# secrets masked), returned as small dicts, never raises, never blocks a request.
# ---------------------------------------------------------------------------
REDIRECT_BODY_MIN = 512          # a bare "Moved" stub is ~0-300 bytes
_DENIAL_DATA_KEYS = {
    "email", "phone", "msisdn", "token", "access_token", "refresh_token", "id_token",
    "password", "password_hash", "secret", "client_secret", "api_key", "apikey",
    "reset_token", "otp", "ssn", "iin", "passport", "card_number", "pan",
}
_PRIVATE_KEY_RE = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")


def _json_keys_with_values(obj, depth: int = 0, out: Optional[set] = None) -> set:
    out = set() if out is None else out
    if depth > 8:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _json_keys_with_values(v, depth + 1, out)
            elif v not in (None, "", False, 0):
                out.add(str(k).lower())
    elif isinstance(obj, list):
        for v in obj[:50]:
            _json_keys_with_values(v, depth + 1, out)
    return out


def wire_signals(stats: Dict, raw: bytes, size: Optional[int] = None) -> List[Dict]:
    """Return the advisory signals one response carries. Never raises.

    `size` is the full body length when `raw` is a truncated excerpt (Caido returns
    the first `bodyLimit` bytes plus `bodySize`).
    """
    out: List[Dict] = []
    try:
        code = int(str(stats.get("http_code") or 0) or 0)
    except (TypeError, ValueError):
        code = 0
    raw = raw or b""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    try:
        size = int(size) if size is not None else len(raw)
    except (TypeError, ValueError):
        size = len(raw)
    try:
        if 300 <= code < 400 and size >= REDIRECT_BODY_MIN:
            out.append({
                "signal": "body-on-redirect", "status": code, "bytes": size,
                "next": "execution-after-redirect candidate: read the body (do not follow -L). "
                        "Compare with the same route's unauthenticated baseline; a protected page "
                        "or data inside a 3xx is the finding (hunt-auth-bypass)."})
        if 400 <= code < 500 and size:
            try:
                keys = _json_keys_with_values(json.loads(raw[:MAX_STORE].decode("utf-8", "replace")))
            except Exception:  # noqa: BLE001 - not JSON, nothing to say
                keys = set()
            hit = sorted(keys & _DENIAL_DATA_KEYS)
            if hit:
                out.append({
                    "signal": "data-in-denial", "status": code, "keys": hit[:6],
                    "next": "the refusal still carries data fields — read the denial body like a "
                            "success body: whose object is serialized here? Re-fire with another "
                            "identity's id and diff (hunt-idor / hunt-api-misconfig)."})
        head = raw[:MAX_STORE]
        text = head.decode("utf-8", "replace")
        m = _SECRET_TOKEN_RE.search(text)
        if m or _PRIVATE_KEY_RE.search(head):
            prefix = (m.group(1)[:6] + "…") if m else "PRIVATE KEY"
            out.append({
                "signal": "secret-in-body", "status": code, "prefix": prefix,
                "next": "credential-shaped value in the response. Validate WHAT it can do with "
                        "one read-only call per ~/security-research/tools/data/keyhacks.md "
                        "(identity endpoint, then scope/permissions listing) — a validated key "
                        "with a mapped blast radius is a finding, an unvalidated one is a lead "
                        "(hunt-source-leak)."})
    except Exception:  # noqa: BLE001
        pass
    return out


def last_signals(memdir: Optional[Path] = None) -> List[Dict]:
    """Signals recorded on the most recent audited request (bbcurl writes them)."""
    try:
        tail = _tail_jsonl(_memdir(memdir) / "audit.jsonl", 1)
        return list((tail[-1] if tail else {}).get("signals") or [])
    except Exception:  # noqa: BLE001
        return []


if __name__ == "__main__":  # tiny CLI, mostly for eyeballing the corpus
    import argparse
    ap = argparse.ArgumentParser(description="response corpus")
    ap.add_argument("cmd", choices=["stats", "show"])
    ap.add_argument("arg", nargs="?", default="")
    a = ap.parse_args()
    if a.cmd == "stats":
        rs = rows(a.arg)
        print(json.dumps(identical_run(rs), indent=2))
    else:
        print(load("", a.arg)[:8000])
