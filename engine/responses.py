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
    r"x-access-token|x-csrf-token|api-key|token|secret|x-session|session)$", re.I)
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
_PII_KEY_CORE = (
    r"(?:[a-z0-9]{1,24}[_-])?(?:iin|personiin|donoriin|msisdn|simmsisdn|telephone|telephonenumber|telephone_number|phone|phonenumber|phone_number|contactphone|contact_phone|contactnumber|contact_number|passport|imsi|icc|iccid|login|email|birthdate|birth_date)"
)
PII_KEY_RE = re.compile(r"^" + _PII_KEY_CORE + r"$", re.I)

_PII_QUERY_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(" + _PII_KEY_CORE + r")=([^&;#\s\"\']*)")
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
    out = _PII_HEADERLINE_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", out)
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
