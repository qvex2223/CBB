#!/usr/bin/env python3
"""
skill_signals.py — URL surface -> the hunt-* skill that already covers it.

Shared by the two hooks so there is exactly one table:
  * `scripts/skill-gate.py`  (PreToolUse) — blocks the request until the skill loads
  * `scripts/hunt-nudge.py`  (PostToolUse) — nudges after the fact

The table is deliberately keyed on the URL alone. A hook cannot see intent, but the
path almost always states the attack surface — `/graphql`, `/payment/order`,
`/camunda-workers/external/`, `?redirect=` — and that is enough to name the skill
whose bypass tables the operator is otherwise re-deriving one curl at a time.

`block` marks the surfaces where hand-rolling is the failure mode being fixed.
Recon-ish surfaces (JS bundles, sourcemaps) are advisory only: hard-gating those
would break recon, which is the one thing the agent already does willingly.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional, Set, Tuple

# (regex on URL, vuln class, skill, block?)
PATH_SIGNALS: List[Tuple[str, str, str, bool]] = [
    (r"/graphql",                       "graphql",               "hunt-graphql",           True),
    (r"/(oauth|authorize|token)\b",     "oauth",                 "hunt-oauth",             True),
    (r"/(saml|sso)\b",                  "saml",                  "hunt-saml",              True),
    (r"/(otp|verify|2fa|mfa|resend)\b", "mfa",                   "hunt-mfa-bypass",        True),
    (r"/(login|signin|signup|register|auth)\b", "auth-bypass",   "hunt-auth-bypass",       True),
    (r"/(upload|attachment|avatar)",    "file-upload",           "hunt-file-upload",       True),
    (r"/(payment|invoice|order|billing|cart|checkout|tariff|balance)",
                                        "business-logic",        "hunt-business-logic",    True),
    (r"/(admin|internal|external|worker|debug|actuator)", "missing_authorization",
                                                                 "hunt-auth-bypass",       True),
    (r"/(user|account|profile|subscriber|customer)s?/[^/?]{3,}",
                                        "idor",                  "hunt-idor",              True),
    (r"/(?:[0-9]{1,}|[0-9a-f]{8}-[0-9a-f-]{20,})(?:[/?#]|$)",
                                        "idor",                  "hunt-idor",              True),
    (r"/(?:[0-9]{1,}|[0-9a-f]{8}-[0-9a-f-]{20,})(?:[/?#]|$)",
                                        "idor",                  "hunt-idor",              True),
    (r"/(export|download|pdf|report)",  "idor",                  "hunt-idor",              True),
    (r"[?&](url|uri|redirect|redirect_uri|next|callback|target|dest|image)=",
                                        "ssrf",                  "hunt-ssrf",              True),
    (r"/api/v[0-9]",                    "api-misconfig",         "hunt-api-misconfig",     True),
    (r"\.(js|map|json)(\?|$)",          "info-leak",             "hunt-source-leak",       False),
    (r"/(robots\.txt|sitemap|\.well-known)", "info-leak",        "hunt-source-leak",       False),
]

URL_RE = re.compile(r"https?://[^\s'\"\\]+")

# Heredoc bodies are file content, not a command line. Writing a test fixture, a
# patch script or a note that happens to contain the word `curl` and a URL used to
# read as a request being fired — which is how the PreToolUse gate once denied a
# patch that was only *describing* a request, and how the nudge fires at a unittest
# file. Cut the bodies out before anything is matched against them.
HEREDOC_RE = re.compile(
    r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1.*?^\2$",
    re.S | re.M)


def strip_heredocs(cmd: str) -> str:
    return HEREDOC_RE.sub("<<HEREDOC", cmd or "")

# A URL in a command is not a request. `python3 -c "...https://x..."`, a grep, an
# echo into notes — gating those trains the operator to switch the gate off. Only
# commands that actually fire count.
SENDER_RE = re.compile(
    r"(^|[\s;&|(])(bbcurl|curl|wget|httpx|ffuf|katana|gau|waybackurls|nuclei|dalfox|gowitness)([\s;&|)]|$)")


def sends_request(cmd: str) -> bool:
    return bool(SENDER_RE.search(strip_heredocs(cmd)))


def urls_in(cmd: str) -> List[str]:
    return URL_RE.findall(strip_heredocs(cmd))


def signals_for(cmd: str) -> List[Tuple[str, str, bool]]:
    """Return every relevant URL signal, deduplicated by skill.

    A route can cross several trust boundaries at once: `/api/v1/orders/42` is
    simultaneously an API, business-flow and object-authorization surface.  The
    old first-match rule discarded the latter signals and made routing depend on
    table order.
    """
    out: List[Tuple[str, str, bool]] = []
    seen: Set[str] = set()
    # Dedupe URLs and skills, while retaining all applicable classes for each URL.
    for u in dict.fromkeys(urls_in(cmd)):
        for pat, vclass, skill, block in PATH_SIGNALS:
            if re.search(pat, u, re.I):
                if skill not in seen:
                    seen.add(skill)
                    out.append((vclass, skill, block))
    return out


# ---------------------------------------------------------------------------
# which skills has this session actually loaded?
# two independent witnesses, because a gate that misreads "loaded" as "not
# loaded" blocks real work, and one that misreads the other way is decorative.
# ---------------------------------------------------------------------------
def _state_path(session_id: str) -> Optional[Path]:
    if not session_id:
        return None
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from memory import resolve_dir  # type: ignore
        base = resolve_dir()
    except Exception:  # noqa: BLE001
        base = Path(__file__).resolve().parent.parent.parent / "hunt-memory"
    d = base / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", session_id)[:80]
    return d / f"skills-{safe}.json"


def record_skill(session_id: str, skill: str) -> None:
    p = _state_path(session_id)
    if not p or not skill:
        return
    try:
        loaded = set(json.loads(p.read_text()))
    except Exception:  # noqa: BLE001
        loaded = set()
    loaded.add(skill)
    p.write_text(json.dumps(sorted(loaded)))


def _from_state(session_id: str) -> Set[str]:
    p = _state_path(session_id)
    if not p or not p.exists():
        return set()
    try:
        return set(json.loads(p.read_text()))
    except Exception:  # noqa: BLE001
        return set()


def _from_transcript(transcript_path: str, tail_bytes: int = 10_000_000) -> Set[str]:
    """Scan the session transcript for Skill tool calls.

    Survives a missing PostToolUse tracker and a resumed session, which the state
    file does not.
    """
    if not transcript_path:
        return set()
    p = Path(transcript_path)
    if not p.exists():
        return set()
    try:
        size = p.stat().st_size
        with p.open("rb") as fh:
            if size > tail_bytes:
                fh.seek(size - tail_bytes)
            blob = fh.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return set()
    found = set()
    for m in re.finditer(r'"skill"\s*:\s*"([^"]+)"', blob):
        found.add(m.group(1))
    return found


def skills_loaded(session_id: str = "", transcript_path: str = "") -> Set[str]:
    names = _from_state(session_id) | _from_transcript(transcript_path)
    # normalize `plugin:hunt-idor` / `claude-bughunter:hunt-idor` -> `hunt-idor`
    return {n.split(":")[-1].strip() for n in names if n}


def satisfied(cmd: str, loaded: Set[str]) -> Tuple[bool, List[Tuple[str, str]]]:
    """(is the gate satisfied?, [(class, skill)] still missing and blocking)"""
    if not sends_request(cmd):
        return True, []
    missing = [(c, s) for c, s, block in signals_for(cmd) if block and s not in loaded]
    return (not missing), missing
