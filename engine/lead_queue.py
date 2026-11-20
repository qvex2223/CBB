#!/usr/bin/env python3
"""lead_queue.py — `cbh leads`: turn the leads/ + primitives/ pile into a work queue.

Measured 2026-11-11 on wildberries: 115 leads + 174 primitives, one finding (downgraded).
Leads were written and never driven to an end, and a quarter of them wait on an account
nobody holds, so every hunt re-read them and moved on. This module:

  * ranks OPEN leads/primitives by payout of their class (profile.json reward_by_class),
    closeness to money (a primitive outranks a lead), and staleness (untouched longest
    first), skipping downranked classes;
  * splits off the ones whose `**Chain:** needs` names an account this engagement does not
    hold, and says which account would unlock how many — the operator decides when to give
    one; agents do not wait on it;
  * closes a lead in one command, so the pile shrinks: `cbh leads close <file> --as refuted`.

`blocked` and `stalled` are not the same verdict, and conflating them emptied a queue.
Measured on mail_vk 2026-11-11: two Playwright servers contended for one browser profile, the
orchestrator read the resulting silence as hung workers, and closed seven leads `--as blocked`
with the note "6 Playwright hunters hung ~20min again". `blocked` is held back from the queue
for the operator, so the whole XSS-in-email class — the paying class on a webmail target — left
the ledger, and the next pass opened `0 workable · 21 blocked`. `blocked` means the target or
the program blocks it (another person's data, program approval, an account nobody holds);
`stalled` means OUR tooling did not finish the lane, and the lead stays workable with a mark
that says a previous lane died before answering it.

Usage:
    cbh leads [program] [--top N] [--json]
    cbh leads close <lead-or-primitive.md> --as proven|refuted|exhausted|blocked|stalled [--note "..."]
    cbh leads reopen <lead-or-primitive.md> --note "why the last lane did not answer it"
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import funnel  # the one definition of a funnel item
import autonomy  # the closed list of reasons a vector may still be parked

# A status banner is written five ways in this workspace, and only the first of them was ever
# detected here: `**Status:** X`, `**Status: X**` (colon inside the bold), `**Status** : X`,
# `## Status — **X**` (a heading, which is how a worker writes a closure it appends at the end of
# a file), and any of those inside a `>` blockquote. Measured on standoff365/ozon 2026-11-11: the
# old anchor `^\*\*Status:\*\* (CLOSED|…)` matched NONE of the engagement's closed files, so a lead
# CLOSED as a verified negative three weeks earlier ranked 771 000 at the top of the queue and a
# refuted primitive held #1 for 25 days. Ranking on payout x staleness over a pile whose closures
# are invisible hands a worker a lane with nothing left to fire.
STATUS_LINE_RE = re.compile(
    r"^[ \t]*(?:>[ \t]*)*(?:#{1,6}[ \t]*)?\*{0,2}status\*{0,2}[ \t]*[:\u2014\u2013-][ \t]*(.*)$",
    re.I | re.M)
# The verdict is read from the START of the banner's remainder: "closed at the registry level" in
# the middle of a sentence whose banner says `lead` must not close the row.
CLOSURE_WORDS = ("closed", "exhausted", "refuted", "killed", "dead", "proven", "reported",
                 "duplicate", "superseded", "merged", "promoted", "withdrawn", "adjudicated",
                 "verified negative", "not a finding", "no finding")
BLOCKED_WORDS = ("blocked",)
# STALLED is deliberately absent from both lists above: the lane did not answer the lead, so
# the lead is neither closed nor held back — it is workable, with a mark on the row.
STALLED_WORDS = ("stalled",)
# NEEDS-RETRY is the verdict that was missing, and it is NOT `stalled`. `stalled` means OUR
# tooling did not finish the lane; `needs-retry` means the TARGET would not answer — a rate
# limit, a re-authentication, an environment that was down. Before this existed those lanes
# were closed `refuted` or `exhausted`, which is a CLOSURE word, so the lead left the queue
# permanently on evidence that was never gathered. Also absent from CLOSURE_WORDS and
# BLOCKED_WORDS on purpose: conflating `blocked` and `stalled` emptied an engagement's queue on
# 2026-11-11, and this is the third member of that family.
RETRY_WORDS = ("needs-retry",)
# How long a needs-retry lead is ranked DOWN rather than held back. A rate limit re-offered on
# the next wave re-tops the queue and burns the slot on the same wall; a hold would instead make
# `cbh leads`' count and its queue disagree, which engine/funnel.py exists to prevent. So it
# stays in the queue, counted, carrying the mark, at a tenth of its score.
RETRY_COOLDOWN_SECONDS = 6 * 3600
RETRY_COOLDOWN_FACTOR = 0.1
STATUS_RE = re.compile(r"^\*\*Status:\*\*.*$", re.M)

# A worker who adjudicates a record at the top writes a HEADING, not a status banner:
#   `## CLOSED 2026-10-16 (wave 10, HUNTER-3) — hypothesis 3 REFUTED by 31 fired requests`
#   `# LEAD — ADJUDICATED 2026-10-16 (wave17 / HUNTER-36). Both hypotheses are DEAD.`
# Neither contains the word "status", so the banner reader saw nothing and both ranked as
# open work. Measured on standoff365/ozon 2026-11-12: the pci-finance lead took a
# deep-hunter lane of the live wave while its own body said the tier had moved to
# `primitives/pci-finance-crossorigin-postmessage-control.md`.
#
# The guard against reading an ordinary section heading as a verdict is the ANCHOR, not the
# word: the verdict word must open the heading (after an optional `LEAD —` tier prefix) AND
# be followed by a date, a bracket, a dash or end-of-clause. `## CLOSED 2026-10-16 (…)` is a
# verdict; `## Proven capability, as fired` is a section and stays open. Same reason the
# banner reader anchors at the start of its remainder.
HEADING_RE = re.compile(r"^[ \t]*(?:>[ \t]*)*#{1,6}[ \t]*(.+)$", re.M)
TIER_PREFIX_RE = re.compile(
    r"^(?:lead|primitive|finding|blocked[- ]test|note)s?[ \t]*[\u2014\u2013-][ \t]*", re.I)
# An ASCII hyphen counts only when a space or the line end follows it: `## Closed-loop
# verification of the oracle` is a section heading, not a closure.
# The verdict word must be followed by a DATE, optionally through one bracket or dash. That
# is what separates an adjudication from a section heading, and position does not: the two
# parked primitives adjudicate at lines 59 and 36 ("## KILLED — 2026-10-16, wave 14,
# HUNTER-20"), while `## Blocked` at line 119 of `ozonid-auth-request-jwt-hs256` and
# `## Not a finding, explicitly` at line 66 of `fa-gateway-route-existence-oracle` are
# sections of records whose real banner says STALLED — both would have been closed by a
# position rule. Every adjudication in this workspace carries its date; a section heading
# does not, so an undated `## REFUTED: …` or `## BLOCKED — …` leaves the row open and the
# mark has to be made in the banner, where `cbh leads close` writes it.
VERDICT_DATE_RE = re.compile(r"^[ \t]*(?:[(\[:,]|[\u2014\u2013]|-(?=[ \t]))?[ \t]*\d{4}\b")
VERDICT_WORDS = CLOSURE_WORDS + BLOCKED_WORDS + STALLED_WORDS + RETRY_WORDS


def _heading_verdict(heading: str) -> str:
    """The verdict a heading states, or "" when it is an ordinary section heading.

    Takes the heading's text or its whole line: emphasis is stripped from ANYWHERE in it,
    because `## **REFUTED**: 2026-10-16` puts `**` between the verdict word and its date,
    and leading `>`/`#` are stripped so a blockquoted banner reads the same.
    """
    h = re.sub(r"[*_`~]", "", heading).strip()
    h = re.sub(r"^(?:>[ \t]*)*#{0,6}[ \t]*", "", h).strip().lower()
    h = TIER_PREFIX_RE.sub("", h).strip()
    for word in VERDICT_WORDS:
        if h.startswith(word) and VERDICT_DATE_RE.match(h[len(word):]):
            return h
    return ""


def _banners(text: str):
    """Every verdict's payload, lower-cased and stripped of markdown emphasis.

    Two sources: a status banner in any of its five spellings, and a heading that states a
    verdict outright (see `_heading_verdict`).
    """
    for m in STATUS_LINE_RE.finditer(text):
        yield m.group(1).strip().lstrip("*_`~ ").lower()
    for m in HEADING_RE.finditer(text):
        verdict = _heading_verdict(m.group(1))
        if verdict:
            yield verdict


def _is_closed(text: str) -> bool:
    # ANY banner, not the last one: `cbh leads close` inserts its verdict at the FIRST status line
    # and keeps the old one below as "Previous status: …", so last-wins would re-open what this
    # very tool just closed.
    return any(b.startswith(CLOSURE_WORDS) for b in _banners(text))


def _is_blocked(text: str) -> bool:
    """The banner says BLOCKED. On its own this no longer holds the lead back — see
    `_holds_back`."""
    return any(b.startswith(BLOCKED_WORDS) for b in _banners(text))


def _holds_back(text: str, eng: Path | None = None) -> str | None:
    """The declared park reason that keeps this lead out of the queue, or None.

    Operator directive 2026-11-14 ("я хочу чтобы он всё тестировал и без моего разрешения"):
    a BLOCKED banner is no longer enough. The file has to DECLARE one of the reasons the
    operator cannot grant — `**Park:** other-user-data|availability|out-of-scope|human-inbox`
    (`engine/autonomy.py`) — or the lead is workable and the next lane fires it. Everything
    the old banner also covered — a write, a POST, an account nobody holds, a programme
    approval, our own tooling failing — is now a lane, not a wait.

    A blocked banner with no declaration is NOT silently obeyed and NOT silently ignored: the
    row stays workable and carries `undeclared_block`, so `cbh leads` can name it. 431 legacy
    files had no declaration at all on 2026-11-14.
    """
    return autonomy.classify(text, eng) if _is_blocked(text) else None


def _is_stalled(text: str) -> bool:
    """A previous lane died in our own tooling without answering this lead.

    `cbh leads close --as stalled` (and `reopen`) writes this banner, and because `close()`
    renames the banner it displaces to `Previous status: …`, which no status regex matches,
    reopening a mis-marked BLOCKED lead genuinely puts it back in the queue.
    """
    return any(b.startswith(STALLED_WORDS) for b in _banners(text))


def _is_needs_retry(text: str) -> bool:
    """The TARGET would not answer the last lane — rate limit, re-auth, environment down.

    Distinct from `_is_stalled` (our own tooling) and from every closure word: the lead stays
    workable, and the only consequence is that it is ranked down for `RETRY_COOLDOWN_SECONDS`
    so it does not immediately re-top the queue and meet the same wall.
    """
    return any(b.startswith(RETRY_WORDS) for b in _banners(text))
CHAIN_RE = re.compile(r"^\*\*Chain:\*\*(.*)$", re.M)
NEEDS_RE = re.compile(r"needs\s+((?:`[^`]+`(?:\s*(?:\+|,|and|&)\s*)?)+)", re.I)
SLUG_RE = re.compile(r"`([^`]+)`")
ACCOUNT_SLUG_RE = re.compile(r"(session|account|login|authenticated|identity|-jar\b|cabinet|"
                             r"bearer|signed-in|logged-in)", re.I)
ROLE_WORDS = ("buyer", "seller", "supplier", "partner", "pvz", "courier", "business", "bank",
              "zakupki", "admin", "employee", "merchant", "customer", "user", "mattermost")
CLASS_WORDS = [  # (regex on name + title + `gives`, class key in reward_by_class)
    (r"\brce\b|command-injection|code-exec|deserial", "rce"),
    (r"account-takeover|\bato\b|session-theft|token-theft|steal", "ato"),
    (r"sqli|sql-injection", "sqli"),
    (r"ssrf|server-side-fetch|fetcher", "ssrf"),
    (r"xxe", "xxe"),
    # \blfr\b: "local file read" is what several programmes (Mail.ru among them) call this
    # class in their own reward table, and without it a lead titled LFR classified as
    # "other" and ranked at DEFAULT_REWARD instead of its declared 125 000 RUB band.
    (r"\blfi\b|\blfr\b|path-traversal|file-read|arbitrary-file", "lfi"),
    (r"idor|bola|ownership|other-user|cross-account|tenant|another-user", "idor"),
    (r"pii|personal-data|data-exposure|export|unauthenticated-read-of|order-data|card-data", "data-exposure"),
    # A credentialed cross-origin grant is a read of another origin's data, not a header nit;
    # without this rule "subdomain" used to match the xss `dom` token and set the payout.
    (r"\bcors\b|cross-origin|\bacao\b", "data-exposure"),
    (r"xss|innerhtml|script-exec|javascript-scheme|sink|html-unsanitised|unsanitized|\bdom\b",
     "xss"),  # \bdom\b, not bare "dom": "Domain=ozon.ru" in a title classified a
              # session-fixation lead as xss and ranked it at the XSS payout (2026-11-11)
    (r"csrf", "csrf"),
    (r"oracle|existence|route-set|registry|name-table|mount-table|allow-method|topology|"
     r"catalogue|catalog|version|stack|disclos|leak|banner|metrics", "info-leak"),
    # One store serving two auth flows with no column saying which minted the row
    # (CVE-2026-114607). Ranked at the `ato` band because that is what it yields: a session for
    # an account we do not own. `invite-token` is deliberately NOT a token here — it collides
    # with ordinary invite leads.
    (r"token-purpose|magic-link|state-token", "ato"),
    # A parameter the SERVER put in its own redirect and then trusted is an authorization
    # failure (CVE-2026-123009), not an open redirect. But an INFERENCE token must be
    # unambiguous, and the bare `redirect-param` was not: measured on the replay 2026-11-17, an
    # open-redirect primitive whose chain line read `gives
    # onelink-redirect-param-in-official-ozon-qr` was re-priced from the open-redirect band to
    # the idor band and pushed into the top-3 lane list, displacing a real lead. A chain slug
    # can use those two words for the ordinary thing. Only tokens that cannot mean anything
    # else stay here; an item that really is this class DECLARES `**Class:** redirect-param`,
    # which routes through skill_map.CLASS_SKILL and never through this table.
    (r"from_base_branch|server-set-param|server-emitted-param", "idor"),
    (r"oauth|redirect-uri|session-fixation", "ato"),
    (r"open-redirect|redirect", "open-redirect"),
]
# Relative payout when a programme publishes no reward_by_class (typical bounty tables).
# A class absent from this map falls to DEFAULT_REWARD, so a routable class with no band here
# ranks LOWER when an item declares it than when it does not — declaring the truth would demote
# the lead. Found 2026-11-17 while adding the two classes below.
DEFAULT_WEIGHTS = {"rce": 1_000_000, "sqli": 600_000, "ato": 600_000, "ssrf": 500_000,
                   "xxe": 500_000, "lfi": 500_000, "idor": 300_000, "data-exposure": 300_000,
                   "xss": 200_000, "postmessage": 200_000, "missing_authorization": 300_000,
                   "secret-exposure": 300_000, "csrf": 50_000, "open-redirect": 20_000,
                   "info-leak": 10_000, "other": 50_000,
                   # CVE-2026-114607: a session for an account we do not own, no interaction.
                   "token-purpose": 600_000,
                   # CVE-2026-123009: reads and writes on an object the caller cannot reach.
                   "redirect-param": 300_000,
                   # `secret` is routable through skill_map.CLASS_SKILL and had no band, so
                   # declaring it demoted the lead to DEFAULT_REWARD — the same defect found on
                   # the two classes above in wave 1. Priced with `secret-exposure`, which it is
                   # a synonym of.
                   "secret": 300_000}
DEFAULT_REWARD = 50_000


def _targets_root() -> Path:
    try:
        from paths import targets_root  # type: ignore
        return Path(targets_root())
    except Exception:  # noqa: BLE001
        return REPO / "Targets"


def resolve_engagement(name: str = "") -> Path | None:
    root = _targets_root()
    if name:
        cands = [p.parent for p in root.glob("**/scope.md")
                 if "_TEMPLATE" not in p.parts and (str(p.parent.relative_to(root)) == name
                                                    or p.parent.name == name)]
        return cands[0] if len(cands) == 1 else None
    proj = os.environ.get("CBH_PROJECT", "")
    if proj and (root / proj / "scope.md").exists():
        return root / proj
    cur = Path.cwd().resolve()
    for d in [cur, *cur.parents]:
        if (d / "scope.md").exists() and root in d.parents:
            return d
    return None


def _profile(eng: Path) -> dict:
    try:
        return json.loads((eng / "profile.json").read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def accounts_held(eng: Path) -> set[str]:
    """Account roles this engagement can act as: identity.json + *session-held* primitives."""
    held: set[str] = set()
    idf = eng / "identity.json"
    if idf.exists():
        try:
            d = json.loads(idf.read_text(encoding="utf-8"))
            items = d if isinstance(d, list) else [d]
            for it in items:
                if isinstance(it, dict) and str(it.get("status", "ok")).lower() not in ("failed", "blocked", "dead"):
                    held.add(str(it.get("role") or "user").lower())
        except Exception:  # noqa: BLE001
            pass
    for p in (eng / "primitives").glob("*session*held*.md"):
        for w in ROLE_WORDS:
            if w in p.name:
                held.add(w)
        held.add("user")
    return held


def cut(text: str, limit: int) -> str:
    """Truncate on a word boundary, and show that it was truncated.

    A hard slice cuts mid-word (`taking a client-supplied route`), which both removes
    the clause that carried the meaning and leaves no sign anything is missing. Every
    consumer that shortens a title or a precedent line for display uses this.
    """
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    head = text[:limit]
    space = head.rfind(" ")
    if space >= limit * 0.6:
        head = head[:space]
    return head.rstrip(" ,.;:—-") + " …"


def _needs(text: str) -> list[str]:
    chains = CHAIN_RE.findall(text)
    if not chains:
        return []
    m = NEEDS_RE.search(chains[-1])
    return SLUG_RE.findall(m.group(1)) if m else []


def _account_need(slugs: list[str], held: set[str]) -> str | None:
    """The unmet account slug, or None when nothing account-shaped is missing."""
    for s in slugs:
        if not ACCOUNT_SLUG_RE.search(s):
            continue
        roles = [w for w in ROLE_WORDS if w in s.lower()] or ["user"]
        if not any(r in held for r in roles):
            return s
    return None


# A lead may state its class outright: `**Class:** secret-exposure` on its own line.
# CLASS_WORDS guesses from the filename and title, which is all there is for most files,
# but a guess cannot see what a fired control already closed — `finance-mf-ssr-render-
# route-url` reads as SSRF and its SSRF hypothesis is closed by three byte-identical
# responses, so the open work is the authz question on 262 unprobed routes. A declaration
# wins over the guess.
CLASS_DECL_RE = re.compile(r"^\*\*Class:\*\*\s*`?([A-Za-z0-9][A-Za-z0-9_\-]*)`?", re.M)

# A lead/primitive writes its own band when the author already looked it up in the programme's
# table: "**Reward band if it lands:** 125 000 RUB". The class table is an inference from the
# file's NAME and TITLE; this is the author's reading of the published table, so it wins. Added
# 2026-11-13 after `cbh leads` printed a 125 000 RUB LFR lead as "[lead/other <=50,000]" and so
# ranked the weaker of two apex leads first in the queue lanes are picked from.
#
# Digits may be grouped with a space, a non-breaking space or a comma (operators paste from the
# platform page, which uses a thin space). A trailing "k"/"тыс" is NOT accepted: it is ambiguous
# next to a table that quotes full rubles, and a wrong reading here silently re-orders the queue.
BAND_DECL_RE = re.compile(
    r"^\*\*(?:Reward band(?: if it lands)?|Band|Payout)\:?\*\*\s*:?\s*"
    r"(?:up to\s*|~\s*|0\s*[-\u2013]\s*)?"
    r"([0-9][0-9\s\u00a0\u202f,]*[0-9]|[0-9])",
    re.M | re.I)

# A multiplier suffix is rejected AFTER the match, not with a lookahead inside it: the digit
# group is greedy-but-backtrackable, so a lookahead let "12k" match just "1" and return 1 - a
# garbage band is worse than none, because it looks real and silently sinks the item. RUB, rub
# and the ruble sign are not multipliers and stay allowed.
_BAND_MULTIPLIER_RE = re.compile(r"\s*(?:k|\u043a|\u0442\u044b\u0441|m|\u043c\u043b\u043d)",
                                 re.I)


def declared_band(text: str) -> int:
    """The payout a lead/primitive states for itself, or 0 when it states none.

    Returns 0 rather than raising on a malformed number: a typo in a note must not take the
    queue down, and 0 simply falls back to the class table."""
    m = BAND_DECL_RE.search(text or "")
    if not m:
        return 0
    if _BAND_MULTIPLIER_RE.match(text, m.end(1)):
        return 0
    digits = re.sub(r"[^0-9]", "", m.group(1))
    if not digits or len(digits) > 9:
        return 0
    return int(digits)


def known_classes() -> set[str]:
    """Every class name something in this workspace can route: the corpus's, the skill
    map's, and the ones CLASS_WORDS itself produces. A declaration outside this set is a
    typo, and a typo that silently became the class would route the item nowhere."""
    names = {cls for _rx, cls in CLASS_WORDS}
    try:
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).resolve().parent))
        import skill_map  # noqa: PLC0415
        names |= set(skill_map.CLASS_SKILL) | set(skill_map.CLASS_TO_CORPUS.values())
    except Exception:  # noqa: BLE001
        pass
    return names


def declared_class(text: str) -> str:
    """The class a lead/primitive file states for itself, or "" (unknown names ignored)."""
    m = CLASS_DECL_RE.search(text or "")
    if not m:
        return ""
    cls = m.group(1).strip().lower()
    return cls if cls in known_classes() else ""


def _class_of(name: str, title: str) -> str:
    hay = f"{name} {title}".lower()
    for rx, cls in CLASS_WORDS:
        if re.search(rx, hay):
            return cls
    return "other"


def _now_ts() -> float:
    """Wall clock, unless `CBH_NOW` pins it.

    `scan`'s score multiplies the reward by a staleness factor derived from whole DAYS, so
    the ranked queue is a function of the calendar. Measured 2026-11-17: two replays of
    UNCHANGED code forty minutes apart returned scores of 57142 and 60714 for the same leads
    (50000 * (1 + 2/14) against 50000 * (1 + 3/14)) because a batch of files sharing an mtime
    crossed the 3-day boundary between them, and two items swapped rank as a result. A
    before/after diff taken across that boundary measures the calendar, not the change.

    `CBH_NOW` (an ISO date or datetime) pins the clock so `scripts/decision_replay.py` is
    deterministic. Nothing in a live hunt sets it, and an unparseable value is ignored rather
    than raising into a hunt.
    """
    pin = os.environ.get("CBH_NOW", "").strip()
    if pin:
        try:
            return dt.datetime.fromisoformat(pin).timestamp()
        except ValueError:
            pass
    return dt.datetime.now().timestamp()


def _age_days(path: Path) -> int:
    return max(0, int((_now_ts() - path.stat().st_mtime) // 86400))


def scan(eng: Path) -> dict:
    prof = _profile(eng)
    rewards = {k.lower(): v for k, v in (prof.get("reward_by_class") or {}).items()}
    down = {k.lower() for k in (prof.get("downrank_classes") or {})}
    held = accounts_held(eng)
    self_reg = bool(prof.get("self_registration", True))
    items, closed, blocked, stalled, undeclared, needs_acct = [], 0, 0, 0, 0, []
    needs_retry = 0
    for kind in ("primitives", "leads"):
        # `funnel.tier_items` is the one definition of what an item is: flat `<slug>.md`
        # plus the folder-per-item write-up, and never the tier's own README. A bare
        # `*.md` glob ranked `primitives/README.md` as work (one of three rowi lanes was
        # briefed to hunt it) and could not see a folder-form item at all — 10 of
        # yukki-lk's 22 primitives. Measured 2026-11-13.
        for f in funnel.tier_items(eng / kind):
            text = f.read_text(encoding="utf-8", errors="ignore")
            if _is_closed(text):
                closed += 1
                continue
            title = (text.splitlines() or [""])[0].lstrip("# ").strip()
            slugs = _needs(text)
            unmet = _account_need(slugs, held)
            gives = " ".join(SLUG_RE.findall(CHAIN_RE.findall(text)[-1].split("gives", 1)[-1])) \
                if CHAIN_RE.findall(text) and "gives" in CHAIN_RE.findall(text)[-1] else ""
            decl = declared_class(text)
            cls = decl or _class_of(funnel.item_name(f), f"{title} {gives}")
            reward = declared_band(text) or \
                rewards.get(cls, DEFAULT_WEIGHTS.get(cls, DEFAULT_REWARD))
            age = _age_days(f)
            score = reward * (1.5 if kind == "primitives" else 1.0) * (1 + min(age, 14) / 14)
            if cls in down:
                score *= 0.2
            row = {"file": str(f.relative_to(eng)), "kind": kind[:-1], "class": cls,
                   "reward": reward, "age_days": age, "needs": slugs, "title": cut(title, 140),
                   "score": int(score), "class_declared": bool(decl)}
            park = _holds_back(text, eng)
            if park:
                blocked += 1
                row["blocked"] = True
                row["park"] = park
            elif _is_blocked(text):
                # A BLOCKED banner with no `**Park:**` declaration. Workable, and named as
                # such so the pile does not quietly keep its old meaning.
                undeclared += 1
                row["undeclared_block"] = True
            if _is_stalled(text):
                stalled += 1
                row["stalled"] = True
            if _is_needs_retry(text):
                needs_retry += 1
                row["needs_retry"] = True
                # Ranked down inside the cooldown, never held back. The close time is the
                # file's mtime, because `cbh leads close` writes the file — the banner's own
                # date is day-granular and cannot carry a six-hour window.
                waited = _now_ts() - f.stat().st_mtime
                if waited < RETRY_COOLDOWN_SECONDS:
                    row["cooling_seconds"] = int(RETRY_COOLDOWN_SECONDS - waited)
                    row["score"] = int(row["score"] * RETRY_COOLDOWN_FACTOR)
            if unmet:
                row["unmet_account"] = unmet
                # An account this engagement does not hold is the lane's FIRST STEP, not a
                # reason to wait: `cbh identity new <url>` + self-register. It is held back
                # only where the programme itself forbids us to register
                # (`"self_registration": false`), which is the operator's own per-programme
                # opt-out. Measured 2026-11-14: 74 of 431 parked files were a registration
                # wall, and a quarter of the queue sat behind one.
                if self_reg:
                    row["register_first"] = unmet
                else:
                    needs_acct.append(row)
            if not row.get("blocked") and row not in needs_acct:
                items.append(row)
    items.sort(key=lambda r: -r["score"])
    unlock: dict[str, list] = {}
    for r in needs_acct:
        unlock.setdefault(r["unmet_account"], []).append(r)
    return {"engagement": str(eng.relative_to(_targets_root())), "accounts_held": sorted(held),
            "self_registration": prof.get("self_registration", True),
            "open": items, "needs_account": unlock, "closed": closed, "blocked": blocked,
            "stalled": stalled, "needs_retry": needs_retry, "undeclared_block": undeclared,
            "park_reasons": list(autonomy.retained(eng))}


def _precedent(file_rel: str, limit: int = 1) -> str:
    """One `precedent:` line under a NEXT row, or "" when anything at all goes wrong.

    Retrieval must never be able to break the queue: an unreadable lead file, a missing
    corpus or a bad JSON row costs the hint, not the lane.
    """
    try:
        import precedent  # type: ignore
        eng = resolve_engagement()
        p = Path(file_rel)
        if not p.is_absolute() and eng:
            p = eng / file_rel
        if not p.exists():
            return ""
        return precedent.lane_line(p.read_text(encoding="utf-8", errors="replace"), limit=limit)
    except Exception:  # noqa: BLE001
        return ""


def render(q: dict, top: int) -> str:
    out = [f"LEAD QUEUE — {q['engagement']}: {len(q['open'])} workable · "
           f"{sum(len(v) for v in q['needs_account'].values())} wait on an account · "
           f"{q['blocked']} parked · {q['closed']} closed"
           + (f" · {q['stalled']} stalled (counted in workable)" if q.get("stalled") else "")
           + (f" · {q['undeclared_block']} undeclared block(s), now workable"
              if q.get("undeclared_block") else ""),
           f"accounts held: {', '.join(q['accounts_held']) or 'none'}"]
    out.append(f"\nNEXT (one deep-hunter lane each, drive to PROVEN or close):")
    for r in q["open"][:top]:
        stale = f" · untouched {r['age_days']}d" if r["age_days"] >= 3 else ""
        # A retry is not a fresh lane: say so, or the next worker repeats the setup that died.
        retry = " · RETRY (last lane stalled in our tooling, not at the target)" if r.get("stalled") else ""
        # A different cause needs a different mark: `stalled` is ours to fix, `needs-retry` is
        # the target's wall and the lane must come back with a different approach, not the same
        # one sooner.
        if r.get("needs_retry"):
            cool = r.get("cooling_seconds") or 0
            retry += (f" · NEEDS-RETRY (the TARGET would not answer — rate limit / re-auth / "
                      f"environment; ranked down for another {cool // 60}m)" if cool else
                      " · NEEDS-RETRY (the TARGET would not answer last time; cooldown over)")
        # Two marks a lane must not have to discover for itself: an account it has to
        # register before anything else is fireable, and a BLOCKED banner left over from
        # when a write or an approval was a reason to stop (operator directive 2026-11-14).
        reg = f" · REGISTER FIRST (`{r['register_first']}`: `cbh identity new <url>`)" \
            if r.get("register_first") else ""
        und = " · BLOCKED banner, no `**Park:**` declaration — workable, fire it" \
            if r.get("undeclared_block") else ""
        out.append(f"  {r['score']:>8}  [{r['kind']}/{r['class']} ≤{r['reward']:,}]"
                   f"{stale}{retry}{reg}{und}  {r['file']}")
        # Paid precedent for THIS lane, unasked. `cbh report-intel` was named in 103 worker
        # briefs in session a0053cc0 and run zero times, because it needs a dataset path and
        # an invented query; here the query comes from the lead file itself. A hint printed
        # next to the lane, never a filter on it: the ranking above is unchanged.
        hint = _precedent(r["file"])
        if hint:
            out.append(hint)
    if q["needs_account"]:
        out.append("\nWAIT ON AN ACCOUNT (`\"self_registration\": false` — this programme forbids "
                   "us to register, so these are the operator's):")
        for slug, rows in sorted(q["needs_account"].items(), key=lambda kv: -sum(r["score"] for r in kv[1]))[:8]:
            out.append(f"  {len(rows):>3} lead(s) unlocked by `{slug}` — top: {rows[0]['file']}")
        if q["self_registration"] is not False:
            out.append("  First try a self-registered throwaway: `cbh identity new <url>` + Playwright "
                       "registration; a working one is recorded in identity.json with a \"role\".")
    out.append("\nClose every lane: `cbh leads close <file> --as proven|refuted|exhausted|blocked|stalled "
               "--note \"why\"`")
    out.append("  `blocked` = ONLY a reason the operator cannot grant, DECLARED on the file as "
               "`**Park:** <reason>`: " + ", ".join(q.get("park_reasons") or []) +
               " (`cbh autonomy`). A write, a POST, an account nobody holds, a programme "
               "approval and our own tooling failing are NOT blocks — they are the lane.")
    out.append("  `stalled` = OUR tooling did not finish the lane (browser lane busy, worker killed, "
               "MCP server gone). The lead stays in this queue.")
    return "\n".join(out)


def close(path: str, verdict: str, note: str) -> int:
    p = Path(path)
    if not p.is_absolute():
        eng = resolve_engagement()
        p = (eng / path) if eng and not p.exists() else p
    if not p.exists() or p.parent.name not in ("leads", "primitives"):
        print(f"not a lead/primitive file: {path}")
        return 2
    text = p.read_text(encoding="utf-8")
    label = {"proven": "PROVEN", "refuted": "REFUTED", "exhausted": "EXHAUSTED",
             "blocked": "BLOCKED", "stalled": "STALLED",
             "needs-retry": "NEEDS-RETRY"}[verdict]
    line = f"**Status:** {label} ({dt.date.today().isoformat()}){(' — ' + note) if note else ''}"
    if STATUS_RE.search(text):
        old = STATUS_RE.search(text).group(0)
        text = text.replace(old, line + "\n\nPrevious status: " + old.replace("**Status:**", "").strip(), 1)
    else:
        lines = text.splitlines()
        text = "\n".join(lines[:1] + ["", line] + lines[1:]) + "\n"
    p.write_text(text, encoding="utf-8")
    print(f"{label}: {p}")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "close":
        ap = argparse.ArgumentParser(prog="cbh leads close")
        ap.add_argument("file")
        ap.add_argument("--as", dest="verdict", required=True,
                        choices=["proven", "refuted", "exhausted", "blocked", "stalled",
                                 "needs-retry"])
        ap.add_argument("--note", default="")
        a = ap.parse_args(argv[1:])
        return close(a.file, a.verdict, a.note)
    if argv and argv[0] == "reopen":
        # Put a lead back in the queue after a tooling failure was recorded as a verdict about
        # the target. Writing STALLED on top displaces the old banner to `Previous status: …`,
        # which no status regex matches, so the row stops being held back.
        ap = argparse.ArgumentParser(
            prog="cbh leads reopen",
            description="Re-open a lead whose last close was our tooling failing, not a "
                        "verdict about the target (writes **Status:** STALLED).")
        ap.add_argument("file")
        ap.add_argument("--note", required=True,
                        help="why the last lane did not answer it, e.g. \"browser lane busy, "
                             "worker killed at 20 min\"")
        a = ap.parse_args(argv[1:])
        return close(a.file, "stalled", a.note)
    ap = argparse.ArgumentParser(prog="cbh leads")
    ap.add_argument("program", nargs="?", default="")
    # `--project` is what `cbh census`/`cbh autohunt` call the same thing, and spelling it
    # that way here used to answer `error: unrecognized arguments: --project`.
    ap.add_argument("--project", default="", help="same as the positional program name")
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    eng = resolve_engagement(a.program or a.project)
    if eng is None:
        print("No engagement resolved: pass a program name, set CBH_PROJECT, or run inside Targets/<...>/.")
        return 2
    q = scan(eng)
    print(json.dumps(q, ensure_ascii=False, indent=1) if a.json else render(q, a.top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
