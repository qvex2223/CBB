#!/usr/bin/env python3
"""autonomy.py — `cbh autonomy`: the one list of reasons a vector may still be parked.

Operator directive 2026-11-14: "мне не нравится функционал blocked test — я хочу чтобы
он всё тестировал и без моего разрешения". The measurement behind it: 431 files under
`Targets/*/*/blocked-tests/`, and a classification of their own titles put only ~11 of
them on the safety floor. The rest were the agent stopping itself:

  * `…-needs-a-post`, `…-write-shaped-…`, `…-anonymous-create` — a state-changing request
    parked for being state-changing. `engine/engine.py::_roe()` printed the rule that made
    them: with `allow_intrusive=False` (the default) the ROE said "no writes/updates/deletes,
    no account creation, NEVER SUBMIT A WEB FORM".
  * `…-needs-a-buyer-account`, `…-needs-a-throwaway-principal` — a registration the lane
    could have done itself with `cbh identity new`.
  * `abt-att-1-lane-not-reproducible-from-bbcurl`, `partner-bff-lane-shell-swallowed`,
    `leasing-cors-arms-blocked-by-url-gate` — OUR tooling failed, which is `stalled`
    (workable, flagged RETRY), never `blocked`.
  * `…-needs-approval` — a programme-rules question the operator has now answered once,
    for every engagement: fire it.

So the parking list is now closed and short. A reason that is not on it is not a reason to
park: the lane fires the request on the operator's own account and reports what came back.

The four that stay are the ones no permission from the operator can grant, because they are
not the operator's to grant:

  other-user-data  another person's data, session or identity. The platform rule and the
                   safety floor both; it is also the single fastest way off a programme.
  availability     anything that could degrade the service or reach users who did not
                   consent: DoS, load testing, request smuggling on a shared pool, a cache
                   poisoning that persists, moving money, stock or queues.
  out-of-scope     `engine/scope.py` refuses it before the socket opens anyway.
  human-inbox      a contact/demo/support/abuse form whose rows a real person reads. Not
                   the operator's data and not availability, which is why it is listed
                   separately and is the one entry an engagement is expected to flip when
                   the programme says the forms are fair game.

Each entry is per-engagement flippable, so the directive does not have to be re-litigated in
prose. `Targets/<name>/profile.json`:

    "autonomy": {"unpark": ["human-inbox"]}       # fire the forms on this programme too
    "autonomy": {"park": ["other-user-data"]}     # an explicit list replaces the default

Usage:
    cbh autonomy                                  # the live policy, and any engagement override
    cbh autonomy --reclassify <platform>/<program>   # ACT/PARK per blocked-tests/ file
    cbh autonomy --reclassify <p>/<prog> --reopen    # write the ACT ones back as RETRY leads
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import funnel  # noqa: E402  — the one definition of a funnel item
import lead_queue  # noqa: E402  — reuse its five-banner closure reader, do not re-implement it


# ---------------------------------------------------------------- the policy
# Order is the order `cbh autonomy` prints and the order `classify()` tests, so the
# gravest reason wins when a file names two.
#
# The patterns are deliberately BROAD. The asymmetry is not symmetric: a false PARK costs
# one lane that the operator can unpark with one command, a false ACT fires a request at
# another person's data. So a file that merely MENTIONS a second real identity parks, and
# the operator unparks it.
PARK_REASONS: dict[str, dict] = {
    "other-user-data": {
        "title": "another person's data, session or identity",
        "why": ("The safety floor and every platform's rules. Own accounts only — a second "
                "identity the operator controls is fine, a real third party's is not."),
        "re": re.compile(
            r"another\s+(?:user|person|customer|seller|account|tenant|subscriber)|"
            r"other\s+(?:user|users|people|person)'?s|someone\s+else'?s|"
            r"a\s+real\s+(?:user|customer|seller|person)|"
            r"\bvictim\b|\bcross-user\b|cross-account|cross-tenant|"
            r"second\s+real\s+(?:user|account|person|identity)|"
            r"third[- ]part(?:y|ies)'?\s*(?:data|account|session)|"
            r"\bforeign\s+(?:id|account|session|identity|mailbox)\b|"
            r"needs?\s+a\s+(?:second|victim|other)\s+(?:user|identity|account|session)\b",
            re.I),
    },
    "availability": {
        "title": "could degrade the service or reach non-consenting users",
        "why": ("Not a permission the operator can give: the blast radius lands on people "
                "who are not in this engagement. DoS, load testing, smuggling on a shared "
                "pool, a cache poisoning that persists, moving money, stock or queues."),
        "re": re.compile(
            r"\bdos\b|\bddos\b|denial[- ]of[- ]service|load[- ]test|stress[- ]test|"
            r"\bflood|availability|\boutage\b|downtime|take\s+(?:it|the\s+\w+)\s+down|"
            r"shared\s+(?:pool|socket|connection|worker)|other\s+users?'?\s+(?:traffic|requests|sessions)|"
            r"poison(?:s|ed|ing)?\s+(?:the\s+)?cache\s+for|persist(?:s|ent)?\s+cache|"
            r"moves?\s+(?:money|funds|stock|inventory)|real\s+payment|charge\s+a\s+card|"
            r"mass[- ](?:action|delete|update|mail)|\bspam\b.*\busers?\b",
            re.I),
    },
    "out-of-scope": {
        "title": "outside the programme's declared scope",
        "why": "`engine/scope.py` is default-deny and refuses it before the socket opens.",
        "re": re.compile(
            r"out[- ]of[- ]scope|\boos\b|not\s+in\s+scope|outside\s+(?:the\s+)?scope|"
            r"scope\s+conflict|different\s+program(?:me)?|another\s+program(?:me)?'?s?\s+asset|"
            r"scope\s+gate\s+(?:refus|deni)",
            re.I),
    },
    "human-inbox": {
        "title": "a form or ticket a real person reads",
        "why": ("Outward-facing and not undoable: the row lands on a human's desk. Flip it "
                "per engagement with `\"autonomy\": {\"unpark\": [\"human-inbox\"]}` in "
                "profile.json when the programme says the forms are in play."),
        "re": re.compile(
            r"human[- ](?:processed|read|reviewed)|read\s+by\s+a\s+human|"
            r"(?:contact|demo|lead|callback|support|abuse|complaint|feedback|subscribe)[- ]form|"
            r"opens?\s+a\s+(?:ticket|support\s+case)|live\s+(?:agent|operator|chat)\s+|"
            r"sends?\s+(?:an\s+)?(?:email|sms)\s+to\s+a\s+(?:real|human)",
            re.I),
    },
}

DEFAULT_PARK = tuple(PARK_REASONS)

# What is no longer a reason, named so a worker reading a stale file recognises its own excuse.
# Each is answered by the thing it should do instead, because "you may" without "do this"
# reproduced the same parking under a different title on 2026-11-11 (`stalled` written as
# `blocked` emptied a queue).
UNPARKED: tuple[tuple[str, str], ...] = (
    ("a write, a POST/PUT/PATCH/DELETE, or a state change on the operator's own account",
     "fire it, minimally, and log what it changed"),
    ("needs an account the engagement does not hold",
     "`cbh identity new <url>` + self-register via Playwright; a wall there is ONE vector, "
     "not the lane"),
    ("needs programme approval",
     "the operator answered once, 2026-11-14: fire it if it is in scope, on our own data, "
     "and clears the four reasons above"),
    ("our own tooling failed (bbcurl, antibot, url gate, a dead worker, a busy browser)",
     "`cbh leads close --as stalled` — it stays in the queue flagged RETRY — then rotate "
     "the channel: Caido, Playwright, a pinned --resolve, another host"),
    ("needs a browser, a websocket, or a raw frame we had not driven yet",
     "drive it; `hunt-*` names the channel and `cbh browser doctor` names the lane state"),
)


# ---------------------------------------------------------------- engagement policy
def _profile(eng: Path) -> dict:
    p = eng / "profile.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace")) or {}
    except (json.JSONDecodeError, OSError):
        return {}


def retained(eng: Path | None = None) -> tuple[str, ...]:
    """The park reasons live for this engagement, in PARK_REASONS order.

    `park` replaces the default outright; `unpark` subtracts from it. An unknown slug is
    ignored rather than silently widening or narrowing the floor — `cbh autonomy` prints it.
    """
    cfg = (_profile(eng) if eng else {}).get("autonomy") or {}
    base = cfg.get("park")
    keep = set(base) & set(PARK_REASONS) if isinstance(base, list) else set(DEFAULT_PARK)
    drop = cfg.get("unpark")
    if isinstance(drop, list):
        keep -= set(drop)
    return tuple(r for r in PARK_REASONS if r in keep)


def unknown_slugs(eng: Path | None = None) -> list[str]:
    cfg = (_profile(eng) if eng else {}).get("autonomy") or {}
    seen = [s for key in ("park", "unpark") if isinstance(cfg.get(key), list) for s in cfg[key]]
    return sorted({s for s in seen if s not in PARK_REASONS})


# ---------------------------------------------------------------- the verdict
# A park is DECLARED, never inferred. The workspace already does this for the two other
# questions a gate has to grade — `**Class:** idor` tells `class_proof` which oracle to
# demand, `**Chain:** needs x · gives y` tells `chain_graph` what a primitive supplies — and
# for the same reason: guessing from prose got it wrong in both directions.
#
# Measured 2026-11-14 on all 431 legacy files: a prose matcher put 163 of them on
# `other-user-data`, and reading them showed most of the hits were the file QUOTING the
# programme's own approval rule ("anything that could affect other users needs prior
# approval") — the rule the operator has now answered. One of them,
# `b2b-accounts-api-authorization-channel-arms`, parked on the sentence "Both are read-only,
# carry no real credential, and target no other user's data". A matcher that reads a denial
# as its own trigger is not a gate.
#
# So: no declaration means NOT PARKED, which is the directive's default. The prose patterns
# survive as a HINT on the reclassification pass only — they tell a lane which legacy file is
# worth a read before it is fired, and they never hold anything back on their own.
DECLARE_RE = re.compile(
    r"^[ \t]*(?:>[ \t]*)*(?:#{1,6}[ \t]*)?\*{0,2}park\*{0,2}[ \t]*[:\u2014\u2013-][ \t]*"
    r"\*{0,2}[ \t]*([a-z][a-z-]*)",   # `**Park:** x` puts the colon inside the bold
    re.I | re.M)


def declared(text: str) -> str | None:
    """The park reason this file declares, or None. An unknown slug is not a park."""
    for m in DECLARE_RE.finditer(text or ""):
        slug = m.group(1).lower()
        if slug in PARK_REASONS:
            return slug
    return None


def hint(text: str, eng: Path | None = None) -> str | None:
    """Which retained reason this file's PROSE reads like — a triage hint, not a verdict.

    Used by `--reclassify` to mark the legacy files worth reading before they are fired. It
    decides nothing: `verdict()` does not consult it.
    """
    for slug in retained(eng):
        if PARK_REASONS[slug]["re"].search(text or ""):
            return slug
    return None


def classify(text: str, eng: Path | None = None) -> str | None:
    """The retained park reason this text DECLARES, or None when the lane should fire it."""
    slug = declared(text)
    return slug if slug and slug in retained(eng) else None


def verdict(text: str, eng: Path | None = None) -> tuple[str, str | None]:
    """("PARK", slug) when the file declares a retained reason, else ("ACT", None).

    A file declaring a reason this engagement has unparked ACTs: the `unpark` in
    `profile.json` is the operator overruling the declaration, which is the point of it.
    """
    slug = classify(text, eng)
    return ("PARK", slug) if slug else ("ACT", None)


def clause(eng: Path | None = None) -> str:
    """The parking paragraph for an ROE, a role file or the hunt-arm standing orders.

    Generated, never retyped: doctrine prose and the gate that reads it cannot drift apart
    when there is one source. 2026-11-14 — the prose in five files disagreed with the code
    in three about what `blocked` meant.
    """
    keep = retained(eng)
    lines = ["PARK A VECTOR ONLY for these reasons — the list is closed, and nothing else on "
             "it is a reason to wait for the operator:"]
    for slug in keep:
        lines.append(f"    * {slug} — {PARK_REASONS[slug]['title']}")
    if not keep:
        lines.append("    * (none — this engagement parks nothing)")
    lines.append("  Everything else is FIRED, on our own account, in scope, minimally, without "
                 "asking:")
    for excuse, instead in UNPARKED:
        lines.append(f"    * {excuse} -> {instead}")
    lines.append("  A parked vector goes to `blocked-tests/` and DECLARES its reason on its own "
                 "line — `**Park:** <reason>` — or it is not parked and the queue hands it to "
                 "the next lane. A vector parked for a reason not on the list above, or parked "
                 "with no declaration at all, is a lane you did not run.")
    return "\n".join(lines)


# ---------------------------------------------------------------- reclassification
def _targets_root() -> Path:
    return lead_queue._targets_root()


def reclassify(eng: Path) -> list[dict]:
    """One row per blocked-tests/ item: its name, verdict, and the reason if it parks.

    Already-adjudicated files are left alone. A blocked-test's verdict is at the BOTTOM of
    the file (the operator's own note on it), so the reader is `lead_queue`'s five-banner
    one and not a head-of-file regex.
    """
    rows = []
    bdir = eng / "blocked-tests"
    if not bdir.is_dir():
        return rows
    # `funnel.tier_items`, not a glob: a tier holds flat `<slug>.md` and folder-per-item
    # write-ups side by side, the tier's own README.md is instructions and never an item, and
    # a folder with several unnamed markdowns is skipped rather than guessed at.
    for f in sorted(funnel.tier_items(bdir)):
        path = Path(f)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        name = funnel.item_name(path)
        if lead_queue._is_closed(text):
            rows.append({"name": name, "path": path, "verdict": "DONE", "reason": None})
            continue
        v, slug = verdict(text, eng)
        rows.append({"name": name, "path": path, "verdict": v, "reason": slug,
                     "hint": None if slug else hint(text, eng)})
    return rows


REOPEN_BANNER = "**Status:** STALLED — unparked {date} by `cbh autonomy`"


def reopen(eng: Path, rows: list[dict]) -> list[Path]:
    """Write each ACT row back into leads/ as a RETRY lead pointing at its record.

    A stub, not a move: the blocked-test file stays as the measurement it already holds, and
    the lead carries the STALLED banner, which `lead_queue` reads as workable-with-a-mark
    rather than held back. An existing lead of the same name is never overwritten — a lane
    may already be on it.
    """
    out = []
    ldir = eng / "leads"
    ldir.mkdir(exist_ok=True)
    date = dt.date.today().isoformat()
    for row in rows:
        if row["verdict"] != "ACT":
            continue
        dest = ldir / f"unparked-{row['name']}.md"
        if dest.exists():
            continue
        rel = row["path"].relative_to(eng)
        # The prose hint is written INTO the lead rather than used to hold it back: the lane
        # reads the record first and then either declares `**Park:** <reason>` on the
        # blocked-test and closes this lead `--as blocked`, or fires the request. That is the
        # one read a regex could not do (see the note above DECLARE_RE).
        h = row.get("hint")
        hint_block = (
            f"**Read before firing:** this record's prose reads like `{h}` "
            f"({PARK_REASONS[h]['title']}). It may be the file quoting the programme's own "
            f"approval rule, which is no longer a parking reason, or it may be the real "
            f"requirement. Decide from the record: if it is real, add `**Park:** {h}` to "
            f"`{rel}` and close this lead `--as blocked --note \"{h}\"`; if it is the quoted "
            f"rule, fire the request.\n\n") if h else ""
        dest.write_text(
            f"# LEAD — {row['name']} (unparked)\n\n"
            f"{REOPEN_BANNER.format(date=date)}\n\n"
            f"**Record:** `{rel}` — the measurement already taken on this vector.\n\n"
            f"{hint_block}"
            f"This vector was parked under `blocked-tests/` for a reason that is no longer a "
            f"parking reason (operator directive {date}: the only reasons left are "
            f"{', '.join(retained(eng)) or 'none'}, and a park must declare itself with a "
            f"`**Park:**` line). Read the record, then take it to proof or refutation: the "
            f"request it was waiting for is fired on our own account, in scope, minimally.\n",
            encoding="utf-8")
        out.append(dest)
    return out


# ---------------------------------------------------------------- CLI
def _resolve(name: str) -> Path | None:
    root = _targets_root()
    p = root / name
    if (p / "scope.md").exists() or (p / "profile.json").exists() or p.is_dir():
        return p
    hits = [d for d in root.glob("*/*") if d.is_dir() and d.name == name]
    return hits[0] if len(hits) == 1 else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="cbh autonomy",
        description="The closed list of reasons a vector may still be parked for the operator.")
    ap.add_argument("--reclassify", metavar="ENGAGEMENT",
                    help="walk that engagement's blocked-tests/ and print ACT/PARK per file")
    ap.add_argument("--reopen", action="store_true",
                    help="with --reclassify: write the ACT ones back into leads/ as RETRY leads")
    ap.add_argument("--only-clean", action="store_true",
                    help="with --reopen: skip the ones whose prose carries a park hint")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    eng = None
    if a.reclassify:
        eng = _resolve(a.reclassify)
        if eng is None or not eng.is_dir():
            print(f"engagement not found: {a.reclassify}", file=sys.stderr)
            return 2

    if not a.reclassify:
        keep = retained(eng)
        if a.json:
            print(json.dumps({"park": list(keep), "unparked": [e for e, _ in UNPARKED]}, indent=2))
            return 0
        print("PARK — a vector waits for the operator only for these:")
        for slug in keep:
            r = PARK_REASONS[slug]
            print(f"  {slug:16s} {r['title']}\n{' ' * 19}{r['why']}")
        if not keep:
            print("  (none)")
        print("\nACT — fired without asking, on our own account, in scope, minimally:")
        for excuse, instead in UNPARKED:
            print(f"  - {excuse}\n      -> {instead}")
        print("\nPer engagement: \"autonomy\": {\"unpark\": [\"human-inbox\"]} in profile.json")
        return 0

    rows = reclassify(eng)
    if a.reopen:
        pick = [r for r in rows if not (a.only_clean and r.get("hint"))]
        made = reopen(eng, pick)
    if a.json:
        print(json.dumps([{k: (str(v) if isinstance(v, Path) else v) for k, v in r.items()}
                          for r in rows], indent=2))
        return 0
    counts: dict[str, int] = {}
    for r in rows:
        key = r["reason"] or (f"ACT?/{r['hint']}" if r.get("hint") else r["verdict"])
        counts[key] = counts.get(key, 0) + 1
    print(f"{eng.relative_to(_targets_root())} — {len(rows)} blocked-test(s)")
    for r in rows:
        tag = f"PARK/{r['reason']}" if r["verdict"] == "PARK" else (
            f"ACT?/{r['hint']}" if r.get("hint") else r["verdict"])
        print(f"  {tag:22s} {r['name']}")
    print("  " + " · ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if a.reopen:
        print(f"  reopened {len(made)} lead(s) into {eng.name}/leads/ as STALLED (RETRY)")
    else:
        print("  --reopen writes the ACT ones back into leads/ as RETRY leads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
