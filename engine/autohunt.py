#!/usr/bin/env python3
"""autohunt.py — `cbh autohunt`: the next wave of worker briefs, decided from state.

What it replaces. Every hunt in this workspace started the same way by hand: read
`cbh leads`, read `cbh chain-graph`, read `cbh stop` for the budget, guess which
`hunt-*` skill each lane needs, remember what the corpus says that class chains
into, then write N briefs. Six commands and a judgement call per worker, repeated
every wave, by the one participant in the loop whose attention is the scarce
resource. The decision is mechanical — the inputs are all on disk — so it is done
here, and the operator is left with the one thing that is genuinely theirs: whether
to hand over an account and whether to submit.

One call = one wave. It is deliberately not a daemon: it reads the engagement's
state, emits the briefs for the slots the client has, and exits. Run it again after
the wave lands and it reads the new state — closures, new primitives, spent budget
— and emits the next one. That makes the loop restartable and auditable, and it
means a crashed wave costs one re-read instead of a lost run.

What each brief carries, and where it comes from:

  item          engine/lead_queue.py   ranked open lead / primitive (payout x staleness,
                                       accounts held, blocked vs stalled)
  skills        engine/skill_graph.py  the ladder for that surface: the URL-signal table
                                       first, then TRIGGER-term overlap; GATED marks the
                                       ones skill-gate will demand anyway
  defer_to      engine/skill_graph.py  lateral owners — another skill owns that surface,
                                       working it in this lane is spent budget
  then          engine/skill_graph.py  where a proof escalates; the severity ceiling of
                                       the lane is the end of that path, not this item
  chain         docs/disclosed-reports the disclosed reports whose class set this item
                                       belongs to, with their ordered steps and payout
  partner       corpus class pairs     the second primitive that turned this class into a
                                       Critical in the corpus, with n and the report ids
  precedent     engine/precedent.py    the nearest disclosed report to this item's title
  capability    engine/chain_graph.py  what the item must GIVE for the chain hub to move
  budget        engine/stop_gate.py    this lane's slice of the engagement's remaining
                                       request budget

Safety: this module sends nothing and decides no severity. The briefs it writes
name `bbcurl` as the transport, so scope, pacing, mandatory headers and the audit
log bind every request a worker makes, exactly as if the operator had written the
brief. On Claude Code the orchestrator may not send at all (`cbh client`), so the
output is briefs to dispatch, never requests.

usage:
    cbh autohunt                       # wave for the engagement in CBH_PROJECT
    cbh autohunt ozon --slots 3        # explicit program and crew size
    cbh autohunt --json                # machine-readable wave
    cbh autohunt --role refuter        # force the role instead of letting state pick
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

import funnel

import chain_graph  # noqa: E402
import client as client_mod  # noqa: E402
import lead_queue  # noqa: E402
from lead_queue import cut as _cut  # noqa: E402
import precedent  # noqa: E402
import skill_graph  # noqa: E402
import stop_gate  # noqa: E402

# The floor per role, used when an item's title scores no skill at all.
ROLE_SKILLS = {
    "refuter": ["triage-validation", "poc-runtime"],
    "scout": ["web2-recon", "hunt-source-leak"],
    "deep-hunter": ["bb-methodology"],
}

HOST_RE = re.compile(r"\b([a-z0-9][a-z0-9.\-]{3,}\.[a-z]{2,})\b", re.I)
H1_RE = re.compile(r"^#{1,3}\s+(.+?)\s*$", re.M)
# `## Title` / `## Заголовок` as a bare section label, and the first non-empty line of its
# body — the claim this workspace's finding template actually holds (see `_title_of_file`).
TITLE_SECTION_RE = re.compile(
    r"^[ \t]*#{1,6}[ \t]*\**[ \t]*(?:title|заголовок)[ \t]*\**[ \t]*$\s*\n[ \t]*(\S.*?)[ \t]*$",
    re.M | re.I)

# Tokens that say nothing about WHICH account a lane is missing. `live-ozonid-session`
# and `operator-authorized-task-admin-session` share `session`; matching on that would
# wall every item that needs any login at all.
WALL_GENERIC = {"session", "account", "login", "token", "valid", "live", "identity",
                "jar", "cookie", "auth", "authenticated", "user", "access", "with",
                "from", "into", "this", "that", "their", "full", "real", "one"}


def _distinctive(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (text or "").lower())
            if len(t) >= 4 and t not in WALL_GENERIC}


# Infrastructure a hunt cannot produce: a network position. Unlike a token, an oracle or a
# route, no amount of requests from this egress turns into "an egress that clears the .o3.ru
# edge challenge". Measured on standoff365/ozon 2026-11-12:
# `msg-o3-ru-mattermost-webhooks-in-public-bundle` took a 509-request lane although its own
# record says `POST /hooks/{token}` returns `403` «Доступ ограничен» 4 705 B from both lanes
# we have — bbcurl and headed Chrome carrying valid antibot cookies, confirmed twice, with
# no antibot challenge in the response, i.e. an edge network/IP restriction. The lane would
# have re-measured the same 403.
EGRESS_PHRASES = ("egress", "allowlisted network", "allowlisted ip", "ip allowlist",
                  "ip-allowlist", "corporate network", "office network", "internal network",
                  "vpn", "russian ip", "ru ip", "residential proxy", "residential ip",
                  "datacenter ip", "another asn", "different asn", "exit node", "exit ip",
                  "from inside the perimeter", "allowlisted source", "network position")


def network_wall(item: dict) -> str:
    """The egress this item's `needs` asks for and this workspace does not have, or "".

    Separate from `operator_wall` because the remedy is different: an account is the
    operator's to hand over, while a network position is nobody's here — the brief has to
    say so and the row has to stop outranking work that can be fired.
    """
    for need in item.get("needs") or []:
        low = (need or "").lower()
        for phrase in EGRESS_PHRASES:
            if phrase in low:
                return need
    return ""


def operator_wall(item: dict, accounts_wanted: list[str]) -> str:
    """The operator-held account group this item's `needs` runs into, or "".

    `lead_queue` already splits off items whose need names an unheld ROLE word, but a
    slug with no role word in it defaults to "user", and this engagement holds a user
    account — so `live-ozonid-session-sr-crm` counted as satisfied and was dispatched
    into the very wall the header above it printed as waiting on the operator. Matching
    is on distinctive tokens only (`ozonid` is in "a valid staff Ozon-ID session"), so
    `antibot-jar-for-the-sigma-static-fence` — obtainable by our own browser lane — is
    not walled by a word it merely shares.

    The item is demoted and labelled, never dropped: the unauthenticated arms of a
    gated route space are still work, and only the operator decides to hand over an
    account.
    """
    for need in item.get("needs") or []:
        toks = _distinctive(need)
        if not toks:
            continue
        for acct in accounts_wanted:
            flat = re.sub(r"[^a-z0-9]+", "", acct.lower())
            if any(t in flat for t in toks):
                return acct
    return ""


def _title_of_file(path: str) -> str:
    """How to name a finding in a brief: its file stem, plus a real claim line if one exists.

    `claimed_but_unproven` rows carry file, severity and evidence state but no
    title, and an empty title also emptied the skill ladder, which is scored on it.
    Reading the first heading does not work on this workspace's finding template:
    its headings are a draft banner ("[ЧЕРНОВИК — перед сабмитом ...]"), the literal
    placeholder "Title", then "Program / scope" — and briefing a lane on "Title"
    also matched the precedent corpus on that word and attached an unrelated RCE
    report. The stem is the identifier the workspace actually uses for a finding
    (`url-minifier-s.acme.com`), so that is the name; a heading is used only when it
    is long enough to be a claim about something.
    """
    # `funnel.item_name` so a folder-form item is named by its folder: `Path(...).stem`
    # is the literal word README for `leads/<slug>/README.md`, and that word reached the
    # skill picker and the brief's own title. Measured 2026-11-13.
    stem = funnel.item_name(path).replace("-", " ") if path else ""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")[:4000]
    except OSError:
        return stem
    sections = {"program / scope", "summary", "impact", "steps to reproduce",
                "evidence", "severity", "title", "описание", "заголовок"}
    # The template's `## Title` is a section LABEL whose body is the actual claim, so
    # skipping the label (above) threw the claim away with it and the refuter lane was
    # keyed on a filename: `title url minifier s.acme.com`. The claim is the first non-empty
    # line under that label — on `findings/url-minifier-s.acme.com.md`, "Анонимное
    # неаутентифицированное создание персистентных коротких ссылок на домене сокращателя
    # Ozon s.acme.com (POST …/url-minifier/create)". Same length floor as a heading claim,
    # and a line still holding a `<placeholder>` is not one.
    m = TITLE_SECTION_RE.search(text)
    if m:
        claim = m.group(1).strip().strip("*_` ")
        if len(claim) >= 25 and "<" not in claim:
            return claim
    for m in H1_RE.finditer(text):
        head = m.group(1).strip()
        if head.startswith("[") or head.lower().startswith(("draft", "черновик")):
            continue
        if len(head) < 25 or head.strip("*_` ").lower() in sections:
            continue
        return head
    return stem


# ---------------------------------------------------------------------------
# role: what the engagement's own state says this wave is for
# ---------------------------------------------------------------------------
def pick_role(assess: dict, queue: dict) -> tuple[str, str]:
    """(role, why). Order matters: a claim with no proof outranks new surface.

    An unproven claim sitting in `findings/` is the most expensive thing in the
    engagement — it blocks submission and it is what the refuter exists for. New
    surface is the cheapest and comes last, because a scout wave that runs while
    open primitives are unworked is how a 115-lead pile was built.
    """
    if assess.get("claimed_but_unproven"):
        n = len(assess["claimed_but_unproven"])
        return "refuter", f"{n} finding(s) claimed without a PASSing PoC — kill or prove them first"
    if queue.get("open"):
        return "deep-hunter", f"{len(queue['open'])} workable lead(s)/primitive(s) in the queue"
    hosts = assess.get("next_hosts") or []
    if hosts:
        return "scout", f"queue empty, {len(hosts)} host(s) never censused"
    unattacked = assess.get("unrefuted") or []
    if unattacked:
        return "refuter", (f"nothing workable and no unseeded host left, "
                           f"{len(unattacked)} claim(s) never faced a kill attempt")
    return "deep-hunter", "no open item and no unseeded host — re-read the ledger before spending"


# ---------------------------------------------------------------------------
# diversification
# ---------------------------------------------------------------------------
def _host_of(item: dict) -> str:
    m = HOST_RE.search(item.get("title") or "")
    return (m.group(1).lower() if m else "")


def _cap_of(item: dict) -> str:
    needs = item.get("needs") or []
    return (needs[0] or "").lower() if needs else ""


def spread(items: list[dict], slots: int) -> list[dict]:
    """Top `slots` items, no two sharing a host or a missing capability.

    Two workers on the same host contend for one pacing budget and one browser
    lane, and two workers waiting on the same missing capability both stall on the
    same wall — which is how a wave of six returned six copies of one refusal.
    Rank order is preserved; a collision is skipped, not reordered, and if that
    leaves slots empty they are filled from the skipped items rather than wasted.
    """
    chosen: list[dict] = []
    hosts: set[str] = set()
    caps: set[str] = set()
    skipped: list[dict] = []
    for it in items:
        h, c = _host_of(it), _cap_of(it)
        if (h and h in hosts) or (c and c in caps):
            skipped.append(it)
            continue
        chosen.append(it)
        if h:
            hosts.add(h)
        if c:
            caps.add(c)
        if len(chosen) >= slots:
            return chosen
    for it in skipped:
        if len(chosen) >= slots:
            break
        chosen.append(it)
    return chosen


# ---------------------------------------------------------------------------
# one brief
# ---------------------------------------------------------------------------
def _corpus_class(item: dict, rungs: list[dict]) -> str:
    """The item's class, expressed in a vocabulary the corpus shares.

    `lead_queue` labels 33 of ozon's 53 open items `other` and one `data-exposure`;
    the corpus speaks `info-leak`, `missing_authorization`, `parser-differential`.
    Taking the queue's label verbatim left those lanes with no partner pair and no
    chain. Candidates in order: the queue's label, then the classes the URL-signal
    table assigned, and the first one the corpus actually knows wins.
    """
    import skill_map

    corpus_classes = {c for r in skill_graph.load_corpus()
                      for c in (r.get("classes") or []) if c}
    candidates: list[str] = []
    for raw in [item.get("class") or ""] + [r.get("vuln_class") or "" for r in rungs]:
        if not raw or raw == "other":
            continue
        for c in (raw, skill_map.CLASS_TO_CORPUS.get(raw, "")):
            if c and c not in candidates:
                candidates.append(c)
    # A class the CORPUS knows, not merely one the skill map knows: `data-exposure`
    # is in CLASS_SKILL and in 0 reports, so accepting it here is what sent the chain
    # lookup to the skill fallback and attached two off-mechanic reports.
    for c in candidates:
        if c in corpus_classes:
            return c
    for c in candidates:
        if skill_map.CLASS_SKILL.get(c):
            return c
    return next((c for c in candidates if c), "")


def brief_for(item: dict, eng: Path, graph: dict, requests: int, role: str) -> dict:
    """Everything a worker needs for one item, with each claim's source attached."""
    # `other` is `lead_queue`'s "no CLASS_WORDS rule matched" placeholder, and it is the
    # literal word in `hunt-misc`'s TRIGGER ("doesn't cleanly fit any other hunt-* class").
    # Appending it to the scoring blob scored the catch-all 1 on 33 of ozon's 53 items,
    # and the catch-all has the highest report_count in the bundle (225), so it won every
    # tie: lane 2 of the 2026-11-12 wave loaded `hunt-misc` for a 262-endpoint SSR render
    # surface and lost its chains with it.
    label = item.get("class", "")
    blob = " ".join(filter(None, [item.get("title", ""), " ".join(item.get("needs") or []),
                                  "" if label in ("", "other") else label]))
    rungs = skill_graph.ladder(blob, graph, top=4)
    if not rungs:
        # A title can carry no surface at all — a refuter lane is keyed on a finding
        # whose heading is its claim, not its endpoint. The role's own skills are the
        # floor, so no lane is ever briefed with nothing to load.
        rungs = [{"skill": s, "gated": False, "via": "role-default", "defer_to": [],
                  "vuln_class": "", "score": 0, "report_count": 0}
                 for s in ROLE_SKILLS.get(role, ["bb-methodology"])]
    # A class the record states for itself outranks the ladder's reading of its title.
    # `finance-mf-ssr-render-route-url` is the measured case: its title says "262
    # endpoints taking a client-supplied `route-url`", so the ladder loads `hunt-ssrf`
    # first — and that file's own SSRF hypothesis is closed by three byte-identical
    # controls. Declaring `missing_authorization` is how a human says "that reading is
    # dead, the open work is authz", and it has to move what the lane loads or the
    # declaration is decoration. A GUESSED class never gets this: it comes from the same
    # filename and title the ladder already read, so it is not a second source.
    if item.get("class_declared"):
        import skill_map  # noqa: PLC0415 - same local import as _corpus_class

        # A skill the ladder already named is PROMOTED, not skipped. Skipping it left the
        # declaration doing nothing on the record it was written for: `hunt-cors` and
        # `hunt-dom` both scored 1 on `origin` for the postMessage lead, so neither was
        # missing — they were second and third behind `hunt-source-leak`, which scored on
        # `bundle`. The declaration decides the ORDER.
        want = [s for s in skill_map.CLASS_SKILL.get(item.get("class", ""), [])
                if s in graph["skills"]]
        if want:
            by_name = {r["skill"]: r for r in rungs}
            declared_rungs = []
            for skill in want:
                row = by_name.pop(skill, None) or {
                    "skill": skill, "vuln_class": item.get("class", ""), "gated": False,
                    "score": 0, "report_count": graph["skills"][skill]["report_count"],
                    "defer_to": [e["dst"] for e in skill_graph.owners(skill, graph)],
                    "escalates_to": [e["dst"] for e in skill_graph.escalations(skill, graph)],
                }
                declared_rungs.append({**row, "via": "class-declared"})
            rungs = (declared_rungs + [r for r in rungs if r["skill"] in by_name])[:4]

    # A refuter's own tooling leads, whatever the item's prose scores. Its job is to fire
    # the three arms whose PASS means the claim is wrong, and `triage-validation` plus
    # `poc-runtime` are what that takes. This used to fall out for free, because a finding
    # was named by its file stem and `url minifier s.acme.com` scored nothing — once the
    # claim line was read properly, `POST …/document-manager/url-minifier/create` scored
    # `hunt-csrf` on `post` and `hunt-llm-ai` on `document` and those two led the lane.
    if role == "refuter":
        floor = [s for s in ROLE_SKILLS.get(role, []) if s in graph["skills"]]
        if floor:
            by_name = {r["skill"]: r for r in rungs}
            rungs = [{**(by_name.pop(sk, None) or {
                "skill": sk, "vuln_class": "", "gated": False, "score": 0,
                "report_count": graph["skills"][sk]["report_count"],
                "defer_to": [e["dst"] for e in skill_graph.owners(sk, graph)],
                "escalates_to": [e["dst"] for e in skill_graph.escalations(sk, graph)],
            }), "via": "role-default"} for sk in floor]
            rungs += [r for r in by_name.values()][:2]

    primary = rungs[0]["skill"] if rungs else "hunt-dispatch"
    cls = _corpus_class(item, rungs)

    # By CLASS first. Keying on the SKILL asks "what has this skill ever been used
    # for", which is every class that maps to it — the widest possible net and the
    # reason a route-space primitive was briefed with `.env`-in-a-bundle chains. The
    # skill is the fallback only when the item has no class at all, and when neither
    # produces a report that shares the mechanic the lane is told so.
    chains = skill_graph.chains_for(cls, graph, top=2) if cls else []
    chains_via = "class" if chains else ""
    if not chains and not cls and role != "refuter":
        # Not for a refuter: `triage-validation` as the primary matched every class that
        # maps to it, so a Low open-redirect claim was briefed with an auxclickjacking and
        # a CSPT chain. A refuter follows the claim in front of it, not a corpus mechanic.
        chains = skill_graph.chains_for(primary, graph, top=2)
        chains_via = "skill" if chains else ""
    pairs = skill_graph.partners(cls, graph, top=3) if cls else []
    escalates = [e["dst"] for e in skill_graph.escalations(primary, graph)]

    return {
        "file": item.get("file", ""),
        "kind": item.get("kind", ""),
        "class": cls,
        "title": item.get("title", ""),
        "reward": item.get("reward", 0),
        "age_days": item.get("age_days", 0),
        "stalled": bool(item.get("stalled")),
        "needs": item.get("needs") or [],
        "role": role,
        "skills": [{"name": r["skill"], "gated": r["gated"], "via": r["via"],
                    "defer_to": r["defer_to"]} for r in rungs],
        "escalates_to": escalates,
        "corpus_chains": [{"id": c["id"], "severity": c["severity"], "bounty": c["bounty"],
                           "classes": c["classes"], "steps": c["steps"][:4],
                           "url": c["url"]} for c in chains],
        "chains_via": chains_via,
        "operator_wall": item.get("operator_wall", ""),
        "network_wall": item.get("network_wall", ""),
        "partners": pairs,
        "precedent": _cut(re.sub(r"\s+", " ", precedent.lane_line(blob) or "").strip(), 300),
        "requests": requests,
        "severity_claimed": item.get("severity_claimed", ""),
        "evidence": item.get("evidence", ""),
        "refute_reason": item.get("refute_reason", ""),
        # `cbh leads close` reads leads/ and primitives/. A finding is closed by the
        # verdict the refuter appends to the finding file itself, and a census batch
        # closes by the leads it writes — pointing all three at one command made two
        # of them print an instruction that does not apply.
        "close": (
            f"`cbh refute {item.get('file','')}` — then, if it lives, "
            f"`cbh leads close {item.get('file','')} --as proven --note '<what survived>'`, "
            f"and if it dies, `--as refuted` with the arm that killed it"
            if role == "refuter" and item.get("kind") == "primitive" else
            f"`cbh refute {item.get('file','')}`, append the verdict to the finding "
            f"(KILLED / SURVIVED / INCOMPLETE + the arms fired), then "
            f"`cbh evidence {item.get('file','')}`"
            if role == "refuter" else
            "write each ranked surface as its own leads/<slug>.md with a **Chain:** line"
            if role == "scout" else
            f"cbh leads close {item.get('file','')} "
            f"--as proven|refuted|exhausted|stalled --note '...'"),
    }


def refuter_share(slots: int, role: str, other_work: bool) -> tuple[int, int]:
    """(lanes refutation may take in all, of those how many for never-attacked claims).

    Two different things are being balanced. An unproven claim in `findings/` blocks
    submission, so it keeps the absolute priority it has always had — but capped at
    `slots - 1`, because eleven of them must not send a wave out with no hunter in it.
    A never-attacked claim is cheaper to leave alone for one more wave, so it takes a
    third of the wave and no more; the point of the floor is that it is never zero
    while such a claim exists. On the 2026-11-12 wildberries session the measured
    split was 125 deep-hunter lanes to 1 refuter.

    A wave forced to `--role deep-hunter` or `--role scout` fires no refuter lane: the
    operator asked for that role by name.
    """
    if role == "refuter":
        return slots, slots
    if role:
        return 0, 0
    if not other_work:
        return slots, slots
    return max(1, slots - 1), (max(1, slots // 3) if slots > 1 else 0)


def wave(program: str = "", slots: int = 0, role: str = "") -> dict:
    """The whole decision: engagement state in, briefs out."""
    eng = lead_queue.resolve_engagement(program or os.environ.get("CBH_PROJECT", ""))
    if eng is None:
        return {"error": "no engagement — pass a program name or set CBH_PROJECT=<platform>/<program>"}

    assess = stop_gate.assess(eng)
    queue = lead_queue.scan(eng)
    graph = skill_graph.build()

    if not slots:
        slots = client_mod.crew()
    chosen_role, why = pick_role(assess, queue)
    chosen_role = role or chosen_role

    # `budget["requests"]` is what this hunt has ALREADY FIRED, not what is left — the
    # wave used it as the remaining allowance and the render called it "left". With no
    # `max_requests` in profile.json (none of the current engagements set one) that made
    # every brief open with "0 request(s) left, 0 per lane", which reads to a worker as a
    # spent budget. Measured 2026-11-13: 8 of 12 engagements briefed 0, and mail_vk
    # briefed 1710 — its fired count. An absent cap is not a cap of zero.
    budget = assess.get("budget") or {}
    fired = int(budget.get("requests") or 0)
    limits = budget.get("limits") or {}
    try:
        cap = int(limits.get("max_requests") or 0)
    except (TypeError, ValueError):
        cap = 0
    left = max(0, cap - fired) if cap else None
    per_lane = (max(1, left // max(1, slots)) if left else 0) if cap else 0

    # Lanes are built per role, not per wave. The first version gave the whole wave
    # to the single highest-priority role, so one finding claimed without a PoC sent
    # a six-slot wave out as one refuter lane and five idle slots while 53 workable
    # items sat in the queue. The priority is about ORDER, not exclusivity.
    lanes: list[tuple[str, dict]] = []
    # Refuter lanes used to come from ONE source: a finding written in THIS hunt with no
    # PASSing PoC. A finding that got its PoC, a finding from an earlier hunt, and every
    # primitive were all unreachable by the role — see `stop_gate.unrefuted` for the
    # measurement. Both sources now feed the lane list, deduped by file, with the
    # unproven ones still first.
    other_work = bool(queue.get("open")) or bool(assess.get("next_hosts"))
    refute_room, unattacked_room = refuter_share(slots, role, other_work)
    seen_refuter: set[str] = set()
    if refute_room:
        for f in (assess.get("claimed_but_unproven") or []):
            if len(lanes) >= refute_room:
                break
            seen_refuter.add(f.get("file", ""))
            lanes.append(("refuter", {
                "file": f.get("file", ""), "kind": "finding",
                "class": "", "needs": [],
                "title": _title_of_file(f.get("file", "")),
                "severity_claimed": f.get("severity", ""),
                "evidence": f.get("evidence", ""),
                "refute_reason": "claimed in this hunt with no PASSing PoC behind it",
                "reward": 0, "age_days": 0}))
        taken = 0
        for u in (assess.get("unrefuted") or []):
            if len(lanes) >= refute_room or taken >= unattacked_room:
                break
            if u.get("file", "") in seen_refuter:
                continue
            seen_refuter.add(u.get("file", ""))
            taken += 1
            lanes.append(("refuter", {
                "file": u.get("file", ""),
                "kind": "finding" if u.get("tier") == "findings" else "primitive",
                "class": "", "needs": [],
                "title": _title_of_file(u.get("file", "")),
                "severity_claimed": u.get("severity", ""),
                "evidence": "",
                "refute_reason": u.get("why", ""),
                "reward": 0, "age_days": 0}))
    # An item whose missing capability IS an account the operator is already holding
    # open goes last, labelled. It is not dropped: the unauthenticated arms are still
    # work, and the operator — not this module — decides to hand over an account.
    accounts = sorted(queue.get("needs_account") or {})
    open_items = list(queue.get("open") or [])
    for it in open_items:
        w = operator_wall(it, accounts)
        if w:
            it["operator_wall"] = w
        n = network_wall(it)
        if n:
            it["network_wall"] = n
    # Stable, so rank is kept inside each band: firable first, then account-walled, then
    # egress-walled, which is the band nothing in this workspace can clear.
    open_items.sort(key=lambda r: (1 if r.get("operator_wall") else 0)
                    + (2 if r.get("network_wall") else 0))
    if role in ("", "deep-hunter"):
        for it in spread(open_items, slots - len(lanes)):
            if len(lanes) >= slots:
                break
            lanes.append(("deep-hunter", it))
    if len(lanes) < slots and role in ("", "scout"):
        hosts = assess.get("next_hosts") or []
        free = slots - len(lanes)
        if hosts:
            for i in range(min(free, len(hosts))):
                batch = hosts[i::free][:8]
                lanes.append(("scout", {
                    "file": "", "kind": "host-batch", "class": "", "needs": [],
                    "title": f"census batch: {', '.join(batch)}",
                    "reward": 0, "age_days": 0}))
    if role == "refuter":
        lanes = [l for l in lanes if l[0] == "refuter"]
    elif role == "scout":
        lanes = [l for l in lanes if l[0] == "scout"]

    briefs = [brief_for(it, eng, graph, per_lane, r) for r, it in lanes]
    return {
        "engagement": queue.get("engagement", str(eng)),
        "engagement_dir": str(eng),
        "client": client_mod.profile(),
        "role": chosen_role,
        "role_why": why if not role else f"forced by --role {role} (state said {why})",
        "slots": slots,
        "budget_requests_fired": fired,
        "budget_requests_cap": cap,
        # None, not 0: no cap configured. 0 means a configured cap is spent.
        "budget_requests_left": left,
        "requests_per_lane": per_lane,
        "bar_met": bool(assess.get("proven")),
        "allow_stop": bool(assess.get("allow")),
        "stop_reason": assess.get("reason", ""),
        "queue": {k: (len(v) if isinstance(v, list) else v)
                  for k, v in queue.items() if k in ("open", "closed", "blocked", "stalled")},
        "accounts_wanted": accounts,
        "walled_open_items": sum(1 for it in open_items if it.get("operator_wall")),
        "egress_walled_open_items": sum(1 for it in open_items if it.get("network_wall")),
        "chain_hub": chain_graph.brief_line(eng).strip(),
        "briefs": briefs,
    }


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------
def render(w: dict) -> str:
    if w.get("error"):
        return f"autohunt: {w['error']}\n"
    c = w["client"]
    L = [f"AUTOHUNT — {w['engagement']}  ·  {c['label']} ({c['client']}), {w['slots']} slot(s)",
         f"  lead role {w['role']} — {w['role_why']}",
         f"  queue     {w['queue'].get('open', 0)} open · {w['queue'].get('stalled', 0)} stalled · "
         f"{w['queue'].get('blocked', 0)} blocked · {w['queue'].get('closed', 0)} closed",
         # `.get` throughout: render is a formatter and is called on partial wave dicts
         # (the test stubs are one), so a missing key must not raise.
         "  budget    " + (
             f"{w.get('budget_requests_left')} of {w.get('budget_requests_cap')} request(s) "
             f"left ({w.get('budget_requests_fired', 0)} fired), "
             f"{w.get('requests_per_lane', 0)} per lane"
             if w.get("budget_requests_cap") else
             f"{w.get('budget_requests_fired', 0)} request(s) fired this hunt · no "
             "`max_requests` in profile.json, so no per-lane cap — pace by AGENTS.md, not "
             "by a number here")]
    if w["bar_met"]:
        L.append("  BAR MET   a qualifying finding is proven — validate and submit before spending more")
    if w["accounts_wanted"]:
        L.append(f"  operator  {len(w['accounts_wanted'])} item group(s) wait on an account: "
                 f"{'; '.join(_cut(a, 60) for a in w['accounts_wanted'][:2])}")
        if w.get("egress_walled_open_items"):
            L.append(f"  egress    {w['egress_walled_open_items']} open item(s) need a network "
                     f"position we do not have — ranked last (WALL below)")
        if w.get("walled_open_items"):
            L.append(f"            + {w['walled_open_items']} open item(s) need one of those "
                     f"accounts too — demoted, not dropped (WALL below)")
            L.append("            a headed window for the operator to log in: "
                     "`cbh browser login <program> --url <page>`")
    L.append(f"  {w['chain_hub']}")
    if not c["orchestrator_may_send"]:
        L.append("  NOTE      this client does not fire requests — dispatch each brief below to a worker")

    for i, b in enumerate(w["briefs"], 1):
        L.append("")
        # 0 is "uncapped", never "no requests": see the budget note in `wave`.
        allow = f"{b['requests']} request(s)" if b.get("requests") else "no request cap"
        L.append(f"--- LANE {i}/{len(w['briefs'])} · {b['role']} · {allow} ---")
        L.append(f"  item      {b['file'] or '(no file — new surface)'}")
        L.append(f"  title     {_cut(b['title'], 150)}")
        meta = []
        if b["kind"]:
            meta.append(b["kind"])
        if b["class"]:
            meta.append(f"class={b['class']}")
        if b["reward"]:
            meta.append(f"reward={b['reward']:,}")
        if b["age_days"]:
            meta.append(f"{b['age_days']}d old")
        if b["stalled"]:
            meta.append("STALLED (a previous lane died before answering it)")
        if meta:
            L.append(f"  meta      {' · '.join(meta)}")
        if b["needs"]:
            L.append(f"  needs     {', '.join(b['needs'][:3])}")
        if b.get("network_wall"):
            L.append(f"  WALL      that need is a network position, not a capability: "
                     f"{_cut(b['network_wall'], 90)}")
            L.append("            nothing in this workspace supplies it — fire only the arms "
                     "that work from this egress,")
            L.append("            re-measure the refusal ONCE to date it, and close `--as "
                     "blocked` (the target's edge is")
            L.append("            what refuses us), never `--as exhausted`.")
        if b.get("operator_wall"):
            L.append(f"  WALL      that need is an account the operator is holding open: "
                     f"{_cut(b['operator_wall'], 70)}")
            L.append("            fire ONLY the arms that need no such session. Do not spend the "
                     "lane waiting for it,")
            L.append("            and do not close it `--as blocked`: nothing about the target "
                     "blocked it. `--as stalled`.")
        if b["skills"]:
            L.append("  load      " + ", ".join(
                f"{s['name']}{'*' if s['gated'] else ''}" for s in b["skills"]))
            loaded = {s["name"] for s in b["skills"]}
            # Only the primary rung's lateral owners, and never one already on the
            # load line: the union over four rungs printed six skills, three of
            # which the lane was being told to load in the same breath.
            if b["skills"][0]["via"] == "class-declared":
                L.append(f"  class     the record declares `{b['class']}` for itself, so the "
                         "leading skill comes from that")
                L.append("            declaration and not from the title's wording — read the "
                         "record's own banner before")
                L.append("            working the class its title suggests.")
            defer = [d for d in (b["skills"][0]["defer_to"] or []) if d not in loaded]
            if defer:
                L.append(f"  defer to  {', '.join(defer[:4])} — those own their surface, do not work it here")
        if b["escalates_to"]:
            L.append(f"  then      prove it, and the chain continues in: {', '.join(b['escalates_to'])}")
        if b.get("chains_via") == "skill":
            L.append("  chain     (matched on the LOADED SKILL, not on this item's class — the "
                     "item has none. Check the")
            L.append("            mechanic before following it, and give the lead file a "
                     "**Chain:** class if it is wrong.)")
        for ch in b["corpus_chains"]:
            L.append(f"  chain     {ch['id']} {ch['severity'].upper()} ${ch['bounty']:,} — "
                     f"{' + '.join(ch['classes'])}")
            for n, step in enumerate(ch["steps"], 1):
                L.append(f"              {n}. {_cut(step, 140)}")
        # Silence here used to be indistinguishable from "the corpus supports nothing".
        # Naming the class that found nothing is what lets the next pass fix the label.
        if not b["corpus_chains"] and b["role"] != "refuter":
            L.append(f"  chain     none — no disclosed report in the corpus carries "
                     f"class={b['class'] or '(unclassified)'}")
            L.append("            work it from the skill's own TRIGGER, and if the class label "
                     "is wrong, fix it in the")
            L.append("            lead file: an off-mechanic chain is worse than no chain.")
        for p in b["partners"]:
            other = [x for x in p["classes"] if x != b["class"]] or p["classes"]
            L.append(f"  partner   {', '.join(other)} — {p['n']} disclosed report(s), "
                     f"${p['bounty']:,}, top {p['top_severity'] or 'n/a'} ({', '.join(p['reports'][:3])})")
        if b.get("refute_reason"):
            L.append(f"  why       {_cut(b['refute_reason'], 150)}")
            if b["kind"] == "primitive":
                L.append("            a primitive is a CAPABILITY claim: refute the capability, "
                         "not an impact it never")
                L.append("            asserted. If it survives, say which chains may stand on it.")
        if b["severity_claimed"] or b["evidence"]:
            L.append(f"  claimed   severity={b['severity_claimed'] or '?'} · "
                     f"evidence={b['evidence'] or '?'}")
        # Precedent is a corpus analogy drawn from the item's title. On a refuter
        # lane the title is a file stem, so the analogy is noise — and noise that
        # reads as evidence is worse than a missing line.
        if b["precedent"] and b["role"] != "refuter":
            L.append(f"  precedent {_cut(b['precedent'], 230)}")
        L.append(f"  transport CBH_PROJECT={w['engagement']} bbcurl — the only transport; "
                 f"impact unproven means primitives/, not findings/")
        L.append(f"  close     {b['close']}")

    L.append("")
    L.append("Re-run `cbh autohunt` after the wave lands: it re-reads closures, new primitives "
             "and spent budget and emits the next one.")
    if not w["allow_stop"]:
        L.append(f"Stop gate: {w['stop_reason'][:160]}")
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="cbh autohunt",
        description="decide the next wave of worker briefs from the engagement's own state")
    ap.add_argument("program", nargs="?", default="", help="engagement (default: CBH_PROJECT)")
    ap.add_argument("--slots", type=int, default=0, help="lanes (default: this client's crew)")
    ap.add_argument("--role", default="", choices=["", "deep-hunter", "scout", "refuter"],
                    help="force the role instead of letting the engagement's state pick it")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    w = wave(a.program, a.slots, a.role)
    if a.json:
        print(json.dumps(w, indent=2, default=str))
    else:
        sys.stdout.write(render(w))
    return 1 if w.get("error") else 0


if __name__ == "__main__":
    sys.exit(main())
