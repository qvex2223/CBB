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

# A census is ONE scout lane over 15-30 hosts (AGENTS.md "How to work"), never one lane per
# host. The old split, `hosts[i::free][:8]`, dealt the host list across every free slot, so
# six uncensused hosts and six free slots became six scout lanes of ONE host each. Measured
# on Grok session 01a1e937 (hackerone/wolt, 2026-11-17): waves printed `census batch:
# corporate.wolt.com`, `census batch: consumer-api.wolt.com`, …, and single-host lanes took
# 221M of the 428M tokens the workers spent, for 0 findings. Pacing is one flock'd budget per
# engagement, so N census lanes fire no more requests per minute than one; each extra lane
# only adds a whole worker context (system prompt, doctrine, skills, notes) re-paid on every
# model call. So hosts fill a lane up to SCOUT_BATCH_MAX before a second lane opens, and a
# wave opens at most SCOUT_LANES_MAX census lanes; the rest of the list is the next wave's.
SCOUT_BATCH_MAX = 30
SCOUT_LANES_MAX = 2

HOST_RE = re.compile(r"\b([a-z0-9][a-z0-9.\-]{3,}\.[a-z]{2,})\b", re.I)
# For an item's FILE NAME, which the funnel spells `<host>-<slug>.md`. HOST_RE cannot be
# reused here: its character class holds both `.` and `-`, so on `talantix.ru-ats` it
# matched the whole string, slug included. The `-|$` boundary is what stops it at the slug
# separator, and the lazy prefix with a `.tld` anchor is what keeps `api.hh.ru-similar-...`
# from stopping at `api.hh`.
FILE_HOST_RE = re.compile(r"^([a-z0-9][a-z0-9.\-]*?\.[a-z]{2,})(?:-|$)", re.I)
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
def pick_role(assess: dict, queue: dict, unrefuted_findings=()) -> tuple[str, str]:
    """(role, why). Order matters: a claim with no proof outranks new surface.

    An unproven claim sitting in `findings/` is the most expensive thing in the
    engagement — it blocks submission and it is what the refuter exists for. New
    surface is the cheapest and comes last, because a scout wave that runs while
    open primitives are unworked is how a 115-lead pile was built.

    `unrefuted_findings` is the SECOND half of "not fully confirmed": a finding with a
    PASSing PoC but no current kill attempt. `refuter_share` already hands the whole wave
    to confirmation for either half, so without this branch the header and the briefs
    disagreed — measured on the 2026-11-14 replay, `tumar/freedom` printed
    `lead role deep-hunter — 68 workable lead(s)` above three refuter briefs.
    """
    if assess.get("claimed_but_unproven"):
        n = len(assess["claimed_but_unproven"])
        return "refuter", f"{n} finding(s) claimed without a PASSing PoC — kill or prove them first"
    if unrefuted_findings:
        n = len(unrefuted_findings)
        return "refuter", (f"{n} finding(s) with a PoC but no current kill attempt — confirm "
                           f"before opening new surface")
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
def _norm_file(path: str) -> str:
    """A comparable key for one funnel item, whatever shape its path arrived in.

    `stop_gate` hands absolute paths (`/home/.../Targets/x/y/primitives/a.md`) while
    `lead_queue` hands engagement-relative ones (`primitives/a.md`). Comparing the raw
    strings never matched, which is why the same record could be claimed twice. The key
    is the last two components — tier plus item name — so both shapes collapse onto it.
    """
    parts = [p for p in str(path or "").replace("\\", "/").split("/") if p]
    return "/".join(parts[-2:]) if len(parts) >= 2 else "/".join(parts)


def _host_of(item: dict) -> str:
    """The host this lane would work, from the title, else from the item's own file name.

    The title alone was not enough, and the gap was silent: `spread()` only skips a
    collision between two items that BOTH report a host, so an item reporting `""`
    collided with nothing and the "no two lanes share a host" rule did not apply to it.
    Measured 2026-11-14 on standoff365/hh — `leads/talantix.ru-ats.md`,
    `leads/hh.ru-oauth-ato.md` and `primitives/hh.ru-account-otp-email.md` all returned
    `""` because their titles name the surface (`Talantix ATS (/ats/*)`) and not the
    hostname, so a six-slot wave put two lanes on `dev.hh.ru` and a third on a host
    another lane already held.

    The funnel names an item `<host>-<slug>.md` (`engine/funnel.py`), and that filing is
    the authoritative answer, so it is tried FIRST. A title is only the fallback, because
    a title names whatever host the write-up talks about — which is often a payload target
    and not the host the lane works at all: `leads/dev.hh.ru-backurl.md` is titled around
    the `backUrl` arm that points at `github.com`, and reading the title first made
    `github.com` this lane's host. An out-of-scope payload host must never be the key the
    wave spreads on.
    """
    name = _norm_file(item.get("file", "")).rsplit("/", 1)[-1]
    m = FILE_HOST_RE.match(re.sub(r"\.md$", "", name, flags=re.I))
    if m:
        return m.group(1).lower()
    m = HOST_RE.search(item.get("title") or "")
    return m.group(1).lower() if m else ""


def _cap_of(item: dict) -> str:
    needs = item.get("needs") or []
    return (needs[0] or "").lower() if needs else ""




def spread(items: list[dict], slots: int, taken_files: set[str] | None = None,
           taken_hosts: set[str] | None = None) -> list[dict]:
    """Top `slots` items, no two sharing a host or a missing capability.

    Two workers on the same host contend for one pacing budget and one browser
    lane, and two workers waiting on the same missing capability both stall on the
    same wall — which is how a wave of six returned six copies of one refusal.
    Rank order is preserved; a collision is skipped, not reordered, and if that
    leaves slots empty they are filled from the skipped items rather than wasted.

    `taken_files` / `taken_hosts` are what the refuter pass already claimed, because the
    spread has to hold across the WHOLE wave and not just inside this pass. Measured
    2026-11-14 on standoff365/hh at six slots: `primitives/hh.ru-account-otp-email.md`
    came back as lane 1 (refuter) AND lane 5 (deep-hunter) — one record, two roles, one
    trying to kill the claim while the other tried to prove it — and `api.hh.ru` held
    two lanes. At three slots the collision was invisible, so widening the crew is what
    exposed it. A file already claimed is skipped outright; a host already claimed is a
    soft collision, skipped first and only filled from the leftovers.
    """
    chosen: list[dict] = []
    hosts: set[str] = set(taken_hosts or ())
    caps: set[str] = set()
    skipped: list[dict] = []
    claimed = {_norm_file(f) for f in (taken_files or ())}
    for it in items:
        if _norm_file(it.get("file", "")) in claimed:
            continue                      # same record in two lanes: never, not even as filler
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
    # Filling a slot from the skipped items beats leaving it idle: pacing is one global
    # flock'd budget, so two lanes on one host serialise instead of adding requests. What
    # they DO contend for is the single browser profile per engagement
    # (`runtime/browser-lock.mjs`), so the lane is marked and the brief says so — a shared
    # host the worker cannot see is how two lanes wedge on one Chromium profile.
    for it in skipped:
        if len(chosen) >= slots:
            break
        h = _host_of(it)
        if h and h in hosts:
            it["host_shared"] = h
        else:
            if h:
                hosts.add(h)
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
        "host_shared": item.get("host_shared", ""),
        "hosts": list(item.get("hosts") or []),
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


def refuter_share(slots: int, role: str, other_work: bool,
                  unconfirmed_findings: int = 0) -> tuple[int, int]:
    """(lanes refutation may take in all, of those how many for never-attacked claims).

    Two different things are being balanced. A finding THIS hunt produced that is not
    fully confirmed blocks submission, so it has absolute priority. A never-attacked
    claim from the backlog is cheaper to leave alone for one more wave, so it takes a
    third of the wave and no more; the point of the floor is that it is never zero while
    such a claim exists. On the 2026-11-12 wildberries session the measured split was
    125 deep-hunter lanes to 1 refuter.

    **Operator directive 2026-11-14: a finding is confirmed BEFORE the crew moves on.**
    "если даже нашёл, пусть просто дальше продолжает искать, но уже после того как
    полностью подтвердил находку." So while an unconfirmed finding exists the wave may go
    entirely to confirmation — the old `slots - 1` hunter floor is dropped for that
    category. The floor was there so a pile of unproven claims could not send out a wave
    with no hunter in it, but it also meant the crew kept opening new surface while a
    claim it had already made sat unproven, which is the half of continuous mode that was
    never enforced: `stop_gate` banks a Medium+ and keeps going, and nothing checked that
    the banked thing was finished first. Confirmation lanes are finite (one per
    unconfirmed finding), so hunting resumes in the same wave the moment they run out —
    "continue searching" is preserved, it just queues behind the proof.

    The backlog share is deliberately NOT raised: 400-odd never-attacked primitives would
    otherwise swallow every wave forever and no new surface would ever be opened.

    A wave forced to `--role deep-hunter` or `--role scout` fires no refuter lane: the
    operator asked for that role by name.
    """
    if role == "refuter":
        return slots, slots
    if role:
        return 0, 0
    if not other_work:
        return slots, slots
    backlog = max(1, slots // 3) if slots > 1 else 0
    if unconfirmed_findings:
        return slots, backlog
    return max(1, slots - 1), backlog


def _crew_slots(eng) -> tuple[int, str]:
    """(slots, where the number came from) for this engagement — `engine/crew.py` decides.

    Falls back to the client row only when crew.py cannot answer, so a broken profile costs
    the override, never the wave.
    """
    try:
        import crew  # type: ignore
        plan = crew.plan(start=str(eng))
        n = int(plan.get("agents") or 0)
        if n > 0:
            return n, str(plan.get("source") or "engine/crew.py")
    except Exception:  # noqa: BLE001 - sizing must never break the wave
        pass
    return client_mod.crew(), "client row (crew.py could not size this engagement)"


def wave(program: str = "", slots: int = 0, role: str = "") -> dict:
    """The whole decision: engagement state in, briefs out."""
    eng = lead_queue.resolve_engagement(program or os.environ.get("CBH_PROJECT", ""))
    if eng is None:
        return {"error": "no engagement — pass a program name or set CBH_PROJECT=<platform>/<program>"}

    assess = stop_gate.assess(eng)
    queue = lead_queue.scan(eng)
    graph = skill_graph.build()

    if not slots:
        # `engine/crew.py` decides, not the client row: `"hunt_agents"` in the engagement's
        # profile.json OVERRIDES any crew number (root AGENTS.md), and `scripts/agent-gate.py`
        # already delegates here for the cap it enforces. This line used to read
        # `client_mod.crew()`, which knows only the client, so a six-lane engagement got a
        # three-brief wave: the cap said 6, the wave emitted 3, and the three idle slots were
        # invisible because nothing printed the disagreement. Measured 2026-11-14 on
        # standoff365/hh with `"hunt_agents": 6` set — `cbh autohunt` still said "3 slot(s)".
        slots, slots_source = _crew_slots(eng)
    else:
        slots_source = "--slots on the command line"
    # "Not fully confirmed" has two halves, and both are a finding THIS hunt claimed:
    # no PASSing PoC behind it (`claimed_but_unproven`), or a PoC but no current kill
    # attempt (`unrefuted`, findings tier). Either one blocks submission, so either one
    # outranks opening new surface (operator directive 2026-11-14) — and the LEAD ROLE has
    # to say so too, or the header contradicts the briefs underneath it.
    unproven = list(assess.get("claimed_but_unproven") or [])
    unrefuted_all = list(assess.get("unrefuted") or [])
    unrefuted_findings = [u for u in unrefuted_all if u.get("tier") == "findings"]
    unrefuted_backlog = [u for u in unrefuted_all if u.get("tier") != "findings"]
    chosen_role, why = pick_role(assess, queue, unrefuted_findings)
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
    unconfirmed = len(unproven) + len(unrefuted_findings)
    refute_room, unattacked_room = refuter_share(slots, role, other_work, unconfirmed)
    seen_refuter: set[str] = set()
    if refute_room:
        for f in unproven:
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
        # A finding needing a kill attempt is NOT backlog: it is this hunt's own claim,
        # so it does not compete for `unattacked_room` (a third of the wave). Before
        # 2026-11-14 both tiers shared that cap, so a finding blocking submission could be
        # crowded out of its own wave by primitives ranked ahead of it.
        taken = 0
        for u in unrefuted_findings + unrefuted_backlog:
            is_backlog = u.get("tier") != "findings"
            if len(lanes) >= refute_room:
                break
            if is_backlog and taken >= unattacked_room:
                continue
            if u.get("file", "") in seen_refuter:
                continue
            seen_refuter.add(u.get("file", ""))
            if is_backlog:
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
        # Exclude what the refuter pass already claimed — by record AND by host.
        taken_hosts = {_host_of(it) for _r, it in lanes if _host_of(it)}
        for it in spread(open_items, slots - len(lanes),
                         taken_files=seen_refuter, taken_hosts=taken_hosts):
            if len(lanes) >= slots:
                break
            lanes.append(("deep-hunter", it))
    if len(lanes) < slots and role in ("", "scout"):
        hosts = list(assess.get("next_hosts") or [])
        free = slots - len(lanes)
        if hosts:
            # `assess` caps `next_hosts` at 6 for the stop gate's own message; a census lane
            # takes up to SCOUT_BATCH_MAX, so ask for the wider list here. Any failure keeps
            # the six already in hand — the census must never cost the wave.
            want = SCOUT_BATCH_MAX * min(free, SCOUT_LANES_MAX)
            try:
                hosts = stop_gate.next_hosts(eng, limit=want) or hosts
            except Exception:  # noqa: BLE001
                pass
            n = min(free, SCOUT_LANES_MAX, -(-len(hosts) // SCOUT_BATCH_MAX))
            for i in range(n):
                batch = hosts[i::n][:SCOUT_BATCH_MAX]
                lanes.append(("scout", {
                    "file": "", "kind": "host-batch", "class": "", "needs": [],
                    "title": f"census batch: {len(batch)} host(s), {', '.join(batch)}",
                    # The full list, because render cuts a title at 150 characters and a
                    # 30-host title would brief the worker with a third of its hosts.
                    "hosts": list(batch),
                    "reward": 0, "age_days": 0}))
    if role == "refuter":
        lanes = [l for l in lanes if l[0] == "refuter"]
    elif role == "scout":
        lanes = [l for l in lanes if l[0] == "scout"]

    briefs = [brief_for(it, eng, graph, per_lane, r) for r, it in lanes]
    # The header names the LANES THAT EXIST, not the plan that produced them. `pick_role`
    # predicts from the queue before `spread` has run, and the two can legitimately part
    # ways: an unattacked claim in `primitives/` is BOTH an open queue item and a refuter
    # candidate, so the refuter lane takes the record and `spread` then refuses to reissue
    # it as a hunter lane (correct — one record, one lane) leaving the prediction stale.
    # Measured on the 2026-11-14 decision replay: `standoff365/hh` printed `lead role
    # deep-hunter — 1 workable lead(s)/primitive(s) in the queue` above a wave of one
    # refuter and two scouts, with no hunter lane at all. A worker reads the header first.
    if not role and lanes:
        mix = [r for r, _ in lanes]
        if chosen_role not in mix:
            actual = max(set(mix), key=mix.count)
            why = (f"{why}, but every one of those went to another lane — this wave is "
                   f"{', '.join(f'{mix.count(r)} {r}' for r in sorted(set(mix)))}")
            chosen_role = actual
    return {
        "engagement": queue.get("engagement", str(eng)),
        "engagement_dir": str(eng),
        "client": client_mod.profile(),
        "role": chosen_role,
        "role_why": why if not role else f"forced by --role {role} (state said {why})",
        "slots": slots,
        "slots_source": slots_source,
        "unconfirmed_findings": unconfirmed,
        "budget_requests_fired": fired,
        "budget_requests_cap": cap,
        # None, not 0: no cap configured. 0 means a configured cap is spent.
        "budget_requests_left": left,
        "requests_per_lane": per_lane,
        "bar_met": bool(assess.get("proven")),
        "allow_stop": bool(assess.get("allow")),
        "stop_reason": assess.get("reason", ""),
        # Whether a Stop hook will ACT on the verdict above. engine/stop_gate.py is a Claude
        # Code `Stop` hook, so for any other client the verdict is advisory and this line is
        # the only place it is ever seen (0 of 59 recorded stop_gate sessions were non-Claude).
        "stop_hook": client_mod.stop_hook(),
        "queue": {k: (len(v) if isinstance(v, list) else v)
                  for k, v in queue.items() if k in ("open", "closed", "blocked", "stalled")},
        "accounts_wanted": accounts,
        "walled_open_items": sum(1 for it in open_items if it.get("operator_wall")),
        "egress_walled_open_items": sum(1 for it in open_items if it.get("network_wall")),
        "chain_hub": chain_graph.brief_line(eng).strip(),
        # Slots this wave leaves empty ON PURPOSE: the queue and the census are both used up
        # at their proper size. Said out loud because an orchestrator told to "keep every
        # slot filled" otherwise fills them itself — on 01a1e937 it wrote 38
        # `<host>-leftover-paths.md` leads to re-sweep hosts already closed `exhausted`.
        "idle_slots": max(0, slots - len(briefs)),
        "briefs": briefs,
    }


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------
def render(w: dict) -> str:
    if w.get("error"):
        return f"autohunt: {w['error']}\n"
    c = w["client"]
    L = [f"AUTOHUNT — {w['engagement']}  ·  {c['label']} ({c['client']}), {w['slots']} slot(s)"
         + (f" — {w['slots_source']}" if w.get("slots_source") else ""),
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
    # Dispatching one lane and waiting for it is the single biggest throughput loss there
    # is, and it is invisible from inside the session: every lane still succeeds, the hunt
    # still progresses, it just runs at a fraction of its budget. Measured 2026-11-14 on a
    # 3.4 h Grok hunt of standoff365/hh — `cbh autohunt` emitted 6 briefs every wave, the
    # orchestrator ran 3-4 lanes concurrently for the first hour and exactly ONE for the
    # last 50 minutes: 46 lanes at 6-8 min each, ~8 lanes/hour against a capacity of ~45,
    # and 9.96 requests/min against a paced budget of 600. So the rule is printed with the
    # count, in the wave itself, every wave.
    if len(w.get("briefs") or []) > 1:
        n = len(w["briefs"])
        L.append(f"  DISPATCH  all {n} brief(s) below in ONE message, then wait. Spawning one "
                 f"lane and waiting for it wastes {n - 1}/{n} of this wave: lanes run "
                 f"6-8 min each, they share one flock'd request budget (so {n} together fire "
                 f"no faster than 1, they just cover {n}x the surface), and the moment a "
                 f"lane hands back, re-run `cbh autohunt` and fill the slot from the queue.")
    if not c["orchestrator_may_send"]:
        L.append("  NOTE      this client does not fire requests — dispatch each brief below to a worker")
    if w.get("idle_slots"):
        L.append(f"  IDLE      {w['idle_slots']} slot(s) stay empty this wave on purpose: the queue "
                 f"and the census are used up at their proper size. Do NOT write new leads to "
                 f"fill them, do NOT split a census batch into one lane per host, and do NOT "
                 f"re-sweep a host already closed `exhausted` without a new input (a JS-named "
                 f"path, a response, a primitive). Re-run `cbh autohunt` when a lane lands.")

    for i, b in enumerate(w["briefs"], 1):
        L.append("")
        # 0 is "uncapped", never "no requests": see the budget note in `wave`.
        allow = f"{b['requests']} request(s)" if b.get("requests") else "no request cap"
        L.append(f"--- LANE {i}/{len(w['briefs'])} · {b['role']} · {allow} ---")
        L.append(f"  item      {b['file'] or '(no file — new surface)'}")
        L.append(f"  title     {_cut(b['title'], 150)}")
        if b.get("hosts"):
            L.append(f"  hosts     ({len(b['hosts'])}, all of them this lane's) {', '.join(b['hosts'])}")
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
        if b.get("host_shared"):
            L.append(f"  SHARED    another lane of this wave is on `{b['host_shared']}` too — the "
                     f"queue does not")
            L.append("            hold enough distinct hosts to fill the crew. Requests are safe "
                     "(pacing is one")
            L.append("            global flock'd budget, so you serialise rather than add load), "
                     "but the engagement has")
            L.append("            ONE browser profile: if this lane needs Playwright, say so in "
                     "the hand-back and")
            L.append("            fire `bbcurl` arms first, or the two lanes wedge on one "
                     "Chromium profile.")
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
    if w.get("unconfirmed_findings"):
        L.append(f"CONFIRM FIRST: {w['unconfirmed_findings']} finding(s) this hunt claimed are not "
                 f"fully confirmed (no PASSing PoC, or no current kill attempt). Operator directive "
                 f"2026-11-14: a finding is finished before the crew opens new surface, so the "
                 f"refuter lanes above come first and hunting resumes in this same wave once they "
                 f"run out. Each one closes with `cbh refute` + `cbh triage`; a KILL is answered "
                 f"with `cbh triage <f> --demote`, never an argument.")
    # Printed BOTH ways, not only on a deny. For a client whose Stop hook will act on it the
    # deny is the interesting case; for a client with no Stop hook the ALLOW is the dangerous
    # one — nothing would stop that session from simply ending, and this line is the whole
    # mechanism it gets.
    L.append(f"Stop gate: {'may stop' if w['allow_stop'] else 'KEEP HUNTING'} — "
             f"{w['stop_reason'][:160] or 'no reason recorded'}")
    if not w.get("stop_hook"):
        # An advisory is not a mechanism. Measured on intigriti/1password 2026-11-18: this
        # exact line printed on every wave and the session still handed the turn back to the
        # operator after each single lane — twice, 17 minutes idle the first time — because
        # "continuing is YOUR obligation" reads as a reminder, not as a step to execute. So the
        # three things that actually stall an unhooked client are now numbered, in the wave,
        # every wave: dispatch width, the spawn flake, and the hand-back.
        n = len(w.get("briefs") or []) or 1
        # Numbered dynamically. At n=1 the width step is OMITTED, not reworded: the parallel
        # arithmetic is nonsense there ("1 together fire no faster than 1") and a one-lane wave
        # has no width to get wrong. Steps 2 and 3 still apply at n=1 — the 2026-11-18 scout
        # was a ONE-lane wave and its spawn 403'd three times before it ran.
        steps = []
        if n > 1:
            steps.append(f"DISPATCH WIDTH. Send all {n} brief(s) above in ONE message. Measured "
                         f"2026-11-18T05:51:18: two lanes sent in one message both ran to the "
                         f"end (66 and 75 tool calls). Lanes share one flock'd budget, so {n} "
                         f"together fire no faster than 1 — they cover {n}x the surface. One "
                         f"lane at a time is the single biggest waste a wave can make.")
        steps.append("A SPAWN THAT 403s IS NOT A DEAD LANE. `API error (status 403 Forbidden): "
                     "permission-denied` is a server-side flake — 6 of 10 spawns on "
                     "2026-11-18, and every one of that day's four brief texts first failed "
                     "and then succeeded BYTE-IDENTICAL, so neither the brief, its length, the "
                     "role nor the model is the cause. Re-send THAT SLOT's identical call at "
                     "once, up to six times, and do not hold the rest of the wave behind it: "
                     "the slots already running stay running. The wave is dispatched only when "
                     "as many lanes are running as there are briefs.")
        steps.append("NEVER HAND THE TURN BACK AFTER A LANE LANDS. Re-run `cbh autohunt`, act "
                     "on the `Stop gate:` line, dispatch the next wave. Do not stop to report "
                     "and wait for permission. A finding never ends the hunt either: bank it, "
                     "confirm it (`cbh refute` + `cbh triage`, a KILL answered with `cbh "
                     "triage <f> --demote`), take the next vector. ONLY THE OPERATOR ENDS A "
                     "HUNT.")
        # The header counts the steps it is about to print, because at n=1 there are two.
        L.append(f"  ^ NO STOP HOOK ON THIS CLIENT — the {len(steps)} steps below are not "
                 f"advice, they are the wave protocol. Nothing else keeps this session "
                 f"hunting.")
        for i, step in enumerate(steps, 1):
            L.append(f"    {i}. {step}")
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
