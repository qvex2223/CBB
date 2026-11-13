#!/usr/bin/env python3
"""
evidence.py — does this finding have a fired request behind it, or a memory?

The 7-Question Gate asks "can I demonstrate this right now?" (Q1) and "can you
prove impact?" (Q6), and until now both were answered by grepping the finding
text for words like "poc" and "response". A finding that *says* "PoC: curl ...
returns 200" passes that check whether or not the request was ever sent.

`poc_runtime.py` already writes a `.result.json` next to every spec it fires:
real bytes, redirect chain, cookies, a verdict computed in code. This module is
the other half — it looks for that artifact and refuses to call a finding
demonstrated without one.

Rules, deliberately blunt:
  * a PASS artifact whose URL appears in the finding text   -> demonstrated
  * a PASS artifact for some other URL                      -> mismatch, not proof
    (this catches the copy-paste of last week's evidence onto today's bug)
  * FAIL / ERROR / INCONCLUSIVE                             -> not proof
  * nothing at all                                          -> not proof

CLI:
    python3 engine/evidence.py <finding.md | dir | result.json>
exit 0 = a PASS artifact backs it, 1 = artifacts exist but none prove it,
2 = no artifact found at all.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

MAX_SCAN = 200  # result files to consider; an engagement with more has other problems

# Claims that live on the wire, not in a single status code. A report that says
# "redirects to /login", "the session dies", "Set-Cookie carries the token" is
# describing behaviour that a one-shot curl cannot show and memory routinely gets
# wrong — the whole reason poc_runtime now records chains and cookies.
WIRE_CLAIM_RE = re.compile(
    r"redirect|302|301|303|307|location:|set-cookie|cookie|session|logout|log out|"
    r"sso|oauth|saml|csrf|token refresh|"
    r"редирект|перенаправ|сесси|кук|вход|выход|авториз",
    re.I)

# A proxy-captured request/response saved next to the finding counts as wire
# evidence: the proxy saw the real exchange, chain included. Caido is this
# workspace's proxy (docs/caido.md) and exports HAR; the .burp.* names stay
# accepted so findings written before 2026-10-14 keep their evidence.
WIRE_CAPTURE_SUFFIXES = (".caido.txt", ".caido.json", ".caido.har",
                         ".burp.txt", ".burp.json", ".burp.har", ".har")

# `bbcurl` now keeps every response body, headers included, under a sha256 in the
# response corpus. A finding that cites one of those hashes is pointing at bytes
# the transport actually received — so a stored 302 with its Location and
# Set-Cookie lines is wire evidence in exactly the way a remembered one is not.
# The citation has to be explicit: matching a corpus entry to a finding by URL
# alone would quietly hand today's report yesterday's capture.
CORPUS_SHA_RE = re.compile(r"\b([0-9a-f]{64})\b")
WIRE_HEADER_RE = re.compile(r"^(location|set-cookie):", re.I | re.M)
HTTP_STATUS_RE = re.compile(r"^HTTP/\d", re.M)


def _load(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _urls(doc: dict) -> List[str]:
    """Every URL the artifact actually hit, chain steps included."""
    out: List[str] = []
    for run in doc.get("runs") or []:
        for step in run.get("steps") or []:
            if step.get("url"):
                out.append(step["url"])
        res = run.get("result") or {}
        if res.get("final_url"):
            out.append(res["final_url"])
    spec = doc.get("spec_file")
    if not out and spec:
        out.append("")
    return out


def _age_days(doc: dict) -> Optional[float]:
    ts = doc.get("timestamp")
    if not ts:
        return None
    try:
        when = datetime.fromisoformat(ts)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return round((datetime.now(timezone.utc) - when).total_seconds() / 86400, 1)
    except Exception:  # noqa: BLE001
        return None


def _endpoint_tokens(url: str) -> List[str]:
    """Bits of a URL worth searching a finding for: host, and the path."""
    try:
        p = urllib.parse.urlsplit(url)
    except Exception:  # noqa: BLE001
        return []
    toks = []
    if p.hostname:
        toks.append(p.hostname)
    if p.path and p.path != "/":
        toks.append(p.path)
    return toks


def _refute_candidates(target: Path) -> List[Path]:
    """Every `*.refute.json` that could belong to this finding, best-named first.

    `engine/refute.py` names its output after the SPEC it fired (`poc.json` ->
    `poc.refute.json`), while a finding is addressed by its report (`report.md`), so the
    two named guesses below can both miss and a real KILLED verdict then reads as "no
    refutation ran". Measured 2026-11-02: `cbh triage` reported PASS-PENDING-REFUTE 7/7
    beside a KILLED refutation sitting in the same folder, which is exactly how a refuted
    finding gets promoted. The directory sweep is the backstop, and it is sound because a
    finding owns its folder (one folder per finding).
    """
    target = Path(target)
    stem = target.name.split(".")[0]
    named = [target.with_name(stem + ".refute.json"),
             target.with_name(target.stem + ".refute.json")]
    out: List[Path] = []
    for c in named:
        if c not in out:
            out.append(c)
    parent = target.parent
    if not parent.is_dir():
        return out
    # The folder sweep only counts a refutation that actually fired against a spec this
    # finding has a PASSing artifact for. Measured 2026-11-02: a lane left a second,
    # deliberately-renamed spec in its folder, its refutation said KILLED, and crediting
    # it to the finding turned a real PASS into a false REFUTED. A refutation of some
    # other spec is not a refutation of this finding — and silently borrowing one is the
    # same class of error as borrowing another bug's PoC.
    # `own` must be THIS write-up's artifacts, not the directory's. Building it from
    # `parent.glob` meant any refutation whose spec had a result ANYWHERE in the folder
    # matched — so in a flat `primitives/` dir a sibling's KILLED was credited here.
    own = {q.name[:-len(".result.json")]
           for q in collect(target) if q.name.endswith(".result.json")}
    for c in sorted(parent.glob("*.refute.json")):
        if c in out:
            continue
        try:
            doc = json.loads(c.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        spec = str(doc.get("spec_file") or doc.get("spec") or "")
        spec_stem = Path(spec).name[:-len(".json")] if spec.endswith(".json") else ""
        # `own` empty means this finding has no .result.json of its own in here, so a
        # refutation sitting in the same flat directory belongs to SOME OTHER file in it.
        # Adopting it was how a `primitives/` entry got a REFUTED read out of another
        # finding's refutation (measured 2026-11-05): four PASS artifacts from other
        # hosts were pooled and the KILLED came from a file this one never mentions.
        if own and spec_stem and spec_stem in own:
            out.append(c)
    return out


def _refutation(target: Path) -> Dict | None:
    """A `<finding>.refute.json` whose controls knocked this finding back.

    `engine/refute.py` fires the requests that would DISPROVE a finding, and its
    verdict has to outrank a PASS: a passing exploit next to a passing control is
    not evidence of a bug, it is evidence the response ignores the input. Without
    this read, the two artifacts would sit side by side and `cbh triage` would
    report DEMONSTRATED off the first one.
    """
    if not target.is_file():
        return None
    for cand in _refute_candidates(target):
        if cand.is_file():
            try:
                doc = json.loads(cand.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if doc.get("verdict") in ("KILLED", "MIS-FRAMED"):
                return {"file": str(cand), **doc}
    return None


def refute_record(target: Path) -> Dict | None:
    """The `<finding>.refute.json` for this finding, whatever its verdict, or None.

    `_refutation` above only returns the KILLED/MIS-FRAMED ones because those outrank
    a PASS. `cbh triage` also needs to know whether `cbh refute` ran at all: a PASS
    nobody tried to kill is not ready for a report (2026-11-02, crit/high lessons —
    a validator pass took an AI hunter from ~80% to ~60% false positives).
    """
    target = Path(target)
    if not target.is_file():
        return None
    for cand in _refute_candidates(target):
        if cand.is_file():
            try:
                return {"file": str(cand), **json.loads(cand.read_text(encoding="utf-8"))}
            except (OSError, ValueError):
                continue
    return None


def _wire_capture_files(where: Path) -> List[Path]:
    if not where or not where.is_dir():
        return []
    out: List[Path] = []
    for q in where.rglob("*"):
        if q.is_file() and str(q).lower().endswith(WIRE_CAPTURE_SUFFIXES):
            out.append(q)
    return sorted(out)


def _corpus_rows(text: str) -> List[Dict]:
    """Response-corpus entries the finding cites by hash."""
    rows: List[Dict] = []
    if not text:
        return rows
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import responses  # type: ignore
    except Exception:  # noqa: BLE001
        return rows
    for sha in dict.fromkeys(CORPUS_SHA_RE.findall(text)):
        path = responses.path_for("", sha)
        if not path:
            continue
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8000]
        except Exception:  # noqa: BLE001
            continue
        rows.append({
            "file": str(path),
            "verdict": "CORPUS-CAPTURE",
            "urls": [],
            "age_days": None,
            "matches_finding": True,
            "steps": 0,
            # Headers are what make it wire evidence. A body captured with the
            # caller's own -o has no header block, and proves nothing about hops.
            "wire": bool(WIRE_HEADER_RE.search(head) or HTTP_STATUS_RE.search(head)),
        })
    return rows


def _wire_captured(doc: dict) -> bool:
    """Did this artifact actually record wire state — a chain, hops, or cookies?"""
    for run in doc.get("runs") or []:
        steps = run.get("steps") or []
        if len(steps) > 1:
            return True
        for r in [run.get("result") or {}] + [st.get("result") or {} for st in steps]:
            if r.get("redirects") or r.get("set_cookie"):
                return True
    return False


def _is_control_artifact(path: Path) -> bool:
    """Artifacts under refutations/ are CONTROLS, never evidence of a finding.

    `engine/refute.py` fires requests designed to pass when the finding is wrong, and
    they land in `refutations/<finding>/`. Left in the candidate pool, a passing
    control could be matched to some other finding by URL tokens and read as proof —
    the exact inversion this pair of tools exists to prevent.
    """
    return any(part == "refutations" for part in path.parts)


def collect(target: Path) -> List[Path]:
    """Find candidate .result.json artifacts for a finding file or directory."""
    if target.is_file() and target.name.endswith(".result.json"):
        return [target]
    if target.is_file():
        # a finding: its own sibling artifacts first, then the engagement's
        sibling = target.with_name(target.stem + ".result.json")
        found = [sibling] if sibling.exists() else []
        # A SPEC's own result is the only honest answer for that spec. Widening to the
        # directory here handed one lane ANOTHER lane's result — and its KILLED — because
        # two lanes shared `primitives/` (measured 2026-11-05). A finding may still fall
        # back to the directory: it names its endpoint in prose and `_check` matches on it.
        if found and target.name.endswith((".poc.json", ".json")):
            return found
        # A same-named folder is this finding's own evidence directory (one folder per
        # finding), so it is searched before any shared directory.
        own_dir = target.with_name(target.stem)
        if own_dir.is_dir():
            found += sorted(q for q in own_dir.rglob("*.result.json")
                            if q not in found and not _is_control_artifact(q))
            if found:
                return found[:MAX_SCAN]
        # NO blanket directory sweep for a flat-tier file. Two measured failures, in both
        # directions, on 2026-11-05:
        #   * sweeping `parent.parent` pooled the whole engagement and a sibling's KILLED
        #     overturned a real primitive (false REFUTED);
        #   * then excluding only artifacts *owned by a sibling .md* still left ORPHANED
        #     artifacts from other hosts in the pool, one matched on a URL token, and a
        #     primitive whose own text says "impact NOT demonstrated" came back
        #     `Q1/Q6 backed by a fired PoC` (false DEMONSTRATED) — the dangerous direction,
        #     because that is the gate that decides whether a report gets drafted.
        # An artifact belongs to this write-up only if it is named after it (`<slug>.result.json`,
        # `<slug>.poc.result.json`) or sits in its own `<slug>/` folder. Anything else is
        # someone else's evidence. Under-claiming here is safe: the fix for a finding with no
        # artifact of its own is to fire one and name it after the finding, which is the house
        # convention already.
        parent = target.parent
        mine = target.name.split(".")[0]
        if parent.is_dir():
            found += sorted(q for q in parent.rglob("*.result.json")
                            if q not in found and not _is_control_artifact(q)
                            and q.name.split(".")[0] == mine)
        return found[:MAX_SCAN]
    if target.is_dir():
        return [q for q in sorted(target.rglob("*.result.json"))
                if not _is_control_artifact(q)][:MAX_SCAN]
    return []


# A finding needs a named party that is harmed. Session a0053cc0 wrote 134 primitives and
# 1 finding on one engagement, and the word `victim` appeared in 15 of its 138 worker
# briefs — nobody was asked who loses what, so "capability proven" kept being written up
# as impact. Only a LABELLED line counts: prose about "an attacker" is what the tier
# confusion is made of. Soft on write (the verdict never changes), strict on read: the
# line is reported, and `cbh triage` holds a pass at PASS-PENDING-VICTIM until it exists.
VICTIM_RE = re.compile(
    r"^[ \t>*\-]*\*{0,2}(victim|who is harmed|harmed party|affected party|"
    r"жертва|кто страдает|кому вред)\*{0,2}[ \t]*[:\u2014\u2013-]", re.I | re.M)


def has_victim(text: str) -> bool:
    """True when the text names the harmed party on a line of its own."""
    return bool(text and VICTIM_RE.search(text))


VICTIM_ADVICE = (
    "No victim line. Add one line — `**Victim:** <party that is not you> loses <what>` — "
    "naming a party that is not the operator (another user, a seller, the programme's own "
    "operator) and what they lose. Cannot name one? It is a `primitives/` entry, not a "
    "finding: `cbh triage <finding> --demote`. A client-held random id is a bearer token, "
    "not an IDOR, and \"could be chained\" is not impact.")


def victim_line(report: Dict) -> str:
    """One line for the gate; empty when the finding names its victim."""
    return "" if report.get("victim") else VICTIM_ADVICE


def _check(text: str, artifacts: List[Path], where: Path,
           refutation: Dict | None = None, name: str = "",
           class_gate: bool = True) -> Dict:
    """Core verdict logic: finding text (already lowercased), candidate artifacts and
    the directory to scan for proxy captures."""
    rows = []
    # Wire evidence that did not come from poc_runtime: corpus entries the finding
    # cites by hash, and proxy captures saved next to it.
    rows += _corpus_rows(text)
    for bp in _wire_capture_files(where):
        rows.append({"file": str(bp), "verdict": "WIRE-CAPTURE", "urls": [],
                     "age_days": None, "matches_finding": True, "steps": 0,
                     "wire": True})
    for path in artifacts:
        doc = _load(path)
        if doc is None:
            continue
        verdict = doc.get("final_verdict", "?")
        urls = _urls(doc)
        # No finding text to match against (dir mode) means every artifact counts.
        if text:
            matched = any(
                all(tok.lower() in text for tok in _endpoint_tokens(u) if tok)
                for u in urls if u
            )
        else:
            matched = True
        rows.append({
            "file": str(path),
            "verdict": verdict,
            "urls": urls,
            "age_days": _age_days(doc),
            "matches_finding": matched,
            "steps": len((doc.get("runs") or [{}])[-1].get("steps") or []),
            "wire": _wire_captured(doc),
        })
    # The class of the claim decides which oracle makes its effect observable, and that
    # question is not answerable from `rows` alone — it needs the artifacts and the folder.
    # Computed here, graded in `_verdict`, so an unimportable module can never wall a finding.
    cls = None
    try:
        if not class_gate:
            raise RuntimeError("class gate off for this caller")
        import class_proof  # noqa: PLC0415 - optional: the gate must survive without it
        # The finding's own name, not the directory's: a flat-tier finding's `where` is
        # the shared `findings/` folder, whose name classifies nothing.
        cls = class_proof.grade(text, artifacts, where, name or where.name)
    except Exception:  # noqa: BLE001
        cls = None
    rep = _verdict(text, rows, refutation, cls)
    rep["class_proof"] = cls or {}
    # Reported, never a verdict: evidence.py grades whether a request proved the claim.
    # Whether the claim names a victim is a different question, and conflating them would
    # turn a proven Critical into NOT-PROVEN over a missing heading.
    rep["victim"] = has_victim(text)
    return rep


def _verdict(text: str, rows: List[Dict], refutation: Dict | None = None,
             class_report: Dict | None = None) -> Dict:
    proving = [r for r in rows if r["verdict"] == "PASS" and r["matches_finding"]]
    if refutation:
        # Outranks everything below, including a PASS: a control that passed means
        # the mechanism in the write-up is not what the evidence shows.
        return {"status": "REFUTED",
                "reason": f"{refutation['verdict']} by its own controls — {refutation.get('why', '')}",
                "artifacts": rows, "refutation": refutation}
    claims_wire = bool(text and WIRE_CLAIM_RE.search(text))
    wire_backed = any(r.get("wire") for r in rows)

    if proving and claims_wire and not wire_backed:
        # The finding talks about redirects/session/cookies; the evidence is a
        # single request with no chain and no cookies recorded. That gap is where
        # "it returned 200" reports come from — the 200 belonged to /login.
        status, reason = "WIRE-UNPROVEN", (
            "the finding describes redirect/session/cookie behaviour, but the only evidence "
            "is a single request with no redirect chain and no Set-Cookie recorded")
    elif proving and class_report and class_report.get("checked") and not class_report.get("ok"):
        # A PASS says the request was fired and matched its `expect`. For some classes that
        # is not the effect: a reflected marker is not execution, a 500 on a quote is not a
        # database, a 200 from a fetcher is not an outbound request. The class names the
        # oracle, `class_proof` reads it off the artifacts, and the claim waits until it fires.
        status, reason = "CLASS-UNPROVEN", (
            f"a fired PoC passed, but a `{class_report['class']}` claim needs "
            f"{class_report['need']} and the artifacts do not show it: "
            f"{class_report['reason']}")
    elif proving:
        status, reason = "DEMONSTRATED", "a fired PoC passed for this finding's endpoint"
    elif not rows:
        status, reason = "NO-EVIDENCE", (
            "no .result.json artifact — nothing was fired, or it was fired outside "
            "poc_runtime and left no evidence")
    elif any(r["verdict"] == "PASS" for r in rows):
        status, reason = "MISMATCH", (
            "the only passing artifacts hit endpoints this finding never mentions")
    elif all(r["verdict"] == "WIRE-CAPTURE" for r in rows):
        # Wire captures only, no .result.json at all. The old message for this case
        # read "artifacts exist but none passed", and gate_line added "the PoC ran and
        # did not pass. Fix the spec or drop the finding" — both false here: nothing
        # ran through poc_runtime, so nothing failed. Measured on yukki-lk, where
        # poc_runtime physically cannot reach the product (it fires via bbcurl and the
        # edge 403s every CLI client), and the only possible evidence is a proxied
        # browser capture. The verdict stays non-passing on purpose: this tool cannot
        # grade a wire capture, and saying so is not the same as saying the claim failed.
        status, reason = "NOT-PROVEN", (
            "no .result.json artifact — only wire capture(s): "
            + ", ".join(Path(r["file"]).name for r in rows)
            + ". Nothing was fired through poc_runtime, so nothing failed; this tool "
              "cannot grade a wire capture")
    else:
        status, reason = "NOT-PROVEN", (
            "artifacts exist but none passed: "
            + ", ".join(sorted({r["verdict"] for r in rows})))
    return {"status": status, "reason": reason, "artifacts": rows}


def check(target: Path) -> Dict:
    """Verdict on whether `target` is backed by a fired, passing PoC."""
    artifacts = collect(target)
    text = ""
    if target.is_file() and not target.name.endswith(".result.json"):
        try:
            text = target.read_text(encoding="utf-8", errors="replace").lower()
        except Exception:  # noqa: BLE001
            text = ""
    where = target.parent if target.is_file() else target
    return _check(text, artifacts, where, _refutation(target), target.stem)


def check_blob(text: str, where: Path) -> Dict:
    """Same verdict for in-memory finding text (an engine candidate) whose artifacts
    live under directory `where`. An empty or unreadable directory is NO-EVIDENCE —
    absence of proof must never read as proof."""
    if not where.is_dir():
        return {"status": "NO-EVIDENCE",
                "reason": f"artifact directory {where} is missing — nothing was fired",
                "artifacts": []}
    # No class gate here. This grades an ENGINE CANDIDATE — a blob of url + param +
    # the hunter's one-line evidence — against a shared `evidence/` directory. There is
    # no per-finding folder to read an oracle out of, and classifying a blob that quotes
    # its own suspicion ("returns other users' PII") would downgrade on the wording of a
    # note rather than on evidence. A candidate becomes a finding in its own folder, and
    # the gate asks the class question there.
    return _check(text.lower(), collect(where), where, class_gate=False)


def _not_proven_advice(report: Dict) -> str:
    """NOT-PROVEN has two causes and they need opposite advice.

    A failed/inconclusive .result.json means the claim did not hold: fix the spec or
    drop it. Wire-capture-only means this tool never saw a PoC at all — telling the
    author to "drop the finding" there is advice against evidence the tool cannot read.
    """
    rows = report.get("artifacts") or []
    if rows and all(r.get("verdict") == "WIRE-CAPTURE" for r in rows):
        return ("Q1/Q6 not gradable by this tool: the only artifacts are wire captures, so "
                "no PoC ran and none failed. Do NOT read this as a refutation. Either land "
                "the proof in a poc_runtime spec (`python3 engine/poc_runtime.py <spec.json>`) "
                "so there is a .result.json, or — when poc_runtime cannot reach the target at "
                "all — say so in the finding and let the operator judge the capture directly.")
    return ("Q1/Q6 not backed: the PoC ran and did not pass. Fix the spec or drop "
            "the finding — do not report an unconfirmed bug.")


def gate_line(report: Dict) -> str:
    """One line for the 7-Question Gate's Q1/Q6."""
    return {
        "DEMONSTRATED": "Q1/Q6 backed by a fired PoC (.result.json = PASS).",
        "REFUTED": "Q1/Q6 overturned: `cbh refute` fired the controls and one of them passed, "
                   "so the exploit's PASS does not mean what the write-up says. Do not report "
                   "it as written — `cbh triage <finding> --demote` moves it to leads/ or "
                   "primitives/, and `/remember --result rejected` keeps the next session from "
                   "repeating the move.",
        "NO-EVIDENCE": "Q1/Q6 unanswerable: run `python3 engine/poc_runtime.py <spec.json>` "
                       "and attach the .result.json. A described PoC is not a fired one.",
        "MISMATCH": "Q1/Q6 not backed: the passing evidence is for a different endpoint. "
                    "Fire a spec against THIS finding's endpoint.",
        "NOT-PROVEN": _not_proven_advice(report),
        "WIRE-UNPROVEN": "Q6 not backed for a wire-level claim. Two ways to fix it, both real: "
                         "(a) re-fire as a multi-step `steps` spec so the chain, the final URL and "
                         "every Set-Cookie land in the artifact; or (b) capture the exchange in "
                         "the proxy (Caido — docs/caido.md — then save request+response next to the "
                         "finding as <finding>.caido.txt). A status code alone cannot show a "
                         "redirect or a dead session.",
        "CLASS-UNPROVEN": "Q1/Q6 backed for the REQUEST, not for the EFFECT: "
                          + (report.get("class_proof") or {}).get("reason", "")
                          + " Fire the oracle this class needs and save its artifact next to "
                            "the finding, or re-frame the claim as the primitive it is "
                            "(`cbh triage <finding> --demote`).",
    }.get(report["status"], "")


def main(argv: List[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: evidence.py <finding.md | dir | result.json>")
        return 2
    target = Path(args[0])
    if not target.exists():
        print(f"not found: {target}")
        return 2

    rep = check(target)
    print(f"evidence for {target}")
    for r in rep["artifacts"]:
        mark = "*" if r["verdict"] == "PASS" and r["matches_finding"] else " "
        age = f"{r['age_days']}d ago" if r["age_days"] is not None else "age unknown"
        chain = f", {r['steps']}-step chain" if r["steps"] else ""
        chain += "" if r.get("wire") else "  [no chain/cookies recorded]"
        link = "" if r["matches_finding"] else "  [endpoint not mentioned in the finding]"
        print(f" {mark} {r['verdict']:<12} {age}{chain}  {r['file']}{link}")
        for u in r["urls"][:4]:
            if u:
                print(f"       {u}")
    if not rep["artifacts"]:
        print("   (none)")
    print()
    print(f"{rep['status']}: {rep['reason']}")
    print(gate_line(rep))
    if rep.get("class_proof"):
        try:
            import class_proof  # noqa: PLC0415
            print(class_proof.line(rep["class_proof"]))
        except Exception:  # noqa: BLE001
            pass
    vl = victim_line(rep)
    if vl:
        print(vl)
    return {"DEMONSTRATED": 0, "MISMATCH": 1, "NOT-PROVEN": 1,
            "WIRE-UNPROVEN": 1, "CLASS-UNPROVEN": 1,
            "NO-EVIDENCE": 2, "REFUTED": 2}[rep["status"]]


if __name__ == "__main__":
    sys.exit(main())
