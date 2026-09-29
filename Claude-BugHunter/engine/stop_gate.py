#!/usr/bin/env python3
"""
stop_gate.py — decide whether a hunt is allowed to end.

The failure this exists for: the session stops while the target is nowhere near
exhausted. Not because the operator asked, and not because the surface was
covered — the agent simply ran out of momentum, wrote a summary, and handed back
a target with untried vectors sitting in its own ledger.

Prose does not fix that. This workspace measured it: a rule the model reads is a
rule it can decide it has already satisfied. So the stop itself is gated, the way
the scope check gates a request.

**The bar is a reportable finding: severity >= medium, with a fired PoC behind it.**
A `.result.json` that PASSes (`engine/evidence.py` says DEMONSTRATED) plus a
severity the finding text actually states. Both halves matter — a Medium nobody
demonstrated is a draft, and a demonstrated Low is not what the operator asked to
be found.

What this must never become: pressure to inflate. A Low written up as a Medium
satisfies the gate and destroys the validity ratio the gate exists to protect, so
the block message says so every time, and the honest exit is always open:

    exhaustion, proven — every vector class marked dead in the ledger, with
    requests actually fired (`vectors.py mark ... dead` enforces that), and the
    rejected attempts logged. Then stopping is correct and the gate steps aside.

There is also a hard cap on how many times one session can be pushed: a gate that
cannot be satisfied and cannot be escaped is a loop, and a loop burns the
operator's money instead of finding bugs.

**Continuous mode (operator directive, 2026-09-21)** inverts the finding door: a
demonstrated Medium+ is *banked* in `Targets/<name>/findings/` and the sweep keeps
going, so the hunt ends only when the operator ends it. See `continuous_config()`
for the three switches and `continuous_message()` for what the refusal says. The
severity bar itself does not move — a banked Low is still a Low.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

MAX_BLOCKS = 6           # per session, before the gate stands down
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
BAR = "medium"

# Budgets: the honest third exit.
#
# Until now a hunt could end two ways — a demonstrated >= medium finding, or proven
# exhaustion of the ledger. Both are outcomes about the *target*. Neither covers the
# real third case: the session has spent the effort the operator budgeted and has not
# got there. Without that exit the gate's only options are to keep pushing a session
# that is no longer learning anything, or to be satisfied by a padded severity — and
# the second is the failure the whole gate exists to prevent.
#
# So a budget can end a hunt, but it must be spent, not merely declared: the request
# count comes from audit.jsonl, the clock from when analysis mode armed, and the
# "no new information" window from the response corpus — identical bodies mean the
# requests were not probes. Numbers live in Targets/<name>/profile.json, never in prose.
BUDGET_KEYS = ("max_requests", "max_minutes", "no_new_information_window")
DEFAULT_NO_NEW_INFO_WINDOW = 0     # 0 = off; opt-in per engagement

# Continuous mode: the operator ends the hunt, nothing else.
#
# The default gate treats a demonstrated >= medium finding as the finish line — the
# hunt earned its exit, so it may stop and report. That is the right default for a
# session the operator is watching, and the wrong one for the way this workspace is
# actually run: the operator wants the sweep to keep going, bank each finding in
# `Targets/<name>/findings/` as it is proven, and roll straight on to the next
# vector, the next host, the next pass. Stopping to report is a context switch the
# operator will make themselves.
#
# So in continuous mode a finding is BANKED, not spent: `assess()` never opens the
# finding door, and never opens the exhaustion door either — an exhausted ledger is
# a signal to rotate hosts, not to hand the target back. Two things still end it:
# the operator (`--continuous off`, or simply ending the session), and an
# explicitly configured budget in `profile.json`, because that number is the
# operator's own instruction written down in advance.
#
# Switched on, highest precedence first:
#   CBH_HUNT_CONTINUOUS=on|off        one session / one shell
#   Targets/<name>/profile.json       "continuous_hunt": true    one engagement
#   hunt-memory/continuous.json       {"enabled": true}          this workspace
#                                     (python3 engine/stop_gate.py --continuous on)
ENV_CONTINUOUS = "CBH_HUNT_CONTINUOUS"
CONTINUOUS_STATE = "continuous.json"
# Still bounded, just far away: a gate that can never stand down would trap a
# session whose operator has walked away, and burn the budget doing it.
CONTINUOUS_MAX_BLOCKS = 500


def _truthy(value) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "on", "true", "yes", "y"):
        return True
    if text in ("0", "off", "false", "no", "n", ""):
        return False
    return None


def _profile_of(project_dir: Optional[Path]) -> Dict:
    if project_dir is None:
        return {}
    try:
        from pacing import Engagement  # type: ignore
        return Engagement(project_dir).profile or {}
    except Exception:  # noqa: BLE001
        return {}


def continuous_state_path(memdir: Optional[Path] = None) -> Path:
    try:
        from memory import resolve_dir  # type: ignore
        base = memdir or resolve_dir()
    except Exception:  # noqa: BLE001
        base = memdir or (Path(__file__).resolve().parent.parent.parent / "hunt-memory")
    base.mkdir(parents=True, exist_ok=True)
    return base / CONTINUOUS_STATE


def continuous_config(project_dir: Optional[Path] = None,
                      memdir: Optional[Path] = None) -> Dict:
    """Is this hunt in continuous mode, and who said so?"""
    env = _truthy(os.environ.get(ENV_CONTINUOUS))
    if env is not None:
        return {"on": env, "source": f"env {ENV_CONTINUOUS}"}
    prof = _truthy(_profile_of(project_dir).get("continuous_hunt"))
    if prof is not None:
        name = project_dir.name if project_dir else "engagement"
        return {"on": prof, "source": f"{name}/profile.json"}
    path = continuous_state_path(memdir)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        state = _truthy(doc.get("enabled"))
        if state is not None:
            return {"on": state, "source": str(path), "note": doc.get("note", "")}
    except Exception:  # noqa: BLE001
        pass
    return {"on": False, "source": "default"}


def set_continuous(enabled: bool, note: str = "", memdir: Optional[Path] = None) -> Dict:
    from datetime import datetime, timezone
    path = continuous_state_path(memdir)
    doc = {"enabled": bool(enabled), "note": note,
           "changed": datetime.now(timezone.utc).isoformat()}
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return doc


def max_blocks(project_dir: Optional[Path] = None) -> int:
    """How many times one session may be pushed before the gate stands down."""
    raw = _profile_of(project_dir).get("max_stop_blocks")
    try:
        if raw not in (None, "", 0):
            return max(1, int(raw))
    except (TypeError, ValueError):
        pass
    return CONTINUOUS_MAX_BLOCKS if continuous_config(project_dir)["on"] else MAX_BLOCKS

# "Severity: High", "Критичность: В", "CVSS 3.1 ... = **7.5**", "[Medium]"
SEV_WORD_RE = re.compile(
    r"(?:severity|критичн\w*|risk|impact)\s*[:=]?\s*"
    r"\*{0,2}(critical|high|medium|low|info\w*|критическ\w+|высок\w+|средн\w+|низк\w+|"
    r"[авсн])\b", re.I)
# "CVSS 3.1: AV:N/... = **5.3**" — the first decimal on that line is the spec
# VERSION, not the score. Reading 3.1 as the score silently downgrades every High
# in this workspace's own findings to Low, which would let the stop gate wave a
# hunt through on a finding that does not exist.
CVSS_LINE_RE = re.compile(r"^.*cvss.*$", re.I | re.M)
CVSS_VERSION_RE = re.compile(r"cvss\s*:?\s*v?(\d\.\d)", re.I)
CVSS_NUM_RE = re.compile(r"(\d{1,2}\.\d)")

RU_SEV = {"критическ": "critical", "высок": "high", "средн": "medium", "низк": "low"}
# RTEAM/Bereke letter bands: А critical, В high, С medium, Н low
LETTER_SEV = {"а": "critical", "в": "high", "с": "medium", "н": "low"}


def _sev_from_word(word: str) -> Optional[str]:
    w = word.lower()
    for prefix, sev in RU_SEV.items():
        if w.startswith(prefix):
            return sev
    if w in LETTER_SEV:
        return LETTER_SEV[w]
    if w.startswith("info"):
        return "info"
    if w in SEVERITY_ORDER:
        return w
    return None


def _sev_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def severity_of(text: str) -> Optional[str]:
    """Highest severity the finding text claims, or None if it claims none."""
    best = None
    for m in SEV_WORD_RE.finditer(text):
        sev = _sev_from_word(m.group(1))
        if sev and (best is None or SEVERITY_ORDER.index(sev) > SEVERITY_ORDER.index(best)):
            best = sev
    for line in CVSS_LINE_RE.findall(text):
        nums = CVSS_NUM_RE.findall(line)
        ver = CVSS_VERSION_RE.search(line)
        if ver and nums and nums[0] == ver.group(1):
            nums = nums[1:]          # drop the spec version, keep the score
        if not nums:
            continue
        try:
            sev = _sev_from_cvss(float(nums[-1]))
        except ValueError:
            continue
        if best is None or SEVERITY_ORDER.index(sev) > SEVERITY_ORDER.index(best):
            best = sev
    return best


def meets_bar(sev: Optional[str]) -> bool:
    return bool(sev) and SEVERITY_ORDER.index(sev) >= SEVERITY_ORDER.index(BAR)


# A CVSS vector ends in "...I:N/A:N", which contains the substring "n/a". Matching
# rejection words by substring therefore marked every properly scored finding as
# rejected, and the stop gate silently ignored it — observed 2026-09-14 on a Medium
# with a PASSing PoC. Strip vectors first, then match on word boundaries.
CVSS_VECTOR_RE = re.compile(r"\b(?:cvss:?[\d.]*/)?av:[nalp](?:/[a-z]{1,2}:[a-z])+", re.I)
REJECT_RE = re.compile(
    r"(?:\brejected\b|\bnot a bug\b|\bn/a\b|\bfalse positive\b|\binformative only\b"
    r"|закрыт|отклон)", re.I)


def _rejected(text: str) -> bool:
    head = CVSS_VECTOR_RE.sub(" ", text[:600]).lower()
    return bool(REJECT_RE.search(head))


def qualifying_findings(project_dir: Path, since_ts: Optional[float] = None) -> List[Dict]:
    """Findings that would actually clear the bar: >= medium AND demonstrated.

    `since_ts` scopes it to the current hunt. Without it a target with one good
    finding from last month would let every future session stop on arrival.
    """
    out: List[Dict] = []
    fdir = project_dir / "findings"
    if not fdir.is_dir():
        return out
    try:
        from evidence import check  # type: ignore
    except Exception:  # noqa: BLE001
        check = None  # type: ignore
    for f in sorted(fdir.glob("*.md")):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if _rejected(text):
            continue
        sev = severity_of(text)
        if not meets_bar(sev):
            continue
        status = "UNCHECKED"
        if check:
            try:
                status = check(f).get("status", "UNCHECKED")
            except Exception:  # noqa: BLE001
                status = "UNCHECKED"
        try:
            mtime = f.stat().st_mtime
        except OSError:
            mtime = 0.0
        this_hunt = since_ts is None or mtime >= since_ts
        out.append({"file": str(f), "severity": sev, "evidence": status, "mtime": mtime,
                    "this_hunt": this_hunt,
                    "qualifies": status == "DEMONSTRATED" and this_hunt})
    return out


def _recent_hosts(engagement: str, limit: int = 6) -> List[str]:
    """Hosts this engagement actually touched, newest first.

    Vector ledgers are keyed by host, not by engagement folder, so asking for
    `next_vectors("kcell")` finds nothing while `web.kcell.kz` has a full ledger.
    """
    try:
        from urllib.parse import urlsplit
        from responses import _tail_jsonl, _memdir  # type: ignore
        rows = _tail_jsonl(_memdir() / "audit.jsonl", 100000)
    except Exception:  # noqa: BLE001
        return []
    seen: List[str] = []
    for r in reversed(rows):
        if engagement and r.get("engagement") != engagement:
            continue
        for u in (r.get("urls") or []):
            h = urlsplit(u).hostname or ""
            if h and h not in seen:
                seen.append(h)
    # Hosts with a ledger come first regardless of how recently they were touched:
    # the ledger is the thing being asked for, and this session's last few requests
    # are often the least interesting host on the target.
    try:
        from vectors import _path  # type: ignore
        with_ledger = [h for h in seen if _path(h).exists()]
        seen = with_ledger + [h for h in seen if h not in with_ledger]
    except Exception:  # noqa: BLE001
        pass
    return seen[:limit]


def untried(project_dir: Path, limit: int = 5) -> List[Dict]:
    try:
        from vectors import next_vectors  # type: ignore
    except Exception:  # noqa: BLE001
        return []
    out: List[Dict] = []
    for key in [project_dir.name, *_recent_hosts(project_dir.name)]:
        try:
            got = next_vectors(key, limit) or []
        except Exception:  # noqa: BLE001
            continue
        for v in got:
            v = dict(v)
            v.setdefault("host", key)
            out.append(v)
        if len(out) >= limit:
            break
    return out[:limit]


def next_hosts(project_dir: Path, limit: int = 6) -> List[str]:
    """Hosts in this engagement that still have somewhere to go.

    Continuous mode never answers an exhausted ledger with "stop"; it answers it
    with the next host. A host qualifies when it has no ledger yet (nothing tried)
    or its ledger still holds untried/active vectors.
    """
    hdir = project_dir / "hosts"
    if not hdir.is_dir():
        return []
    try:
        from vectors import _path, load  # type: ignore
    except Exception:  # noqa: BLE001
        return [f.stem for f in sorted(hdir.glob("*.md"))][:limit]
    out: List[str] = []
    for f in sorted(hdir.glob("*.md")):
        host = f.stem
        try:
            if not _path(host).exists():
                out.append(host)
                continue
            vectors = load(host).get("vectors") or []
        except Exception:  # noqa: BLE001
            continue
        if any(v.get("status") in ("untried", "active") for v in vectors):
            out.append(host)
        if len(out) >= limit:
            break
    return out[:limit]


def exhaustion(project_dir: Path) -> Dict:
    """Return a positive exhaustion verdict only when a real ledger exists.

    Empty ledgers are not evidence.  Every vector must be terminal and a `dead`
    vector must carry either fired requests or an explicit structural reason.
    """
    try:
        from vectors import load  # type: ignore
    except Exception:  # noqa: BLE001
        return {"proven": False, "reason": "vector ledger unavailable"}
    ledgers = []
    for key in [project_dir.name, *_recent_hosts(project_dir.name)]:
        try:
            data = load(key)
        except Exception:  # noqa: BLE001
            continue
        vectors = data.get("vectors") or []
        if vectors:
            ledgers.append((key, vectors))
    if not ledgers:
        return {"proven": False, "reason": "no populated vector ledger"}
    open_items = []
    unsupported = []
    total = 0
    for key, vectors in ledgers:
        total += len(vectors)
        for vec in vectors:
            if vec.get("status") in ("untried", "active"):
                open_items.append(f"{key}:{vec.get('id')}")
            if vec.get("status") == "dead" and not vec.get("requests_fired") and not vec.get("notes"):
                unsupported.append(f"{key}:{vec.get('id')}")
    proven = not open_items and not unsupported
    return {"proven": proven, "vectors": total, "open": open_items[:10],
            "unsupported": unsupported[:10],
            "reason": (f"{total} vectors have terminal, evidenced outcomes" if proven
                       else f"{len(open_items)} open and {len(unsupported)} unsupported dead vectors")}


def _engagement_budgets(project_dir: Path) -> Dict:
    """Read the budget numbers from the engagement's profile. Absent = no budget."""
    try:
        from pacing import Engagement  # type: ignore
        profile = Engagement(project_dir).profile
    except Exception:  # noqa: BLE001
        return {}
    out = {}
    for key in BUDGET_KEYS:
        raw = profile.get(key)
        if raw in (None, "", 0):
            continue
        try:
            out[key] = float(raw)
        except (TypeError, ValueError):
            continue
    return out


def _hunt_requests(engagement: str, since_ts: Optional[float]) -> List[Dict]:
    """Audit rows this hunt actually produced. The budget is spent, not declared."""
    try:
        from datetime import datetime, timezone
        from responses import _memdir, _tail_jsonl  # type: ignore
        rows = _tail_jsonl(_memdir() / "audit.jsonl", 100000)
    except Exception:  # noqa: BLE001
        return []
    cutoff = None
    if since_ts:
        cutoff = datetime.fromtimestamp(since_ts, timezone.utc).isoformat()
    out = []
    for r in rows:
        if engagement and r.get("engagement") != engagement:
            continue
        if cutoff and (r.get("timestamp") or "") < cutoff:
            continue
        out.append(r)
    return out


def budget(project_dir: Path, since_ts: Optional[float] = None) -> Dict:
    """Has this hunt spent what the engagement budgeted for it?

    Returns {"spent": bool, "exit_condition": <key>, ...}. A budget that is not
    configured can never be spent, so the default remains "keep hunting".
    """
    import time as _time
    limits = _engagement_budgets(project_dir)
    rows = _hunt_requests(project_dir.name, since_ts)
    spent_minutes = round((_time.time() - since_ts) / 60.0, 1) if since_ts else None

    usage = {"requests": len(rows), "minutes": spent_minutes, "limits": limits,
             "spent": False, "exit_condition": None, "detail": ""}

    if "max_requests" in limits and len(rows) >= limits["max_requests"]:
        usage.update(spent=True, exit_condition="max_requests",
                     detail=f"{len(rows)} requests fired, budget {int(limits['max_requests'])}")
        return usage
    if "max_minutes" in limits and spent_minutes is not None \
            and spent_minutes >= limits["max_minutes"]:
        usage.update(spent=True, exit_condition="max_minutes",
                     detail=f"{spent_minutes} minutes elapsed, budget {int(limits['max_minutes'])}")
        return usage

    window = int(limits.get("no_new_information_window", DEFAULT_NO_NEW_INFO_WINDOW))
    if window and len(rows) >= window:
        recent = [r for r in rows[-window:] if r.get("body_sha256")]
        if len(recent) >= window:
            try:
                from responses import identical_run  # type: ignore
                run = identical_run(recent)
            except Exception:  # noqa: BLE001
                run = None
            # One distinct body across the whole window means the last `window`
            # requests were the same answer repeated. That is grinding, and more of
            # it will not produce a finding.
            if run and run["distinct"] <= 1:
                usage.update(spent=True, exit_condition="no_new_information_window",
                             detail=f"last {window} requests returned {run['distinct']} "
                                    f"distinct body — no new information")
                return usage
            usage["distinct_in_window"] = run["distinct"] if run else None
    return usage


def assess(project_dir: Optional[Path], since_ts: Optional[float] = None) -> Dict:
    """Is stopping earned? Returns the verdict plus what to do instead."""
    if project_dir is None:
        return {"allow": True, "reason": "not inside an engagement"}
    found = qualifying_findings(project_dir, since_ts)
    proven = [f for f in found if f["qualifies"]]
    claimed = [f for f in found if f["this_hunt"] and not f["qualifies"]]
    older = [f for f in found if not f["this_hunt"]]
    exhausted = exhaustion(project_dir)
    spend = budget(project_dir, since_ts)

    cont = continuous_config(project_dir)

    if proven:
        exit_condition, reason = "finding", \
            "a demonstrated >= medium finding was produced in this hunt"
    elif exhausted["proven"]:
        exit_condition, reason = "exhaustion", exhausted["reason"]
    elif spend["spent"]:
        exit_condition = spend["exit_condition"]
        reason = (f"the engagement's {spend['exit_condition']} budget is spent "
                  f"({spend['detail']}) with no demonstrated >= medium finding")
    else:
        exit_condition, reason = None, ("this hunt has produced no demonstrated >= medium "
                                        "finding and coverage remains open")

    allow = bool(proven) or exhausted["proven"] or spend["spent"]

    if cont["on"]:
        # A finding is banked on disk and the sweep continues; an exhausted ledger
        # means "next host", not "done". Only a configured budget — the operator's
        # own number, written down in advance — still ends it.
        allow = bool(spend["spent"])
        if spend["spent"]:
            exit_condition = spend["exit_condition"]
            reason = (f"continuous mode, but the engagement's {spend['exit_condition']} "
                      f"budget is spent ({spend['detail']})")
        else:
            exit_condition = None
            banked = f"{len(proven)} finding(s) banked this hunt; " if proven else ""
            reason = (f"continuous mode ({cont['source']}): {banked}"
                      "stopping is the operator's call, not the gate's")

    return {
        "allow": allow,
        "continuous": cont,
        "engagement": project_dir.name,
        "proven": proven,
        "claimed_but_unproven": claimed,
        "older_findings": older,
        "scoped_to_this_hunt": since_ts is not None,
        "untried": untried(project_dir),
        "next_hosts": next_hosts(project_dir),
        "exhaustion": exhausted,
        "budget": spend,
        # Which door the hunt left by. Recorded so "why did this session stop?" is
        # answerable later without re-deriving it from the transcript.
        "exit_condition": exit_condition,
        "reason": reason,
    }


def continuous_message(a: Dict) -> str:
    """The refusal used in continuous mode.

    Tone matters here. The default gate says "you have not earned an exit yet",
    which is wrong when the hunt has just proven a Medium: the work was good, it is
    banked, and the only instruction is *keep going*. A message that reads as
    failure after a real finding teaches the wrong lesson and invites padding the
    next one.
    """
    eng = a["engagement"]
    proven = a.get("proven") or []
    lines = [
        f"CONTINUOUS HUNT — {eng}: stopping is disabled. The operator ends this hunt, "
        f"nothing else ({(a.get('continuous') or {}).get('source', '?')}).",
        "",
        "Do not summarise, do not hand the target back, do not ask whether to carry on. "
        "Bank what you have and take the next vector.",
    ]

    if proven:
        lines += ["", f"BANKED THIS HUNT — {len(proven)} finding(s) at or above {BAR}. "
                      f"They are already on disk; a finding is not a reason to stop:"]
        for f in proven[:5]:
            lines.append(f"  - {Path(f['file']).name}  [{f['severity']}]  {f['evidence']}")
        lines += [
            "  Close each one out, then move on — in this order, without stopping:",
            f"    1. the file stays in Targets/{eng}/findings/ (keep the .result.json beside it)",
            "    2. /remember --result confirmed   (feeds analytics and the next session's pickup)",
            "    3. python3 engine/vectors.py mark <host> <vector-id> confirmed",
            "    4. /chain — a confirmed finding is the best lead on this target right now",
        ]

    if a.get("claimed_but_unproven"):
        lines += ["", "Unproven claims still open — finish the PoC before writing anything else:"]
        for f in a["claimed_but_unproven"][:3]:
            lines.append(f"  - {Path(f['file']).name}  [{f['severity']}]  evidence: {f['evidence']}")
        lines.append("  Spec it, fire engine/poc_runtime.py, then `cbh evidence <finding.md>` "
                     "must say DEMONSTRATED.")

    if a["untried"]:
        lines += ["", "Next, from this target's own ledger:"]
        for v in a["untried"][:5]:
            line = f"  - [{v.get('class')}] {v.get('endpoint')}"
            if v.get("skill"):
                line += f"   (skill: {v['skill']})"
            lines.append(line)
            if v.get("next_mutation"):
                lines.append(f"      next move: {v['next_mutation']}")
    else:
        lines += ["", "No untried vectors on the hosts touched so far — so rotate the HOST, "
                      "not the session."]

    if (a.get("exhaustion") or {}).get("proven"):
        lines += ["", "This ledger is exhausted. In continuous mode that means the next host, "
                      "not the end of the hunt."]

    hosts = a.get("next_hosts") or []
    if hosts:
        lines += ["", "Hosts in scope with room left:"] + [f"  - {h}" for h in hosts[:6]]
        lines.append("  python3 engine/vectors.py seed <host> --endpoints '<paths>'  "
                     "then `next <host>`")
    else:
        lines += ["", "Every known host has a closed ledger — widen the surface instead of "
                      "stopping:",
                  "  /recon <target>      new subdomains, new routes, new parameters",
                  "  /cve                 what landed on these versions since the last pass",
                  "  cbh recon-diff       what changed since the last snapshot"]

    lines += [
        "",
        "Rotation ladder, in order — 'the host is hardened' is never the answer:",
        "  1. python3 engine/vectors.py rotate <class>   (method swap, /v2->/v1, auth strip,",
        "     content-type swap, param pollution, path normalization, X-Original-URL, mobile)",
        "  2. python3 engine/vectors.py next <host>",
        "  3. python3 engine/vectors.py revisit <host>   (old findings, new methods)",
        "  4. /chain",
        "  5. next host in scope, then a fresh recon pass",
        "",
        "Unchanged by continuous mode, because they are what makes the output worth having:",
        "  * severity is what the evidence shows — never inflate a Low to make a pass look good;",
        "  * a claim with no fired request stays an open thread, not a finding;",
        "  * scope and pacing still gate every request (they are in code, not in this message).",
        "",
        "To end it: the operator says so, or `python3 engine/stop_gate.py --continuous off`.",
    ]
    return "\n".join(lines)


def block_message(a: Dict) -> str:
    if (a.get("continuous") or {}).get("on"):
        return continuous_message(a)
    lines = [
        f"STOP REFUSED — {a['engagement']} has no reportable finding yet "
        f"(bar: severity >= {BAR}, backed by a fired PoC).",
        "",
        "Keep hunting. Do not summarise, do not hand the target back, do not close hosts.",
    ]
    if a["claimed_but_unproven"]:
        lines += ["", "Closest to done — these claim the severity but have no PASSing artifact:"]
        for f in a["claimed_but_unproven"][:3]:
            lines.append(f"  - {Path(f['file']).name}  [{f['severity']}]  evidence: {f['evidence']}")
        lines.append("  Finish one: write the spec, fire it with engine/poc_runtime.py, "
                     "then `cbh evidence <finding.md>` must say DEMONSTRATED.")
    if a.get("older_findings") and a.get("scoped_to_this_hunt"):
        lines += ["",
                  f"({len(a['older_findings'])} qualifying finding(s) exist on this target from "
                  "earlier sessions. They are not what this hunt owes — today's session has "
                  "produced nothing reportable yet.)"]
    spend = a.get("budget") or {}
    if spend.get("limits"):
        parts = []
        if "max_requests" in spend["limits"]:
            parts.append(f"{spend.get('requests', 0)}/{int(spend['limits']['max_requests'])} requests")
        if "max_minutes" in spend["limits"] and spend.get("minutes") is not None:
            parts.append(f"{spend['minutes']}/{int(spend['limits']['max_minutes'])} minutes")
        if parts:
            lines += ["", f"Budget for this hunt: {' · '.join(parts)} spent. "
                          "When it runs out, stopping is allowed and honest — "
                          "inflating a finding to get there early is not."]

    if a["untried"]:
        lines += ["", "Untried vectors in this target's own ledger:"]
        for v in a["untried"][:5]:
            line = f"  - [{v.get('class')}] {v.get('endpoint')}"
            if v.get("skill"):
                line += f"   (skill: {v['skill']})"
            lines.append(line)
            if v.get("next_mutation"):
                lines.append(f"      next move: {v['next_mutation']}")
    else:
        lines += ["", "No vector ledger yet — build one, then `next` always has an answer:",
                  "  python3 engine/vectors.py seed <host> --endpoints '<paths you already found>'"]
    lines += [
        "",
        "Rotation ladder, in order — never 'the host is hardened':",
        "  1. python3 engine/vectors.py rotate <class>   (method swap, /v2->/v1, auth strip,",
        "     content-type swap, param pollution, path normalization, X-Original-URL, mobile surface)",
        "  2. python3 engine/vectors.py next <host>      (impact-ranked, untouched)",
        "  3. python3 engine/vectors.py revisit <host>   (old findings, new methods)",
        "  4. /chain                                     (what does a small finding unlock)",
        "  5. only then: another host in scope",
        "",
        "Two things this gate will NOT accept, because both cost more than stopping early:",
        "  * inflating a Low into a Medium to get past it — the validity ratio is the asset",
        "    being protected here, and a padded report burns it;",
        "  * inventing impact a fired request does not show.",
        "",
        "Honest exit, always open: prove exhaustion. Every vector class marked dead with",
        "requests actually fired (`python3 engine/vectors.py mark <target> <id> dead` refuses",
        "otherwise), rejected attempts logged with /remember --result rejected. Then say so",
        "plainly and stop — that is a real answer about the target, not a lack of momentum.",
    ]
    return "\n".join(lines)


def _state_path(memdir: Optional[Path] = None) -> Path:
    try:
        from memory import resolve_dir  # type: ignore
        base = memdir or resolve_dir()
    except Exception:  # noqa: BLE001
        base = memdir or (Path(__file__).resolve().parent.parent.parent / "hunt-memory")
    d = base / "pacing"
    d.mkdir(parents=True, exist_ok=True)
    return d / "stop_gate.json"


def blocks_so_far(session_id: str, memdir: Optional[Path] = None) -> int:
    try:
        return int(json.loads(_state_path(memdir).read_text()).get(session_id, 0))
    except Exception:  # noqa: BLE001
        return 0


def record_block(session_id: str, memdir: Optional[Path] = None) -> int:
    p = _state_path(memdir)
    try:
        state = json.loads(p.read_text())
    except Exception:  # noqa: BLE001
        state = {}
    state[session_id] = int(state.get(session_id, 0)) + 1
    try:
        p.write_text(json.dumps(state))
    except Exception:  # noqa: BLE001
        pass
    return state[session_id]


if __name__ == "__main__":
    import argparse
    from pacing import find_project_dir  # type: ignore
    ap = argparse.ArgumentParser(description="is this hunt allowed to stop?")
    ap.add_argument("--project", default="", help="engagement dir (default: resolve from cwd)")
    ap.add_argument("--continuous", choices=("on", "off", "status"), default=None,
                    help="keep hunting until the operator stops it: findings are banked "
                         "in findings/ and the sweep continues")
    ap.add_argument("--note", default="", help="why, recorded with --continuous on|off")
    a = ap.parse_args()
    pd = Path(a.project) if a.project else find_project_dir()
    if a.continuous:
        if a.continuous == "status":
            cfg = continuous_config(pd)
            print(json.dumps({**cfg, "max_blocks": max_blocks(pd),
                              "state_file": str(continuous_state_path())}, indent=2))
            sys.exit(0)
        doc = set_continuous(a.continuous == "on", a.note)
        state = "ON — hunts run until you stop them" if doc["enabled"] else "OFF — default gate"
        print(f"continuous mode: {state}")
        print(f"  state file: {continuous_state_path()}")
        cfg = continuous_config(pd)
        if cfg["on"] != doc["enabled"]:
            print(f"  NOTE: {cfg['source']} overrides this file (currently "
                  f"{'on' if cfg['on'] else 'off'})")
        sys.exit(0)
    verdict = assess(pd)
    print(json.dumps({k: v for k, v in verdict.items() if k != "untried"}, indent=2,
                     ensure_ascii=False))
    if not verdict["allow"]:
        print()
        print(block_message(verdict))
    sys.exit(0 if verdict["allow"] else 1)
