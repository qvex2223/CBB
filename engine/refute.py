#!/usr/bin/env python3
"""
refute.py — try to KILL a finding before a triager does.

Everything else in this workspace is built to confirm: `poc_runtime` fires the
exploit and asks "did it work", `evidence.py` asks "is there a PASS behind this
claim", `triage` asks the seven questions. All of those reward a yes, and the model
that wrote the finding is the one answering them. The hunters who measured this
(rez0 + xssdoctor, July 2026) only moved their false-positive rate — 80% down to
60% — when they ran a separate pass whose reward was *disproving* the finding.

So this module fires the controls instead of the exploit. Each control is a request
whose PASS means the finding is wrong, and none of them is a judgement call:

  * **credentials-removed** — the same request with the session stripped. A PASS
    means the result never depended on being authenticated, so an authorization
    claim is mis-framed (the resource may well be a finding, as unauthenticated
    exposure, but not the one that was written).
  * **control-value** — the same request with the attack value swapped for the
    tester's own, judged against the ORIGINAL `expect`. A PASS means the response
    does not react to the input at all: the oracle is a stub and the finding is
    dead. (Not substituting inside `expect` is the whole trick — substitute there
    and the control degenerates into "does my own object return my own data".)
  * **exploit-removed** — multi-step chains only: run login and verify with the
    exploit step deleted. A PASS on verify means the state the finding claims to
    have caused was already there.
  * **answer-never-moved** — no request at all: the response corpus already knows
    whether the decisive field ever changed for this path. A constant one across
    enough captures means the same thing as a control-value PASS, for free.

The two value-based controls need the spec to say what the attack value is, because
guessing which token in a URL is the payload is exactly the kind of inference that
produces a confident wrong answer:

    "refute": {"attack": "124", "control": "123"}

Without it those controls are reported SKIPPED, with the line to add. Nothing is
silently assumed.

Verdicts: KILLED · MIS-FRAMED · SURVIVED · INCOMPLETE. A KILLED or MIS-FRAMED
result is written to `<finding>.refute.json`, which `engine/evidence.py` reads, so
`cbh triage` and `/validate` see it without being told. The finding itself is never
deleted: `cbh triage <finding> --demote` moves it down the funnel to `leads/` or
`primitives/`, because the observation was usually real even when the claim was not.

Every control goes out through `poc_runtime`, so scope, pacing, mandatory headers,
the audit log and the response corpus all apply exactly as they do to the exploit.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional

ENGINE = Path(__file__).resolve().parent
sys.path.insert(0, str(ENGINE))

# Headers that carry identity. Stripped by the credentials-removed control; the
# program's own mandatory headers are NOT in here and are never touched.
AUTH_HEADERS = {"cookie", "authorization", "x-api-key", "x-auth-token", "x-session",
                "x-csrf-token", "x-xsrf-token", "x-access-token", "api-key",
                "authentication", "proxy-authorization", "x-amz-security-token"}

# Step names that are setup or read-back rather than the attack itself.
SETUP_NAMES = ("login", "auth", "signin", "sign-in", "session", "setup", "own", "control")
VERIFY_NAMES = ("verify", "readback", "read-back", "confirm", "check")

KILLED, MISFRAMED, SURVIVED, INCOMPLETE = "KILLED", "MIS-FRAMED", "SURVIVED", "INCOMPLETE"


# --------------------------------------------------------------------------- inputs
def find_spec(target: Path) -> Optional[Path]:
    """The exploit spec behind a finding: its sibling, or whatever its artifact names.

    Every candidate is confined to the target's OWN folder. Measured 2026-11-02: two lanes
    each had a spec named `poc.poc.json`, resolution reached the other finding's copy, and
    `cbh refute` fired THAT chain's controls — including its `DELETE` leg — against objects
    the calling lane had never heard of, then overwrote its `refutations/` directory. A
    refutation that can fire another finding's requests is worse than no refutation: it
    spends a live programme's budget, mutates someone else's evidence, and both verdicts
    become unattributable. A spec outside the folder is refused rather than guessed at.
    """
    target = Path(target)
    if target.is_dir():
        # A folder-per-finding target: its own spec, never a sibling finding's.
        here = sorted(q for q in target.glob("*.poc.json") if q.is_file())
        return here[0] if len(here) == 1 else None
    if target.name.endswith(".poc.json"):
        return target
    stem = target.name[:-len(".result.json")] if target.name.endswith(".result.json") else target.stem
    for cand in (target.with_name(stem + ".poc.json"), target.with_name(stem + ".json")):
        if cand.is_file() and cand.suffix == ".json" and not cand.name.endswith(".result.json"):
            return cand
    artifact = target.with_name(stem + ".result.json")
    if artifact.is_file():
        try:
            named = json.loads(artifact.read_text(encoding="utf-8")).get("spec_file")
        except (OSError, ValueError):
            named = None
        if named:
            cand = Path(named)
            if cand.is_file() and cand.resolve().parent == target.resolve().parent:
                return cand
    # Last resort inside the finding's own folder only — a uniquely named spec beside it.
    here = sorted(q for q in target.parent.glob("*.poc.json") if q.is_file())
    return here[0] if len(here) == 1 else None


def project_of(path: Path) -> Optional[Path]:
    for parent in path.resolve().parents:
        if parent.parent.name == "Targets":
            return parent
        if (parent / "profile.json").is_file() and any(a.name == "Targets" for a in parent.parents):
            return parent
    return None


# --------------------------------------------------------------------------- controls
def _strip_auth(headers: Optional[Dict]) -> Dict:
    return {k: v for k, v in (headers or {}).items() if k.lower() not in AUTH_HEADERS}


def _swap(value, attack: str, control: str):
    if isinstance(value, str):
        return value.replace(attack, control)
    if isinstance(value, dict):
        return {k: _swap(v, attack, control) for k, v in value.items()}
    if isinstance(value, list):
        return [_swap(v, attack, control) for v in value]
    return value


def _exploit_step_index(steps: List[Dict]) -> Optional[int]:
    """Which step is the attack: the last one that is neither setup nor verification."""
    candidates = []
    for i, st in enumerate(steps):
        name = str(st.get("name", "")).lower()
        if any(h in name for h in SETUP_NAMES) or any(h in name for h in VERIFY_NAMES):
            continue
        candidates.append(i)
    if candidates:
        return candidates[-1]
    return None


def build_controls(spec: Dict) -> List[Dict]:
    """The control specs, each with what a PASS of it would mean."""
    out: List[Dict] = []
    refute = spec.get("refute") or {}
    attack, control = str(refute.get("attack") or ""), str(refute.get("control") or "")
    steps = spec.get("steps") or []

    # ---- credentials removed
    if steps:
        kept = [st for st in steps
                if not any(h in str(st.get("name", "")).lower() for h in ("login", "auth", "signin", "sign-in"))]
        naked = dict(spec)
        naked["steps"] = [dict(st, headers=_strip_auth(st.get("headers"))) for st in kept]
        naked["headers"] = _strip_auth(spec.get("headers"))
        had_auth = any(st.get("headers") != n.get("headers")
                       for st, n in zip(kept, naked["steps"])) or len(kept) != len(steps)
    else:
        naked = dict(spec, headers=_strip_auth(spec.get("headers")))
        had_auth = naked["headers"] != (spec.get("headers") or {})
    naked["note"] = "REFUTE control: same request with every credential header removed"
    out.append({
        "name": "credentials-removed",
        "spec": naked,
        "runnable": had_auth,
        "skip_reason": None if had_auth else
            "the exploit spec carries no credential header, so there is nothing to strip — "
            "this finding is already an unauthenticated claim",
        "pass_means": MISFRAMED,
        "pass_text": "the same result comes back with no credentials at all, so the result "
                     "never depended on the identity the finding is written around",
    })

    # ---- attack value swapped for the tester's own
    runnable = bool(attack and control)
    swapped = dict(spec)
    if runnable:
        for key in ("url", "body", "headers", "vars"):
            if key in swapped:
                swapped[key] = _swap(swapped[key], attack, control)
        if steps:
            swapped["steps"] = [
                dict(st, **{k: _swap(st[k], attack, control)
                            for k in ("url", "body", "headers") if k in st})
                for st in steps
            ]
        # `expect` is deliberately NOT swapped: the control asks whether the original
        # expectation still holds when the attack value is gone.
        swapped["note"] = (f"REFUTE control: attack value {attack!r} replaced with own "
                           f"{control!r}, judged against the ORIGINAL expect")
    out.append({
        "name": "control-value",
        "spec": swapped,
        "runnable": runnable,
        "skip_reason": None if runnable else
            'the spec does not declare the attack value. Add  "refute": {"attack": '
            '"<the value that makes this an attack>", "control": "<your own equivalent>"}  '
            "to the spec and run this again — guessing which token is the payload is not "
            "something this tool gets to do for you",
        "pass_means": KILLED,
        "pass_text": "the original expectation still holds with the attack value removed, so "
                     "the response does not react to the input: the oracle is a stub",
    })

    # ---- the chain without its exploit step
    idx = _exploit_step_index(steps) if steps else None
    trimmed = dict(spec)
    if idx is not None and len(steps) > 1:
        trimmed["steps"] = [st for i, st in enumerate(steps) if i != idx]
        trimmed["note"] = (f"REFUTE control: chain re-run with the exploit step "
                           f"({steps[idx].get('name') or idx}) deleted")
    out.append({
        "name": "exploit-removed",
        "spec": trimmed,
        "runnable": idx is not None and len(steps) > 1,
        "skip_reason": None if (idx is not None and len(steps) > 1) else
            "single-request PoC (or a chain with no identifiable exploit step): there is no "
            "step to remove. A `steps` chain with login/exploit/verify makes this control work",
        "pass_means": KILLED,
        "pass_text": "the verification still passes with the exploit step deleted, so the "
                     "state the finding claims to have caused was already there",
    })
    return out


# --------------------------------------------------------------------------- offline
def answer_never_moved(spec: Dict, project: Optional[Path]) -> Optional[Dict]:
    """Ask the response corpus whether the decisive field for this path ever changed."""
    try:
        import responses  # type: ignore
    except Exception:  # noqa: BLE001
        return None
    url = spec.get("url") or next((st.get("url") for st in (spec.get("steps") or [])
                                   if st.get("url")), "")
    if not url:
        return None
    path = re.sub(r"^https?://[^/]+", "", url).split("?")[0]
    try:
        return responses.constant_field_alert(url_substr=path,
                                              engagement=project.name if project else "")
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- firing
def fire(control: Dict, outdir: Path, scope_md: Optional[Path]) -> Dict:
    """Run one control through poc_runtime and read its verdict back."""
    outdir.mkdir(parents=True, exist_ok=True)
    spec_path = outdir / f"{control['name']}.poc.json"
    spec_path.write_text(json.dumps(control["spec"], indent=2, ensure_ascii=False) + "\n",
                         encoding="utf-8")
    cmd = [sys.executable, str(ENGINE / "poc_runtime.py"), str(spec_path)]
    if scope_md and scope_md.is_file():
        cmd += ["--md", str(scope_md)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    artifact = spec_path.with_name(spec_path.stem + ".result.json")
    verdict = "ERROR"
    if artifact.is_file():
        try:
            verdict = json.loads(artifact.read_text(encoding="utf-8")).get("final_verdict", "ERROR")
        except (OSError, ValueError):
            pass
    return {"name": control["name"], "verdict": verdict, "spec": str(spec_path),
            "artifact": str(artifact) if artifact.is_file() else None,
            "pass_means": control["pass_means"], "pass_text": control["pass_text"],
            "stdout_tail": (proc.stdout or proc.stderr or "").strip().splitlines()[-3:]}


def _decisive_fields(corpus) -> list:
    """The constant decisive fields a corpus block reports, under either key name.

    `engine/responses.py::constant_field_alert()` writes `decisive_fields`; this module
    asked for `decisive` and therefore never saw them, so the KILLED escalation below
    could not fire and the summary line always printed "varied". That failed LENIENT —
    a finding resting on a field that never reacts to input would survive its own
    refute pass. Both key names are accepted so older corpus blocks still read.
    """
    if not corpus:
        return []
    return list(corpus.get("decisive_fields") or corpus.get("decisive") or [])


# The report template's own declaration of what the finding is about. The claim is
# a CHAIN on these findings — authorize, then token, then the call that proves the
# capability — and a spec usually covers one hop of it.
CLAIM_URL_FIELDS = (
    "vulnerable url", "vulnerable urls", "vulnerable endpoint", "endpoint",
    "\u0443\u044f\u0437\u0432\u0438\u043c\u044b\u0439 url", "\u0443\u044f\u0437\u0432\u0438\u043c\u044b\u0435 url",
)
CLAIM_FIELD_RE = re.compile(
    r"^[ \t]*[-*]?[ \t]*\*\*(?P<label>[^*:]{2,40}?):?\*\*:?[ \t]*(?P<value>.+)$", re.M)
URL_RE = re.compile(r"https?://[^\s`'\"<>)\]}|]+")
# Credential markers that mean the write-up's own steps are authenticated. Checked
# against the write-up, not the spec, because the whole failure being guarded here
# is a spec that does not cover the authenticated hop.
CLAIM_AUTH_MARKERS = ("bearer ", "authorization:", "cookie:", "access_token",
                      "session cookie", "logged in", "own account", "aimsid",
                      "x-api-key", "credential")


def _claim_doc(target: Path) -> Optional[Path]:
    """The finding write-up behind a refute target, or None.

    Only inside the target's own folder, for the same reason `find_spec` is: a
    write-up from another finding would make the coverage verdict unattributable.
    """
    target = Path(target)
    folder = target if target.is_dir() else target.parent
    for name in ("finding.md", "report.md"):
        cand = folder / name
        if cand.is_file():
            return cand
    here = sorted(q for q in folder.glob("*.md") if q.is_file())
    return here[0] if len(here) == 1 else None


def _norm_url(url: str) -> str:
    """scheme://host/path, query and fragment dropped, trailing slash normalised.

    The query is dropped because a spec routinely carries the live
    `code_challenge`/`state` the write-up does not, and a claim hop is the same
    hop whether or not those are present.
    """
    url = url.strip().rstrip(".,;:\u2014\u2013)>\"'`")
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    if not host:
        return ""
    path = parts.path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    return f"{parts.scheme.lower()}://{host}{path}"


def _spec_urls(spec: Dict) -> List[str]:
    raw = []
    if spec.get("url"):
        raw.append(str(spec["url"]))
    for st in spec.get("steps") or []:
        if isinstance(st, dict) and st.get("url"):
            raw.append(str(st["url"]))
    seen, out = set(), []
    for u in raw:
        # A spec URL may carry `{{var}}` placeholders; the host and the fixed path
        # prefix still identify the hop, which is all the comparison needs.
        n = _norm_url(re.sub(r"\{\{[^}]*\}\}", "", u))
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _claim_urls(text: str) -> List[str]:
    """Every URL on the write-up's declared claim line(s).

    Deliberately NOT every URL in the document: a write-up cites precedent
    reports, platform pages and programme links, and none of those is an arm of
    the claim. The template's `**Vulnerable URL:**` line is the claim.
    """
    out, seen = [], set()
    for m in CLAIM_FIELD_RE.finditer(text or ""):
        label = m.group("label").strip().lower().strip("* ")
        if label not in CLAIM_URL_FIELDS:
            continue
        for raw in URL_RE.findall(m.group("value")):
            n = _norm_url(raw)
            if n and n not in seen:
                seen.add(n)
                out.append(n)
    return out


def claim_coverage(target: Path, spec: Dict, controls: Optional[List[Dict]] = None) -> Dict:
    """Which arms of the finding's own claim the refuted spec actually reaches.

    Why this exists. `standoff365/mail_vk`, 2026-11-12: a finding whose claim is
    "the consent screen says the app cannot send or read mail, and the issued
    token then sends and reads mail" was refuted against
    `authorize-302.poc.json` — the UNAUTHENTICATED first hop, which only shows
    `mail.api.messages.send` inside a `Location` header. The arm that carries the
    claim (`POST /mcp` `tools/call mail-send`, Bearer attached) had no spec at
    all, so it was never attacked. One control fired, `credentials-removed` was
    SKIPPED as "this finding is already an unauthenticated claim", and the result
    was reported `SURVIVED`. Nothing in that sentence was false and the whole of
    it was misleading.

    So a refutation now has to say which hops it covered. A `SURVIVED` verdict
    over a partial spec is downgraded to `INCOMPLETE` by `judge`, with the
    untested hop named. No inference about which hop matters: the comparison is
    between the write-up's own declared claim line and the spec's own URLs.
    """
    doc = _claim_doc(target)
    if doc is None:
        return {"checked": False, "reason": "no finding write-up beside the spec"}
    try:
        text = doc.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {"checked": False, "reason": f"{doc.name}: unreadable ({e})"}
    claim = _claim_urls(text)
    if not claim:
        return {"checked": False, "doc": doc.name,
                "reason": f"{doc.name} declares no `**Vulnerable URL:**` line to compare against"}
    fired = _spec_urls(spec)
    untested = []
    for hop in claim:
        if any(f == hop or f.startswith(hop + "/") or hop.startswith(f + "/") for f in fired):
            continue
        untested.append(hop)
    low = text.lower()
    auth_markers = sorted({m.strip() for m in CLAIM_AUTH_MARKERS if m in low})
    spec_has_auth = any(
        str(k).lower() in AUTH_HEADERS
        for src in [spec.get("headers") or {}] + [st.get("headers") or {}
                                                  for st in (spec.get("steps") or [])
                                                  if isinstance(st, dict)]
        for k in src)
    creds_skipped = any(c.get("name") == "credentials-removed" and not c.get("runnable")
                        for c in (controls or []))
    return {
        "checked": True,
        "doc": doc.name,
        "claim_hops": claim,
        "spec_hops": fired,
        "untested_hops": untested,
        # The write-up describes an authenticated arm, the refuted spec carries no
        # credential, and the credential control was therefore skipped as "nothing
        # to strip". That skip reason is about the SPEC and reads as a statement
        # about the FINDING, which is how an authorization claim goes unexamined.
        "auth_claim_unrefuted": bool(auth_markers and not spec_has_auth and creds_skipped),
        "auth_markers": auth_markers,
    }


def judge(results: List[Dict], skipped: List[Dict], corpus: Optional[Dict],
          coverage: Optional[Dict] = None) -> Dict:
    passed = [r for r in results if r["verdict"] == "PASS"]
    killers = [r for r in passed if r["pass_means"] == KILLED]
    misframe = [r for r in passed if r["pass_means"] == MISFRAMED]
    if killers:
        verdict, why = KILLED, killers[0]["pass_text"]
    elif misframe:
        verdict, why = MISFRAMED, misframe[0]["pass_text"]
    elif results:
        verdict, why = SURVIVED, (f"{len(results)} control(s) fired and none of them passed: "
                                  "the finding's mechanism is the best explanation left")
    else:
        verdict, why = INCOMPLETE, "no control could be built from this spec"
    _dec = _decisive_fields(corpus)
    if _dec and verdict == SURVIVED:
        verdict = KILLED
        why = (f"the corpus already answers it: {', '.join(_dec[:3])} never changed "
               f"across {corpus.get('responses')} captures of {corpus.get('path')} — a field that "
               f"does not react to input cannot be the oracle the finding relies on")
    # Coverage gate. A KILLED/MIS-FRAMED verdict stands on its own: a control that
    # passed on ONE hop of the claim is a real refutation of that hop. Only
    # SURVIVED is downgraded, because "nothing killed it" is a claim about the
    # whole finding and cannot be made from a spec that covered part of it.
    cov = coverage or {}
    if verdict == SURVIVED and cov.get("checked"):
        reasons = []
        if cov.get("untested_hops"):
            reasons.append(
                f"the claim's own `Vulnerable URL` line names "
                f"{len(cov['claim_hops'])} hop(s) and this spec fires "
                f"{len(cov['spec_hops'])} of them — untested: "
                f"{', '.join(cov['untested_hops'][:3])}")
        if cov.get("auth_claim_unrefuted"):
            reasons.append(
                "the write-up describes an authenticated arm "
                f"({', '.join(cov.get('auth_markers') or [])[:80]}) but the refuted spec "
                "carries no credential, so `credentials-removed` was skipped as "
                "'nothing to strip' — that is a fact about this spec, not about the finding")
        if reasons:
            verdict = INCOMPLETE
            why = ("the controls that fired did not reach the claim: " + "; ".join(reasons)
                   + ". Write a spec for the untested hop and refute that, or say in the "
                     "report which arm is unrefuted.")
    return {"verdict": verdict, "why": why, "controls": results, "skipped": skipped,
            "corpus": corpus, "coverage": cov or None}


# --------------------------------------------------------------------------- cli
def _report(target: Path, spec_path: Path, out: Dict) -> None:
    print(f"refute — {target.name}   (spec: {spec_path.name})")
    print()
    for r in out["controls"]:
        mark = "PASSED" if r["verdict"] == "PASS" else r["verdict"]
        print(f"  {r['name']:<20} {mark:<13} would mean: {r['pass_means']}")
        if r["verdict"] == "PASS":
            print(f"      -> {r['pass_text']}")
    for s in out["skipped"]:
        print(f"  {s['name']:<20} SKIPPED")
        print(f"      {s['skip_reason']}")
    if out.get("corpus"):
        c = out["corpus"]
        print(f"  answer-never-moved   {'CONSTANT' if _decisive_fields(c) else 'varied':<13} "
              f"{c.get('path')} over {c.get('responses')} captures")
    cov = out.get("coverage") or {}
    if cov.get("checked"):
        hops, fired = cov.get("claim_hops") or [], cov.get("spec_hops") or []
        print(f"  claim coverage       {len(hops) - len(cov.get('untested_hops') or [])}"
              f"/{len(hops)} hop(s)   (from {cov.get('doc')}'s Vulnerable URL line)")
        for hop in cov.get("untested_hops") or []:
            print(f"      UNTESTED  {hop}")
        if cov.get("auth_claim_unrefuted"):
            print("      UNTESTED  the authenticated arm: this spec carries no credential, "
                  "so credentials-removed could not run")
    elif cov.get("reason"):
        print(f"  claim coverage       not checked — {cov['reason']}")
    print()
    print(f"VERDICT: {out['verdict']}")
    print(f"  {out['why']}")
    if out["verdict"] in (KILLED, MISFRAMED):
        print()
        print("  Do not report it as written. `cbh triage <finding> --demote` moves it to")
        print("  leads/ or primitives/ with the reason attached — the observation keeps its")
        print("  place in the funnel, and findings/ holds only what survived this.")
        print("  `/remember --result rejected` so the next session does not repeat the move.")
    elif out["verdict"] == SURVIVED:
        print("  Controls fired and failed as they should. That is not proof of impact —")
        print("  `cbh evidence <finding>` still has to say DEMONSTRATED.")
    elif out["verdict"] == INCOMPLETE and (out.get("coverage") or {}).get("checked"):
        print()
        print("  This is NOT a refutation of the finding — it is a refutation of one hop of it.")
        print("  Write a spec for each UNTESTED hop above (`cbh spec` can build one from a")
        print("  request that already flew) and run `cbh refute` on that spec too. Until then")
        print("  the report must say which arm is unrefuted; `SURVIVED` would have claimed")
        print("  the whole claim was attacked.")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="refute",
        description="fire the controls that would disprove a finding, and judge them")
    ap.add_argument("target", help="finding markdown, its .poc.json, or its .result.json")
    ap.add_argument("--plan", action="store_true",
                    help="build and print the controls without firing anything")
    ap.add_argument("--scope-md", help="scope.md to check against (default: the engagement's)")
    ap.add_argument("--out", help="where to write the refute JSON "
                                  "(default: <finding>.refute.json)")
    a = ap.parse_args(argv)

    target = Path(a.target)
    if not target.exists():
        print(f"not found: {target}", file=sys.stderr)
        return 2
    spec_path = find_spec(target)
    if spec_path is None:
        print(f"no PoC spec found for {target.name}.")
        print("refute works off the request that was actually fired, not off the write-up.")
        print("Expected a sibling <stem>.poc.json, or a <stem>.result.json naming its spec.")
        print("`cbh spec <url-substring> --out <stem>.poc.json` rebuilds one from a request")
        print("that already flew.")
        return 2
    spec = json.loads(spec_path.read_text(encoding="utf-8"))

    project = project_of(target) or project_of(spec_path)
    scope_md = Path(a.scope_md) if a.scope_md else (project / "scope.md" if project else None)

    controls = build_controls(spec)
    runnable = [c for c in controls if c["runnable"]]
    skipped = [{"name": c["name"], "skip_reason": c["skip_reason"]}
               for c in controls if not c["runnable"]]

    if a.plan:
        print(f"refute plan — {target.name}   ({len(runnable)} control(s) would fire)")
        for c in runnable:
            print(f"\n  {c['name']}  — a PASS would mean {c['pass_means']}")
            print("  " + json.dumps(c["spec"], indent=2, ensure_ascii=False)[:800].replace("\n", "\n  "))
        for s in skipped:
            print(f"\n  {s['name']}  SKIPPED: {s['skip_reason']}")
        return 0

    # Name the artifacts after the SPEC, not the target's slug-up-to-first-dot. Measured
    # 2026-11-06: two lanes refuted two different specs that shared a slug prefix
    # (`<slug>.poc.json` and `<slug>.invisible.poc.json`), both resolved to stem `<slug>`,
    # and the second run SILENTLY OVERWROTE the first's `<slug>.refute.json` and its
    # `refutations/<slug>/` directory. Both verdicts happened to be SURVIVED, so nothing
    # looked wrong — the earlier lane's artifact was simply gone. A refutation is evidence;
    # evidence must not be addressable by a name two specs can share.
    spec_name = spec_path.name
    if spec_name.endswith(".poc.json"):
        stem = spec_name[:-len(".poc.json")]
    elif spec_name.endswith(".json"):
        stem = spec_name[:-len(".json")]
    else:
        stem = spec_path.stem
    outdir = (project / "refutations" / stem) if project else spec_path.parent / f"refute-{stem}"
    results = [fire(c, outdir, scope_md) for c in runnable]
    coverage = claim_coverage(target, spec, controls)
    out = judge(results, skipped, answer_never_moved(spec, project), coverage)
    out["target"] = str(target)
    out["spec_file"] = str(spec_path)

    dest = Path(a.out) if a.out else target.with_name(stem + ".refute.json")
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _report(target, spec_path, out)
    print(f"\nWritten: {dest}")
    return {KILLED: 2, MISFRAMED: 2, SURVIVED: 0, INCOMPLETE: 1}[out["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
