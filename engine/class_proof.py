#!/usr/bin/env python3
"""
class_proof.py — the oracle a class of bug needs before "demonstrated" is true.

`evidence.py` grades whether a request was fired and matched its `expect`. That is
one question, and it is class-blind: a reflected marker in an HTML body passes it as
an XSS, a `500` on a quote passes it as an SQL injection, and a `200` from a fetcher
passes it as an SSRF. Measured across this workspace's own corpus: of 16 live
findings, the ones that later collapsed under refutation all collapsed the same way —
the artifact proved that a request reached something, and the write-up asserted the
effect.

So each class states the oracle that makes its effect observable, and the gate reads
it off the ARTIFACTS, never off the prose:

  xss            execution, not reflection — a browser/proxy artifact, because a
                 `.result.json` records bytes and bytes do not run
  sqli           a time delta between two steps, or DB data/errors in the body
  rce            command output in the body, or an OOB callback
  ssrf / xxe     an OOB hit log: the effect is an outbound request, which the
                 response that triggered it cannot witness
  lfi            file content in the body
  idor           two identities in one artifact — one identity cannot show an
                 ownership boundary
  csrf           a cross-origin PoC document next to the finding
  open-redirect  a hop whose host is not the host we asked

Everything else has no class-specific oracle and is graded by `evidence.py` alone.
Saying "no oracle for this class" out loud is deliberate: a silent pass and a
checked pass must not look the same in the report.

The class comes from `lead_queue`'s vocabulary — one table for the whole workspace —
and is read from the finding's declared `**Class:**` line, else matched against its
title and file name only. Not the whole document: a write-up that says "redirect"
nine times while arguing about something else would classify itself.

    python3 engine/class_proof.py <finding.md>      # what this finding's class needs
"""
from __future__ import annotations

import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Callable, Dict, List, Optional

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

# Identity carriers. A step that sends one of these is acting as somebody; a step that
# sends none is acting as nobody, and "nobody" is a second identity for an authz claim.
IDENTITY_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token",
                    "x-access-token", "x-session-token", "x-csrf-token")

# Artifacts only a browser or a proxy can produce. `.result.json` is deliberately not
# here: that is `poc_runtime`'s own record of bytes on the wire.
BROWSER_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp4", ".har",
                    ".caido.txt", ".caido.json", ".caido.har", ".burp.txt",
                    ".burp.json", ".burp.har")
BROWSER_NAME_RE = re.compile(r"(console|devtools|browser|screenshot|alert|execution)",
                             re.I)

# A file that MAKES the proof is not the proof. `native-alert-proof-nonce.mjs` matched
# BROWSER_NAME_RE and passed the XSS oracle on its own name while the real artifact — the
# screenshot one folder down — went unread (measured 2026-11-13). Name matching is for
# recordings only; a suffix match is unaffected, so a `.har` keeps passing on its type.
SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".mjs", ".cjs", ".js", ".ts", ".py", ".rb",
                   ".pl", ".ps1", ".bat", ".exe", ".poc.json")

# Hit logs an out-of-band listener writes. `scripts/oob-responder.py` writes one JSON
# line per hit; interactsh and a self-hosted canary are the same shape.
OOB_NAME_RE = re.compile(r"(^|[._-])(oob|interactsh|collab|collaborator|canary|callback)"
                         r"([._-]|$)", re.I)

# Shapes that are the file, not a claim about the file.
FILE_CONTENT_RE = re.compile(
    r"root:x:0:0|daemon:x:1:1|\[boot loader\]|BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY|"
    r"<\?php|__pycache__|/etc/shadow:|APP_KEY=|DB_PASSWORD=", re.I)

# Shapes only a database produces. An application's own 500 page is not one.
DB_ERROR_RE = re.compile(
    r"SQLSTATE\[|syntax error at or near|ORA-\d{5}|SQL syntax|mysqli?_|"
    r"psycopg2\.|pg_query|sqlite3\.OperationalError|Microsoft OLE DB|"
    r"Unclosed quotation mark|PG::SyntaxError|ActiveRecord::StatementInvalid", re.I)

# Shapes only a shell produces.
EXEC_OUTPUT_RE = re.compile(
    r"uid=\d+\([a-z_][a-z0-9_-]*\)|gid=\d+\(|Linux [a-z0-9.-]+ \d+\.\d+|"
    r"total \d+\s+drwx|Directory of [A-Z]:\\", re.I)

MAX_FILES = 400          # a finding folder, not a crawl
TIME_DELTA_MS = 2000.0      # the shortest delay a human would call a delay
TIME_DELTA_FACTOR = 3.0     # and it must dwarf the fast arm, not edge past it


class Ctx:
    """Everything a rule may look at. Loaded once, read by whichever rule runs."""

    def __init__(self, text: str, artifacts: List[Path], where: Path):
        self.text = text or ""
        self.where = where
        self.docs: List[dict] = []
        self.specs: List[dict] = []
        for p in artifacts:
            doc = _load(Path(p))
            if doc is None:
                continue
            self.docs.append(doc)
            spec = _spec_of(Path(p), doc)
            if spec is not None:
                self.specs.append(spec)
        # Recursive: one folder per finding, and its artifacts sit in subfolders —
        # `evidence/proof-xss-*.png`, `cdp/*.console.json`, `report/`. A top-level glob
        # read the wildberries javascript-scheme XSS as execution-unproven while its
        # screenshot and CDP log sat one level down (measured 2026-11-13). Bounded so a
        # finding folder holding a crawl cannot stall the gate.
        self.files = []
        if where.is_dir():
            for q in sorted(where.rglob("*")):
                if q.is_file():
                    self.files.append(q)
                    if len(self.files) >= MAX_FILES:
                        break

    # -- views over the artifacts ------------------------------------------------
    def results(self) -> List[dict]:
        """Every recorded response, step results included."""
        out = []
        for doc in self.docs:
            for run in doc.get("runs") or []:
                res = run.get("result")
                if isinstance(res, dict):
                    out.append(res)
                for st in run.get("steps") or []:
                    if isinstance(st.get("result"), dict):
                        out.append(st["result"])
        return out

    def result_groups(self) -> List[List[dict]]:
        """Results grouped per run, steps only where a run has them. The run-level
        `result` is an AGGREGATE of the same run: mixing it in made a 4000 ms vs 6100 ms
        pair read against the aggregate's 120 ms and pass a delta that is 1.5x, not 3x
        (measured 2026-11-13). A delta is only a delta between two arms of one PoC."""
        out = []
        for doc in self.docs:
            for run in doc.get("runs") or []:
                steps = [st["result"] for st in run.get("steps") or []
                         if isinstance(st.get("result"), dict)]
                if len(steps) >= 2:
                    out.append(steps)
                elif isinstance(run.get("result"), dict):
                    out.append([run["result"]])
        return out

    def bodies(self) -> List[str]:
        return [r.get("body") or "" for r in self.results()]

    def spec_steps(self) -> List[List[dict]]:
        """Steps per spec, so "two identities" is asked within one PoC and not across
        two unrelated ones."""
        out = []
        for spec in self.specs:
            steps = spec.get("steps")
            out.append(list(steps) if isinstance(steps, list) and steps else [spec])
        return out

    def named(self, suffixes=(), name_re: Optional[re.Pattern] = None) -> List[Path]:
        """Artifacts of a type, or recordings named for one. Suffix hits come first:
        they are matched on what the file IS, which is the stronger claim."""
        by_type, by_name = [], []
        for p in self.files:
            low = p.name.lower()
            if suffixes and low.endswith(tuple(suffixes)):
                by_type.append(p)
            elif (name_re is not None and name_re.search(low)
                  and not low.endswith(SCRIPT_SUFFIXES)):
                by_name.append(p)
        return by_type + by_name


def _load(path: Path) -> Optional[dict]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _spec_of(artifact: Path, doc: dict) -> Optional[dict]:
    """The spec a result came from. `poc_runtime` records its path; the conventional
    `<stem>.poc.json` beside `<stem>.poc.result.json` is the fallback."""
    named = str(doc.get("spec_file") or "")
    for cand in ([Path(named)] if named else []) + [
            artifact.with_name(artifact.name.replace(".result.json", ".json"))]:
        for p in ({cand, artifact.parent / cand.name} if not cand.is_absolute()
                  else {cand}):
            if p.is_file():
                got = _load(p)
                if got is not None:
                    return got
    return None


# ---------------------------------------------------------------------------
# the class of the claim
# ---------------------------------------------------------------------------
def classify(text: str, name: str = "") -> tuple[str, str]:
    """(class, source). Source is `declared`, `guessed` or `""` when nothing matched."""
    try:
        import lead_queue  # noqa: PLC0415 - one class vocabulary for the workspace
    except Exception:  # noqa: BLE001 - the gate must never fail on an import
        return "", ""
    # Case-insensitive on purpose: `evidence.check()` lowercases a finding's text
    # before grading it, and the shared pattern is anchored on `**Class:**`. Reusing it
    # verbatim read every declaration as absent and guessed from the title instead.
    decl = re.compile(lead_queue.CLASS_DECL_RE.pattern, re.M | re.I).search(text or "")
    if decl:
        return decl.group(1).strip().lower(), "declared"
    # Title and file name only. The first heading that is a claim rather than a
    # template label, plus the stem, is the same input `lead_queue` classifies on.
    head = ""
    for line in (text or "").splitlines():
        s = line.strip().lstrip("# ").strip()
        if len(s) >= 25 and not s.startswith("[") and "<" not in s:
            head = s
            break
    blob = f"{name} {head}".lower()
    # The shared vocabulary was written against file NAMES, so its tokens are hyphenated
    # (`unauthenticated-read-of`, `path-traversal`, `cross-origin`). A prose title writes
    # the same words with spaces and matched nothing: 9 of 16 live findings classified as
    # "no class" on titles that name their class in words (measured 2026-11-13). Both
    # spellings are tried, and the file name is unaffected.
    spellings = (blob, blob.replace(" ", "-"))
    for pattern, cls in lead_queue.CLASS_WORDS:
        if any(re.search(pattern, b) for b in spellings):
            return cls, "guessed"
    return "", ""


# ---------------------------------------------------------------------------
# the rules
# ---------------------------------------------------------------------------
def _names(paths: List[Path], limit: int = 3) -> str:
    """Distinct file names. A finding folder keeps a copy of its screenshot under
    `report/`, and naming the same file twice reads as two independent artifacts."""
    seen: List[str] = []
    for p in paths:
        if p.name not in seen:
            seen.append(p.name)
        if len(seen) >= limit:
            break
    return ", ".join(seen)


def _xss(ctx: Ctx) -> tuple[bool, str]:
    hits = ctx.named(BROWSER_SUFFIXES, BROWSER_NAME_RE)
    if hits:
        return True, f"execution observed outside poc_runtime: {_names(hits)}"
    return False, ("the only artifacts are byte records. A reflected marker is a sink, "
                   "not an execution: open the PoC URL in the headed browser "
                   "(`cbh browser login <program> --url <poc>`) and save the alert or the "
                   "console record next to the finding, or export the exchange from Caido")


def _sqli(ctx: Ctx) -> tuple[bool, str]:
    for group in ctx.result_groups():
        times = [r.get("elapsed_ms") for r in group
                 if isinstance(r.get("elapsed_ms"), (int, float))]
        if len(times) < 2:
            continue
        slow, fast = max(times), min(times)
        if slow - fast >= TIME_DELTA_MS and (fast <= 0 or slow / fast >= TIME_DELTA_FACTOR):
            return True, f"time delta between two arms of one PoC: {fast:.0f} ms vs {slow:.0f} ms"
    for body in ctx.bodies():
        m = DB_ERROR_RE.search(body)
        if m:
            return True, f"the database answered in the body: {m.group(0)[:40]!r}"
    return False, ("no time delta between steps and no database output in any body. "
                   f"A time-based arm needs two steps on one spec whose `elapsed_ms` "
                   f"differ by >= {TIME_DELTA_MS:.0f} ms and >= {TIME_DELTA_FACTOR:.0f}x; "
                   "an in-band arm needs the data or the driver's error, not the app's 500")


def _rce(ctx: Ctx) -> tuple[bool, str]:
    for body in ctx.bodies():
        m = EXEC_OUTPUT_RE.search(body)
        if m:
            return True, f"command output in the body: {m.group(0)[:40]!r}"
    hits = _oob_hits(ctx)
    if hits:
        return True, f"OOB callback recorded in {hits[0].name}"
    return False, ("no command output in any body and no OOB callback. Execution is "
                   "witnessed by its output or by a request the target made to a host "
                   "you control, never by a 500 or a timeout")


def _oob_hits(ctx: Ctx) -> List[Path]:
    """OOB logs beside the finding that actually recorded a hit, not empty files."""
    out = []
    for p in ctx.named(name_re=OOB_NAME_RE):
        try:
            raw = p.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if not raw:
            continue
        # One JSON object per line (`oob-responder.py --log`), or a JSON array.
        rows = [ln for ln in raw.splitlines() if ln.strip().startswith("{")]
        if rows or raw.startswith("["):
            out.append(p)
    return out


def _oob(ctx: Ctx) -> tuple[bool, str]:
    hits = _oob_hits(ctx)
    if hits:
        return True, f"OOB hit log beside the finding: {hits[0].name}"
    return False, ("no OOB hit log. The effect here is a request the TARGET makes, and "
                   "the response that triggered it cannot witness it: run "
                   "`python3 scripts/oob-responder.py --port <p> --log <dir>/oob.jsonl` on "
                   "a host the target can reach, hand the app that URL, and save the hit "
                   "log next to the finding. Check the programme permits OOB first")


def _lfi(ctx: Ctx) -> tuple[bool, str]:
    for body in ctx.bodies():
        m = FILE_CONTENT_RE.search(body)
        if m:
            return True, f"file content in the body: {m.group(0)[:40]!r}"
    return False, ("no file content in any body. A path that 500s or 404s differently is "
                   "a traversal oracle — a primitive — until the file's own bytes come back")


def _identity_of(step: dict) -> str:
    """What this step is acting as: the identity headers it carries, normalised."""
    headers = step.get("headers") or {}
    if not isinstance(headers, dict):
        return ""
    parts = [f"{k.lower()}={str(v)}" for k, v in sorted(headers.items())
             if k.lower() in IDENTITY_HEADERS and str(v).strip()]
    return "|".join(parts)


def _idor(ctx: Ctx) -> tuple[bool, str]:
    for steps in ctx.spec_steps():
        ids = {_identity_of(st) for st in steps}
        if len(ids) >= 2:
            named = sorted(("(none)" if not i else i.split("=", 1)[0]) for i in ids)
            return True, f"{len(ids)} identities in one spec: {', '.join(named)}"
    return False, ("every step of this PoC acts as the same identity. An ownership "
                   "boundary is shown by two: the owner's and someone else's (or "
                   "nobody's). Add the second arm to the spec — same request, other "
                   "credential — so one artifact holds both answers")


def _secret_exposure(ctx: Ctx) -> tuple[bool, str]:
    """A leaked credential is proven by USING it, never by finding it.

    The oracle is two arms of ONE PoC against the SAME url: the arm carrying the credential
    answers 2xx, the arm without it does not. Anything less is a string in a response.

    Why this rule exists. ARTEX reported a planted fake secret as genuine on 30 of 120 tasks
    (arXiv 2611.07611) — a secret that has not been used is not evidence that it is real, let
    alone that it grants anything. And note the shape this must NOT accept: `cbh refute`'s
    `credentials-removed` control passes by construction on an unauthenticated-exposure claim,
    because the request carried no credential in the first place. That control shows the endpoint
    answers WITHOUT the secret, which is the opposite of this proof.

    The same-url guard is load-bearing: a 2xx on one route beside a 401 on another proves
    nothing about the credential, only that two routes differ.
    """
    for spec, group in zip(ctx.specs, ctx.result_groups()):
        steps = spec.get("steps")
        steps = list(steps) if isinstance(steps, list) and steps else [spec]
        # Index pairing is only honest when the run recorded one result per step.
        if len(steps) != len(group):
            continue
        by_url: Dict[str, Dict[str, list]] = {}
        for st, res in zip(steps, group):
            url = str(st.get("url") or "")
            code = res.get("status")
            if not url or not isinstance(code, int):
                continue
            arm = "with" if _identity_of(st) else "without"
            by_url.setdefault(url, {"with": [], "without": []})[arm].append(code)
        for url, arms in by_url.items():
            authed = [c for c in arms["with"] if 200 <= c < 300]
            denied = [c for c in arms["without"] if not 200 <= c < 300]
            if authed and denied:
                return True, (f"the credential authenticated on one url: {authed[0]} carrying "
                              f"it against {denied[0]} without it, {url[:60]}")
    return False, ("the secret was found, not used. This class is proven by two arms of ONE "
                   "spec against the SAME url: a step carrying the credential in an identity "
                   f"header ({', '.join(IDENTITY_HEADERS[:4])}, ...) answering 2xx, and a step "
                   "without it answering anything else. A planted or revoked key looks "
                   "identical to a live one until it is used — and `cbh refute`'s "
                   "`credentials-removed` control is NOT this proof: it shows the endpoint "
                   "answers without the secret, which is the opposite claim. If the credential "
                   "travels as a query parameter rather than a header, put the header arm in "
                   "the spec anyway or declare the class the finding actually is")


def _csrf(ctx: Ctx) -> tuple[bool, str]:
    docs = [p for p in ctx.files if p.suffix.lower() in (".html", ".htm")]
    if docs:
        return True, f"cross-origin PoC document: {docs[0].name}"
    return False, ("no .html PoC next to the finding. A forged cross-site request is "
                   "proven by a document on another origin that fires it with the "
                   "victim's cookies, not by a curl that carries them deliberately")


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001 - an unparseable URL proves nothing
        return ""


def _open_redirect(ctx: Ctx) -> tuple[bool, str]:
    for doc in ctx.docs:
        for run in doc.get("runs") or []:
            for res in [run.get("result") or {}] + [st.get("result") or {}
                                                    for st in run.get("steps") or []]:
                if not isinstance(res, dict):
                    continue
                src = _host(res.get("url") or res.get("final_url") or "")
                dests = [r.get("url") or r.get("location") or "" if isinstance(r, dict) else str(r)
                         for r in (res.get("redirects") or [])]
                loc = (res.get("headers") or {}).get("location") or ""
                for dest in dests + [loc, res.get("final_url") or ""]:
                    dh = _host(dest if "://" in str(dest) else "")
                    if dh and src and dh != src:
                        return True, f"a hop left the origin: {src} -> {dh}"
    return False, ("no hop to another host in any artifact. The claim is that the app "
                   "sends a visitor off-origin, so the artifact has to show the hop: "
                   "record the `Location` (or the followed chain) whose host is not the "
                   "host we asked")


RULES: Dict[str, tuple[str, Callable[[Ctx], tuple[bool, str]]]] = {
    "xss": ("execution, not reflection", _xss),
    "sqli": ("a time delta or the database's own output", _sqli),
    "rce": ("command output or an OOB callback", _rce),
    "ssrf": ("an OOB hit log", _oob),
    "xxe": ("an OOB hit log", _oob),
    "lfi": ("the file's own bytes in the body", _lfi),
    "idor": ("two identities in one artifact", _idor),
    "csrf": ("a cross-origin PoC document", _csrf),
    "open-redirect": ("a hop to another host", _open_redirect),
    # The class already existed everywhere — CATALOG, CLASS_WORDS, skill_map, a 300 000 band —
    # and had no oracle, so `cbh triage` graded it as "not checked". It is the one class whose
    # artifact is most often a grep hit rather than a request.
    "secret-exposure": ("the credential authenticating, not its presence", _secret_exposure),
}


def grade(text: str, artifacts: List[Path], where: Path, name: str = "") -> Dict:
    """Does this finding's class have its oracle? Reads artifacts, never the prose.

    `ok` is True when the oracle fired AND when the class has no oracle — the two
    cases are told apart by `checked`, so a report never shows an unchecked class as
    a passed one.
    """
    cls, source = classify(text, name)
    rule = RULES.get(cls)
    if rule is None:
        return {"class": cls, "class_source": source, "checked": False, "ok": True,
                "need": "", "reason": (f"no class-specific oracle for `{cls}`"
                                       if cls else "the finding declares no class")}
    need, fn = rule
    ok, reason = fn(Ctx(text, artifacts, where))
    return {"class": cls, "class_source": source, "checked": True, "ok": ok,
            "need": need, "reason": reason}


def line(report: Dict) -> str:
    """One line for the gate."""
    if not report.get("checked"):
        return f"class proof   not checked — {report.get('reason', '')}"
    mark = "ok" if report.get("ok") else "MISSING"
    return (f"class proof   {mark} · `{report['class']}` needs {report['need']} "
            f"({report['class_source']}) — {report['reason']}")


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        return 2
    target = Path(argv[0])
    if not target.exists():
        print(f"class_proof: no such path: {target}", file=sys.stderr)
        return 2
    try:
        import evidence  # noqa: PLC0415 - only the CLI needs the artifact collector
        artifacts = evidence.collect(target)
    except Exception:  # noqa: BLE001
        artifacts = []
    text = ""
    if target.is_file():
        text = target.read_text(encoding="utf-8", errors="replace")
    where = target.parent if target.is_file() else target
    rep = grade(text, artifacts, where, target.stem)
    print(line(rep))
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
