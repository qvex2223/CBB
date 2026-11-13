#!/usr/bin/env python3
"""workspace_check — catch the silent drifts before they cost a hunt.

Written 2026-10-20 after three drifts were each found by accident, a week late:
the hooks were missing from ~/.claude/settings.json (so Caido/Playwright traffic
went out ungated), ~/.claude/skills was a stale copy of skills/, and 70 scope.md
files carried a platform reward table whose zeros were empty fields, not zero pay.

Every check here is local and fast (no network, no target): it reads files.
`cbh doctor` prints the full table; session-brief prints one line per FAIL.

usage: workspace_check.py [--json] [--quiet]
exit: 0 all ok/warn · 1 at least one FAIL
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

HOME = Path(os.path.expanduser("~"))
SETTINGS = HOME / ".claude" / "settings.json"
CLAUDE_MD_BUDGET = 60_000          # bytes; above this every session pays for it

# script -> (event, matcher) it must be wired under
HOOKS = {
    "session-brief.py": ("SessionStart", None),
    "hunt-arm.py": ("UserPromptSubmit", None),
    "mcp-gate.py": ("PreToolUse", "mcp__"),
    "skill-gate.py": ("PreToolUse", "Bash"),
    "hunt-recall.py": ("PreToolUse", "Bash"),
    "hunt-nudge.py": ("PostToolUse", "Bash"),
    "skill-track.py": ("PostToolUse", "Skill"),
    "mcp-signals.py": ("PostToolUse", "mcp__caido"),
    # The remedy for a browser/proxy failure (engine/browser_hints.py) only reaches the
    # model if this is wired; without it a navigation failure is just a Chromium error
    # code and the next move is a guess.
    "mcp-hint.py": ("PostToolUse", "mcp__playwright"),
    "hunt-stop-gate.py": ("Stop", None),
    "control-guard.py": ("PreToolUse", "Edit"),
    "crew-gate.py": ("PreToolUse", "Bash"),
    "agent-gate.py": ("PreToolUse", "Agent"),
    # also wired on PostToolUse/Bash for a command that exited non-zero; one
    # matching wiring is enough for this check.
    "error-log.py": ("PostToolUseFailure", None),
}


# Binaries CLAUDE.md's "Tool stand" declares installed. Drift here is silent and
# expensive: a skill whose command returns `command not found` is a skill the agent
# abandons mid-hunt without logging it. On 2026-10-21 four of these (amass, gowitness,
# nuclei, dalfox) had vanished since the 2026-08-10 audit and nothing noticed.
TOOLS_REQUIRED = [
    # recon / DNS
    "subfinder", "dnsx", "amass", "assetfinder", "alterx", "tlsx", "asnmap", "mapcidr",
    # http / crawl / fuzz
    "httpx", "katana", "ffuf", "gau", "waybackurls", "gowitness", "grpcurl",
    # plumbing
    "anew", "qsreplace", "unfurl", "gf", "jq",
    # JS comprehension
    "jsluice", "wakaru",
    # secrets / SCA
    "gitleaks", "trivy",
    # bypass / takeover / OOB / scanners (policy-restricted, but must exist)
    "nomore403", "subzy", "interactsh-client", "nuclei", "dalfox",
    # installed 2026-10-29 at the operator's instruction. Both build their own
    # traffic, so bbcurl cannot cover them: scripts/bbscan is their gate and is
    # what the skills and the vector ladder name. Raw `sqlmap`/`nmap` still work
    # and are still ungated -- that is why bbscan exists.
    "sqlmap", "nmap", "nsupdate", "bbscan",
    "notify",
    # this workspace's own entry points
    "bbcurl", "cbh", "heavy-run",
]

# Documented as unavailable on this box (see CLAUDE.md "Wanted but NOT installable").
# Listed so the check stays quiet about them AND so one showing up gets reported as news.
TOOLS_KNOWN_ABSENT = [
    "semgrep", "trufflehog", "arjun", "paramspider", "x8", "uro", "jwt_tool",
]


def _r(status, name, detail, fix=""):
    return {"status": status, "check": name, "detail": detail, "fix": fix}


def check_hooks(settings_path=SETTINGS):
    try:
        s = json.loads(Path(settings_path).read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return [_r("FAIL", "hooks", f"cannot read {settings_path}: {e}",
                   "python3 docs/setup/apply-hooks.py --apply, then restart Claude Code")]
    wired = {}
    for event, groups in (s.get("hooks") or {}).items():
        for g in groups or []:
            for h in g.get("hooks") or []:
                cmd = h.get("command", "")
                for script in HOOKS:
                    if script in cmd:
                        wired.setdefault(script, []).append((event, g.get("matcher") or "", cmd))
    out, missing, broken = [], [], []
    for script, (event, matcher) in HOOKS.items():
        hits = [w for w in wired.get(script, []) if w[0] == event
                and (matcher is None or matcher in w[1])]
        if not hits:
            missing.append(script)
            continue
        for _, _, cmd in hits:
            paths = [t for t in cmd.split() if t.endswith(".py")]
            if paths and not Path(os.path.expanduser(paths[0])).is_file():
                broken.append(f"{script} -> {paths[0]}")
    if missing:
        out.append(_r("FAIL", "hooks", f"not wired: {', '.join(missing)}",
                      "python3 docs/setup/apply-hooks.py --apply, then restart Claude Code"))
    if broken:
        out.append(_r("FAIL", "hooks", f"wired to a missing file: {'; '.join(broken)}",
                      "re-run docs/setup/apply-hooks.py --apply"))
    env_mem = (s.get("env") or {}).get("CBH_MEMORY_DIR")
    try:
        from paths import memory_dir
        want = str(memory_dir())
    except Exception:  # noqa: BLE001
        want = None
    if want and env_mem and Path(env_mem).resolve() != Path(want).resolve():
        out.append(_r("FAIL", "memory-dir", f"settings env CBH_MEMORY_DIR={env_mem} but the "
                      f"workspace resolves {want} — two corpora", "fix env in ~/.claude/settings.json"))
    if not out:
        out.append(_r("OK", "hooks", f"{len(HOOKS)}/{len(HOOKS)} wired"))

    return out


def check_model_routing():
    """Stale provider wiring in settings.json would break every model in the session.

    Until 2026-11-13 the crew ran on a second provider behind a local proxy, which meant
    `env.ANTHROPIC_BASE_URL` pointed at 127.0.0.1 and `env.CLAUDE_CODE_SUBAGENT_MODEL`
    named that provider's model. Both are gone with it. If either is still set, nothing
    is listening on that port and no model in this session is reachable — a total,
    silent failure, so it is checked rather than assumed.
    """
    out = []
    try:
        st = json.loads(SETTINGS.read_text(encoding="utf-8")) if SETTINGS.is_file() else {}
        env = st.get("env") or {}
        base = (env.get("ANTHROPIC_BASE_URL") or "").strip()
        sub = (env.get("CLAUDE_CODE_SUBAGENT_MODEL") or "").strip()
        if base:
            out.append(_r("FAIL", "model-routing",
                          f"settings route every request through {base}, which this "
                          "toolkit no longer runs",
                          f"remove env.ANTHROPIC_BASE_URL from {SETTINGS}"))
        if sub and not sub.lower().startswith("claude"):
            out.append(_r("FAIL", "model-routing",
                          f"subagents are set to {sub}, which has no endpoint here",
                          f"remove env.CLAUDE_CODE_SUBAGENT_MODEL from {SETTINGS} or set "
                          "a Claude model"))
        if not out:
            out.append(_r("OK", "model-routing", "no stale provider routing in settings"))
    except Exception as e:  # noqa: BLE001
        out.append(_r("FAIL", "model-routing", f"check crashed: {e}"))
    return out


def _tree_digest(root: Path):
    d = {}
    if not root.is_dir():
        return d
    for p in sorted(root.rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts:
            d[str(p.relative_to(root))] = hashlib.sha1(p.read_bytes()).hexdigest()
    return d


def check_skill_copies(repo=REPO, home=HOME / ".claude"):
    out = []
    for sub in ("skills", "commands"):
        src, dst = _tree_digest(repo / sub), _tree_digest(home / sub)
        if not src:
            continue
        stale = [k for k, v in src.items() if dst.get(k) != v]
        if stale:
            out.append(_r("FAIL", f"{sub}-copy",
                          f"~/.claude/{sub} differs from repo on {len(stale)} file(s), e.g. {stale[0]}",
                          f"cp -a {sub}/. ~/.claude/{sub}/"))
        else:
            out.append(_r("OK", f"{sub}-copy", f"{len(src)} files in sync"))
    return out


ZERO_ROW = re.compile(r"^\|\s*(high|medium|low)\s*\|\s*0\s*\|\s*0\s*\|", re.M | re.I)


def check_reward_models(targets=None):
    try:
        from paths import targets_root
        targets = targets or targets_root()
    except Exception:  # noqa: BLE001
        return []
    unverified = []
    for scope in sorted(Path(targets).glob("**/scope.md")):
        if "_TEMPLATE" in scope.parts:
            continue
        t = scope.read_text(encoding="utf-8", errors="replace")
        if ZERO_ROW.search(t) and "onlyMaxPayment" not in t and "Reward model" not in t:
            unverified.append(str(scope.parent.relative_to(targets)))
    if unverified:
        return [_r("WARN", "reward-model",
                   f"{len(unverified)} scope.md with 0|0 bands and no onlyMaxPayment verdict: "
                   f"{', '.join(unverified[:5])}{' …' if len(unverified) > 5 else ''}",
                   "read the programme's payout text; a 0|0 row may be an empty field, not zero pay")]
    return [_r("OK", "reward-model", "every zero band carries a verdict")]


def check_context_size(repo=REPO, targets=None):
    try:
        from paths import targets_root
        targets = targets or targets_root()
    except Exception:  # noqa: BLE001
        targets = repo / "Targets"
    big = []
    # AGENTS.md is the doctrine every client loads, so it is budgeted like CLAUDE.md;
    # the engagement folders' AGENTS.md are symlinks to their CLAUDE.md and are skipped.
    heads = [repo / "AGENTS.md", repo / "CLAUDE.md"]
    for p in heads + sorted(Path(targets).glob("**/CLAUDE.md")):
        if p.is_file() and not p.is_symlink() and p.stat().st_size > CLAUDE_MD_BUDGET:
            big.append(f"{p.relative_to(repo)} {p.stat().st_size // 1000} KB")
    if big:
        return [_r("WARN", "context-size", f"over {CLAUDE_MD_BUDGET // 1000} KB: {'; '.join(big)}",
                   "move worker journals to recon/, keep rules in AGENTS.md")]
    return [_r("OK", "context-size",
               f"root AGENTS.md + every CLAUDE.md under {CLAUDE_MD_BUDGET // 1000} KB")]


def check_tool_stand(required=None, absent=None):
    """PATH vs the declared stand. No network, no target: shutil.which only."""
    import shutil
    required = TOOLS_REQUIRED if required is None else required
    absent = TOOLS_KNOWN_ABSENT if absent is None else absent
    missing = [b for b in required if not shutil.which(b)]
    appeared = [b for b in absent if shutil.which(b)]
    out = []
    if missing:
        out.append(_r("FAIL", "tool-stand",
                      f"{len(missing)}/{len(required)} declared binaries not on PATH: "
                      + " ".join(missing),
                      "GOBIN=~/.local/bin GOPATH=~/security-research/tools/gopath "
                      "~/security-research/tools/go/bin/go install <module>@latest — "
                      "see docs/toolstand-audit-20261021.md"))
    else:
        out.append(_r("OK", "tool-stand", f"all {len(required)} declared binaries on PATH"))
    if appeared:
        out.append(_r("WARN", "tool-stand-new",
                      "documented-absent binaries now present: " + " ".join(appeared),
                      "update CLAUDE.md 'Wanted but NOT installable' — a skill may now run"))
    return out


def run_all():
    res = []
    for fn in (check_hooks, check_model_routing, check_skill_copies,
               check_reward_models, check_context_size, check_tool_stand):
        try:
            res += fn()
        except Exception as e:  # noqa: BLE001 - a broken check must say so, not vanish
            res.append(_r("FAIL", fn.__name__, f"check crashed: {e}"))
    return res


def brief_lines(results=None):
    """One line per FAIL, for session-brief. Empty when healthy."""
    results = results if results is not None else run_all()
    return [f"WORKSPACE FAIL [{r['check']}]: {r['detail']} — fix: {r['fix']}"
            for r in results if r["status"] == "FAIL"]


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    res = run_all()
    if "--json" in argv:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    elif "--quiet" in argv:
        for line in brief_lines(res):
            print(line)
    else:
        for r in res:
            print(f"{r['status']:5} {r['check']:<14} {r['detail']}")
            if r["status"] != "OK" and r["fix"]:
                print(f"{'':20} fix: {r['fix']}")
    return 1 if any(r["status"] == "FAIL" for r in res) else 0


if __name__ == "__main__":
    raise SystemExit(main())
