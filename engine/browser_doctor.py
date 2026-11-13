#!/usr/bin/env python3
"""`cbh browser doctor` — the facts behind a browser failure, in one screen.

A failed navigation says `net::ERR_TOO_MANY_RETRIES` and nothing else. Everything that
decides whether that is the target or this box is local state: which engagement the MCP
server resolved, whether the browser proxies through Caido, whether another lane holds
the profile, whether a real Chrome is installed, whether there is a display. Measured 2026-11-11: the same
navigation was re-fired four times without any of it being read once.

Read-only: it opens no browser and sends nothing at a target. The one thing it cannot
see from here is Caido's intercept status (that needs Caido's own token), so it says so
and names the tool call that answers it.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "engine"))

CHROME_CANDIDATES = ["/opt/google/chrome/chrome", "/usr/bin/google-chrome-stable",
                     "/usr/bin/google-chrome"]


def _port_open(host: str, port: int, timeout: float = 0.7) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _age(iso: str) -> str:
    try:
        started = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        return ""
    secs = int((datetime.now(timezone.utc) - started).total_seconds())
    return f"{secs // 60}m{secs % 60:02d}s"


def mcp_server_env(name: str = "playwright") -> dict:
    """The env block `.mcp.json` hands that MCP server, or {}.

    Static file, not the live process: it says what the NEXT server start will get.
    A running server keeps whatever it was started with — headless and the profile are
    both bound at start — so a change here shows up only after a restart.
    """
    try:
        d = json.loads((REPO / ".mcp.json").read_text(encoding="utf-8"))
        return dict(((d.get("mcpServers") or {}).get(name) or {}).get("env") or {})
    except Exception:  # noqa: BLE001
        return {}


def running_playwright_servers() -> list[dict]:
    """The flags the LIVE MCP servers were started with, read from /proc.

    `.mcp.json` and the `playwright-direct` marker describe what the NEXT server start
    gets. A running server keeps whatever it was given: the proxy, the profile mode and
    headless are all bound at start. On 2026-11-12 this command printed "direct marker
    present — browser goes direct" while the live server carried
    `--proxy-server http://127.0.0.1:8080 --isolated`, because it had been started
    outside the engagement folder and resolved no engagement; mail.ru RSTs a MITM'd
    connection, so a whole lane burned on net::ERR_TOO_MANY_RETRIES before anyone read
    the process arguments. So read them here.
    """
    found: list[dict] = []
    proc = Path("/proc")
    if not proc.is_dir():
        return found
    for entry in sorted(proc.iterdir()):
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        argv = [a for a in raw.split(b"\x00") if a]
        if not any(b"@playwright/mcp/cli.js" in a for a in argv):
            continue
        args = [a.decode("utf-8", "replace") for a in argv]

        def _flag_value(name: str) -> str:
            for i, a in enumerate(args):
                if a == name and i + 1 < len(args):
                    return args[i + 1]
                if a.startswith(name + "="):
                    return a.split("=", 1)[1]
            return ""

        try:
            started = datetime.fromtimestamp(entry.stat().st_mtime,
                                             tz=timezone.utc).isoformat()
        except OSError:
            started = ""
        found.append({
            "pid": int(entry.name),
            "proxy": _flag_value("--proxy-server"),
            "isolated": "--isolated" in args,
            "headless": "--headless" in args,
            "output_dir": _flag_value("--output-dir"),
            "started_at": started,
        })
    return found


def collect() -> dict:
    from pacing import Engagement  # type: ignore
    import browser_state  # type: ignore

    eng = Engagement.detect()
    project = Path(eng.project_dir) if eng.project_dir else None
    caido_host = os.environ.get("CBH_CAIDO_HOST", "127.0.0.1")
    caido_port = int(os.environ.get("CBH_CAIDO_PORT", "8080"))
    chrome = next((p for p in [os.environ.get("CBH_PLAYWRIGHT_CHROME"), *CHROME_CANDIDATES]
                   if p and Path(p).exists()), None)
    display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY") or ""
    direct = bool(project and browser_state.engagement_is_direct(project))
    # The browser runs in the MCP SERVER's process, not in this shell, and the server
    # gets its environment from .mcp.json. Reading only os.environ made this command
    # report `headless` while the configured server was headed, and the other way round
    # — a property of a process it cannot see, stated as fact.
    mcp_env = mcp_server_env()
    headed_client = (os.environ.get("CBH_PLAYWRIGHT_HEADED") == "1"
                     or mcp_env.get("CBH_PLAYWRIGHT_HEADED") == "1")
    return {
        "engagement": eng.name if project else None,
        "project_dir": str(project) if project else None,
        "engine": _engine(mcp_env),
        "profile_dir": (str(project / browser_state.profile_dir_name(_engine(mcp_env)))
                        if project else None),
        "min_interval_seconds": eng.min_interval,
        "caido": {"endpoint": f"{caido_host}:{caido_port}",
                  "listening": _port_open(caido_host, caido_port),
                  "browser_uses_it": not (direct or browser_state.caido_off()),
                  "intercept_status": "unknown from here"},
        "direct_marker": direct,
        "chrome": chrome,
        "display": display,
        "headless": bool(os.environ.get("CBH_PLAYWRIGHT_HEADLESS") == "1"
                         or mcp_env.get("CBH_PLAYWRIGHT_HEADLESS") == "1"
                         or not display
                         or not headed_client),
        "headed_configured_in_mcp_json": mcp_env.get("CBH_PLAYWRIGHT_HEADED") == "1",
        "isolated": os.environ.get("CBH_PLAYWRIGHT_ISOLATED") == "1",
        "mcp_cli": (REPO / "runtime" / "node_modules" / "@playwright" / "mcp" / "cli.js").exists(),
        "lanes": browser_state.live_lanes(),
        "running_servers": running_playwright_servers(),
    }


def render(d: dict) -> list[str]:
    out: list[str] = ["browser doctor"]
    eng = d["engagement"]
    if eng:
        out.append(f"  engagement        {eng}  ({d['project_dir']})")
    else:
        out.append("  engagement        NONE resolved from this folder")
        out.append("    -> the MCP servers take their engagement from the launch directory. A "
                   "client started")
        out.append("       at the repo root still works: the gate resolves the engagement from the "
                   "URL, as")
        out.append("       long as exactly one program's scope.md admits it. Browser control URLs "
                   "(about:blank,")
        out.append("       data:, chrome://) need no engagement at all.")
    out.append(f"  profile           {d['profile_dir'] or '(in-memory, --isolated)'}"
               f"{'  [ISOLATED]' if d['isolated'] else ''}")
    caido = d["caido"]
    state = "listening" if caido["listening"] else "DOWN"
    route = "browser proxies through it" if caido["browser_uses_it"] else "browser goes direct"
    out.append(f"  caido             {caido['endpoint']} {state} — {route}")
    if caido["browser_uses_it"]:
        out.append("    -> intercept status cannot be read from here. If navigation fails, call "
                   "caido_intercept_status:")
        out.append("       PAUSED means the queue HOLDS every proxied request and the browser "
                   "will report")
        out.append("       net::ERR_TOO_MANY_RETRIES. Resume with "
                   "caido_intercept_control {\"action\":\"resume\"}.")
        if not caido["listening"]:
            out.append("    -> Caido is down and the wrapper refuses to start a proxy-less "
                       "browser: scripts/caido-up.sh")
    if d["direct_marker"]:
        out.append("  direct marker     present — this engagement's browser bypasses Caido "
                   "(playwright-direct)")
    servers = d.get("running_servers") or []
    if not servers:
        out.append("  live mcp server   none running — the next browser call starts one, which "
                   "reads .mcp.json")
        out.append("                    and the marker fresh. A server killed mid-session does "
                   "NOT respawn by itself:")
        out.append("                    reconnect `playwright` in /mcp, or restart the client.")
    for s in servers:
        route = f"proxy {s['proxy']}" if s["proxy"] else "DIRECT (no --proxy-server)"
        mode = "isolated profile" if s["isolated"] else "persistent profile"
        window = "headless" if s["headless"] else "headed"
        age = _age(s["started_at"])
        out.append(f"  live mcp server   pid {s['pid']}  {route}  ·  {mode}  ·  {window}"
                   f"{'  ' + age if age else ''}")
        if s["proxy"] and (d["direct_marker"] or caido["browser_uses_it"] is False):
            out.append("    -> MISMATCH: this engagement asks for the direct lane but the RUNNING "
                       "server carries")
            out.append("       --proxy-server. The flags above are what the browser actually "
                       "uses; the marker and")
            out.append("       .mcp.json only bind at start. Through Caido, mail.ru RSTs the "
                       "connection and every")
            out.append("       navigation dies as net::ERR_TOO_MANY_RETRIES. Restart the "
                       "playwright MCP server.")
        if s["isolated"] and d["profile_dir"] and not d["isolated"]:
            out.append("    -> MISMATCH: --isolated, so the engagement profile and its logged-in "
                       "session are NOT")
            out.append("       loaded — an authed lane lands logged out. The server resolves the "
                       "engagement at start:")
            out.append("       set CBH_PROJECT=<platform>/<program> in .mcp.json's playwright env, "
                       "then restart it.")
    out.append(f"  engine            {d['engine']}"
               + ("" if d["engine"] == "chromium"
                  else "  (CBH_PLAYWRIGHT_BROWSER — its own profile dir, its own login)"))
    out.append(f"  chrome            {d['chrome'] or 'NOT FOUND — falling back to Playwright'
                                                    ' bundled Chromium'}")
    if not d["chrome"]:
        out.append("    -> some targets (mail.ru) RST the bundled Chromium but load in installed "
                   "Chrome.")
    out.append(f"  display           {d['display'] or 'none'}"
               f"  ->  {'headless' if d['headless'] else 'headed window'}")
    if d.get("headed_configured_in_mcp_json"):
        out.append("    -> .mcp.json sets CBH_PLAYWRIGHT_HEADED=1 for the playwright server. "
                   "Headless is bound")
        out.append("       at server start, so a server already running when that was written "
                   "is still headless;")
        out.append("       restart the client to get the window.")
    elif not d["headless"]:
        pass
    else:
        out.append("    -> no window: headed needs CBH_PLAYWRIGHT_HEADED=1 in .mcp.json's "
                   "playwright env (or")
        out.append("       a client that forces headed itself). Add it, then restart the "
                   "client.")
    if d["profile_dir"] is None:
        out.append("    -> an operator login typed into this browser is LOST at lane end: no "
                   "engagement resolved,")
        out.append("       so the profile is in-memory. `cbh browser login <program> --url <u>` "
                   "opens a headed")
        out.append("       window on the engagement's own profile dir instead, and writes "
                   "browser-state.json.")
    if not d["mcp_cli"]:
        out.append("  playwright mcp    MISSING — run `npm ci` in runtime/")
    lanes = d["lanes"]
    if not lanes:
        out.append("  live lanes        none — the profile is free")
    for lane in lanes:
        age = _age(lane["started_at"])
        out.append(f"  live lane         {lane['engagement']}  pid {lane['pid']}  "
                   f"{lane['label']}{'  ' + age if age else ''}")
        out.append("    -> one browser per profile. A second server does not queue, it waits "
                   "25 s and refuses.")
        out.append("       Another lane needs bbcurl, or CBH_PLAYWRIGHT_ISOLATED=1 for an "
                   "unauthenticated render.")
    out.append("")
    out.append("  A failed navigation is diagnosed before it is retried: "
               "`cbh browser hint` reads an")
    out.append("  error on stdin and prints the next move "
               "(engine/browser_hints.py owns that table).")
    return out


def _engine(mcp_env: dict) -> str:
    """The engine the browser lane actually runs: .mcp.json's env wins over this shell."""
    import browser_state  # type: ignore
    if (mcp_env or {}).get(browser_state.ENGINE_ENV):
        return browser_state.engine_name(mcp_env)
    return browser_state.engine_name()


def _engagement_dir(program: str) -> Path | None:
    """The engagement folder for `program`, or the one this cwd is inside."""
    import lead_queue  # type: ignore
    if program:
        return lead_queue.resolve_engagement(program)
    from pacing import Engagement  # type: ignore
    eng = Engagement.detect()
    if eng.project_dir:
        return Path(eng.project_dir)
    return lead_queue.resolve_engagement(os.environ.get("CBH_PROJECT", ""))


def login(program: str, url: str, cookie: str, port: int, wait_min: int) -> int:
    """Open a HEADED browser on the engagement's own profile so the operator can log in.

    The agent never sees the password: it picks the URL, the operator types into the
    window, and scripts/operator-login.mjs waits for the session cookie and writes
    browser-state.json next to the profile.

    The URL is scope-checked HERE because this lane does not go through
    scripts/mcp-gate.py — a CDP-driven browser is unpaced and unaudited, which is
    exactly why the one navigation it makes has to be proven in scope first. Default
    deny: no scope.md, no window.
    """
    eng = _engagement_dir(program)
    if eng is None:
        print("browser login: no engagement — pass a program name or set "
              "CBH_PROJECT=<platform>/<program>", file=sys.stderr)
        return 1
    scope_md = eng / "scope.md"
    if not scope_md.is_file():
        print(f"browser login: {scope_md} not found — default deny, no window opened",
              file=sys.stderr)
        return 1
    from scope import _scope_from_md  # type: ignore
    reason = _scope_from_md(str(scope_md)).reject_reason(url)
    if reason is not None:
        print(f"browser login: REFUSED — {reason} (scope: {scope_md})", file=sys.stderr)
        return 1

    import browser_state  # type: ignore
    # Not os.environ: the engine lives in .mcp.json's env for the playwright server,
    # so a login typed in a shell that never exported it would land in the chromium
    # profile dir while the hunting lane reads browser-profile-<engine>.
    profile = eng / browser_state.profile_dir_name(_engine(mcp_server_env()))
    state = eng / "browser-state.json"
    script = REPO / "scripts" / "operator-login.mjs"
    # The engine travels WITH the call: the operator's shell usually never exported it,
    # and the script must open the same engine whose profile dir we just resolved.
    env = dict(os.environ, LOGIN_COOKIE=cookie, CBH_PROJECT=str(program or ""),
               CBH_PLAYWRIGHT_BROWSER=_engine(mcp_server_env()))
    print(f"engagement   {eng}")
    print(f"scope        {url} is in scope per {scope_md.name}")
    print(f"cookie       waiting for '{cookie}' — override with --cookie")
    print("NOTE         this window is CDP-driven: unpaced and unaudited. Log in, nothing else.")
    import subprocess  # noqa: PLC0415
    return subprocess.call(["node", str(script), str(profile), str(state), url,
                            str(port), str(wait_min)], env=env, cwd=str(REPO))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cbh browser",
                                 description="Local browser-lane state: doctor | hint | login")
    ap.add_argument("command", nargs="?", default="doctor",
                    choices=["doctor", "hint", "login"])
    ap.add_argument("program", nargs="?", default="",
                    help="login: engagement (default: CBH_PROJECT or this folder)")
    ap.add_argument("--json", action="store_true", help="machine-readable state")
    ap.add_argument("--tool", default="playwright__browser_navigate",
                    help="hint: which tool produced the error")
    ap.add_argument("--url", default="", help="login: the page to open (scope-checked)")
    ap.add_argument("--cookie", default="", help="login: session cookie to wait for")
    ap.add_argument("--port", type=int, default=9222, help="login: CDP port")
    ap.add_argument("--wait", type=int, default=15, help="login: minutes to wait")
    args = ap.parse_args(argv)

    if args.command == "login":
        if not args.url:
            print("browser login: --url is required", file=sys.stderr)
            return 2
        return login(args.program, args.url, args.cookie or "refresh_token",
                     args.port, args.wait)

    if args.command == "hint":
        from browser_hints import hint_for  # type: ignore
        text = sys.stdin.read()
        hint = hint_for(args.tool, text)
        print(hint or "no hint for that error — read it as the target's own answer.")
        return 0

    state = collect()
    if args.json:
        print(json.dumps(state, indent=2, default=str))
        return 0
    print("\n".join(render(state)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
