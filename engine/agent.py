#!/usr/bin/env python3
"""
agent.py — the engine's LLM dispatch. Only recon/hunt/validate are model-driven;
the orchestrator, scope, and state are deterministic code.

Engine = headless `claude -p`. Agents are asked to end with a fenced ```json``` block
which we parse into structured data.

**Skills do NOT auto-activate here**, despite what this docstring used to claim. The
worker gets exactly `ALLOWED_TOOLS` below, and `Skill` is not in that list, so a headless
agent cannot load a `hunt-*` skill; `skills_on=False` additionally closes the slash-command
door into the same bundle. That is deliberate — the engine's value is its deterministic
control flow, and an agent that can open 62 skills mid-run is neither reproducible nor
cheap — but it means the engine hunts with less context than an interactive session does.
Reach for the interactive `/hunt` flow when the skill knowledge is the point.

Requests leave through `Bash(bbcurl:*)` or `Bash(bbscan:*)` (both scope-gated, paced,
audited) or the MCP servers (gated by `scripts/mcp-gate.py`). Bare `curl`, `sqlmap` and
`nmap` are deliberately absent from ALLOWED_TOOLS: each would bypass every one of those.
`bbscan` is the only path to sqlmap/nmap a worker has.
"""
import json
import os
import re
import subprocess
import time

ENGINE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(ENGINE)
MCP_CONFIG = os.environ.get("CBH_MCP_CONFIG", os.path.join(WORKSPACE, ".mcp.json"))
ALLOWED_TOOLS = " ".join([
    "mcp__caido__*", "mcp__playwright__*",
    "Bash(bbcurl:*)", "Bash(bbscan:*)", "Bash(python3:*)", "Bash(jq:*)",
    "Bash(openssl:*)", "Bash(base64:*)",
])


DEFAULT_WORKER_MODEL = "claude-sonnet-5-5"



def worker_model(project=None, explicit=None):
    """The model every worker runs on, resolved in one place.

    It used to be the literal "claude-sonnet-4-6" in three files (agent.py,
    freeroam.py, engine.py), so moving the crew to a new model meant three edits and
    a forgotten one. Precedence: explicit argument > CBH_WORKER_MODEL >
    "worker_model" in the engagement's profile.json > DEFAULT_WORKER_MODEL.
    """
    if explicit:
        return explicit
    env = (os.environ.get("CBH_WORKER_MODEL") or "").strip()
    if env:
        return env
    try:
        import sys
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)
        from pacing import find_project_dir  # type: ignore
        d = find_project_dir()
        if project and d is None:
            from paths import targets_root  # type: ignore
            for cand in targets_root().glob(f"**/{project}/profile.json"):
                d = cand.parent
                break
        if d is not None and (d / "profile.json").is_file():
            m = (json.loads((d / "profile.json").read_text(encoding="utf-8"))
                 .get("worker_model") or "").strip()
            if m:
                return m
    except Exception:  # noqa: BLE001 - a broken profile must not stop the crew
        pass
    return DEFAULT_WORKER_MODEL


def run_agent(task, skills_on=False, model=None, max_turns=40, timeout=600,
              project=None, tools=None, cwd=None, session_id=None):
    """`tools` overrides ALLOWED_TOOLS for this worker, so a caller can widen it and
    let an orchestrated worker read and write the engagement's files."""
    model = worker_model(project, model)
    if not os.path.exists(MCP_CONFIG):
        return {"result":"", "error":f"missing MCP config: {MCP_CONFIG}", "duration_s":0}
    cmd = ["claude", "-p", task,
           "--mcp-config", MCP_CONFIG, "--strict-mcp-config",
           "--permission-mode", "bypassPermissions",
           "--allowedTools", (tools or ALLOWED_TOOLS),
           "--max-turns", str(max_turns), "--model", model,
           # Streamed, not a single final blob. With `--output-format json` the whole
           # run is readable only from the closing `result` event, and `claude -p`
           # killed at --max-turns never emits one: the reply comes back empty and
           # every turn of real, paced, audited probing is unrecoverable. That cost
           # 41+71 turns on 2026-10-17 and another 68 turns / $2.88 / 564 s on
           # 2026-10-20 (konsol, freeroam on web.konsol.team), the second time with
           # the raised hard cap already in place — raising the cap cannot fix it,
           # because the agent can always overrun whatever the cap is. Streaming can:
           # each assistant turn is its own line, so a killed run still has its work.
           "--output-format", "stream-json", "--verbose"]
    # A worker is its own session, so without a pinned id the operator cannot find its
    # transcript to read (it never shows up in this session's agent list — it is not a
    # sidechain). With the id pinned, the transcript path is predictable and
    # `claude --resume <id>` opens the worker's own chat.
    if session_id:
        cmd += ["--session-id", session_id]
    if not skills_on:
        cmd.append("--disable-slash-commands")
    t0 = time.time()
    try:
        env = dict(os.environ)
        # Workers keep full file access (they write recon/ and hosts/); only the
        # engagement controls are fenced, by scripts/control-guard.py keyed on this.
        # Cause: 2026-10-20 konsol INCIDENT, a freeroam worker set continuous_hunt=false.
        env["CBH_AGENT_ROLE"] = "worker"
        if project:
            env["CBH_PROJECT"] = project
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=env, cwd=cwd)
    except subprocess.TimeoutExpired as e:
        # Salvage what the worker already streamed. The kill-at-timeout path used to
        # drop `e.stdout` on the floor, so a worker that ran 100 s and emitted real
        # turns came back as {"result": "", "error": "timeout"} — the exact loss the
        # stream-json switch was made to prevent, just on the other exit path.
        # Seen 2026-10-28: 1 of 3 parallel workers, 100 s of work reported as empty.
        out = e.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        salvaged = ""
        try:
            salvaged = (_parse_stream(out) or {}).get("result") or ""
        except Exception:  # noqa: BLE001
            salvaged = ""
        return {"result": salvaged, "error": "timeout", "partial": bool(salvaged),
                "duration_s": round(time.time() - t0, 1)}
    try:
        d = _parse_stream(p.stdout)
        res = d.get("result") or ""
        # usage-limit / API errors come back as a short result with no real work
        if "usage limit" in res.lower() or "session limit" in res.lower():
            return {"result": res, "error": "rate-limited", "duration_s": round(time.time() - t0, 1)}
        process_error = None
        if p.returncode:
            process_error = (p.stderr or d.get("error") or f"claude exited {p.returncode}").strip()[:500]
        return {"result": res, "cost_usd": d.get("total_cost_usd"),
                "num_turns": d.get("num_turns"), "error": process_error,
                "partial": d.get("partial", False),
                "duration_s": round(time.time() - t0, 1)}
    except Exception as e:
        return {"result": p.stdout[:300], "error": f"parse:{e}", "duration_s": round(time.time() - t0, 1)}


def _parse_stream(stdout):
    """Fold `--output-format stream-json` NDJSON into the shape the json format gave.

    Returns the closing `result` event's fields when the run finished. When it was
    killed at --max-turns there is no such event, so the assistant turns emitted
    before the kill are concatenated instead: partial work beats no work, and the
    caller's `extract_json` can still find a block an agent emitted mid-run.
    `partial` says which of the two happened, so a caller can tell a completed run
    from a salvaged one instead of guessing from an empty error field.
    """
    texts, final = [], {}
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue  # a non-JSON line is noise, not a reason to lose the rest
        if not isinstance(ev, dict):
            continue
        if ev.get("type") == "result":
            final = ev
        elif ev.get("type") == "assistant":
            content = (ev.get("message") or {}).get("content") or []
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        t = (block.get("text") or "").strip()
                        if t:
                            texts.append(t)
    if final.get("result"):
        return {"result": final["result"], "total_cost_usd": final.get("total_cost_usd"),
                "num_turns": final.get("num_turns"), "error": final.get("error"),
                "partial": False}
    if not texts:
        # Not NDJSON at all. Keep reading the single-blob `--output-format json`
        # shape, so this stays correct if the CLI hands it back anyway.
        try:
            blob = json.loads(stdout)
        except Exception:
            blob = None
        if isinstance(blob, dict) and blob.get("result") is not None:
            return {"result": blob.get("result") or "",
                    "total_cost_usd": blob.get("total_cost_usd"),
                    "num_turns": blob.get("num_turns"), "error": blob.get("error"),
                    "partial": False}
    return {"result": "\n\n".join(texts), "total_cost_usd": final.get("total_cost_usd"),
            "num_turns": final.get("num_turns"), "error": final.get("error"),
            "partial": bool(texts)}


def extract_json(text):
    """Pull the last valid JSON array/object out of an agent reply."""
    if not text:
        return None
    blocks = re.findall(r"```json\s*(.*?)```", text, re.S)
    blocks += re.findall(r"```\s*(\[.*?\]|\{.*?\})\s*```", text, re.S)
    for b in reversed(blocks):
        try:
            return json.loads(b.strip())
        except Exception:
            pass
    for b in reversed(re.findall(r"(\[.*\]|\{.*\})", text, re.S)):
        try:
            return json.loads(b)
        except Exception:
            pass
    return None


if __name__ == "__main__":
    # offline self-test of the JSON extractor (no agent call)
    assert extract_json('blah ```json\n[{"a":1}]\n``` end') == [{"a": 1}]
    assert extract_json('text {"x": "y"} more') == {"x": "y"}
    assert extract_json("no json here") is None
    assert extract_json('first {"a":1} then ```json\n{"b":2}\n```') == {"b": 2}  # prefers fenced/last
    print("agent.py extractor self-test: PASS")
