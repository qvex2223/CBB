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

Requests leave through `Bash(bbcurl:*)` (scope-gated, paced, audited) or the MCP servers
(gated by `scripts/mcp-gate.py`). Bare `curl` is deliberately absent from ALLOWED_TOOLS:
it would bypass every one of those.
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
    "mcp__burpmcp__*", "mcp__playwright__*",
    "Bash(bbcurl:*)", "Bash(python3:*)", "Bash(jq:*)", "Bash(openssl:*)", "Bash(base64:*)",
])


def run_agent(task, skills_on=False, model="claude-sonnet-4-6", max_turns=40, timeout=600,
              project=None):
    if not os.path.exists(MCP_CONFIG):
        return {"result":"", "error":f"missing MCP config: {MCP_CONFIG}", "duration_s":0}
    cmd = ["claude", "-p", task,
           "--mcp-config", MCP_CONFIG, "--strict-mcp-config",
           "--permission-mode", "bypassPermissions",
           "--allowedTools", ALLOWED_TOOLS,
           "--max-turns", str(max_turns), "--model", model,
           "--output-format", "json"]
    if not skills_on:
        cmd.append("--disable-slash-commands")
    t0 = time.time()
    try:
        env = dict(os.environ)
        if project:
            env["CBH_PROJECT"] = project
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return {"result": "", "error": "timeout", "duration_s": round(time.time() - t0, 1)}
    try:
        d = json.loads(p.stdout)
        res = d.get("result") or ""
        # usage-limit / API errors come back as a short result with no real work
        if "usage limit" in res.lower() or "session limit" in res.lower():
            return {"result": res, "error": "rate-limited", "duration_s": round(time.time() - t0, 1)}
        process_error = None
        if p.returncode:
            process_error = (p.stderr or d.get("error") or f"claude exited {p.returncode}").strip()[:500]
        return {"result": res, "cost_usd": d.get("total_cost_usd"),
                "num_turns": d.get("num_turns"), "error": process_error,
                "duration_s": round(time.time() - t0, 1)}
    except Exception as e:
        return {"result": p.stdout[:300], "error": f"parse:{e}", "duration_s": round(time.time() - t0, 1)}


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
