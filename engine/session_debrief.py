#!/usr/bin/env python3
"""
session_debrief.py — the other half of session-brief: close the loop on the way out.

`session-brief.py` opens a session on facts instead of recollection. Nothing
closed the loop on the way out, so the durable record of "what did we actually
do" depended on the agent remembering to write it — and the workspace's own
logging rule says chat is not durable. When a session ended mid-sweep the
notes went stale, and the next brief opened on a fiction.

This writes a full-prose debrief into the engagement's `notes.md` as it happens
to be knowable from artefacts, never from memory:

  * requests actually fired (audit.jsonl) — the only thing that counts as work
  * findings logged and rejected this session (journal.jsonl)
  * vectors still open, with the next mutation (vectors ledger)
  * what was **not** done, stated plainly — an untried vector is not a closed one

Prose is the artefact here: `notes.md` is read back by `/pickup`, `cbh view`
and `session-brief`, so the debrief is written in full sentences, not compressed
to a scoreboard. Compressing it would be a direct loss to cross-session memory.

CLI:
    python3 engine/session_debrief.py --project Targets/kcell
    python3 engine/session_debrief.py --project Targets/kcell --print   # don't write
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

SCHEMA_VERSION = "1.0"


def _memdir(explicit: Optional[Path] = None) -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get("CBH_MEMORY_DIR")
    if env:
        return Path(env)
    for cand in (ROOT / "hunt-memory", Path.cwd() / "hunt-memory"):
        if cand.exists():
            return cand
    return Path.home() / ".cbh" / "hunt-memory"


def _tail_jsonl(path: Path, limit: int = 5000) -> List[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def _since_ts(since_minutes: int) -> float:
    return datetime.now(timezone.utc).timestamp() - since_minutes * 60


def _ts(row: dict) -> float:
    for key in ("ts", "timestamp", "at", "time"):
        v = row.get(key)
        if v is None:
            continue
        if isinstance(v, (int, float)):
            return float(v)
        try:
            return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
        except Exception:
            continue
    return 0.0


def collect(project: Path, *, since_minutes: int = 720,
            memdir: Optional[Path] = None) -> dict:
    mem = _memdir(memdir)
    cutoff = _since_ts(since_minutes)
    engagement = project.name

    audit = [r for r in _tail_jsonl(mem / "audit.jsonl") if _ts(r) >= cutoff]
    if engagement:
        scoped = [r for r in audit if r.get("engagement") in (None, "", engagement)]
        audit = scoped or audit  # fall back to the whole window if labels are missing

    journal = [r for r in _tail_jsonl(mem / "journal.jsonl") if _ts(r) >= cutoff]
    if engagement:
        journal = [r for r in journal
                   if r.get("target") in (None, "", engagement)
                   or r.get("engagement") in (None, "", engagement)]

    findings = [r for r in journal
                if (r.get("result") or r.get("outcome") or "").lower()
                in ("confirmed", "submitted", "accepted", "paid", "partial")]
    rejected = [r for r in journal
                if (r.get("result") or r.get("outcome") or "").lower()
                in ("rejected", "na", "duplicate", "downgraded")]

    hosts = sorted({(r.get("host") or _host_of(r.get("url", "")))
                    for r in audit if (r.get("host") or r.get("url"))})
    hosts = [h for h in hosts if h]

    # Vectors still open — the honest "what is left".
    open_vectors: List[dict] = []
    try:
        import vectors as V  # type: ignore
        ledger = V.load(engagement, memdir=mem)
        for v in (ledger.get("vectors") or []):
            status = (v.get("status") or "").lower()
            if status in ("dead", "confirmed", "closed"):
                continue
            nxt = V.next_mutation(v)
            open_vectors.append({
                "id": v.get("id"), "class": v.get("class") or v.get("vclass"),
                "endpoint": v.get("endpoint") or v.get("target"),
                "status": status or "open",
                "requests_fired": v.get("requests_fired", 0),
                "next_mutation": nxt,
            })
    except Exception:
        pass

    return {
        "schema_version": SCHEMA_VERSION,
        "project": str(project),
        "engagement": engagement,
        "window_minutes": since_minutes,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "requests_fired": len(audit),
            "findings_logged": len(findings),
            "rejections_logged": len(rejected),
            "hosts_touched": len(hosts),
            "open_vectors": len(open_vectors),
        },
        "hosts": hosts,
        "findings": [{k: r.get(k) for k in
                      ("target", "endpoint", "vuln_class", "severity", "result",
                       "technique", "notes") if r.get(k) is not None} for r in findings],
        "rejected": [{k: r.get(k) for k in
                      ("target", "endpoint", "vuln_class", "result", "technique", "notes")
                      if r.get(k) is not None} for r in rejected][:40],
        "open_vectors": open_vectors,
        "urls_fired": [r.get("url") for r in audit if r.get("url")][:80],
    }


def _host_of(url: str) -> str:
    try:
        import urllib.parse
        return urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        return ""


def to_prose(data: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    c = data["counts"]
    lines = [f"## Session debrief — {now}", ""]
    lines.append(
        f"Окно {data['window_minutes']} мин. Отправлено запросов: **{c['requests_fired']}** "
        f"на {c['hosts_touched']} хост(ах). В журнал попало находок: **{c['findings_logged']}**, "
        f"отклонённых/пустых попыток: **{c['rejections_logged']}**. "
        f"Открытыми остаются векторы: **{c['open_vectors']}**.")
    lines.append("")

    if data["hosts"]:
        lines.append("### Хосты, по которым реально уходили запросы")
        lines.append("")
        for h in data["hosts"]:
            lines.append(f"- `{h}`")
        lines.append("")

    if data["findings"]:
        lines.append("### Что залогировано как находка")
        lines.append("")
        for f in data["findings"]:
            sev = f.get("severity") or "?"
            lines.append(f"- **{f.get('vuln_class') or 'unclassified'}** ({sev}) на "
                         f"`{f.get('endpoint') or f.get('target')}` — {f.get('notes') or ''}")
        lines.append("")

    if data["rejected"]:
        lines.append("### Что проверено и отвергнуто (это тоже результат)")
        lines.append("")
        for f in data["rejected"][:20]:
            lines.append(f"- `{f.get('endpoint') or f.get('target')}` — "
                         f"{f.get('technique') or f.get('vuln_class') or ''} "
                         f"[{f.get('result')}] {f.get('notes') or ''}")
        lines.append("")

    if data["open_vectors"]:
        lines.append("### Открытые векторы и следующая мутация")
        lines.append("")
        for v in data["open_vectors"]:
            nxt = v.get("next_mutation") or "следующая мутация из `vectors.py rotate`"
            lines.append(f"- `{v.get('id')}` {v.get('class')} на `{v.get('endpoint')}` "
                         f"— status {v.get('status')}, запросов {v.get('requests_fired')}; "
                         f"далее: {nxt}")
        lines.append("")
    else:
        lines.append("### Открытых векторов нет")
        lines.append("")
        lines.append("Если это не доказанное исчерпание — прогони `cbh vectors next "
                     "<host>` / свежий `/recon`, а не закрывай хост.")
        lines.append("")

    lines.append("### Чего в этой сессии не было")
    lines.append("")
    lines.append("- Запросы, которые не уходили, остаются гипотезами: план/аномалия "
                 "без `.result.json` — открытый тред, не результат.")
    lines.append("- Ничего из перечисленного выше не закрыто по одному тому, что сессия "
                 "закончилась; закрывает только `vectors.py mark` с реально отправленными "
                 "запросами или явное решение оператора.")
    lines.append("")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True,
                    help="engagement dir, e.g. Targets/kcell")
    ap.add_argument("--since-minutes", type=int, default=720,
                    help="look-back window for this debrief (default 12h)")
    ap.add_argument("--dir", type=Path, default=None, help="hunt-memory directory")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="print the debrief instead of appending to notes.md")
    ap.add_argument("--out", type=Path, default=None,
                    help="write the prose here instead of notes.md")
    args = ap.parse_args(argv)

    project = Path(args.project).expanduser().resolve()
    if not project.exists():
        print(f"[error] no such project: {project}", file=sys.stderr)
        return 2

    data = collect(project, since_minutes=args.since_minutes, memdir=args.dir)
    prose = to_prose(data)

    if args.print_only:
        sys.stdout.write(prose)
        return 0

    target = args.out or (project / "notes.md")
    with open(target, "a", encoding="utf-8") as fh:
        fh.write("\n" + prose + "\n")
    print(f"{target}: appended debrief "
          f"({data['counts']['requests_fired']} requests, "
          f"{data['counts']['open_vectors']} open vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
