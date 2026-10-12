# FROZEN 2026-09-27 — this workspace is retired, read-only

Live workspace: **/opt/Devin-2.0** (agent rules: `AGENTS.md` there; this `CLAUDE.md` is kept for history).

What changed on freeze:
- `hunt-memory/` is now a symlink → `/opt/Devin-2.0/hunt-memory` (single corpus — the pre-merge
  directory is preserved at `hunt-memory.merged-20260927/`). Nothing written here is lost; new
  writes from either runtime land in one place.
- The engagement `Targets/ozon` was copied to `/opt/Devin-2.0/Targets/ozon` (this copy is the
  frozen record — edit the Devin-2.0 one).
- All cron jobs pointing at `/opt/Claude-BugHunter` and `/opt/Devin` were commented out
  (backup: `/tmp/crontab.bak-20260927`); equivalent jobs now run under `/opt/Devin-2.0`.
- `cbh`/`bbcurl` in `~/.local/bin` still resolve to `/opt/Claude-BugHunter/scripts/` — left in
  place deliberately; they still work, and their writes now reach the shared corpus.
