---
name: view
description: Deterministic backing is `cbh view <project-dir>` — reads a Targets/<name>/ project's findings/*.md, hosts/*.md and notes.md, writes a local, self-contained dashboard.html (severity tiles, findings table, host activity, open threads). Read-only, local file only, never uploaded anywhere. Usage: /view <project-dir>
---

# /view

Generate a local, browsable dashboard over an engagement's markdown notes —
the equivalent of usestrix/strix's `strix view`, but over this repo's
markdown-native `Targets/<name>/{findings,hosts,notes.md}` layout instead of
a run-output directory.

## What This Does

1. Reads every `findings/*.md` — best-effort extracts title, severity,
   status, CVE ID, last date mentioned.
2. Reads every `hosts/*.md` — title, last-touched date, line count (rough
   depth-of-investigation signal), a "final status" line if present.
3. Reads `notes.md`'s `## Open Threads` section if present.
4. Writes a single self-contained `dashboard.html` — no external requests,
   no JS dependencies, works offline, respects light/dark via
   `prefers-color-scheme`.

## Usage

```
/view Targets/acme
```

Under the hood:

```bash
python3 cbh/cli.py view ~/Targets/acme
# or, if cbh is on PATH:
cbh view ~/Targets/acme --out /custom/path/dashboard.html
```

Default output path is `<project>/dashboard.html`.

## Notes

- **Best-effort parsing, not authoritative.** Findings/host files are prose,
  not strict frontmatter — severity may show `Unknown` if a finding's
  severity is written as free-form/in-flux text (e.g. "stale, needs
  re-scoring"). Treat the dashboard as a navigation aid, not a source of
  truth; the markdown files remain authoritative.
- **Never published.** This writes a local file only — do not run it through
  the `Artifact` tool or any external hosting; engagement notes can contain
  real client infrastructure detail and are not for third-party services.
- Re-run any time notes change — it's cheap and fully deterministic.

## Related

- `notes.md` / `hosts/<host>.md` / `findings/*.md` — the source of truth this
  reads from; keep logging discipline there per this workspace's CLAUDE.md.
