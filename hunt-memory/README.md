# hunt-memory — cross-session corpus (empty on purpose)

`engine/memory.py` writes here. Nothing from a live engagement is versioned; this
directory ships as structure only.

| file | written by | contents |
|---|---|---|
| `journal.jsonl` | `/remember`, `poc_runtime` | every logged attempt — confirmed, rejected, open |
| `patterns.jsonl` | `/remember --result confirmed` | confirmed findings only; feeds `pattern-analytics.py` |
| `audit.jsonl` | `bbcurl`, `poc_runtime` | one row per request fired (gitignored — request log, pure liability in history) |
| `targets/<host>.json` | recon + hunt | per-host profile: stack, tested endpoints, open threads |
| `responses/<engagement>/<sha256>.txt` | `bbcurl` | response corpus, backs `cbh diff` / `cbh spec` (gitignored) |
| `pacing/<project>.json` | `engine/pacing.py` | flock'd pacing state, per-machine runtime (gitignored) |

Resolution walks up from cwd; `$CBH_MEMORY_DIR` overrides. Prune with
`cbh memory-gc --prune-responses <days> --rotate`.
