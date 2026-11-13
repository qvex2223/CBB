#!/usr/bin/env bash
# caido-up — bring the Caido proxy up, idempotently. Safe to call on every hunt.
#
# Caido is the only thing on this box that can answer "what actually happened on
# the wire" (redirect chains, cookie/session state across a flow, replaying a
# captured request), and it does not survive a reboot: it was started by hand, so
# every session after a restart found `ECONNREFUSED 127.0.0.1:8080` and quietly
# hunted without the last-mile tool. Operator directive 2026-10-16: start it
# automatically before every hunt instead of printing instructions.
#
# Idempotent by design — if something is already listening on the port this exits 0
# without touching it, so calling it from a hook, from `cbh tools doctor --start`
# and by hand in the same minute cannot produce two instances fighting over one
# project directory.
#
#   scripts/caido-up.sh            # start if needed, wait for the port, report
#   scripts/caido-up.sh --quiet    # same, but silent unless it actually failed
#   scripts/caido-up.sh --status   # report only, never start anything
#
# CBH_CAIDO_AUTOSTART=off makes the hooks skip calling this entirely; running the
# script by hand still works, because that is an explicit decision.
set -uo pipefail

PORT="${CBH_CAIDO_PORT:-8080}"
HOST="${CBH_CAIDO_HOST:-127.0.0.1}"
BIN="${CBH_CAIDO_BIN:-$HOME/security-research/tools/caido/bin/caido-cli}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="$REPO/logs/caido.log"
WAIT_SECONDS="${CBH_CAIDO_WAIT:-25}"

QUIET=0
STATUS_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --quiet) QUIET=1 ;;
    --status) STATUS_ONLY=1 ;;
    *) echo "caido-up: unknown argument: $arg" >&2; exit 64 ;;
  esac
done

say() { [ "$QUIET" = 1 ] || echo "$@"; }

listening() {
  # No `ss`/`lsof` dependency: bash's own /dev/tcp is enough to answer this.
  (exec 3<>"/dev/tcp/$HOST/$PORT") 2>/dev/null && exec 3<&- 2>/dev/null
}

if listening; then
  say "caido: already up on $HOST:$PORT"
  exit 0
fi

if [ "$STATUS_ONLY" = 1 ]; then
  echo "caido: DOWN ($HOST:$PORT)"
  exit 1
fi

if [ ! -x "$BIN" ]; then
  echo "caido: binary not found or not executable: $BIN" >&2
  echo "caido: see docs/caido.md (install + provenance)" >&2
  exit 127
fi

mkdir -p "$(dirname "$LOG")"
# --no-open: headless, no browser. --no-sync: nothing leaves this machine for
# Caido's cloud sync. setsid so the proxy outlives the hook/session that started it.
setsid nohup "$BIN" --listen "$HOST:$PORT" --no-open --no-sync >>"$LOG" 2>&1 &
pid=$!

for _ in $(seq 1 "$WAIT_SECONDS"); do
  if listening; then
    say "caido: started (pid $pid) on $HOST:$PORT — log: $LOG"
    exit 0
  fi
  kill -0 "$pid" 2>/dev/null || break
  sleep 1
done

if listening; then
  say "caido: started (pid $pid) on $HOST:$PORT — log: $LOG"
  exit 0
fi

echo "caido: FAILED to come up within ${WAIT_SECONDS}s — last log lines:" >&2
tail -n 5 "$LOG" >&2 2>/dev/null
echo "caido: hunting can continue through bbcurl; the wire-level tool is missing." >&2
exit 1
