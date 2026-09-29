#!/bin/bash
# install-recon-snapshot.sh — opt-in daily recon-delta pass for one engagement.
#
# This installs the SNAPSHOT + DIFF step only. It performs no requests: it reads the
# manifests recon already produced, writes recon/<target>/hunt-queue.md for the high-risk
# deltas, and seeds the vector ledger so `cbh vectors next` surfaces new attack surface.
#
# Scheduling the recon RUN itself is deliberately not automated here. A cron job that
# sends requests at a live bug-bounty program is the operator's decision — pacing, scope
# and the program's own rules all apply, and none of them should be inherited from an
# installer. Run `cbh recon <target>` yourself, or add it to this entry knowingly.
#
# Note on this box: WSL is off at night, and cron here has no anacron catch-up — the same
# gap that silently hid two live CVEs between 2026-08-19 and 2026-08-27. The entry below
# therefore also runs @reboot, and the two no-op each other via the stamp file.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENGAGEMENT="${1:-}"

if [[ -z "$ENGAGEMENT" ]]; then
  echo "usage: $0 /path/to/Targets/<name> [HH:MM]"
  echo
  echo "Runs the snapshot/diff pass for every recon/<target>/manifest.json in that"
  echo "engagement. Nothing is sent to any target."
  exit 2
fi

if [[ ! -d "$ENGAGEMENT/recon" ]]; then
  echo "no recon/ directory under $ENGAGEMENT — run \`cbh recon <target>\` first"
  exit 2
fi

AT="${2:-08:15}"
HOUR="${AT%%:*}"
MINUTE="${AT##*:}"
LOG="$PROJECT_ROOT/logs/recon-snapshot.log"
STAMP="$PROJECT_ROOT/logs/stamps/recon-snapshot-$(basename "$ENGAGEMENT")"
mkdir -p "$PROJECT_ROOT/logs/stamps"

CMD="python3 $SCRIPT_DIR/recon-snapshot.py --project $ENGAGEMENT --all >> $LOG 2>&1 && touch $STAMP"
DAILY="$MINUTE $HOUR * * * $CMD"
# @reboot catch-up: only if the stamp is older than 20h, so the two never double-fire.
BOOT="@reboot sleep 120 && [ ! -f $STAMP -o -n \"\$(find $STAMP -mmin +1200 2>/dev/null)\" ] && $CMD"

echo "Installing recon-snapshot for $(basename "$ENGAGEMENT") at $AT daily:"
echo "  $DAILY"
echo "  $BOOT"
echo
read -r -p "Add these crontab entries? [y/N] " reply
[[ "$reply" =~ ^[Yy]$ ]] || { echo "aborted — nothing changed"; exit 0; }

BACKUP="$PROJECT_ROOT/logs/crontab.bak-$(date +%Y%m%d%H%M%S)"
crontab -l > "$BACKUP" 2>/dev/null || true
echo "crontab backed up to $BACKUP"

( crontab -l 2>/dev/null | grep -v "recon-snapshot.py --project $ENGAGEMENT"
  echo "$DAILY"
  echo "$BOOT" ) | crontab -

echo "installed. Check $LOG after the first run."
echo "Remove with: crontab -e   (or restore $BACKUP)"
