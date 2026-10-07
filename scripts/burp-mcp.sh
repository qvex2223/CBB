#!/usr/bin/env bash
# burp-mcp — start / stop / check the Burp Suite MCP server this workspace talks to.
#
# The MCP entry in /opt/Claude/.mcp.json points at http://localhost:8181/mcp/sse,
# which is BurpMCP's SSE endpoint. That URL only answers while Burp is actually
# running, and Burp is a GUI app: on this box it runs against a virtual X display.
# Previously it was started by hand (and the whole stack lived in /tmp, one reboot
# away from gone), so "the Burp MCP is broken" really meant "nobody started Burp".
#
#   burp-mcp.sh start     boot Xvfb if needed, launch Burp with BurpMCP loaded,
#                         click through the startup wizard, switch the MCP server
#                         on, and wait until the port answers
#   burp-mcp.sh status    is the port up? is Burp running? what does MCP say?
#   burp-mcp.sh stop      kill the Burp process (leaves Xvfb alone)
#   burp-mcp.sh logs      tail the launch log
#
# Everything is overridable: BURP_HOME, BURP_MCP_PORT, BURP_DISPLAY.
set -uo pipefail

BURP_HOME="${BURP_HOME:-/opt/Claude/tools/burp}"
BURP_JAR="$BURP_HOME/burpsuite_community.jar"
BURP_EXT="$BURP_HOME/BurpMCP.jar"
BURP_CONF="$BURP_HOME/user-config.json"
JAVA_BIN="${JAVA_BIN:-$BURP_HOME/jdk-21.0.11+10-jre/bin/java}"
PORT="${BURP_MCP_PORT:-8181}"
DISPLAY_NUM="${BURP_DISPLAY:-:99}"
LOG="$BURP_HOME/burp-launch.log"
ROBOT="$BURP_HOME/RobotTool.class"   # java.awt.Robot clicker, for the GUI wizard
PIDFILE="$BURP_HOME/burp.pid"
WAIT_SECONDS="${BURP_WAIT:-120}"

port_up() { (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && exec 3<&- && return 0 || return 1; }
burp_pid() { pgrep -f -- "$BURP_JAR" | head -1; }

cmd_status() {
  local pid; pid="$(burp_pid)"
  echo "burp process : ${pid:-not running}"
  echo "display      : $DISPLAY_NUM ($(pgrep -f "Xvfb $DISPLAY_NUM" >/dev/null && echo 'Xvfb up' || echo 'no Xvfb'))"
  if port_up; then
    echo "mcp port     : $PORT open"
    echo "mcp endpoint : http://localhost:$PORT/mcp/sse"
    return 0
  fi
  echo "mcp port     : $PORT CLOSED — the MCP server will show as failed in Claude Code"
  echo "fix          : $0 start"
  return 1
}

# Burp Community has no headless mode and no way to skip its startup wizard, so
# the wizard gets clicked. Coordinates are for the 1920x1080 virtual screen this
# script creates; every click is verified by the thing it is supposed to produce
# (the MCP port opening), never assumed.
robot() { DISPLAY="$DISPLAY_NUM" "$JAVA_BIN" -cp "$BURP_HOME" RobotTool "$@" 2>/dev/null; }

enable_mcp_server() {
  robot click 1383 143 >/dev/null   # BurpMCP tab
  sleep 2
  robot click 980 183  >/dev/null   # "MCP Server: Disabled" -> enabled (x=1047 is dead space inside the button; 980 works — verified 2026-09-26)
  sleep 3
}

click_through_wizard() {
  echo "clicking through the startup wizard"
  sleep 12
  robot key escape >/dev/null       # dismiss any stray dialog without hunting for its buttons
  sleep 1
  robot click 1366 831 >/dev/null   # "Next" — temporary project in memory
  sleep 3
  robot click 551 758  >/dev/null   # "Default to the above in future"
  sleep 1
  robot click 1345 831 >/dev/null   # "Start Burp"
  sleep 20
  enable_mcp_server
}

cmd_start() {
  # All clients share one GUI/proxy. Serialize startup and recheck under the lock.
  exec 9>"$BURP_HOME/start.lock"
  flock -w 180 9 || { echo "another Burp startup is still in progress"; exit 1; }
  for f in "$BURP_JAR" "$BURP_EXT" "$JAVA_BIN"; do
    [ -e "$f" ] || { echo "missing: $f"; echo "set BURP_HOME to where the Burp stack lives."; exit 2; }
  done
  if port_up; then echo "already up: http://localhost:$PORT/mcp/sse"; exit 0; fi

  # Burp already running, port closed: the MCP server is just switched off. Flip it
  # rather than starting a second instance fighting for the same port.
  if [ -n "$(burp_pid)" ]; then
    echo "burp is running (pid $(burp_pid)) but the MCP server is off — enabling it"
    enable_mcp_server
    if port_up; then echo "up: http://localhost:$PORT/mcp/sse"; exit 0; fi
    echo "could not enable it from here; showing what Burp displays:"
    robot screenshot "$BURP_HOME/burp-stuck.png" >/dev/null && echo "$BURP_HOME/burp-stuck.png"
    exit 1
  fi

  if ! pgrep -f "Xvfb $DISPLAY_NUM" >/dev/null; then
    rm -f /tmp/.X${DISPLAY_NUM#:}-lock "/tmp/.X11-unix/X${DISPLAY_NUM#:}" 2>/dev/null  # stale lock from a crashed run blocks Xvfb
  echo "starting Xvfb on $DISPLAY_NUM"
    nohup Xvfb "$DISPLAY_NUM" -screen 0 1920x1080x24 >"$BURP_HOME/xvfb.log" 2>&1 9>&- &
    sleep 2
  fi

  echo "starting Burp (extension: BurpMCP, config: $BURP_CONF)"
  DISPLAY="$DISPLAY_NUM" nohup "$JAVA_BIN" \
    -Djava.awt.headless=false \
    -Xmx2g \
    -jar "$BURP_JAR" \
    --user-config-file="$BURP_CONF" \
    --disable-auto-update \
    >"$LOG" 2>&1 9>&- &
  echo $! >"$PIDFILE"

  if [ -f "$ROBOT" ]; then
    click_through_wizard
  else
    echo "no RobotTool.class in $BURP_HOME — finish the wizard yourself on $DISPLAY_NUM"
  fi

  echo -n "waiting for the MCP port"
  for _ in $(seq 1 "$WAIT_SECONDS"); do
    if port_up; then
      echo
      echo "up: http://localhost:$PORT/mcp/sse"
      echo "Claude Code reads .mcp.json at session start — restart the session, /mcp to verify."
      exit 0
    fi
    echo -n "."
    sleep 1
  done
  echo
  echo "timed out after ${WAIT_SECONDS}s."
  robot screenshot "$BURP_HOME/burp-stuck.png" >/dev/null && \
    echo "screenshot of what Burp is showing: $BURP_HOME/burp-stuck.png"
  echo "last lines of $LOG:"
  tail -10 "$LOG"
  echo "Most likely: a wizard button moved. Look at the screenshot, then either click"
  echo "it by hand (DISPLAY=$DISPLAY_NUM) or fix the coordinates in click_through_wizard()."
  exit 1
}

cmd_stop() {
  local pid; pid="$(burp_pid)"
  if [ -z "$pid" ]; then echo "burp is not running"; exit 0; fi
  kill "$pid" && echo "stopped burp (pid $pid)"
}

case "${1:-status}" in
  start)  cmd_start ;;
  stop)   cmd_stop ;;
  status) cmd_status ;;
  screenshot) shift; robot screenshot "${1:-$BURP_HOME/burp-screen.png}" ;;
  logs)   tail -40 "$LOG" ;;
  *)      echo "usage: $0 {start|stop|status|logs}"; exit 2 ;;
esac
