#!/usr/bin/env bash
#
# Keyhole sync server — one-click launcher and control script for Linux/macOS.
#
#   start-keyhole-server.sh            start it (or just show it, if running)
#   start-keyhole-server.sh stop
#   start-keyhole-server.sh restart
#   start-keyhole-server.sh status
#   start-keyhole-server.sh logs
#
# Double-click the file, or use the "Keyhole Sync Server" application entry —
# its right-click menu maps to the subcommands above.
#
# Where a systemd user service named keyhole-sync.service exists, every
# subcommand drives that, so the icon and `systemctl --user` cannot disagree
# about what is running. Without one it falls back to running the server in the
# foreground, which is what makes this work on a machine that has never been
# set up. For day-to-day development `npm run dev:server` is still the direct
# route; this exists so none of it requires a terminal.

set -euo pipefail

# Everything below is resolved from this script's own location, never from the
# working directory. A launcher's working directory is wherever the file
# manager happened to be, and KEYHOLE_DB is relative by default — left to
# drift, launching from two places would quietly create two separate empty
# databases, which is indistinguishable from losing every account you had
# registered. Same reasoning as the tray app; see ../server-tray/README.md.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

PORT="${KEYHOLE_PORT:-8787}"
URL="http://127.0.0.1:$PORT"
SERVICE="keyhole-sync.service"

# Loopback, overriding the server's own 0.0.0.0 default. That default is
# reasonable for a deliberate deployment behind a firewall and a bad one for
# something you launch by double-clicking: it would publish a password-sync
# service to every network you join, including untrusted Wi-Fi. Exposing it to
# other devices should be a decision — server/README.md covers doing it with
# TLS, which is not optional once the credential leaves this machine. A
# `tailscale serve` proxy connects from 127.0.0.1 and needs no change here.
export KEYHOLE_HOST=127.0.0.1
export KEYHOLE_PORT="$PORT"
export KEYHOLE_DB="$REPO_ROOT/server/data/keyhole.sqlite"

# Launched from an icon there may be no terminal at all, so say things twice:
# once on stdout for when there is one, once to the desktop for when there is
# not. Neither is allowed to fail the script.
note() {
  printf '  %s\n' "$1"
  if command -v notify-send >/dev/null 2>&1; then
    notify-send --app-name="Keyhole Sync" --icon=network-server "Keyhole Sync" "$1" >/dev/null 2>&1 || true
  fi
}

die() {
  printf '\n  %s\n\n' "$*" >&2
  if command -v notify-send >/dev/null 2>&1; then
    notify-send --app-name="Keyhole Sync" --icon=dialog-error --urgency=critical "Keyhole Sync" "$*" >/dev/null 2>&1 || true
  fi
  # Launched from a file manager this window is all the user sees, so a failure
  # has to stay on screen rather than flashing past as the terminal closes.
  if [ -t 0 ]; then
    printf '  Press Enter to close.\n' >&2
    read -r _ || true
  fi
  exit 1
}

open_url() { command -v xdg-open >/dev/null 2>&1 && xdg-open "$URL" >/dev/null 2>&1 || true; }

is_healthy() { curl -fsS --max-time 2 "$URL/api/v1/health" >/dev/null 2>&1; }

# Poll rather than sleeping a fixed amount: opening the browser before the
# server answers lands the user on a connection error.
wait_healthy() {
  for _ in $(seq 1 100); do
    is_healthy && return 0
    sleep 0.2
  done
  return 1
}

have_service() {
  command -v systemctl >/dev/null 2>&1 && systemctl --user cat "$SERVICE" >/dev/null 2>&1
}

listener_pid() {
  command -v ss >/dev/null 2>&1 || return 1
  ss -ltnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | head -1
}

check_runtime() {
  command -v node >/dev/null 2>&1 || die "Node is not installed.
  The Keyhole server needs Node 22.5 or newer:
      sudo snap refresh node --channel=24/stable"

  # node:sqlite and TypeScript type stripping both arrived in 22.5. Below that
  # the server does not fail gracefully, it fails on an import.
  local v major minor
  v="$(node -p 'process.versions.node')"
  major="${v%%.*}"
  minor="$(printf '%s' "$v" | cut -d. -f2)"
  if [ "$major" -lt 22 ] || { [ "$major" -eq 22 ] && [ "$minor" -lt 5 ]; }; then
    die "Node $v is too old.
  The Keyhole server needs 22.5 or newer for node:sqlite:
      sudo snap refresh node --channel=24/stable"
  fi

  if [ ! -d "$REPO_ROOT/node_modules/fastify" ]; then
    printf '\n  Installing dependencies (first run only)…\n\n'
    (cd "$REPO_ROOT" && npm install) || die "npm install failed — run it by hand in $REPO_ROOT to see why."
  fi
}

cmd_start() {
  # Already up: treat the click as "show me the server" rather than starting a
  # second copy that could only collide on the port.
  if is_healthy; then
    note "Already running at $URL"
    open_url
    exit 0
  fi

  if have_service; then
    systemctl --user start "$SERVICE" || die "systemctl --user start $SERVICE failed.
  See: journalctl --user -u $SERVICE -n 50"
    wait_healthy || die "The service started but never answered on $URL.
  See: journalctl --user -u $SERVICE -n 50"
    note "Started · $URL"
    open_url
    exit 0
  fi

  # No service on this machine: run it here, in the foreground.
  check_runtime
  printf '\n  Keyhole sync server\n'
  printf '  %s\n' "$URL"
  printf '  vault database: %s\n' "$KEYHOLE_DB"
  printf '  Ctrl+C to stop.\n\n'
  ( wait_healthy && open_url ) &
  # exec, so Ctrl+C reaches the server itself instead of an npm wrapper that
  # would leave it orphaned and still holding the port.
  cd "$REPO_ROOT"
  exec node --experimental-strip-types server/src/index.ts
}

cmd_stop() {
  if have_service; then
    systemctl --user stop "$SERVICE" || die "systemctl --user stop $SERVICE failed."
    note "Stopped"
    return
  fi
  local pid
  pid="$(listener_pid || true)"
  if [ -n "${pid:-}" ]; then
    kill "$pid" && note "Stopped (pid $pid)"
  else
    note "Not running"
  fi
}

cmd_restart() {
  if have_service; then
    systemctl --user restart "$SERVICE" || die "systemctl --user restart $SERVICE failed.
  See: journalctl --user -u $SERVICE -n 50"
    wait_healthy || die "Restarted but never answered on $URL.
  See: journalctl --user -u $SERVICE -n 50"
    note "Restarted · $URL"
    return
  fi
  cmd_stop
  sleep 1
  cmd_start
}

cmd_status() {
  if have_service; then
    systemctl --user status "$SERVICE" --no-pager || true
  else
    local pid
    pid="$(listener_pid || true)"
    [ -n "${pid:-}" ] && printf '  Running (pid %s)\n' "$pid" || printf '  Not running\n'
  fi
  printf '\n  Health: '
  is_healthy && printf 'OK — %s\n' "$URL" || printf 'no response on %s\n' "$URL"
  printf '  Database: %s\n\n' "$KEYHOLE_DB"
  # `if`, not `[ -t 0 ] && …`: as the last statement in the function a false
  # test would become the return value, and under `set -e` that exits 1 every
  # time this runs without a terminal.
  if [ -t 0 ]; then
    printf '  Press Enter to close.\n'
    read -r _ || true
  fi
}

cmd_logs() {
  if have_service; then
    journalctl --user -u "$SERVICE" -n 200 -f
  else
    die "No $SERVICE on this machine — logs go to the window the server is running in."
  fi
}

case "${1:-start}" in
  start | '') cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_restart ;;
  status) cmd_status ;;
  logs) cmd_logs ;;
  -h | --help | help)
    printf 'usage: %s [start|stop|restart|status|logs]\n' "$(basename "$0")"
    ;;
  *) die "Unknown command: $1
  usage: $(basename "$0") [start|stop|restart|status|logs]" ;;
esac
