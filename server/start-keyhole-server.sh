#!/usr/bin/env bash
#
# Keyhole sync server — one-click launcher for Linux and macOS.
#
# Double-click this file (or the "Keyhole Sync Server" entry in your
# applications menu) and the server comes up on http://127.0.0.1:8787 with the
# status page open in your browser. Press Ctrl+C, or close the window, to stop.
#
# For day-to-day development `npm run dev:server` does the same thing; this
# exists so starting the server does not require a terminal.

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

# Loopback, overriding the server's own 0.0.0.0 default. That default is
# reasonable for a deliberate deployment behind a firewall and a bad one for
# something you launch by double-clicking: it would publish a password-sync
# service to every network you join, including untrusted Wi-Fi. Exposing it to
# other devices should be a decision — server/README.md covers doing it with
# TLS, which is not optional once the credential leaves this machine.
export KEYHOLE_HOST=127.0.0.1
export KEYHOLE_PORT="$PORT"
export KEYHOLE_DB="$REPO_ROOT/server/data/keyhole.sqlite"

# Launched from a file manager, this window is all the user sees — so failures
# have to stay on screen rather than flashing past as the terminal closes.
die() {
  printf '\n  %s\n\n' "$*" >&2
  if [ -t 0 ]; then
    printf '  Press Enter to close.\n' >&2
    read -r _ || true
  fi
  exit 1
}

command -v node >/dev/null 2>&1 || die "Node is not installed.
  The Keyhole server needs Node 22.5 or newer:
      sudo snap refresh node --channel=24/stable"

# node:sqlite and TypeScript type stripping both arrived in 22.5. Below that
# the server does not fail gracefully, it fails on an import.
node_version="$(node -p 'process.versions.node')"
node_major="${node_version%%.*}"
node_minor="$(printf '%s' "$node_version" | cut -d. -f2)"
if [ "$node_major" -lt 22 ] || { [ "$node_major" -eq 22 ] && [ "$node_minor" -lt 5 ]; }; then
  die "Node $node_version is too old.
  The Keyhole server needs 22.5 or newer for node:sqlite:
      sudo snap refresh node --channel=24/stable"
fi

# Starting a second copy would only collide on the port. Treat the click as
# "show me the server" instead.
if curl -fsS --max-time 2 "$URL/api/v1/health" >/dev/null 2>&1; then
  printf '\n  Keyhole sync is already running at %s\n\n' "$URL"
  command -v xdg-open >/dev/null 2>&1 && xdg-open "$URL" >/dev/null 2>&1 || true
  exit 0
fi

if [ ! -d "$REPO_ROOT/node_modules/fastify" ]; then
  printf '\n  Installing dependencies (first run only)…\n\n'
  (cd "$REPO_ROOT" && npm install) || die "npm install failed — run it by hand in $REPO_ROOT to see why."
fi

printf '\n  Keyhole sync server\n'
printf '  %s\n' "$URL"
printf '  vault database: %s\n' "$KEYHOLE_DB"
printf '  Ctrl+C to stop.\n\n'

# Open the status page once the server actually answers, rather than racing it
# and landing on a connection error.
(
  for _ in $(seq 1 100); do
    if curl -fsS --max-time 1 "$URL/api/v1/health" >/dev/null 2>&1; then
      command -v xdg-open >/dev/null 2>&1 && xdg-open "$URL" >/dev/null 2>&1 || true
      exit 0
    fi
    sleep 0.2
  done
) &

# exec, so Ctrl+C reaches the server itself instead of an npm wrapper that
# would leave it orphaned and still holding the port.
cd "$REPO_ROOT"
exec node --experimental-strip-types server/src/index.ts
