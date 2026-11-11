#!/bin/bash
#
# MobSF Local Runner for iOS-Pentesting-Skill
#
# Usage: ./scripts/run-mobsf-local.sh [--port PORT] [--detach]
#

set -e

INSTALL_DIR="${INSTALL_DIR:-$HOME/MobSF}"
VENV_DIR="${VENV_DIR:-$INSTALL_DIR/venv}"
PORT="${PORT:-8000}"
DETACH="${DETACH:-false}"

if [ -f "$VENV_DIR/bin/activate" ]; then
    # Resolved at runtime; shellcheck cannot follow it.
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
else
    echo "❌ Virtual environment not found at $VENV_DIR"
    echo "   Run ./scripts/install-mobsf-local.sh first"
    exit 1
fi

cd "$INSTALL_DIR"

if pgrep -f "manage.py runserver" > /dev/null; then
    echo "⚠️  MobSF is already running."
    echo "   Web UI: http://127.0.0.1:${PORT}"
    echo "   API: http://127.0.0.1:${PORT}/api/v1"
    exit 0
fi

echo "🚀 Starting MobSF server..."
# Bind to 127.0.0.1 by default — MobSF has no auth, exposing it on
# 0.0.0.0 would let any host on the network upload binaries and read
# scan results. Override with --host 0.0.0.0 only if you know what
# you're doing (e.g. behind a reverse proxy with auth).
HOST="${HOST:-127.0.0.1}"
if [[ "$DETACH" == "true" ]]; then
    nohup python manage.py runserver "${HOST}:${PORT}" > /dev/null 2>&1 &
    echo "✅ MobSF started in background on ${HOST}:${PORT}"
    echo "   Web UI: http://${HOST}:${PORT}"
    echo "   API: http://${HOST}:${PORT}/api/v1"
else
    python manage.py runserver "${HOST}:${PORT}"
fi
